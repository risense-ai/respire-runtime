//! Explicit host factors for profile migration; never opens a credential store.
use super::*;
use respire_protocol::host_control::{HostAuthSessionMaterial, HostAuthVaultFactors};
use respire_protocol::migration_control::HostMigrationMaterial;

pub(super) struct Plan {
    pub keys: Option<crate::memory::SessionKeys>,
    pub selected: Option<usize>,
    pub session: Value,
    pub references: Vec<Value>,
}

#[derive(Debug)]
pub(super) struct CredentialsRequired(pub Value);
impl std::fmt::Display for CredentialsRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("migration requires host credential custody")
    }
}
impl std::error::Error for CredentialsRequired {}

pub(super) fn unlock(session: &Value, material: &HostAuthSessionMaterial)
    -> Result<crate::memory::SessionKeys> {
    let salt = session["kdf_salt"].as_str().context("legacy session salt missing")?;
    let wrapped = session["wrapped_urk"].as_str().context("legacy wrapped key missing")?;
    let nonce = session["urk_nonce"].as_str().context("legacy key nonce missing")?;
    use crate::memory::SessionKeys;
    Ok(match &material.factors {
        HostAuthVaultFactors::V1 { password, account_secret } =>
            SessionKeys::unlock(password, account_secret, salt, wrapped, nonce)?,
        HostAuthVaultFactors::V2 { super_password } =>
            SessionKeys::unlock_super(super_password, salt, wrapped, nonce)?,
        HostAuthVaultFactors::V3 { super_password, secret_key } =>
            SessionKeys::unlock_vault(super_password, secret_key, salt, wrapped, nonce)?,
        HostAuthVaultFactors::V4 { super_password } =>
            SessionKeys::unlock_v4(super_password, salt, wrapped, nonce)?,
    })
}

pub(super) fn prepare(profile: &Profile, bytes: &[u8], database: &Path,
    material: Option<&HostMigrationMaterial>) -> Result<Plan> {
    let mut session: Value = serde_json::from_slice(bytes)?;
    let version = session["vault_version"].as_u64().unwrap_or(1);
    anyhow::ensure!((1..=4).contains(&version), "unsupported legacy vault version");
    let wrapped = session["wrapped_urk"].as_str().is_some_and(|value| !value.is_empty());
    let inline = ["pass", "super", "secret", "secret_key"].iter()
        .any(|field| session.get(*field).is_some());
    if !wrapped && !inline && material.is_none_or(|value| value.candidates.is_empty()) {
        anyhow::ensure!(encrypted_count(database)? == 0,
            "legacy session has no wrapped key; original data was preserved");
        validate_live_memories(database, None)?;
        return Ok(Plan { keys: None, selected: None, session, references: Vec::new() });
    }
    let material = material.context("explicit host migration material is required; no credential store was opened")?;
    let digest = hex::encode(Sha256::digest(bytes));
    for candidate in &material.candidates {
        anyhow::ensure!(candidate.session_sha256 == digest,
            "host migration material differs from the original session");
        let candidate_version = match &candidate.factors {
            HostAuthVaultFactors::V1 { account_secret, .. } => {
                anyhow::ensure!(!account_secret.is_empty(), "legacy account factor is empty"); 1
            }
            HostAuthVaultFactors::V2 { super_password } => {
                anyhow::ensure!(!super_password.is_empty(), "legacy super password is empty"); 2
            }
            HostAuthVaultFactors::V3 { super_password, secret_key } => {
                anyhow::ensure!(!super_password.is_empty() && !secret_key.is_empty(), "legacy vault factor is empty"); 3
            }
            HostAuthVaultFactors::V4 { super_password } => {
                anyhow::ensure!(!super_password.is_empty(), "legacy super password is empty"); 4
            }
        };
        anyhow::ensure!(candidate_version == version, "host migration factor version changed");
    }
    let mut selected = None;
    let mut keys = None;
    for (index, candidate) in material.candidates.iter().enumerate() {
        if !wrapped {
            anyhow::ensure!(encrypted_count(database)? == 0,
                "legacy session has no wrapped key; original data was preserved");
            selected = Some(index);
            break;
        }
        if let Ok(recovered) = unlock(&session, candidate) {
            selected = Some(index);
            keys = Some(recovered);
            break;
        }
    }
    let selected = selected.context("legacy vault could not be unlocked with supplied host material; original data was preserved")?;
    validate_live_memories(database, keys.as_ref())?;
    // Namespace conversion includes tombstones and embeddings as well as live payloads.
    // Reject unreadable source bytes while Copying is still safe to retry.
    if database.is_file() {
        let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let columns = connection.prepare("PRAGMA table_info(memories)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
        if !columns.is_empty() {
            let query = if columns.contains("embedding_enc") {
                "SELECT ciphertext,nonce,embedding_enc FROM memories"
            } else { "SELECT ciphertext,nonce,'' FROM memories" };
            let mut statement = connection.prepare(query)?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let keys = keys.as_ref().context("legacy ciphertext requires usable session keys")?;
                let ciphertext: String = row.get(0)?;
                let nonce: String = row.get(1)?;
                let embedding: String = row.get(2)?;
                keys.decrypt_content(&ciphertext, &nonce).map_err(|_| anyhow!(
                    "a source record cannot be decrypted; original library and keys were preserved"))?;
                keys.migrate_embedding(&embedding).map_err(|_| anyhow!(
                    "a source embedding cannot be decrypted; original library and keys were preserved"))?;
            }
        }
    }
    let Some(custody) = material.custody.as_ref() else {
        return Ok(Plan { keys, selected: Some(selected), session, references: Vec::new() });
    };
    anyhow::ensure!(material.candidates.len() == 1 && custody.keyring_account == format!("legacy-{}", &profile.identity[..16])
        && matches!(custody.keyring_backend.as_str(), "native" | "secret_service"),
        "host migration custody differs from its source or persistent backend");
    let legacy = matches!(version, 1 | 3);
    anyhow::ensure!(legacy == custody.legacy_secret_backend.is_some()
        && custody.legacy_secret_backend.as_deref().is_none_or(|backend| matches!(backend, "native" | "secret_service"))
        && (version != 1 || custody.login_password_retained), "incomplete host migration custody");
    let fields = session.as_object_mut().context("legacy session must be an object")?;
    for field in ["pass", "super", "secret", "secret_key", "legacy_secret_backend"] { fields.remove(field); }
    fields.insert("keyring_account".into(), json!(custody.keyring_account));
    fields.insert("keyring_backend".into(), json!(custody.keyring_backend));
    fields.insert("vault_version".into(), json!(version));
    let mut references = Vec::new();
    if version != 1 { references.push(json!({"slot":"super", "backend":custody.keyring_backend})); }
    if custody.login_password_retained { references.push(json!({"slot":"pass", "backend":custody.keyring_backend})); }
    if let Some(backend) = &custody.legacy_secret_backend {
        fields.insert("legacy_secret_backend".into(), json!(backend));
        references.push(json!({"slot":"legacy-secret", "backend":backend}));
    }
    Ok(Plan { keys, selected: None, session, references })
}

pub(super) fn rewrap(candidate: &HostAuthSessionMaterial,
    keys: &crate::memory::SessionKeys) -> Result<(String, String, String)> {
    use crate::memory::crypto;
    let salt = crypto::random_hex(16);
    let kek = match &candidate.factors {
        HostAuthVaultFactors::V1 { password, account_secret } => crypto::derive_rsrs_password_kek(password, account_secret, &salt)?,
        HostAuthVaultFactors::V2 { super_password } => crypto::derive_super_kek(super_password, &salt)?,
        HostAuthVaultFactors::V3 { super_password, secret_key } => crypto::derive_rsrs_vault_kek(super_password, secret_key, &salt)?,
        HostAuthVaultFactors::V4 { super_password } => crypto::derive_rsrs_kek(super_password, &salt)?,
    };
    let (nonce, wrapped) = crypto::wrap_key(&keys.urk, &kek)?;
    anyhow::ensure!(crypto::unwrap_key(&wrapped, &nonce, &kek)? == keys.urk,
        "new key wrap did not round-trip; migration was not completed");
    Ok((salt, format!("{}{wrapped}", crypto::RSRS_PREFIX), nonce))
}

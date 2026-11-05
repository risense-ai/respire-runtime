//! Prepare login without changing the active account; commit only after vault verification.
use std::path::{Path, PathBuf};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use std::io::Write;
use sha2::Digest;
use respire_protocol::{HostAuthIdentity, HostAuthOutcome, HostAuthResult};
use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult,
    HostAuthAuthorization, HostAuthLoginParams, HostAuthRegisterParams};

#[derive(Serialize, Deserialize)]
struct Recovery {
    directory: PathBuf,
    original: Option<Vec<u8>>,
    config: Option<Vec<u8>>,
    alias: String,
    backends: Vec<String>,
    #[serde(default)]
    pass_backends: Vec<String>,
    directory_existed: bool,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    owns_config: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    active: Option<Recovery>,
    operations: Vec<AuthRecord>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthPhase { Admitted, RemotePending, RemoteUnknown, Authorized, Prepared, AwaitingVerification, RollingBack, Committed, RolledBack }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountOperation {
    register: bool,
    addr: String,
    user: String,
    source_identity: HostAuthIdentity,
    target: Option<PathBuf>,
    authorization: Option<Value>,
    vault: Option<Value>,
    #[serde(default)]
    published_vault: bool,
    #[serde(default)]
    vault_pending: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthRecord {
    operation_id: String,
    idempotency_key: String,
    fingerprint: String,
    root: PathBuf,
    profile: PathBuf,
    original_sha256: Option<String>,
    candidate: Option<Vec<u8>>,
    candidate_sha256: Option<String>,
    alias: String,
    backend: Option<String>,
    phase: AuthPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<AccountOperation>,
}

fn digest(bytes: &[u8]) -> String { hex::encode(sha2::Sha256::digest(bytes)) }

fn load_journal() -> Result<Journal> {
    let path = recovery_path();
    ensure!(!std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()),
        "login recovery record must not be a symbolic link");
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound =>
            return Ok(Journal { schema_version: 2, ..Journal::default() }),
        Err(error) => return Err(error.into()),
    };
    let value: Value = serde_json::from_slice(&bytes).context("invalid login recovery record; retain it for recovery")?;
    if value.get("schema_version").is_none() {
        return Ok(Journal { schema_version: 2, active: Some(serde_json::from_value(value)?), operations: Vec::new() });
    }
    let journal: Journal = serde_json::from_value(value)?;
    ensure!(journal.schema_version == 2, "unsupported login recovery schema");
    Ok(journal)
}

fn save_journal(journal: &Journal) -> Result<()> {
    let path = recovery_path();
    std::fs::create_dir_all(path.parent().context("recovery root is missing")?)?;
    private_write(&path, &serde_json::to_vec(journal)?)
}

fn retire_active(journal: &mut Journal) -> Result<()> {
    journal.active = None;
    if journal.operations.is_empty() {
        std::fs::remove_file(recovery_path())?;
        #[cfg(unix)] {
            std::fs::File::open(recovery_path().parent().context("recovery root is missing")?)?.sync_all()?;
        }
        Ok(())
    } else { save_journal(journal) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_login_restores_existing_and_new_profiles() -> Result<()> {
        let _guard = crate::test_lock::guard();
        let root = tempfile::tempdir()?;
        let previous_root = crate::env::var_os("RSRS_DATA_DIR");
        let previous_super = crate::env::var_os("RSRS_SUPER");
        std::env::set_var("RSRS_DATA_DIR", root.path());
        let code = crate::memory::crypto::generate_secret_key();
        std::env::set_var("RSRS_SUPER", &code);
        let result = (|| -> Result<()> {
            let config = br#"{"custom":"preserve","api_base":"https://previous.invalid"}"#;
            let old = br#"{"user":"existing","token":"old-token"}"#;
            std::fs::write(crate::service::client_config_path(), config)?;
            let existing = crate::service::account_dir("existing")?;
            std::fs::create_dir_all(&existing)?;
            std::fs::write(existing.join("session.json"), old)?;
            let (salt, wrapped, nonce) = crate::auth::wrap_with_v4(&code, &[42; 32])?;
            let vault = json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
            let case_dir = crate::service::account_dir("shiningray")?;
            std::fs::create_dir_all(&case_dir)?;
            std::fs::write(case_dir.join("session.json"), br#"{"user":"shiningray","addr":"https://old.invalid"}"#)?;
            let cloud_dir = login_directory("https://cloud.invalid", "ShiningRay")?;
            ensure!(cloud_dir != case_dir && !cloud_dir.exists(), "case collision reused source");
            let second_server = login_directory("https://cloud.invalid", "shiningray")?;
            ensure!(second_server != case_dir, "server change reused source");
            ensure!(login_directory("https://old.invalid", "shiningray")? == case_dir, "original identity was not reused");
            for user in ["existing", "new-account"] {
                let mut prepared = PreparedLogin::prepare_with_vault("https://fixture.invalid", &json!({"user":user,"token":"new-token"}), code.clone(), vault.clone(), None)?;
                let directory = prepared.directory.clone();
                prepared.commit()?;
                ensure!(recovery_pending(), "commit did not retain recovery state");
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    ensure!(std::fs::metadata(recovery_path())?.permissions().mode() & 0o777 == 0o600, "recovery is not private");
                }
                let record = std::fs::read_to_string(recovery_path())?;
                ensure!(!record.contains(&code), "recovery persisted the super password");
                drop(prepared); // Simulate process loss: only the durable record remains.
                recover_interrupted()?;
                recover_interrupted()?; // Recovery must be idempotent.
                ensure!(std::fs::read(crate::service::client_config_path())? == config, "configuration changed");
                ensure!(std::fs::read(existing.join("session.json"))? == old, "existing session changed");
                if user == "new-account" { ensure!(!directory.exists(), "failed new account remained selectable"); }
                ensure!(!recovery_pending(), "completed recovery retained its journal");
            }
            let canonical_root = root.path().canonicalize()?;
            save_journal(&Journal { schema_version: 2, active: None, operations: vec![AuthRecord {
                operation_id: uuid::Uuid::new_v4().to_string(), idempotency_key: "retained".into(),
                fingerprint: keygen_fingerprint(&canonical_root, &canonical_root, false)?,
                root: canonical_root.clone(), profile: canonical_root, original_sha256: None,
                candidate: None, candidate_sha256: None, alias: "login-retained".into(), backend: None,
                phase: AuthPhase::RolledBack, account: None,
            }] })?;
            let mut prepared = PreparedLogin::prepare_with_vault("https://fixture.invalid", &json!({"user":"completed-account","token":"new-token"}), code.clone(), vault, None)?;
            prepared.commit()?;
            prepared.complete()?;
            ensure!(!recovery_pending() && load_journal()?.operations.len() == 1, "login completion lost the auth receipt");
            Ok(())
        })();
        match previous_root { Some(value) => std::env::set_var("RSRS_DATA_DIR", value), None => std::env::remove_var("RSRS_DATA_DIR") }
        match previous_super { Some(value) => std::env::set_var("RSRS_SUPER", value), None => std::env::remove_var("RSRS_SUPER") }
        result
    }

    #[test]
    fn auth_admission_recovers_without_regenerating_and_retains_receipts() -> Result<()> {
        assert!(require_persistent_auth_backend("kernel").is_err());
        require_persistent_auth_backend("native")?;
        require_persistent_auth_backend("secret_service")?;
        let isolated = crate::test_lock::Isolate::new()?;
        let root = isolated.path().canonicalize()?;
        let ownership = AuthOwnership::acquire(&root, &root)?;
        let id = uuid::Uuid::new_v4().to_string();
        let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        let previous_config = br#"{"custom":"before-auth"}"#;
        let current_config = br#"{"custom":"changed-outside-auth"}"#;
        let mut journal = Journal { schema_version: 2, active: Some(Recovery {
            directory: root.clone(), original: None, config: Some(previous_config.to_vec()), alias: alias.clone(),
            backends: Vec::new(), pass_backends: Vec::new(), directory_existed: true, operation_id: Some(id.clone()), owns_config: false,
        }), operations: vec![AuthRecord {
            operation_id: id.clone(), idempotency_key: id.clone(), fingerprint: keygen_fingerprint(&root, &root, false)?,
            root: root.clone(), profile: root.clone(), original_sha256: None, candidate: None, candidate_sha256: None,
            alias, backend: None, phase: AuthPhase::Admitted, account: None,
        }] };
        save_journal(&journal)?;
        std::fs::write(crate::service::client_config_path(), current_config)?;
        ownership.recover(&HostAuthIdentity::Absent)?;
        ownership.recover(&HostAuthIdentity::Absent)?;
        assert_eq!(std::fs::read(crate::service::client_config_path())?, current_config);
        let result = control_keygen(&ownership, &HostAuthIdentity::Absent, &id, &id, false, true)?;
        assert_eq!(result.outcome, HostAuthOutcome::RolledBack);
        assert!(result.super_password.is_none());
        assert!(!root.join("session.json").exists());
        assert!(control_keygen(&ownership, &HostAuthIdentity::Absent, &id, &id, true, false).is_err());
        assert!(control_keygen(&ownership, &HostAuthIdentity::Absent, &uuid::Uuid::new_v4().to_string(), &id, false, false).is_err());
        journal = load_journal()?;
        assert!(journal.active.is_none());
        assert_eq!(journal.operations.len(), 1);

        // Decode an actual legacy record, then preserve terminal auth receipts across login completion.
        let active = Recovery { directory: root.clone(), original: None, config: None,
            alias: format!("login-{}", uuid::Uuid::new_v4().simple()), backends: Vec::new(),
            pass_backends: Vec::new(), directory_existed: true, operation_id: None, owns_config: false };
        let mut legacy = serde_json::to_value(&active)?;
        legacy.as_object_mut().context("legacy recovery must be an object")?.remove("operation_id");
        private_write(&recovery_path(), &serde_json::to_vec(&legacy)?)?;
        assert!(load_journal()?.active.is_some());
        journal.active = Some(active);
        save_journal(&journal)?;
        drop(ownership);
        recover_interrupted()?;
        assert!(!crate::service::client_config_path().exists(), "legacy login did not restore its absent configuration");
        assert!(!recovery_pending());
        assert_eq!(load_journal()?.operations.len(), 1);

        let ownership = AuthOwnership::acquire(&root, &root)?;
        let account_id = uuid::Uuid::new_v4().to_string();
        let (mut account_journal, account_index, fresh) = admit_account(&ownership, &HostAuthIdentity::Absent,
            &account_id, &account_id, true, "https://never-contact.invalid", "receipt-user")?;
        assert!(fresh);
        assert!(!admit_account(&ownership, &HostAuthIdentity::Absent, &account_id, &account_id,
            true, "https://never-contact.invalid", "receipt-user")?.2);
        assert!(admit_account(&ownership, &HostAuthIdentity::Absent, &account_id, &account_id,
            true, "https://other.invalid", "receipt-user").is_err());
        account_journal.operations[account_index].phase = AuthPhase::RemotePending;
        save_journal(&account_journal)?;
        let params = HostAuthRegisterParams {
            schema_version: 1, binding: respire_protocol::ControlBinding {
                installation_root: root.clone(), profile: root.clone(), launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: None,
            }, identity: HostAuthIdentity::Absent, addr: "https://never-contact.invalid".into(), user: "receipt-user".into(),
            password: "must-not-be-durable".into(), super_password: Some("must-not-be-durable-either".into()),
        };
        // A replay must return before either network access or credential creation.
        assert_eq!(control_register(&ownership, &account_id, &account_id, &params)?.outcome, HostAuthAccountOutcome::Unknown);
        ownership.recover(&HostAuthIdentity::Absent)?;
        drop(ownership);
        assert!(recover_interrupted().is_err(), "account admission entered keygen recovery");
        let ownership = AuthOwnership::acquire(&root, &root)?;
        assert_eq!(control_account_result(&ownership, &HostAuthIdentity::Absent, &account_id, &account_id)?.outcome,
            HostAuthAccountOutcome::Unknown);
        assert!(control_account_result(&ownership, &HostAuthIdentity::Absent, &account_id, "wrong-key").is_err());
        assert!(!String::from_utf8(std::fs::read(recovery_path())?)?.contains("must-not-be-durable"));
        account_journal.operations[account_index].phase = AuthPhase::Admitted;
        let owned_config = br#"{"custom":"account-before"}"#;
        let active = account_journal.active.as_mut().context("account recovery is missing")?;
        active.owns_config = true;
        active.config = Some(owned_config.to_vec());
        save_journal(&account_journal)?;
        std::fs::write(crate::service::client_config_path(), serde_json::to_vec(&json!({"custom":"account-before","data_dir":root}))?)?;
        assert_eq!(control_account_rollback(ownership, &HostAuthIdentity::Absent, &account_id, &account_id)?.outcome,
            HostAuthAccountOutcome::RolledBack);
        assert_eq!(std::fs::read(crate::service::client_config_path())?, owned_config);
        assert!(!recovery_pending());
        assert_eq!(load_journal()?.operations.len(), 2);

        keygen_overwrite_guard(&root, None, false)?;
        let database_path = crate::service::database_path(&root)?;
        assert!(!database_path.exists(), "overwrite guard initialized a store");
        let database = rusqlite::Connection::open(&database_path)?;
        database.execute_batch("CREATE TABLE memories(deleted INTEGER); INSERT INTO memories VALUES(0);")?;
        drop(database);
        assert!(keygen_overwrite_guard(&root, None, false).is_err());
        keygen_overwrite_guard(&root, None, true)?;
        std::fs::remove_file(&database_path)?;
        std::fs::write(&database_path, b"invalid database")?;
        assert!(keygen_overwrite_guard(&root, None, false).is_err());
        std::fs::remove_file(database_path)?;

        std::fs::write(root.join("session.json"), b"{")?;
        assert!(verify_auth_identity(&root, &root, &HostAuthIdentity::Absent).is_err());
        std::fs::write(root.join("session.json"), b"{}")?;
        assert!(verify_auth_identity(&root, &root, &HostAuthIdentity::Absent).is_err());
        assert!(verify_auth_identity(&root, &root, &HostAuthIdentity::Unbound {
            operation_id: id, session_sha256: digest(b"{}"),
        }).is_err());
        Ok(())
    }

    #[test]
    fn prepared_auth_candidate_requires_its_checkpointed_credential() -> Result<()> {
        let isolated = crate::test_lock::Isolate::new()?;
        let root = isolated.path().canonicalize()?;
        let ownership = AuthOwnership::acquire(&root, &root)?;
        let id = uuid::Uuid::new_v4().to_string();
        let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        let candidate = serde_json::to_vec(&json!({"vault_version":4,"kdf_salt":"invalid",
            "wrapped_urk":"invalid","urk_nonce":"invalid","keyring_account":alias,
            "keyring_backend":"unavailable-test-backend","auth_operation_id":id}))?;
        let identity = HostAuthIdentity::Unbound { operation_id: id.clone(), session_sha256: digest(&candidate) };
        let journal = Journal { schema_version: 2, active: Some(Recovery {
            directory: root.clone(), original: None, config: None, alias: alias.clone(),
            backends: Vec::new(), pass_backends: Vec::new(), directory_existed: true, operation_id: Some(id.clone()), owns_config: false,
        }), operations: vec![AuthRecord {
            operation_id: id.clone(), idempotency_key: id, fingerprint: keygen_fingerprint(&root, &root, false)?,
            root: root.clone(), profile: root.clone(), original_sha256: None,
            candidate: Some(candidate.clone()), candidate_sha256: Some(digest(&candidate)),
            alias, backend: Some("unavailable-test-backend".into()), phase: AuthPhase::Prepared, account: None,
        }] };
        save_journal(&journal)?;
        std::fs::write(root.join("session.json"), &candidate)?;
        assert!(ownership.recover(&identity).is_err());
        assert!(load_journal()?.active.is_some());
        assert!(verify_auth_identity(&root, &root, &identity).is_err());
        assert_eq!(std::fs::read(root.join("session.json"))?, candidate);
        Ok(())
    }
}

fn recovery_path() -> PathBuf {
    crate::service::client_config_path().with_file_name(".login-recovery.json")
}

fn auth_journal_lock() -> Result<std::fs::File> {
    let path = recovery_path().with_extension("json.lock");
    std::fs::create_dir_all(path.parent().context("auth recovery root is missing")?)?;
    ensure!(!std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()),
        "auth recovery lock must not be a symbolic link");
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                ensure!(std::time::Instant::now() < deadline, "auth recovery journal is busy");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
    }
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_file_name(format!(".login-write-{}", uuid::Uuid::new_v4().simple()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        respire_spawn::durable::replace_file(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() && temporary.exists() { std::fs::remove_file(&temporary)?; }
    result
}

fn restore(path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    match bytes {
        Some(bytes) => private_write(path, bytes),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        },
    }
}

pub fn recovery_pending() -> bool {
    match load_journal() { Ok(journal) => journal.active.is_some(), Err(_) => true }
}

pub fn auth_recovery_pending() -> Result<bool> {
    let journal = load_journal()?;
    let Some(active) = journal.active.as_ref() else { return Ok(false); };
    let Some(id) = active.operation_id.as_deref() else { return Ok(false); };
    let record = journal.operations.iter().find(|record| record.operation_id == id)
        .context("active auth recovery has no admission receipt")?;
    if let Some(account) = &record.account {
        if record.phase == AuthPhase::AwaitingVerification {
            ensure!(record.root == crate::service::main_data_dir().canonicalize()?
                && account.target.as_deref() == Some(active.directory.as_path())
                && active.directory.canonicalize()? == crate::service::data_dir().canonicalize()?
                && active.alias == record.alias, "runtime verification does not own the active account candidate");
            verify_account_candidate(record)?;
            return Ok(false);
        }
    }
    Ok(true)
}

/// Called by the host under its takeover lock, after stopping the interrupted runtime.
/// Roll back local state only. A published cloud v4 wrap is resumed by the existing
/// migration path, which proves that the old and new wraps contain the same URK.
pub fn recover_interrupted() -> Result<()> {
    crate::service::require_profile_change_host()?;
    let _journal_lock = auth_journal_lock()?;
    let mut journal = load_journal()?;
    let Some(record) = &journal.active else { return Ok(()); };
    if record.operation_id.is_some() {
        ensure!(!journal.operations.iter().any(|operation|
            Some(operation.operation_id.as_str()) == record.operation_id.as_deref() && operation.account.is_some()),
            "account operation requires its original receipt; remote effects must not be automatically retried or rolled back");
        let root = crate::service::main_data_dir().canonicalize()?;
        let profile = crate::service::data_dir().canonicalize()?;
        return recover_keygen(&mut journal, &root, &profile);
    }
    rollback_record(record)?;
    retire_active(&mut journal)
}

fn rollback_record(record: &Recovery) -> Result<()> {
    rollback_record_inner(record, true)
}

fn quarantine_new_profile(record: &Recovery) -> Result<()> {
    if !record.directory_existed && record.directory.exists() {
        let parent = record.directory.parent().context("recovery directory has no parent")?;
        std::fs::rename(&record.directory, parent.join(format!(".failed-{}", record.alias)))?;
    }
    Ok(())
}

fn rollback_record_inner(record: &Recovery, quarantine: bool) -> Result<()> {
    ensure!(record.alias.starts_with("login-") && record.alias.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'), "invalid recovery credential alias");
    ensure!(record.directory.exists() || record.original.is_none(), "original account directory is missing; retain the recovery record");
    if record.directory.exists() {
        read_original(&record.directory)?;
        restore(&record.directory.join("session.json"), record.original.as_deref())?;
    }
    if record.operation_id.is_none() || record.owns_config {
        restore(&crate::service::client_config_path(), record.config.as_deref())?;
    }
    for backend in &record.backends {
        crate::keystore::remove_imported(&record.alias, "super", backend)?;
    }
    for backend in &record.pass_backends {
        crate::keystore::remove_imported(&record.alias, "pass", backend)?;
    }
    if quarantine { quarantine_new_profile(record)?; }
    Ok(())
}

/// Read the selected source as one committed snapshot, without creating plaintext files.
/// WP-2c: the implementation moved into the domain crate (`service::local_snapshot`);
/// this wrapper keeps the `respire_app::login_transaction::local_snapshot` path stable.
pub fn local_snapshot(source_secret: Option<&str>) -> Result<String> {
    crate::service::local_snapshot(source_secret)
}

// A sessionless library can identify itself only by decrypting with the authorized data key.
fn library_accepts_keys(directory: &Path, keys: &crate::memory::SessionKeys) -> Result<bool> {
    let path = crate::service::database_path(directory)?;
    if !path.is_file() { return Ok(false); }
    let database = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_memories: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')", [], |row| row.get(0))?;
    if !has_memories { return Ok(false); }
    let mut statement = database.prepare("SELECT ciphertext,nonce FROM memories WHERE ciphertext <> '' AND COALESCE(deleted,0)=0")?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let mut stored = crate::memory::model::StoredMemory::new_pending(String::new(), String::new());
        stored.ciphertext = row.get(0)?;
        stored.nonce = row.get(1)?;
        if crate::memory::MemoryEngine::open(keys, &stored).is_err() { return Ok(false); }
        count += 1;
    }
    Ok(count > 0)
}

/// A remote identity includes its server; filesystem case folding is not account identity.
pub fn login_directory(addr: &str, user: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let base = addr.trim().trim_end_matches('/');
    let matches = |directory: &Path| -> Result<bool> {
        let Some(bytes) = read_original(directory)? else { return Ok(false); };
        let session: Value = serde_json::from_slice(&bytes).context("account session is invalid")?;
        let stored_addr = session["addr"].as_str().unwrap_or("").trim().trim_end_matches('/');
        // Older recovery-only profiles carry v1/v3 factors before the first login.
        let recovery_only = stored_addr.is_empty() && !crate::service::database_path(directory)?.is_file();
        Ok(session["user"].as_str() == Some(user) && (stored_addr == base || recovery_only))
    };
    for directory in [crate::service::data_dir(), crate::service::main_data_dir()] {
        if matches(&directory)? { return Ok(directory); }
    }
    let accounts = crate::service::accounts_root();
    if accounts.is_dir() {
        for item in std::fs::read_dir(&accounts)? {
            let item = item?;
            if item.file_type()?.is_dir() && matches(&item.path())? { return Ok(item.path()); }
        }
    }
    let plain = crate::service::account_dir(user)?;
    if !plain.exists() { return Ok(plain); }
    let suffix = hex::encode(Sha256::digest(format!("{base}\n{user}").as_bytes()));
    let isolated = crate::service::account_dir(&format!("{user}-{}", &suffix[..16]))?;
    ensure!(!isolated.exists() || matches(&isolated)? || read_original(&isolated)?.is_none(),
        "isolated account destination is occupied; original libraries were preserved");
    Ok(isolated)
}

pub struct PreparedLogin {
    pub user: String,
    pub directory: PathBuf,
    original: Option<Vec<u8>>,
    session: Value,
    super_password: String,
    login_password: Option<String>,
    alias: String,
    recovery_written: bool,
    migration_cloud: Option<Value>,
    migration_auth: Option<Value>,
}

fn read_original(directory: &Path) -> Result<Option<Vec<u8>>> {
    let path = directory.join("session.json");
    if std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
        || std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        anyhow::bail!("login destination must not be a symbolic link");
    }
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Both guards are held by the helper, never by its waiting CLI parent.
pub struct AuthOwnership {
    root: PathBuf,
    profile: PathBuf,
    _root_lock: crate::lock::LibraryLock,
    _profile_lock: Option<crate::lock::LibraryLock>,
    _journal_lock: std::fs::File,
}

impl AuthOwnership {
    pub fn acquire(root: &Path, profile: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let profile = profile.canonicalize()?;
        ensure!(root == crate::service::main_data_dir().canonicalize()?
            && profile == crate::service::data_dir().canonicalize()?, "auth profile changed");
        let wait = std::time::Duration::from_secs(1);
        let root_lock = crate::lock::LibraryLock::acquire(&root, wait)?;
        let profile_lock = if root == profile { None }
            else { Some(crate::lock::LibraryLock::acquire(&profile, wait)?) };
        let journal_lock = auth_journal_lock()?;
        Ok(Self { root, profile, _root_lock: root_lock, _profile_lock: profile_lock, _journal_lock: journal_lock })
    }

    pub fn recover(&self, identity: &HostAuthIdentity) -> Result<()> {
        let mut journal = load_journal()?;
        if journal.active.as_ref().is_some_and(|active| active.operation_id.is_some()) {
            verify_auth_identity_inner(&self.root, &self.profile, identity, true)?;
            if !journal.operations.iter().any(|record| record.account.is_some()
                && journal.active.as_ref().and_then(|active| active.operation_id.as_deref()) == Some(record.operation_id.as_str())) {
                recover_keygen(&mut journal, &self.root, &self.profile)?;
            }
        }
        Ok(())
    }
}

fn canonical_operation_id(value: &str) -> Result<()> {
    let id = uuid::Uuid::parse_str(value).context("invalid auth operation ID")?;
    ensure!(id.get_version_num() == 4 && id.to_string() == value, "auth operation ID must be a canonical random UUID");
    Ok(())
}

fn verify_candidate(record: &AuthRecord) -> Result<String> {
    let bytes = record.candidate.as_deref().context("auth candidate is missing")?;
    ensure!(record.candidate_sha256.as_deref() == Some(digest(bytes).as_str()), "auth candidate digest mismatch");
    let session: Value = serde_json::from_slice(bytes)?;
    let object = session.as_object().context("auth candidate must be an object")?;
    ensure!(object.len() == 7 && session.get("user").is_none()
        && session["vault_version"] == 4 && session["keyring_account"].as_str() == Some(record.alias.as_str())
        && session["auth_operation_id"].as_str() == Some(record.operation_id.as_str())
        && session["keyring_backend"].as_str() == record.backend.as_deref(), "invalid unbound auth candidate");
    let backend = record.backend.as_deref().context("auth credential backend is missing")?;
    require_persistent_auth_backend(backend)?;
    let secret = crate::keystore::read_imported(&record.alias, "super", backend)?;
    crate::memory::SessionKeys::unlock_v4(&secret,
        session["kdf_salt"].as_str().context("candidate salt is missing")?,
        session["wrapped_urk"].as_str().context("candidate wrap is missing")?,
        session["urk_nonce"].as_str().context("candidate nonce is missing")?)
        .context("auth recovery credential does not unlock the candidate")?;
    Ok(secret)
}

/// This reader is exclusive to private auth control; business identity stays strict.
pub fn verify_auth_identity(root: &Path, profile: &Path, expected: &HostAuthIdentity) -> Result<()> {
    verify_auth_identity_inner(root, profile, expected, false)
}

fn verify_auth_identity_inner(root: &Path, profile: &Path, expected: &HostAuthIdentity, recovering: bool) -> Result<()> {
    let original = read_original(profile)?;
    match (original.as_deref(), expected) {
        (None, HostAuthIdentity::Absent) => Ok(()),
        (Some(bytes), HostAuthIdentity::Bound { account_id, session_sha256 }) => {
            let session: Value = serde_json::from_slice(bytes).context("invalid auth session JSON")?;
            let user = session["user"].as_str().filter(|user| !user.is_empty()).context("bound auth session needs a user")?;
            ensure!(digest(user.as_bytes()) == *account_id && digest(bytes) == *session_sha256,
                "bound auth session identity changed");
            Ok(())
        }
        (Some(bytes), HostAuthIdentity::Unbound { operation_id, session_sha256 }) => {
            canonical_operation_id(operation_id)?;
            ensure!(digest(bytes) == *session_sha256, "unbound auth session digest mismatch");
            let journal = load_journal()?;
            let record = journal.operations.iter().find(|record| record.operation_id == *operation_id)
                .context("unbound auth session has no transaction receipt")?;
            let prepared = recovering && record.phase == AuthPhase::Prepared
                && journal.active.as_ref().is_some_and(|active| active.operation_id.as_deref() == Some(operation_id.as_str()));
            ensure!(record.root == root && record.profile == profile && (record.phase == AuthPhase::Committed || prepared)
                && record.candidate.as_deref() == Some(bytes), "unbound auth receipt does not own this session");
            verify_candidate(record)?;
            Ok(())
        }
        _ => anyhow::bail!("auth session identity mismatch; malformed sessions are not anonymous"),
    }
}

fn recover_keygen(journal: &mut Journal, root: &Path, profile: &Path) -> Result<()> {
    let active = journal.active.as_ref().context("auth recovery is missing")?;
    let id = active.operation_id.as_deref().context("active recovery is not an auth transaction")?;
    let index = journal.operations.iter().position(|record| record.operation_id == id)
        .context("auth recovery has no admission receipt")?;
    let record = &journal.operations[index];
    ensure!(record.account.is_none(), "account operation is not a keygen transaction");
    ensure!(record.root == root && record.profile == profile && active.directory == profile
        && record.alias == active.alias && record.original_sha256 == active.original.as_deref().map(digest),
        "auth recovery owner mismatch");
    let current = read_original(profile)?;
    if record.phase == AuthPhase::Prepared && current.is_some() && current == record.candidate {
        ensure!(record.backend.as_ref().is_some_and(|backend| active.backends.contains(backend)),
            "auth candidate has no credential backend checkpoint");
        verify_candidate(record)?;
        journal.operations[index].phase = AuthPhase::Committed;
        return retire_active(journal);
    }
    ensure!(record.phase == AuthPhase::Admitted || record.phase == AuthPhase::Prepared,
        "terminal auth operation retained an active transaction");
    ensure!(current == active.original, "auth session changed outside its transaction; retain recovery");
    rollback_record(active)?;
    journal.operations[index].phase = AuthPhase::RolledBack;
    retire_active(journal)
}

fn auth_result(record: &AuthRecord) -> Result<HostAuthResult> {
    let committed = record.phase == AuthPhase::Committed;
    let current = read_original(&record.profile)?;
    ensure!(if committed { current == record.candidate }
        else { current.as_deref().map(digest) == record.original_sha256 }, "auth result owner session changed");
    Ok(HostAuthResult {
        operation_id: record.operation_id.clone(),
        outcome: match record.phase {
            AuthPhase::Committed => HostAuthOutcome::Committed,
            AuthPhase::RolledBack => HostAuthOutcome::RolledBack,
            _ => HostAuthOutcome::Unknown,
        },
        session_sha256: if committed { record.candidate_sha256.clone() } else { None },
        path: record.profile.join("session.json"),
        super_password: if committed { Some(verify_candidate(record)?) } else { None },
    })
}

fn keygen_overwrite_guard(profile: &Path, original: Option<&[u8]>, force: bool) -> Result<()> {
    let session: Value = match original {
        Some(bytes) => serde_json::from_slice(bytes).context("invalid keygen session; original files preserved")?,
        None => json!({}),
    };
    ensure!(session.is_object(), "keygen session must be an object");
    let has_wrap = session["wrapped_urk"].as_str().is_some_and(|wrap| !wrap.is_empty());
    if force { return Ok(()); }
    ensure!(!has_wrap || (!session["user"].as_str().is_some_and(|user| !user.is_empty())
        && !session["token"].as_str().is_some_and(|token| !token.is_empty())),
        "keygen would replace cloud key material; back up first and use force explicitly");
    let path = crate::service::database_path(profile)?;
    if path.exists() {
        let database = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let memories: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')", [], |row| row.get(0))?;
        if memories {
            let count: i64 = database.query_row("SELECT COUNT(*) FROM memories WHERE deleted = 0", [], |row| row.get(0))?;
            ensure!(count == 0, "keygen would replace keys for existing memories; back up first and use force explicitly");
        }
    }
    Ok(())
}

fn keygen_fingerprint(root: &Path, profile: &Path, force: bool) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&json!({"schema_version":respire_protocol::HOST_AUTH_SCHEMA_V,
        "method":"control.auth.keygen", "root":root,"profile":profile,"force":force}))?))
}

fn require_persistent_auth_backend(backend: &str) -> Result<()> {
    ensure!(backend != "kernel", "offline auth requires a persistent credential backend; the volatile kernel keyring cannot recover this transaction");
    Ok(())
}

/// The caller supplies ownership only after checking the inherited launch capability.
/// Replays and result queries never generate replacement key material.
pub fn control_keygen(
    ownership: &AuthOwnership, identity: &HostAuthIdentity, operation_id: &str,
    idempotency_key: &str, force: bool, query_only: bool,
) -> Result<HostAuthResult> {
    crate::service::require_profile_change_host()?;
    canonical_operation_id(operation_id)?;
    ensure!(!idempotency_key.is_empty() && idempotency_key.len() <= 128
        && idempotency_key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "invalid auth idempotency key");
    ensure!(ownership.root == crate::service::main_data_dir().canonicalize()?
        && ownership.profile == crate::service::data_dir().canonicalize()?, "auth ownership changed");
    let mut journal = load_journal()?;
    ensure!(!journal.active.as_ref().is_some_and(|active| active.operation_id.is_some()),
        "recover the owned auth transaction before executing or querying it");
    ensure!(journal.active.is_none(), "interrupted login must be recovered before auth control");
    verify_auth_identity(&ownership.root, &ownership.profile, identity)?;
    let fingerprint = keygen_fingerprint(&ownership.root, &ownership.profile, force)?;
    if let Some(record) = journal.operations.iter().find(|record|
        record.operation_id == operation_id || (record.root == ownership.root && record.idempotency_key == idempotency_key)) {
        ensure!(record.operation_id == operation_id && record.idempotency_key == idempotency_key
            && record.fingerprint == fingerprint && record.root == ownership.root && record.profile == ownership.profile,
            "auth idempotency conflict");
        return auth_result(record);
    }
    ensure!(!query_only, "auth operation has no admission receipt");
    // Retaining receipts is necessary to prevent an old operation ID from rotating keys again.
    ensure!(journal.operations.len() < 4096, "auth receipt capacity reached; existing results remain queryable");
    let original = read_original(&ownership.profile)?;
    keygen_overwrite_guard(&ownership.profile, original.as_deref(), force)?;
    let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
    let config = match std::fs::read(crate::service::client_config_path()) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    journal.active = Some(Recovery { directory: ownership.profile.clone(), original: original.clone(), config,
        alias: alias.clone(), backends: Vec::new(), pass_backends: Vec::new(), directory_existed: true,
        operation_id: Some(operation_id.to_owned()), owns_config: false });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: operation_id.to_owned(), idempotency_key: idempotency_key.to_owned(),
        fingerprint, root: ownership.root.clone(), profile: ownership.profile.clone(), original_sha256: original.as_deref().map(digest),
        candidate: None, candidate_sha256: None, alias: alias.clone(), backend: None, phase: AuthPhase::Admitted, account: None });
    save_journal(&journal)?;
    let mutation = (|| -> Result<()> {
        let (secret, _urk, salt, wrapped, nonce) = crate::auth::new_vault_v4()?;
        let mut session = json!({"vault_version":4,"kdf_salt":salt,"wrapped_urk":wrapped,
            "urk_nonce":nonce,"keyring_account":alias,"auth_operation_id":operation_id});
        let backend = crate::keystore::import_credential_checkpoint(&alias, "super", &secret, |backend| {
            require_persistent_auth_backend(backend)?;
            journal.active.as_mut().context("auth recovery is missing")?.backends.push(backend.to_owned());
            session["keyring_backend"] = json!(backend);
            let candidate = serde_json::to_vec_pretty(&session)?;
            journal.operations[index].backend = Some(backend.to_owned());
            journal.operations[index].candidate_sha256 = Some(digest(&candidate));
            journal.operations[index].candidate = Some(candidate);
            save_journal(&journal)
        })?;
        ensure!(journal.operations[index].backend.as_deref() == Some(backend), "auth backend checkpoint mismatch");
        verify_candidate(&journal.operations[index])?;
        journal.operations[index].phase = AuthPhase::Prepared;
        save_journal(&journal)?;
        ensure!(read_original(&ownership.profile)? == original, "auth session changed before commit");
        private_write(&ownership.profile.join("session.json"),
            journal.operations[index].candidate.as_deref().context("auth candidate is missing")?)?;
        journal.operations[index].phase = AuthPhase::Committed;
        retire_active(&mut journal)
    })();
    if let Err(error) = mutation {
        // Re-read durable state: a failed terminal fsync may follow a committed session.
        journal = load_journal()?;
        if journal.active.is_some() { recover_keygen(&mut journal, &ownership.root, &ownership.profile)?; }
        if journal.operations.get(index).is_some_and(|record| record.phase == AuthPhase::Committed) {
            save_journal(&journal)?;
            return auth_result(&journal.operations[index]);
        }
        return Err(error.context("auth keygen did not commit; query its retained operation receipt"));
    }
    auth_result(&journal.operations[index])
}

fn checkpoint_account_candidate(journal: &mut Journal, index: usize, session: &Value) -> Result<()> {
    ensure!(session.get("pass").is_none() && session.get("super").is_none(), "plaintext factors cannot enter recovery");
    let bytes = serde_json::to_vec_pretty(session)?;
    journal.operations[index].candidate_sha256 = Some(digest(&bytes));
    journal.operations[index].candidate = Some(bytes);
    Ok(())
}

fn account_fingerprint(ownership: &AuthOwnership, identity: &HostAuthIdentity, register: bool, addr: &str, user: &str) -> Result<String> {
    // Replays never consume replacement credentials or repeat a remote request.
    // Do not put a password or an offline password verifier in the receipt.
    Ok(digest(&serde_json::to_vec(&json!({"schema_version":1,"register":register,
        "root":ownership.root,"source":ownership.profile,"identity":identity,"addr":addr,"user":user}))?))
}

fn admit_account(ownership: &AuthOwnership, identity: &HostAuthIdentity, operation_id: &str,
    key: &str, register: bool, addr: &str, user: &str) -> Result<(Journal, usize, bool)> {
    crate::service::require_profile_change_host()?;
    canonical_operation_id(operation_id)?;
    ensure!(!key.is_empty() && key.len() <= 128 && key.bytes().all(|byte|
        byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)), "invalid auth idempotency key");
    ensure!(ownership.root == crate::service::main_data_dir().canonicalize()?
        && ownership.profile == crate::service::data_dir().canonicalize()?, "auth ownership changed");
    ensure!(!user.is_empty() && !addr.is_empty(), "account and server are required");
    verify_auth_identity(&ownership.root, &ownership.profile, identity)?;
    let fingerprint = account_fingerprint(ownership, identity, register, addr, user)?;
    let mut journal = load_journal()?;
    if let Some(index) = journal.operations.iter().position(|record|
        record.operation_id == operation_id || record.idempotency_key == key) {
        let record = &journal.operations[index];
        ensure!(record.operation_id == operation_id && record.idempotency_key == key
            && record.root == ownership.root && record.profile == ownership.profile
            && record.fingerprint == fingerprint && record.account.is_some(), "auth idempotency conflict");
        return Ok((journal, index, false));
    }
    ensure!(journal.active.is_none(), "resolve the interrupted transaction before admitting another account operation");
    ensure!(journal.operations.len() < 4096, "auth receipt capacity reached");
    let original = read_original(&ownership.profile)?;
    let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
    journal.active = Some(Recovery { directory: ownership.profile.clone(), original: original.clone(),
        config: None, alias: alias.clone(), backends: Vec::new(), pass_backends: Vec::new(),
        directory_existed: true, operation_id: Some(operation_id.to_owned()), owns_config: false });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: operation_id.to_owned(), idempotency_key: key.to_owned(),
        fingerprint, root: ownership.root.clone(), profile: ownership.profile.clone(),
        original_sha256: original.as_deref().map(digest), candidate: None, candidate_sha256: None,
        alias, backend: None, phase: AuthPhase::Admitted, account: Some(AccountOperation {
            register, addr: addr.to_owned(), user: user.to_owned(), source_identity: identity.clone(),
            target: None, authorization: None, vault: None, published_vault: false, vault_pending: false,
        }) });
    save_journal(&journal)?;
    Ok((journal, index, true))
}

fn account_result(record: &AuthRecord) -> Result<HostAuthAccountResult> {
    let account = record.account.as_ref().context("operation is not account authentication")?;
    let applied = record.phase == AuthPhase::AwaitingVerification || record.phase == AuthPhase::Committed;
    if applied { verify_account_candidate(record)?; }
    Ok(HostAuthAccountResult { operation_id: record.operation_id.clone(),
        outcome: match record.phase {
            _ if account.vault_pending && !account.published_vault => HostAuthAccountOutcome::Unknown,
            AuthPhase::AwaitingVerification => HostAuthAccountOutcome::AwaitingVerification,
            AuthPhase::Committed => HostAuthAccountOutcome::Committed,
            AuthPhase::RolledBack => HostAuthAccountOutcome::RolledBack,
            _ => HostAuthAccountOutcome::Unknown,
        }, source_profile: record.profile.clone(), target_profile: account.target.clone(),
        account_id: if applied { Some(digest(account.user.as_bytes())) } else { None },
        session_sha256: if applied { record.candidate_sha256.clone() } else { None },
        super_password: if account.register && applied {
            Some(crate::keystore::read_imported(&record.alias, "super", record.backend.as_deref().context("account backend is missing")?)?)
        } else { None },
    })
}

fn commit_account(ownership: &AuthOwnership, journal: &mut Journal, index: usize, prepared: &mut PreparedLogin) -> Result<HostAuthAccountResult> {
    ensure!(read_original(&ownership.profile)?.as_deref().map(digest) == journal.operations[index].original_sha256,
        "source profile changed before account commit");
    ensure!(read_original(&prepared.directory)? == prepared.original, "target profile changed before account commit");
    prepared.alias = journal.operations[index].alias.clone();
    prepared.session["keyring_account"] = json!(prepared.alias);
    let active = journal.active.as_mut().context("account recovery is missing")?;
    active.directory = prepared.directory.clone();
    active.original = prepared.original.clone();
    active.directory_existed = prepared.directory.exists();
    active.config = match std::fs::read(crate::service::client_config_path()) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    active.owns_config = true;
    journal.operations[index].account.as_mut().context("account receipt is missing")?.target = Some(prepared.directory.clone());
    checkpoint_account_candidate(journal, index, &prepared.session)?;
    save_journal(journal)?;
    // Lock creation can create a new target directory, so its prior absence was journaled above.
    let target = if prepared.directory.exists() { prepared.directory.canonicalize()? } else { prepared.directory.clone() };
    let _target_lock = if target == ownership.root || target == ownership.profile { None }
        else { Some(crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?) };
    ensure!(read_original(&prepared.directory)? == prepared.original, "target changed while acquiring ownership");
    prepared.commit_inner_for(Some(&journal.operations[index].operation_id))?;
    *journal = load_journal()?;
    account_result(&journal.operations[index])
}

/// A durable pending receipt is written before POST; an interrupted POST is never replayed.
pub fn control_register(ownership: &AuthOwnership, operation_id: &str, key: &str,
    params: &HostAuthRegisterParams) -> Result<HostAuthAccountResult> {
    ensure!(params.schema_version == respire_protocol::HOST_AUTH_SCHEMA_V
        && params.binding.installation_root == ownership.root && params.binding.profile == ownership.profile,
        "registration binding mismatch");
    let addr = params.addr.trim().trim_end_matches('/');
    let (mut journal, index, fresh) = admit_account(ownership, &params.identity, operation_id, key, true, addr, &params.user)?;
    if !fresh { return account_result(&journal.operations[index]); }
    let source = read_original(&ownership.profile)?;
    let local: Value = match source { Some(bytes) => serde_json::from_slice(&bytes)?, None => json!({}) };
    let (secret, vault) = if local["wrapped_urk"].as_str().is_some_and(|wrap| !wrap.is_empty())
        && !local["user"].as_str().is_some_and(|user| !user.is_empty()) {
        let secret = match &params.identity {
            HostAuthIdentity::Unbound { operation_id, .. } => {
                let source = journal.operations.iter().find(|record| record.operation_id == *operation_id)
                    .context("unbound source receipt is missing")?;
                verify_candidate(source)?
            }
            _ => anyhow::bail!("registration requires a receipt-backed unbound vault"),
        };
        if let Some(expected) = &params.super_password { ensure!(*expected == secret, "recovery code does not match the unbound vault"); }
        (secret, json!({"version":local["vault_version"],"kdf_salt":local["kdf_salt"],
            "wrapped_urk":local["wrapped_urk"],"urk_nonce":local["urk_nonce"]}))
    } else {
        let (secret, _, salt, wrapped, nonce) = crate::auth::new_vault_v4()?;
        (secret, json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce}))
    };
    let alias = journal.operations[index].alias.clone();
    let use_source = matches!(&params.identity, HostAuthIdentity::Absent | HostAuthIdentity::Unbound { .. });
    journal.operations[index].account.as_mut().context("account receipt is missing")?.vault = Some(vault.clone());
    crate::keystore::import_credential_checkpoint(&alias, "super", &secret, |backend| {
        require_persistent_auth_backend(backend)?;
        journal.operations[index].backend = Some(backend.to_owned());
        journal.active.as_mut().context("account recovery is missing")?.backends.push(backend.to_owned());
        save_journal(&journal)
    })?;
    journal.operations[index].phase = AuthPhase::RemotePending;
    save_journal(&journal)?;
    let authorized = match crate::auth::registration_authorization(addr, &params.user, &params.password) {
        Ok(authorization) => authorization,
        Err(error) => {
            journal.operations[index].phase = AuthPhase::RemoteUnknown;
            save_journal(&journal)?;
            return Err(error.context("registration outcome unknown; query the original operation, do not resend"));
        }
    };
    journal.operations[index].account.as_mut().context("account receipt is missing")?.authorization = Some(authorized.clone());
    journal.operations[index].phase = AuthPhase::Authorized;
    save_journal(&journal)?;
    let mut prepared = PreparedLogin::prepare_with_vault_inner(addr, &authorized, secret, vault, None, use_source)?;
    commit_account(ownership, &mut journal, index, &mut prepared)
}

pub fn control_login(ownership: &AuthOwnership, operation_id: &str, key: &str,
    params: &HostAuthLoginParams) -> Result<HostAuthAccountResult> {
    ensure!(params.schema_version == respire_protocol::HOST_AUTH_SCHEMA_V
        && params.binding.installation_root == ownership.root && params.binding.profile == ownership.profile,
        "login binding mismatch");
    let addr = params.addr.trim().trim_end_matches('/');
    let (mut journal, index, fresh) = admit_account(ownership, &params.identity, operation_id, key, false, addr, &params.user)?;
    if !fresh { return account_result(&journal.operations[index]); }
    journal.operations[index].phase = AuthPhase::RemotePending;
    save_journal(&journal)?;
    let mut authorized = match &params.authorization {
        HostAuthAuthorization::Password { password, totp } =>
            crate::auth::password_authorization_noninteractive(addr, &params.user, password, totp.as_deref())?,
        HostAuthAuthorization::Browser { token, session_id } => {
            ensure!(!token.is_empty(), "browser authorization token is missing");
            json!({"addr":addr,"user":params.user,"token":token,"session_id":session_id})
        }
    };
    let mut durable_authorization = authorized.clone();
    durable_authorization.as_object_mut().context("authorization must be an object")?.remove("pass");
    journal.operations[index].account.as_mut().context("account receipt is missing")?.authorization = Some(durable_authorization);
    journal.operations[index].phase = AuthPhase::Authorized;
    save_journal(&journal)?;
    let vault = PreparedLogin::fetch_vault(addr, &authorized)?;
    ensure!(!vault.is_null(), "cloud vault is absent; original key material was preserved");
    let mut prepared = PreparedLogin::prepare_with_vault(addr, &authorized, params.super_password.clone(), vault, None)?;
    authorized.as_object_mut().map(|object| object.remove("pass"));
    commit_account(ownership, &mut journal, index, &mut prepared)
}

/// Result recovery never authenticates again and never resends a registration.
pub fn control_account_result(ownership: &AuthOwnership, identity: &HostAuthIdentity,
    operation_id: &str, key: &str) -> Result<HostAuthAccountResult> {
    verify_auth_identity(&ownership.root, &ownership.profile, identity)?;
    let mut journal = load_journal()?;
    let index = owned_account_index(&journal, &ownership.root, &ownership.profile, operation_id, key)?;
    let record = &journal.operations[index];
    if record.phase == AuthPhase::Prepared {
        let target = record.account.as_ref().and_then(|account| account.target.as_ref()).context("account target is missing")?;
        let active = journal.active.as_ref().context("account recovery is missing")?;
        ensure!(active.operation_id.as_deref() == Some(operation_id) && active.directory == *target
            && active.alias == record.alias && active.owns_config, "account recovery binding mismatch");
        let _target_lock = if *target == ownership.root || *target == ownership.profile { None }
            else { Some(crate::lock::LibraryLock::acquire(target, std::time::Duration::from_secs(1))?) };
        let current = read_original(target)?;
        ensure!(current == record.candidate || current == active.original, "interrupted account session changed");
        verify_account_material(record, false)?;
        verify_account_config(active)?;
        if current != record.candidate {
            private_write(&target.join("session.json"), record.candidate.as_deref().context("account candidate is missing")?)?;
        }
        crate::service::set_data_dir(&target.to_string_lossy())?;
        journal.operations[index].phase = AuthPhase::AwaitingVerification;
        save_journal(&journal)?;
    }
    if journal.operations[index].phase == AuthPhase::AwaitingVerification || journal.operations[index].phase == AuthPhase::Committed {
        verify_account_candidate(&journal.operations[index])?;
    }
    account_result(&journal.operations[index])
}

fn owned_account_index(journal: &Journal, root: &Path, profile: &Path, id: &str, key: &str) -> Result<usize> {
    canonical_operation_id(id)?;
    let index = journal.operations.iter().position(|record| record.operation_id == id && record.idempotency_key == key)
        .context("account admission receipt is missing")?;
    let record = &journal.operations[index];
    let account = record.account.as_ref().context("operation is not account authentication")?;
    ensure!(record.root == root && (record.profile == profile || account.target.as_deref() == Some(profile)), "account receipt owner mismatch");
    let current = read_original(profile)?;
    ensure!((record.profile == profile && current.as_deref().map(digest) == record.original_sha256)
        || (account.target.as_deref() == Some(profile) && current.is_some() && current == record.candidate),
        "account receipt no longer owns the selected session");
    Ok(index)
}

fn verify_account_candidate(record: &AuthRecord) -> Result<()> {
    verify_account_material(record, true)
}

fn verify_account_material(record: &AuthRecord, require_published: bool) -> Result<()> {
    let account = record.account.as_ref().context("account receipt is missing")?;
    let target = account.target.as_ref().context("account target is missing")?;
    let bytes = record.candidate.as_deref().context("account candidate is missing")?;
    ensure!(record.candidate_sha256.as_deref() == Some(digest(bytes).as_str())
        && (!require_published || read_original(target)?.as_deref() == Some(bytes)), "account candidate changed");
    let session: Value = serde_json::from_slice(bytes)?;
    ensure!(session["user"].as_str() == Some(account.user.as_str())
        && session["addr"].as_str() == Some(account.addr.as_str())
        && session["keyring_account"].as_str() == Some(record.alias.as_str()), "account candidate identity mismatch");
    let backend = record.backend.as_deref().context("account credential checkpoint is missing")?;
    require_persistent_auth_backend(backend)?;
    let secret = crate::keystore::read_imported(&record.alias,
        if session["vault_version"] == 1 { "pass" } else { "super" }, backend)?;
    let salt = session["kdf_salt"].as_str().context("account salt is missing")?;
    let wrapped = session["wrapped_urk"].as_str().context("account wrap is missing")?;
    let nonce = session["urk_nonce"].as_str().context("account nonce is missing")?;
    match session["vault_version"].as_i64() {
        Some(1) => crate::memory::SessionKeys::unlock(&secret, session["secret"].as_str().context("original account secret is missing")?, salt, wrapped, nonce)?,
        Some(2) => crate::memory::SessionKeys::unlock_super(&secret, salt, wrapped, nonce)?,
        Some(3) => crate::memory::SessionKeys::unlock_vault(&secret, session["secret_key"].as_str().context("original secret key is missing")?, salt, wrapped, nonce)?,
        Some(4) => crate::memory::SessionKeys::unlock_v4(&secret, salt, wrapped, nonce)?,
        _ => anyhow::bail!("unsupported account vault"),
    };
    Ok(())
}

fn verify_account_config(active: &Recovery) -> Result<()> {
    let current = match std::fs::read(crate::service::client_config_path()) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if current != active.config {
        let mut expected: Value = match &active.config { Some(bytes) => serde_json::from_slice(bytes)?, None => json!({}) };
        expected["data_dir"] = json!(active.directory.to_string_lossy());
        ensure!(current.as_ref().map(|bytes| serde_json::from_slice::<Value>(bytes)).transpose()? == Some(expected),
            "client configuration changed outside the account transaction; retain recovery");
    }
    Ok(())
}

/// Completion owns the journal, not the running store's library lock. The callback
/// must independently verify the live target Runtime; a client boolean is not proof.
pub fn control_account_complete(root: &Path, profile: &Path, identity: &HostAuthIdentity,
    operation_id: &str, key: &str, mut verify_runtime: impl FnMut(&HostAuthAccountResult) -> Result<()>) -> Result<HostAuthAccountResult> {
    crate::service::require_profile_change_host()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    ensure!(root == crate::service::main_data_dir().canonicalize()?
        && profile == crate::service::data_dir().canonicalize()?, "completion selection changed");
    let _journal_lock = auth_journal_lock()?;
    verify_auth_identity(&root, &profile, identity)?;
    let mut journal = load_journal()?;
    let index = owned_account_index(&journal, &root, &profile, operation_id, key)?;
    let record = &journal.operations[index];
    verify_account_candidate(record)?;
    ensure!(record.account.as_ref().and_then(|account| account.target.as_deref()) == Some(profile.as_path()),
        "completion requires the receipt's selected target");
    if record.phase == AuthPhase::Committed { return account_result(record); }
    ensure!(record.phase == AuthPhase::AwaitingVerification, "account is not ready for runtime verification");
    ensure!(journal.active.as_ref().and_then(|active| active.operation_id.as_deref()) == Some(operation_id),
        "completion does not own active recovery");
    verify_runtime(&account_result(record)?)?;
    let account = record.account.as_ref().context("account receipt is missing")?;
    if account.register && !account.published_vault {
        let authorized = account.authorization.clone().context("registration authorization is missing")?;
        let addr = account.addr.clone();
        let vault = account.vault.clone().context("registration vault is missing")?;
        let pending = account.vault_pending;
        let current = PreparedLogin::fetch_vault(&addr, &authorized)?;
        if current != vault {
            ensure!(current.is_null(), "server vault differs; preserve local credentials and receipt");
            if pending { return account_result(&journal.operations[index]); }
            journal.operations[index].account.as_mut().context("account receipt is missing")?.vault_pending = true;
            save_journal(&journal)?;
            let token = authorized["token"].as_str().context("registration token is missing")?;
            let sent = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
                .post(&format!("{addr}/api/self/vault"))
                .set("Authorization", &format!("Bearer {token}")).set("If-None-Match", "*").send_json(vault.clone());
            if sent.is_err() && PreparedLogin::fetch_vault(&addr, &authorized)? != vault {
                return account_result(&journal.operations[index]);
            }
        }
        journal.operations[index].account.as_mut().context("account receipt is missing")?.published_vault = true;
        save_journal(&journal)?;
    }
    verify_account_candidate(&journal.operations[index])?;
    verify_runtime(&account_result(&journal.operations[index])?)?;
    journal.operations[index].phase = AuthPhase::Committed;
    retire_active(&mut journal)?;
    account_result(&journal.operations[index])
}

pub fn control_account_rollback(mut ownership: AuthOwnership, identity: &HostAuthIdentity,
    operation_id: &str, key: &str) -> Result<HostAuthAccountResult> {
    crate::service::require_profile_change_host()?;
    verify_auth_identity(&ownership.root, &ownership.profile, identity)?;
    let mut journal = load_journal()?;
    let index = owned_account_index(&journal, &ownership.root, &ownership.profile, operation_id, key)?;
    let record = &journal.operations[index];
    if record.phase == AuthPhase::RolledBack { return account_result(record); }
    ensure!(record.phase != AuthPhase::Committed && record.phase != AuthPhase::RemotePending
        && record.phase != AuthPhase::RemoteUnknown, "remote outcome must be resolved before compensation");
    let account = record.account.as_ref().context("account receipt is missing")?;
    ensure!(!account.vault_pending && !account.published_vault, "published or unknown remote vault cannot be compensated by deleting local keys");
    let active = journal.active.as_ref().context("account recovery is missing")?;
    ensure!(active.operation_id.as_deref() == Some(operation_id), "rollback does not own recovery");
    let target_lock = if !active.directory.exists() || active.directory == ownership.root || active.directory == ownership.profile { None }
        else { Some(crate::lock::LibraryLock::acquire(&active.directory, std::time::Duration::from_secs(1))?) };
    let current = read_original(&active.directory)?;
    ensure!(current == active.original || current == record.candidate, "target session changed outside the transaction");
    if active.owns_config {
        verify_account_config(active)?;
    }
    journal.operations[index].phase = AuthPhase::RollingBack;
    save_journal(&journal)?;
    rollback_record_inner(journal.active.as_ref().context("account recovery is missing")?, false)?;
    // Windows cannot quarantine a directory while SQLite still owns its lock file.
    // The root/source guards and the durable RollingBack record remain held.
    drop(target_lock);
    if journal.active.as_ref().is_some_and(|active| !active.directory_existed && active.directory == ownership.profile) {
        drop(ownership._profile_lock.take());
    }
    quarantine_new_profile(journal.active.as_ref().context("account recovery is missing")?)?;
    journal.operations[index].phase = AuthPhase::RolledBack;
    retire_active(&mut journal)?;
    account_result(&journal.operations[index])
}

impl PreparedLogin {
    pub fn prepare(addr: &str, authorized: &Value, super_password: String) -> Result<Self> {
        let vault = Self::fetch_vault(addr, authorized)?;
        Self::prepare_with_vault(addr, authorized, super_password, vault, None)
    }

    pub fn fetch_vault(addr: &str, authorized: &Value) -> Result<Value> {
        let token = authorized["token"].as_str().filter(|token| !token.is_empty()).context("authorization did not return a token")?;
        match ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .get(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {token}")).call() {
            Ok(response) => response.into_json().map_err(Into::into),
            Err(ureq::Error::Status(404, _)) => Ok(Value::Null),
            Err(error) => Err(error).context("could not fetch the account vault"),
        }
    }

    /// Publish only a fully migrated library's wrap, preserving its original factors.
    pub fn prepare_migration(addr: &str, authorized: &Value, password: &str, legacy_super: Option<&str>, secret_key: Option<&str>, new_super: Option<&str>) -> Result<Self> {
        crate::service::require_profile_change_host()?;
        let mut local = crate::auth::read_session_json()?;
        ensure!(local["user"] == authorized["user"], "select the migrated account before publishing its vault");
        ensure!(local["crypto_namespace"].as_str() == Some(crate::memory::crypto::RSRS_PREFIX),
            "run rsrs migrate --source <source> --account <new-account> first; changing only a vault wrap is not a full migration");
        let original = local.clone();
        let version = local["vault_version"].as_i64().context("local vault missing version")?;
        if let Some(secret) = secret_key.filter(|value| !value.is_empty()) {
            local[if version == 1 { "secret" } else { "secret_key" }] = json!(secret);
        }
        let user = authorized["user"].as_str().context("authorization did not return a user")?;
        let alias = local["keyring_account"].as_str().unwrap_or(user);
        let super_password = if version == 1 {
            ensure!(new_super.is_none() && legacy_super.is_none(), "v1 uses the original login password and Account Secret, not a super Key");
            String::new()
        } else {
            legacy_super.filter(|value| !value.is_empty()).map(str::to_owned)
                .or_else(|| crate::keystore::load_super(alias))
                .context("the original super Key is required; no replacement Key was generated")?
        };
        ensure!(new_super.is_none_or(|value| value == super_password),
            "migration preserves the original super Key; --new-super cannot replace it");
        let keys = crate::auth::unlock_session_keys(&local, password, Some(&super_password), alias)?;
        let cloud = Self::fetch_vault(addr, authorized)?;
        if !cloud.is_null() {
            ensure!(cloud["version"] == local["vault_version"], "migration must preserve the original vault factors");
            let mut cloud_session = local.clone();
            for field in ["kdf_salt", "wrapped_urk", "urk_nonce"] { cloud_session[field] = cloud[field].clone(); }
            let cloud_keys = crate::auth::unlock_session_keys(&cloud_session, password, Some(&super_password), alias)?;
            ensure!(cloud_keys.urk == keys.urk, "cloud and local vault data keys differ; original data was preserved");
        }
        let vault = json!({"version":local["vault_version"],"kdf_salt":local["kdf_salt"],"wrapped_urk":local["wrapped_urk"],"urk_nonce":local["urk_nonce"]});
        let mut factors = authorized.clone();
        factors["pass"] = json!(password);
        if version == 1 { factors["secret"] = local["secret"].clone(); }
        let mut prepared = Self::prepare_with_vault(addr, &factors, super_password, vault.clone(), Some((original, keys.urk)))?;
        if cloud != vault { prepared.migration_cloud = Some(cloud); }
        // Explicit cloud migration recalculates the authentication hash from the
        // same login password. Ordinary login never changes this stored salt.
        let salt = crate::memory::crypto::derive_auth_salt(user)?;
        let pass_hash = crate::memory::crypto::derive_pass_hash(password, &salt)?;
        prepared.session["auth_salt"] = json!(salt);
        prepared.login_password = Some(password.to_owned());
        prepared.migration_auth = Some(json!({"salt":salt,"pass_hash":pass_hash}));
        ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .get(&format!("{}/auth/salt", addr.trim().trim_end_matches('/'))).query("user", user).call()
            .context("cloud namespace migration requires a server supporting /auth/salt; original password was preserved")?;
        Ok(prepared)
    }

    pub fn migration_super_password(&self) -> Option<&str> {
        None
    }

    /// Publish the unchanged URK's new wrap only after host/runtime verification.
    pub fn finish_migration(&self, addr: &str, authorized: &Value) -> Result<()> {
        if self.migration_cloud.is_none() && self.migration_auth.is_none() { return Ok(()); }
        let token = authorized["token"].as_str().context("authorization did not return a token")?;
        if let Some(original) = self.migration_cloud.as_ref() {
        ensure!(Self::fetch_vault(addr, authorized)? == *original, "cloud vault changed during migration; original local session was restored");
        let vault = json!({"version":self.session["vault_version"],"kdf_salt":self.session["kdf_salt"],"wrapped_urk":self.session["wrapped_urk"],"urk_nonce":self.session["urk_nonce"]});
        let mut request = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .post(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {token}"));
        if original.is_null() { request = request.set("If-None-Match", "*"); }
        let result = request.send_json(vault.clone());
        if let Err(error) = result {
            // A lost HTTP response can follow a committed write; inspect that exact wrap once.
            if !Self::fetch_vault(addr, authorized).is_ok_and(|current| current == vault) {
                return Err(anyhow!("legacy vault publication failed: {error}; retain the original super Key and library"));
            }
        }
        }
        if let Some(authentication) = self.migration_auth.as_ref() {
            let agent = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build();
            let result = agent.post(&format!("{}/api/self/password", addr.trim().trim_end_matches('/')))
                .set("Authorization", &format!("Bearer {token}")).send_json(authentication.clone());
            if let Err(error) = result {
                let confirmed: Value = agent.get(&format!("{}/auth/salt", addr.trim().trim_end_matches('/')))
                    .query("user", &self.user).call()?.into_json()?;
                ensure!(confirmed["salt"] == authentication["salt"],
                    "authentication namespace publication failed: {error}; retry explicit migration with the original password");
            }
        }
        Ok(())
    }

    pub fn prepare_with_vault(addr: &str, authorized: &Value, super_password: String, vault: Value, legacy: Option<(Value, [u8; 32])>) -> Result<Self> {
        Self::prepare_with_vault_inner(addr, authorized, super_password, vault, legacy, false)
    }

    fn prepare_with_vault_inner(addr: &str, authorized: &Value, super_password: String, vault: Value,
        legacy: Option<(Value, [u8; 32])>, registration_source: bool) -> Result<Self> {
        crate::service::require_profile_change_host()?;
        let user = authorized["user"].as_str().filter(|user| !user.is_empty()).context("authorization did not return a user")?.to_owned();
        let token = authorized["token"].as_str().filter(|token| !token.is_empty()).context("authorization did not return a token")?;
        let base = addr.trim().trim_end_matches('/');
        let version = vault["version"].as_i64().context("vault missing version")?;
        ensure!((1..=4).contains(&version), "unsupported vault version; original factors were preserved");
        let salt = vault["kdf_salt"].as_str().context("vault missing kdf_salt")?;
        let wrapped = vault["wrapped_urk"].as_str().context("vault missing wrapped_urk")?;
        let nonce = vault["urk_nonce"].as_str().context("vault missing urk_nonce")?;
        let current = crate::service::data_dir();
        let mut directory = if (registration_source && crate::service::session_user_of_dir(&current).is_empty())
            || (legacy.is_some() && crate::service::session_user_of_dir(&current) == user) {
            current.clone()
        } else { login_directory(base, &user)? };
        let original = read_original(&directory)?;
        let mut session: Value = match original.as_deref() {
            Some(bytes) => serde_json::from_slice(bytes).context("target account session is invalid; original files were preserved")?,
            None => json!({}),
        };
        ensure!(session.is_object(), "target account session must be an object");
        let previous_alias = session["keyring_account"].as_str().unwrap_or(&user);
        let login_password = authorized["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned)
            .or_else(|| if version == 1 { crate::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty()) } else { None })
            .or_else(|| session["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned))
            .or_else(|| crate::keystore::load_login_pass(previous_alias));
        let account_secret = authorized["secret"].as_str().filter(|value| !value.is_empty())
            .or_else(|| session["secret"].as_str().filter(|value| !value.is_empty())).map(str::to_owned);
        let verified = match version {
            1 => crate::memory::SessionKeys::unlock(
                login_password.as_deref().context("original v1 login password is required")?,
                account_secret.as_deref().context("original v1 Account Secret is required")?, salt, wrapped, nonce),
            2 => crate::memory::SessionKeys::unlock_super(&super_password, salt, wrapped, nonce),
            3 => crate::memory::SessionKeys::unlock_vault(&super_password,
                session["secret_key"].as_str().context("original Secret Key is required; select the explicitly migrated profile")?,
                salt, wrapped, nonce),
            _ => crate::memory::SessionKeys::unlock_v4(&super_password, salt, wrapped, nonce),
        }.context("original decryption factors do not unlock this account; the original account was preserved")?;
        if original.is_none() && legacy.is_none() {
            let plain = crate::service::account_dir(&user)?;
            let suffix = hex::encode(sha2::Sha256::digest(format!("{base}\n{user}").as_bytes()));
            let isolated = crate::service::account_dir(&format!("{user}-{}", &suffix[..16]))?;
            for candidate in [current, crate::service::main_data_dir(), plain, isolated] {
                if read_original(&candidate)?.is_none() && library_accepts_keys(&candidate, &verified)? {
                    directory = candidate;
                    break;
                }
            }
        }
        ensure!(session["user"].as_str().is_none_or(|owner| owner.is_empty() || owner == user), "destination belongs to another account");
        if let Some((original, urk)) = legacy.as_ref() {
            ensure!(session == *original && verified.urk == *urk, "legacy session changed or migration would replace its data key");
        }
        let database = crate::service::database_path(&directory)?;
        if database.is_file() {
            let database = rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let has_memories: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')", [], |row| row.get(0))?;
            if has_memories {
                let count: i64 = database.query_row("SELECT count(*) FROM memories WHERE ciphertext <> ''", [], |row| row.get(0))?;
                if count > 0 {
                    let same_wrap = session["kdf_salt"] == vault["kdf_salt"] && session["wrapped_urk"] == vault["wrapped_urk"] && session["urk_nonce"] == vault["urk_nonce"];
                    if legacy.is_none() && !same_wrap {
                        // Full logout removes the wrap, and a super-password change can
                        // rewrap the same URK. Prove compatibility against local data.
                        ensure!(library_accepts_keys(&directory, &verified)?,
                            "local library uses different key material or compatibility could not be verified; original data was preserved");
                    }
                }
            }
        }
        let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        if version == 1 { session["secret"] = json!(account_secret.context("original v1 Account Secret is required")?); }
        for field in ["pass", "super"] { session.as_object_mut().map(|object| object.remove(field)); }
        if version >= 4 {
            for field in ["secret", "secret_key"] { session.as_object_mut().map(|object| object.remove(field)); }
        }
        session["user"] = json!(user);
        session["addr"] = json!(base);
        session["token"] = json!(token);
        session["session_id"] = authorized["session_id"].clone();
        let local_wrap = [session["kdf_salt"].clone(), session["wrapped_urk"].clone(), session["urk_nonce"].clone()];
        session["vault_version"] = json!(version);
        session["kdf_salt"] = vault["kdf_salt"].clone();
        session["wrapped_urk"] = vault["wrapped_urk"].clone();
        session["urk_nonce"] = vault["urk_nonce"].clone();
        if session["crypto_namespace"].as_str() == Some(crate::memory::crypto::RSRS_PREFIX)
            && !wrapped.starts_with(crate::memory::crypto::RSRS_PREFIX) {
            // A local explicit namespace migration can precede cloud rewrapping.
            // Keep its current namespace after verifying the cloud URK above.
            ensure!(local_wrap[1].as_str().is_some_and(|value| value.starts_with(crate::memory::crypto::RSRS_PREFIX)),
                "migrated local wrap is missing; original account was preserved");
            session["kdf_salt"] = local_wrap[0].clone();
            session["wrapped_urk"] = local_wrap[1].clone();
            session["urk_nonce"] = local_wrap[2].clone();
        }
        session["keyring_account"] = json!(alias);
        Ok(Self { user, directory, original, session, super_password, login_password, alias, recovery_written: false, migration_cloud: None, migration_auth: None })
    }

    pub fn commit(&mut self) -> Result<()> {
        ensure!(read_original(&self.directory)? == self.original, "target session changed during login; original account was preserved");
        let result = self.commit_inner();
        if let Err(error) = result {
            return match self.rollback() { Ok(()) => Err(error), Err(rollback) => Err(error.context(format!("login rollback failed: {rollback:#}"))) };
        }
        Ok(())
    }

    fn commit_inner(&mut self) -> Result<()> {
        self.commit_inner_for(None)
    }

    fn commit_inner_for(&mut self, operation_id: Option<&str>) -> Result<()> {
        let _legacy_journal_lock = if operation_id.is_none() { Some(auth_journal_lock()?) } else { None };
        let mut journal = load_journal()?;
        let account_index = match operation_id {
            Some(id) => {
                let index = journal.operations.iter().position(|record| record.operation_id == id
                    && record.account.is_some() && record.phase == AuthPhase::Authorized)
                    .context("account admission is missing")?;
                ensure!(journal.active.as_ref().and_then(|active| active.operation_id.as_deref()) == Some(id),
                    "account commit does not own recovery");
                Some(index)
            }
            None => { ensure!(journal.active.is_none(), "interrupted login must be recovered before another commit"); None }
        };
        let config = match std::fs::read(crate::service::client_config_path()) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let staged_backends = if account_index.is_some() {
            journal.active.as_ref().context("account recovery is missing")?.backends.clone()
        } else { Vec::new() };
        let directory_existed = if account_index.is_some() {
            journal.active.as_ref().context("account recovery is missing")?.directory_existed
        } else { self.directory.exists() };
        journal.active = Some(Recovery { directory: self.directory.clone(), original: self.original.clone(), config,
            alias: self.alias.clone(), backends: staged_backends, pass_backends: Vec::new(),
            directory_existed, operation_id: operation_id.map(str::to_owned), owns_config: account_index.is_some() });
        if let Some(index) = account_index {
            journal.operations[index].account.as_mut().context("account receipt is missing")?.target = Some(self.directory.clone());
            checkpoint_account_candidate(&mut journal, index, &self.session)?;
        }
        save_journal(&journal)?;
        self.recovery_written = true;
        if self.session["vault_version"] == 1 {
            let password = self.login_password.as_deref().context("original v1 login password is required")?;
            if account_index.is_none() && crate::env::var("RSRS_PASS").is_ok_and(|value| !value.is_empty() && value == password) {
                // Headless v1 retains its original password/Account Secret factors.
                self.session.as_object_mut().map(|object| { object.remove("keyring_account"); object.remove("keyring_backend"); });
            } else {
                crate::keystore::import_credential_checkpoint(&self.alias, "pass", password, |backend| {
                    if account_index.is_some() { require_persistent_auth_backend(backend)?; }
                    journal.active.as_mut().context("login recovery is missing")?.pass_backends.push(backend.to_owned());
                    if let Some(index) = account_index {
                        self.session["keyring_backend"] = json!(backend);
                        journal.operations[index].backend = Some(backend.to_owned());
                        checkpoint_account_candidate(&mut journal, index, &self.session)?;
                    }
                    save_journal(&journal)
                })?;
            }
        } else if account_index.is_none() && crate::env::var("RSRS_SUPER").is_ok_and(|value| value == self.super_password) {
            // Headless hosts explicitly supply the same verified key to their runtime.
            self.session.as_object_mut().map(|object| { object.remove("keyring_account"); object.remove("keyring_backend"); });
        } else {
            let backend = crate::keystore::import_credential_checkpoint(&self.alias, "super", &self.super_password, |backend| {
                if account_index.is_some() { require_persistent_auth_backend(backend)?; }
                journal.active.as_mut().context("login recovery is missing")?.backends.push(backend.to_owned());
                if let Some(index) = account_index {
                    self.session["keyring_backend"] = json!(backend);
                    journal.operations[index].backend = Some(backend.to_owned());
                    checkpoint_account_candidate(&mut journal, index, &self.session)?;
                }
                save_journal(&journal)
            })?;
            self.session["keyring_backend"] = json!(backend);
            if let Some(password) = self.login_password.as_deref() {
                crate::keystore::import_credential_checkpoint(&self.alias, "pass", password, |backend| {
                    if account_index.is_some() { require_persistent_auth_backend(backend)?; }
                    journal.active.as_mut().context("login recovery is missing")?.pass_backends.push(backend.to_owned());
                    save_journal(&journal)
                })?;
            }
        }
        if let Some(index) = account_index {
            checkpoint_account_candidate(&mut journal, index, &self.session)?;
            journal.operations[index].phase = AuthPhase::Prepared;
            save_journal(&journal)?;
        }
        if !self.directory.exists() {
            let parent = self.directory.parent().context("account directory has no parent")?;
            std::fs::create_dir_all(parent)?;
            std::fs::create_dir(&self.directory)?;
        }
        private_write(&self.directory.join("session.json"), &serde_json::to_vec_pretty(&self.session)?)?;
        crate::service::set_data_dir(&self.directory.to_string_lossy())?;
        if let Some(index) = account_index {
            journal.operations[index].phase = AuthPhase::AwaitingVerification;
            save_journal(&journal)?;
        }
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        if self.recovery_written {
            recover_interrupted()?;
            self.recovery_written = false;
        }
        Ok(())
    }

    pub fn complete(&self) -> Result<()> {
        let _journal_lock = auth_journal_lock()?;
        let mut journal = load_journal()?;
        let active = journal.active.as_ref().context("login recovery is missing")?;
        ensure!(active.operation_id.is_none() && active.alias == self.alias && active.directory == self.directory,
            "login completion does not own the active transaction");
        retire_active(&mut journal).context("login verified but recovery record could not be retired")
    }
}

//! Read local identity metadata without unlocking keys or opening a store.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

/// Only a missing file is absent; an existing file must be a valid session object.
pub fn read_session_json(path: &Path) -> Result<Option<Value>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read session {}", path.display()))
        }
    };
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("session {} contains invalid JSON", path.display()))?;
    anyhow::ensure!(
        value.is_object(),
        "session {} must contain a JSON object",
        path.display()
    );
    Ok(Some(value))
}

/// Only an absent session permits the caller's profile-based identity fallback.
pub fn session_user_of_dir(dir: &Path) -> Result<Option<String>> {
    let directory = crate::config::normalize_control_path(dir)?;
    let path = directory.join("session.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let value: Value = serde_json::from_slice(&read_identity_record(&path)?)
                .context("current account identity contains invalid JSON")?;
            let user = value["user"]
                .as_str()
                .filter(|user| !user.is_empty())
                .context("current account identity missing user")?;
            Ok(Some(user.to_owned()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("current account identity is unavailable"),
    }
}

/// Auth-only claims; an Unbound candidate is not authorized until Runtime checks
/// its original transaction receipt and the persistent credential backend.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthSessionIdentity {
    Absent,
    Unbound { operation_id: String, session_sha256: String },
    Bound { account_id: String, session_sha256: String },
}

/// Hash the original file bytes, not a reserialized session. No keys are unlocked.
pub fn auth_session_identity(
    dir: &Path,
    sha256: impl Fn(&[u8]) -> String,
) -> Result<AuthSessionIdentity> {
    let directory = crate::config::normalize_control_path(dir)?;
    let path = directory.join("session.json");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuthSessionIdentity::Absent);
        }
        Err(error) => return Err(error).context("auth session identity is unavailable"),
        Ok(_) => {}
    }
    let bytes = read_identity_record(&path)?;
    let session: Value = serde_json::from_slice(&bytes).context("invalid auth session JSON")?;
    let object = session.as_object().context("auth session must be an object")?;
    if let Some(user) = object.get("user").filter(|user| user.as_str() != Some("")) {
        let user = user.as_str().filter(|user| !user.is_empty())
            .context("bound auth session needs a nonempty user")?;
        return Ok(AuthSessionIdentity::Bound {
            account_id: sha256(user.as_bytes()),
            session_sha256: sha256(&bytes),
        });
    }
    let fields = ["kdf_salt", "wrapped_urk", "urk_nonce", "keyring_account",
        "keyring_backend", "auth_operation_id"];
    let keygen = object.len() == 7 && session.get("user").is_none() && session["vault_version"] == 4;
    anyhow::ensure!((keygen || offline_recovery_candidate(&session))
        && fields.iter().all(|field| session[*field].as_str().is_some_and(|value| !value.is_empty())),
        "unbound auth session must be an exact keygen or offline recovery candidate");
    anyhow::ensure!(session["keyring_backend"] != "kernel",
        "unbound auth requires a persistent credential backend");
    let operation_id = session["auth_operation_id"].as_str()
        .context("unbound auth operation ID is missing")?;
    let id = operation_id.as_bytes();
    anyhow::ensure!(id.len() == 36 && id[14] == b'4' && b"89ab".contains(&id[19])
        && id.iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) { *byte == b'-' }
            else { byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) }
        }), "unbound auth operation ID must be a canonical random UUID");
    Ok(AuthSessionIdentity::Unbound {
        operation_id: operation_id.to_owned(),
        session_sha256: sha256(&bytes),
    })
}

fn offline_recovery_candidate(session: &Value) -> bool {
    let Some(object) = session.as_object() else { return false; };
    let Some(version @ (1 | 2 | 4)) = session["vault_version"].as_i64() else { return false; };
    session["user"] == "" && session["addr"] == ""
        && object.len() == (if version == 1 { 10 } else { 9 })
        && (version != 1 || session["secret"].as_str().is_some_and(|value| !value.is_empty()))
        && object.keys().all(|field| matches!(field.as_str(), "user" | "addr" | "vault_version"
            | "kdf_salt" | "wrapped_urk" | "urk_nonce" | "keyring_account" | "keyring_backend" | "auth_operation_id")
            || (version == 1 && field == "secret"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbound_reader_keeps_keygen_strict_and_requires_offline_receipt_fields() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("session.json");
        let session = serde_json::json!({"vault_version":4, "kdf_salt":"salt", "wrapped_urk":"wrap",
            "urk_nonce":"nonce", "keyring_account":"login-fixture", "keyring_backend":"native",
            "auth_operation_id":"00000000-0000-4000-8000-000000000001"});
        let read = |value: &Value| -> Result<AuthSessionIdentity> {
            std::fs::write(&path, serde_json::to_vec(value)?)?;
            auth_session_identity(root.path(), |_| "synthetic-digest".to_owned())
        };
        assert!(matches!(read(&session)?, AuthSessionIdentity::Unbound { .. }));
        let mut changed = session.clone();
        changed["vault_version"] = serde_json::json!(2);
        assert!(read(&changed).is_err());
        changed = session.clone();
        changed["user"] = serde_json::json!("");
        assert!(read(&changed).is_err());
        changed["addr"] = serde_json::json!("");
        assert!(matches!(read(&changed)?, AuthSessionIdentity::Unbound { .. }));
        for (field, value) in [("keyring_backend", "kernel"), ("auth_operation_id", "foreign-operation"),
            ("kdf_salt", ""), ("token", "unexpected-token")] {
            let mut invalid = changed.clone();
            invalid[field] = serde_json::json!(value);
            assert!(read(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn offline_recovery_claim_rejects_cloud_or_plaintext_material() {
        for version in [1, 2, 4] {
            let mut session = serde_json::json!({"user":"", "addr":"", "vault_version":version,
                "kdf_salt":"salt", "wrapped_urk":"wrap", "urk_nonce":"nonce",
                "keyring_account":"login-fixture", "keyring_backend":"native",
                "auth_operation_id":"00000000-0000-4000-8000-000000000001"});
            if version == 1 { session["secret"] = serde_json::json!("synthetic-account-secret"); }
            assert!(offline_recovery_candidate(&session));
            for field in ["token", "session_id", "pass", "super", "secret_key"] {
                let mut changed = session.clone();
                changed[field] = serde_json::json!("unexpected");
                assert!(!offline_recovery_candidate(&changed));
            }
            for (field, value) in [("user", "named-account"), ("addr", "https://never-contact.invalid")] {
                let mut changed = session.clone();
                changed[field] = serde_json::json!(value);
                assert!(!offline_recovery_candidate(&changed));
            }
            session["vault_version"] = serde_json::json!(3);
            assert!(!offline_recovery_candidate(&session));
        }
    }
}

// Share the control-root boundary, including its exact system-ancestor aliases.
fn read_identity_record(path: &Path) -> Result<Vec<u8>> {
    let path = crate::config::normalize_control_path(path)?;
    let file = std::fs::File::open(&path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 65536,
        "invalid recovery record"
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "recovery record exceeds 64 KiB");
    Ok(bytes)
}

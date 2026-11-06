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

mod login;
mod identity;
pub use identity::{control_identity_write, control_identity_write_result};
mod keys;
pub use keys::{control_key, control_key_result, control_key_rollback, control_key_complete, verify_key_receipt};
mod space;
pub use space::control_space;
mod profile;
pub use profile::control_profile_remove;

#[derive(Serialize, Deserialize)]
struct Recovery {
    directory: PathBuf,
    original: Option<Vec<u8>>,
    config: Option<Vec<u8>>,
    alias: String,
    backends: Vec<String>,
    #[serde(default)]
    pass_backends: Vec<String>,
    #[serde(default)]
    totp_backends: Vec<String>,
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
enum AuthPhase { Admitted, LoginInput, RemotePending, RemoteUnknown, Authorized, Prepared, AwaitingVerification, RollingBack, Committed, RolledBack }

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    login: Option<login::LoginProgress>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<identity::IdentityOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_operation: Option<keys::KeyOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    space_operation: Option<space::SpaceOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_remove: Option<profile::ProfileRemoveOperation>,
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
    if let Some(active) = &journal.active {
        for backend in &active.totp_backends {
            crate::keystore::remove_imported(&active.alias, "totp", backend)?;
        }
    }
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
                phase: AuthPhase::RolledBack, account: None, identity: None, key_operation: None, space_operation: None, profile_remove: None,
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
            backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(), directory_existed: true, operation_id: Some(id.clone()), owns_config: false,
        }), operations: vec![AuthRecord {
            operation_id: id.clone(), idempotency_key: id.clone(), fingerprint: keygen_fingerprint(&root, &root, false)?,
            root: root.clone(), profile: root.clone(), original_sha256: None, candidate: None, candidate_sha256: None,
            alias, backend: None, phase: AuthPhase::Admitted, account: None, identity: None, key_operation: None, space_operation: None, profile_remove: None,
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
            pass_backends: Vec::new(), totp_backends: Vec::new(), directory_existed: true, operation_id: None, owns_config: false };
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

        #[cfg(windows)]
        {
            use std::path::{Component, Prefix};
            let mut ordinary_root = match root.components().next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => PathBuf::from(format!("{}:\\", char::from(drive))),
                    _ => anyhow::bail!("canonical account fixture requires a local drive"),
                },
                _ => anyhow::bail!("canonical account fixture requires an absolute root"),
            };
            ordinary_root.extend(root.components().skip(2).map(|part| part.as_os_str()));
            assert_eq!(ordinary_root.canonicalize()?, root);
            let ordinary_target = ordinary_root.join("canonical-account-target");
            std::fs::create_dir(&ordinary_target)?;
            let canonical_target = ordinary_target.canonicalize()?;
            assert_ne!(ordinary_target, canonical_target);
            let candidate = serde_json::to_vec(&json!({"user":"receipt-user","addr":"https://never-contact.invalid"}))?;
            private_write(&ordinary_target.join("session.json"), &candidate)?;
            let durable_before = std::fs::read(recovery_path())?;
            let mut target_journal = load_journal()?;
            let record = &mut target_journal.operations[account_index];
            record.phase = AuthPhase::AwaitingVerification;
            record.candidate = Some(candidate.clone());
            record.candidate_sha256 = Some(digest(&candidate));
            record.account.as_mut().context("canonical account receipt missing")?.target = Some(ordinary_target.clone());
            assert_eq!(owned_account_index(&target_journal, &root, &canonical_target, &account_id, &account_id)?, account_index);
            target_journal.operations[account_index].account.as_mut().context("canonical account receipt missing")?.target = Some(canonical_target.clone());
            assert_eq!(owned_account_index(&target_journal, &root, &canonical_target, &account_id, &account_id)?, account_index);
            assert!(owned_account_index(&target_journal, &root, &canonical_target, &account_id, "wrong-key").is_err());
            private_write(&ordinary_target.join("session.json"), br#"{"user":"changed-owner"}"#)?;
            assert!(owned_account_index(&target_journal, &root, &canonical_target, &account_id, &account_id).is_err());
            assert_eq!(std::fs::read(recovery_path())?, durable_before);
            assert_eq!(std::fs::read(crate::service::client_config_path())?, owned_config);
            assert!(!root.join("session.json").exists());
            std::fs::remove_file(ordinary_target.join("session.json"))?;
            std::fs::remove_dir(ordinary_target)?;
        }

        // Login intents are admission identity, not supplemental credentials.
        let ownership = AuthOwnership::acquire(&root, &root)?;
        let login_id = uuid::Uuid::new_v4().to_string();
        let (mut login_journal, login_index, _) = admit_account_with_intent(&ownership,
            &HostAuthIdentity::Absent, &login_id, &login_id, false,
            "https://never-contact.invalid", "receipt-user", Some((false, false, false)))?;
        let admitted_fingerprint = login_journal.operations[login_index].fingerprint.clone();
        let admitted_bytes = std::fs::read(recovery_path())?;
        for changed in [(true, false, false), (false, true, false), (true, true, false), (false, false, true)] {
            assert!(admit_account_with_intent(&ownership, &HostAuthIdentity::Absent,
                &login_id, &login_id, false, "https://never-contact.invalid", "receipt-user", Some(changed)).is_err());
            assert_eq!(std::fs::read(recovery_path())?, admitted_bytes);
        }
        let mut login_params: HostAuthLoginParams = serde_json::from_value(json!({
            "schema_version":1,"binding":params.binding,"identity":{"kind":"absent"},
            "addr":"https://never-contact.invalid","user":"receipt-user",
            "authorization":{"kind":"browser","token":"synthetic-unused-token"},"super_password":"",
            "continuation":{"legacy_password":"must-not-be-durable","account_secret":"must-not-be-durable",
                "source_secret":"must-not-be-durable","migrate_local":false,"migrate_vault":false}
        }))?;
        let challenge = serde_json::from_value(json!({"ticket":"synthetic-private-ticket","auth_salt":"synthetic-salt"}))?;
        let payload = login::encode_challenge(&login_journal.operations[login_index], challenge)?;
        let challenge_sha = digest(payload.as_bytes());
        login::verify_challenge(&login_journal.operations[login_index], &challenge_sha, &payload)?;
        login_journal.operations[login_index].fingerprint = "different-intent".into();
        assert!(login::verify_challenge(&login_journal.operations[login_index], &challenge_sha, &payload).is_err());
        login_journal.operations[login_index].fingerprint = admitted_fingerprint.clone();
        login_journal.operations[login_index].operation_id = uuid::Uuid::new_v4().to_string();
        assert!(login::verify_challenge(&login_journal.operations[login_index], &challenge_sha, &payload).is_err());
        login_journal.operations[login_index].operation_id = login_id.clone();
        assert!(login::verify_challenge(&login_journal.operations[login_index], &digest(b"changed"), &payload).is_err());
        let mut input_record = serde_json::to_value(&login_journal.operations[login_index])?;
        input_record["account"]["login"]["challenge"] = json!({"backend":"native","sha256":challenge_sha});
        login_journal.operations[login_index] = serde_json::from_value(input_record)?;
        login_journal.active.as_mut().context("challenge recovery missing")?.totp_backends.push("native".into());
        login_journal.operations[login_index].phase = AuthPhase::LoginInput;
        login_params.authorization = HostAuthAuthorization::Password { password: String::new(), totp: None };
        save_journal(&login_journal)?;
        let missing_totp = control_login(&ownership, &login_id, &login_id, &login_params)?;
        assert_eq!(missing_totp.outcome, HostAuthAccountOutcome::AwaitingInput);
        assert_eq!(missing_totp.login.context("TOTP input status missing")?.required_inputs, ["totp"]);
        login_params.authorization = HostAuthAuthorization::Password { password: String::new(), totp: Some("invalid".into()) };
        assert_eq!(control_login(&ownership, &login_id, &login_id, &login_params)?.outcome, HostAuthAccountOutcome::AwaitingInput);
        assert!(!String::from_utf8(std::fs::read(recovery_path())?)?.contains("synthetic-private-ticket"));
        login_journal.active.as_mut().context("challenge recovery missing")?.totp_backends.clear();
        login_journal.operations[login_index].phase = AuthPhase::RemotePending;
        save_journal(&login_journal)?;
        // An uncertain authorization returns its receipt before any network or replacement factor.
        assert_eq!(control_login(&ownership, &login_id, &login_id, &login_params)?.outcome, HostAuthAccountOutcome::Unknown);
        login_journal.operations[login_index].phase = AuthPhase::Authorized;
        let account = login_journal.operations[login_index].account.as_mut().context("login test receipt missing")?;
        account.authorization = Some(json!({"user":"receipt-user","token":"synthetic-retained-token"}));
        account.vault = Some(json!({"version":4}));
        save_journal(&login_journal)?;
        let supplemental = control_login(&ownership, &login_id, &login_id, &login_params)?;
        assert_eq!(supplemental.outcome, HostAuthAccountOutcome::AwaitingInput);
        assert_eq!(supplemental.login.context("input status missing")?.required_inputs, ["super_password"]);
        assert_eq!(load_journal()?.operations[login_index].fingerprint, admitted_fingerprint);
        assert!(!String::from_utf8(std::fs::read(recovery_path())?)?.contains("must-not-be-durable"));
        // v1 rejects presence, including an explicitly empty super parameter.
        let mut v1_journal = load_journal()?;
        v1_journal.operations[login_index].account.as_mut().context("v1 receipt missing")?.vault = Some(json!({"version":1}));
        save_journal(&v1_journal)?;
        let before_explicit_super = std::fs::read(recovery_path())?;
        assert_eq!(login_params.super_password.as_deref(), Some(""));
        assert!(control_login(&ownership, &login_id, &login_id, &login_params).is_err());
        assert_eq!(std::fs::read(recovery_path())?, before_explicit_super);
        login_params.super_password = None;
        let input = login_params.continuation.as_mut().context("v1 input missing")?;
        input.legacy_password = None;
        input.account_secret = None;
        let v1_input = control_login(&ownership, &login_id, &login_id, &login_params)?;
        assert_eq!(v1_input.outcome, HostAuthAccountOutcome::AwaitingInput);
        assert!(v1_input.login.context("v1 input status missing")?.required_inputs.contains(&"account_secret".to_owned()));
        let omitted = serde_json::to_value(&login_params)?;
        assert!(omitted.get("super_password").is_none());
        assert!(serde_json::from_value::<HostAuthLoginParams>(omitted)?.super_password.is_none());
        login_params.continuation.as_mut().context("continuation missing")?.migrate_local = true;
        assert!(control_login(&ownership, &login_id, &login_id, &login_params).is_err());
        let mut merge = login::LoginProgress::new(false, false, true);
        assert!(merge.confirm_merge(&root, true).is_err());
        merge.offer_merge(&root)?;
        merge.confirm_merge(&root, false)?;
        let confirmed = serde_json::to_vec(&merge)?;
        assert!(merge.confirm_merge(&root, true).is_err());
        assert_eq!(serde_json::to_vec(&merge)?, confirmed);
        assert!(merge.offer_merge(&root.join("another-target")).is_err());
        assert_eq!(serde_json::to_vec(&merge)?, confirmed);
        // Unknown authorization cannot restart password/browser authorization.
        login_params.continuation.as_mut().context("continuation missing")?.migrate_local = false;
        login_journal.operations[login_index].phase = AuthPhase::RemoteUnknown;
        save_journal(&login_journal)?;
        assert_eq!(control_login(&ownership, &login_id, &login_id, &login_params)?.outcome,
            HostAuthAccountOutcome::Unknown);
        login_journal.operations[login_index].phase = AuthPhase::Authorized;
        save_journal(&login_journal)?;
        assert_eq!(control_account_rollback(ownership, &HostAuthIdentity::Absent, &login_id, &login_id)?.outcome,
            HostAuthAccountOutcome::RolledBack);

        // Pre-continuation receipts keep their original fingerprint and result-only behavior.
        let ownership = AuthOwnership::acquire(&root, &root)?;
        let legacy_id = uuid::Uuid::new_v4().to_string();
        let (legacy_journal, _, _) = admit_account(&ownership, &HostAuthIdentity::Absent,
            &legacy_id, &legacy_id, false, "https://never-contact.invalid", "receipt-user")?;
        let legacy_bytes = std::fs::read(recovery_path())?;
        let legacy = control_login(&ownership, &legacy_id, &legacy_id, &login_params)?;
        assert_eq!(legacy.outcome, HostAuthAccountOutcome::Unknown);
        assert!(legacy.login.is_none());
        assert_eq!(std::fs::read(recovery_path())?, legacy_bytes);
        assert_eq!(load_journal()?.operations.len(), legacy_journal.operations.len());
        assert_eq!(control_account_rollback(ownership, &HostAuthIdentity::Absent, &legacy_id, &legacy_id)?.outcome,
            HostAuthAccountOutcome::RolledBack);

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

        // Missing source factors remain on the same admitted login without opening its store.
        let source_user = format!("source-{}", uuid::Uuid::new_v4().simple());
        let source_password = uuid::Uuid::new_v4().to_string();
        let source_secret = crate::memory::crypto::generate_account_secret();
        let source_salt = crate::memory::crypto::random_hex(16);
        let source_kek = crate::memory::crypto::derive_kek(&source_password, &source_secret, &source_salt)?;
        let (source_nonce, source_wrap) = crate::memory::crypto::wrap_key(&crate::memory::crypto::generate_key(), &source_kek)?;
        let source_bytes = serde_json::to_vec(&json!({"user":source_user,"addr":"https://source.invalid",
            "vault_version":1,"secret":source_secret,"kdf_salt":source_salt,"wrapped_urk":source_wrap,"urk_nonce":source_nonce}))?;
        private_write(&root.join("session.json"), &source_bytes)?;
        let source_identity = HostAuthIdentity::Bound { account_id: digest(source_user.as_bytes()), session_sha256: digest(&source_bytes) };
        let ownership = AuthOwnership::acquire(&root, &root)?;
        let same_id = uuid::Uuid::new_v4().to_string();
        let (mut same_account, same_index, _) = admit_account_with_intent(&ownership, &source_identity,
            &same_id, &same_id, false, "https://source.invalid", &source_user, Some((true, false, false)))?;
        let (same_super, _, same_salt, same_wrap, same_nonce) = crate::auth::new_vault_v4()?;
        same_account.operations[same_index].phase = AuthPhase::Authorized;
        let same = same_account.operations[same_index].account.as_mut().context("same account receipt missing")?;
        same.authorization = Some(json!({"user":source_user,"token":"synthetic-unused-token"}));
        same.vault = Some(json!({"version":4,"kdf_salt":same_salt,"wrapped_urk":same_wrap,"urk_nonce":same_nonce}));
        save_journal(&same_account)?;
        let same_params: HostAuthLoginParams = serde_json::from_value(json!({
            "schema_version":1,"binding":{"installation_root":root,"profile":root,
                "launch_id":uuid::Uuid::new_v4().to_string(),"expected_account_id":digest(source_user.as_bytes())},
            "identity":source_identity,"addr":"https://source.invalid","user":source_user,
            "authorization":{"kind":"browser","token":"synthetic-unused-token"},"super_password":same_super,
            "continuation":{"migrate_local":true,"migrate_vault":false,"offer_local_merge":false}
        }))?;
        let same_rejected = control_login(&ownership, &same_id, &same_id, &same_params).err()
            .context("same-profile migration was not rejected")?;
        assert_eq!(same_rejected.to_string(), "source and destination are the same account; no migration needed");
        assert_eq!(std::fs::read(root.join("session.json"))?, source_bytes);
        assert_eq!(control_account_rollback(ownership, &source_identity, &same_id, &same_id)?.outcome,
            HostAuthAccountOutcome::RolledBack);
        let ownership = AuthOwnership::acquire(&root, &root)?;
        let import_id = uuid::Uuid::new_v4().to_string();
        let (mut importing, index, _) = admit_account_with_intent(&ownership, &source_identity,
            &import_id, &import_id, false, "https://never-contact.invalid", "import-target", Some((true, false, false)))?;
        let (target_super, _, salt, wrapped, nonce) = crate::auth::new_vault_v4()?;
        importing.operations[index].phase = AuthPhase::Authorized;
        let account = importing.operations[index].account.as_mut().context("import receipt missing")?;
        account.authorization = Some(json!({"user":"import-target","token":"synthetic-unused-token"}));
        account.vault = Some(json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce}));
        save_journal(&importing)?;
        let mut import_params: HostAuthLoginParams = serde_json::from_value(json!({
            "schema_version":1,"binding":{"installation_root":root,"profile":root,
                "launch_id":uuid::Uuid::new_v4().to_string(),"expected_account_id":digest(source_user.as_bytes())},
            "identity":source_identity,"addr":"https://never-contact.invalid","user":"import-target",
            "authorization":{"kind":"browser","token":"synthetic-unused-token"},"super_password":target_super,
            "continuation":{"migrate_local":true,"migrate_vault":false,"offer_local_merge":false}
        }))?;
        assert!(!login_directory("https://never-contact.invalid", "import-target")?.try_exists()?,
            "first-login regression requires a missing target directory");
        let missing_source = control_login(&ownership, &import_id, &import_id, &import_params)?;
        assert_eq!(missing_source.outcome, HostAuthAccountOutcome::AwaitingInput);
        assert_eq!(missing_source.login.context("source input status missing")?.required_inputs, ["source_secret"]);
        assert_eq!(std::fs::read(root.join("session.json"))?, source_bytes);
        assert!(!crate::service::database_path(&root)?.exists());
        import_params.continuation.as_mut().context("import input missing")?.source_secret = Some("synthetic-wrong-source-password".into());
        assert!(control_login(&ownership, &import_id, &import_id, &import_params).is_err());
        assert_eq!(std::fs::read(root.join("session.json"))?, source_bytes);
        assert_eq!(control_account_rollback(ownership, &source_identity, &import_id, &import_id)?.outcome,
            HostAuthAccountOutcome::RolledBack);

        use crate::sync::SyncControl as _;
        let sync_control = login::ImportSyncControl::default();
        sync_control.progress("pull");
        assert!(sync_control.remote::<()>(|| Err(anyhow!("synthetic read failure"))).is_err());
        assert!(!sync_control.remote_effect_possible.get());
        sync_control.progress("push");
        assert!(sync_control.remote::<()>(|| Err(anyhow!("synthetic lost write response"))).is_err());
        sync_control.progress("pull");
        sync_control.remote(|| Ok(()))?;
        assert!(sync_control.remote_effect_possible.get(), "a later read erased a possible write");
        let unclassified = login::ImportSyncControl::default();
        unclassified.remote(|| Ok(()))?;
        assert!(unclassified.remote_effect_possible.get());

        // Exercise the production compensation against a real candidate and mock keyring.
        let keyring = crate::migration::memory_keyring_for_test();
        let ownership = AuthOwnership::acquire(&root, &root)?;
        let rollback_id = uuid::Uuid::new_v4().to_string();
        let config_before = std::fs::read(crate::service::client_config_path())?;
        let (mut pending, index, _) = admit_account_with_intent(&ownership, &source_identity,
            &rollback_id, &rollback_id, false, "https://never-contact.invalid", "import-target", Some((true, false, false)))?;
        pending.operations[index].phase = AuthPhase::Authorized;
        save_journal(&pending)?;
        let (code, _, salt, wrapped, nonce) = crate::auth::new_vault_v4()?;
        let mut prepared = PreparedLogin::prepare_with_vault("https://never-contact.invalid",
            &json!({"user":"import-target","token":"synthetic-compensation-token"}), code.clone(),
            json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce}), None)?;
        let old_alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        let old_backend = crate::keystore::import_credential_checkpoint(&old_alias, "super", &code,
            require_persistent_auth_backend)?;
        assert_eq!(old_backend, "native", "app and domain must share the test keyring backend");
        let mut old_session = prepared.session.clone();
        old_session["keyring_account"] = json!(old_alias);
        old_session["keyring_backend"] = json!(old_backend);
        let old_bytes = serde_json::to_vec(&old_session)?;
        std::fs::create_dir_all(&prepared.directory)?;
        private_write(&prepared.directory.join("session.json"), &old_bytes)?;
        prepared.original = Some(old_bytes.clone());
        let database = crate::service::database_path(&prepared.directory)?;
        let store = crate::transport::local::LocalStore::open(&database)?;
        store.meta_set("compensation_test", "retain-existing-database")?;
        drop(store);
        let database_before = std::fs::read(&database)?;
        commit_account(&ownership, &mut pending, index, &mut prepared)?;
        assert_ne!(std::fs::read(crate::service::client_config_path())?, config_before);
        let target = prepared.directory.clone();
        #[cfg(windows)]
        assert_ne!(target, target.canonicalize()?, "regression requires an ordinary Windows target path");
        let selection_checkpoint = std::fs::read(recovery_path())?;
        let missing_snapshot = login::resume_import(&ownership, &mut pending, index).err()
            .context("import without a snapshot unexpectedly continued")?;
        assert_eq!(missing_snapshot.to_string(), "admitted encrypted import snapshot missing",
            "resume_import did not pass selection, target ownership and candidate validation");
        assert_eq!(std::fs::read(recovery_path())?, selection_checkpoint,
            "selection validation changed the durable operation before its snapshot was verified");
        assert_eq!(serde_json::to_value(&pending.operations[index])?["account"]["login"]["sync_started"], json!(false));
        let original_material = original_import_material(&pending.operations[index],
            pending.active.as_ref().context("compensation recovery missing")?)?;
        let mut same_target: Journal = serde_json::from_slice(&selection_checkpoint)?;
        let source_spelling = std::path::absolute(isolated.path())?;
        same_target.active.as_mut().context("same target recovery missing")?.directory = source_spelling.clone();
        same_target.operations[index].account.as_mut().context("same target receipt missing")?.target = Some(source_spelling);
        let same_rejected = rollback_import_before_copy(&ownership, &mut same_target, index, None,
            original_material.as_deref()).err().context("source target compensation was not rejected")?;
        assert_eq!(same_rejected.to_string(), "import cannot prove an unpublished owned target; retain the original operation");
        assert_eq!(std::fs::read(recovery_path())?, selection_checkpoint);
        let mut changed = serde_json::to_value(&pending.operations[index])?;
        changed["account"]["login"]["import_started"] = json!(true);
        let original_record = std::mem::replace(&mut pending.operations[index], serde_json::from_value(changed)?);
        let lock = crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?;
        let checkpoint = std::fs::read(recovery_path())?;
        assert!(rollback_import_before_copy(&ownership, &mut pending, index, Some(lock), original_material.as_deref()).is_err());
        assert_eq!(std::fs::read(recovery_path())?, checkpoint);
        pending.operations[index] = original_record;
        let (other_code, _, other_salt, other_wrap, other_nonce) = crate::auth::new_vault_v4()?;
        let other_alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        let other_backend = crate::keystore::import_credential_checkpoint(&other_alias, "super", &other_code,
            require_persistent_auth_backend)?;
        let mut other_session = old_session.clone();
        other_session["keyring_account"] = json!(other_alias);
        other_session["keyring_backend"] = json!(other_backend);
        other_session["kdf_salt"] = json!(other_salt);
        other_session["wrapped_urk"] = json!(other_wrap);
        other_session["urk_nonce"] = json!(other_nonce);
        pending.active.as_mut().context("compensation recovery missing")?.original = Some(serde_json::to_vec(&other_session)?);
        let other_material = original_import_material(&pending.operations[index],
            pending.active.as_ref().context("compensation recovery missing")?)?;
        assert_ne!(other_material, original_material);
        let candidate_config = std::fs::read(crate::service::client_config_path())?;
        let candidate_session = std::fs::read(target.join("session.json"))?;
        let lock = crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?;
        let rejected = rollback_import_before_copy(&ownership, &mut pending, index, Some(lock), other_material.as_deref());
        assert!(rejected.err().is_some_and(|error| error.to_string().contains("target keys differ")));
        assert_eq!(std::fs::read(recovery_path())?, checkpoint);
        assert_eq!(std::fs::read(crate::service::client_config_path())?, candidate_config);
        assert_eq!(std::fs::read(target.join("session.json"))?, candidate_session);
        pending.active.as_mut().context("compensation recovery missing")?.original = Some(old_bytes.clone());
        std::fs::write(crate::service::client_config_path(), b"{\"changed\":true}")?;
        let lock = crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?;
        assert!(rollback_import_before_copy(&ownership, &mut pending, index, Some(lock), original_material.as_deref()).is_err());
        assert_eq!(std::fs::read(recovery_path())?, checkpoint);
        // Restore the exact candidate config, not an unrelated external edit.
        let active = pending.active.as_ref().context("compensation recovery missing")?;
        let mut candidate_config: Value = serde_json::from_slice(active.config.as_deref().context("source config missing")?)?;
        candidate_config["data_dir"] = json!(target.to_string_lossy());
        std::fs::write(crate::service::client_config_path(), serde_json::to_vec(&candidate_config)?)?;
        let lock = crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?;
        rollback_import_before_copy(&ownership, &mut pending, index, Some(lock), original_material.as_deref())?;
        assert!(target.is_dir(), "compensation quarantined an existing target");
        assert_eq!(std::fs::read(target.join("session.json"))?, old_bytes);
        assert_eq!(std::fs::read(database)?, database_before);
        assert_eq!(crate::keystore::read_imported(&old_alias, "super", &old_backend)?, code);
        assert_eq!(std::fs::read(crate::service::client_config_path())?, config_before);
        assert_eq!(std::fs::read(root.join("session.json"))?, source_bytes);
        assert!(load_journal()?.active.is_none());
        let terminal = std::fs::read(recovery_path())?;
        assert_eq!(control_account_result(&ownership, &source_identity, &rollback_id, &rollback_id)?.outcome,
            HostAuthAccountOutcome::RolledBack);
        assert_eq!(control_login(&ownership, &rollback_id, &rollback_id, &import_params)?.outcome,
            HostAuthAccountOutcome::RolledBack);
        assert_eq!(std::fs::read(recovery_path())?, terminal, "terminal query resumed import or authentication");
        drop(ownership);
        drop(keyring);
        identity::assert_existing_recovery(&root)?;
        keys::assert_existing_recovery(&root)?;
        space::assert_existing_recovery(&root)?;
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
            backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(), directory_existed: true, operation_id: Some(id.clone()), owns_config: false,
        }), operations: vec![AuthRecord {
            operation_id: id.clone(), idempotency_key: id, fingerprint: keygen_fingerprint(&root, &root, false)?,
            root: root.clone(), profile: root.clone(), original_sha256: None,
            candidate: Some(candidate.clone()), candidate_sha256: Some(digest(&candidate)),
            alias, backend: Some("unavailable-test-backend".into()), phase: AuthPhase::Prepared, account: None, identity: None, key_operation: None, space_operation: None, profile_remove: None,
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

pub fn recovery_state() -> Result<respire_protocol::host_control::HostLoginRecoveryState> {
    use respire_protocol::host_control::HostLoginRecoveryState;
    let journal = load_journal()?;
    Ok(match journal.active.as_ref() {
        None => HostLoginRecoveryState::Clear,
        Some(active) if active.operation_id.is_none() => HostLoginRecoveryState::LegacyPending,
        Some(_) => HostLoginRecoveryState::OperationPending,
    })
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
    if record.key_operation.is_some() && record.phase == AuthPhase::AwaitingVerification {
        keys::verify_boot_candidate(record, active)?;
        return Ok(false);
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
            Some(operation.operation_id.as_str()) == record.operation_id.as_deref()
                && (operation.account.is_some() || operation.identity.is_some() || operation.key_operation.is_some() || operation.space_operation.is_some() || operation.profile_remove.is_some())),
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
    for backend in &record.totp_backends {
        crate::keystore::remove_imported(&record.alias, "totp", backend)?;
    }
    if quarantine { quarantine_new_profile(record)?; }
    Ok(())
}

/// Read the selected source as one committed snapshot, without creating plaintext files.
/// WP-2c: the implementation moved into the domain crate (`service::local_snapshot`);
/// this wrapper keeps the `respire_app::login_transaction::local_snapshot` path stable.
pub fn local_snapshot(source_secret: Option<&str>) -> Result<String> {
    let session = crate::auth::read_session_json()?;
    ensure!(session.is_object(), "source session must be an object");
    let user = session["user"].as_str().unwrap_or("local");
    let alias = session["keyring_account"].as_str().unwrap_or(user);
    if session["vault_version"].as_i64().unwrap_or(1) == 1 && source_secret.is_none()
        && session["pass"].as_str().is_none() && crate::keystore::load_login_pass(alias).is_none() {
        for field in ["wrapped_urk", "urk_nonce", "kdf_salt", "secret"] {
            ensure!(session[field].as_str().is_some_and(|value| !value.is_empty()), "source session missing {field}");
        }
        return Err(crate::auth::SessionCredentialRequired("original source password required").into());
    }
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
            // Identity writes resume only through their own fenced operation/result.
            if journal.operations.iter().any(|record| (record.identity.is_some() || record.key_operation.is_some() || record.space_operation.is_some() || record.profile_remove.is_some())
                && journal.active.as_ref().and_then(|active| active.operation_id.as_deref()) == Some(record.operation_id.as_str())) {
                verify_auth_identity(&self.root, &self.profile, identity)?;
                return Ok(());
            }
            verify_auth_identity_inner(&self.root, &self.profile, identity, true)?;
            if !journal.operations.iter().any(|record| record.account.is_some()
                && journal.active.as_ref().and_then(|active| active.operation_id.as_deref()) == Some(record.operation_id.as_str())) {
                recover_keygen(&mut journal, &self.root, &self.profile)?;
            }
        }
        Ok(())
    }

    /// Legacy rollback never admits or replays a journaled account operation.
    pub fn recover_legacy(&self, identity: &HostAuthIdentity) -> Result<bool> {
        verify_auth_identity(&self.root, &self.profile, identity)?;
        let mut journal = load_journal()?;
        let Some(active) = journal.active.as_ref() else { return Ok(false); };
        ensure!(active.operation_id.is_none(),
            "query the original authentication operation; automatic recovery is not permitted");
        rollback_record(active)?;
        retire_active(&mut journal)?;
        Ok(true)
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
    ensure!(record.account.is_none() && record.identity.is_none() && record.key_operation.is_none()
        && record.space_operation.is_none(), "operation is not a keygen transaction");
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
        alias: alias.clone(), backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(), directory_existed: true,
        operation_id: Some(operation_id.to_owned()), owns_config: false });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: operation_id.to_owned(), idempotency_key: idempotency_key.to_owned(),
        fingerprint, root: ownership.root.clone(), profile: ownership.profile.clone(), original_sha256: original.as_deref().map(digest),
        candidate: None, candidate_sha256: None, alias: alias.clone(), backend: None, phase: AuthPhase::Admitted, account: None, identity: None, key_operation: None, space_operation: None, profile_remove: None });
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
    admit_account_with_intent(ownership, identity, operation_id, key, register, addr, user, None)
}

fn admit_account_with_intent(ownership: &AuthOwnership, identity: &HostAuthIdentity, operation_id: &str,
    key: &str, register: bool, addr: &str, user: &str,
    login_intent: Option<(bool, bool, bool)>) -> Result<(Journal, usize, bool)> {
    crate::service::require_profile_change_host()?;
    canonical_operation_id(operation_id)?;
    ensure!(!key.is_empty() && key.len() <= 128 && key.bytes().all(|byte|
        byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)), "invalid auth idempotency key");
    ensure!(ownership.root == crate::service::main_data_dir().canonicalize()?
        && ownership.profile == crate::service::data_dir().canonicalize()?, "auth ownership changed");
    ensure!(!user.is_empty() && !addr.is_empty(), "account and server are required");
    verify_auth_identity(&ownership.root, &ownership.profile, identity)?;
    let base = account_fingerprint(ownership, identity, register, addr, user)?;
    let fingerprint = match login_intent {
        Some(intent) => digest(&serde_json::to_vec(&(&base, intent))?),
        None => base.clone(),
    };
    let mut journal = load_journal()?;
    if let Some(index) = journal.operations.iter().position(|record|
        record.operation_id == operation_id || record.idempotency_key == key) {
        let record = &journal.operations[index];
        let legacy_login = login_intent == Some((false, false, false)) && record.fingerprint == base
            && record.account.as_ref().is_some_and(|account| !account.register && account.login.is_none());
        ensure!(record.operation_id == operation_id && record.idempotency_key == key
            && record.root == ownership.root && record.profile == ownership.profile
            && (record.fingerprint == fingerprint || legacy_login) && record.account.is_some(), "auth idempotency conflict");
        return Ok((journal, index, false));
    }
    ensure!(journal.active.is_none(), "resolve the interrupted transaction before admitting another account operation");
    ensure!(journal.operations.len() < 4096, "auth receipt capacity reached");
    let original = read_original(&ownership.profile)?;
    let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
    journal.active = Some(Recovery { directory: ownership.profile.clone(), original: original.clone(),
        config: None, alias: alias.clone(), backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(),
        directory_existed: true, operation_id: Some(operation_id.to_owned()), owns_config: false });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: operation_id.to_owned(), idempotency_key: key.to_owned(),
        fingerprint, root: ownership.root.clone(), profile: ownership.profile.clone(),
        original_sha256: original.as_deref().map(digest), candidate: None, candidate_sha256: None,
        alias, backend: None, phase: AuthPhase::Admitted, identity: None, key_operation: None, space_operation: None, profile_remove: None, account: Some(AccountOperation {
            register, addr: addr.to_owned(), user: user.to_owned(), source_identity: identity.clone(),
            target: None, authorization: None, vault: None, published_vault: false, vault_pending: false,
            login: login_intent.map(|(migrate_local, migrate_vault, offer_local_merge)|
                login::LoginProgress::new(migrate_local, migrate_vault, offer_local_merge)),
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
            AuthPhase::Authorized | AuthPhase::LoginInput if account.login.as_ref()
                .is_some_and(|login| login.awaiting_input()) => HostAuthAccountOutcome::AwaitingInput,
            _ if account.vault_pending && !account.published_vault
                || record.phase != AuthPhase::RolledBack && account.login.as_ref().is_some_and(|login| login.pending()) => HostAuthAccountOutcome::Unknown,
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
        login: account.login.as_ref().map(|login| login.status(record.phase == AuthPhase::RolledBack, account)),
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
    login::control_login(ownership, operation_id, key, params)
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
        let lock_target = if target.exists() { target.canonicalize()? } else { target.clone() };
        let _target_lock = if lock_target == ownership.root || lock_target == ownership.profile { None }
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
    login::resume_import(ownership, &mut journal, index)?;
    login::reconcile_publication(&mut journal, index)?;
    account_result(&journal.operations[index])
}

fn owned_account_index(journal: &Journal, root: &Path, profile: &Path, id: &str, key: &str) -> Result<usize> {
    canonical_operation_id(id)?;
    let index = journal.operations.iter().position(|record| record.operation_id == id && record.idempotency_key == key)
        .context("account admission receipt is missing")?;
    let record = &journal.operations[index];
    let account = record.account.as_ref().context("operation is not account authentication")?;
    ensure!(record.root == root, "account receipt owner mismatch");
    let current = read_original(profile)?;
    let owns_source = record.profile == profile && current.as_deref().map(digest) == record.original_sha256;
    // An untouched source may query a candidate whose directory does not exist yet.
    let owns_target = if owns_source { false } else {
        account.target.as_ref().map(|target| target.canonicalize()).transpose()?.as_deref() == Some(profile)
    };
    ensure!(record.profile == profile || owns_target, "account receipt owner mismatch");
    ensure!(owns_source || (owns_target && current.is_some() && current == record.candidate),
        "account receipt no longer owns the selected session");
    Ok(index)
}

fn verify_account_candidate(record: &AuthRecord) -> Result<()> {
    verify_account_material(record, true)
}

fn verify_account_material(record: &AuthRecord, require_published: bool) -> Result<()> {
    account_material_keys(record, require_published).map(|_| ())
}

fn account_material_keys(record: &AuthRecord, require_published: bool) -> Result<crate::memory::SessionKeys> {
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
    session_material_keys(&session, &record.alias, backend)
}

fn session_material_keys(session: &Value, alias: &str, backend: &str) -> Result<crate::memory::SessionKeys> {
    require_persistent_auth_backend(backend)?;
    let secret = if session["vault_version"] == 1 {
        crate::keystore::read_imported_v1_password(alias, backend)?
    } else { crate::keystore::read_imported(alias, "super", backend)? };
    let salt = session["kdf_salt"].as_str().context("account salt is missing")?;
    let wrapped = session["wrapped_urk"].as_str().context("account wrap is missing")?;
    let nonce = session["urk_nonce"].as_str().context("account nonce is missing")?;
    let keys = match session["vault_version"].as_i64() {
        Some(1) => crate::memory::SessionKeys::unlock(&secret, session["secret"].as_str().context("original account secret is missing")?, salt, wrapped, nonce)?,
        Some(2) => crate::memory::SessionKeys::unlock_super(&secret, salt, wrapped, nonce)?,
        Some(3) => crate::memory::SessionKeys::unlock_vault(&secret, session["secret_key"].as_str().context("original secret key is missing")?, salt, wrapped, nonce)?,
        Some(4) => crate::memory::SessionKeys::unlock_v4(&secret, salt, wrapped, nonce)?,
        _ => anyhow::bail!("unsupported account vault"),
    };
    Ok(keys)
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
    let target = record.account.as_ref().and_then(|account| account.target.as_ref())
        .context("account target is missing")?.canonicalize()?;
    ensure!(target == profile, "completion requires the receipt's selected target");
    if record.phase == AuthPhase::Committed { return account_result(record); }
    ensure!(record.phase == AuthPhase::AwaitingVerification, "account is not ready for runtime verification");
    ensure!(journal.active.as_ref().and_then(|active| active.operation_id.as_deref()) == Some(operation_id),
        "completion does not own active recovery");
    verify_runtime(&account_result(record)?)?;
    login::finish_migration(&mut journal, index)?;
    if journal.operations[index].account.as_ref().and_then(|account| account.login.as_ref())
        .is_some_and(|login| login.pending()) {
        return account_result(&journal.operations[index]);
    }
    let record = &journal.operations[index];
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
    let active = journal.active.as_ref().context("account recovery is missing")?;
    let target = if active.directory.exists() { Some(active.directory.canonicalize()?) } else { None };
    let target_lock = if target.as_ref().is_none_or(|target| *target == ownership.root || *target == ownership.profile) { None }
        else { Some(crate::lock::LibraryLock::acquire(&active.directory, std::time::Duration::from_secs(1))?) };
    rollback_account_material(&mut journal, index)?;
    // Windows cannot quarantine a directory while SQLite still owns its lock file.
    // The root/source guards and the durable RollingBack record remain held.
    drop(target_lock);
    if journal.active.as_ref().is_some_and(|active| !active.directory_existed && target.as_deref() == Some(ownership.profile.as_path())) {
        drop(ownership._profile_lock.take());
    }
    finish_account_rollback(&mut journal, index)?;
    account_result(&journal.operations[index])
}

fn rollback_account_material(journal: &mut Journal, index: usize) -> Result<()> {
    let record = &journal.operations[index];
    ensure!(record.phase != AuthPhase::Committed && record.phase != AuthPhase::RemotePending
        && record.phase != AuthPhase::RemoteUnknown, "remote outcome must be resolved before compensation");
    let account = record.account.as_ref().context("account receipt is missing")?;
    ensure!(!account.login.as_ref().is_some_and(|login| login.publication_started()),
        "legacy publication is pending or complete; retain the original account receipt");
    ensure!(!account.vault_pending && !account.published_vault, "published or unknown remote vault cannot be compensated by deleting local keys");
    let active = journal.active.as_ref().context("account recovery is missing")?;
    ensure!(active.operation_id.as_deref() == Some(record.operation_id.as_str()), "rollback does not own recovery");
    let current = read_original(&active.directory)?;
    ensure!(current == active.original || current == record.candidate, "target session changed outside the transaction");
    if active.owns_config {
        verify_account_config(active)?;
    }
    journal.operations[index].phase = AuthPhase::RollingBack;
    save_journal(journal)?;
    rollback_record_inner(journal.active.as_ref().context("account recovery is missing")?, false)?;
    Ok(())
}

fn finish_account_rollback(journal: &mut Journal, index: usize) -> Result<()> {
    quarantine_new_profile(journal.active.as_ref().context("account recovery is missing")?)?;
    journal.operations[index].phase = AuthPhase::RolledBack;
    retire_active(journal)
}

fn rollback_import_before_copy(ownership: &AuthOwnership, journal: &mut Journal, index: usize,
    target_lock: Option<crate::lock::LibraryLock>, original_material: Option<&str>) -> Result<()> {
    let record = &journal.operations[index];
    let account = record.account.as_ref().context("import account missing")?;
    let login = account.login.as_ref().context("import progress missing")?;
    let active = journal.active.as_ref().context("import recovery missing")?;
    let target_identity = active.directory.canonicalize()?;
    ensure!(record.phase == AuthPhase::AwaitingVerification && !account.register
        && login.can_compensate_import()
        && record.root == ownership.root && record.profile == ownership.profile
        && active.owns_config
        && (!active.directory_existed || original_material.is_some())
        && active.alias == record.alias
        && account.target.as_ref() == Some(&active.directory)
        && target_identity != ownership.root && target_identity != ownership.profile,
        "import cannot prove an unpublished owned target; retain the original operation");
    ensure!(crate::service::main_data_dir().canonicalize()? == ownership.root
        && crate::service::data_dir().canonicalize()? == target_identity
        && read_original(&ownership.profile)?.as_deref().map(digest) == record.original_sha256,
        "import source or selection changed before compensation");
    verify_auth_identity(&ownership.root, &ownership.profile, &account.source_identity)?;
    ensure!(target_lock.as_ref().context("import target ownership missing")?.protects(&active.directory)?,
        "import target ownership changed before compensation");
    ensure!(original_import_material(record, active)?.as_deref() == original_material,
        "original target credentials changed before compensation");
    let candidate_keys = account_material_keys(record, true)?;
    ensure!(original_material.is_none_or(|original| original == digest(&candidate_keys.urk)),
        "original and candidate target keys differ; retain the candidate and original operation");
    rollback_account_material(journal, index)?;
    let record = &journal.operations[index];
    let active = journal.active.as_ref().context("import recovery missing")?;
    ensure!(read_original(&active.directory)? == active.original
        && original_import_material(record, active)?.as_deref() == original_material
        && crate::service::data_dir().canonicalize()? == ownership.profile,
        "import compensation could not verify restored target or source selection");
    verify_auth_identity(&ownership.root, &ownership.profile,
        &record.account.as_ref().context("import account missing")?.source_identity)?;
    drop(target_lock);
    finish_account_rollback(journal, index)
}

fn original_import_material(record: &AuthRecord, active: &Recovery) -> Result<Option<String>> {
    let Some(bytes) = active.original.as_deref() else { return Ok(None); };
    let session: Value = serde_json::from_slice(bytes)?;
    let account = record.account.as_ref().context("import account missing")?;
    let alias = session["keyring_account"].as_str().context("original target credential alias missing")?;
    let backend = session["keyring_backend"].as_str().context("original target credential backend missing")?;
    ensure!(alias != record.alias && session["user"].as_str() == Some(account.user.as_str())
        && session["addr"].as_str() == Some(account.addr.as_str()), "original target credential identity mismatch");
    let keys = session_material_keys(&session, alias, backend)?;
    Ok(Some(digest(&keys.urk)))
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
        if version == 3 { factors["secret_key"] = local["secret_key"].clone(); }
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
        self.finish_migration_guarded(addr, authorized, |_, _| Ok(()))
    }

    fn finish_migration_guarded(&self, addr: &str, authorized: &Value,
        mut checkpoint: impl FnMut(&str, bool) -> Result<()>) -> Result<()> {
        if self.migration_cloud.is_none() && self.migration_auth.is_none() { return Ok(()); }
        let token = authorized["token"].as_str().context("authorization did not return a token")?;
        if let Some(original) = self.migration_cloud.as_ref() {
        ensure!(Self::fetch_vault(addr, authorized)? == *original, "cloud vault changed during migration; original local session was restored");
        let vault = json!({"version":self.session["vault_version"],"kdf_salt":self.session["kdf_salt"],"wrapped_urk":self.session["wrapped_urk"],"urk_nonce":self.session["urk_nonce"]});
        let mut request = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .post(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {token}"));
        if original.is_null() { request = request.set("If-None-Match", "*"); }
        checkpoint("vault", false)?;
        let result = request.send_json(vault.clone());
        if let Err(error) = result {
            // A lost HTTP response can follow a committed write; inspect that exact wrap once.
            if !Self::fetch_vault(addr, authorized).is_ok_and(|current| current == vault) {
                return Err(anyhow!("legacy vault publication failed: {error}; retain the original super Key and library"));
            }
        }
        checkpoint("vault", true)?;
        }
        if let Some(authentication) = self.migration_auth.as_ref() {
            let agent = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build();
            checkpoint("password", false)?;
            let result = agent.post(&format!("{}/api/self/password", addr.trim().trim_end_matches('/')))
                .set("Authorization", &format!("Bearer {token}")).send_json(authentication.clone());
            if let Err(error) = result {
                let confirmed: Value = agent.get(&format!("{}/auth/salt", addr.trim().trim_end_matches('/')))
                    .query("user", &self.user).call()?.into_json()?;
                ensure!(confirmed["salt"] == authentication["salt"],
                    "authentication namespace publication failed: {error}; retry explicit migration with the original password");
            }
            checkpoint("password", true)?;
        }
        Ok(())
    }

    pub fn prepare_with_vault(addr: &str, authorized: &Value, super_password: String, vault: Value, legacy: Option<(Value, [u8; 32])>) -> Result<Self> {
        Self::prepare_with_vault_inner(addr, authorized, super_password, vault, legacy, false)
    }

    fn prepare_with_vault_inner(addr: &str, authorized: &Value, super_password: String, vault: Value,
        legacy: Option<(Value, [u8; 32])>, registration_source: bool) -> Result<Self> {
        Self::prepare_candidate(addr, authorized, super_password, vault, legacy, registration_source, false, None)
    }

    // Only the owned fivekeys transaction may prepare an unauthenticated candidate.
    // Its caller verifies the kit first and never publishes it before authentication.
    fn prepare_candidate(addr: &str, authorized: &Value, super_password: String, vault: Value,
        legacy: Option<(Value, [u8; 32])>, registration_source: bool, without_token: bool, fixed_directory: Option<&Path>) -> Result<Self> {
        crate::service::require_profile_change_host()?;
        let user = authorized["user"].as_str().filter(|user| !user.is_empty()).context("authorization did not return a user")?.to_owned();
        let token = authorized["token"].as_str().filter(|token| !token.is_empty());
        ensure!(without_token || token.is_some(), "authorization did not return a token");
        let base = addr.trim().trim_end_matches('/');
        let version = vault["version"].as_i64().context("vault missing version")?;
        ensure!((1..=4).contains(&version), "unsupported vault version; original factors were preserved");
        let salt = vault["kdf_salt"].as_str().context("vault missing kdf_salt")?;
        let wrapped = vault["wrapped_urk"].as_str().context("vault missing wrapped_urk")?;
        let nonce = vault["urk_nonce"].as_str().context("vault missing urk_nonce")?;
        let current = crate::service::data_dir();
        let mut directory = if let Some(directory) = fixed_directory { directory.to_path_buf() }
        else if (registration_source && crate::service::session_user_of_dir(&current).is_empty())
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
        let login_password = authorized["pass"].as_str().filter(|value| version == 1 || !value.is_empty()).map(str::to_owned)
            .or_else(|| if version == 1 { crate::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty()) } else { None })
            .or_else(|| session["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned))
            .or_else(|| crate::keystore::load_login_pass(previous_alias));
        let account_secret = authorized["secret"].as_str().filter(|value| !value.is_empty())
            .or_else(|| session["secret"].as_str().filter(|value| !value.is_empty())).map(str::to_owned);
        let secret_key = authorized["secret_key"].as_str().filter(|value| !value.is_empty())
            .or_else(|| session["secret_key"].as_str().filter(|value| !value.is_empty())).map(str::to_owned);
        let verified = match version {
            1 => crate::memory::SessionKeys::unlock(
                login_password.as_deref().context("original v1 login password is required")?,
                account_secret.as_deref().context("original v1 Account Secret is required")?, salt, wrapped, nonce),
            2 => crate::memory::SessionKeys::unlock_super(&super_password, salt, wrapped, nonce),
            3 => crate::memory::SessionKeys::unlock_vault(&super_password,
                secret_key.as_deref().context("original Secret Key is required; select the explicitly migrated profile")?,
                salt, wrapped, nonce),
            _ => crate::memory::SessionKeys::unlock_v4(&super_password, salt, wrapped, nonce),
        }.context("original decryption factors do not unlock this account; the original account was preserved")?;
        if fixed_directory.is_none() && original.is_none() && legacy.is_none() {
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
        if version == 3 { session["secret_key"] = json!(secret_key.context("original Secret Key is required")?); }
        for field in ["pass", "super"] { session.as_object_mut().map(|object| object.remove(field)); }
        if version >= 4 {
            for field in ["secret", "secret_key"] { session.as_object_mut().map(|object| object.remove(field)); }
        }
        session["user"] = json!(user);
        session["addr"] = json!(base);
        if let Some(token) = token {
            session["token"] = json!(token);
            session["session_id"] = authorized["session_id"].clone();
        } else if let Some(object) = session.as_object_mut() {
            object.remove("token");
            object.remove("session_id");
        }
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
        let staged_totp_backends = if account_index.is_some() {
            journal.active.as_ref().context("account recovery is missing")?.totp_backends.clone()
        } else { Vec::new() };
        let directory_existed = if account_index.is_some() {
            journal.active.as_ref().context("account recovery is missing")?.directory_existed
        } else { self.directory.exists() };
        journal.active = Some(Recovery { directory: self.directory.clone(), original: self.original.clone(), config,
            alias: self.alias.clone(), backends: staged_backends, pass_backends: Vec::new(), totp_backends: staged_totp_backends,
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

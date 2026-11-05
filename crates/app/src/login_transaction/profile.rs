//! Local removal shares the existing fenced account journal, never credentials.
use super::*;
use respire_protocol::profile_maintenance::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileRemoveOperation {
    original: HostProfileRemoveOperation,
}

fn plain(path: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(!metadata.file_type().is_symlink(), "profile removal refuses symlinks");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(metadata.file_attributes() & 0x400 == 0, "profile removal refuses reparse points");
    }
    Ok(metadata)
}

fn target(root: &Path, name: &str) -> Result<PathBuf> {
    ensure!(!name.is_empty() && name != "main"
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
        "invalid profile removal name; main is reserved");
    ensure!(root.is_absolute() && plain(root)?.is_dir() && root.canonicalize()? == root,
        "profile removal installation root changed");
    let accounts = root.join("accounts");
    ensure!(plain(&accounts)?.is_dir() && accounts.canonicalize()? == accounts,
        "profile removal account root is redirected");
    Ok(accounts.join(name))
}

fn check_target(root: &Path, directory: &Path) -> Result<()> {
    ensure!(plain(directory)?.is_dir() && directory.canonicalize()? == directory
        && directory.parent() == Some(root.join("accounts").as_path()),
        "profile removal target changed or escaped its installation");
    for name in ["lock.db", "lock.db-journal", "lock.db-wal", "lock.db-shm"] {
        match plain(&directory.join(name)) {
            Ok(metadata) => ensure!(metadata.is_file(), "invalid profile lock file"),
            Err(error) if error.downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn check_tree(directory: &Path) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = plain(&path)?;
        if metadata.is_dir() {
            check_tree(&path)?;
        } else {
            ensure!(metadata.is_file(), "profile removal refuses special files");
        }
    }
    Ok(())
}

fn result(record: Option<&AuthRecord>, original: &HostProfileRemoveOperation) -> HostProfileRemoveResult {
    HostProfileRemoveResult {
        operation_id: original.operation_id.clone(),
        fingerprint: original.fingerprint.clone(),
        identity: original.identity.clone(),
        outcome: if record.is_some_and(|record| record.phase == AuthPhase::Committed) {
            HostProfileRemoveOutcome::Committed
        } else {
            HostProfileRemoveOutcome::Unknown
        },
    }
}

pub fn control_profile_remove(
    ownership: &AuthOwnership,
    original: &HostProfileRemoveOperation,
    query_only: bool,
) -> Result<HostProfileRemoveResult> {
    canonical_operation_id(&original.operation_id)?;
    ensure!(original.schema_version == HOST_PROFILE_SCHEMA_V && original.key == original.operation_id
        && original.fingerprint == digest(&original.fingerprint_bytes()?)
        && original.installation_root == ownership.root && original.profile == ownership.profile,
        "profile removal original binding changed");
    verify_auth_identity(&ownership.root, &ownership.profile, &original.identity)?;
    let mut journal = load_journal()?;
    if let Some(record) = journal.operations.iter().find(|record|
        record.operation_id == original.operation_id || record.idempotency_key == original.key)
    {
        ensure!(record.operation_id == original.operation_id && record.idempotency_key == original.key
            && record.root == ownership.root && record.profile == ownership.profile
            && record.fingerprint == original.fingerprint
            && record.profile_remove.as_ref().is_some_and(|operation| operation.original == *original),
            "profile removal operation/idempotency conflict");
        // Repeats, including FirstAttempt, only observe the durable record.
        return Ok(result(Some(record), original));
    }
    if query_only {
        return Ok(result(None, original));
    }
    ensure!(journal.active.is_none() && journal.operations.len() < 4096,
        "resolve account recovery or journal capacity before removing a profile");
    crate::snapshot::ensure_no_incomplete_restore(&ownership.profile)?;
    let directory = target(&ownership.root, &original.name)?;
    ensure!(directory != ownership.profile, "this profile is in use; select another profile before deleting");
    check_target(&ownership.root, &directory)?;
    let target_lock = crate::lock::LibraryLock::acquire(&directory, std::time::Duration::ZERO)?;
    check_target(&ownership.root, &directory)?;
    verify_auth_identity(&ownership.root, &directory, &original.target_identity)?;
    check_tree(&directory)?;
    ensure!(target_lock.protects(&directory)?, "profile removal target lock changed");
    let index = journal.operations.len();
    journal.operations.push(AuthRecord {
        operation_id: original.operation_id.clone(), idempotency_key: original.key.clone(),
        fingerprint: original.fingerprint.clone(), root: ownership.root.clone(), profile: ownership.profile.clone(),
        original_sha256: None, candidate: None, candidate_sha256: None,
        alias: format!("profile-remove-{}", original.operation_id), backend: None, phase: AuthPhase::Prepared,
        account: None, identity: None, key_operation: None, space_operation: None,
        profile_remove: Some(ProfileRemoveOperation { original: original.clone() }),
    });
    // No rollback image exists. Generic login/key recovery must not touch this record.
    journal.active = Some(Recovery { directory: directory.clone(), original: None, config: None,
        alias: journal.operations[index].alias.clone(), backends: Vec::new(), pass_backends: Vec::new(),
        totp_backends: Vec::new(), directory_existed: true,
        operation_id: Some(original.operation_id.clone()), owns_config: false });
    save_journal(&journal)?;
    // SQLite may keep lock.db undeletable on Windows. Root/profile ownership and the
    // caller's Paused takeover remain held; dropping this handle is not a stop proof.
    drop(target_lock);
    ensure!(crate::service::main_data_dir().canonicalize()? == ownership.root
        && crate::service::data_dir().canonicalize()? == ownership.profile,
        "profile removal selection changed before deletion");
    verify_auth_identity(&ownership.root, &ownership.profile, &original.identity)?;
    ensure!(target(&ownership.root, &original.name)? == directory, "profile removal target changed");
    check_target(&ownership.root, &directory)?;
    verify_auth_identity(&ownership.root, &directory, &original.target_identity)?;
    check_tree(&directory)?;
    // Preflight is not an OS nofollow/open-by-handle guarantee: external renames
    // between this final check and remove_dir_all remain a TOCTOU limitation.
    std::fs::remove_dir_all(&directory)?;
    respire_spawn::durable::sync_directory(
        directory.parent().context("profile removal account parent missing")?)?;
    verify_auth_identity(&ownership.root, &ownership.profile, &original.identity)?;
    journal.operations[index].phase = AuthPhase::Committed;
    journal.active = None;
    save_journal(&journal)?;
    Ok(result(Some(&journal.operations[index]), original))
}

//! Private admission evidence for one exact migration operation.
//!
//! Copying has no external side effects and may be restarted into a fresh stage.
//! Transforming is deliberately not replayable: credential writes and randomized
//! database conversion need a separate transaction journal before that is safe.
//! RejectedSchema is terminal and carries no credential or publication effects.
//! Unpublished Ready also stays closed until staged data and credentials can be
//! independently revalidated; its receipt alone is not an integrity proof.
use super::*;
use respire_protocol::migration_control::HostMigrationOperation;
use serde::{Deserialize, Serialize};
use std::io::Read;

#[cfg(windows)]
#[path = "migration_registry.rs"]
mod registry;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase { Copying, Transforming, Ready, RejectedSchema }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    schema: u32,
    original: HostMigrationOperation,
    source: PathBuf,
    session_digest: Option<String>,
    pub(super) stage: PathBuf,
    pub(super) phase: Phase,
}

fn path(home: &Path, original: &HostMigrationOperation) -> Result<PathBuf> {
    let id = uuid::Uuid::parse_str(&original.operation_id)?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == original.operation_id
        && original.key == original.operation_id, "invalid migration intent operation ID");
    Ok(home.join(".rsrs-migration-intents").join(format!("{id}.json")))
}

fn no_links(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(!metadata.file_type().is_symlink(), "migration intent path is a symbolic link");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "migration intent path is a reparse point");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn session_digest(source: &Path) -> Result<Option<String>> {
    let path = source.join("session.json");
    no_links(&path)?;
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(hex::encode(Sha256::digest(bytes)))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn verify_source(record: &Intent, profile: &Profile) -> Result<()> {
    no_links(&profile.source)?;
    anyhow::ensure!(record.source == profile.source.canonicalize()?
        && record.original.source_id == profile.identity
        && record.session_digest == session_digest(&profile.source)?,
        "migration source identity changed after admission; the original operation was retained");
    Ok(())
}

fn validate(home: &Path, original: &HostMigrationOperation, record: &Intent) -> Result<()> {
    anyhow::ensure!(record.schema == 1 && record.original == *original && record.source.is_absolute(),
        "migration intent disagrees with the original operation");
    let stage_name = record.stage.file_name().and_then(|name| name.to_str())
        .context("invalid migration stage name")?;
    let id = uuid::Uuid::parse_str(stage_name)?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == stage_name
        && record.stage == home.join(".rsrs-migration-staging").join(stage_name),
        "migration stage is outside its private staging root");
    no_links(&record.stage)?;
    Ok(())
}

fn read_frames(home: &Path, path: &Path) -> Result<Option<Intent>> {
    no_links(path)?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 64 * 1024, "invalid migration intent size or type");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(!bytes.is_empty() && bytes.len() <= 64 * 1024 && bytes.last() == Some(&b'\n'),
        "migration intent is truncated or exceeds its size limit");
    let mut previous: Option<Intent> = None;
    for frame in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let record: Intent = serde_json::from_slice(frame)?;
        validate(home, &record.original, &record)?;
        if let Some(prior) = previous.as_ref() { transition(prior, &record)?; }
        else { anyhow::ensure!(record.phase == Phase::Copying, "migration intent lacks admission"); }
        previous = Some(record);
    }
    Ok(previous)
}

fn transition(previous: &Intent, next: &Intent) -> Result<()> {
    anyhow::ensure!(previous.original == next.original && previous.source == next.source
        && previous.session_digest == next.session_digest, "migration intent binding changed");
    anyhow::ensure!(match (previous.phase, next.phase) {
        (Phase::Copying, Phase::Copying) => true,
        (Phase::Copying, Phase::RejectedSchema) | (Phase::Copying, Phase::Transforming) | (Phase::Transforming, Phase::Ready) => previous.stage == next.stage,
        _ => false,
    }, "migration intent phase regressed or changed its transformation stage");
    Ok(())
}

pub(super) fn load(home: &Path, original: &HostMigrationOperation) -> Result<Option<Intent>> {
    let record = read_frames(home, &path(home, original)?)?;
    if let Some(record) = record.as_ref() { validate(home, original, record)?; }
    #[cfg(windows)] registry::verify(home, original, record.as_ref())?;
    Ok(record)
}

pub(super) fn save(home: &Path, record: &Intent) -> Result<()> {
    use std::io::Write;
    validate(home, &record.original, record)?;
    let path = path(home, &record.original)?;
    no_links(&path)?;
    let directory = path.parent().context("migration intent has no parent")?;
    private_directory(directory)?;
    // Admission directory creation must also survive a power loss on Unix.
    #[cfg(unix)] { std::fs::File::open(home)?.sync_all()?; }
    let prior = load(home, &record.original)?;
    if let Some(prior) = prior.as_ref() { transition(prior, record)?; }
    else { anyhow::ensure!(record.phase == Phase::Copying, "migration intent lacks admission"); }
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    let existing = if prior.is_some() { std::fs::metadata(&path)?.len() } else { 0 };
    anyhow::ensure!(existing + bytes.len() as u64 <= 64 * 1024, "migration intent journal is full; retain it for recovery");
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if prior.is_some() { options.append(true); } else { options.create_new(true); }
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    // Never replace this filename. FlushFileBuffers (Windows) / fsync (Unix)
    // orders each appended phase before its side effects, without rename recovery.
    file.write_all(&bytes)?;
    file.sync_all()?;
    #[cfg(unix)] { std::fs::File::open(directory)?.sync_all()?; }
    #[cfg(windows)] registry::persist(home, record)?;
    Ok(())
}

pub(super) fn reject_conflicting_admission(home: &Path, original: Option<&HostMigrationOperation>, source_id: &str, account: &str) -> Result<()> {
    #[cfg(windows)] registry::reject_conflicts(home, original, source_id, account)?;
    let directory = home.join(".rsrs-migration-intents");
    no_links(&directory)?;
    if !directory.exists() { return Ok(()); }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let candidate = read_frames(home, &entry.path())?.context("migration intent disappeared")?;
        anyhow::ensure!(entry.path() == path(home, &candidate.original)?, "migration intent filename changed");
        if original.is_none_or(|original| candidate.original != *original)
            && (candidate.original.source_id == source_id || candidate.original.account.eq_ignore_ascii_case(account)) {
            anyhow::ensure!(candidate.phase == Phase::RejectedSchema || migration_control_result(&candidate.original)?.is_some(),
                "another unfinished migration owns this source or account; recover its original operation");
        }
    }
    Ok(())
}

pub(super) fn admit_or_load(home: &Path, original: &HostMigrationOperation, profile: &Profile) -> Result<Intent> {
    if let Some(record) = load(home, original)? {
        verify_source(&record, profile)?;
        return Ok(record);
    }
    reject_conflicting_admission(home, Some(original), &original.source_id, &original.account)?;
    no_links(&profile.source)?;
    let record = Intent {
        schema: 1, original: original.clone(), source: profile.source.canonicalize()?,
        session_digest: session_digest(&profile.source)?,
        stage: home.join(".rsrs-migration-staging").join(uuid::Uuid::new_v4().to_string()),
        phase: Phase::Copying,
    };
    save(home, &record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture(home: &Path) -> Result<(HostMigrationOperation, Profile)> {
        let source = home.join(".onememory");
        private_directory(&source)?;
        write_json(&source.join("session.json"), &json!({"user":"synthetic-intent-owner"}))?;
        let id = uuid::Uuid::new_v4().to_string();
        let source_id = identity(&source)?;
        let original = HostMigrationOperation {
            schema_version: 1, operation_id: id.clone(), key: id,
            installation_root: crate::service::accounts_root().parent().context("no root")?.to_owned(),
            profile: crate::service::data_dir(), identity: respire_protocol::HostAuthIdentity::Absent,
            source_id: source_id.clone(), account: "intent-fixture".into(), fingerprint: "fixture".into(),
        };
        let profile = Profile { source, destination: crate::service::accounts_root().join(&original.account),
            identity: source_id, services: ["1memory", "memocap", "respire"] };
        Ok((original, profile))
    }

    #[test]
    fn invalid_snapshot_rejects_before_checkpoint_and_preserves_original() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        let (_, profile) = fixture(&home)?;
        let database = profile.source.join("onememory.db");
        Connection::open(&database)?.execute_batch("CREATE TABLE memories (id INTEGER PRIMARY KEY, user TEXT, ciphertext TEXT, nonce TEXT, created_at INTEGER, updated_at INTEGER)")?;
        let before = std::fs::read(&database)?;
        let checkpoint = std::cell::Cell::new(false);
        let stage = home.join("invalid-stage");
        let error = snapshot_profile_checkpoint(&profile, &stage, &[], true, || {
            checkpoint.set(true);
            Ok(())
        }).err().context("incompatible schema was accepted")?;
        assert!(error.downcast_ref::<InvalidSchema>().is_some());
        assert!(!checkpoint.get());
        assert_eq!(std::fs::read(database)?, before);
        assert!(!stage.join(RECEIPT).exists());
        assert!(!profile.destination.exists());
        Ok(())
    }

    #[test]
    fn durable_schema_rejection_is_terminal_and_releases_conflicts() -> Result<()> {
        let isolate = crate::test_lock::Isolate::new()?;
        std::env::set_var("RSRS_DATA_DIR", isolate.path().canonicalize()?);
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let database = profile.source.join("onememory.db");
        Connection::open(&database)?.execute_batch("CREATE TABLE memories (id INTEGER PRIMARY KEY, user TEXT, ciphertext TEXT, nonce TEXT, created_at INTEGER, updated_at INTEGER)")?;
        let error = migrate_profile_locked(&home, &original.source_id, &original.account, Some(&original))
            .err().context("incompatible schema was accepted")?;
        assert!(error.downcast_ref::<SchemaRejected>().is_some());
        let mut record = load(&home, &original)?.context("missing rejection")?;
        assert!(record.phase == Phase::RejectedSchema);
        let before = std::fs::read(path(&home, &original)?)?;
        // Source disappearance must not erase an already durable operation outcome.
        std::fs::remove_file(database)?;
        std::fs::remove_file(profile.source.join("session.json"))?;
        let error = migrate_profile_locked(&home, &original.source_id, &original.account, Some(&original))
            .err().context("rejected operation was replayed")?;
        assert!(error.downcast_ref::<SchemaRejected>().is_some());
        assert_eq!(std::fs::read(path(&home, &original)?)?, before);
        assert!(!profile.destination.exists());
        record.phase = Phase::Transforming;
        assert!(save(&home, &record).is_err());
        let mut replacement = original.clone();
        replacement.operation_id = uuid::Uuid::new_v4().to_string();
        replacement.key = replacement.operation_id.clone();
        reject_conflicting_admission(&home, Some(&replacement), &replacement.source_id, &replacement.account)?;
        Ok(())
    }

    #[test]
    fn result_query_returns_durable_rejection_without_resnapshot_or_replay() -> Result<()> {
        let isolate = crate::test_lock::Isolate::new()?;
        let root = isolate.path().canonicalize()?;
        std::env::set_var("RSRS_DATA_DIR", &root);
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let saved = ["HOME", "USERPROFILE"].map(|name| (name, std::env::var_os(name)));
        std::env::set_var("HOME", &home);
        std::env::set_var("USERPROFILE", &home);
        let result = (|| -> Result<()> {
            let (mut original, profile) = fixture(&home)?;
            original.fingerprint = hex::encode(Sha256::digest(original.fingerprint_bytes()?));
            Connection::open(profile.source.join("onememory.db"))?.execute_batch(
                "CREATE TABLE memories (id TEXT, user TEXT, ciphertext TEXT, nonce TEXT, created_at INTEGER, updated_at INTEGER)")?;
            let ownership = crate::login_transaction::AuthOwnership::acquire(&root, &root)?;
            let error = control_migrate_profile(&ownership, &original, false)
                .err().context("invalid schema was accepted")?;
            assert!(error.downcast_ref::<SchemaRejected>().is_some());
            let before = std::fs::read(path(&home, &original)?)?;
            let stage = load(&home, &original)?.context("missing rejection")?.stage;
            // The query uses the durable outcome, even if the source is later repaired.
            Connection::open(profile.source.join("onememory.db"))?.execute_batch("DROP TABLE memories")?;
            let error = control_migrate_profile(&ownership, &original, true)
                .err().context("rejection query replayed migration")?;
            assert!(error.downcast_ref::<SchemaRejected>().is_some());
            assert_eq!(std::fs::read(path(&home, &original)?)?, before);
            assert_eq!(load(&home, &original)?.context("missing rejection")?.stage, stage);
            assert!(!profile.destination.exists());
            let mut changed = original.clone();
            changed.account = "changed-binding".into();
            changed.fingerprint = hex::encode(Sha256::digest(changed.fingerprint_bytes()?));
            let error = control_migrate_profile(&ownership, &changed, true)
                .err().context("changed operation accepted rejection")?;
            assert!(error.downcast_ref::<SchemaRejected>().is_none());
            Ok(())
        })();
        for (name, value) in saved {
            match value { Some(value) => std::env::set_var(name, value), None => std::env::remove_var(name) }
        }
        result
    }

    #[test]
    fn rejection_cannot_follow_uncertain_effects_or_a_torn_journal() -> Result<()> {
        use std::io::Write;
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let mut record = admit_or_load(&home, &original, &profile)?;
        record.phase = Phase::Transforming;
        save(&home, &record)?;
        record.phase = Phase::RejectedSchema;
        assert!(save(&home, &record).is_err());
        std::fs::OpenOptions::new().append(true).open(path(&home, &original)?)?.write_all(b"{\"phase\":\"rejected_schema\"")?;
        assert!(load(&home, &original).is_err());
        assert!(migrate_profile_locked(&home, &original.source_id, &original.account, Some(&original)).is_err());
        assert!(!profile.destination.exists());
        Ok(())
    }

    #[test]
    fn intent_never_adopts_unbound_stage_or_different_operation() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let orphan = home.join(".rsrs-migration-staging").join(uuid::Uuid::new_v4().to_string());
        private_directory(&orphan)?;
        write_json(&orphan.join(RECEIPT), &json!({"source_identity":original.source_id,"complete":true}))?;
        assert!(load(&home, &original)?.is_none());
        let record = admit_or_load(&home, &original, &profile)?;
        assert_ne!(record.stage, orphan);
        let mut different = original.clone();
        different.account = "other-account".into();
        assert!(load(&home, &different).is_err());
        different = original.clone();
        different.fingerprint = "different".into();
        assert!(load(&home, &different).is_err());
        different = original.clone();
        different.operation_id = uuid::Uuid::new_v4().to_string();
        different.key = different.operation_id.clone();
        assert!(load(&home, &different)?.is_none());
        Ok(())
    }

    #[test]
    fn intent_rejects_source_change_and_outside_stage() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let mut record = admit_or_load(&home, &original, &profile)?;
        write_json(&profile.source.join("session.json"), &json!({"user":"changed-owner"}))?;
        assert!(admit_or_load(&home, &original, &profile).is_err());
        record.stage = home.join(uuid::Uuid::new_v4().to_string());
        assert!(save(&home, &record).is_err());
        Ok(())
    }

    #[test]
    fn copying_recovers_to_fresh_stage_and_retains_partial_snapshot() -> Result<()> {
        let isolate = crate::test_lock::Isolate::new()?;
        std::env::set_var("RSRS_DATA_DIR", isolate.path().canonicalize()?);
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let record = admit_or_load(&home, &original, &profile)?;
        private_directory(&record.stage)?;
        std::fs::write(record.stage.join("onememory.db"), b"synthetic interrupted copy")?;
        let original_session = std::fs::read(profile.source.join("session.json"))?;
        migrate_profile_locked(&home, &original.source_id, &original.account, Some(&original))?;
        assert!(migration_control_result(&original)?.is_some());
        assert_eq!(std::fs::read(record.stage.join("onememory.db"))?, b"synthetic interrupted copy");
        assert_eq!(std::fs::read(profile.source.join("session.json"))?, original_session);
        let completed = load(&home, &original)?.context("intent disappeared")?;
        assert!(completed.phase == Phase::Ready);
        assert_ne!(completed.stage, record.stage);
        Ok(())
    }

    #[test]
    fn transforming_is_not_replayed_and_never_published() -> Result<()> {
        let isolate = crate::test_lock::Isolate::new()?;
        std::env::set_var("RSRS_DATA_DIR", isolate.path().canonicalize()?);
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let mut record = admit_or_load(&home, &original, &profile)?;
        record.phase = Phase::Transforming;
        private_directory(&record.stage)?;
        std::fs::write(record.stage.join("rsrs.db"), b"uncertain transform")?;
        save(&home, &record)?;
        let intent_before = std::fs::read(path(&home, &original)?)?;
        assert!(migrate_profile_locked(&home, &original.source_id, &original.account, Some(&original)).is_err());
        assert!(!profile.destination.exists());
        assert_eq!(std::fs::read(record.stage.join("rsrs.db"))?, b"uncertain transform");
        assert_eq!(std::fs::read(path(&home, &original)?)?, intent_before);
        record.phase = Phase::Ready;
        save(&home, &record)?;
        assert!(migrate_profile_locked(&home, &original.source_id, &original.account, Some(&original)).is_err());
        assert!(!profile.destination.exists());
        assert_eq!(std::fs::read(record.stage.join("rsrs.db"))?, b"uncertain transform");
        Ok(())
    }

    #[test]
    fn copy_checkpoint_failure_prevents_transform() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (_, profile) = fixture(&home)?;
        let stage = home.join("stage");
        let bytes = std::fs::read(profile.source.join("session.json"))?;
        assert!(snapshot_profile_checkpoint(&profile, &stage, &[], true,
            || Err(anyhow!("synthetic durable checkpoint failure"))).is_err());
        assert_eq!(std::fs::read(stage.join("session.json"))?, bytes);
        assert!(!stage.join(RECEIPT).exists());
        assert!(!profile.destination.exists());
        Ok(())
    }

    #[test]
    fn result_entry_recovers_only_durable_copying_and_is_idempotent() -> Result<()> {
        use respire_protocol::migration_control::HostMigrationOutcome as Outcome;
        let isolate = crate::test_lock::Isolate::new()?;
        let root = isolate.path().canonicalize()?;
        std::env::set_var("RSRS_DATA_DIR", &root);
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let saved = ["HOME", "USERPROFILE"].map(|name| (name, std::env::var_os(name)));
        std::env::set_var("HOME", &home);
        std::env::set_var("USERPROFILE", &home);
        let result = (|| -> Result<()> {
            let (mut original, profile) = fixture(&home)?;
            original.fingerprint = hex::encode(Sha256::digest(original.fingerprint_bytes()?));
            let ownership = crate::login_transaction::AuthOwnership::acquire(&root, &root)?;
            assert!(control_migrate_profile(&ownership, &original, true)?.outcome == Outcome::Unknown);
            assert!(!profile.destination.exists());
            assert!(load(&home, &original)?.is_none());
            admit_or_load(&home, &original, &profile)?;
            let outcome = control_migrate_profile(&ownership, &original, true)?.outcome;
            assert!(outcome == Outcome::Completed);
            let receipt_before = std::fs::read(profile.destination.join(RECEIPT))?;
            let intent_before = std::fs::read(path(&home, &original)?)?;
            assert!(control_migrate_profile(&ownership, &original, true)?.outcome == Outcome::Completed);
            assert_eq!(std::fs::read(profile.destination.join(RECEIPT))?, receipt_before);
            assert_eq!(std::fs::read(path(&home, &original)?)?, intent_before);
            // A separate accepted operation exercises the non-replay phases.
            original.operation_id = uuid::Uuid::new_v4().to_string();
            original.key = original.operation_id.clone();
            original.account = "second-intent-fixture".into();
            original.fingerprint = hex::encode(Sha256::digest(original.fingerprint_bytes()?));
            let mut record = admit_or_load(&home, &original, &profile)?;
            for phase in [Phase::Transforming, Phase::Ready] {
                record.phase = phase;
                save(&home, &record)?;
                let before = std::fs::read(path(&home, &original)?)?;
                assert!(control_migrate_profile(&ownership, &original, true)?.outcome == Outcome::Unknown);
                assert_eq!(std::fs::read(path(&home, &original)?)?, before);
                assert!(!crate::service::accounts_root().join(&original.account).exists());
            }
            Ok(())
        })();
        for (name, value) in saved {
            match value { Some(value) => std::env::set_var(name, value), None => std::env::remove_var(name) }
        }
        result
    }


    #[test]
    fn append_journal_never_falls_back_after_torn_or_regressed_phase() -> Result<()> {
        use std::io::Write;
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let mut record = admit_or_load(&home, &original, &profile)?;
        record.phase = Phase::Transforming;
        save(&home, &record)?;
        record.phase = Phase::Copying;
        assert!(save(&home, &record).is_err());
        let mut file = std::fs::OpenOptions::new().append(true).open(path(&home, &original)?)?;
        file.write_all(b"{\"schema\":1")?;
        file.sync_all()?;
        assert!(load(&home, &original).is_err());
        assert!(admit_or_load(&home, &original, &profile).is_err());
        Ok(())
    }

    #[test]
    fn new_operation_cannot_take_an_unfinished_source_or_account() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        #[cfg(windows)] let _registry_scope = registry::TestScope::new(&home);
        let (original, profile) = fixture(&home)?;
        let mut record = admit_or_load(&home, &original, &profile)?;
        record.phase = Phase::Transforming;
        save(&home, &record)?;
        let before = std::fs::read(path(&home, &original)?)?;
        let mut other = original.clone();
        other.operation_id = uuid::Uuid::new_v4().to_string();
        other.key = other.operation_id.clone();
        other.account = "different-account".into();
        assert!(admit_or_load(&home, &other, &profile).is_err());
        other.account = original.account.clone();
        other.source_id = "a".repeat(64);
        assert!(admit_or_load(&home, &other, &profile).is_err());
        other.account = original.account.to_ascii_uppercase();
        assert!(admit_or_load(&home, &other, &profile).is_err());
        assert!(migrate_profile_locked(&home, &original.source_id, &original.account, None).is_err());
        assert!(!path(&home, &other)?.exists());
        assert_eq!(std::fs::read(path(&home, &original)?)?, before);
        Ok(())
    }

}

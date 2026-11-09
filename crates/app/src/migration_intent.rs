//! Private admission evidence for one exact migration operation.
//!
//! Copying has no external side effects and may be restarted into a fresh stage.
//! Transforming is deliberately not replayable: credential writes and randomized
//! database conversion need a separate transaction journal before that is safe.
//! Unpublished Ready also stays closed until staged data and credentials can be
//! independently revalidated; its receipt alone is not an integrity proof.
use super::*;
use respire_protocol::migration_control::HostMigrationOperation;
use serde::{Deserialize, Serialize};
use std::io::Read;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase { Copying, Transforming, Ready }

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

pub(super) fn load(home: &Path, original: &HostMigrationOperation) -> Result<Option<Intent>> {
    let path = path(home, original)?;
    no_links(&path)?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 64 * 1024, "invalid migration intent size or type");
    let mut bytes = Vec::new();
    std::fs::File::open(&path)?.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 64 * 1024, "migration intent exceeds its size limit");
    let record: Intent = serde_json::from_slice(&bytes)?;
    validate(home, original, &record)?;
    Ok(Some(record))
}

pub(super) fn save(home: &Path, record: &Intent) -> Result<()> {
    validate(home, &record.original, record)?;
    let path = path(home, &record.original)?;
    no_links(&path)?;
    private_directory(path.parent().context("migration intent has no parent")?)?;
    write_json(&path, &serde_json::to_value(record)?)
}

pub(super) fn admit_or_load(home: &Path, original: &HostMigrationOperation, profile: &Profile) -> Result<Intent> {
    if let Some(record) = load(home, original)? {
        verify_source(&record, profile)?;
        return Ok(record);
    }
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

    fn fixture(home: &Path) -> Result<(HostMigrationOperation, Profile)> {
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
    fn intent_never_adopts_unbound_stage_or_different_operation() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
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
            let mut record = admit_or_load(&home, &original, &profile)?;
            // Simulated durable phase records only; no transformation is executed here.
            for phase in [Phase::Transforming, Phase::Ready] {
                record.phase = phase;
                save(&home, &record)?;
                let before = std::fs::read(path(&home, &original)?)?;
                assert!(control_migrate_profile(&ownership, &original, true)?.outcome == Outcome::Unknown);
                assert_eq!(std::fs::read(path(&home, &original)?)?, before);
                assert!(!profile.destination.exists());
            }
            record.phase = Phase::Copying;
            save(&home, &record)?;
            assert!(control_migrate_profile(&ownership, &original, true)?.outcome == Outcome::Completed);
            let receipt_before = std::fs::read(profile.destination.join(RECEIPT))?;
            let intent_before = std::fs::read(path(&home, &original)?)?;
            assert!(control_migrate_profile(&ownership, &original, true)?.outcome == Outcome::Completed);
            assert_eq!(std::fs::read(profile.destination.join(RECEIPT))?, receipt_before);
            assert_eq!(std::fs::read(path(&home, &original)?)?, intent_before);
            Ok(())
        })();
        for (name, value) in saved {
            match value { Some(value) => std::env::set_var(name, value), None => std::env::remove_var(name) }
        }
        result
    }

}

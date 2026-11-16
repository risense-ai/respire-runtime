//! Core recovery snapshots contain only sessions already prepared by the host.
use super::*;

fn validate_snapshot(bytes: &[u8]) -> Result<()> {
    let session: Value = serde_json::from_slice(bytes).context("invalid recovery session; retain recovery")?;
    ensure!(session.is_object(), "invalid recovery session; retain recovery");
    ensure!(["pass", "super", "secret", "secret_key"].iter().all(|field| session.get(*field).is_none()),
        "host_preparation_required: the host must store session factors before starting the Runtime transaction");
    Ok(())
}

pub(super) fn prepare_candidates(journal: &mut Journal) -> Result<()> {
    for record in &journal.operations {
        ensure!(record.candidate_backup.is_none(),
            "host_recovery_required: retain the historical candidate snapshot for host recovery");
        if let Some(bytes) = record.candidate.as_deref() {
            validate_snapshot(bytes)?;
            ensure!(record.candidate_sha256.as_deref() == Some(digest(bytes).as_str()),
                "candidate digest mismatch; retain recovery");
        }
    }
    Ok(())
}

pub(super) fn write(journal: &Journal) -> Result<()> {
    let path = recovery_path();
    std::fs::create_dir_all(path.parent().context("recovery root is missing")?)?;
    private_write(&path, &serde_json::to_vec(journal)?)
}

pub(super) fn original_digest(active: &Recovery) -> Result<Option<String>> {
    ensure!(active.original_backup.is_none() && active.original_backups.is_empty(),
        "host_recovery_required: retain the historical original snapshot for host recovery");
    if let Some(original) = active.original.as_deref() { validate_snapshot(original)?; }
    Ok(active.original.as_deref().map(digest))
}

pub(super) fn prepare(journal: &mut Journal) -> Result<()> {
    if let Some(active) = journal.active.as_ref() {
        original_digest(active)?;
        if let Some(restored) = active.restored.as_deref() { validate_snapshot(restored)?; }
    }
    Ok(())
}

pub(super) fn hydrate(journal: &mut Journal) -> Result<()> {
    prepare_candidates(journal)?;
    prepare(journal)
}

pub(super) fn remove(active: &Recovery) -> Result<()> {
    ensure!(active.retired, "original snapshots cannot be removed before durable retirement");
    ensure!(active.original_backup.is_none() && active.original_backups.is_empty(),
        "host_recovery_required: historical credential cleanup belongs to the host");
    Ok(())
}

pub(super) fn rollback_snapshot(_journal: &mut Journal, record: &Recovery) -> Result<Option<Vec<u8>>> {
    original_digest(record)?;
    // The host has already preserved the original factors; restore the same wrap and metadata.
    Ok(record.original.clone())
}

pub(super) fn matches_original(record: &Recovery, current: &Option<Vec<u8>>) -> bool {
    current == &record.original || record.restored.as_ref().is_some_and(|restored| current.as_ref() == Some(restored))
}

pub(super) fn matches_restored(record: &AuthRecord, profile: &Path, current: &Option<Vec<u8>>) -> bool {
    matches!(record.phase, AuthPhase::RollingBack | AuthPhase::RolledBack)
        && record.restored.as_ref().is_some_and(|restored| restored.profile == profile
            && current.as_deref().map(digest).as_deref() == Some(restored.sha256.as_str()))
}

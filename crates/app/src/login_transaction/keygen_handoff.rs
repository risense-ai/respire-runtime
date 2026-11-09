//! Read-only handoff for a previously committed offline keygen receipt.
use super::*;
use respire_protocol::host_control::{HostAuthKeygenParams, HostKeygenHandoffReceipt,
    HostKeygenRuntimeIdentity, HOST_AUTH_SCHEMA_V};

fn committed_receipt(root: &Path, profile: &Path, operation_id: &str,
    key: &str, params: &HostAuthKeygenParams) -> Result<(String, String)> {
    let journal = load_journal()?;
    ensure!(journal.active.is_none(), "auth recovery blocks keygen handoff");
    let record = journal.operations.iter().find(|record| record.operation_id == operation_id)
        .context("keygen handoff receipt missing")?;
    ensure!(record.root == root && record.profile == profile && record.idempotency_key == key
        && record.fingerprint == keygen_fingerprint(root, profile, params.force)?
        && record.phase == AuthPhase::Committed && record.account.is_none()
        && record.identity.is_none() && record.key_operation.is_none()
        && record.space_operation.is_none() && record.profile_remove.is_none(),
        "keygen handoff receipt mismatch");
    let hash = record.candidate_sha256.as_ref().context("keygen candidate missing")?;
    ensure!(matches!(&params.identity, HostAuthIdentity::Unbound { operation_id: id, session_sha256 }
        if id == operation_id && session_sha256 == hash), "keygen handoff identity mismatch");
    verify_auth_identity(root, profile, &params.identity)?;
    ensure!(read_original(profile)? == record.candidate, "keygen candidate changed");
    // Compare the whole journal record without returning any private material.
    Ok((hash.clone(), digest(&serde_json::to_vec(record)?)))
}

/// The dispatcher supplies a trusted live verifier only after consuming a Verified
/// grant. No AuthOwnership/library lock is acquired beside the serving Runtime.
pub fn control_keygen_complete(operation_id: &str, key: &str, params: &HostAuthKeygenParams,
    mut verify_runtime: impl FnMut(&Path, &HostAuthIdentity) -> Result<HostKeygenRuntimeIdentity>,
) -> Result<HostKeygenHandoffReceipt> {
    crate::service::require_profile_change_host()?;
    canonical_operation_id(operation_id)?;
    ensure!(params.schema_version == HOST_AUTH_SCHEMA_V && !key.is_empty() && key.len() <= 128
        && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "invalid keygen handoff parameters");
    let root = params.binding.installation_root.canonicalize()?;
    let profile = params.binding.profile.canonicalize()?;
    ensure!(root == crate::service::main_data_dir().canonicalize()?
        && profile == crate::service::data_dir().canonicalize()?, "keygen handoff scope changed");
    let _journal_lock = auth_journal_lock()?;
    let before = committed_receipt(&root, &profile, operation_id, key, params)?;
    let runtime = verify_runtime(&profile, &params.identity)?;
    ensure!(before == committed_receipt(&root, &profile, operation_id, key, params)?,
        "keygen receipt changed during live verification");
    Ok(HostKeygenHandoffReceipt { schema_version: HOST_AUTH_SCHEMA_V,
        operation_id: operation_id.to_owned(), session_sha256: before.0,
        path: profile.join("session.json"), runtime })
}

#[cfg(test)]
mod tests;

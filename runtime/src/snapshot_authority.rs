//! Snapshot maintenance authority, separate from fresh worker launch generation.
use anyhow::{Context, Result};
use respire_protocol::maintenance_control::{
    MaintenanceAction as Action, MaintenanceControlParams as Params,
    MaintenanceControlResult as Receipt, MAINTENANCE_CONTROL_METHOD, MAINTENANCE_CONTROL_SCHEMA_V,
};
use respire_protocol::{
    HostControlLaunchGrant, RpcRequest, RuntimeStopOutcome, RuntimeStopReceipt,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::maintenance_control::{Access, RestoreDispatch};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotBinding {
    operation_id: String,
    request_fingerprint: String,
    sync_generation: usize,
    snapshot_id: String,
    account_id: String,
    drained_birth: String,
    #[serde(default)]
    drain: Option<RuntimeStopReceipt>,
    #[serde(default)]
    offline: Option<OfflineProof>,
    #[serde(default)]
    verified_runtime: Option<VerifiedRuntime>,
    #[serde(default)]
    legacy_recovery: Option<respire_protocol::maintenance_control::LegacySnapshotRecoveryBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfflineProof {
    endpoint_sha256: Option<String>,
    endpoint_pid: Option<u32>,
    prior_runtime: Option<VerifiedRuntime>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedRuntime {
    scope: respire_protocol::RuntimeRequestScope,
    pid: u32,
    process_start_id: String,
    image_path: PathBuf,
    image_sha256: String,
    runtime_version: String,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn legacy_request(
    request: &RpcRequest,
) -> Result<respire_protocol::maintenance_control::LegacySnapshotRecoveryParams> {
    use respire_protocol::maintenance_control::LEGACY_SNAPSHOT_RECOVERY_METHOD;
    anyhow::ensure!(
        request.v == respire_commands::rpc_worker::PROTOCOL_V
            && request.method == LEGACY_SNAPSHOT_RECOVERY_METHOD
            && request.args.len() == 1
            && canonical_operation(&request.id)
            && request.scope.is_none()
            && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none()
            && request.lifecycle.is_none(),
        "invalid legacy snapshot recovery request shape"
    );
    let params: respire_protocol::maintenance_control::LegacySnapshotRecoveryParams =
        serde_json::from_str(&request.args[0])?;
    anyhow::ensure!(
        params.schema_version == MAINTENANCE_CONTROL_SCHEMA_V
            && canonical_operation(&params.recovery_operation_id)
            && request.operation_id.as_deref() == Some(params.recovery_operation_id.as_str())
            && request.idempotency_key == request.operation_id
            && digest_shape(&params.journal_sha256)
            && digest_shape(&params.request_fingerprint)
            && legacy_fingerprint(&params)? == params.request_fingerprint,
        "invalid legacy snapshot recovery identity"
    );
    Ok(params)
}

fn canonical_operation(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}

fn digest_shape(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn legacy_fingerprint(
    params: &respire_protocol::maintenance_control::LegacySnapshotRecoveryParams,
) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&(
        "snapshot-legacy-recovery-v1",
        &params.binding.installation_root,
        &params.binding.profile,
        &params.binding.expected_account_id,
        &params.recovery_operation_id,
        &params.journal_sha256,
    ))?))
}

pub(crate) fn validate_legacy_launch(
    grant: &HostControlLaunchGrant,
    bytes: &[u8],
    params: &respire_protocol::maintenance_control::LegacySnapshotRecoveryParams,
) -> Result<()> {
    let snapshot = validate_marker_ownership(grant, bytes, false)?;
    let recovery = snapshot.legacy_recovery.as_ref()
        .context("legacy recovery requires its own marker binding")?;
    anyhow::ensure!(
        snapshot.operation_id.is_empty() && snapshot.request_fingerprint.is_empty()
            && snapshot.sync_generation == 0 && snapshot.snapshot_id.is_empty()
            && params.schema_version == MAINTENANCE_CONTROL_SCHEMA_V
            && canonical_operation(&params.recovery_operation_id)
            && digest_shape(&params.journal_sha256)
            && legacy_fingerprint(params)? == params.request_fingerprint
            && params.binding.installation_root == grant.installation_root
            && params.binding.profile == grant.profile
            && params.binding.launch_id == grant.instance_id
            && params.binding.expected_account_id.as_deref() == Some(grant.account_id.as_str())
            && recovery.account_id == grant.account_id
            && recovery.recovery_operation_id == params.recovery_operation_id
            && recovery.request_fingerprint == params.request_fingerprint
            && recovery.journal_sha256 == params.journal_sha256,
        "legacy recovery differs from its exact capability or impersonates an original operation"
    );
    Ok(())
}

pub(crate) fn authorize_legacy_recovery(
    params: &respire_protocol::maintenance_control::LegacySnapshotRecoveryParams,
) -> Result<()> {
    let grant = crate::startup_identity::consumed_control_grant()?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    crate::startup_identity::verify_managed_boot()?;
    let bytes = crate::startup_identity::read_private_file(&marker_path(grant))?
        .context("legacy snapshot maintenance marker disappeared")?;
    validate_legacy_launch(grant, &bytes, params)
}

pub(crate) fn dispatch_legacy_recovery(
    params: &respire_protocol::maintenance_control::LegacySnapshotRecoveryParams,
    account: &str,
) -> Result<respire_protocol::maintenance_control::LegacySnapshotRecoveryResult> {
    use respire_protocol::maintenance_control::{LegacySnapshotRecoveryAction, LegacySnapshotRecoveryResult};
    use respire_protocol::maintenance_control::MaintenanceState;
    authorize_legacy_recovery(params)?;
    let grant = crate::startup_identity::consumed_control_grant()?;
    anyhow::ensure!(!account.is_empty() && hash(account.as_bytes()) == grant.account_id,
        "legacy snapshot account differs from the authorized grant");
    // Keep the same installation-before-profile lock order as original snapshot maintenance.
    let _owner = respire_app::lock::LibraryLock::acquire(
        &grant.installation_root.join("runtime"), std::time::Duration::ZERO)?;
    let ownership = respire_app::lock::LibraryLock::acquire(
        &grant.profile, std::time::Duration::from_secs(15))?;
    authorize_legacy_recovery(params)?;
    let operation = respire_app::snapshot::SnapshotOperation {
        operation_id: params.recovery_operation_id.clone(),
        request_fingerprint: params.request_fingerprint.clone(),
    };
    let mut status = respire_app::snapshot::legacy_recovery_status(
        &grant.profile, account, &operation, &params.journal_sha256)?;
    // A recorded recovery is query-only even when the caller repeats Recover.
    if status.is_none() && params.action == LegacySnapshotRecoveryAction::Recover {
        let description = respire_app::snapshot::describe_legacy_recovery(&grant.profile, account)?;
        anyhow::ensure!(description.journal_sha256 == params.journal_sha256
            && description.account_fingerprint == grant.account_id,
            "legacy journal differs from the approved recovery description");
        respire_app::service::ensure_writable()?;
        authorize_legacy_recovery(params)?;
        status = Some(respire_app::snapshot::recover_legacy_locked(
            &grant.profile, account, &description, &operation, &ownership)?);
    }
    authorize_legacy_recovery(params)?;
    let (state, cleanup_pending, cleanup_warning) = match status {
        Some(status) => (legacy_stage(&status.phase)?, status.cleanup_pending, status.cleanup_warning),
        None => (MaintenanceState::Unknown, false, None),
    };
    Ok(LegacySnapshotRecoveryResult {
        recovery_operation_id: params.recovery_operation_id.clone(),
        request_fingerprint: params.request_fingerprint.clone(),
        journal_sha256: params.journal_sha256.clone(),
        state,
        cleanup_pending,
        cleanup_warning,
    })
}

fn legacy_stage(phase: &str) -> Result<respire_protocol::maintenance_control::MaintenanceState> {
    use respire_protocol::maintenance_control::MaintenanceState;
    match phase {
        "prepared" => Ok(MaintenanceState::Prepared),
        "installed" => Ok(MaintenanceState::Installed),
        "verified" => Ok(MaintenanceState::Verified),
        "released" => Ok(MaintenanceState::Released),
        "rolled_back" => Ok(MaintenanceState::RolledBack),
        _ => anyhow::bail!("unsupported legacy snapshot journal stage"),
    }
}

fn marker_path(grant: &HostControlLaunchGrant) -> PathBuf {
    grant
        .installation_root
        .join("runtime/autostart/maintenance.json")
}

/// Called by startup's existing maintenance check for the Paused snapshot case
/// only. Normal grant image/registration/context checks must still run there.
pub(crate) fn validate_offline_launch(grant: &HostControlLaunchGrant, bytes: &[u8]) -> Result<()> {
    validate_marker(grant, bytes, false).map(|_| ())
}

/// Distinct startup role: metadata finalization, never offline DB replacement.
pub(crate) fn validate_finalize_launch(grant: &HostControlLaunchGrant, bytes: &[u8]) -> Result<()> {
    let snapshot = validate_marker(grant, bytes, true)?;
    verify_runtime(grant, &snapshot)
}

fn validate_marker(
    grant: &HostControlLaunchGrant,
    bytes: &[u8],
    finalize: bool,
) -> Result<SnapshotBinding> {
    let snapshot = validate_marker_ownership(grant, bytes, finalize)?;
    anyhow::ensure!(snapshot.legacy_recovery.is_none(),
        "legacy recovery cannot impersonate an original snapshot operation");
    let params = Params {
        schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
        binding: respire_protocol::ControlBinding {
            installation_root: grant.installation_root.clone(),
            profile: grant.profile.clone(),
            launch_id: grant.instance_id.clone(),
            expected_account_id: Some(snapshot.account_id.clone()),
        },
        operation_id: snapshot.operation_id.clone(),
        request_fingerprint: snapshot.request_fingerprint.clone(),
        sync_generation: snapshot.sync_generation,
        snapshot_id: snapshot.snapshot_id.clone(),
        action: Action::Query,
    };
    anyhow::ensure!(
        uuid::Uuid::parse_str(&snapshot.operation_id)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == snapshot.operation_id)
            && snapshot.snapshot_id.len() == 32
            && snapshot.snapshot_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && crate::maintenance_control::fingerprint(&params)? == snapshot.request_fingerprint,
        "invalid snapshot marker operation identity"
    );
    Ok(snapshot)
}

fn validate_marker_ownership(
    grant: &HostControlLaunchGrant,
    bytes: &[u8],
    finalize: bool,
) -> Result<SnapshotBinding> {
    anyhow::ensure!(
        bytes.len() <= 16 * 1024,
        "snapshot maintenance marker too large"
    );
    let marker: serde_json::Value = serde_json::from_slice(bytes)?;
    let binding = grant
        .maintenance
        .as_ref()
        .context("snapshot maintenance grant missing")?;
    anyhow::ensure!(
        hash(bytes) == binding.marker_sha256
            && marker["schema"] == 1
            && marker["phase"] == if finalize { "Verified" } else { "Paused" }
            && marker["id"] == binding.coordinator_id
            && marker["owner_pid"] == binding.controller_pid
            && marker["owner_birth"] == binding.controller_birth
            && marker["expected_version"] == binding.issuer_cli_version
            && marker["expected_profile"].as_str().map(Path::new) == Some(grant.profile.as_path())
            && marker["token"]
                .as_str()
                .is_some_and(|token| uuid::Uuid::parse_str(token).is_ok())
            && binding.controller_pid == grant.supervisor_pid
            && binding.controller_birth == grant.supervisor_birth
            && binding.controller_pid > 0
            && !binding.controller_birth.is_empty()
            && !binding.issuer_cli_version.is_empty()
            && crate::startup_identity::process_birth(binding.controller_pid)?.as_deref()
                == Some(binding.controller_birth.as_str()),
        "snapshot requires the exact live controller's role-specific marker"
    );
    let snapshot: SnapshotBinding = serde_json::from_value(marker["snapshot"].clone())?;
    anyhow::ensure!(
        if finalize {
            snapshot.verified_runtime.is_some()
        } else {
            snapshot.verified_runtime.is_none()
        },
        "snapshot marker role mismatch"
    );
    anyhow::ensure!(
        snapshot.account_id == grant.account_id
            && matches!(
                (&snapshot.drain, &snapshot.offline),
                (Some(_), None) | (None, Some(_))
            ),
        "snapshot requires exactly one drain or offline ownership proof"
    );
    if let Some(proof) = snapshot.offline.as_ref() {
        anyhow::ensure!(
            snapshot.drained_birth.is_empty(),
            "offline proof cannot impersonate drain"
        );
        verify_offline_proof(grant, proof, !finalize)?;
    }
    if let Some(receipt) = snapshot.drain.as_ref() {
        let prefix = if cfg!(windows) {
            "windows-filetime-"
        } else if cfg!(target_os = "linux") {
            "linux-starttime-"
        } else {
            "darwin-lstart-"
        };
        anyhow::ensure!(
            receipt.schema_version == 1
                && receipt.protocol_version == grant.protocol_version
                && receipt.state == RuntimeStopOutcome::Drained
                && receipt.unfinished.is_empty()
                && receipt.pid > 0
                && receipt.pid != grant.supervisor_pid
                && receipt.pid != std::process::id()
                && receipt.generation > 0
                && receipt.installation_id == grant.installation_id
                && receipt.account_id == grant.account_id
                && snapshot.account_id == grant.account_id
                && !receipt.operation_id.is_empty()
                && !receipt.image_path.is_empty()
                && !receipt.image_sha256.is_empty()
                && !receipt.runtime_version.is_empty()
                && !snapshot.drained_birth.is_empty()
                && receipt.process_start_id == format!("{prefix}{}", snapshot.drained_birth)
                && !receipt.instance_id.is_empty()
                && receipt.instance_id.len() <= 128
                && receipt
                    .instance_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && crate::startup_identity::process_birth(receipt.pid)?.as_deref()
                    != Some(snapshot.drained_birth.as_str()),
            "snapshot has no complete authenticated dead-owner drain"
        );
        let receipt_path = grant
            .installation_root
            .join("runtime")
            .join(format!("stop-{}.json", receipt.instance_id));
        let stored = crate::startup_identity::read_private_file(&receipt_path)?
            .context("snapshot final stop receipt missing")?;
        let stored: RuntimeStopReceipt = serde_json::from_slice(&stored)?;
        anyhow::ensure!(
            stored == *receipt,
            "snapshot stop receipt differs from published drain"
        );
    }
    Ok(snapshot)
}

fn offline_endpoint_matches(proof: &OfflineProof, bytes: Option<&[u8]>) -> Result<bool> {
    match (&proof.endpoint_sha256, proof.endpoint_pid, bytes) {
        (None, None, None) => Ok(true),
        (Some(digest), Some(pid), Some(bytes)) if pid > 0 && bytes.len() <= 16 * 1024 => {
            let value: serde_json::Value = serde_json::from_slice(bytes)?;
            Ok(digest == &hash(bytes) && value["pid"].as_u64() == Some(u64::from(pid)))
        }
        _ => Ok(false),
    }
}

fn verify_offline_proof(
    grant: &HostControlLaunchGrant,
    proof: &OfflineProof,
    current: bool,
) -> Result<()> {
    anyhow::ensure!(
        match (&proof.endpoint_sha256, proof.endpoint_pid) {
            (None, None) => true,
            (Some(digest), Some(pid)) =>
                pid > 0
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            _ => false,
        },
        "snapshot offline endpoint proof malformed"
    );
    if let Some(prior) = proof.prior_runtime.as_ref() {
        anyhow::ensure!(
            prior.pid > 0 && !prior.process_start_id.is_empty(),
            "snapshot offline prior process identity missing"
        );
    }
    // A Verified target legitimately replaces the endpoint. Its strict callback
    // fences that live identity instead; absence is an Offline capability only.
    if !current {
        return Ok(());
    }
    let bytes = crate::startup_identity::read_private_file(
        &grant.installation_root.join("runtime/endpoint.json"),
    )?;
    anyhow::ensure!(
        offline_endpoint_matches(proof, bytes.as_deref())?,
        "snapshot offline endpoint changed"
    );
    if let Some(pid) = proof.endpoint_pid {
        anyhow::ensure!(
            crate::startup_identity::process_birth(pid)?.is_none(),
            "snapshot recorded owner is alive/unobservable; no offline authorization"
        );
    }
    if let Some(prior) = proof.prior_runtime.as_ref() {
        let prefix = if cfg!(windows) {
            "windows-filetime-"
        } else if cfg!(target_os = "linux") {
            "linux-starttime-"
        } else {
            "darwin-lstart-"
        };
        anyhow::ensure!(
            !crate::startup_identity::process_birth(prior.pid)?
                .is_some_and(|birth| prior.process_start_id == format!("{prefix}{birth}")),
            "snapshot previous Runtime still lives; real drain required"
        );
    }
    Ok(())
}

/// Rechecked before lock acquisition, before replacement and after the action
/// by maintenance_control. Never delegates to read-only verify_control_binding.
pub(crate) fn authorize_offline(params: &Params, access: Access) -> Result<()> {
    anyhow::ensure!(
        matches!(access, Access::Offline | Access::StartRestore)
            && !matches!(params.action, Action::Commit | Action::Release),
        "snapshot offline capability cannot finalize a serving store"
    );
    let grant = crate::startup_identity::consumed_control_grant()?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    // Reuse current image/account/registration and controller fencing, with the
    // parent's narrowly scoped Paused snapshot hook in startup validation.
    crate::startup_identity::verify_managed_boot()?;
    let bytes = crate::startup_identity::read_private_file(&marker_path(grant))?
        .context("snapshot maintenance marker disappeared")?;
    let snapshot = validate_marker(grant, &bytes, false)?;
    anyhow::ensure!(
        params.schema_version == MAINTENANCE_CONTROL_SCHEMA_V
            && params.binding.installation_root == grant.installation_root
            && params.binding.profile == grant.profile
            && params.binding.launch_id == grant.instance_id
            && params.binding.expected_account_id.as_deref() == Some(snapshot.account_id.as_str())
            && params.operation_id == snapshot.operation_id
            && params.request_fingerprint == snapshot.request_fingerprint
            && params.sync_generation == snapshot.sync_generation
            && params.snapshot_id == snapshot.snapshot_id,
        "snapshot request differs from the consumed marker capability"
    );
    // grant.sync_generation describes this fresh process, not the original O.
    Ok(())
}

/// Fixed method dispatch connects the authority directly to the existing
/// snapshot executor and journal; no generic command or alternate lock path.
pub(crate) fn dispatch_offline(
    request: &RpcRequest,
    account: &str,
    keys: Option<&respire_app::SessionKeys>,
    dispatch: RestoreDispatch,
) -> Result<Receipt> {
    let params = parse_request(request)?;
    authorize_offline(&params, Access::Offline)?;
    // Same installation owner as serve: held across the existing library lock,
    // journal transaction and repeated authorization. Never used by finalizers.
    let _owner = respire_app::lock::LibraryLock::acquire(
        &params.binding.installation_root.join("runtime"),
        std::time::Duration::ZERO,
    )
    .context("snapshot installation ownership unavailable; no offline DB access")?;
    crate::maintenance_control::execute_offline(&params, account, keys, dispatch, authorize_offline)
}

fn parse_request(request: &RpcRequest) -> Result<Params> {
    anyhow::ensure!(
        request.v == respire_commands::rpc_worker::PROTOCOL_V
            && request.method == MAINTENANCE_CONTROL_METHOD
            && request.args.len() == 1
            && uuid::Uuid::parse_str(&request.id)
                .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == request.id)
            && request.scope.is_none()
            && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none()
            && request.lifecycle.is_none(),
        "invalid snapshot maintenance request shape"
    );
    let params: Params = serde_json::from_str(&request.args[0])?;
    anyhow::ensure!(
        request.operation_id.as_deref() == Some(params.operation_id.as_str())
            && request.idempotency_key == request.operation_id,
        "snapshot request operation ID mismatch"
    );
    Ok(params)
}

/// Full target fencing is independent of the fresh helper's instance/generation.
/// Health is an actor report, not by itself evidence of process ownership.
fn verify_runtime(grant: &HostControlLaunchGrant, snapshot: &SnapshotBinding) -> Result<()> {
    let target = snapshot
        .verified_runtime
        .as_ref()
        .context("verified snapshot target missing")?;
    anyhow::ensure!(
        target.pid > 0
            && target.pid != std::process::id()
            && target.pid != grant.supervisor_pid
            && target.scope.generation > 0
            && !target.scope.instance_id.is_empty()
            && target.scope.account_id == snapshot.account_id
            && target.image_path.is_absolute()
            && target.image_path.canonicalize()? == target.image_path
            && target.image_path == grant.image_path
            && target
                .image_sha256
                .eq_ignore_ascii_case(&grant.image_sha256)
            && !target.runtime_version.is_empty(),
        "invalid verified snapshot target identity"
    );
    let birth = crate::startup_identity::process_birth(target.pid)?
        .context("verified snapshot Runtime exited")?;
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    anyhow::ensure!(
        target.process_start_id == format!("{prefix}{birth}"),
        "verified snapshot Runtime PID was reused"
    );
    let process = verified_process(target.pid, &birth, &target.process_start_id)?;
    anyhow::ensure!(
        process == target.image_path
            && crate::startup_identity::hash_file(&target.image_path)?
                .eq_ignore_ascii_case(&target.image_sha256),
        "verified snapshot native process or image differs from marker"
    );
    let health = respire_commands::net_rpc::health()?;
    let scope: respire_protocol::RuntimeRequestScope =
        serde_json::from_value(respire_commands::net_rpc::request_scope(&health)?)?;
    anyhow::ensure!(
        scope == target.scope
            && health.pid == target.pid
            && health.v == grant.protocol_version
            && health.process_start_id == target.process_start_id
            && health.installation_id == grant.installation_id
            && Path::new(&health.installation_root).canonicalize()? == grant.installation_root
            && Path::new(&health.data_dir).canonicalize()? == grant.profile
            && Path::new(&health.image_path).canonicalize()? == target.image_path
            && Path::new(&health.exe).canonicalize()? == target.image_path
            && health
                .image_sha256
                .eq_ignore_ascii_case(&target.image_sha256)
            && health.runtime_version == target.runtime_version
            && health.store_ready
            && health.snapshot_restore_id.as_deref() == Some(snapshot.snapshot_id.as_str()),
        "verified snapshot actor/store identity differs from marker"
    );
    anyhow::ensure!(
        crate::startup_identity::process_birth(target.pid)?.as_deref() == Some(birth.as_str())
            && verified_process(target.pid, &birth, &target.process_start_id)? == process,
        "verified snapshot process changed during actor verification"
    );
    Ok(())
}

fn verified_process(pid: u32, birth: &str, process_start_id: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        crate::startup_identity::process_birth(pid)?.as_deref() == Some(birth),
        "snapshot target process changed before native image inspection"
    );
    #[cfg(target_os = "linux")]
    {
        // The older commands inspector only recognizes combined-CLI argv on
        // Linux. Use its same procfs image authority, pinned to the native birth.
        let _ = process_start_id;
        let image = std::fs::read_link(format!("/proc/{pid}/exe"))?.canonicalize()?;
        anyhow::ensure!(
            crate::startup_identity::process_birth(pid)?.as_deref() == Some(birth),
            "snapshot target process changed during procfs inspection"
        );
        Ok(image)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let process = respire_commands::net_rpc::runtime_process_identity(pid)?;
        anyhow::ensure!(
            process.started_at == birth || process.started_at == process_start_id,
            "snapshot native process birth differs from marker"
        );
        Ok(Path::new(&process.executable).canonicalize()?)
    }
}

pub(crate) fn authorize_finalize(params: &Params, access: Access) -> Result<()> {
    anyhow::ensure!(
        access == Access::Finalize
            && matches!(
                params.action,
                Action::Commit | Action::Release | Action::Query
            ),
        "Verified metadata helper cannot perform offline replacement"
    );
    let grant = crate::startup_identity::consumed_control_grant()?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    crate::startup_identity::verify_managed_boot()?;
    let bytes = crate::startup_identity::read_private_file(&marker_path(grant))?
        .context("Verified snapshot marker disappeared")?;
    let snapshot = validate_marker(grant, &bytes, true)?;
    anyhow::ensure!(
        params.schema_version == MAINTENANCE_CONTROL_SCHEMA_V
            && params.binding.installation_root == grant.installation_root
            && params.binding.profile == grant.profile
            && params.binding.launch_id == grant.instance_id
            && params.binding.expected_account_id.as_deref() == Some(snapshot.account_id.as_str())
            && params.operation_id == snapshot.operation_id
            && params.request_fingerprint == snapshot.request_fingerprint
            && params.sync_generation == snapshot.sync_generation
            && params.snapshot_id == snapshot.snapshot_id,
        "snapshot finalization differs from consumed Verified capability"
    );
    verify_runtime(grant, &snapshot)?;
    let after = crate::startup_identity::read_private_file(&marker_path(grant))?
        .context("Verified snapshot marker disappeared during verification")?;
    validate_marker(grant, &after, true)?;
    Ok(())
}

/// Existing execute_verified owns journal semantics and cleanup warnings. This
/// helper never acquires a library lock, opens a store, or replaces DB files.
pub(crate) fn dispatch_finalize(request: &RpcRequest, account: &str) -> Result<Receipt> {
    let params = parse_request(request)?;
    crate::maintenance_control::execute_verified(
        &params,
        account,
        authorize_finalize,
        |binding, snapshot_id| verify_snapshot_store(&params, binding, snapshot_id),
    )
}

/// Independent strict callback at execute_verified's verify-before-commit gate.
fn verify_snapshot_store(
    params: &Params,
    binding: &respire_protocol::ControlBinding,
    snapshot_id: &str,
) -> Result<()> {
    anyhow::ensure!(
        binding.installation_root == params.binding.installation_root
            && binding.profile == params.binding.profile
            && binding.launch_id == params.binding.launch_id
            && binding.expected_account_id == params.binding.expected_account_id
            && snapshot_id == params.snapshot_id,
        "snapshot verify callback binding mismatch"
    );
    authorize_finalize(params, Access::Finalize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_endpoint_evidence_is_exact_not_health_or_drain() -> Result<()> {
        let absent = OfflineProof {
            endpoint_sha256: None,
            endpoint_pid: None,
            prior_runtime: None,
        };
        let bytes = br#"{"pid":123,"v":1}"#;
        assert!(offline_endpoint_matches(&absent, None)?);
        assert!(!offline_endpoint_matches(&absent, Some(bytes))?);
        let proof = OfflineProof {
            endpoint_sha256: Some(hash(bytes)),
            endpoint_pid: Some(123),
            prior_runtime: None,
        };
        assert!(offline_endpoint_matches(&proof, Some(bytes))?);
        assert!(!offline_endpoint_matches(&proof, None)?);
        assert!(!offline_endpoint_matches(
            &proof,
            Some(br#"{"pid":124,"v":1}"#)
        )?);
        let wrong_pid = OfflineProof {
            endpoint_sha256: Some(hash(bytes)),
            endpoint_pid: Some(124),
            prior_runtime: None,
        };
        assert!(!offline_endpoint_matches(&wrong_pid, Some(bytes))?);
        let partial = OfflineProof {
            endpoint_sha256: Some(hash(bytes)),
            endpoint_pid: None,
            prior_runtime: None,
        };
        assert!(!offline_endpoint_matches(&partial, Some(bytes))?);
        let malformed = OfflineProof {
            endpoint_sha256: Some(hash(b"invalid")),
            endpoint_pid: Some(123),
            prior_runtime: None,
        };
        assert!(offline_endpoint_matches(&malformed, Some(b"invalid")).is_err());
        let oversized = vec![b' '; 16 * 1024 + 1];
        assert!(!offline_endpoint_matches(&proof, Some(&oversized))?);
        Ok(())
    }
}

//! Snapshot-only control client. Lifecycle/drain and maintenance grants belong
//! to the coordinator; this module never opens the business store.
use std::path::Path;
use std::time::Instant;

use super::lifecycle::MAINTENANCE_MARKER_MAX_BYTES;
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::maintenance_control::{
    MaintenanceAction as Action, MaintenanceControlParams as Params,
    MaintenanceControlResult as Receipt, MaintenanceState as State, MAINTENANCE_CONTROL_METHOD,
    MAINTENANCE_CONTROL_SCHEMA_V,
};
use respire_protocol::{ControlBinding, HostControlLaunchGrant, RpcRequest, RpcResponse};
use sha2::{Digest, Sha256};
use respire_protocol::maintenance_control::{LegacySnapshotRecoveryParams as LegacyParams, LegacySnapshotRecoveryResult as LegacyReceipt,
    LEGACY_SNAPSHOT_RECOVERY_METHOD};
pub(crate) use respire_protocol::maintenance_control::LegacySnapshotDescriptor;

fn digest_shape(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn validate_legacy_descriptor(descriptor: &LegacySnapshotDescriptor) -> Result<()> {
    anyhow::ensure!(digest_shape(&descriptor.journal_sha256) && digest_shape(&descriptor.account_id)
        && descriptor.stage != State::Unknown, "invalid legacy snapshot descriptor");
    Ok(())
}

pub(crate) fn legacy_fingerprint(params: &LegacyParams) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&(
        "snapshot-legacy-recovery-v1", &params.binding.installation_root,
        &params.binding.profile, &params.binding.expected_account_id,
        &params.recovery_operation_id, &params.journal_sha256))?)))
}

/// One fixed exchange. A failed response never starts another recovery operation.
pub(crate) fn dispatch_legacy_snapshot(
    takeover: &LibraryLock,
    grant: &HostControlLaunchGrant,
    params: &LegacyParams,
) -> Result<LegacyReceipt> {
    crate::runtime_policy::require_host("legacy snapshot recovery")?;
    let operation = uuid::Uuid::parse_str(&params.recovery_operation_id)?;
    anyhow::ensure!(params.schema_version == MAINTENANCE_CONTROL_SCHEMA_V
        && operation.get_version_num() == 4 && operation.to_string() == params.recovery_operation_id
        && digest_shape(&params.journal_sha256)
        && params.request_fingerprint == legacy_fingerprint(params)?
        && params.binding.installation_root == grant.installation_root
        && params.binding.profile == grant.profile
        && params.binding.expected_account_id.as_deref() == Some(grant.account_id.as_str())
        && params.binding.launch_id == grant.instance_id
        && takeover.protects(&grant.installation_root.join("runtime/takeover"))?,
        "legacy snapshot request binding mismatch");
    let path = grant.installation_root.join("runtime/autostart/maintenance.json");
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(MAINTENANCE_MARKER_MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    let marker: serde_json::Value = serde_json::from_slice(&bytes)?;
    let capability = grant.maintenance.as_ref().context("legacy snapshot maintenance grant missing")?;
    let bound = &marker["snapshot"]["legacy_recovery"];
    anyhow::ensure!(bytes.len() <= MAINTENANCE_MARKER_MAX_BYTES
        && format!("{:x}", Sha256::digest(&bytes)) == capability.marker_sha256
        && marker["phase"] == "Paused" && marker["id"] == capability.coordinator_id
        && marker["owner_pid"] == capability.controller_pid
        && marker["owner_birth"] == capability.controller_birth
        && marker["expected_version"] == capability.issuer_cli_version
        && marker["expected_profile"].as_str().map(Path::new) == Some(grant.profile.as_path())
        && capability.controller_pid == std::process::id()
        && capability.controller_pid == grant.supervisor_pid
        && capability.controller_birth == grant.supervisor_birth
        && bound["recovery_operation_id"] == params.recovery_operation_id
        && bound["request_fingerprint"] == params.request_fingerprint
        && bound["journal_sha256"] == params.journal_sha256
        && bound["account_id"] == grant.account_id
        && marker["snapshot"]["verified_runtime"].is_null(),
        "legacy snapshot helper requires its exact Paused recovery marker");
    let request = RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(), method: LEGACY_SNAPSHOT_RECOVERY_METHOD.to_owned(),
        args: vec![serde_json::to_string(params)?], scope: None,
        operation_id: Some(params.recovery_operation_id.clone()),
        idempotency_key: Some(params.recovery_operation_id.clone()), parent_operation_id: None,
        queue_wait_ms: None, lifecycle: None };
    let result = super::supervise::exchange_snapshot_control(&grant.image_path, grant, &request,
        Instant::now() + std::time::Duration::from_secs(60), |response, pid| {
        anyhow::ensure!(response.v == request.v && response.id == request.id
            && response.bin == "rsrs-runtime" && response.pid == Some(pid)
            && response.operation_id == request.operation_id && response.idempotency_key == request.idempotency_key
            && response.scope.is_none() && response.web_url.is_none()
            && response.data_dir.as_deref().map(Path::new) == Some(grant.profile.as_path()),
            "legacy snapshot response identity mismatch");
        if !response.ok || response.exit != 0 || response.code.is_some() || response.error.is_some() {
            return Err(SnapshotRemoteFailure { code: response.code, exit: response.exit,
                validation_reason: None }.into());
        }
        let envelope = response.envelope.context("legacy snapshot receipt missing")?;
        let receipt: LegacyReceipt = serde_json::from_value(envelope.summary.clone())?;
        anyhow::ensure!(envelope.command == "snapshot"
            && receipt.recovery_operation_id == params.recovery_operation_id
            && receipt.request_fingerprint == params.request_fingerprint
            && receipt.journal_sha256 == params.journal_sha256
            && (receipt.cleanup_warning.is_none() || receipt.cleanup_pending)
            && (receipt.state != State::Unknown || (!receipt.cleanup_pending && receipt.cleanup_warning.is_none()))
            && if receipt.cleanup_pending { matches!(envelope.status, Status::Warn)
                && (envelope.errors.is_empty() || envelope.errors.as_slice()
                    == receipt.cleanup_warning.as_ref().map(std::slice::from_ref).unwrap_or_default())
            } else { matches!(envelope.status, Status::Ok) && envelope.errors.is_empty() },
            "legacy snapshot receipt mismatch");
        for (name, value, ok) in [("control_ready", "true", true), ("store_ready", "false", false)] {
            let mut items = envelope.items.iter().filter(|item| item.name == name);
            anyhow::ensure!(items.next().is_some_and(|item| item.value == value
                && if ok { matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) })
                && items.next().is_none(), "legacy snapshot readiness mismatch");
        }
        Ok(envelope)
    }).context("snapshot_outcome_unknown; query the same recovery operation; no recovery replayed")?;
    serde_json::from_value(result.summary).context("invalid legacy snapshot result")
}

/// Keep this original request identity across helper exits, restart and query.
/// Reconstructing it never authorizes replay; the Runtime journal decides that.
pub(crate) struct SnapshotOperation {
    original: Params,
}

#[derive(Debug)]
pub(crate) struct SnapshotOutcomeUnknown {
    pub operation_id: String,
    pub request_fingerprint: String,
    pub snapshot_id: String,
    pub sync_generation: usize,
}

impl std::fmt::Display for SnapshotOutcomeUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot_outcome_unknown operation_id={}; query the original operation before replay or compensation", self.operation_id)
    }
}

impl std::error::Error for SnapshotOutcomeUnknown {}

/// Preserve Runtime error codes for the parent's fixed rejection mapping.
/// A code alone is not permission to replay; unconfirmed writes remain unknown.
#[derive(Debug)]
pub(crate) struct SnapshotRemoteFailure {
    pub code: Option<String>,
    pub exit: i32,
    validation_reason: Option<&'static str>,
}

impl std::fmt::Display for SnapshotRemoteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("snapshot Runtime did not confirm a receipt")?;
        if let Some(reason) = self.validation_reason {
            write!(f, "; validation cause: {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SnapshotRemoteFailure {}

impl SnapshotOperation {
    /// Accept the exact original DTO, including its fingerprint and generation.
    /// The first caller creates O once; reconnect callers reuse that same O.
    pub(crate) fn from_original(original: Params) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&original.operation_id)
            .context("invalid snapshot operation ID")?;
        anyhow::ensure!(
            original.schema_version == MAINTENANCE_CONTROL_SCHEMA_V
                && id.get_version_num() == 4
                && id.to_string() == original.operation_id
                && original.snapshot_id.len() == 32
                && original
                    .snapshot_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid original snapshot operation"
        );
        let binding = &original.binding;
        anyhow::ensure!(
            binding.installation_root.is_absolute()
                && binding.profile.is_absolute()
                && binding.installation_root.canonicalize()? == binding.installation_root
                && binding.profile.canonicalize()? == binding.profile
                && binding
                    .expected_account_id
                    .as_deref()
                    .is_some_and(|id| id.len() == 64
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
                && original.request_fingerprint
                    == Self::fingerprint(binding, original.sync_generation, &original.snapshot_id)?,
            "original snapshot operation binding or fingerprint mismatch"
        );
        Ok(Self { original })
    }

    /// Exactly the Runtime tuple: no action, launch ID or request ID in the hash.
    pub(crate) fn fingerprint(
        binding: &ControlBinding,
        generation: usize,
        snapshot_id: &str,
    ) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                "snapshot-restore-v1",
                &binding.installation_root,
                &binding.profile,
                &binding.expected_account_id,
                generation,
                snapshot_id,
            ))?)
        ))
    }

    pub(crate) fn original(&self) -> &Params {
        &self.original
    }

    fn request(&self, binding: ControlBinding, action: Action) -> Result<RpcRequest> {
        anyhow::ensure!(
            binding.installation_root == self.original.binding.installation_root
                && binding.profile == self.original.binding.profile
                && binding.expected_account_id == self.original.binding.expected_account_id
                && !binding.launch_id.is_empty(),
            "snapshot reconnect changed the original operation owner"
        );
        let mut params = self.original.clone();
        params.binding = binding;
        params.action = action;
        Ok(RpcRequest {
            v: respire_commands::rpc_client::PROTOCOL_V,
            id: uuid::Uuid::new_v4().to_string(),
            method: MAINTENANCE_CONTROL_METHOD.to_owned(),
            args: vec![serde_json::to_string(&params)?],
            scope: None,
            operation_id: Some(params.operation_id.clone()),
            idempotency_key: Some(params.operation_id),
            parent_operation_id: None,
            queue_wait_ms: None,
            lifecycle: None,
        })
    }

    /// Exactly one bounded two-frame exchange, with no retry or compensation.
    /// The parent must supply a consumed Offline grant backed by proven owner
    /// exit, not just a failed health probe. No profile library lock is taken.
    pub(crate) fn offline(
        &self,
        takeover: &LibraryLock,
        binary: &Path,
        grant: &HostControlLaunchGrant,
        action: Action,
        deadline: Instant,
    ) -> Result<Receipt> {
        crate::runtime_policy::require_host("snapshot maintenance control")?;
        anyhow::ensure!(
            matches!(
                action,
                Action::Restore | Action::Rollback | Action::Recover | Action::Query
            ),
            "snapshot commit/release requires the dedicated Verified helper"
        );
        self.helper(takeover, binary, grant, action, "Paused", deadline)
    }

    /// Dedicated metadata finalizer. Verified never authorizes Restore/Recover
    /// or Rollback; the target Runtime retains its live store and library lock.
    pub(crate) fn finalize_helper(
        &self,
        takeover: &LibraryLock,
        binary: &Path,
        grant: &HostControlLaunchGrant,
        action: Action,
        deadline: Instant,
    ) -> Result<Receipt> {
        crate::runtime_policy::require_host("snapshot Verified metadata finalization")?;
        anyhow::ensure!(
            matches!(action, Action::Commit | Action::Release | Action::Query),
            "Verified snapshot helper cannot replace the offline store"
        );
        self.helper(takeover, binary, grant, action, "Verified", deadline)
    }

    fn helper(
        &self,
        takeover: &LibraryLock,
        binary: &Path,
        grant: &HostControlLaunchGrant,
        action: Action,
        phase: &str,
        deadline: Instant,
    ) -> Result<Receipt> {
        anyhow::ensure!(
            takeover.protects(&grant.installation_root.join("runtime/takeover"))?
                && grant.maintenance.is_some()
                && grant.image_path == binary.canonicalize()?,
            "snapshot control requires matching takeover, image and maintenance grant"
        );
        let path = grant
            .installation_root
            .join("runtime/autostart/maintenance.json");
        let file = std::fs::File::open(path)?;
        anyhow::ensure!(
            file.metadata()?.len() <= MAINTENANCE_MARKER_MAX_BYTES as u64,
            "snapshot marker too large"
        );
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(MAINTENANCE_MARKER_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let marker: serde_json::Value = serde_json::from_slice(&bytes)?;
        let capability = grant
            .maintenance
            .as_ref()
            .context("snapshot maintenance grant missing")?;
        let bound = &marker["snapshot"];
        anyhow::ensure!(
            bytes.len() <= MAINTENANCE_MARKER_MAX_BYTES
                && format!("{:x}", Sha256::digest(&bytes)) == capability.marker_sha256
                && marker["phase"] == phase
                && marker["id"] == capability.coordinator_id
                && marker["owner_pid"] == capability.controller_pid
                && marker["owner_birth"] == capability.controller_birth
                && marker["expected_version"] == capability.issuer_cli_version
                && marker["expected_profile"].as_str().map(Path::new)
                    == Some(grant.profile.as_path())
                && capability.controller_pid == std::process::id()
                && capability.controller_pid == grant.supervisor_pid
                && capability.controller_birth == grant.supervisor_birth
                && bound["operation_id"] == self.original.operation_id
                && bound["request_fingerprint"] == self.original.request_fingerprint
                && bound["sync_generation"].as_u64()
                    == Some(u64::try_from(self.original.sync_generation)?)
                && bound["snapshot_id"] == self.original.snapshot_id
                && bound["account_id"] == grant.account_id
                && if phase == "Verified" {
                    bound["verified_runtime"].is_object()
                } else {
                    bound["verified_runtime"].is_null()
                },
            "snapshot helper requires the exact operation and role-specific marker"
        );
        let request = self.request(
            ControlBinding {
                installation_root: grant.installation_root.clone(),
                profile: grant.profile.clone(),
                launch_id: grant.instance_id.clone(),
                expected_account_id: Some(grant.account_id.clone()),
            },
            action,
        )?;
        let envelope = super::supervise::exchange_snapshot_control(
            binary,
            grant,
            &request,
            deadline,
            |response, pid| self.validate_response(response, &request, pid, false),
        )
        .map_err(|error| error.context(self.unknown()))?;
        serde_json::from_value(envelope.summary).context(self.unknown())
    }

    /// Query never substitutes Restore, changes O or refreshes the generation.
    pub(crate) fn query_offline(
        &self,
        takeover: &LibraryLock,
        binary: &Path,
        grant: &HostControlLaunchGrant,
        deadline: Instant,
    ) -> Result<Receipt> {
        self.offline(takeover, binary, grant, Action::Query, deadline)
    }

    /// Typed request for the dedicated Verified metadata helper.
    pub(crate) fn finalize_request(
        &self,
        verified_binding: ControlBinding,
        action: Action,
    ) -> Result<RpcRequest> {
        anyhow::ensure!(
            matches!(action, Action::Commit | Action::Release | Action::Query),
            "invalid snapshot finalize action"
        );
        self.request(verified_binding, action)
    }

    /// `pid` is the owned helper PID, never the live store's PID. The helper
    /// reports store_ready=false; target store verification runs in Runtime.
    pub(crate) fn validate_finalize_response(
        &self,
        response: RpcResponse<ResultEnvelope>,
        request: &RpcRequest,
        pid: u32,
    ) -> Result<Receipt> {
        let envelope = self
            .validate_response(response, request, pid, false)
            .map_err(|error| error.context(self.unknown()))?;
        serde_json::from_value(envelope.summary).context(self.unknown())
    }

    fn unknown(&self) -> SnapshotOutcomeUnknown {
        SnapshotOutcomeUnknown {
            operation_id: self.original.operation_id.clone(),
            request_fingerprint: self.original.request_fingerprint.clone(),
            snapshot_id: self.original.snapshot_id.clone(),
            sync_generation: self.original.sync_generation,
        }
    }

    // This is diagnostic-only: a known validation cause never proves a terminal outcome.
    fn restore_validation_reason(
        &self,
        response: &RpcResponse<ResultEnvelope>,
        request: &RpcRequest,
    ) -> Option<&'static str> {
        if response.ok || response.exit != 2
            || response.code.as_deref() != Some("snapshot_outcome_unknown")
            || request.args.len() != 1 {
            return None;
        }
        let params: Params = serde_json::from_str(&request.args[0]).ok()?;
        if params.action != Action::Restore || params.schema_version != MAINTENANCE_CONTROL_SCHEMA_V
            || params.operation_id != self.original.operation_id
            || params.snapshot_id != self.original.snapshot_id
            || params.sync_generation != self.original.sync_generation
            || params.request_fingerprint != self.original.request_fingerprint
            || Self::fingerprint(&params.binding, params.sync_generation, &params.snapshot_id).ok()?
                != self.original.request_fingerprint {
            return None;
        }
        let envelope = response.envelope.as_ref()?;
        let error = response.error.as_ref()?;
        if envelope.command != "snapshot" || !matches!(envelope.status, Status::Fail)
            || envelope.errors.as_slice() != std::slice::from_ref(error) {
            return None;
        }
        // Emit only fixed known causes, never any raw remote error, path or credential.
        match error.rsplit(": ").next()? {
            "snapshot witness checkpoint is unverifiable; diagnostic copy cannot be a restore target" =>
                Some("snapshot witness checkpoint is unverifiable; diagnostic copy cannot be a restore target"),
            "snapshot witness checkpoint mismatch or missing checkpoint" =>
                Some("snapshot witness checkpoint mismatch or missing checkpoint"),
            "snapshot witness checkpoint exists without a witness schema" =>
                Some("snapshot witness checkpoint exists without a witness schema"),
            _ => None,
        }
    }

    fn validate_response(
        &self,
        response: RpcResponse<ResultEnvelope>,
        request: &RpcRequest,
        pid: u32,
        serving: bool,
    ) -> Result<ResultEnvelope> {
        anyhow::ensure!(
            request.method == MAINTENANCE_CONTROL_METHOD
                && request.operation_id.as_deref() == Some(self.original.operation_id.as_str())
                && request.idempotency_key == request.operation_id
                && response.v == request.v
                && response.id == request.id
                && response.bin == "rsrs-runtime"
                && response.pid == Some(pid)
                && response.operation_id == request.operation_id
                && response.idempotency_key == request.idempotency_key
                && response.scope.is_none()
                && response.web_url.is_none(),
            "snapshot response identity mismatch"
        );
        let directory = response
            .data_dir
            .as_deref()
            .context("snapshot response profile missing")?;
        anyhow::ensure!(
            Path::new(directory).canonicalize()? == self.original.binding.profile,
            "snapshot response profile mismatch"
        );
        if !response.ok || response.exit != 0 || response.code.is_some() || response.error.is_some()
        {
            let validation_reason = self.restore_validation_reason(&response, request);
            return Err(SnapshotRemoteFailure {
                code: response.code,
                exit: response.exit,
                validation_reason,
            }
            .into());
        }
        let envelope = response.envelope.context("snapshot result missing")?;
        anyhow::ensure!(
            envelope.command == "snapshot",
            "unexpected snapshot control command"
        );
        for (name, value, ready) in [
            ("control_ready", "true", true),
            (
                "store_ready",
                if serving { "true" } else { "false" },
                serving,
            ),
        ] {
            let mut items = envelope.items.iter().filter(|item| item.name == name);
            anyhow::ensure!(
                items.next().is_some_and(|item| item.value == value
                    && if ready {
                        matches!(item.status, Status::Ok)
                    } else {
                        matches!(item.status, Status::Skip)
                    })
                    && items.next().is_none(),
                "snapshot control readiness mismatch"
            );
        }
        let receipt: Receipt = serde_json::from_value(envelope.summary.clone())
            .map_err(|_| anyhow::anyhow!("invalid snapshot receipt shape"))?;
        anyhow::ensure!(
            receipt.operation_id == self.original.operation_id
                && receipt.request_fingerprint == self.original.request_fingerprint
                && receipt.snapshot_id == self.original.snapshot_id,
            "snapshot receipt does not identify the original request"
        );
        anyhow::ensure!(
            if receipt.state == State::Unknown {
                receipt.before_restore.is_none()
                    && receipt.sync_quarantined.is_none()
                    && !receipt.cleanup_pending
                    && receipt.cleanup_warning.is_none()
            } else {
                receipt
                    .before_restore
                    .as_deref()
                    .is_some_and(|id| !id.is_empty())
                    && if receipt.state == State::RolledBack {
                        receipt.sync_quarantined.is_none()
                    } else {
                        receipt.sync_quarantined == Some(true)
                    }
            },
            "inconsistent snapshot receipt state"
        );
        anyhow::ensure!(
            receipt.cleanup_warning.is_none() || receipt.cleanup_pending,
            "snapshot cleanup warning lacks pending cleanup"
        );
        anyhow::ensure!(
            if receipt.cleanup_pending {
                matches!(envelope.status, Status::Warn)
                    && (envelope.errors.is_empty()
                        || envelope.errors.as_slice()
                            == receipt
                                .cleanup_warning
                                .as_ref()
                                .map(std::slice::from_ref)
                                .unwrap_or_default())
            } else {
                matches!(envelope.status, Status::Ok) && envelope.errors.is_empty()
            },
            "snapshot envelope and receipt disagree"
        );
        // Unknown remains a typed result, never proof that Restore may be sent.
        // Cleanup warnings remain successful receipts, never rollback triggers.
        Ok(envelope)
    }
}

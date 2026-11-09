//! Snapshot capability publication follows the existing authenticated drain.
use super::super::snapshot_control::{SnapshotOperation, dispatch_legacy_snapshot, legacy_fingerprint, validate_legacy_descriptor};
use respire_protocol::maintenance_control::{LegacySnapshotRecoveryAction as LegacyAction,
    LegacySnapshotRecoveryParams as LegacyParams, LegacySnapshotRecoveryResult as LegacyReceipt};
use respire_protocol::ControlBinding;
use super::*;
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::maintenance_control::{MaintenanceAction, MaintenanceControlResult};
use respire_protocol::maintenance_control::{
    MaintenanceControlParams, MaintenanceState, MAINTENANCE_CONTROL_SCHEMA_V,
};
use respire_protocol::{HostControlLaunchGrant, RuntimeStopReceipt};
use std::io::Read;

/// Optional field `snapshot` in the existing maintenance marker, not a ledger.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotMarkerBinding {
    pub operation_id: String,
    pub request_fingerprint: String,
    pub sync_generation: usize,
    pub snapshot_id: String,
    pub account_id: String,
    pub drained_birth: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain: Option<RuntimeStopReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline: Option<SnapshotOfflineProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_runtime: Option<SnapshotVerifiedRuntime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_recovery: Option<LegacySnapshotRecoveryBinding>,
}

pub(crate) use respire_protocol::maintenance_control::LegacySnapshotRecoveryBinding;

/// Absence evidence is not a drain receipt. Installation and library locks
/// serialize its publication; Runtime reacquires both before offline execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotOfflineProof {
    pub endpoint_sha256: Option<String>,
    pub endpoint_pid: Option<u32>,
    pub prior_runtime: Option<SnapshotVerifiedRuntime>,
}

/// Frozen only after the coordinator independently verifies the live target.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotVerifiedRuntime {
    pub scope: respire_protocol::RuntimeRequestScope,
    pub pid: u32,
    pub process_start_id: String,
    pub image_path: PathBuf,
    pub image_sha256: String,
    pub runtime_version: String,
}

impl SnapshotOfflineProof {
    fn capture(root: &Path, prior_runtime: Option<SnapshotVerifiedRuntime>) -> Result<Self> {
        let path = root.join("runtime/endpoint.json");
        let (endpoint_sha256, endpoint_pid) = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.len() <= 16 * 1024,
                    "snapshot endpoint is not a bounded regular file"
                );
                let mut bytes = Vec::new();
                fs::File::open(&path)?
                    .take(16 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                anyhow::ensure!(bytes.len() <= 16 * 1024, "snapshot endpoint too large");
                let endpoint: Value = serde_json::from_slice(&bytes)?;
                let pid = endpoint["pid"]
                    .as_u64()
                    .and_then(|pid| u32::try_from(pid).ok())
                    .filter(|pid| *pid > 0)
                    .context("snapshot endpoint owner PID missing")?;
                // A legacy locator has no birth. Any live/reused PID is ambiguous.
                anyhow::ensure!(
                    manager::process_birth(pid)?.is_none(),
                    "snapshot owner is alive but health is unavailable; drain proof required"
                );
                (Some(hash(&bytes)), Some(pid))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(error) => return Err(error.into()),
        };
        if let Some(prior) = prior_runtime.as_ref() {
            anyhow::ensure!(
                prior.pid > 0 && !prior.process_start_id.is_empty(),
                "snapshot previous Runtime identity incomplete"
            );
            let alive = manager::process_birth(prior.pid)?.is_some_and(|birth| {
                prior.process_start_id == format!("{}{birth}", snapshot_birth_prefix())
            });
            anyhow::ensure!(
                !alive,
                "snapshot previous Runtime is alive without health; no offline recovery"
            );
        }
        Ok(Self {
            endpoint_sha256,
            endpoint_pid,
            prior_runtime,
        })
    }

    fn verify(&self, root: &Path) -> Result<()> {
        let current = Self::capture(root, self.prior_runtime.clone())?;
        anyhow::ensure!(
            current.endpoint_sha256 == self.endpoint_sha256
                && current.endpoint_pid == self.endpoint_pid,
            "snapshot endpoint changed since offline fencing"
        );
        Ok(())
    }
}

fn normal_marker(operation: &SnapshotOperation) -> Result<SnapshotMarkerBinding> {
    let original = operation.original();
    Ok(SnapshotMarkerBinding {
        operation_id: original.operation_id.clone(),
        request_fingerprint: original.request_fingerprint.clone(),
        sync_generation: original.sync_generation,
        snapshot_id: original.snapshot_id.clone(),
        account_id: original.binding.expected_account_id.clone().context("snapshot account missing")?,
        drained_birth: String::new(), drain: None, offline: None, verified_runtime: None,
        legacy_recovery: None,
    })
}

fn same_snapshot_intent(left: &SnapshotMarkerBinding, right: &SnapshotMarkerBinding) -> bool {
    left.operation_id == right.operation_id && left.request_fingerprint == right.request_fingerprint
        && left.sync_generation == right.sync_generation && left.snapshot_id == right.snapshot_id
        && left.account_id == right.account_id && left.legacy_recovery == right.legacy_recovery
}

impl Maintenance {
    /// Publish absence only while both existing locks exclude serving/startup.
    /// The helper reacquires installation ownership before the existing DB lock.
    fn snapshot_bind_offline(&mut self, takeover: &LibraryLock, operation: &SnapshotOperation) -> Result<()> {
        self.snapshot_bind_offline_intent(takeover, &operation.original().binding, normal_marker(operation)?)
    }

    fn snapshot_bind_offline_intent(&mut self, takeover: &LibraryLock, binding: &ControlBinding,
        mut next_binding: SnapshotMarkerBinding) -> Result<()> {
        let root = &binding.installation_root;
        anyhow::ensure!(
            takeover.protects(&root.join("runtime/takeover"))?
                && self.installation_root()? == root.as_path(),
            "snapshot takeover changed"
        );
        let _owner = LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)
            .context("snapshot installation ownership unavailable; absent health is not stopped proof")?;
        let _library = LibraryLock::acquire(&binding.profile, Duration::ZERO)
            .context("snapshot library ownership unavailable; no offline action taken")?;
        if let Some(config) = self.config.as_ref() {
            owned(config)?;
            anyhow::ensure!(
                !manager::inspect(config)?.running,
                "snapshot supervisor is still running; explicit drain is required"
            );
        }
        let bytes = marker_bytes(root)?.context("snapshot offline marker missing")?;
        let mut actual: Marker = serde_json::from_slice(&bytes)?;
        let held = self
            .marker
            .as_ref()
            .context("snapshot offline owner missing")?;
        anyhow::ensure!(
            hash(&bytes)
                == self
                    .marker_digest
                    .as_deref()
                    .context("snapshot digest missing")?
                && serde_json::to_vec(&actual)? == serde_json::to_vec(held)?
                && actual.owner_pid == std::process::id()
                && controller_alive(&actual)?
                && current_boot_token().as_deref() == Some(actual.token.as_str()),
            "snapshot offline controller changed"
        );
        if let Some(bound) = actual.snapshot.as_ref() {
            anyhow::ensure!(same_snapshot_intent(bound, &next_binding), "snapshot offline intent changed");
        }
        let prior = actual
            .snapshot
            .as_ref()
            .and_then(|bound| bound.verified_runtime.clone())
            .or_else(|| {
                actual
                    .snapshot
                    .as_ref()
                    .and_then(|bound| bound.offline.as_ref())
                    .and_then(|proof| proof.prior_runtime.clone())
            });
        let proof = SnapshotOfflineProof::capture(root, prior)?;
        actual.phase = Phase::Paused;
        actual.expected_profile = Some(binding.profile.clone());
        next_binding.offline = Some(proof);
        actual.snapshot = Some(next_binding);
        let next = serde_json::to_vec(&actual)?;
        anyhow::ensure!(
            next.len() <= MAINTENANCE_MARKER_MAX_BYTES,
            "snapshot offline marker too large"
        );
        actual
            .snapshot
            .as_ref()
            .and_then(|bound| bound.offline.as_ref())
            .context("snapshot offline evidence missing")?
            .verify(root)?;
        private_write(&marker_path(root), &next, Some(&hash(&bytes)))?;
        self.marker = Some(actual);
        self.marker_digest = Some(hash(&next));
        Ok(())
    }

    fn snapshot_owned_marker(
        &self,
        takeover: &LibraryLock,
        binding: &ControlBinding,
    ) -> Result<(PathBuf, Vec<u8>, Marker)> {
        let root = &binding.installation_root;
        if let Some(config) = self.config.as_ref() {
            owned(config)?;
            anyhow::ensure!(
                config.installation == *root,
                "snapshot registration root changed"
            );
        }
        let (selected_root, selected_profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(
            takeover.protects(&root.join("runtime/takeover"))?
                && self.installation_root()? == root.as_path()
                && selected_root.canonicalize()? == *root
                && selected_profile.canonicalize()? == binding.profile,
            "snapshot takeover, installation or selected profile changed"
        );
        let path = marker_path(root);
        let bytes = marker_bytes(root)?.context("snapshot maintenance marker missing")?;
        let actual = marker(root)?.context("snapshot maintenance marker missing")?;
        let held = self
            .marker
            .as_ref()
            .context("snapshot maintenance ownership missing")?;
        anyhow::ensure!(
            actual.phase == Phase::Paused
                && held.phase == Phase::Paused
                && actual.id == held.id
                && actual.token == held.token
                && actual.owner_pid == std::process::id()
                && actual.owner_birth == held.owner_birth
                && controller_alive(&actual)?
                && current_boot_token().as_deref() == Some(held.token.as_str())
                && actual.expected_version == super::maintenance_issuer_version()?
                && serde_json::to_vec(&actual)?
                    == serde_json::to_vec(&serde_json::from_slice::<Marker>(&bytes)?)?
                && hash(&bytes)
                    == self
                        .marker_digest
                        .as_deref()
                        .context("snapshot marker digest missing")?,
            "snapshot requires this controller's exact Paused marker"
        );
        Ok((path, bytes, actual))
    }

    /// No capability is published before drain_runtime validates final receipt,
    /// process exit and supervisor shutdown. Probe/lock availability is not proof.
    pub(crate) fn snapshot_drain_and_bind(&mut self, takeover: &LibraryLock,
        operation: &SnapshotOperation, health: &crate::net_rpc::Health) -> Result<()> {
        self.snapshot_drain_intent(takeover, &operation.original().binding, normal_marker(operation)?, health)
    }

    fn snapshot_drain_intent(&mut self, takeover: &LibraryLock, binding: &ControlBinding,
        mut next_binding: SnapshotMarkerBinding, health: &crate::net_rpc::Health) -> Result<()> {
        let (_, _, actual) = self.snapshot_owned_marker(takeover, binding)?;
        anyhow::ensure!(
            actual.snapshot.is_none(),
            "snapshot marker already bound; query that operation instead of draining again"
        );
        let birth = if let Some(config) = self.config.as_ref() {
            verify_owned_runtime(config, health)?
        } else {
            // Manual mode has no Registration to impersonate. Fence the real
            // installed Runtime and process before requesting its actual drain.
            crate::net_rpc::request_scope(health)?;
            let (binary, digest) = super::super::supervise::installed_auth_runtime()?;
            let process = crate::net_rpc::runtime_process_identity(health.pid)?;
            let birth = manager::process_birth(health.pid)?
                .context("manual snapshot owner exited before drain")?;
            let prefix = snapshot_birth_prefix();
            anyhow::ensure!(
                health.managed_id.is_none()
                    && Path::new(&health.installation_root).canonicalize()?
                        == binding.installation_root
                    && Path::new(&health.data_dir).canonicalize()? == binding.profile
                    && health.installation_id
                        == hash(
                            binding
                                .installation_root
                                .display()
                                .to_string()
                                .as_bytes()
                        )
                    && Path::new(&health.image_path).canonicalize()? == binary
                    && Path::new(&health.exe).canonicalize()? == binary
                    && Path::new(&process.executable).canonicalize()? == binary
                    && health.process_start_id == format!("{prefix}{birth}")
                    && (process.started_at == birth
                        || process.started_at == health.process_start_id)
                    && health.image_sha256.eq_ignore_ascii_case(&digest),
                "manual snapshot owner differs from the installed Runtime"
            );
            birth
        };
        anyhow::ensure!(
            Some(health.account_id.as_str()) == binding.expected_account_id.as_deref(),
            "snapshot drain account differs from original operation"
        );
        self.drain_runtime(health)?;
        // Reuse the existing receipt reader and validation, including Drained
        // and empty unfinished. The existing drain already bound its stop O.
        let drain: RuntimeStopReceipt =
            serde_json::from_value(crate::net_rpc::final_stop_receipt(health, None)?)?;
        anyhow::ensure!(
            manager::process_birth(health.pid)?.as_deref() != Some(birth.as_str()),
            "snapshot drained owner is still alive"
        );
        let (path, bytes, mut actual) = self.snapshot_owned_marker(takeover, binding)?;
        anyhow::ensure!(
            actual.snapshot.is_none(),
            "snapshot marker changed during drain"
        );
        actual.expected_profile = Some(binding.profile.clone());
        next_binding.drained_birth = birth;
        next_binding.drain = Some(drain);
        actual.snapshot = Some(next_binding);
        let next = serde_json::to_vec(&actual)?;
        anyhow::ensure!(
            next.len() <= MAINTENANCE_MARKER_MAX_BYTES,
            "snapshot maintenance marker exceeds bounded limit"
        );
        private_write(&path, &next, Some(&hash(&bytes)))?;
        self.marker = Some(actual);
        self.marker_digest = Some(hash(&next));
        Ok(())
    }

    pub(crate) fn snapshot_launch_binding(
        &self,
        takeover: &LibraryLock,
        operation: &SnapshotOperation,
    ) -> Result<Value> {
        let (_, bytes, actual) = self.snapshot_owned_marker(takeover, &operation.original().binding)?;
        let bound = actual
            .snapshot
            .as_ref()
            .context("snapshot has no authenticated drain capability")?;
        let original = operation.original();
        anyhow::ensure!(
            bound.operation_id == original.operation_id
                && bound.request_fingerprint == original.request_fingerprint
                && bound.sync_generation == original.sync_generation
                && bound.snapshot_id == original.snapshot_id
                && Some(bound.account_id.as_str())
                    == original.binding.expected_account_id.as_deref()
                && actual.expected_profile.as_ref() == Some(&original.binding.profile)
                && match (&bound.drain, &bound.offline) {
                    (Some(drain), None) =>
                        manager::process_birth(drain.pid)?.as_deref()
                            != Some(bound.drained_birth.as_str()),
                    (None, Some(proof)) => {
                        proof.verify(&original.binding.installation_root)?;
                        true
                    }
                    _ => false,
                }
                && match self.config.as_ref() {
                    Some(config) => !manager::inspect(config)?.running,
                    None => true,
                },
            "snapshot operation or drained owner changed"
        );
        // No generation is copied into a fresh launch grant. The marker hash
        // binds the original operation's generation independently.
        Ok(json!({
            "marker_sha256": hash(&bytes),
            "coordinator_id": actual.id,
            "controller_pid": actual.owner_pid,
            "controller_birth": actual.owner_birth,
            "issuer_cli_version": actual.expected_version,
        }))
    }

    /// Actual path: authenticated drain -> marker CAS -> fresh grant -> existing
    /// bounded exchange. Subsequent Query reuses the already published marker.
    pub(crate) fn snapshot_offline_locked(
        &mut self,
        takeover: &LibraryLock,
        operation: &SnapshotOperation,
        action: MaintenanceAction,
        health_to_drain: Option<&crate::net_rpc::Health>,
        deadline: Instant,
    ) -> Result<MaintenanceControlResult> {
        crate::runtime_policy::require_host("snapshot offline maintenance")?;
        anyhow::ensure!(
            matches!(
                action,
                MaintenanceAction::Restore
                    | MaintenanceAction::Rollback
                    | MaintenanceAction::Recover
                    | MaintenanceAction::Query
            ),
            "offline finalization forbidden"
        );
        if let Some(health) = health_to_drain {
            self.snapshot_drain_and_bind(takeover, operation, health)?;
        }
        let binding = self.snapshot_launch_binding(takeover, operation)?;
        let original = operation.original();
        let (binary, digest) = super::super::supervise::installed_auth_runtime()?;
        let managed_id = self
            .config
            .as_ref()
            .filter(|config| config.enabled && !config.manually_stopped)
            .map(|config| config.id.as_str());
        let (grant, _) = super::super::supervise::prepare_snapshot_grant(
            &binary,
            &original.binding.installation_root,
            &original.binding.profile,
            managed_id,
            crate::net_rpc::rpc_port(),
            original
                .binding
                .expected_account_id
                .as_deref()
                .context("snapshot account missing")?,
            Some(binding),
        )?;
        let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
        anyhow::ensure!(
            grant.image_sha256.eq_ignore_ascii_case(&digest),
            "snapshot helper image changed after manifest verification"
        );
        // Original generation is marker-bound; the fresh helper keeps its own.
        operation.offline(takeover, &binary, &grant, action, deadline)
    }

    /// Startup consumes only a drain-backed Paused snapshot capability. The
    /// selected Runtime is still the existing registered/detached launch path.
    pub(crate) fn snapshot_start_runtime(
        &mut self,
        takeover: &LibraryLock,
        operation: &SnapshotOperation,
    ) -> Result<()> {
        self.snapshot_launch_binding(takeover, operation)?;
        self.check_account_runtime()?;
        self.mark(Phase::Starting)?;
        crate::rpc::ensure_daemon_locked()
    }

    fn snapshot_target_proof(
        &self,
        operation: &SnapshotOperation,
    ) -> Result<SnapshotVerifiedRuntime> {
        self.snapshot_live_proof(operation, true)
    }

    fn snapshot_live_proof(
        &self,
        operation: &SnapshotOperation,
        require_snapshot: bool,
    ) -> Result<SnapshotVerifiedRuntime> {
        self.snapshot_live_binding(&operation.original().binding,
            require_snapshot.then_some(operation.original().snapshot_id.as_str()))
    }

    fn snapshot_live_binding(&self, binding: &ControlBinding, snapshot_id: Option<&str>) -> Result<SnapshotVerifiedRuntime> {
        let (root, profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(
            root.canonicalize()? == binding.installation_root
                && profile.canonicalize()? == binding.profile,
            "snapshot target selection changed"
        );
        let health = crate::net_rpc::health()?;
        let scope = crate::net_rpc::request_scope(&health)?;
        let (binary, digest) = super::super::supervise::installed_auth_runtime()?;
        let birth = manager::process_birth(health.pid)?.context("snapshot target exited")?;
        let process = crate::net_rpc::runtime_process_identity(health.pid)?;
        let expected_managed = self.config.as_ref().map(|config| config.id.as_str());
        anyhow::ensure!(
            scope.generation > 0
                && health.pid != std::process::id()
                && health.process_start_id == format!("{}{birth}", snapshot_birth_prefix())
                && (process.started_at == birth || process.started_at == health.process_start_id)
                && Some(scope.account_id.as_str())
                    == binding.expected_account_id.as_deref()
                && health.managed_id.as_deref() == expected_managed
                && Path::new(&health.installation_root).canonicalize()?
                    == binding.installation_root
                && health.installation_id
                    == hash(
                        binding
                            .installation_root
                            .display()
                            .to_string()
                            .as_bytes()
                    )
                && Path::new(&health.data_dir).canonicalize()? == binding.profile
                && Path::new(&health.image_path).canonicalize()? == binary
                && Path::new(&health.exe).canonicalize()? == binary
                && Path::new(&process.executable).canonicalize()? == binary
                && health.image_sha256.eq_ignore_ascii_case(&digest)
                && !health.runtime_version.is_empty()
                && health.store_ready
                && (snapshot_id.is_none()
                    || health.snapshot_restore_id.as_deref()
                        == snapshot_id),
            "snapshot target process, scope or actual restored store is not verified"
        );
        anyhow::ensure!(
            manager::process_birth(health.pid)?.as_deref() == Some(birth.as_str())
                && crate::net_rpc::runtime_process_identity(health.pid)? == process,
            "snapshot target changed during verification"
        );
        Ok(SnapshotVerifiedRuntime {
            scope,
            pid: health.pid,
            process_start_id: health.process_start_id,
            image_path: binary,
            image_sha256: digest,
            runtime_version: health.runtime_version,
        })
    }

    /// Real target proof and Verified phase are one marker CAS. No generic
    /// mark(Verified) call can substitute for this snapshot transition.
    pub(crate) fn snapshot_target_verified(
        &mut self,
        takeover: &LibraryLock,
        operation: &SnapshotOperation,
    ) -> Result<()> {
        let original = operation.original();
        let root = self.installation_root()?.to_path_buf();
        anyhow::ensure!(
            root == original.binding.installation_root
                && takeover.protects(&root.join("runtime/takeover"))?,
            "snapshot verification requires the original installation takeover"
        );
        let path = marker_path(&root);
        let bytes = marker_bytes(&root)?.context("snapshot target marker missing")?;
        let mut actual = marker(&root)?.context("snapshot target marker missing")?;
        let held = self
            .marker
            .as_ref()
            .context("snapshot target ownership missing")?;
        anyhow::ensure!(
            matches!(actual.phase, Phase::Starting | Phase::Verified)
                && actual.phase == held.phase
                && actual.id == held.id
                && actual.token == held.token
                && actual.owner_pid == std::process::id()
                && actual.owner_birth == held.owner_birth
                && actual.expected_version == super::maintenance_issuer_version()?
                && actual.expected_profile.as_ref() == Some(&original.binding.profile)
                && current_boot_token().as_deref() == Some(held.token.as_str())
                && controller_alive(&actual)?
                && hash(&bytes)
                    == self
                        .marker_digest
                        .as_deref()
                        .context("snapshot target digest missing")?
                && serde_json::to_vec(&actual)?
                    == serde_json::to_vec(&serde_json::from_slice::<Marker>(&bytes)?)?,
            "snapshot target does not belong to this exact Starting/Verified controller"
        );
        let bound = actual
            .snapshot
            .as_ref()
            .context("snapshot target has no drain-backed operation")?;
        anyhow::ensure!(
            bound.operation_id == original.operation_id
                && bound.request_fingerprint == original.request_fingerprint
                && bound.sync_generation == original.sync_generation
                && bound.snapshot_id == original.snapshot_id
                && Some(bound.account_id.as_str())
                    == original.binding.expected_account_id.as_deref(),
            "snapshot target operation changed"
        );
        let proof = self.snapshot_target_proof(operation)?;
        anyhow::ensure!(
            self.snapshot_target_proof(operation)? == proof,
            "snapshot target changed before Verified publication"
        );
        actual.phase = Phase::Verified;
        actual
            .snapshot
            .as_mut()
            .context("snapshot target operation missing")?
            .verified_runtime = Some(proof);
        let next = serde_json::to_vec(&actual)?;
        anyhow::ensure!(
            next.len() <= MAINTENANCE_MARKER_MAX_BYTES,
            "snapshot proof exceeds marker limit"
        );
        private_write(&path, &next, Some(&hash(&bytes)))?;
        self.marker = Some(actual);
        self.marker_digest = Some(hash(&next));
        Ok(())
    }

    /// Consumes only an already Verified marker published by the lifecycle
    /// owner. This method cannot promote Paused/Starting or invent target proof.
    pub(crate) fn snapshot_finalize_locked(
        &self,
        takeover: &LibraryLock,
        operation: &SnapshotOperation,
        action: MaintenanceAction,
        deadline: Instant,
    ) -> Result<MaintenanceControlResult> {
        crate::runtime_policy::require_host("snapshot Verified metadata finalization")?;
        anyhow::ensure!(
            matches!(
                action,
                MaintenanceAction::Commit | MaintenanceAction::Release | MaintenanceAction::Query
            ),
            "Verified snapshot helper cannot replace the store"
        );
        let original = operation.original();
        let root = self.installation_root()?;
        let actual = marker(root)?.context("Verified snapshot marker missing")?;
        let held = self
            .marker
            .as_ref()
            .context("Verified snapshot ownership missing")?;
        let bytes = marker_bytes(root)?.context("Verified snapshot marker missing")?;
        anyhow::ensure!(
            root == original.binding.installation_root.as_path()
                && takeover.protects(&root.join("runtime/takeover"))?
                && actual.phase == Phase::Verified
                && held.phase == Phase::Verified
                && actual.id == held.id
                && actual.token == held.token
                && actual.owner_pid == std::process::id()
                && actual.owner_birth == held.owner_birth
                && current_boot_token().as_deref() == Some(held.token.as_str())
                && controller_alive(&actual)?
                && actual
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.verified_runtime.is_some())
                && serde_json::to_vec(&actual)?
                    == serde_json::to_vec(&serde_json::from_slice::<Marker>(&bytes)?)?
                && hash(&bytes)
                    == self
                        .marker_digest
                        .as_deref()
                        .context("Verified snapshot digest missing")?,
            "snapshot finalization requires this controller's exact Verified marker"
        );
        let binding = maintenance_binding(&original.binding.profile, None, false)?
            .context("Verified snapshot launch binding missing")?;
        let (binary, digest) = super::super::supervise::installed_auth_runtime()?;
        let (grant, _) = super::super::supervise::prepare_snapshot_grant(
            &binary,
            root,
            &original.binding.profile,
            self.config
                .as_ref()
                .filter(|config| config.enabled && !config.manually_stopped)
                .map(|config| config.id.as_str()),
            crate::net_rpc::rpc_port(),
            original
                .binding
                .expected_account_id
                .as_deref()
                .context("snapshot account missing")?,
            Some(binding),
        )?;
        let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
        anyhow::ensure!(
            grant.image_sha256.eq_ignore_ascii_case(&digest),
            "snapshot finalizer image changed after manifest verification"
        );
        operation.finalize_helper(takeover, &binary, &grant, action, deadline)
    }

    /// Replacing an old drain proof requires another actual drain, including
    /// final receipt and supervisor exit. Never infer this from absent health.
    fn snapshot_pause_after_drain(
        &mut self,
        takeover: &LibraryLock,
        binding: &ControlBinding,
        expected: &SnapshotMarkerBinding,
        health: &crate::net_rpc::Health,
    ) -> Result<()> {
        let root = self.installation_root()?.to_path_buf();
        let bytes = marker_bytes(&root)?.context("snapshot recovery marker missing")?;
        let mut actual: Marker = serde_json::from_slice(&bytes)?;
        let held = self
            .marker
            .as_ref()
            .context("snapshot recovery ownership missing")?;
        anyhow::ensure!(
            takeover.protects(&root.join("runtime/takeover"))?
                && hash(&bytes)
                    == self
                        .marker_digest
                        .as_deref()
                        .context("snapshot recovery digest missing")?
                && serde_json::to_vec(&actual)? == serde_json::to_vec(held)?
                && actual.owner_pid == std::process::id()
                && controller_alive(&actual)?
                && current_boot_token().as_deref() == Some(actual.token.as_str()),
            "snapshot recovery controller changed"
        );
        crate::net_rpc::request_scope(health)?;
        let (binary, digest) = super::super::supervise::installed_auth_runtime()?;
        let birth =
            manager::process_birth(health.pid)?.context("snapshot recovery owner exited")?;
        let process = crate::net_rpc::runtime_process_identity(health.pid)?;
        anyhow::ensure!(
            Path::new(&health.installation_root).canonicalize()? == root
                && Path::new(&health.data_dir).canonicalize()? == binding.profile
                && Some(health.account_id.as_str())
                    == binding.expected_account_id.as_deref()
                && health.process_start_id == format!("{}{birth}", snapshot_birth_prefix())
                && (process.started_at == birth || process.started_at == health.process_start_id)
                && Path::new(&process.executable).canonicalize()? == binary
                && Path::new(&health.image_path).canonicalize()? == binary
                && health.image_sha256.eq_ignore_ascii_case(&digest)
                && health.managed_id.as_deref()
                    == self.config.as_ref().map(|config| config.id.as_str()),
            "snapshot recovery owner differs from original operation"
        );
        self.drain_runtime(health)?;
        let drain: RuntimeStopReceipt =
            serde_json::from_value(crate::net_rpc::final_stop_receipt(health, None)?)?;
        let snapshot = actual
            .snapshot
            .as_mut()
            .context("snapshot recovery operation missing")?;
        anyhow::ensure!(
            same_snapshot_intent(snapshot, expected),
            "snapshot recovery operation changed"
        );
        snapshot.drain = Some(drain);
        snapshot.offline = None;
        snapshot.drained_birth = birth;
        snapshot.verified_runtime = None;
        actual.phase = Phase::Paused;
        let next = serde_json::to_vec(&actual)?;
        anyhow::ensure!(
            next.len() <= MAINTENANCE_MARKER_MAX_BYTES,
            "snapshot recovery marker too large"
        );
        private_write(&marker_path(&root), &next, Some(&hash(&bytes)))?;
        self.marker = Some(actual);
        self.marker_digest = Some(hash(&next));
        Ok(())
    }
}

fn snapshot_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn legacy_marker(params: &LegacyParams) -> Result<SnapshotMarkerBinding> {
    let account_id = params.binding.expected_account_id.clone().context("legacy snapshot account missing")?;
    Ok(SnapshotMarkerBinding {
        // These fields never identify an original restore for legacy recovery.
        operation_id: String::new(), request_fingerprint: String::new(), sync_generation: 0,
        snapshot_id: String::new(), account_id: account_id.clone(), drained_birth: String::new(),
        drain: None, offline: None, verified_runtime: None,
        legacy_recovery: Some(LegacySnapshotRecoveryBinding {
            recovery_operation_id: params.recovery_operation_id.clone(),
            request_fingerprint: params.request_fingerprint.clone(),
            journal_sha256: params.journal_sha256.clone(), account_id,
        }),
    })
}

impl Maintenance {
    pub(super) fn legacy_pause_for_query(&mut self, takeover: &LibraryLock,
        params: &LegacyParams, health: Option<&crate::net_rpc::Health>) -> Result<()> {
        let expected = legacy_marker(params)?;
        anyhow::ensure!(params.request_fingerprint == legacy_fingerprint(params)?
            && self.marker.as_ref().and_then(|marker| marker.snapshot.as_ref())
                .is_some_and(|bound| same_snapshot_intent(bound, &expected)),
            "legacy recovery query intent changed");
        if let Some(health) = health {
            self.snapshot_pause_after_drain(takeover, &params.binding, &expected, health)?;
        } else {
            self.snapshot_bind_offline_intent(takeover, &params.binding, expected)?;
        }
        self.legacy_launch_binding(takeover, params)?;
        Ok(())
    }

    fn legacy_launch_binding(&self, takeover: &LibraryLock, params: &LegacyParams) -> Result<Value> {
        let (_, bytes, actual) = self.snapshot_owned_marker(takeover, &params.binding)?;
        let bound = actual.snapshot.as_ref().context("legacy snapshot binding missing")?;
        anyhow::ensure!(same_snapshot_intent(bound, &legacy_marker(params)?)
            && actual.expected_profile.as_ref() == Some(&params.binding.profile)
            && bound.verified_runtime.is_none()
            && params.request_fingerprint == legacy_fingerprint(params)?
            && match (&bound.drain, &bound.offline) {
                (Some(drain), None) => manager::process_birth(drain.pid)?.as_deref()
                    != Some(bound.drained_birth.as_str()),
                (None, Some(proof)) => { proof.verify(&params.binding.installation_root)?; true }
                _ => false,
            }
            && match self.config.as_ref() {
                Some(config) => !manager::inspect(config)?.running,
                None => true,
            }, "legacy recovery intent or stopped owner changed");
        Ok(json!({"marker_sha256":hash(&bytes), "coordinator_id":actual.id,
            "controller_pid":actual.owner_pid, "controller_birth":actual.owner_birth,
            "issuer_cli_version":actual.expected_version}))
    }

    fn legacy_dispatch(&self, takeover: &LibraryLock, original: &LegacyParams,
        action: LegacyAction) -> Result<LegacyReceipt> {
        let binding = self.legacy_launch_binding(takeover, original)?;
        let (binary, digest) = super::super::supervise::installed_auth_runtime()?;
        let managed_id = self.config.as_ref().filter(|config| config.enabled && !config.manually_stopped)
            .map(|config| config.id.as_str());
        let (grant, _) = super::super::supervise::prepare_snapshot_grant(&binary,
            &original.binding.installation_root, &original.binding.profile, managed_id,
            crate::net_rpc::rpc_port(), original.binding.expected_account_id.as_deref()
                .context("legacy snapshot account missing")?, Some(binding))?;
        let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
        anyhow::ensure!(grant.image_sha256.eq_ignore_ascii_case(&digest), "legacy snapshot helper image changed");
        let mut params = original.clone();
        params.action = action;
        params.binding.launch_id = grant.instance_id.clone();
        dispatch_legacy_snapshot(takeover, &grant, &params)
    }
}

fn recover_legacy_snapshot(takeover: &LibraryLock) -> Result<ResultEnvelope> {
    anyhow::ensure!(current_boot_token().is_none(), "legacy recovery cannot nest maintenance");
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(takeover.protects(&root.join("runtime/takeover"))?
        && marker_bytes(&root)?.is_none(), "legacy recovery requires an unclaimed installation");
    let descriptor = super::super::supervise::discover_legacy_snapshot()?;
    let descriptor = descriptor.context("no legacy snapshot recovery journal; no recovery attempted")?;
    validate_legacy_descriptor(&descriptor)?;
    let account = super::super::recovery::account_identity_source(&profile)?;
    anyhow::ensure!(hash(account.as_bytes()) == descriptor.account_id,
        "legacy snapshot journal account differs from selected profile");
    let mut params = LegacyParams { schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
        binding: ControlBinding { installation_root: root, profile, launch_id: uuid::Uuid::new_v4().to_string(),
            expected_account_id: Some(descriptor.account_id) },
        recovery_operation_id: uuid::Uuid::new_v4().to_string(), request_fingerprint: String::new(),
        journal_sha256: descriptor.journal_sha256, action: LegacyAction::Recover };
    params.request_fingerprint = legacy_fingerprint(&params)?;
    let health = crate::rpc::probe_runtime()?;
    let mut maintenance = begin_maintenance_locked()?;
    if let Some(health) = health.as_ref() {
        maintenance.snapshot_drain_intent(takeover, &params.binding, legacy_marker(&params)?, health)?;
    } else {
        maintenance.snapshot_bind_offline_intent(takeover, &params.binding, legacy_marker(&params)?)?;
    }
    // This fresh O is dispatched once. A lost reply permits Query only.
    let receipt = match maintenance.legacy_dispatch(takeover, &params, LegacyAction::Recover) {
        Ok(receipt) => receipt,
        Err(_) => maintenance.legacy_dispatch(takeover, &params, LegacyAction::Query)
            .context("legacy recovery outcome unknown; marker retained; no recovery replayed")?,
    };
    complete_legacy_snapshot(&mut maintenance, takeover, &params, receipt)
}

fn query_legacy_snapshot(takeover: &LibraryLock) -> Result<ResultEnvelope> {
    let mut maintenance = adopt_snapshot_marker(takeover)?;
    let marker = maintenance.marker.as_ref().context("legacy recovery marker missing")?;
    let bound = marker.snapshot.as_ref().and_then(|snapshot| snapshot.legacy_recovery.as_ref())
        .context("legacy recovery request identity missing")?;
    let params = LegacyParams { schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
        binding: ControlBinding { installation_root: maintenance.installation_root()?.to_path_buf(),
            profile: marker.expected_profile.clone().context("legacy recovery profile missing")?,
            launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: Some(bound.account_id.clone()) },
        recovery_operation_id: bound.recovery_operation_id.clone(), request_fingerprint: bound.request_fingerprint.clone(),
        journal_sha256: bound.journal_sha256.clone(), action: LegacyAction::Query };
    let health = crate::rpc::probe_runtime()?;
    maintenance.legacy_pause_for_query(takeover, &params, health.as_ref())?;
    let receipt = maintenance.legacy_dispatch(takeover, &params, LegacyAction::Query)?;
    complete_legacy_snapshot(&mut maintenance, takeover, &params, receipt)
}

fn complete_legacy_snapshot(maintenance: &mut Maintenance, takeover: &LibraryLock,
    params: &LegacyParams, mut receipt: LegacyReceipt) -> Result<ResultEnvelope> {
    anyhow::ensure!(matches!(receipt.state, MaintenanceState::Released | MaintenanceState::RolledBack
        | MaintenanceState::Verified),
        "snapshot_outcome_unknown recovery_operation_id={}; marker retained; no recovery replayed",
        params.recovery_operation_id);
    let mut runtime_verified = false;
    if !receipt.cleanup_pending {
        anyhow::ensure!(matches!(receipt.state, MaintenanceState::Released | MaintenanceState::RolledBack),
            "legacy recovery cleanup is not complete; marker retained");
        maintenance.legacy_launch_binding(takeover, params)?;
        maintenance.check_account_runtime()?;
        maintenance.mark(Phase::Starting)?;
        crate::rpc::ensure_daemon_locked()?;
        let proof = maintenance.snapshot_live_binding(&params.binding, None)?;
        anyhow::ensure!(maintenance.snapshot_live_binding(&params.binding, None)? == proof,
            "legacy recovered Runtime changed before completion");
        runtime_verified = true;
        if maintenance.finish().is_err() {
            receipt.cleanup_pending = true;
            receipt.cleanup_warning = Some("snapshot recovery completed; host maintenance cleanup pending".to_owned());
        }
    }
    let mut output = ResultEnvelope::new("snapshot", if receipt.cleanup_pending { Status::Warn } else { Status::Ok },
        json!({"action":"recovered", "sync_quarantined":true, "cloud_rollback":false,
            "runtime_verified":runtime_verified, "service_released":!receipt.cleanup_pending,
            "operation_id":receipt.recovery_operation_id}), Vec::new());
    output.details = json!({"operation":{"recovery_operation_id":receipt.recovery_operation_id,
        "request_fingerprint":receipt.request_fingerprint}, "journal_sha256":receipt.journal_sha256,
        "state":receipt.state, "cleanup_pending":receipt.cleanup_pending});
    if receipt.cleanup_pending {
        output.errors.push(receipt.cleanup_warning.unwrap_or_else(||
            "snapshot recovery committed; cleanup pending; no rollback attempted".to_owned()));
    }
    Ok(output)
}

fn original_operation(
    root: PathBuf,
    profile: PathBuf,
    snapshot: &SnapshotMarkerBinding,
) -> Result<SnapshotOperation> {
    SnapshotOperation::from_original(MaintenanceControlParams {
        schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
        binding: respire_protocol::ControlBinding {
            installation_root: root,
            profile,
            launch_id: uuid::Uuid::new_v4().to_string(),
            expected_account_id: Some(snapshot.account_id.clone()),
        },
        operation_id: snapshot.operation_id.clone(),
        request_fingerprint: snapshot.request_fingerprint.clone(),
        sync_generation: snapshot.sync_generation,
        snapshot_id: snapshot.snapshot_id.clone(),
        action: MaintenanceAction::Query,
    })
}

/// Adopt only the existing snapshot marker. Generic begin(recover) would erase
/// the original operation and must not be used for snapshot recovery.
fn adopt_snapshot(takeover: &LibraryLock) -> Result<(Maintenance, SnapshotOperation)> {
    let maintenance = adopt_snapshot_marker(takeover)?;
    let held = maintenance.marker.as_ref().context("snapshot marker missing")?;
    let snapshot = held.snapshot.as_ref().context("snapshot operation missing")?;
    anyhow::ensure!(snapshot.legacy_recovery.is_none(), "legacy marker cannot authorize original restore");
    let profile = held.expected_profile.clone().context("snapshot profile missing")?;
    let operation = original_operation(maintenance.installation_root()?.to_path_buf(), profile, snapshot)?;
    Ok((maintenance, operation))
}

fn adopt_snapshot_marker(takeover: &LibraryLock) -> Result<Maintenance> {
    anyhow::ensure!(
        current_boot_token().is_none(),
        "snapshot recovery cannot nest maintenance"
    );
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(
        takeover.protects(&root.join("runtime/takeover"))?,
        "snapshot recovery takeover mismatch"
    );
    let bytes = marker_bytes(&root)?.context(
        "snapshot recovery unsupported: no original-operation marker; no journal replay attempted",
    )?;
    let mut value = marker(&root)?.context("snapshot recovery marker missing")?;
    anyhow::ensure!(
        serde_json::to_vec(&value)?
            == serde_json::to_vec(&serde_json::from_slice::<Marker>(&bytes)?)?
            && !controller_alive(&value)?
            && value.expected_version == super::maintenance_issuer_version()?
            && value.expected_profile.as_ref() == Some(&profile),
        "snapshot recovery requires the exact abandoned marker and original profile"
    );
    anyhow::ensure!(value.snapshot.is_some(), "snapshot recovery marker has no operation");
    let registration = read_registration(&root)?;
    let expected_id = if let Some(config) = registration.as_ref() {
        owned(config)?;
        anyhow::ensure!(
            config.installation == root,
            "snapshot recovery registration root changed"
        );
        config.id.clone()
    } else {
        format!("host-{}", hash(root.display().to_string().as_bytes()))
    };
    anyhow::ensure!(
        value.id == expected_id,
        "snapshot recovery coordinator changed"
    );
    let config = registration.filter(|config| config.enabled && !config.manually_stopped);
    value.token = uuid::Uuid::new_v4().to_string();
    value.owner_pid = std::process::id();
    value.owner_birth = manager::process_birth(value.owner_pid)?
        .context("snapshot recovery controller birth missing")?;
    let next = serde_json::to_vec(&value)?;
    anyhow::ensure!(
        next.len() <= MAINTENANCE_MARKER_MAX_BYTES,
        "snapshot recovery marker too large"
    );
    private_write(&marker_path(&root), &next, Some(&hash(&bytes)))?;
    ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
    Ok(Maintenance {
        installation: Some(root), config, marker: Some(value),
        marker_digest: Some(hash(&next)), completed: false,
    })
}

fn snapshot_query(
    maintenance: &mut Maintenance,
    takeover: &LibraryLock,
    operation: &SnapshotOperation,
) -> Result<MaintenanceControlResult> {
    let result = maintenance.snapshot_offline_locked(
        takeover,
        operation,
        MaintenanceAction::Query,
        None,
        snapshot_deadline(),
    )?;
    anyhow::ensure!(
        result.state != MaintenanceState::Unknown,
        "snapshot_outcome_unknown operation_id={}; no Restore or compensation was replayed",
        operation.original().operation_id
    );
    Ok(result)
}

fn recover_owned(
    maintenance: &mut Maintenance,
    takeover: &LibraryLock,
    operation: &SnapshotOperation,
) -> Result<(MaintenanceControlResult, bool)> {
    let health = crate::rpc::probe_runtime()?;
    if let Some(health) = health.as_ref() {
        maintenance.snapshot_pause_after_drain(takeover, &operation.original().binding,
            &normal_marker(operation)?, health)?;
    } else {
        maintenance.snapshot_bind_offline(takeover, operation)?;
    }
    // The Offline authority independently revalidates the stored real drain.
    snapshot_query(maintenance, takeover, operation)?;
    let mut result = maintenance.snapshot_offline_locked(
        takeover,
        operation,
        MaintenanceAction::Recover,
        None,
        snapshot_deadline(),
    )?;
    anyhow::ensure!(
        matches!(
            result.state,
            MaintenanceState::RolledBack | MaintenanceState::Verified | MaintenanceState::Released
        ),
        "snapshot recovery did not return a terminal receipt; original marker retained"
    );
    if result.cleanup_pending {
        return Ok((result, false));
    }
    anyhow::ensure!(
        matches!(
            result.state,
            MaintenanceState::RolledBack | MaintenanceState::Released
        ),
        "snapshot recovery cleanup is not complete"
    );
    maintenance.snapshot_start_runtime(takeover, operation)?;
    let proof = maintenance.snapshot_live_proof(operation, false)?;
    anyhow::ensure!(
        maintenance.snapshot_live_proof(operation, false)? == proof,
        "recovered Runtime changed before maintenance completion"
    );
    finish_snapshot_terminal(maintenance, &mut result);
    Ok((result, true))
}

pub(crate) fn snapshot_restore_control(snapshot_id: &str) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("snapshot restore control")?;
    anyhow::ensure!(
        current_boot_token().is_none(),
        "snapshot restore cannot nest maintenance"
    );
    super::super::supervise::installed_auth_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let takeover = crate::runtime_policy::takeover_lock()?;
    let health = crate::rpc::probe_runtime()?;
    let (account_id, generation) = if let Some(health) = health.as_ref() {
        crate::net_rpc::request_scope(health)?;
        (
            health.account_id.clone(),
            usize::try_from(health.generation)?,
        )
    } else {
        // Identity comes from session metadata, never an attempted DB open.
        let account = super::super::recovery::account_identity_source(&profile)?;
        (hash(account.as_bytes()), 0)
    };
    let mut params = MaintenanceControlParams {
        schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
        binding: respire_protocol::ControlBinding {
            installation_root: root,
            profile,
            launch_id: uuid::Uuid::new_v4().to_string(),
            expected_account_id: Some(account_id),
        },
        operation_id: uuid::Uuid::new_v4().to_string(),
        request_fingerprint: String::new(),
        sync_generation: generation,
        snapshot_id: snapshot_id.to_owned(),
        action: MaintenanceAction::Restore,
    };
    params.request_fingerprint = SnapshotOperation::fingerprint(
        &params.binding,
        params.sync_generation,
        &params.snapshot_id,
    )?;
    let operation = SnapshotOperation::from_original(params)?;
    let mut maintenance = begin_maintenance_locked()?;
    if health.is_none() {
        maintenance.snapshot_bind_offline(&takeover, &operation)?;
    }
    let restored = match maintenance.snapshot_offline_locked(
        &takeover,
        &operation,
        MaintenanceAction::Restore,
        health.as_ref(),
        snapshot_deadline(),
    ) {
        Ok(result) => result,
        Err(error) => {
            snapshot_query(&mut maintenance, &takeover, &operation).with_context(|| {
                format!(
                    "snapshot restore exchange failed; query original operation_id={}: {error:#}",
                    operation.original().operation_id
                )
            })?
        }
    };
    anyhow::ensure!(restored.state == MaintenanceState::Installed,
        "snapshot restore is not Installed (operation_id={}); use snapshot recover --confirm; no Restore was replayed", operation.original().operation_id);
    let started = maintenance
        .snapshot_start_runtime(&takeover, &operation)
        .and_then(|_| maintenance.snapshot_target_verified(&takeover, &operation));
    if let Err(error) = started {
        // No Commit has been sent. Query after a genuine target drain before
        // allowing Runtime recovery to choose rollback versus committed cleanup.
        let recovered = recover_owned(&mut maintenance, &takeover, &operation);
        return match recovered {
            Ok((result, verified)) => Err(error.context(if verified && !result.cleanup_pending {
                "snapshot startup/verification failed; original operation recovered".to_owned()
            } else {
                format!("snapshot startup/verification failed; recovery cleanup remains pending operation_id={}", operation.original().operation_id)
            })),
            Err(recovery) => Err(error.context(format!(
                "snapshot startup failed; recovery remains pending operation_id={}: {recovery:#}",
                operation.original().operation_id
            ))),
        };
    }
    // Commit includes verify -> durable commit -> release in Runtime. Any error
    // from this boundary is unknown, never a reason to enter rollback above.
    let mut committed = match maintenance.snapshot_finalize_locked(&takeover, &operation, MaintenanceAction::Commit, snapshot_deadline()) {
        Ok(result) => result,
        Err(error) => maintenance.snapshot_finalize_locked(&takeover, &operation, MaintenanceAction::Query, snapshot_deadline())
            .with_context(|| format!("snapshot commit outcome unknown operation_id={}: {error:#}; no rollback attempted", operation.original().operation_id))?,
    };
    anyhow::ensure!(matches!(committed.state, MaintenanceState::Verified | MaintenanceState::Released),
        "snapshot commit not confirmed operation_id={}; marker kept; use snapshot recover --confirm, do not replay Restore", operation.original().operation_id);
    if committed.state == MaintenanceState::Released && !committed.cleanup_pending {
        finish_snapshot_terminal(&mut maintenance, &mut committed);
    }
    snapshot_output("restored", &committed, true)
}

pub(crate) fn snapshot_recover_control() -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("snapshot recovery control")?;
    super::super::supervise::installed_auth_runtime()?;
    let takeover = crate::runtime_policy::takeover_lock()?;
    let (root, _) = respire_client_host::config::control_roots()?;
    match marker(&root)? {
        None => return recover_legacy_snapshot(&takeover),
        Some(value) if value.snapshot.as_ref().is_some_and(|snapshot| snapshot.legacy_recovery.is_some()) => {
            return query_legacy_snapshot(&takeover);
        }
        Some(_) => {}
    }
    let (mut maintenance, operation) = adopt_snapshot(&takeover)?;
    let (result, runtime_verified) = recover_owned(&mut maintenance, &takeover, &operation)?;
    snapshot_output("recovered", &result, runtime_verified)
}

fn finish_snapshot_terminal(maintenance: &mut Maintenance, receipt: &mut MaintenanceControlResult) {
    // A terminal journal state is already known. Host marker/registration cleanup
    // failure is a warning, never a reason to compensate accepted data.
    if let Err(error) = maintenance.finish() {
        receipt.cleanup_pending = true;
        receipt.cleanup_warning = Some(format!(
            "snapshot transaction completed; host maintenance cleanup pending: {error:#}"
        ));
    }
}

fn snapshot_output(
    action: &str,
    receipt: &MaintenanceControlResult,
    runtime_verified: bool,
) -> Result<ResultEnvelope> {
    let released = !receipt.cleanup_pending
        && matches!(
            receipt.state,
            MaintenanceState::Released | MaintenanceState::RolledBack
        );
    let mut output = ResultEnvelope::new(
        "snapshot",
        if released { Status::Ok } else { Status::Warn },
        json!({"action":action,"sync_quarantined":receipt.sync_quarantined,
            "cloud_rollback":false,"runtime_verified":runtime_verified,"service_released":released,
            "operation_id":receipt.operation_id}),
        Vec::new(),
    );
    output.details = json!({"restored":receipt.snapshot_id,"before_restore":receipt.before_restore,
        "sync_quarantined":receipt.sync_quarantined,
        "operation":{"operation_id":receipt.operation_id,"request_fingerprint":receipt.request_fingerprint},
        "state":receipt.state,"cleanup_pending":receipt.cleanup_pending});
    if receipt.cleanup_pending {
        output.errors.push(receipt.cleanup_warning.clone().unwrap_or_else(||
            "snapshot transaction completed; cleanup pending; use snapshot recover --confirm; do not roll back the committed store".to_owned()));
    }
    Ok(output)
}

fn snapshot_birth_prefix() -> &'static str {
    if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};

    static VERIFIER_MODE: AtomicU8 = AtomicU8::new(0);

    fn verify_test_embedding() -> Result<respire_host_control::VerifiedRuntime> {
        let mode = VERIFIER_MODE.load(Ordering::SeqCst);
        anyhow::ensure!(mode != 1, "snapshot test embedding verifier refused image");
        let current = std::env::current_exe()?.canonicalize()?;
        let version = current.parent().and_then(|path| path.file_name())
            .and_then(|name| name.to_str()).context("test image directory missing")?;
        let image = if mode == 2 {
            PathBuf::from(std::env::var_os("RESP_SNAPSHOT_OTHER_IMAGE")
                .context("changed test image missing")?).canonicalize()?
        } else { current.clone() };
        respire_host_control::VerifiedRuntime::verify_installed(
            &image, &hash(&fs::read(&image)?), version, 12345)
    }

    fn forbidden_account_host() -> std::sync::Arc<dyn respire_host_control::HostLifecycle> {
        panic!("snapshot issuer test entered account host")
    }

    fn write_fixture(root: &Path, value: &Marker) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(value)?;
        fs::write(marker_path(root), &bytes)?;
        Ok(bytes)
    }

    fn hold_fixture(root: &Path, value: &Marker, bytes: &[u8]) -> Maintenance {
        ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
        Maintenance {
            installation: Some(root.to_owned()), config: None, marker: Some(value.clone()),
            marker_digest: Some(hash(bytes)), completed: false,
        }
    }

    fn assert_unchanged(root: &Path, before: &[u8]) -> Result<()> {
        assert_eq!(fs::read(marker_path(root))?, before);
        Ok(())
    }

    #[test]
    fn embedded_snapshot_issuer_gates_use_reverified_runtime() -> Result<()> {
        const CHILD: &str = "RESP_SNAPSHOT_ISSUER_CHILD";
        const COMPLETE: &str = "embedded-snapshot-issuer-gates-checked";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let thread = std::thread::current();
            let name = thread.name().context("snapshot test name missing")?;
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", name, "--nocapture", "--test-threads=1"])
                .env(CHILD, "1").output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            anyhow::ensure!(output.status.success(), "isolated snapshot issuer test failed: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr));
            anyhow::ensure!(stdout.contains(&format!("test {name} ..."))
                && stdout.contains("1 passed; 0 failed") && stdout.contains(COMPLETE),
                "isolated snapshot issuer assertions did not execute: {stdout}");
            return Ok(());
        }
        let _env = crate::runtime_fetch::runtime_fetch_tests::env_scope(&[
            "RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_RUNTIME_BIN", "RSRS_RUNTIME_BOOT_TOKEN",
            "RESP_SNAPSHOT_OTHER_IMAGE"])?;
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                VERIFIER_MODE.store(0, Ordering::SeqCst);
                ACTIVE.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _reset = Reset;
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        std::env::set_var("RSRS_DATA_DIR", &root);
        std::env::set_var("RSRS_BIN_DIR", root.join("bin"));
        std::env::remove_var("RSRS_RUNTIME_BIN");
        std::env::remove_var("RSRS_RUNTIME_BOOT_TOKEN");
        ACTIVE.with(|slot| *slot.borrow_mut() = None);
        let other_image = root.join("other-runtime-image");
        fs::write(&other_image, b"different verified image")?;
        std::env::set_var("RESP_SNAPSHOT_OTHER_IMAGE", &other_image);
        crate::embedding::install_runtime_embedding(crate::embedding::RuntimeEmbedding {
            verify_runtime: verify_test_embedding, account_host: forbidden_account_host,
            offline_keygen_handoff: None,
        })?;
        let issuer = verify_test_embedding()?.version().to_owned();
        assert_ne!(issuer, env!("CARGO_PKG_VERSION"));
        let (selected_root, profile) = respire_client_host::config::control_roots()?;
        assert_eq!(selected_root.canonicalize()?, root);
        assert_eq!(profile.canonicalize()?, root);
        fs::create_dir_all(marker_path(&root).parent().context("marker parent missing")?)?;
        let takeover = LibraryLock::acquire(&root.join("runtime/takeover"), Duration::ZERO)?;
        let binding = ControlBinding {
            installation_root: root.clone(), profile: root.clone(),
            launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: Some("a".repeat(64)),
        };
        let snapshot_id = "b".repeat(32);
        let operation = SnapshotOperation::from_original(MaintenanceControlParams {
            schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
            request_fingerprint: SnapshotOperation::fingerprint(&binding, 1, &snapshot_id)?,
            binding: binding.clone(), operation_id: uuid::Uuid::new_v4().to_string(),
            sync_generation: 1, snapshot_id, action: MaintenanceAction::Query,
        })?;
        let owned = Marker {
            schema: 1, id: format!("host-{}", hash(root.display().to_string().as_bytes())),
            token: uuid::Uuid::new_v4().to_string(), phase: Phase::Paused,
            expected_profile: Some(root.clone()), expected_version: issuer.clone(),
            owner_pid: std::process::id(),
            owner_birth: manager::process_birth(std::process::id())?.context("controller birth missing")?,
            snapshot: None, agent_config: None,
        };
        assert!(controller_alive(&owned)?);

        // Each call uses the production entry point, with every earlier guard satisfied.
        for version in [issuer.as_str(), env!("CARGO_PKG_VERSION"), "foreign-issuer"] {
            for mode in 0..=2 {
                VERIFIER_MODE.store(mode, Ordering::SeqCst);
                let mut value = owned.clone();
                value.expected_version = version.to_owned();
                let before = write_fixture(&root, &value)?;
                let maintenance = hold_fixture(&root, &value, &before);
                let result = maintenance.snapshot_owned_marker(&takeover, &binding);
                if mode == 0 && version == issuer {
                    let (path, bytes, actual) = result?;
                    assert_eq!(path, marker_path(&root));
                    assert_eq!(bytes, before);
                    assert_eq!(actual.expected_version, issuer);
                } else {
                    let error = result.err().context("invalid issuer unexpectedly owned marker")?;
                    let expected = match mode {
                        1 => "snapshot test embedding verifier refused image",
                        2 => "selected Runtime changed during host command",
                        _ => "snapshot requires this controller's exact Paused marker",
                    };
                    assert_eq!(error.to_string(), expected);
                }
                assert_unchanged(&root, &before)?;
                drop(maintenance);

                value.phase = Phase::Starting;
                let before = write_fixture(&root, &value)?;
                let mut maintenance = hold_fixture(&root, &value, &before);
                let error = maintenance.snapshot_target_verified(&takeover, &operation)
                    .err().context("target without drain unexpectedly verified")?;
                let expected = match mode {
                    1 => "snapshot test embedding verifier refused image",
                    2 => "selected Runtime changed during host command",
                    _ if version == issuer => "snapshot target has no drain-backed operation",
                    _ => "snapshot target does not belong to this exact Starting/Verified controller",
                };
                assert_eq!(error.to_string(), expected);
                assert_unchanged(&root, &before)?;
                drop(maintenance);
            }
        }
        VERIFIER_MODE.store(0, Ordering::SeqCst);
        for case in ["foreign-profile", "foreign-token", "foreign-controller", "changed-digest"] {
            let before = write_fixture(&root, &owned)?;
            let mut maintenance = hold_fixture(&root, &owned, &before);
            let mut selected = binding.clone();
            match case {
                "foreign-profile" => {
                    selected.profile = root.join("foreign");
                    fs::create_dir_all(&selected.profile)?;
                    selected.profile = selected.profile.canonicalize()?;
                }
                "foreign-token" => ACTIVE.with(|slot| *slot.borrow_mut() = Some(uuid::Uuid::new_v4().to_string())),
                "foreign-controller" => maintenance.marker.as_mut().context("held marker missing")?.id = "foreign".into(),
                "changed-digest" => maintenance.marker_digest = Some(hash(b"changed")),
                _ => unreachable!("unknown fixture"),
            }
            assert!(maintenance.snapshot_owned_marker(&takeover, &selected).is_err(), "accepted {case}");
            assert_unchanged(&root, &before)?;
            drop(maintenance);
            ACTIVE.with(|slot| *slot.borrow_mut() = None);
        }
        // A reaped real process supplies an absent owner PID, not a fabricated birth mismatch.
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .arg("--list").stdout(std::process::Stdio::null()).spawn()?;
        let dead_pid = child.id();
        anyhow::ensure!(child.wait()?.success(), "dead-owner fixture failed");
        assert!(manager::process_birth(dead_pid)?.is_none());
        let mut abandoned = owned.clone();
        abandoned.owner_pid = dead_pid;
        abandoned.snapshot = Some(normal_marker(&operation)?);
        assert!(!controller_alive(&abandoned)?);
        for version in [issuer.as_str(), env!("CARGO_PKG_VERSION"), "foreign-issuer"] {
            for mode in 0..=2 {
                VERIFIER_MODE.store(mode, Ordering::SeqCst);
                let mut value = abandoned.clone();
                value.expected_version = version.to_owned();
                let before = write_fixture(&root, &value)?;
                assert!(current_boot_token().is_none());
                let result = adopt_snapshot_marker(&takeover);
                if mode == 0 && version == issuer {
                    let adopted = result?;
                    let after = marker(&root)?.context("adopted marker missing")?;
                    assert_eq!(after.expected_version, issuer);
                    assert_eq!(after.owner_pid, std::process::id());
                    assert!(controller_alive(&after)?);
                    assert_ne!(after.token, value.token);
                    assert_eq!(current_boot_token().as_deref(), Some(after.token.as_str()));
                    assert_eq!(serde_json::to_value(&after.snapshot)?, serde_json::to_value(&value.snapshot)?);
                    assert_eq!(after.expected_profile, value.expected_profile);
                    assert_eq!(after.id, value.id);
                    drop(adopted);
                } else {
                    let error = result.err().context("foreign issuer or failed verifier adopted marker")?;
                    let expected = match mode {
                        1 => "snapshot test embedding verifier refused image",
                        2 => "selected Runtime changed during host command",
                        _ => "snapshot recovery requires the exact abandoned marker and original profile",
                    };
                    assert_eq!(error.to_string(), expected);
                    assert_unchanged(&root, &before)?;
                }
                assert!(current_boot_token().is_none());
            }
        }
        VERIFIER_MODE.store(0, Ordering::SeqCst);
        for case in ["live-owner", "foreign-profile", "foreign-coordinator", "missing-operation"] {
            let mut value = abandoned.clone();
            match case {
                "live-owner" => { value.owner_pid = owned.owner_pid; value.owner_birth = owned.owner_birth.clone(); }
                "foreign-profile" => value.expected_profile = Some(root.join("foreign")),
                "foreign-coordinator" => value.id = "foreign-controller".into(),
                "missing-operation" => value.snapshot = None,
                _ => unreachable!("unknown fixture"),
            }
            let before = write_fixture(&root, &value)?;
            assert!(adopt_snapshot_marker(&takeover).is_err(), "accepted {case}");
            assert_unchanged(&root, &before)?;
            assert!(current_boot_token().is_none());
        }
        println!("{COMPLETE}");
        Ok(())
    }
}

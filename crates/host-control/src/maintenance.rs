//! Durable host maintenance ownership shared by the CLI and native Runtime.
//!
//! The embedding performs real service/process operations. This module owns the
//! marker, phase transitions, drain-before-auth proof and live target checks.
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::net_rpc::Health;
use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult};
use respire_protocol::{HostAuthIdentity, HostControlMaintenanceBinding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::launch::{hash, process_birth};
use crate::VerifiedRuntime;

mod accounts;
pub(crate) use accounts::{finish_account_routing, pending_account};
mod private_io;
mod takeover;
use private_io::{marker_bytes, private_write, registration_digest};
pub use takeover::takeover_lock;

pub(crate) const MAINTENANCE_MARKER_MAX_BYTES: usize = 16 * 1024;
thread_local! {
    static ACTIVE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Observed and ownership-checked registration, never a request-side claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationMode {
    Unregistered,
    Stopped { coordinator_id: String },
    Managed { coordinator_id: String },
}

impl RegistrationMode {
    fn coordinator_id(&self, root: &Path) -> String {
        match self {
            Self::Unregistered => format!("host-{}", hash(root.display().to_string().as_bytes())),
            Self::Stopped { coordinator_id } | Self::Managed { coordinator_id } => {
                coordinator_id.clone()
            }
        }
    }

    fn managed_id(&self) -> Option<&str> {
        match self {
            Self::Managed { coordinator_id } => Some(coordinator_id),
            _ => None,
        }
    }
}

/// Host-only operations, implemented against the embedding's actual lifecycle.
/// A Runtime without service-manager support must reject an existing registration
/// from `inspect_registration`; reporting it as unregistered is not permitted.
pub trait HostLifecycle {
    fn require_account_write(&self) -> Result<()>;
    fn verified_runtime(&self) -> Result<VerifiedRuntime>;
    fn issuer_version(&self) -> &str;
    fn inspect_registration(&self, root: &Path) -> Result<RegistrationMode>;
    /// Persist the checked existing managed registration only. Never register it.
    fn set_maintenance(&self, root: &Path, enabled: bool) -> Result<()>;
    fn probe_runtime(&self) -> Result<Option<Health>>;
    fn endpoint_path(&self) -> PathBuf;
    /// Verify exact ownership, wait for final drain receipt and process exit,
    /// acquire the released library lock, remove only its locator, then stop and
    /// re-inspect a managed supervisor. Never kill an unverified owner.
    fn drain_runtime(&self, health: &Health) -> Result<()>;
    /// Launch the checked installed image with the inherited serving grant.
    /// Return only after independently observed readiness, or an error. No
    /// installer, registration creation or unverified detached fallback belongs here.
    fn start_account_runtime(&self, launch: &LaunchContext) -> Result<()>;
    /// Called only after independent commit verification and durable maintenance
    /// completion, while this coordinator still holds installation takeover.
    /// Ordinary CLI hosts keep the verified serving instance. A legacy desktop
    /// host must drain that exact strict instance and verify its fresh host lane.
    fn finish_account_handoff(&self, _receipt: &HostAuthAccountResult) -> Result<()> {
        Ok(())
    }
    fn finish_key_handoff(
        &self,
        _profile: &Path,
        _identity: &HostAuthIdentity,
        _serving: bool,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryMode {
    Fresh,
    QueryOriginal,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Phase {
    Paused,
    Starting,
    Verified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchPurpose {
    Account,
    AccountComplete,
    Serving,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: u32,
    id: String,
    token: String,
    phase: Phase,
    expected_profile: Option<PathBuf>,
    expected_version: String,
    owner_pid: u32,
    owner_birth: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_config: Option<Value>,
}

/// A non-deserializable capability minted only from this controller's exact
/// marker. It never exports the durable reusable maintenance token.
pub struct OwnedMaintenanceBinding {
    root: PathBuf,
    profile: PathBuf,
    marker: Marker,
    maintenance: HostControlMaintenanceBinding,
    registration: RegistrationMode,
    registration_sha256: Option<String>,
    purpose: LaunchPurpose,
    host: Arc<dyn HostLifecycle>,
}

pub type LaunchBinding = OwnedMaintenanceBinding;

/// One attempt to launch a replacement from a real Starting owner. It cannot be
/// cloned, deserialized, or retried after an uncertain launch.
pub struct LaunchContext {
    binding: OwnedMaintenanceBinding,
    identity: HostAuthIdentity,
    claimed: Cell<bool>,
}

impl LaunchContext {
    pub fn installation_root(&self) -> &Path {
        self.binding.installation_root()
    }
    pub fn profile(&self) -> &Path {
        self.binding.profile()
    }
    pub(crate) fn claim(&self) -> Result<(&OwnedMaintenanceBinding, &HostAuthIdentity)> {
        anyhow::ensure!(
            !self.claimed.replace(true),
            "replacement launch was already attempted; query its outcome"
        );
        self.binding.revalidate()?;
        anyhow::ensure!(
            self.binding.phase() == Phase::Starting
                && self.binding.purpose() == LaunchPurpose::Serving
                && crate::identity(self.profile())? == self.identity,
            "replacement launch owner or identity changed"
        );
        ensure_no_owner(self.binding.host.as_ref())?;
        Ok((&self.binding, &self.identity))
    }
}

impl OwnedMaintenanceBinding {
    pub fn installation_root(&self) -> &Path {
        &self.root
    }
    pub fn profile(&self) -> &Path {
        &self.profile
    }
    pub fn maintenance(&self) -> &HostControlMaintenanceBinding {
        &self.maintenance
    }
    pub fn managed_id(&self) -> Option<&str> {
        self.registration.managed_id()
    }
    pub fn registration_sha256(&self) -> Option<&str> {
        self.registration_sha256.as_deref()
    }
    pub fn phase(&self) -> Phase {
        self.marker.phase
    }
    pub fn purpose(&self) -> LaunchPurpose {
        self.purpose
    }

    pub fn revalidate(&self) -> Result<()> {
        verify_selection(&self.root, &self.profile)?;
        ensure_registration(self.host.as_ref(), &self.root, &self.registration)?;
        let bytes = marker_bytes(&self.root)?.context("maintenance grant marker disappeared")?;
        let actual = parse_marker(&bytes)?;
        ensure_exact_owner(
            &actual,
            &self.marker,
            &bytes,
            &self.maintenance.marker_sha256,
        )?;
        ensure_purpose(self.purpose, actual.phase)?;
        anyhow::ensure!(
            actual.expected_profile.as_deref() == Some(self.profile.as_path())
                && actual.expected_version == self.host.issuer_version(),
            "maintenance launch profile or issuer changed"
        );
        anyhow::ensure!(
            registration_digest(&self.root, &self.registration)?.as_deref()
                == self.registration_sha256.as_deref(),
            "maintenance registration changed before launch"
        );
        if self.purpose == LaunchPurpose::Account {
            ensure_no_owner(self.host.as_ref())?;
        }
        Ok(())
    }
}

pub struct Maintenance {
    root: PathBuf,
    host: Arc<dyn HostLifecycle>,
    registration: RegistrationMode,
    marker: Marker,
    marker_digest: String,
    drained: bool,
    original_health: Option<Health>,
    account_origin: Option<accounts::AccountOrigin>,
    account_record: Option<accounts::AccountRecord>,
    completed: bool,
}

fn account_owner_token(
    recovery: RecoveryMode,
    previous: Option<&Marker>,
    retained: Option<&str>,
) -> Result<String> {
    match retained {
        Some(token) => {
            let parsed = uuid::Uuid::parse_str(token)?;
            anyhow::ensure!(
                (recovery == RecoveryMode::QueryOriginal || previous.is_none())
                    && parsed.get_version_num() == 4
                    && parsed.to_string() == token
                    && previous.is_none_or(|previous| previous.token == token),
                "recovery cannot replace its original maintenance token"
            );
            Ok(token.to_owned())
        }
        None => {
            anyhow::ensure!(
                recovery == RecoveryMode::Fresh,
                "account recovery requires the verified original operation token"
            );
            Ok(uuid::Uuid::new_v4().to_string())
        }
    }
}

impl Maintenance {
    /// Caller retains the same takeover lock through drain, private exchange,
    /// target verification and completion. An AwaitingInput continuation may keep
    /// this owner alive, but must reacquire takeover before using it again.
    pub(crate) fn begin_locked(
        takeover: &LibraryLock,
        host: Arc<dyn HostLifecycle>,
        recovery: RecoveryMode,
    ) -> Result<Self> {
        Self::begin_with_token(takeover, host, recovery, None)
    }

    fn begin_with_token(
        takeover: &LibraryLock,
        host: Arc<dyn HostLifecycle>,
        recovery: RecoveryMode,
        retained_token: Option<&str>,
    ) -> Result<Self> {
        host.require_account_write()?;
        anyhow::ensure!(
            current_boot_token().is_none(),
            "host maintenance already has an active controller"
        );
        let (root, _) = selected_roots()?;
        anyhow::ensure!(
            takeover.protects(&root.join("runtime/takeover"))?,
            "maintenance requires this installation's takeover ownership"
        );
        let registration = host.inspect_registration(&root)?;
        validate_registration_mode(&root, &registration)?;
        let previous = marker_bytes(&root)?;
        let prior = previous.as_deref().map(parse_marker).transpose()?;
        anyhow::ensure!(prior.is_none() || recovery == RecoveryMode::QueryOriginal,
            "interrupted host maintenance; query the original operation before starting another write");
        let id = registration.coordinator_id(&root);
        if let Some(prior) = prior.as_ref() {
            anyhow::ensure!(
                prior.id == id && prior.snapshot.is_none() && prior.agent_config.is_none(),
                "maintenance belongs to another coordinator or operation family"
            );
            anyhow::ensure!(
                !controller_alive(prior)? || prior.owner_pid == std::process::id(),
                "maintenance still belongs to a live controller"
            );
        }
        let value = Marker {
            schema: 1,
            id,
            token: account_owner_token(recovery, prior.as_ref(), retained_token)?,
            phase: Phase::Paused,
            expected_profile: None,
            expected_version: host.issuer_version().to_owned(),
            owner_pid: std::process::id(),
            owner_birth: process_birth(std::process::id())?
                .context("controller process identity unavailable")?,
            snapshot: None,
            agent_config: None,
        };
        anyhow::ensure!(
            !value.expected_version.is_empty(),
            "maintenance issuer version is missing"
        );
        let bytes = serde_json::to_vec(&value)?;
        private_write(
            &marker_path(&root),
            &bytes,
            previous.as_ref().map(|bytes| hash(bytes)).as_deref(),
        )?;
        if matches!(registration, RegistrationMode::Managed { .. }) {
            host.set_maintenance(&root, true)?;
        }
        ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
        Ok(Self {
            root,
            host,
            registration,
            marker: value,
            marker_digest: hash(&bytes),
            drained: false,
            original_health: None,
            account_origin: None,
            account_record: None,
            completed: false,
        })
    }

    /// Only the shared key coordinator calls this after validating the exact
    /// persisted journal (or its exact archive). Request input cannot construct
    /// the original maintenance token or coordinator.
    pub(crate) fn resume_key_locked(
        takeover: &LibraryLock,
        host: Arc<dyn HostLifecycle>,
        root: &Path,
        profile: &Path,
        source: &Path,
        token: &str,
        coordinator: &str,
    ) -> Result<Self> {
        host.require_account_write()?;
        anyhow::ensure!(
            current_boot_token().is_none(),
            "host maintenance already has a controller"
        );
        verify_selection(root, profile)?;
        anyhow::ensure!(
            takeover.protects(&root.join("runtime/takeover"))?,
            "key recovery requires this installation's takeover ownership"
        );
        let id = uuid::Uuid::parse_str(token).context("invalid key maintenance token")?;
        anyhow::ensure!(
            id.get_version_num() == 4
                && id.to_string() == token
                && respire_client_host::config::normalize_control_path(source)?.canonicalize()?
                    == source,
            "key recovery requires the canonical original owner and source"
        );
        let registration = host.inspect_registration(root)?;
        validate_registration_mode(root, &registration)?;
        anyhow::ensure!(
            registration.coordinator_id(root) == coordinator,
            "key recovery registration or coordinator changed"
        );
        let previous = marker_bytes(root)?;
        if let Some(bytes) = previous.as_ref() {
            let value = parse_marker(bytes)?;
            anyhow::ensure!(
                value.id == coordinator
                    && value.token == token
                    && value.snapshot.is_none()
                    && value.agent_config.is_none()
                    && matches!(value.expected_profile.as_deref(), Some(expected) if expected == profile || expected == source)
                    && value.expected_version == host.issuer_version()
                    && (!controller_alive(&value)? || value.owner_pid == std::process::id()),
                "key recovery does not own the original maintenance marker"
            );
        }
        let value = Marker {
            schema: 1,
            id: coordinator.to_owned(),
            token: token.to_owned(),
            phase: Phase::Paused,
            expected_profile: Some(profile.to_path_buf()),
            expected_version: host.issuer_version().to_owned(),
            owner_pid: std::process::id(),
            owner_birth: process_birth(std::process::id())?
                .context("key recovery controller birth unavailable")?,
            snapshot: None,
            agent_config: None,
        };
        let bytes = serde_json::to_vec(&value)?;
        private_write(
            &marker_path(root),
            &bytes,
            previous.as_ref().map(|bytes| hash(bytes)).as_deref(),
        )?;
        if matches!(registration, RegistrationMode::Managed { .. }) {
            host.set_maintenance(root, true)?;
        }
        ACTIVE.with(|slot| *slot.borrow_mut() = Some(token.to_owned()));
        Ok(Self {
            root: root.to_path_buf(),
            host,
            registration,
            marker: value,
            marker_digest: hash(&bytes),
            drained: false,
            original_health: None,
            account_origin: None,
            account_record: None,
            completed: false,
        })
    }

    pub(crate) fn key_recovery_binding(&self) -> Result<(String, String)> {
        self.check_owner()?;
        anyhow::ensure!(
            self.marker.phase == Phase::Paused && self.drained,
            "key recovery metadata requires the drained Paused owner"
        );
        Ok((self.marker.token.clone(), self.marker.id.clone()))
    }

    pub(crate) fn pause_key(&mut self) -> Result<()> {
        self.check_owner()?;
        self.write_phase(Phase::Paused)
    }

    /// Restored serving/readiness expectations come only from the shared key
    /// coordinator's revalidated journal, not an authorization flag from a client.
    pub(crate) fn finish_key(
        &mut self,
        profile: &Path,
        identity: &HostAuthIdentity,
        restore_owner: bool,
        restore_store: bool,
    ) -> Result<()> {
        self.check_owner()?;
        verify_selection(&self.root, profile)?;
        anyhow::ensure!(
            &crate::identity(profile)? == identity,
            "key terminal identity differs from the selected profile"
        );
        anyhow::ensure!(
            !restore_store || restore_owner,
            "key recovery store expectation has no original owner"
        );
        let require_ready = restore_store
            || self
                .original_health
                .as_ref()
                .is_some_and(|health| health.store_ready);
        if self.marker.phase == Phase::Verified {
            self.verify_runtime(profile, identity, true)?;
        } else if restore_owner {
            anyhow::ensure!(
                self.marker.phase == Phase::Starting,
                "key owner must be explicitly restored before completion"
            );
            self.verify_runtime(profile, identity, require_ready)?;
        } else {
            anyhow::ensure!(
                self.marker.phase == Phase::Paused && self.drained,
                "non-serving key completion requires the drained Paused owner"
            );
            ensure_no_owner(self.host.as_ref())?;
        }
        self.check_owner()?;
        anyhow::ensure!(
            &crate::identity(profile)? == identity,
            "key identity changed during owner restoration"
        );
        self.write_phase(Phase::Verified)?;
        self.finish()
    }

    pub fn installation_root(&self) -> &Path {
        &self.root
    }
    pub fn phase(&self) -> Phase {
        self.marker.phase
    }
    pub fn coordinator_id(&self) -> &str {
        &self.marker.id
    }

    pub fn check_account_runtime(&self) -> Result<()> {
        self.check_owner()?;
        self.host.require_account_write()?;
        self.host.verified_runtime()?.revalidate()
    }

    /// Consume the exact owner observed by the trusted coordinator before it
    /// published Paused. Some serving modes deliberately revoke health when the
    /// marker appears; probing again before the identity-bound stop deadlocks
    /// maintenance. The native owner and image are rechecked before any effect.
    pub(crate) fn drain_observed_runtime(&mut self, observed: Option<&Health>) -> Result<()> {
        self.check_owner()?;
        anyhow::ensure!(
            self.marker.phase == Phase::Paused,
            "drain requires Paused maintenance"
        );
        if self.drained {
            // Key setup may call this again after writing its original journal.
            // Never send a second stop for an already consumed observation.
            ensure_no_owner(self.host.as_ref())?;
            return Ok(());
        }
        match observed {
            Some(health) => self.drain_runtime(health),
            None => {
                ensure_no_owner(self.host.as_ref())?;
                self.drained = true;
                Ok(())
            }
        }
    }

    pub(crate) fn drain_runtime(&mut self, health: &Health) -> Result<()> {
        self.check_owner()?;
        anyhow::ensure!(
            self.marker.phase == Phase::Paused && !self.drained,
            "drain requires an unconsumed Paused owner observation"
        );
        let (_, selected) = selected_roots()?;
        verify_health_roots(health, &self.root, &selected)?;
        respire_commands::net_rpc::request_scope(health)?;
        let process = respire_commands::net_rpc::runtime_process_identity(health.pid)?;
        let image = Path::new(&process.executable).canonicalize()?;
        let image_sha256 = crate::launch::hash_file(&image)?;
        verify_observed_process(health, &process, &image_sha256)?;
        anyhow::ensure!(
            health.managed_id.as_deref() == self.registration.managed_id(),
            "observed runtime belongs to a different managed owner"
        );
        let birth =
            process_birth(health.pid)?.context("observed runtime process already exited")?;
        anyhow::ensure!(
            process_start_matches(&birth, &health.process_start_id)
                && respire_commands::net_rpc::runtime_process_identity(health.pid)? == process,
            "observed runtime process changed before typed drain"
        );
        // No fresh health read here: the checked observation supplies the exact
        // installation, instance, account and generation for request_stop_for.
        self.host.drain_runtime(health)?;
        anyhow::ensure!(
            process_birth(health.pid)?.as_deref() != Some(birth.as_str()),
            "runtime drain returned before the exact owner exited"
        );
        ensure_no_owner(self.host.as_ref())?;
        self.check_owner()?;
        if self.original_health.is_none() {
            self.original_health = Some(health.clone());
        }
        self.drained = true;
        Ok(())
    }

    pub fn auth_launch_binding(
        &mut self,
        profile: &Path,
    ) -> Result<Option<OwnedMaintenanceBinding>> {
        self.check_owner()?;
        anyhow::ensure!(
            self.drained && self.marker.phase == Phase::Paused,
            "account authorization requires the drained Paused owner"
        );
        verify_selection(&self.root, profile)?;
        ensure_no_owner(self.host.as_ref())?;
        self.marker.expected_profile = Some(profile.to_path_buf());
        self.write_phase(Phase::Paused)?;
        Ok(Some(self.binding(profile, LaunchPurpose::Account)?))
    }

    pub fn start_account_runtime(&mut self) -> Result<()> {
        self.check_account_runtime()?;
        anyhow::ensure!(self.drained, "replacement startup requires a drained owner");
        let (_, selected) = selected_roots()?;
        self.write_phase(Phase::Starting)?;
        let launch = LaunchContext {
            binding: self.binding(&selected, LaunchPurpose::Serving)?,
            identity: crate::identity(&selected)?,
            claimed: Cell::new(false),
        };
        self.host.start_account_runtime(&launch)?;
        self.drained = false;
        Ok(())
    }

    pub fn start_account_target(
        &mut self,
        source: &Path,
        operation_id: &str,
        receipt: &HostAuthAccountResult,
        register: bool,
    ) -> Result<()> {
        crate::account_control::validate_account_receipt(receipt, operation_id, source, register)?;
        self.start_account_runtime()?;
        self.account_target_verified(source, operation_id, receipt, register)
    }

    pub(crate) fn start_key_target(
        &mut self,
        source: &Path,
        operation_id: &str,
        receipt: &respire_protocol::key_control::HostKeyResult,
    ) -> Result<()> {
        let target = crate::key::validate_applied_target(receipt, operation_id, source)?;
        self.start_account_runtime()?;
        self.verify_ready_runtime(&target, &receipt.identity)?;
        crate::key::validate_applied_target(receipt, operation_id, source)?;
        self.check_owner()?;
        anyhow::ensure!(
            matches!(self.marker.phase, Phase::Starting | Phase::Verified)
                && self.marker.expected_profile.as_deref() == Some(target.as_path()),
            "key target launch does not belong to this maintenance controller"
        );
        self.write_phase(Phase::Verified)
    }

    pub(crate) fn key_complete_launch_binding(
        &self,
        source: &Path,
        operation_id: &str,
        receipt: &respire_protocol::key_control::HostKeyResult,
    ) -> Result<Option<OwnedMaintenanceBinding>> {
        let target = crate::key::validate_applied_target(receipt, operation_id, source)?;
        self.check_owner()?;
        anyhow::ensure!(
            self.marker.phase == Phase::Verified
                && self.marker.expected_profile.as_deref() == Some(target.as_path()),
            "key completion requires this controller's exact Verified marker"
        );
        Ok(Some(self.binding(&target, LaunchPurpose::AccountComplete)?))
    }

    pub fn account_target_verified(
        &mut self,
        source: &Path,
        operation_id: &str,
        receipt: &HostAuthAccountResult,
        register: bool,
    ) -> Result<()> {
        crate::account_control::validate_account_receipt(receipt, operation_id, source, register)?;
        ensure_applied(receipt)?;
        let target = receipt_target(receipt)?;
        let identity = crate::identity(&target)?;
        self.verify_ready_runtime(&target, &identity)?;
        self.check_owner()?;
        anyhow::ensure!(
            matches!(self.marker.phase, Phase::Starting | Phase::Verified)
                && self.marker.expected_profile.as_deref() == Some(target.as_path()),
            "account target launch does not belong to this maintenance controller"
        );
        self.write_phase(Phase::Verified)
    }

    pub fn account_complete_launch_binding(
        &self,
        source: &Path,
        operation_id: &str,
        receipt: &HostAuthAccountResult,
        register: bool,
    ) -> Result<Option<OwnedMaintenanceBinding>> {
        crate::account_control::validate_account_receipt(receipt, operation_id, source, register)?;
        ensure_applied(receipt)?;
        let target = receipt_target(receipt)?;
        self.check_owner()?;
        anyhow::ensure!(
            self.marker.phase == Phase::Verified,
            "account completion requires this controller's exact Verified marker"
        );
        Ok(Some(self.binding(&target, LaunchPurpose::AccountComplete)?))
    }

    /// Completion cannot promote a merely Paused or Starting marker. Failure at
    /// any earlier step leaves durable maintenance in place for explicit recovery.
    pub fn finish(&mut self) -> Result<()> {
        if self.completed {
            return Ok(());
        }
        self.check_owner()?;
        anyhow::ensure!(
            self.marker.phase == Phase::Verified,
            "maintenance completion requires independently Verified state"
        );
        if matches!(self.registration, RegistrationMode::Managed { .. }) {
            self.host.set_maintenance(&self.root, false)?;
        }
        self.check_owner()?;
        let path = marker_path(&self.root);
        fs::remove_file(&path)?;
        let durable = respire_spawn::durable::sync_directory(
            path.parent().context("maintenance parent missing")?,
        );
        // Account commit is not undone by a namespace-sync failure. Never
        // manufacture durable completion or attempt a fresh authentication.
        self.completed = true;
        self.clear_active();
        durable.context("account verified; maintenance namespace cleanup is unconfirmed")
    }

    /// A rollback can restore a non-serving source. That is verified by exact
    /// source identity and owner absence, not by inventing runtime readiness.
    pub fn finish_rollback(
        &mut self,
        source: &Path,
        original_identity: &HostAuthIdentity,
        was_serving: bool,
    ) -> Result<()> {
        self.check_owner()?;
        verify_selection(&self.root, source)?;
        anyhow::ensure!(
            &crate::identity(source)? == original_identity,
            "account rollback did not restore the original source identity"
        );
        anyhow::ensure!(
            was_serving
                == self.account_origin.as_ref().map_or_else(
                    || self.original_health.is_some(),
                    |origin| origin.was_serving
                ),
            "rollback serving state differs from the actually drained owner"
        );
        if was_serving {
            self.start_account_runtime()?;
            self.verify_runtime(
                source,
                original_identity,
                self.account_origin.as_ref().map_or_else(
                    || {
                        self.original_health
                            .as_ref()
                            .is_some_and(|health| health.store_ready)
                    },
                    |origin| origin.store_ready,
                ),
            )?;
        } else {
            anyhow::ensure!(
                self.marker.phase == Phase::Paused && self.drained,
                "non-serving rollback requires the original drained Paused owner"
            );
            ensure_no_owner(self.host.as_ref())?;
        }
        self.write_phase(Phase::Verified)?;
        self.finish()
    }

    /// Recheck a committed target before removing the marker after its completion
    /// helper returns. A typed receipt alone is not a readiness proof.
    pub fn verify_account_target(
        &self,
        source: &Path,
        operation_id: &str,
        receipt: &HostAuthAccountResult,
        register: bool,
    ) -> Result<()> {
        crate::account_control::validate_account_receipt(receipt, operation_id, source, register)?;
        ensure_applied(receipt)?;
        let target = receipt_target(receipt)?;
        self.verify_ready_runtime(&target, &crate::identity(&target)?)
    }

    fn verify_ready_runtime(&self, profile: &Path, identity: &HostAuthIdentity) -> Result<()> {
        self.verify_runtime(profile, identity, true)
    }

    fn verify_runtime(
        &self,
        profile: &Path,
        identity: &HostAuthIdentity,
        require_ready: bool,
    ) -> Result<()> {
        self.check_owner()?;
        verify_selection(&self.root, profile)?;
        let runtime = self.host.verified_runtime()?;
        runtime.revalidate()?;
        let health = self
            .host
            .probe_runtime()?
            .context("account target Runtime is unavailable")?;
        verify_health_roots(&health, &self.root, profile)?;
        respire_commands::net_rpc::request_scope(&health)?;
        let process = respire_commands::net_rpc::runtime_process_identity(health.pid)?;
        let account_id = match identity {
            HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
            _ => hash(profile.display().to_string().as_bytes()),
        };
        anyhow::ensure!(
            (!require_ready || health.store_ready)
                && health.account_id == account_id
                && health.runtime_version == runtime.version()
                && Path::new(&health.image_path).canonicalize()? == runtime.path()
                && Path::new(&health.exe).canonicalize()? == runtime.path()
                && Path::new(&process.executable).canonicalize()? == runtime.path()
                && process_start_matches(&process.started_at, &health.process_start_id)
                && health.image_sha256.eq_ignore_ascii_case(runtime.sha256())
                && health.managed_id.as_deref() == self.registration.managed_id(),
            "target Runtime does not match the selected account, image or managed owner"
        );
        anyhow::ensure!(
            respire_commands::net_rpc::runtime_process_identity(health.pid)? == process
                && &crate::identity(profile)? == identity,
            "target Runtime or account identity changed during verification"
        );
        self.check_owner()
    }

    fn check_owner(&self) -> Result<()> {
        anyhow::ensure!(
            !self.completed,
            "maintenance transaction is already completed"
        );
        let (root, _) = selected_roots()?;
        anyhow::ensure!(root == self.root, "maintenance installation changed");
        ensure_registration(self.host.as_ref(), &self.root, &self.registration)?;
        let bytes = marker_bytes(&self.root)?.context("maintenance marker disappeared")?;
        let actual = parse_marker(&bytes)?;
        ensure_exact_owner(&actual, &self.marker, &bytes, &self.marker_digest)
    }

    fn write_phase(&mut self, phase: Phase) -> Result<()> {
        // expected_profile may be newly pinned by auth_launch_binding, but the
        // current persisted bytes must still exactly match the last held digest.
        let bytes = marker_bytes(&self.root)?.context("maintenance marker disappeared")?;
        let actual = parse_marker(&bytes)?;
        let mut held = self.marker.clone();
        held.expected_profile = actual.expected_profile.clone();
        ensure_exact_owner(&actual, &held, &bytes, &self.marker_digest)?;
        ensure_registration(self.host.as_ref(), &self.root, &self.registration)?;
        let mut next = self.marker.clone();
        next.phase = phase;
        if matches!(phase, Phase::Starting | Phase::Verified) {
            let (root, selected) = selected_roots()?;
            anyhow::ensure!(root == self.root, "maintenance installation changed");
            next.expected_profile = Some(selected);
        }
        let next_bytes = serde_json::to_vec(&next)?;
        private_write(
            &marker_path(&self.root),
            &next_bytes,
            Some(&self.marker_digest),
        )?;
        self.marker = next;
        self.marker_digest = hash(&next_bytes);
        Ok(())
    }

    fn binding(&self, profile: &Path, purpose: LaunchPurpose) -> Result<OwnedMaintenanceBinding> {
        self.check_owner()?;
        verify_selection(&self.root, profile)?;
        ensure_purpose(purpose, self.marker.phase)?;
        let result = OwnedMaintenanceBinding {
            root: self.root.clone(),
            profile: profile.to_path_buf(),
            marker: self.marker.clone(),
            maintenance: HostControlMaintenanceBinding {
                marker_sha256: self.marker_digest.clone(),
                coordinator_id: self.marker.id.clone(),
                controller_pid: self.marker.owner_pid,
                controller_birth: self.marker.owner_birth.clone(),
                issuer_cli_version: self.marker.expected_version.clone(),
            },
            registration: self.registration.clone(),
            registration_sha256: registration_digest(&self.root, &self.registration)?,
            purpose,
            host: Arc::clone(&self.host),
        };
        result.revalidate()?;
        Ok(result)
    }

    fn clear_active(&self) {
        ACTIVE.with(|slot| {
            let mut active = slot.borrow_mut();
            if active.as_deref() == Some(self.marker.token.as_str()) {
                *active = None;
            }
        });
    }
}

impl Drop for Maintenance {
    fn drop(&mut self) {
        self.clear_active();
    }
}

pub(crate) fn current_boot_token() -> Option<String> {
    ACTIVE.with(|slot| slot.borrow().clone())
}

/// Durable journal writes are internal to the shared coordinators and inherit
/// the marker writer's private mode, bound, CAS and namespace sync semantics.
pub(crate) fn write_recovery(path: &Path, bytes: &[u8], expected: Option<&str>) -> Result<()> {
    let (root, _) = selected_roots()?;
    anyhow::ensure!(
        path.starts_with(root.join("runtime/autostart"))
            && !path
                .components()
                .any(|part| part == std::path::Component::ParentDir),
        "recovery journal escapes this installation's control directory"
    );
    private_write(path, bytes, expected)
}

pub(crate) fn marker_path(root: &Path) -> PathBuf {
    root.join("runtime/autostart/maintenance.json")
}

fn selected_roots() -> Result<(PathBuf, PathBuf)> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    Ok((root.canonicalize()?, profile.canonicalize()?))
}

fn verify_selection(root: &Path, profile: &Path) -> Result<()> {
    let (actual_root, actual_profile) = selected_roots()?;
    anyhow::ensure!(
        actual_root == root && actual_profile == profile,
        "maintenance installation or selected profile changed"
    );
    Ok(())
}

fn parse_marker(bytes: &[u8]) -> Result<Marker> {
    let value: Marker =
        serde_json::from_slice(bytes).context("invalid runtime maintenance marker")?;
    anyhow::ensure!(
        value.schema == 1
            && uuid::Uuid::parse_str(&value.token).is_ok()
            && value.owner_pid > 0
            && !value.owner_birth.is_empty()
            && !value.id.is_empty()
            && !value.expected_version.is_empty(),
        "invalid runtime maintenance marker"
    );
    Ok(value)
}

fn controller_alive(value: &Marker) -> Result<bool> {
    Ok(process_birth(value.owner_pid)?.as_deref() == Some(value.owner_birth.as_str()))
}

fn ensure_exact_owner(actual: &Marker, held: &Marker, bytes: &[u8], digest: &str) -> Result<()> {
    anyhow::ensure!(
        actual == held
            && actual.owner_pid == std::process::id()
            && current_boot_token().as_deref() == Some(held.token.as_str())
            && hash(bytes) == digest
            && controller_alive(actual)?,
        "maintenance owner, phase, process birth or exact marker digest changed"
    );
    Ok(())
}

fn ensure_purpose(purpose: LaunchPurpose, phase: Phase) -> Result<()> {
    anyhow::ensure!(
        match purpose {
            LaunchPurpose::Account => phase == Phase::Paused,
            LaunchPurpose::AccountComplete => phase == Phase::Verified,
            LaunchPurpose::Serving => matches!(phase, Phase::Starting | Phase::Verified),
        },
        "maintenance phase does not authorize this launch role"
    );
    Ok(())
}

fn validate_registration_mode(root: &Path, mode: &RegistrationMode) -> Result<()> {
    let path = root.join("runtime/autostart/registration.json");
    if matches!(mode, RegistrationMode::Unregistered) {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!("existing registration cannot be treated as unregistered"),
        }
    } else {
        let bytes = private_io::bounded_bytes(&path, 64 * 1024)?
            .context("registered maintenance owner disappeared")?;
        let value: Value = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            value["id"].as_str() == Some(mode.coordinator_id(root).as_str())
                && value["installation"].as_str().map(Path::new) == Some(root),
            "observed registration does not match its maintenance owner"
        );
    }
    Ok(())
}

fn ensure_registration(
    host: &dyn HostLifecycle,
    root: &Path,
    expected: &RegistrationMode,
) -> Result<()> {
    let actual = host.inspect_registration(root)?;
    validate_registration_mode(root, &actual)?;
    anyhow::ensure!(
        &actual == expected,
        "maintenance startup registration changed"
    );
    Ok(())
}

fn ensure_no_owner(host: &dyn HostLifecycle) -> Result<()> {
    anyhow::ensure!(
        host.probe_runtime()?.is_none() && !host.endpoint_path().try_exists()?,
        "account control blocked: runtime owner or locator has no completed drain proof"
    );
    Ok(())
}

fn verify_health_roots(health: &Health, root: &Path, profile: &Path) -> Result<()> {
    anyhow::ensure!(
        health.pid > 0
            && !health.data_dir.is_empty()
            && !health.installation_root.is_empty()
            && Path::new(&health.data_dir).canonicalize()? == profile
            && Path::new(&health.installation_root).canonicalize()? == root
            && health.installation_id == hash(root.display().to_string().as_bytes()),
        "runtime owner roots or installation identity do not match maintenance"
    );
    Ok(())
}

/// Match the observed old image, never the selected replacement image. An
/// upgrade may legitimately drain a different Runtime version and executable.
fn verify_observed_process(
    health: &Health,
    process: &respire_commands::net_rpc::RuntimeProcessIdentity,
    image_sha256: &str,
) -> Result<()> {
    let executable = Path::new(&process.executable).canonicalize()?;
    anyhow::ensure!(
        health.pid > 0
            && health.v == crate::PROTOCOL_V
            && !health.instance_id.is_empty()
            && !health.account_id.is_empty()
            && health.generation > 0
            && !health.runtime_version.is_empty()
            && health.image_sha256.len() == 64
            && health
                .image_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && Path::new(&health.image_path).canonicalize()? == executable
            && Path::new(&health.exe).canonicalize()? == executable
            && process_start_matches(&process.started_at, &health.process_start_id)
            && health.image_sha256.eq_ignore_ascii_case(image_sha256),
        "observed Runtime process, image digest or typed stop scope changed"
    );
    Ok(())
}

fn process_start_matches(birth: &str, start_id: &str) -> bool {
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    !birth.is_empty() && start_id.strip_prefix(prefix) == Some(birth)
}

fn ensure_applied(receipt: &HostAuthAccountResult) -> Result<()> {
    anyhow::ensure!(
        matches!(
            receipt.outcome,
            HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Committed
        ),
        "account verification requires an applied candidate receipt"
    );
    Ok(())
}

fn receipt_target(receipt: &HostAuthAccountResult) -> Result<PathBuf> {
    let target = receipt
        .target_profile
        .as_deref()
        .context("account target is missing")?;
    respire_client_host::config::normalize_control_path(target)?
        .canonicalize()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests;

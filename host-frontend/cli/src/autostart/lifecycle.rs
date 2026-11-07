//! One host lifecycle owner. A durable maintenance marker fences queued/direct
//! requests until the replacement store has been verified; failure stays paused.
use super::{
    control_path, disabled_status, hash, identity, manager, private_write, read_registration,
    AutostartCommand, Platform, Registration, RuntimeCommand, ENVIRONMENT,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};

mod snapshot_control;
pub(crate) use snapshot_control::{snapshot_recover_control, snapshot_restore_control};
// Runtime snapshot authority must use this limit; its generic reader caps at 64 KiB.
pub(super) const MAINTENANCE_MARKER_MAX_BYTES: usize = 16 * 1024;

static MANAGED_ID: OnceLock<String> = OnceLock::new();
static CREDENTIAL_STATE: AtomicU8 = AtomicU8::new(0);
thread_local! {
    static ACTIVE: RefCell<Option<String>> = const { RefCell::new(None) };
    static RECOVERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) enum Phase {
    Paused,
    Starting,
    Verified,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    snapshot: Option<snapshot_control::SnapshotMarkerBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_config: Option<Value>,
}

fn marker_path(root: &Path) -> PathBuf {
    control_path(root).with_file_name("maintenance.json")
}
fn marker_bytes(root: &Path) -> Result<Option<Vec<u8>>> {
    let path = marker_path(root);
    let meta = match fs::symlink_metadata(&path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    anyhow::ensure!(
        meta.is_file() && !meta.file_type().is_symlink()
            && meta.len() <= MAINTENANCE_MARKER_MAX_BYTES as u64,
        "invalid runtime maintenance marker"
    );
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(MAINTENANCE_MARKER_MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= MAINTENANCE_MARKER_MAX_BYTES, "runtime maintenance marker too large");
    Ok(Some(bytes))
}
fn marker(root: &Path) -> Result<Option<Marker>> {
    let Some(bytes) = marker_bytes(root)? else { return Ok(None); };
    let value: Marker = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        value.schema == 1 && uuid::Uuid::parse_str(&value.token).is_ok(),
        "invalid runtime maintenance marker"
    );
    Ok(Some(value))
}

fn controller_alive(value: &Marker) -> Result<bool> {
    Ok(manager::process_birth(value.owner_pid)?.as_deref() == Some(value.owner_birth.as_str()))
}

pub(super) fn save(config: &mut Registration) -> Result<()> {
    let path = control_path(&config.installation);
    let bytes = serde_json::to_vec_pretty(config)?;
    let result = private_write(&path, &bytes, config.digest.as_deref());
    // Namespace fsync can fail after publication. Preserve the observed identity
    // while propagating that error; the separate maintenance marker stays put.
    if fs::read(&path).is_ok_and(|actual| actual == bytes) {
        config.digest = Some(hash(&bytes));
    }
    result
}

pub(super) fn ensure_control_endpoint(config: &Registration) -> Result<()> {
    let registered = config
        .environment
        .get("RSRS_RPC_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .context("registered runtime port is missing or invalid")?;
    anyhow::ensure!(registered==crate::net_rpc::rpc_port(),
        "host port differs from registered runtime port {registered}; use the registered RSRS_RPC_PORT to stop/remove the old registration before enabling new settings");
    Ok(())
}

pub(super) fn owned(config: &Registration) -> Result<()> {
    anyhow::ensure!(
        config.owner == manager::owner()?,
        "runtime registration belongs to another OS user"
    );
    let bin = config
        .environment
        .get("RSRS_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| config.installation.join("bin"));
    let expected = bin.join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" });
    anyhow::ensure!(
        config.executable == expected,
        "runtime registration has an unexpected executable"
    );
    Ok(())
}

pub(crate) fn note_credential_access(available: bool) {
    CREDENTIAL_STATE.store(if available { 1 } else { 2 }, Ordering::Release);
}
pub(crate) fn credential_state() -> &'static str {
    match CREDENTIAL_STATE.load(Ordering::Acquire) {
        1 => "ready",
        2 => "unavailable",
        _ => "unknown",
    }
}
pub(crate) fn managed_enabled() -> Result<bool> {
    Ok(read_registration(&respire_client_host::paths::main_data_dir())?.is_some_and(|config| config.enabled))
}
pub(crate) fn record_exit(success: bool) {
    if managed_id().is_some() {
        if let Ok(Some(config)) = read_registration(&respire_client_host::paths::main_data_dir()) {
            if event(&config, if success { "exit_ok" } else { "exit_error" }).is_err() {
                eprintln!("Managed runtime event could not be recorded.");
            }
        }
    }
}

pub(crate) fn managed_id() -> Option<&'static str> {
    MANAGED_ID.get().map(String::as_str)
}
pub(crate) fn current_boot_token() -> Option<String> {
    ACTIVE.with(|v| v.borrow().clone())
}

pub(crate) fn check_direct_access() -> Result<()> {
    let root = respire_client_host::paths::main_data_dir();
    if let Some(value) = marker(&root)? {
        anyhow::ensure!(ACTIVE.with(|v|v.borrow().as_deref()==Some(value.token.as_str())),
            "runtime maintenance is incomplete; use the host runtime restart or the indicated snapshot/login recovery before accessing the library");
    }
    Ok(())
}

pub(crate) fn check_managed_request() -> Result<()> {
    check_direct_access()
}

pub(crate) fn verify_managed_boot() -> Result<()> {
    let root = respire_client_host::paths::main_data_dir();
    let config = read_registration(&root)?;
    if let Some(id) = managed_id() {
        let config = config
            .as_ref()
            .context("managed runtime registration disappeared")?;
        anyhow::ensure!(
            config.id == id && config.enabled && !config.manually_stopped,
            "managed runtime startup is disabled or manually stopped"
        );
    }
    if let Some(value) = marker(&root)? {
        anyhow::ensure!(
            controller_alive(&value)?,
            "maintenance controller exited; explicit host runtime restart is required"
        );
        let token = std::env::var("RSRS_RUNTIME_BOOT_TOKEN").ok();
        let permitted = managed_id() == Some(value.id.as_str())
            || token.as_deref() == Some(value.token.as_str());
        anyhow::ensure!(
            permitted && matches!(value.phase, Phase::Starting | Phase::Verified),
            "runtime maintenance has not authorized a replacement process"
        );
        anyhow::ensure!(
            value.expected_version == env!("CARGO_PKG_VERSION")
                && value.expected_profile.as_deref()
                    == Some(respire_client_host::config::control_roots()?.1.canonicalize()?.as_path()),
            "replacement runtime version/profile differs from maintenance plan"
        );
    }
    Ok(())
}

pub(crate) struct Maintenance {
    installation: Option<PathBuf>,
    config: Option<Registration>,
    marker: Option<Marker>,
    marker_digest: Option<String>,
    completed: bool,
}

impl Maintenance {
    fn inactive() -> Self {
        Self {
            installation: None,
            config: None,
            marker: None,
            marker_digest: None,
            completed: true,
        }
    }

    fn begin(mut config: Registration, recover: bool) -> Result<Self> {
        owned(&config)?;
        ensure_control_endpoint(&config)?;
        let registration = manager::inspect(&config)?;
        anyhow::ensure!(
            !registration.registered || config.artifact_hashes.contains_key("service"),
            "unknown existing startup registration; no lifecycle action taken"
        );
        let previous = marker(&config.installation)?;
        anyhow::ensure!(
            previous.is_none() || recover,
            "interrupted runtime maintenance; use runtime restart on the host"
        );
        let previous_digest = if previous.is_some() {
            Some(hash(&fs::read(marker_path(&config.installation))?))
        } else {
            None
        };
        let value = Marker {
            schema: 1,
            id: config.id.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            phase: Phase::Paused,
            expected_profile: None,
            expected_version: env!("CARGO_PKG_VERSION").into(),
            owner_pid: std::process::id(),
            owner_birth: manager::process_birth(std::process::id())?
                .context("controller process identity unavailable")?,
            snapshot: None,
            agent_config: None,
        };
        if let Some(previous) = previous {
            anyhow::ensure!(
                previous.id == config.id,
                "maintenance belongs to another runtime registration"
            );
        }
        let bytes = serde_json::to_vec(&value)?;
        private_write(
            &marker_path(&config.installation),
            &bytes,
            previous_digest.as_deref(),
        )?;
        config.maintenance = true;
        save(&mut config)?;
        ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
        Ok(Self {
            installation: Some(config.installation.clone()),
            config: Some(config),
            marker: Some(value),
            marker_digest: Some(hash(&bytes)),
            completed: false,
        })
    }

    fn installation_root(&self) -> Result<&Path> {
        self.installation.as_deref().context("maintenance installation is unavailable")
    }

    fn begin_local(root: PathBuf, config: Option<Registration>, recover: bool) -> Result<Self> {
        let id = if let Some(config) = config.as_ref() {
            owned(config)?;
            anyhow::ensure!(config.installation == root, "maintenance installation changed");
            config.id.clone()
        } else {
            format!("host-{}", hash(root.display().to_string().as_bytes()))
        };
        let previous = marker(&root)?;
        anyhow::ensure!(previous.is_none() || recover,
            "interrupted host maintenance; query the original operation before starting another write");
        if let Some(previous) = previous.as_ref() {
            anyhow::ensure!(previous.id == id, "maintenance belongs to another installation coordinator");
        }
        let previous_digest = previous.as_ref().map(|_| fs::read(marker_path(&root)))
            .transpose()?.map(|bytes| hash(&bytes));
        let value = Marker {
            schema: 1, id, token: uuid::Uuid::new_v4().to_string(), phase: Phase::Paused,
            expected_profile: None, expected_version: env!("CARGO_PKG_VERSION").into(),
            owner_pid: std::process::id(), owner_birth: manager::process_birth(std::process::id())?
                .context("controller process identity unavailable")?,
            snapshot: None,
            agent_config: None,
        };
        let bytes = serde_json::to_vec(&value)?;
        private_write(&marker_path(&root), &bytes, previous_digest.as_deref())?;
        ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
        // Local maintenance never owns or changes the optional OS service registration.
        Ok(Self { installation: Some(root), config: None, marker: Some(value),
            marker_digest: Some(hash(&bytes)), completed: false })
    }

    pub(super) fn mark(&mut self, phase: Phase) -> Result<()> {
        let Some(root) = self.installation.as_ref() else {
            return Ok(());
        };
        let actual = fs::read(marker_path(root))?;
        let current: Marker = serde_json::from_slice(&actual)?;
        let value = self
            .marker
            .as_mut()
            .context("maintenance marker unavailable")?;
        anyhow::ensure!(
            current.id == value.id && current.token == value.token
                && current.agent_config == value.agent_config,
            "maintenance owner changed before phase transition"
        );
        value.phase = phase;
        if matches!(phase, Phase::Starting | Phase::Verified) {
            value.expected_profile = Some(respire_client_host::config::control_roots()?.1.canonicalize()?);
        }
        let bytes = serde_json::to_vec(value)?;
        anyhow::ensure!(bytes.len() <= MAINTENANCE_MARKER_MAX_BYTES, "runtime maintenance marker too large");
        private_write(
            &marker_path(root),
            &bytes,
            Some(&hash(&actual)),
        )?;
        self.marker_digest = Some(hash(&bytes));
        Ok(())
    }

    /// Bind the stopped owner's actual Paused marker without authorizing serving.
    pub(crate) fn auth_launch_binding(&mut self, profile: &Path) -> Result<Option<Value>> {
        let (root, selected) = respire_client_host::config::control_roots()?;
        let root = root.canonicalize()?;
        anyhow::ensure!(selected.canonicalize()? == profile,
            "auth maintenance profile differs from the selected profile");
        if self.installation.is_some() {
            anyhow::ensure!(self.installation_root()? == root, "auth maintenance installation changed");
            if let Some(config) = self.config.as_ref() {
                owned(config)?;
                anyhow::ensure!(config.installation == root, "auth maintenance installation changed");
            }
            let actual = marker(&root)?.context("auth maintenance marker is missing")?;
            let held = self.marker.as_ref().context("auth maintenance ownership is missing")?;
            anyhow::ensure!(actual.phase == Phase::Paused && held.phase == Phase::Paused
                && actual.id == held.id && actual.token == held.token
                && actual.owner_pid == std::process::id()
                && current_boot_token().as_deref() == Some(held.token.as_str())
                && hash(&fs::read(marker_path(&root))?) == self.marker_digest.as_deref()
                    .context("auth maintenance digest is missing")?,
                "auth maintenance owner or phase changed");
            self.marker.as_mut().context("auth maintenance ownership is missing")?
                .expected_profile = Some(profile.to_path_buf());
            self.mark(Phase::Paused)?;
        }
        maintenance_binding(profile, None, true)
    }

    pub(crate) fn save_agent_config(&mut self, record: &respire_protocol::config_control::AgentConfigMaintenance) -> Result<()> {
        let root = self.installation_root()?.to_path_buf();
        let actual = marker_bytes(&root)?.context("agent config maintenance missing")?;
        anyhow::ensure!(Some(hash(&actual)).as_deref() == self.marker_digest.as_deref(),
            "agent config maintenance changed");
        let held = self.marker.as_mut().context("agent config owner missing")?;
        anyhow::ensure!(held.phase == Phase::Paused && held.snapshot.is_none(), "agent config requires Paused maintenance");
        held.agent_config = Some(serde_json::to_value(record)?);
        let bytes = serde_json::to_vec(held)?;
        anyhow::ensure!(bytes.len() <= MAINTENANCE_MARKER_MAX_BYTES, "agent config exceeds maintenance record bound");
        private_write(&marker_path(&root), &bytes, Some(&hash(&actual)))?;
        self.marker_digest = Some(hash(&bytes));
        Ok(())
    }

    /// Runtime may add only the original operation's receipt, never change its owner or intent.
    pub(crate) fn refresh_agent_config(&mut self) -> Result<respire_protocol::config_control::AgentConfigMaintenance> {
        let root = self.installation_root()?;
        let bytes = marker_bytes(root)?.context("agent config maintenance missing")?;
        let actual: Marker = serde_json::from_slice(&bytes)?;
        let held = self.marker.as_ref().context("agent config owner missing")?;
        let previous: respire_protocol::config_control::AgentConfigMaintenance = serde_json::from_value(
            held.agent_config.clone().context("agent config review missing")?)?;
        let current: respire_protocol::config_control::AgentConfigMaintenance = serde_json::from_value(
            actual.agent_config.clone().context("agent config review disappeared")?)?;
        let mut expected = previous.clone();
        expected.receipt = current.receipt.clone();
        anyhow::ensure!(current == expected && current.receipt.as_ref().is_none_or(|receipt| receipt.review == previous.review)
            && previous.receipt.as_ref().is_none_or(|receipt| current.receipt.as_ref() == Some(receipt)),
            "agent config receipt changed its original operation");
        let mut expected_marker = held.clone();
        expected_marker.agent_config = actual.agent_config.clone();
        anyhow::ensure!(serde_json::to_value(&expected_marker)? == serde_json::to_value(&actual)?,
            "agent config maintenance owner changed");
        self.marker = Some(actual);
        self.marker_digest = Some(hash(&bytes));
        Ok(current)
    }

    pub(crate) fn drain_runtime(&self, health: &crate::net_rpc::Health) -> Result<()> {
        let Some(config) = self.config.as_ref() else {
            return crate::rpc::drain_occupant(health, Duration::from_secs(60));
        };
        owned(config)?;
        ensure_control_endpoint(config)?;
        manager::inspect(config)?;
        verify_owned_runtime(config, health)?;
        crate::rpc::drain_occupant(health, Duration::from_secs(60))?;
        // Finish stopping the supervisor before a profile change makes old health unavailable.
        stop_drained_supervisor(config)
    }

    /// Only an independently checked live target may advance an account transaction.
    pub(crate) fn start_account_target(
        &mut self, source: &Path, operation_id: &str,
        receipt: &respire_protocol::host_control::HostAuthAccountResult, register: bool,
    ) -> Result<()> {
        super::validate_auth_account_receipt(receipt, operation_id, source, register)?;
        self.start_account_runtime()?;
        self.account_target_verified(source, operation_id, receipt, register)
    }

    /// Both host lifecycle modes require the installed independent Runtime.
    pub(crate) fn check_account_runtime(&self) -> Result<()> {
        self.installation_root()?;
        let (binary, _) = super::supervise::installed_auth_runtime()?;
        if let Some(config) = self.config.as_ref() {
            owned(config)?;
            anyhow::ensure!(registered_runtime_image(config)? == binary
                && !config.environment.contains_key("GH_TOKEN")
                && !config.environment.contains_key("GITHUB_TOKEN"),
                "account startup requires the installed managed Runtime and nonsecret registration environment");
        } else if let Some(raw) = respire_client_host::env::var_os("RSRS_RUNTIME_BIN") {
            anyhow::ensure!(PathBuf::from(raw).canonicalize()? == binary,
                "account startup cannot select an override instead of the installed managed Runtime");
        }
        Ok(())
    }

    pub(crate) fn start_account_runtime(&mut self) -> Result<()> {
        self.check_account_runtime()?;
        self.mark(Phase::Starting)?;
        crate::rpc::ensure_daemon_locked()
    }

    pub(crate) fn resume_managed_runtime(&mut self) -> Result<()> {
        // begin_maintenance_locked keeps stopped or disabled registrations in local maintenance.
        if self.config.is_some() {
            self.start_account_runtime()?;
        }
        Ok(())
    }

    /// Only an independently checked live target may advance an account transaction.
    pub(crate) fn account_target_verified(
        &mut self, source: &Path, operation_id: &str,
        receipt: &respire_protocol::host_control::HostAuthAccountResult, register: bool,
    ) -> Result<()> {
        super::supervise::verify_account_target(receipt, operation_id, source, register)?;
        let root = self.installation_root()?.to_path_buf();
        if let Some(config) = self.config.as_ref() { owned(config)?; }
        let target = receipt.target_profile.as_ref().context("account target is missing")?;
        let target = respire_client_host::config::normalize_control_path(target)?.canonicalize()?;
        let path = marker_path(&root);
        let bytes = fs::read(&path)?;
        let mut actual = marker(&root)?.context("account maintenance marker is missing")?;
        let held = self.marker.as_ref().context("account maintenance ownership is missing")?;
        anyhow::ensure!(actual.id == held.id && actual.token == held.token
            && actual.owner_pid == std::process::id() && actual.owner_birth == held.owner_birth
            && current_boot_token().as_deref() == Some(held.token.as_str())
            && matches!(actual.phase, Phase::Starting | Phase::Verified)
            && actual.expected_profile.as_ref() == Some(&target)
            && actual.expected_version == env!("CARGO_PKG_VERSION") && controller_alive(&actual)?
            && serde_json::to_vec(&actual)? == serde_json::to_vec(&serde_json::from_slice::<Marker>(&bytes)?)?,
            "account target launch does not belong to this maintenance controller");
        actual.phase = Phase::Verified;
        let next = serde_json::to_vec(&actual)?;
        private_write(&path, &next, Some(&hash(&bytes)))?;
        self.marker = Some(actual);
        self.marker_digest = Some(hash(&next));
        Ok(())
    }

    /// Completion is a separate grant role. It never converts Paused/Starting into Verified.
    pub(crate) fn account_complete_launch_binding(
        &self, source: &Path, operation_id: &str,
        receipt: &respire_protocol::host_control::HostAuthAccountResult, register: bool,
    ) -> Result<Option<Value>> {
        super::validate_auth_account_receipt(receipt, operation_id, source, register)?;
        anyhow::ensure!(matches!(receipt.outcome,
            respire_protocol::host_control::HostAuthAccountOutcome::AwaitingVerification
                | respire_protocol::host_control::HostAuthAccountOutcome::Committed),
            "account completion requires an applied candidate receipt");
        let (root, selected) = respire_client_host::config::control_roots()?;
        let root = root.canonicalize()?;
        let target = receipt.target_profile.as_ref().context("account target is missing")?;
        let target = respire_client_host::config::normalize_control_path(target)?.canonicalize()?;
        anyhow::ensure!(self.installation_root()? == root, "account completion installation changed");
        if let Some(config) = self.config.as_ref() { owned(config)?; }
        let actual = marker(&root)?.context("account completion marker is missing")?;
        let held = self.marker.as_ref().context("account completion ownership is missing")?;
        anyhow::ensure!(selected.canonicalize()? == target,
            "account completion installation or selection changed");
        verified_account_marker(&actual, held, &target, &fs::read(marker_path(&root))?,
            self.marker_digest.as_deref().context("account completion marker digest is missing")?)?;
        maintenance_binding(&target, None, false)
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        if self.completed {
            return Ok(());
        }
        self.mark(Phase::Verified)?;
        if let Some(config) = self.config.as_mut() {
            config.maintenance = false;
            save(config)?;
        }
        let path = marker_path(self.installation_root()?);
        anyhow::ensure!(
            hash(&fs::read(&path)?)
                == self
                    .marker_digest
                    .as_deref()
                    .context("maintenance digest missing")?,
            "maintenance changed before completion"
        );
        fs::remove_file(&path)?;
        // Already verified, so a namespace-cleanup warning must never trigger a
        // later profile rollback after requests have been accepted.
        if respire_spawn::durable::sync_directory(
            path.parent().context("maintenance parent missing")?,
        )
        .is_err()
        {
            eprintln!("Runtime verified; maintenance namespace cleanup needs a later check.");
        }
        self.completed = true;
        ACTIVE.with(|slot| *slot.borrow_mut() = None);
        Ok(())
    }
}

impl Drop for Maintenance {
    fn drop(&mut self) {
        if self.installation.is_some() {
            ACTIVE.with(|slot| {
                let mut active = slot.borrow_mut();
                if active.as_deref() == self.marker.as_ref().map(|value| value.token.as_str()) {
                    *active = None;
                }
            });
        }
    }
}

pub(crate) fn begin_maintenance_locked() -> Result<Maintenance> {
    anyhow::ensure!(
        !ACTIVE.with(|v| v.borrow().is_some()),
        "host maintenance already has an active controller"
    );
    let (root, _) = respire_client_host::config::control_roots()?;
    fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    match read_registration(&root)? {
        Some(config) if config.enabled && !config.manually_stopped => {
            let guard = Maintenance::begin(config, RECOVERY.with(|v| v.get()))?;
            reset_attempts(
                guard
                    .config
                    .as_ref()
                    .context("maintenance registration missing")?,
            )?;
            Ok(guard)
        }
        config => Maintenance::begin_local(root, config, RECOVERY.with(|v| v.get())),
    }
}

/// Reattach only the original identity-write controller, retaining its stable token.
pub(crate) fn resume_identity_write_maintenance(
    root: &Path, profile: &Path, token: &str, coordinator: &str,
) -> Result<Maintenance> {
    resume_key_maintenance(root, profile, profile, token, coordinator)
}

/// A key receipt can move selection before its private response reaches CLI.
/// Keep the original token/controller checks, allowing only source or selection.
pub(crate) fn resume_key_maintenance(
    root: &Path, profile: &Path, source: &Path, token: &str, coordinator: &str,
) -> Result<Maintenance> {
    resume_key_maintenance_inner(root, profile, source, token, coordinator, false)
}

pub(crate) fn pending_agent_config(root: &Path) -> Result<Option<(respire_protocol::config_control::AgentConfigMaintenance, String, String)>> {
    let Some(marker) = marker(root)? else { return Ok(None); };
    let record = marker.agent_config.context("finish existing maintenance before agent config")?;
    Ok(Some((serde_json::from_value(record)?, marker.token, marker.id)))
}

pub(crate) fn resume_agent_config_maintenance(root: &Path, profile: &Path, token: &str, coordinator: &str) -> Result<Maintenance> {
    resume_key_maintenance_inner(root, profile, profile, token, coordinator, true)
}

fn resume_key_maintenance_inner(root: &Path, profile: &Path, source: &Path, token: &str, coordinator: &str,
    agent_config: bool) -> Result<Maintenance> {
    anyhow::ensure!(current_boot_token().is_none(), "host maintenance already has a controller");
    let (selected_root, selected_profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(selected_root.canonicalize()? == root && selected_profile.canonicalize()? == profile,
        "identity recovery selection changed");
    let previous = marker_bytes(root)?;
    let mut registration = read_registration(root)?;
    if let Some(config) = registration.as_ref() {
        owned(config)?;
        anyhow::ensure!(config.installation == root && config.id == coordinator, "identity recovery registration changed");
        ensure_control_endpoint(config)?;
    } else {
        anyhow::ensure!(coordinator == format!("host-{}", hash(root.display().to_string().as_bytes())),
            "identity recovery coordinator changed");
    }
    let previous_marker = marker(root)?;
    if let Some(value) = previous_marker.as_ref() {
        anyhow::ensure!(value.token == token && value.id == coordinator && value.snapshot.is_none()
            && value.agent_config.is_some() == agent_config
            && matches!(value.expected_profile.as_deref(), Some(expected) if expected == profile || expected == source)
            && value.expected_version == env!("CARGO_PKG_VERSION")
            && (!controller_alive(value)? || value.owner_pid == std::process::id()),
            "identity recovery does not own the existing maintenance marker");
    }
    let value = Marker { schema: 1, id: coordinator.to_owned(), token: token.to_owned(), phase: Phase::Paused,
        expected_profile: Some(profile.to_path_buf()), expected_version: env!("CARGO_PKG_VERSION").into(),
        owner_pid: std::process::id(), owner_birth: manager::process_birth(std::process::id())?
            .context("identity recovery controller birth unavailable")?, snapshot: None,
        agent_config: previous_marker.and_then(|value| value.agent_config) };
    let bytes = serde_json::to_vec(&value)?;
    private_write(&marker_path(root), &bytes, previous.as_ref().map(|bytes| hash(bytes)).as_deref())?;
    let mut config = registration.take().filter(|config| config.enabled && !config.manually_stopped);
    if let Some(config) = config.as_mut() { config.maintenance = true; save(config)?; }
    ACTIVE.with(|slot| *slot.borrow_mut() = Some(token.to_owned()));
    Ok(Maintenance { installation: Some(root.to_path_buf()), config, marker: Some(value),
        marker_digest: Some(hash(&bytes)), completed: false })
}

/// Explicit host restart is the recovery operation for an interrupted transition.
/// The caller holds the same installation takeover lock as profile changes.
pub(crate) fn restart_maintenance_locked() -> Result<Maintenance> {
    crate::runtime_fetch::require_automatic_migration_safe()?;
    let Some(config) = read_registration(&respire_client_host::paths::main_data_dir())? else {
        return with_explicit_recovery(begin_maintenance_locked);
    };
    let mut guard = Maintenance::begin(config, true)?;
    let config = guard
        .config
        .as_mut()
        .context("restart registration missing")?;
    config.manually_stopped = false;
    save(config)?;
    reset_attempts(config)?;
    Ok(guard)
}

/// Legacy detached mode may be used after an explicitly disabled registration.
/// It still needs the active controller's phase/token before opening the store.
pub(crate) fn authorize_detached_boot_locked() -> Result<()> {
    let Some(token) = current_boot_token() else {
        return Ok(());
    };
    let (root, profile) = respire_client_host::config::control_roots()?;
    let Some(mut value) = marker(&root)? else {
        bail!("active maintenance marker missing");
    };
    anyhow::ensure!(value.token == token, "maintenance owner changed");
    let path = marker_path(&root);
    let previous = fs::read(&path)?;
    value.phase = Phase::Starting;
    value.expected_profile = Some(profile.canonicalize()?);
    private_write(&path, &serde_json::to_vec(&value)?, Some(&hash(&previous)))
}

/// Export only an authorization binding; never forward the reusable maintenance token.
fn verified_account_marker(actual: &Marker, held: &Marker, target: &Path, bytes: &[u8], digest: &str) -> Result<()> {
    anyhow::ensure!(actual.phase == Phase::Verified && held.phase == Phase::Verified
        && actual.id == held.id && actual.token == held.token
        && actual.owner_pid == std::process::id() && actual.owner_birth == held.owner_birth
        && actual.expected_profile.as_deref() == Some(target)
        && current_boot_token().as_deref() == Some(held.token.as_str())
        && hash(bytes) == digest,
        "account completion requires this controller's exact Verified marker");
    Ok(())
}

/// Export only an authorization binding; never forward the reusable maintenance token.
pub(super) fn launch_maintenance_binding(profile: &Path, managed_id: Option<&str>) -> Result<Option<Value>> {
    maintenance_binding(profile, managed_id, false)
}

fn maintenance_binding(profile: &Path, managed_id: Option<&str>, auth: bool) -> Result<Option<Value>> {
    let root = respire_client_host::paths::main_data_dir();
    let Some(value) = marker(&root)? else {
        return Ok(None);
    };
    let bytes = fs::read(marker_path(&root))?;
    let observed: Marker = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid runtime maintenance authorization"))?;
    let managed_authorized = if let Some(id) = managed_id {
        let config = read_registration(&root)?.context("managed launch registration is missing")?;
        owned(&config)?;
        anyhow::ensure!(
            std::env::current_exe()?.canonicalize()? == config.executable.canonicalize()?,
            "managed launch controller differs from the registered CLI"
        );
        config.id == id && value.id == id && config.enabled && !config.manually_stopped
    } else {
        false
    };
    anyhow::ensure!(
        serde_json::to_vec(&observed)? == serde_json::to_vec(&value)?
            && (managed_authorized || current_boot_token().as_deref() == Some(value.token.as_str()))
            && if auth { value.phase == Phase::Paused }
                else { matches!(value.phase, Phase::Starting | Phase::Verified) }
            && value.expected_profile.as_deref() == Some(profile)
            && value.expected_version == env!("CARGO_PKG_VERSION")
            && controller_alive(&value)?,
        "runtime maintenance does not authorize the selected launch"
    );
    Ok(Some(json!({
        "marker_sha256": hash(&bytes),
        "coordinator_id": value.id,
        "controller_pid": value.owner_pid,
        "controller_birth": value.owner_birth,
        "issuer_cli_version": value.expected_version,
    })))
}

pub(crate) fn background_paused() -> bool {
    // Malformed/unreadable control state also fences background mutations.
    !matches!(marker(&respire_client_host::paths::main_data_dir()), Ok(None))
}

pub(crate) fn with_explicit_recovery<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            RECOVERY.with(|v| v.set(self.0));
        }
    }
    let _reset = Reset(RECOVERY.with(|v| v.replace(true)));
    action()
}

pub(crate) fn coordinate_materialization() -> Result<Option<PathBuf>> {
    crate::runtime_fetch::require_automatic_migration_safe()?;
    if current_boot_token().is_some() {
        return Ok(None);
    }
    let root = respire_client_host::paths::main_data_dir();
    let Some(config) = read_registration(&root)?.filter(|c| c.enabled) else {
        return Ok(None);
    };
    let _ownership = crate::runtime_policy::takeover_lock()?;
    owned(&config)?;
    let was_running = crate::rpc::probe_runtime()?.is_some();
    let mut guard = Maintenance::begin(config, false)?;
    reset_attempts(guard.config.as_ref().context("registration missing")?)?;
    raw_stop_owned(guard.config.as_ref().context("registration missing")?)?;
    let executable = crate::mcp::materialize_bin().map_err(anyhow::Error::msg)?;
    if was_running {
        start_candidate(&mut guard)?;
    }
    guard.finish()?;
    Ok(Some(executable))
}

pub(super) fn registered_runtime_image(config: &Registration) -> Result<PathBuf> {
    let root = config.installation.canonicalize()?;
    let registered_root = PathBuf::from(
        config
            .environment
            .get("RSRS_DATA_DIR")
            .context("registered runtime root is missing")?,
    );
    anyhow::ensure!(
        registered_root.canonicalize()? == root
            && respire_client_host::paths::main_data_dir().canonicalize()? == root,
        "registered runtime root belongs to another installation"
    );
    // The registered supervisor clears runtime overrides before selecting its child.
    let accepted = crate::runtime_fetch::read_manifest()?
        .is_some_and(|manifest| crate::runtime_fetch::version_in_accept(&manifest.version));
    let runtime =
        if let Some(managed) = crate::runtime_fetch::managed_runtime_path()?.filter(|_| accepted) {
            managed
        } else {
            config
                .executable
                .parent()
                .context("supervisor executable parent missing")?
                .join(crate::runtime_fetch::RUNTIME_BINARY)
        };
    let runtime = runtime
        .canonicalize()
        .context("selected Runtime is unavailable")?;
    anyhow::ensure!(runtime.is_file(), "selected Runtime is not a file");
    Ok(runtime)
}

pub(super) fn verify_owned_runtime(config: &Registration, health: &crate::net_rpc::Health) -> Result<String> {
    let root = config.installation.canonicalize()?;
    let runtime = registered_runtime_image(config)?;
    anyhow::ensure!(
        runtime != config.executable.canonicalize()?
            && runtime != std::env::current_exe()?.canonicalize()?
            && crate::mcp::exe_matches_dest(&health.exe, &runtime)
            && crate::mcp::exe_matches_dest(&health.image_path, &runtime)
            && !health.data_dir.is_empty()
            && Path::new(&health.data_dir).canonicalize()? == respire_client_host::config::control_roots()?.1.canonicalize()?
            && !health.installation_root.is_empty()
            && Path::new(&health.installation_root).canonicalize()? == root
            && health.installation_id == hash(root.display().to_string().as_bytes())
            && health.managed_id.as_deref() == Some(config.id.as_str())
            && health.pid > 0,
        "runtime identity/profile does not match this startup registration; no lifecycle action taken"
    );
    let birth =
        manager::process_birth(health.pid)?.context("owned runtime process already exited")?;
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    anyhow::ensure!(
        health.process_start_id == format!("{prefix}{birth}"),
        "owned runtime process birth does not match health"
    );
    Ok(birth)
}

fn raw_stop_owned(config: &Registration) -> Result<()> {
    owned(config)?;
    ensure_control_endpoint(config)?;
    let manager_state = manager::inspect(config)?;
    // A closed listener can still belong to a draining child in the supervisor's job.
    let Some(health) = crate::rpc::probe_runtime()
        .context("owned runtime health is unavailable; manager stop is blocked")?
    else {
        anyhow::ensure!(
            !manager_state.running && !crate::rpc::endpoint_path().exists(),
            "owned runtime has no verifiable health/drain proof; manager stop is blocked"
        );
        return Ok(());
    };
    verify_owned_runtime(config, &health)?;
    crate::rpc::drain_occupant(&health, Duration::from_secs(60))?;
    stop_drained_supervisor(config)
}

// Call only after drain_occupant has verified the child's final receipt and exit.
pub(super) fn stop_drained_supervisor(config: &Registration) -> Result<()> {
    manager::stop(config)?;
    anyhow::ensure!(
        !manager::inspect(config)?.running && !crate::rpc::endpoint_path().try_exists()?,
        "drained runtime supervisor is still active or its endpoint changed; replacement is blocked"
    );
    Ok(())
}

pub(super) fn wait_ready(config: &Registration) -> Result<()> {
    owned(config)?;
    manager::inspect(config)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if let Some(health) = crate::rpc::probe_runtime()? {
            verify_owned_runtime(config, &health)?;
            anyhow::ensure!(
                crate::runtime_fetch::version_in_accept(&health.runtime_version),
                "managed runtime version mismatch"
            );
            if health.store_ready || respire_client_host::settings::off_mode()? {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("owned runtime did not confirm store readiness; maintenance remains paused")
}

fn start_candidate(guard: &mut Maintenance) -> Result<()> {
    let config = guard
        .config
        .as_ref()
        .context("managed registration missing")?;
    anyhow::ensure!(
        config.executable == crate::mcp::stable_bin_path(),
        "service executable differs from host configuration; explicitly reconfigure startup first"
    );
    let executable = crate::mcp::materialize_bin().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        executable == config.executable,
        "managed native path changed unexpectedly"
    );
    let current = manager::inspect(config)?;
    anyhow::ensure!(current.registered,"startup registration is missing; upgrade never registers it automatically; run runtime autostart enable explicitly");
    guard.mark(Phase::Starting)?;
    manager::start(
        guard
            .config
            .as_ref()
            .context("managed registration missing")?,
    )?;
    wait_ready(
        guard
            .config
            .as_ref()
            .context("managed registration missing")?,
    )
}

pub(crate) fn may_reuse_runtime(health: &crate::net_rpc::Health) -> Result<bool> {
    if background_paused() {
        return Ok(false);
    }
    match read_registration(&respire_client_host::paths::main_data_dir())? {
        Some(config) if config.enabled => Ok(
            !config.manually_stopped && health.managed_id.as_deref() == Some(config.id.as_str())
        ),
        _ => Ok(true),
    }
}

pub(crate) fn ensure_managed_locked() -> Result<bool> {
    let Some(config) = read_registration(&respire_client_host::paths::main_data_dir())? else {
        return Ok(false);
    };
    if !config.enabled {
        return Ok(false);
    }
    owned(&config)?;
    if config.manually_stopped {
        if let Some(token) = current_boot_token() {
            let value = marker(&config.installation)?.context("manual account maintenance marker is missing")?;
            anyhow::ensure!(value.id == config.id && value.token == token
                && value.owner_pid == std::process::id() && controller_alive(&value)?
                && matches!(value.phase, Phase::Starting | Phase::Verified),
                "manual detached launch lacks this host controller's startup authority");
            // A foreground maintenance helper may verify a target without enabling the service.
            return Ok(false);
        }
    }
    anyhow::ensure!(
        !config.manually_stopped,
        "runtime was manually stopped; use runtime start explicitly"
    );
    crate::runtime_fetch::require_automatic_migration_safe()?;
    if ACTIVE.with(|v| v.borrow().is_some()) {
        let value = marker(&config.installation)?.context("active maintenance marker missing")?;
        let digest = hash(&fs::read(marker_path(&config.installation))?);
        let mut borrowed = Maintenance {
            installation: Some(config.installation.clone()),
            config: Some(config),
            marker: Some(value),
            marker_digest: Some(digest),
            completed: true,
        };
        let result = (|| {
            raw_stop_owned(borrowed.config.as_ref().context("registration missing")?)?;
            start_candidate(&mut borrowed)
        })();
        // This borrowed guard does not own completion or its caller's token.
        borrowed.config = None;
        borrowed.installation = None;
        result?;
        return Ok(true);
    }
    check_direct_access()?;
    if let Some(health) = crate::rpc::probe_runtime()? {
        if crate::rpc::runtime_acceptable(&health)?
            && health.managed_id.as_deref() == Some(config.id.as_str())
        {
            return Ok(true);
        }
    }
    let mut guard = Maintenance::begin(config, false)?;
    raw_stop_owned(guard.config.as_ref().context("registration missing")?)?;
    start_candidate(&mut guard)?;
    guard.finish()?;
    Ok(true)
}

fn start_explicit_locked() -> Result<()> {
    crate::runtime_fetch::require_automatic_migration_safe()?;
    let root = respire_client_host::paths::main_data_dir();
    let Some(mut config) = read_registration(&root)? else {
        return crate::rpc::ensure_daemon_locked();
    };
    owned(&config)?;
    manager::inspect(&config)?;
    check_direct_access()?;
    if !config.enabled {
        ensure_control_endpoint(&config)?;
        // Explicit start clears the stop flag without re-enabling sign-in startup.
        if config.manually_stopped {
            config.manually_stopped = false;
            save(&mut config)?;
        }
        return crate::rpc::ensure_daemon_locked();
    }
    if !config.manually_stopped {
        if let Some(health) = crate::rpc::probe_runtime()? {
            if health.managed_id.as_deref() == Some(config.id.as_str())
                && crate::rpc::runtime_acceptable(&health)?
            {
                reset_attempts(&config)?;
                return Ok(());
            }
        }
    }
    // Fence OS-triggered launches before clearing the persistent stop flag.
    let mut guard = Maintenance::begin(config, false)?;
    let config = guard
        .config
        .as_mut()
        .context("start registration missing")?;
    config.manually_stopped = false;
    save(config)?;
    reset_attempts(config)?;
    raw_stop_owned(guard.config.as_ref().context("registration missing")?)?;
    start_candidate(&mut guard)?;
    guard.finish()
}

pub(crate) fn stop_managed_locked() -> Result<bool> {
    let Some(mut config) = read_registration(&respire_client_host::paths::main_data_dir())? else {
        return Ok(false);
    };
    if !config.enabled {
        return Ok(false);
    }
    owned(&config)?;
    manager::inspect(&config)?;
    ensure_control_endpoint(&config)?;
    config.manually_stopped = true;
    save(&mut config)?;
    let mut guard = Maintenance::begin(config, false)?;
    raw_stop_owned(
        guard
            .config
            .as_ref()
            .context("managed registration missing")?,
    )?;
    guard.finish()?;
    Ok(true)
}

fn new_registration() -> Result<Registration> {
    let root = respire_client_host::paths::main_data_dir();
    let environment_root = if root.is_absolute() {
        root.clone()
    } else {
        std::env::current_dir()?.join(&root)
    };
    fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let owner = manager::owner()?;
    let executable = crate::mcp::stable_bin_path();
    let home = dirs::home_dir()
        .context("current-user home unavailable")?
        .canonicalize()?;
    let mut environment = BTreeMap::new();
    for &key in ENVIRONMENT {
        if let Ok(value) = respire::env::var(key) {
            super::plain_value(&value)?;
            environment.insert(key.into(), value);
        }
    }
    environment.insert(
        "RSRS_DATA_DIR".into(),
        environment_root
            .to_str()
            .context("non-UTF8 installation")?
            .into(),
    );
    environment.insert(
        "RSRS_BIN_DIR".into(),
        executable
            .parent()
            .context("native executable parent missing")?
            .to_str()
            .context("non-UTF8 native directory")?
            .into(),
    );
    environment.insert(
        "RSRS_RPC_PORT".into(),
        crate::net_rpc::rpc_port().to_string(),
    );
    Ok(Registration {
        schema: 1,
        platform: Platform::current()?,
        id: identity(&root, &owner),
        installation: root,
        executable,
        user_home: home,
        owner,
        enabled: false,
        manually_stopped: false,
        maintenance: false,
        environment,
        artifact_hashes: BTreeMap::new(),
        digest: None,
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Attempts {
    schema: u32,
    id: String,
    starts: Vec<u64>,
}

fn attempts_path(root: &Path) -> PathBuf {
    control_path(root).with_file_name("launch-attempts.json")
}
fn read_attempts(config: &Registration) -> Result<(Attempts, Option<String>)> {
    let path = attempts_path(&config.installation);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                Attempts {
                    schema: 1,
                    id: config.id.clone(),
                    starts: Vec::new(),
                },
                None,
            ))
        }
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 4096,
        "invalid runtime launch budget"
    );
    let bytes = fs::read(path)?;
    let value: Attempts = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        value.schema == 1 && value.id == config.id && value.starts.len() <= 3,
        "runtime launch budget belongs to an unknown registration"
    );
    Ok((value, Some(hash(&bytes))))
}
fn record_attempt(config: &Registration, now: u64) -> Result<bool> {
    let (mut attempts, digest) = read_attempts(config)?;
    attempts
        .starts
        .retain(|started| now.saturating_sub(*started) < 120);
    if attempts.starts.len() >= 3 {
        return Ok(false);
    }
    attempts.starts.push(now);
    private_write(
        &attempts_path(&config.installation),
        &serde_json::to_vec(&attempts)?,
        digest.as_deref(),
    )?;
    Ok(true)
}
pub(super) fn reset_attempts(config: &Registration) -> Result<()> {
    let (mut attempts, digest) = read_attempts(config)?;
    attempts.starts.clear();
    private_write(
        &attempts_path(&config.installation),
        &serde_json::to_vec(&attempts)?,
        digest.as_deref(),
    )?;
    manager::reset_backoff(config)
}
fn now_seconds() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
/// Best-effort fixed stages help diagnose a stalled explicit restart without
/// exporting arguments, account data or raw OS errors. Never weaken a fence if
/// its diagnostic file cannot be updated.
pub(crate) fn restart_stage(name: &str) {
    if let Ok(Some(config)) = read_registration(&respire_client_host::paths::main_data_dir()) {
        let _ = event(&config, name);
    }
}

/// Supervisor events reuse the fixed lifecycle event names so the diagnostic
/// file stays bounded and never captures free-form text.
pub(super) fn record_supervise_event(config: &Registration, name: &str) {
    if let Err(error) = event(config, name) {
        eprintln!("supervisor event could not be recorded: {error}");
    }
}

fn event(config: &Registration, name: &str) -> Result<()> {
    // Fixed event names only. Never serialize command arguments, errors,
    // environment values, account identifiers or recovery material.
    anyhow::ensure!(
        [
            "starting",
            "paused",
            "crash_limit",
            "exit_ok",
            "exit_error",
            "restart_probe",
            "restart_managed",
            "restart_identity",
            "restart_stop",
            "restart_start",
            "restart_ready"
        ]
        .contains(&name),
        "unknown runtime event"
    );
    let path = control_path(&config.installation).with_file_name("events.jsonl");
    let previous = match fs::symlink_metadata(&path) {
        Ok(meta) => {
            anyhow::ensure!(
                meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 65536,
                "invalid runtime event file"
            );
            Some(fs::read(&path)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut bytes = previous.clone().unwrap_or_default();
    let mut line = serde_json::to_vec(
        &json!({"schema":1,"id":config.id,"pid":std::process::id(),"version":env!("CARGO_PKG_VERSION"),"time":now_seconds()?,"event":name}),
    )?;
    line.push(b'\n');
    if bytes.len() + line.len() > 65536 {
        let backup = path.with_file_name("events.previous.jsonl");
        let prior_backup = match fs::symlink_metadata(&backup) {
            Ok(meta) => {
                anyhow::ensure!(
                    meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 65536,
                    "invalid runtime event backup"
                );
                Some(fs::read(&backup)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        private_write(
            &backup,
            &bytes,
            prior_backup.as_ref().map(|v| hash(v)).as_deref(),
        )?;
        bytes.clear();
    }
    bytes.extend(line);
    private_write(&path, &bytes, previous.as_ref().map(|v| hash(v)).as_deref())
}

fn status() -> Result<Value> {
    let mut value = disabled_status()?;
    let root = respire_client_host::paths::main_data_dir();
    if let Some(config) = read_registration(&root)? {
        owned(&config)?;
        let actual = manager::inspect(&config)?;
        value["registered"] = json!(actual.registered);
        value["enabled"] = json!(config.enabled && actual.enabled);
        value["registration"] = serde_json::to_value(actual)?;
        value["maintenance"] = json!(marker(&root)?.is_some());
    }
    match crate::rpc::probe_runtime() {
        Ok(Some(health)) => {
            if health.installation_root.is_empty()
                || !crate::mcp::same_path(Path::new(&health.installation_root), &root)
            {
                value["runtime"] = json!({"running":null,"state":if health.installation_root.is_empty() {"legacy_identity_unavailable"} else {"another_installation"},"version":health.bin});
                return Ok(value);
            }
            value["runtime"] = json!({"running":true,"pid":health.pid,"version":health.bin,"data_dir":health.data_dir,"store_ready":health.store_ready,"inference":health.inference,"credential_state":if health.credential_state.is_empty() {"unknown"} else {health.credential_state.as_str()},"network_state":"not_probed"});
        }
        Ok(None) => value["runtime"] = json!({"running":false}),
        Err(_) => value["runtime"] = json!({"running":null,"state":"unreachable_or_unverified"}),
    }
    Ok(value)
}

fn emit(command: &str, summary: Value) -> Result<()> {
    crate::emit_result(crate::output::ResultEnvelope::new(
        command,
        crate::OutputStatus::Ok,
        summary,
        Vec::new(),
    ))
}

pub(crate) fn execute(command: &RuntimeCommand) -> Result<()> {
    match command {
        RuntimeCommand::KeyResult { operation_id } => {
            return crate::emit_result(super::control_key_result(operation_id)?);
        }
        RuntimeCommand::KeyRollback { operation_id, confirm } => {
            anyhow::ensure!(*confirm, "key rollback requires explicit --confirm");
            return crate::emit_result(super::control_key_rollback(operation_id)?);
        }
        RuntimeCommand::AuthResult { operation_id, force } => {
            return crate::emit_result(super::control_auth_result(operation_id, *force)?);
        }
        RuntimeCommand::AccountResult { operation_id, source_profile, register } => {
            return crate::emit_result(super::control_account_result(
                operation_id, source_profile, *register,
            )?);
        }
        RuntimeCommand::AccountRollback { operation_id, source_profile, register, confirm } => {
            anyhow::ensure!(*confirm, "account rollback requires explicit --confirm");
            return crate::emit_result(super::control_account_rollback(
                operation_id, source_profile, *register,
            )?);
        }
        _ => {}
    }
    if let RuntimeCommand::Result { context } = command {
        let response: crate::rpc::RpcResponse =
            serde_json::from_value(crate::net_rpc::rpc_result(context)?)
                .context("invalid runtime.result response")?;
        if let Some(code @ ("scope_required" | "scope_mismatch")) = response.code.as_deref() {
            bail!(
                "{code}: {}",
                response
                    .error
                    .as_deref()
                    .unwrap_or("runtime.result scope rejected")
            );
        }
        if let Some(envelope) = response.envelope {
            crate::emit_result(envelope)?;
            crate::set_exit_code(response.exit);
            return Ok(());
        }
        bail!(
            "{}",
            response
                .error
                .unwrap_or_else(|| "runtime.result returned an empty response".to_owned())
        );
    }
    if matches!(
        command,
        RuntimeCommand::Status
            | RuntimeCommand::Autostart {
                command: AutostartCommand::Status
            }
    ) {
        return emit("runtime.autostart.status", status()?);
    }
    crate::runtime_policy::require_host("runtime lifecycle")?;
    match command {
        RuntimeCommand::Run {
            managed,
            installation_root,
            supervised_child,
        } => run_foreground(
            managed.as_deref(),
            installation_root.as_deref(),
            *supervised_child,
        ),
        RuntimeCommand::Stop => {
            let stopped = crate::rpc::probe_runtime()?;
            crate::rpc::stop_if_running()?;
            let result = match stopped {
                Some(health) => crate::net_rpc::final_stop_receipt(&health, None)?,
                None => json!({"state":"stopped", "already_stopped":true}),
            };
            emit("runtime.stop", result)
        }
        RuntimeCommand::Restart => {
            let value = crate::rpc::restart_runtime(Duration::from_secs(10))?;
            emit("runtime.restart", value)
        }
        RuntimeCommand::Start => {
            crate::runtime_fetch::require_automatic_migration_safe()?;
            let _ownership = crate::runtime_policy::takeover_lock()?;
            start_explicit_locked()?;
            emit("runtime.start", status()?)
        }
        RuntimeCommand::Autostart {
            command: AutostartCommand::Enable { now },
        } => enable(*now),
        RuntimeCommand::Autostart {
            command: AutostartCommand::Disable { stop },
        } => disable(*stop, false),
        RuntimeCommand::Autostart {
            command: AutostartCommand::Remove { stop },
        } => disable(*stop, true),
        RuntimeCommand::Install {
            file,
            version,
            mirror,
        } => install_runtime(file.as_deref(), version.as_deref(), mirror.as_deref()),
        RuntimeCommand::List => emit("runtime.list", runtime_inventory()?),
        RuntimeCommand::Clean => {
            let removed = crate::runtime_fetch::clean_old()?;
            emit("runtime.clean", json!({"removed": removed}))
        }
        RuntimeCommand::Update => {
            let binary = crate::runtime_fetch::download_and_install(None, None)?;
            emit(
                "runtime.update",
                json!({"version": crate::runtime_fetch::pinned()?.required.clone(), "binary": binary}),
            )
        }
        RuntimeCommand::Supervise { data_dir } => {
            return super::supervise::supervise(data_dir);
        }
        RuntimeCommand::KeyResult { .. }
        | RuntimeCommand::KeyRollback { .. }
        | RuntimeCommand::AuthResult { .. }
        | RuntimeCommand::AccountResult { .. }
        | RuntimeCommand::AccountRollback { .. } => {
            bail!("authentication recovery command was not handled before lifecycle setup")
        }
        _ => bail!("unsupported runtime lifecycle command"),
    }
}

/// `runtime install`: pinned download by default, or an offline archive with
/// `--file`/`--version`, with an optional explicit `--mirror` origin.
fn install_runtime(file: Option<&Path>, version: Option<&str>, mirror: Option<&str>) -> Result<()> {
    match (file, version) {
        (Some(archive), Some(explicit_version)) => {
            anyhow::ensure!(mirror.is_none(), "--mirror is only accepted for downloads");
            let binary = crate::runtime_fetch::install_from_file(archive, explicit_version)?;
            emit(
                "runtime.install",
                json!({"source":"file","version":explicit_version,"binary":binary}),
            )
        }
        (Some(_), None) => bail!("--file requires --version"),
        (None, Some(_)) => bail!("--version is only accepted together with --file"),
        (None, None) => {
            if let Some(origin) = mirror {
                respire_commands::model_download::validate_mirror(origin)?;
            }
            let binary = crate::runtime_fetch::download_and_install(None, mirror)?;
            emit(
                "runtime.install",
                json!({"source":"download","version":crate::runtime_fetch::pinned()?.required.clone(),"binary":binary}),
            )
        }
    }
}

fn runtime_inventory() -> Result<Value> {
    let pin = crate::runtime_fetch::pinned()?;
    let installed = crate::runtime_fetch::list_installed()?;
    let versions: Vec<Value> = installed
        .iter()
        .map(
            |entry| json!({"version": entry.version, "path": entry.path, "current": entry.current}),
        )
        .collect();
    Ok(json!({
        "required": pin.required.clone(),
        "accept": pin.accept_raw.clone(),
        "installed": versions,
    }))
}

fn enable(now: bool) -> Result<()> {
    crate::runtime_fetch::require_automatic_migration_safe()?;
    // A platform-rejected native path must not even create lifecycle state.
    manager::validate_executable(Platform::current()?, &crate::mcp::stable_bin_path())?;
    let _ownership = crate::runtime_policy::takeover_lock()?;
    // Resolve before creating the registration: otherwise our new registration
    // would look like an unbound legacy owner to the materialization preflight.
    crate::rpc::resolve_runtime_executable()?;
    anyhow::ensure!(crate::runtime_fetch::managed_runtime_path()?.is_some(),
        "autostart requires a verified managed Runtime before registration; install the trusted release first");
    let mut config = match read_registration(&respire_client_host::paths::main_data_dir())? {
        Some(config) if !config.enabled && config.artifact_hashes.is_empty() => {
            owned(&config)?;
            anyhow::ensure!(
                !manager::inspect(&config)?.registered,
                "unknown remaining registration; refusing reconfiguration"
            );
            let mut fresh = new_registration()?;
            fresh.digest = config.digest;
            fresh
        }
        Some(config) => config,
        None => new_registration()?,
    };
    owned(&config)?;
    manager::inspect(&config)?;
    config.manually_stopped = false;
    let was_running = crate::rpc::probe_runtime()?.is_some();
    let mut guard = Maintenance::begin(config, false)?;
    let install = (|| -> Result<()> {
        raw_stop_owned(guard.config.as_ref().context("registration missing")?)?;
        crate::mcp::materialize_bin().map_err(anyhow::Error::msg)?;
        let config = guard.config.as_mut().context("registration missing")?;
        manager::install(config)?;
        reset_attempts(config)?;
        config.enabled = true;
        save(config)?;
        if now || was_running {
            start_candidate(&mut guard)?;
        }
        Ok(())
    })();
    if let Err(error) = install {
        if let Some(config) = guard.config.as_mut() {
            config.enabled = false;
            if let Err(save_error) = save(config) {
                return Err(error.context(format!("startup remains paused: {save_error}")));
            }
        }
        return Err(error.context("startup registration did not complete; runtime maintenance remains paused for explicit host recovery"));
    }
    guard.finish()?;
    emit("runtime.autostart.enable", status()?)
}

fn disable(stop: bool, remove: bool) -> Result<()> {
    let command = if remove {
        "runtime.autostart.remove"
    } else {
        "runtime.autostart.disable"
    };
    if read_registration(&respire_client_host::paths::main_data_dir())?.is_none() {
        return emit(command, status()?);
    }
    let _ownership = crate::runtime_policy::takeover_lock()?;
    let Some(mut config) = read_registration(&respire_client_host::paths::main_data_dir())? else {
        return emit(command, status()?);
    };
    owned(&config)?;
    let actual = manager::inspect(&config)?;
    anyhow::ensure!(
        !remove || stop || marker(&config.installation)?.is_none(),
        "interrupted maintenance requires remove --stop or explicit host runtime restart"
    );
    anyhow::ensure!(
        !remove || stop || !actual.running,
        "stop the owned runtime before removing its startup registration"
    );
    if stop {
        ensure_control_endpoint(&config)?;
        config.manually_stopped = true;
        save(&mut config)?;
        let mut guard = Maintenance::begin(config, true)?;
        raw_stop_owned(guard.config.as_ref().context("registration missing")?)?;
        guard.finish()?;
        config = read_registration(&respire_client_host::paths::main_data_dir())?
            .context("registration disappeared")?;
    }
    config.enabled = false;
    save(&mut config)?;
    manager::disable(&config)?;
    if remove {
        manager::remove(&config)?;
        config.artifact_hashes.clear();
        save(&mut config)?;
    }
    emit(
        if remove {
            "runtime.autostart.remove"
        } else {
            "runtime.autostart.disable"
        },
        status()?,
    )
}

fn run_foreground(id: Option<&str>, root: Option<&Path>, supervised_child: bool) -> Result<()> {
    anyhow::ensure!(
        !supervised_child || (cfg!(windows) && id.is_some()),
        "supervised-child requires a Windows managed registration"
    );
    if let Some(id) = id {
        let root = root.context("managed runtime needs its explicit installation root")?;
        let config = read_registration(root)?.context("managed runtime registration missing")?;
        owned(&config)?;
        anyhow::ensure!(config.id == id, "managed runtime identity mismatch");
        if !config.enabled || config.manually_stopped {
            return Ok(());
        }
        anyhow::ensure!(
            crate::mcp::same_path(&std::env::current_exe()?, &config.executable),
            "managed startup must use the configured stable native executable"
        );
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(|key| {
                key.starts_with("RSRS_")
                    || key.starts_with("ONEMEMORY_")
                    || key.starts_with("RESPIRE_")
            }) {
                std::env::remove_var(key);
            }
        }
        for (key, value) in &config.environment {
            std::env::set_var(key, value);
        }
        std::env::set_var("HOME", &config.user_home);
        std::env::set_var("USERPROFILE", &config.user_home);
        #[cfg(windows)]
        if !supervised_child {
            return supervise_windows_runtime(&config);
        }
        if let Some(value) = marker(&config.installation)? {
            if value.phase == Phase::Paused || !controller_alive(&value)? {
                event(&config, "paused")?;
                return Ok(());
            }
        }
        if !record_attempt(&config, now_seconds()?)? {
            event(&config, "crash_limit")?;
            return Ok(());
        }
        event(&config, "starting")?;
        MANAGED_ID
            .set(id.to_owned())
            .map_err(|_| anyhow::anyhow!("managed runtime already initialized"))?;
    } else {
        anyhow::ensure!(
            root.is_none(),
            "installation-root is only accepted for a managed registration"
        );
        anyhow::ensure!(!read_registration(&respire_client_host::paths::main_data_dir())?.is_some_and(|config|config.enabled),"the service manager owns this runtime; use runtime start instead of an unmanaged foreground instance");
        check_direct_access()?;
    }
    verify_managed_boot()?;
    let stopped = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
    }
    let binary = crate::rpc::resolve_runtime_executable()?.canonicalize()?;
    let image_sha256 = hash(&fs::read(&binary)?);
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "serve".into(),
        "--data-dir".into(),
        respire_client_host::paths::main_data_dir().into_os_string(),
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        crate::net_rpc::rpc_port().to_string().into(),
    ];
    if managed_id().is_some() {
        arguments.push("--supervised".into());
    }
    let (mut child, instance_id) =
        super::supervise::spawn_authorized_runtime(&binary, &arguments, managed_id())?;
    let pid = child.id();
    let birth = manager::process_birth(pid)?;
    let mut drain: Option<std::thread::JoinHandle<Result<()>>> = None;
    let mut drain_requested = false;
    let result = (|| -> Result<()> {
        loop {
            if let Some(status) = child.try_wait().context("cannot reap foreground Runtime")? {
                if let Some(drain) = drain.take() {
                    drain.join().map_err(|_| anyhow::anyhow!("Runtime drain thread panicked"))??;
                }
                crate::set_exit_code(status.code().unwrap_or(1));
                return Ok(());
            }
            if drain.as_ref().is_some_and(|drain| drain.is_finished()) {
                if let Some(drain) = drain.take() {
                    drain.join().map_err(|_| anyhow::anyhow!("Runtime drain thread panicked"))??;
                }
            }
            if stopped.load(Ordering::Acquire) && !drain_requested {
                drain_requested = true;
                let binary = binary.clone();
                let image_sha256 = image_sha256.clone();
                let instance_id = instance_id.clone();
                let birth = birth.clone();
                // Reap on this thread while drain verifies process exit and the final receipt.
                drain = Some(std::thread::spawn(move || -> Result<()> {
                    let birth = birth.context("foreground Runtime exited before its birth was captured")?;
                    let deadline = Instant::now() + Duration::from_secs(10);
                    let health = loop {
                        if let Some(health) = crate::rpc::probe_runtime()? {
                            break health;
                        }
                        anyhow::ensure!(
                            Instant::now() < deadline,
                            "foreground Runtime has no verifiable health; no process was forced to exit"
                        );
                        std::thread::sleep(Duration::from_millis(50));
                    };
                    let process = crate::net_rpc::runtime_process_identity(pid)?;
                    anyhow::ensure!(
                        health.pid == pid
                            && health.instance_id == instance_id
                            && crate::mcp::exe_matches_dest(&process.executable, &binary)
                            && (process.started_at == birth || process.started_at == health.process_start_id)
                            && manager::process_birth(pid)?.as_deref() == Some(birth.as_str())
                            && crate::mcp::exe_matches_dest(&health.exe, &binary)
                            && crate::mcp::exe_matches_dest(&health.image_path, &binary)
                            && health.image_sha256.eq_ignore_ascii_case(&image_sha256)
                            && health.managed_id.as_deref() == managed_id(),
                        "foreground Runtime ownership changed; no drain requested"
                    );
                    crate::rpc::drain_occupant(&health, Duration::from_secs(120))
                }));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    if managed_id().is_some() {
        let config = read_registration(&respire_client_host::paths::main_data_dir())?
            .context("managed runtime registration disappeared")?;
        event(
            &config,
            if result.is_ok() {
                "exit_ok"
            } else {
                "exit_error"
            },
        )?;
    }
    result
}

#[cfg(any(windows, test))]
fn retry_supervised_child(failures: &mut u8, uptime: Duration) -> bool {
    if uptime >= Duration::from_secs(120) {
        *failures = 0;
    }
    *failures = failures.saturating_add(1);
    *failures < 3
}

#[cfg(windows)]
fn supervisor_may_run(expected: &Registration) -> Result<bool> {
    let current = read_registration(&expected.installation)?
        .context("supervised registration disappeared")?;
    anyhow::ensure!(
        current.id == expected.id
            && current.owner == expected.owner
            && current.executable == expected.executable,
        "supervised registration identity changed"
    );
    if !current.enabled || current.manually_stopped {
        return Ok(false);
    }
    if let Some(value) = marker(&expected.installation)? {
        return Ok(value.phase != Phase::Paused
            && controller_alive(&value)?
            && value.id == expected.id
            && value.expected_version == env!("CARGO_PKG_VERSION"));
    }
    Ok(true)
}

#[cfg(windows)]
fn supervise_windows_runtime(config: &Registration) -> Result<()> {
    // Task Scheduler remains the current-user logon owner, but does not
    // reliably retry terminated Exec actions. Keep its action in the foreground
    // and supervise a foreground child; never open the library in this parent.
    respire_spawn::confine_supervisor_tree()
        .context("cannot establish owned supervisor process tree")?;
    let mut failures = 0;
    loop {
        if !supervisor_may_run(config)? {
            return Ok(());
        }
        let mut command = std::process::Command::new(&config.executable);
        command
            .args([
                "runtime",
                "run",
                "--managed",
                &config.id,
                "--installation-root",
            ])
            .arg(&config.installation)
            .arg("--supervised-child")
            .env_remove("RSRS_RUNTIME_BOOT_TOKEN")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let started = Instant::now();
        let status = match respire_spawn::spawn_host_control(&mut command) {
            Ok(mut child) => Some(
                child
                    .wait()
                    .context("cannot confirm owned runtime child exit")?,
            ),
            Err(_) => None,
        };
        if status.is_some_and(|status| status.success()) {
            return Ok(());
        }
        event(config, "exit_error")?;
        if !supervisor_may_run(config)? {
            return Ok(());
        }
        if !retry_supervised_child(&mut failures, started.elapsed()) {
            event(config, "crash_limit")?;
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if !supervisor_may_run(config)? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreground_supervisor_retries_are_bounded_and_reset_only_after_stability() -> Result<()> {
        let mut failures = 0;
        assert!(retry_supervised_child(
            &mut failures,
            Duration::from_secs(1)
        ));
        assert!(retry_supervised_child(
            &mut failures,
            Duration::from_secs(1)
        ));
        assert!(!retry_supervised_child(
            &mut failures,
            Duration::from_secs(1)
        ));
        assert!(retry_supervised_child(
            &mut failures,
            Duration::from_secs(120)
        ));
        assert_eq!(failures, 1);
        Ok(())
    }

    #[test]
    fn registration_captures_nonsecret_opt_outs_and_legacy_names_canonically() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.0 {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
        let keys = [
            "RSRS_DATA_DIR",
            "RSRS_BIN_DIR",
            "RSRS_NO_AUTOSYNC",
            "ONEMEMORY_NO_AUTOSYNC",
            "RSRS_UPDATE_CHECK",
        ];
        let _restore = Restore(
            keys.into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
        );
        let root = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", root.path());
        std::env::set_var("RSRS_BIN_DIR", root.path().join("bin"));
        std::env::remove_var("RSRS_NO_AUTOSYNC");
        std::env::set_var("ONEMEMORY_NO_AUTOSYNC", "1");
        std::env::set_var("RSRS_UPDATE_CHECK", "0");
        let config = new_registration()?;
        anyhow::ensure!(
            config
                .environment
                .get("RSRS_NO_AUTOSYNC")
                .map(String::as_str)
                == Some("1")
        );
        anyhow::ensure!(
            config
                .environment
                .get("RSRS_UPDATE_CHECK")
                .map(String::as_str)
                == Some("0")
        );
        anyhow::ensure!(!config
            .environment
            .keys()
            .any(|key| key.starts_with("ONEMEMORY_")));
        anyhow::ensure!(
            !control_path(root.path()).exists(),
            "capturing settings registered startup"
        );
        Ok(())
    }

    #[test]
    fn every_unfinished_phase_fences_requests_and_background_work() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE.with(|slot| *slot.borrow_mut() = None);
                match &self.0 {
                    Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
                    None => std::env::remove_var("RSRS_DATA_DIR"),
                }
                match &self.1 {
                    Some(v) => std::env::set_var("RSRS_RUNTIME_BOOT_TOKEN", v),
                    None => std::env::remove_var("RSRS_RUNTIME_BOOT_TOKEN"),
                }
            }
        }
        let _restore = Restore(
            std::env::var_os("RSRS_DATA_DIR"),
            std::env::var_os("RSRS_RUNTIME_BOOT_TOKEN"),
        );
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        anyhow::ensure!(!background_paused());
        for phase in [Phase::Paused, Phase::Starting, Phase::Verified] {
            let mut value = Marker {
                schema: 1,
                id: "synthetic-installation".into(),
                token: uuid::Uuid::new_v4().to_string(),
                phase,
                expected_profile: Some(dir.path().canonicalize()?),
                expected_version: env!("CARGO_PKG_VERSION").into(),
                owner_pid: std::process::id(),
                owner_birth: manager::process_birth(std::process::id())?
                    .context("test process birth missing")?,
                snapshot: None,
                agent_config: None,
            };
            let path = marker_path(&respire_client_host::paths::main_data_dir());
            fs::create_dir_all(path.parent().context("test marker parent")?)?;
            fs::write(&path, serde_json::to_vec(&value)?)?;
            anyhow::ensure!(controller_alive(&value)?);
            anyhow::ensure!(background_paused() && check_direct_access().is_err());
            ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
            check_direct_access()?;
            let profile = dir.path().canonicalize()?;
            let bytes = fs::read(&path)?;
            let authorized = verified_account_marker(&value, &value, &profile, &bytes, &hash(&bytes));
            assert_eq!(authorized.is_ok(), phase == Phase::Verified);
            if phase == Phase::Verified {
                assert!(verified_account_marker(&value, &value, &profile.join("foreign"), &bytes, &hash(&bytes)).is_err());
                assert!(verified_account_marker(&value, &value, &profile, &bytes, &hash(b"changed marker")).is_err());
                let mut foreign = value.clone(); foreign.token = uuid::Uuid::new_v4().to_string();
                assert!(verified_account_marker(&value, &foreign, &profile, &bytes, &hash(&bytes)).is_err());
            }
            if phase == Phase::Paused {
                let binding = maintenance_binding(&profile, None, true)?
                    .context("paused auth binding missing")?;
                anyhow::ensure!(binding["marker_sha256"] == hash(&fs::read(&path)?));
                anyhow::ensure!(launch_maintenance_binding(&profile, None).is_err());
                anyhow::ensure!(maintenance_binding(&profile.join("foreign"), None, true).is_err());
            } else {
                anyhow::ensure!(maintenance_binding(&profile, None, true).is_err());
                anyhow::ensure!(launch_maintenance_binding(&profile, None)?.is_some());
            }
            // Owning the controller token never authorizes background threads.
            anyhow::ensure!(background_paused());
            std::env::set_var("RSRS_RUNTIME_BOOT_TOKEN", &value.token);
            if phase == Phase::Paused {
                anyhow::ensure!(verify_managed_boot().is_err());
            } else {
                verify_managed_boot()?;
                std::env::set_var("RSRS_RUNTIME_BOOT_TOKEN", "foreign-controller");
                anyhow::ensure!(verify_managed_boot().is_err());
                std::env::set_var("RSRS_RUNTIME_BOOT_TOKEN", &value.token);
                let mut wrong = value.clone();
                wrong.expected_version.push_str("-foreign");
                fs::write(&path, serde_json::to_vec(&wrong)?)?;
                anyhow::ensure!(verify_managed_boot().is_err());
                wrong = value.clone();
                wrong.expected_profile = Some(dir.path().join("other-profile"));
                fs::write(&path, serde_json::to_vec(&wrong)?)?;
                anyhow::ensure!(verify_managed_boot().is_err());
            }
            ACTIVE.with(|slot| *slot.borrow_mut() = None);
            value.owner_birth.push_str("-reused-pid");
            fs::write(&path, serde_json::to_vec(&value)?)?;
            anyhow::ensure!(!controller_alive(&value)?);
            anyhow::ensure!(verify_managed_boot().is_err());
            fs::remove_file(path)?;
        }
        let path = marker_path(&respire_client_host::paths::main_data_dir());
        fs::write(&path, b"malformed")?;
        anyhow::ensure!(background_paused() && check_direct_access().is_err());
        fs::remove_file(path)?;
        anyhow::ensure!(!background_paused());
        check_direct_access()?;
        let root = dir.path().canonicalize()?;
        let mut local = begin_maintenance_locked()?;
        assert_eq!(local.installation_root()?, root);
        assert!(local.config.is_none() && !control_path(&root).exists());
        let first = marker(&root)?.context("local Paused marker missing")?;
        assert_eq!(first.phase, Phase::Paused);
        assert!(!first.id.is_empty());
        assert_eq!(local.auth_launch_binding(&root)?.context("local auth binding missing")?["marker_sha256"],
            hash(&fs::read(marker_path(&root))?));
        local.mark(Phase::Starting)?;
        assert_eq!(marker(&root)?.context("local Starting marker missing")?.expected_profile.as_deref(), Some(root.as_path()));
        local.mark(Phase::Verified)?;
        assert_eq!(marker(&root)?.context("local Verified marker missing")?.phase, Phase::Verified);
        local.finish()?;
        assert!(!marker_path(&root).exists() && !control_path(&root).exists());
        let mut interrupted = begin_maintenance_locked()?;
        interrupted.auth_launch_binding(&root)?;
        let token = current_boot_token().context("local maintenance token missing")?;
        drop(local);
        assert_eq!(current_boot_token().as_deref(), Some(token.as_str()));
        let original = fs::read(marker_path(&root))?;
        drop(interrupted);
        assert!(background_paused() && current_boot_token().is_none());
        assert_eq!(fs::read(marker_path(&root))?, original);
        assert!(begin_maintenance_locked().is_err());
        let mut recovered = with_explicit_recovery(begin_maintenance_locked)?;
        recovered.auth_launch_binding(&root)?;
        let owned = fs::read(marker_path(&root))?;
        let mut foreign: Marker = serde_json::from_slice(&owned)?;
        foreign.token = uuid::Uuid::new_v4().to_string();
        fs::write(marker_path(&root), serde_json::to_vec(&foreign)?)?;
        assert!(recovered.finish().is_err() && marker_path(&root).exists());
        fs::write(marker_path(&root), owned)?;
        recovered.finish()?;
        let takeover = crate::runtime_policy::takeover_lock()?;
        for phase in [Phase::Paused, Phase::Starting, Phase::Verified] {
            use respire_protocol::maintenance_control::{LegacySnapshotRecoveryAction,
                LegacySnapshotRecoveryParams, LegacySnapshotRecoveryBinding, MAINTENANCE_CONTROL_SCHEMA_V};
            let mut maintenance = begin_maintenance_locked()?;
            let mut params = LegacySnapshotRecoveryParams {
                schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
                binding: respire_protocol::ControlBinding { installation_root: root.clone(),
                    profile: root.clone(), launch_id: uuid::Uuid::new_v4().to_string(),
                    expected_account_id: Some("a".repeat(64)) },
                recovery_operation_id: uuid::Uuid::new_v4().to_string(),
                request_fingerprint: String::new(), journal_sha256: "b".repeat(64),
                action: LegacySnapshotRecoveryAction::Query,
            };
            params.request_fingerprint = super::super::snapshot_control::legacy_fingerprint(&params)?;
            maintenance.marker.as_mut().context("test legacy marker missing")?.snapshot =
                Some(snapshot_control::SnapshotMarkerBinding {
                    operation_id: String::new(), request_fingerprint: String::new(),
                    sync_generation: 0, snapshot_id: String::new(), account_id: "a".repeat(64),
                    drained_birth: String::new(), drain: None, offline: None, verified_runtime: None,
                    legacy_recovery: Some(LegacySnapshotRecoveryBinding {
                        recovery_operation_id: params.recovery_operation_id.clone(),
                        request_fingerprint: params.request_fingerprint.clone(),
                        journal_sha256: params.journal_sha256.clone(), account_id: "a".repeat(64),
                    }),
                });
            maintenance.mark(phase)?;
            let original = fs::read(marker_path(&root))?;
            let mut foreign = params.clone();
            foreign.recovery_operation_id = uuid::Uuid::new_v4().to_string();
            foreign.request_fingerprint = super::super::snapshot_control::legacy_fingerprint(&foreign)?;
            assert!(maintenance.legacy_pause_for_query(&takeover, &foreign, None).is_err());
            let library = respire_client_host::lock::LibraryLock::acquire(&root, Duration::ZERO)?;
            assert!(maintenance.legacy_pause_for_query(&takeover, &params, None).is_err());
            assert_eq!(fs::read(marker_path(&root))?, original);
            drop(library);
            maintenance.legacy_pause_for_query(&takeover, &params, None)?;
            let paused = marker(&root)?.context("test legacy Paused marker missing")?;
            assert_eq!(paused.phase, Phase::Paused);
            assert_eq!(paused.snapshot.as_ref().and_then(|bound| bound.legacy_recovery.as_ref())
                .context("test legacy intent missing")?.recovery_operation_id, params.recovery_operation_id);
            assert!(paused.snapshot.as_ref().is_some_and(|bound| bound.offline.is_some()
                && bound.drain.is_none() && bound.verified_runtime.is_none()));
            assert!(background_paused());
            maintenance.finish()?;
        }
        drop(takeover);
        for (enabled, stopped) in [(false, false), (true, true)] {
            let mut config = super::super::tests::fixture(Platform::current()?);
            config.owner = manager::owner()?;
            config.installation = root.clone();
            config.id = identity(&root, &config.owner);
            config.executable = root.join("bin").join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" });
            config.environment.insert("RSRS_RPC_PORT".into(), crate::net_rpc::rpc_port().to_string());
            config.enabled = enabled;
            config.manually_stopped = stopped;
            let original = serde_json::to_vec(&config)?;
            private_write(&control_path(&root), &original, None)?;
            let mut manual = begin_maintenance_locked()?;
            assert!(manual.config.is_none());
            manual.auth_launch_binding(&root)?;
            manual.mark(Phase::Starting)?;
            assert!(!ensure_managed_locked()?);
            assert_eq!(fs::read(control_path(&root))?, original);
            manual.finish()?;
            assert_eq!(fs::read(control_path(&root))?, original);
            assert!(!marker_path(&root).exists());
            if stopped { assert!(ensure_managed_locked().is_err()); }
            fs::remove_file(control_path(&root))?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_autostart_resolves_before_registration_and_remains_installable() -> Result<()> {
        let _env = crate::runtime_fetch::runtime_fetch_tests::env_scope(&[
            "RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_CORE_TEST_MODE", "RSRS_RUNTIME_BIN",
            "ONEMEMORY_RUNTIME_BIN", "RESPIRE_RUNTIME_BIN", "RSRS_RPC_PORT", "HOME", "USERPROFILE",
        ])?;
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        fs::create_dir(root.join("home"))?;
        std::env::set_var("HOME", root.join("home"));
        std::env::set_var("USERPROFILE", root.join("home"));
        std::env::set_var("RSRS_DATA_DIR", &root);
        std::env::set_var("RSRS_BIN_DIR", root.join("bin"));
        std::env::set_var("RSRS_CORE_TEST_MODE", "1");
        for key in ["RSRS_RUNTIME_BIN", "ONEMEMORY_RUNTIME_BIN", "RESPIRE_RUNTIME_BIN"] {
            std::env::remove_var(key);
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std::env::set_var("RSRS_RPC_PORT", listener.local_addr()?.port().to_string());
        drop(listener);
        let error = enable(false).err().context("fresh hermetic download unexpectedly succeeded")?;
        anyhow::ensure!(format!("{error:#}").contains("runtime downloads are disabled"));
        anyhow::ensure!(!control_path(&root).exists() && !marker_path(&root).exists());
        anyhow::ensure!(!crate::mcp::stable_bin_path().exists());

        crate::runtime_fetch::runtime_fetch_tests::install_lifecycle_fixture()?;
        let config = new_registration()?;
        let (_manager, state) = manager::test_adapter::install(&config);
        enable(false)?;
        anyhow::ensure!(state.borrow().registered && state.borrow().enabled && !state.borrow().running);
        anyhow::ensure!(read_registration(&root)?.context("fresh registration missing")?.enabled);
        anyhow::ensure!(!marker_path(&root).exists());
        anyhow::ensure!(!crate::mcp::bin_needs_refresh(&std::env::current_exe()?, &config.executable)
            .map_err(anyhow::Error::msg)?);
        Ok(())
    }

    #[test]
    fn legacy_start_and_restart_reject_before_takeover_and_recheck_after_lock() -> Result<()> {
        let _env = crate::runtime_fetch::runtime_fetch_tests::env_scope(&[
            "RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_CORE_TEST_MODE",
        ])?;
        std::env::set_var("RSRS_CORE_TEST_MODE", "1");
        for command in [RuntimeCommand::Start, RuntimeCommand::Restart] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().canonicalize()?;
            std::env::set_var("RSRS_DATA_DIR", &root);
            std::env::set_var("RSRS_BIN_DIR", root.join("bin"));
            fs::write(root.join("session.json"), b"legacy session")?;
            let error = execute(&command).err().context("unbound legacy start was accepted")?;
            anyhow::ensure!(error.is::<crate::runtime_fetch::LegacyRuntimeMigrationRequired>());
            anyhow::ensure!(fs::read(root.join("session.json"))? == b"legacy session");
            anyhow::ensure!(!root.join("runtime").exists(), "rejection created takeover state");
            anyhow::ensure!(fs::read_dir(&root)?.count() == 1);
        }

        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        std::env::set_var("RSRS_DATA_DIR", &root);
        std::env::set_var("RSRS_BIN_DIR", root.join("bin"));
        crate::runtime_fetch::require_automatic_migration_safe()?;
        let _ownership = crate::runtime_policy::takeover_lock()?;
        // Model state appearing after initial admission. The lock is coordination
        // metadata and must not be removed as a cleanup response to this refusal.
        fs::write(root.join("session.json"), b"late legacy session")?;
        let error = start_explicit_locked().err().context("locked start skipped its second check")?;
        anyhow::ensure!(error.is::<crate::runtime_fetch::LegacyRuntimeMigrationRequired>());
        let error = restart_maintenance_locked().err().context("restart maintenance skipped its check")?;
        anyhow::ensure!(error.is::<crate::runtime_fetch::LegacyRuntimeMigrationRequired>());
        anyhow::ensure!(fs::read(root.join("session.json"))? == b"late legacy session");
        anyhow::ensure!(root.join("runtime/takeover/lock.db").is_file());
        anyhow::ensure!(!control_path(&root).exists() && !marker_path(&root).exists());
        anyhow::ensure!(!crate::runtime_fetch::manifest_path().exists());
        Ok(())
    }

    #[test]
    fn managed_launch_budget_is_bounded_persistent_and_registration_scoped() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = super::super::tests::fixture(Platform::current()?);
        config.installation = dir.path().canonicalize()?;
        anyhow::ensure!(record_attempt(&config, 100)?);
        anyhow::ensure!(record_attempt(&config, 101)?);
        anyhow::ensure!(record_attempt(&config, 102)?);
        anyhow::ensure!(!record_attempt(&config, 103)?);
        anyhow::ensure!(
            !record_attempt(&config, 99)?,
            "clock reversal must not reopen the budget"
        );
        anyhow::ensure!(record_attempt(&config, 222)?);
        let (value, _) = read_attempts(&config)?;
        anyhow::ensure!(value.starts == vec![222]);
        config.id = "another-installation".into();
        anyhow::ensure!(read_attempts(&config).is_err());
        Ok(())
    }

    #[test]
    fn lifecycle_events_are_bounded_fixed_fields_and_private() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = super::super::tests::fixture(Platform::current()?);
        config.installation = dir.path().canonicalize()?;
        event(&config, "starting")?;
        anyhow::ensure!(event(&config, "secret-error-message").is_err());
        let path = control_path(&config.installation).with_file_name("events.jsonl");
        let bytes = fs::read(&path)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(value.as_object().context("event object missing")?.len() == 6);
        anyhow::ensure!(value["event"] == "starting" && value["id"] == config.id);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(fs::metadata(&path)?.permissions().mode() & 0o777 == 0o600);
        }
        fs::write(&path, vec![b' '; 65500])?;
        event(&config, "exit_ok")?;
        anyhow::ensure!(fs::metadata(&path)?.len() < 1024);
        anyhow::ensure!(fs::metadata(path.with_file_name("events.previous.jsonl"))?.len() == 65500);
        let backup = path.with_file_name("events.previous.jsonl");
        let full = vec![b' '; 65500];
        fs::write(&path, &full)?;
        fs::write(&backup, b"previous rotation")?;
        event(&config, "exit_error")?;
        anyhow::ensure!(fs::read(&backup)? == full);
        fs::remove_file(&backup)?;
        fs::create_dir(&backup)?;
        fs::write(&path, &full)?;
        anyhow::ensure!(event(&config, "exit_ok").is_err() && fs::read(&path)? == full);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_restart_recovers_every_phase_and_clears_manual_stop() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Vec<(std::ffi::OsString, std::ffi::OsString)>);
        impl Restore {
            fn captures(key: &std::ffi::OsStr) -> bool {
                key.to_str().is_some_and(|key| {
                    matches!(key, "HOME" | "USERPROFILE")
                        || ["RSRS_", "ONEMEMORY_", "RESPIRE_"]
                            .iter()
                            .any(|prefix| key.starts_with(prefix))
                })
            }
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE.with(|slot| *slot.borrow_mut() = None);
                for (key, _) in std::env::vars_os().filter(|(key, _)| Self::captures(key)) {
                    std::env::remove_var(key);
                }
                for (key, value) in &self.0 {
                    std::env::set_var(key, value);
                }
            }
        }
        let _restore = Restore(std::env::vars_os().filter(|(key, _)| Restore::captures(key)).collect());
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        std::env::set_var("RSRS_DATA_DIR", &root);
        std::env::set_var("RSRS_BIN_DIR", root.join("bin"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std::env::set_var("RSRS_RPC_PORT", listener.local_addr()?.port().to_string());
        drop(listener);
        let mut config = super::super::tests::fixture(Platform::Linux);
        config.installation = root.clone();
        config.user_home = root.join("home");
        config.executable = root.join("bin/rsrs");
        config.id = identity(&root, &config.owner);
        config.environment.insert(
            "RSRS_RPC_PORT".into(),
            crate::net_rpc::rpc_port().to_string(),
        );
        config
            .environment
            .insert("RSRS_DATA_DIR".into(), root.display().to_string());
        config.environment.insert(
            "RSRS_BIN_DIR".into(),
            root.join("bin").display().to_string(),
        );
        fs::create_dir_all(root.join("bin"))?;
        fs::copy(std::env::current_exe()?, &config.executable)?;
        let runtime = crate::runtime_fetch::runtime_fetch_tests::install_lifecycle_fixture()?;
        std::env::remove_var("RSRS_RUNTIME_BIN");
        let birth =
            manager::process_birth(std::process::id())?.context("test process birth missing")?;
        let health = json!({
            "server": "respire", "bin": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(), "v": crate::rpc::PROTOCOL_V,
            "exe": runtime, "image_path": runtime, "data_dir": root,
            "installation_root": root, "installation_id": hash(root.display().to_string().as_bytes()),
            "managed_id": config.id, "process_start_id": format!("linux-starttime-{birth}")
        });
        verify_owned_runtime(&config, &serde_json::from_value(health.clone())?)?;
        for (field, foreign) in [
            ("exe", json!(config.executable)),
            ("image_path", json!(config.executable)),
            ("data_dir", json!(config.user_home)),
            ("installation_root", json!(config.user_home)),
            ("installation_id", json!("foreign-installation")),
            ("managed_id", json!("foreign-registration")),
            ("process_start_id", json!("linux-starttime-reused")),
            ("pid", json!(0)),
        ] {
            let mut changed = health.clone();
            changed[field] = foreign;
            anyhow::ensure!(
                verify_owned_runtime(&config, &serde_json::from_value(changed)?).is_err()
            );
        }
        config.enabled = true;
        let (_scope, state) = manager::test_adapter::install(&config);
        manager::install(&mut config)?;
        save(&mut config)?;
        let version = crate::runtime_fetch::pinned()?.required.clone();
        let installed = root.join("runtime").join(&version);
        fs::create_dir_all(&installed)?;
        let inventory = runtime_inventory()?;
        anyhow::ensure!(inventory["required"] == version && inventory["installed"][0]["version"] == version
            && inventory["installed"][0]["current"] == true);
        anyhow::ensure!(install_runtime(Some(&runtime), None, None).is_err());
        anyhow::ensure!(install_runtime(None, Some(&version), None).is_err());
        anyhow::ensure!(install_runtime(Some(&runtime), Some(&version), Some("https://example.invalid")).is_err());

        // Recovery must revalidate the registered owner again at the cleanup boundary.
        {
            let _takeover = crate::runtime_policy::takeover_lock()?;
            let session = root.join("session.json");
            fs::write(&session, br#"{"user":"recovery-fixture-account"}"#)?;
            let instance = uuid::Uuid::new_v4().to_string();
            let registration = fs::read(control_path(&root))?;
            let grant = serde_json::to_string(&json!({
                "schema_version":1, "protocol_version":crate::rpc::PROTOCOL_V,
                "nonce":instance, "instance_id":instance, "installation_root":root,
                "installation_id":hash(root.display().to_string().as_bytes()), "profile":root,
                "account_id":hash(b"recovery-fixture-account"), "sync_generation":0,
                "image_path":runtime, "image_sha256":hash(b"synthetic runtime; never executed"),
                "supervisor_pid":u32::MAX-1, "supervisor_birth":"456", "managed_id":config.id,
                "registration_sha256":hash(&registration), "maintenance":null,
                "port":crate::net_rpc::rpc_port(), "issued_at_ms":1, "expires_at_ms":2,
            }))?;
            let receipt = serde_json::to_vec(&json!({
                "schema_version":2, "protocol_version":crate::rpc::PROTOCOL_V, "state":"consumed",
                "grant_json":grant, "grant_sha256":hash(grant.as_bytes()),
                "registration_json":std::str::from_utf8(&registration)?,
                "pid":u32::MAX, "process_start_id":"123",
            }))?;
            let launch = root.join("runtime/autostart/launch");
            fs::create_dir_all(&launch)?;
            let claim = launch.join(format!("launch-{instance}.claimed"));
            fs::write(&claim, &receipt)?;
            let endpoint = crate::rpc::endpoint_path();
            let record = serde_json::to_vec(&json!({
                "schema_version":2, "server":"respire", "v":crate::rpc::PROTOCOL_V,
                "bin":version, "runtime_version":version, "url":crate::net_rpc::rpc_base_url(),
                "pid":u32::MAX, "process_start_id":"linux-starttime-123", "instance_id":instance,
                "installation_root":root, "data_dir":root,
                "installation_id":hash(root.display().to_string().as_bytes()),
                "account_id":hash(b"recovery-fixture-account"), "generation":7,
                "exe":runtime, "image_path":runtime, "image_sha256":hash(b"synthetic runtime; never executed"),
                "managed_id":config.id, "launch_receipt_sha256":hash(&receipt),
            }))?;
            fs::write(&endpoint, &record)?;
            state.borrow_mut().running = true;
            anyhow::ensure!(super::super::StaleOwner::prepare_locked().is_err());
            state.borrow_mut().running = false;
            let listener = std::net::TcpListener::bind(("127.0.0.1", crate::net_rpc::rpc_port()))?;
            anyhow::ensure!(super::super::StaleOwner::prepare_locked().is_err());
            drop(listener);
            let stale = super::super::StaleOwner::prepare_locked()?;
            let mut changed = config.clone();
            changed.manually_stopped = true;
            save(&mut changed)?;
            anyhow::ensure!(stale.remove_endpoint_locked().is_err());
            anyhow::ensure!(fs::read(&endpoint)? == record && fs::read(&claim)? == receipt);
            fs::write(control_path(&root), &registration)?;
            super::super::StaleOwner::prepare_locked()?.remove_endpoint_locked()?;
            anyhow::ensure!(!endpoint.exists() && fs::read(&claim)? == receipt && !root.join("rsrs.db").exists());
            fs::remove_file(session)?;
        }
        let changes = state.borrow().changes.clone();
        config.enabled = false;
        config.manually_stopped = true;
        save(&mut config)?;
        anyhow::ensure!(!ensure_managed_locked()? && !stop_managed_locked()?);
        run_foreground(Some(&config.id), Some(&root), false)?;
        std::env::set_var("RSRS_RUNTIME_BIN", root.join("missing-runtime"));
        anyhow::ensure!(start_explicit_locked().is_err());
        std::env::remove_var("RSRS_RUNTIME_BIN");
        config = read_registration(&root)?.context("disabled registration disappeared")?;
        anyhow::ensure!(!config.enabled && !config.manually_stopped
            && state.borrow().changes == changes);
        config.enabled = true;
        save(&mut config)?;

        // Stop at real boot fences, before signal handlers or runtime_entry can run.
        let mut paused = Maintenance::begin(config.clone(), false)?;
        anyhow::ensure!(run_foreground(Some(&config.id), None, false).is_err());
        anyhow::ensure!(run_foreground(Some("foreign"), Some(&root), false).is_err());
        anyhow::ensure!(run_foreground(Some(&config.id), Some(&root), false).is_err());
        let executable = fs::read(&config.executable)?;
        fs::remove_file(&config.executable)?;
        std::os::unix::fs::symlink(std::env::current_exe()?, &config.executable)?;
        for key in ["RSRS_UNREGISTERED", "ONEMEMORY_UNREGISTERED", "RESPIRE_UNREGISTERED"] {
            std::env::set_var(key, "must-not-reach-the-child");
        }
        run_foreground(Some(&config.id), Some(&root), false)?;
        for key in ["RSRS_UNREGISTERED", "ONEMEMORY_UNREGISTERED", "RESPIRE_UNREGISTERED"] {
            anyhow::ensure!(std::env::var_os(key).is_none());
        }
        anyhow::ensure!(std::env::var_os("HOME").as_deref() == Some(config.user_home.as_os_str())
            && std::env::var_os("USERPROFILE").as_deref() == Some(config.user_home.as_os_str()));
        paused.mark(Phase::Starting)?;
        let now = now_seconds()?;
        for _ in 0..3 {
            anyhow::ensure!(record_attempt(&config, now)?);
        }
        run_foreground(Some(&config.id), Some(&root), false)?;
        anyhow::ensure!(managed_id().is_none() && read_attempts(&config)?.0.starts.len() == 3);
        let events = fs::read_to_string(control_path(&root).with_file_name("events.jsonl"))?;
        anyhow::ensure!(events.contains("\"event\":\"paused\"") && events.contains("\"event\":\"crash_limit\""));
        paused.finish()?;
        config = read_registration(&root)?.context("paused registration disappeared")?;
        fs::remove_file(&config.executable)?;
        fs::write(&config.executable, executable)?;
        reset_attempts(&config)?;
        for materialize in [false, true] {
            state.borrow_mut().running = true;
            let error = if materialize {
                coordinate_materialization().map(|_| ())
            } else {
                ensure_managed_locked().map(|_| ())
            }
            .err()
            .context("maintenance without owner proof unexpectedly succeeded")?;
            anyhow::ensure!(format!("{error:#}").contains("manager stop is blocked")
                && state.borrow().running && background_paused());
            state.borrow_mut().running = false;
            let mut recovered = restart_maintenance_locked()?;
            recovered.finish()?;
        }
        config = read_registration(&root)?.context("recovered registration disappeared")?;
        let cold_changes = state.borrow().changes.clone();
        raw_stop_owned(&config)?;
        anyhow::ensure!(
            !state.borrow().running && state.borrow().changes == cold_changes,
            "cold start attempted to stop an absent owner"
        );
        // Model the interval after a verified child drain but before supervisor exit.
        state.borrow_mut().running = true;
        anyhow::ensure!(
            raw_stop_owned(&config).is_err() && state.borrow().changes == cold_changes,
            "an active supervisor without drain proof was stopped"
        );
        let mut maintenance = Maintenance::begin(config.clone(), false)?;
        let mut foreign = health.clone();
        foreign["managed_id"] = json!("foreign-registration");
        anyhow::ensure!(
            maintenance.drain_runtime(&serde_json::from_value(foreign)?).is_err()
                && state.borrow().running,
            "profile maintenance stopped a foreign owner"
        );
        let before_stop = state.borrow().changes.clone();
        state.borrow_mut().fail = Some("stop".into());
        anyhow::ensure!(
            stop_drained_supervisor(&config).is_err() && state.borrow().running,
            "failed supervisor stop permitted replacement"
        );
        state.borrow_mut().fail = None;
        stop_drained_supervisor(&config)?;
        let after_stop = state.borrow().changes.clone();
        anyhow::ensure!(!state.borrow().running && after_stop.len() == before_stop.len() + 1);
        raw_stop_owned(&config)?;
        anyhow::ensure!(
            state.borrow().changes == after_stop,
            "a drained and stopped supervisor required a second health proof"
        );
        maintenance.finish()?;
        let cold_changes = state.borrow().changes.clone();
        let endpoint = crate::rpc::endpoint_path();
        fs::create_dir_all(endpoint.parent().context("test endpoint parent missing")?)?;
        anyhow::ensure!(!endpoint.exists());
        fs::write(&endpoint, br#"{"v":1,"pid":0}"#)?;
        anyhow::ensure!(
            raw_stop_owned(&config).is_err()
                && endpoint.exists()
                && state.borrow().changes == cold_changes,
            "unverified stopped owner was reclaimed"
        );
        fs::remove_file(endpoint)?;
        for phase in [Phase::Paused, Phase::Starting, Phase::Verified] {
            let current = read_registration(&root)?.context("test registration missing")?;
            let mut interrupted = Maintenance::begin(current, false)?;
            interrupted.mark(phase)?;
            let old_token = interrupted
                .marker
                .as_ref()
                .context("test marker missing")?
                .token
                .clone();
            drop(interrupted);
            anyhow::ensure!(check_direct_access().is_err() && background_paused());
            let current = read_registration(&root)?.context("test registration missing")?;
            anyhow::ensure!(Maintenance::begin(current, false).is_err());
            let mut recovered = restart_maintenance_locked()?;
            anyhow::ensure!(
                recovered
                    .marker
                    .as_ref()
                    .context("test recovery marker missing")?
                    .token
                    != old_token
            );
            authorize_detached_boot_locked()?;
            recovered.finish()?;
            anyhow::ensure!(marker(&root)?.is_none() && !background_paused());
        }
        state.borrow_mut().running = true;
        let changes = state.borrow().changes.clone();
        let blocked = stop_managed_locked()
            .err()
            .context("missing health permitted manager stop")?;
        anyhow::ensure!(format!("{blocked:#}").contains("manager stop is blocked"));
        anyhow::ensure!(state.borrow().running && state.borrow().changes == changes);
        anyhow::ensure!(background_paused());
        state.borrow_mut().running = false;
        let mut recovered = restart_maintenance_locked()?;
        recovered.finish()?;
        let mut stopped = read_registration(&root)?.context("test registration missing")?;
        stopped.manually_stopped = true;
        save(&mut stopped)?;
        anyhow::ensure!(
            read_registration(&root)?
                .context("test registration missing")?
                .manually_stopped
        );
        let unchanged = fs::read(control_path(&root))?;
        state.borrow_mut().dropin = true;
        anyhow::ensure!(restart_maintenance_locked().is_err() && start_explicit_locked().is_err());
        anyhow::ensure!(fs::read(control_path(&root))? == unchanged && marker(&root)?.is_none());
        state.borrow_mut().dropin = false;
        let original_port = std::env::var("RSRS_RPC_PORT")?;
        let different = if original_port == "65534" {
            "65533"
        } else {
            "65534"
        };
        std::env::set_var("RSRS_RPC_PORT", different);
        anyhow::ensure!(restart_maintenance_locked().is_err() && start_explicit_locked().is_err());
        anyhow::ensure!(fs::read(control_path(&root))? == unchanged && marker(&root)?.is_none());
        std::env::set_var("RSRS_RPC_PORT", original_port);
        let mut restarted = restart_maintenance_locked()?;
        anyhow::ensure!(
            !read_registration(&root)?
                .context("test registration missing")?
                .manually_stopped
        );
        restarted.finish()?;
        // Failure after marking verified must retain a fence, not silently let
        // new background or direct work run against a partially committed plan.
        let current = read_registration(&root)?.context("test registration missing")?;
        let mut interrupted = Maintenance::begin(current, false)?;
        interrupted.mark(Phase::Starting)?;
        let path = control_path(&root);
        let mut bytes = fs::read(&path)?;
        bytes.push(b' ');
        fs::write(path, bytes)?;
        anyhow::ensure!(interrupted.finish().is_err());
        drop(interrupted);
        anyhow::ensure!(background_paused() && check_direct_access().is_err());
        let mut recovered = restart_maintenance_locked()?;
        recovered.finish()?;
        anyhow::ensure!(!background_paused());
        // Recreate a running owner without health before checking the stop fence.
        state.borrow_mut().running = true;
        state.borrow_mut().fail = Some("enable".into());
        let failed = enable(false)
            .err()
            .context("backend registration failure was not returned")?;
        anyhow::ensure!(
            format!("{failed:#}").contains("manager stop is blocked"),
            "missing health did not block before backend registration"
        );
        anyhow::ensure!(
            marker(&root)?.is_some()
                && !read_registration(&root)?
                    .context("failed registration missing")?
                    .enabled
        );
        state.borrow_mut().fail = None;
        let changes = state.borrow().changes.clone();
        let blocked = disable(true, true)
            .err()
            .context("missing health permitted removal")?;
        anyhow::ensure!(format!("{blocked:#}").contains("manager stop is blocked"));
        anyhow::ensure!(
            marker(&root)?.is_some()
                && manager::inspect(
                    &read_registration(&root)?.context("preserved registration missing")?
                )?
                .registered
                && state.borrow().changes == changes
        );
        Ok(())
    }

    #[test]
    fn private_configuration_refuses_unknown_files_links_and_unplanned_changes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?.join("registration.json");
        private_write(&path, b"initial", None)?;
        anyhow::ensure!(private_write(&path, b"overwrite", None).is_err());
        anyhow::ensure!(private_write(&path, b"overwrite", Some(&hash(b"wrong"))).is_err());
        private_write(&path, b"updated", Some(&hash(b"initial")))?;
        anyhow::ensure!(fs::read(&path)? == b"updated");
        #[cfg(unix)]
        {
            let link = directory.path().canonicalize()?.join("link");
            std::os::unix::fs::symlink(&path, &link)?;
            anyhow::ensure!(private_write(&link, b"bad", Some(&hash(b"updated"))).is_err());
        }
        Ok(())
    }
}

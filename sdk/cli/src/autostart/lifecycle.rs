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

static MANAGED_ID: OnceLock<String> = OnceLock::new();
static CREDENTIAL_STATE: AtomicU8 = AtomicU8::new(0);
thread_local! {
    static ACTIVE: RefCell<Option<String>> = const { RefCell::new(None) };
    static RECOVERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Phase {
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
}

fn marker_path(root: &Path) -> PathBuf {
    control_path(root).with_file_name("maintenance.json")
}
fn marker(root: &Path) -> Result<Option<Marker>> {
    let path = marker_path(root);
    let meta = match fs::symlink_metadata(&path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    anyhow::ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 4096,
        "invalid runtime maintenance marker"
    );
    let value: Marker = serde_json::from_slice(&fs::read(path)?)?;
    anyhow::ensure!(
        value.schema == 1 && uuid::Uuid::parse_str(&value.token).is_ok(),
        "invalid runtime maintenance marker"
    );
    Ok(Some(value))
}

fn controller_alive(value: &Marker) -> Result<bool> {
    Ok(manager::process_birth(value.owner_pid)?.as_deref() == Some(value.owner_birth.as_str()))
}

fn save(config: &mut Registration) -> Result<()> {
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

fn ensure_control_endpoint(config: &Registration) -> Result<()> {
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
    Ok(read_registration(&respire::service::main_data_dir())?.is_some_and(|config| config.enabled))
}
pub(crate) fn record_exit(success: bool) {
    if managed_id().is_some() {
        if let Ok(Some(config)) = read_registration(&respire::service::main_data_dir()) {
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
    let root = respire::service::main_data_dir();
    if let Some(value) = marker(&root)? {
        anyhow::ensure!(ACTIVE.with(|v|v.borrow().as_deref()==Some(value.token.as_str())),
            "runtime maintenance is incomplete; use the host runtime restart or the indicated snapshot/login recovery before accessing the library");
    }
    Ok(())
}

pub(crate) fn check_managed_request() -> Result<()> {
    if crate::rpc::worker_active() {
        check_direct_access()?;
    }
    Ok(())
}

pub(crate) fn verify_managed_boot() -> Result<()> {
    let root = respire::service::main_data_dir();
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
                    == Some(respire::service::data_dir().canonicalize()?.as_path()),
            "replacement runtime version/profile differs from maintenance plan"
        );
    }
    Ok(())
}

pub(crate) struct Maintenance {
    config: Option<Registration>,
    marker: Option<Marker>,
    marker_digest: Option<String>,
    completed: bool,
}

impl Maintenance {
    fn inactive() -> Self {
        Self {
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
            config: Some(config),
            marker: Some(value),
            marker_digest: Some(hash(&bytes)),
            completed: false,
        })
    }

    fn mark(&mut self, phase: Phase) -> Result<()> {
        let Some(config) = self.config.as_ref() else {
            return Ok(());
        };
        let actual = fs::read(marker_path(&config.installation))?;
        let current: Marker = serde_json::from_slice(&actual)?;
        let value = self
            .marker
            .as_mut()
            .context("maintenance marker unavailable")?;
        anyhow::ensure!(
            current.id == value.id && current.token == value.token,
            "maintenance owner changed before phase transition"
        );
        value.phase = phase;
        if matches!(phase, Phase::Starting | Phase::Verified) {
            value.expected_profile = Some(respire::service::data_dir().canonicalize()?);
        }
        let bytes = serde_json::to_vec(value)?;
        private_write(
            &marker_path(&config.installation),
            &bytes,
            Some(&hash(&actual)),
        )?;
        self.marker_digest = Some(hash(&bytes));
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        if self.completed {
            return Ok(());
        }
        self.mark(Phase::Verified)?;
        let config = self
            .config
            .as_mut()
            .context("maintenance registration unavailable")?;
        config.maintenance = false;
        save(config)?;
        let path = marker_path(&config.installation);
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
        if self.config.is_some() {
            ACTIVE.with(|slot| *slot.borrow_mut() = None);
        }
    }
}

pub(crate) fn begin_maintenance_locked() -> Result<Maintenance> {
    if ACTIVE.with(|v| v.borrow().is_some()) {
        return Ok(Maintenance::inactive());
    }
    match read_registration(&respire::service::main_data_dir())? {
        Some(config) if config.enabled => {
            let guard = Maintenance::begin(config, RECOVERY.with(|v| v.get()))?;
            reset_attempts(
                guard
                    .config
                    .as_ref()
                    .context("maintenance registration missing")?,
            )?;
            Ok(guard)
        }
        _ => Ok(Maintenance::inactive()),
    }
}

/// Explicit host restart is the recovery operation for an interrupted transition.
/// The caller holds the same installation takeover lock as profile changes.
pub(crate) fn restart_maintenance_locked() -> Result<Maintenance> {
    let Some(config) = read_registration(&respire::service::main_data_dir())? else {
        return Ok(Maintenance::inactive());
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
    let root = respire::service::main_data_dir();
    let Some(mut value) = marker(&root)? else {
        bail!("active maintenance marker missing");
    };
    anyhow::ensure!(value.token == token, "maintenance owner changed");
    let path = marker_path(&root);
    let previous = fs::read(&path)?;
    value.phase = Phase::Starting;
    value.expected_profile = Some(respire::service::data_dir().canonicalize()?);
    private_write(&path, &serde_json::to_vec(&value)?, Some(&hash(&previous)))
}

pub(crate) fn background_paused() -> bool {
    // Malformed/unreadable control state also fences background mutations.
    !matches!(marker(&respire::service::main_data_dir()), Ok(None))
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
    if current_boot_token().is_some() {
        return Ok(None);
    }
    let root = respire::service::main_data_dir();
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

fn raw_stop_owned(config: &Registration) -> Result<()> {
    ensure_control_endpoint(config)?;
    manager::inspect(config)?;
    if let Some(health) = crate::rpc::probe_runtime()? {
        anyhow::ensure!(
            crate::mcp::exe_matches_dest(&health.exe, &config.executable)
                && !health.data_dir.is_empty()
                && crate::mcp::same_path(
                    Path::new(&health.data_dir),
                    &respire::service::data_dir()
                ),
            "runtime identity/profile does not match this installation; no lifecycle action taken"
        );
        crate::rpc::stop_occupant(health.pid)?;
    }
    manager::stop(config)
}

fn wait_ready(config: &Registration) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if let Some(health) = crate::rpc::probe_runtime()? {
            anyhow::ensure!(
                (crate::runtime_fetch::version_in_accept(&health.runtime_version)
                    // Legacy combined binaries and the split-transition shim
                    // both report this CLI's exact train.
                    || health.bin == env!("CARGO_PKG_VERSION"))
                    && (crate::mcp::exe_matches_dest(&health.exe, &config.executable)
                        || crate::runtime_fetch::managed_runtime_path()
                            .ok()
                            .flatten()
                            .is_some_and(|managed| crate::mcp::exe_matches_dest(&health.exe, &managed)))
                    && !health.data_dir.is_empty()
                    && crate::mcp::same_path(
                        Path::new(&health.data_dir),
                        &respire::service::data_dir()
                    ),
                "managed runtime version/executable/profile mismatch"
            );
            anyhow::ensure!(
                health.managed_id.as_deref() == Some(config.id.as_str()),
                "runtime is not owned by this startup registration"
            );
            if health.store_ready || respire::service::off_mode() {
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
    raw_stop_owned(config)?;
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
    match read_registration(&respire::service::main_data_dir())? {
        Some(config) if config.enabled => Ok(
            !config.manually_stopped && health.managed_id.as_deref() == Some(config.id.as_str())
        ),
        _ => Ok(true),
    }
}

pub(crate) fn ensure_managed_locked() -> Result<bool> {
    let Some(config) = read_registration(&respire::service::main_data_dir())? else {
        return Ok(false);
    };
    if !config.enabled {
        return Ok(false);
    }
    owned(&config)?;
    anyhow::ensure!(
        !config.manually_stopped,
        "runtime was manually stopped; use runtime start explicitly"
    );
    if ACTIVE.with(|v| v.borrow().is_some()) {
        let value = marker(&config.installation)?.context("active maintenance marker missing")?;
        let digest = hash(&fs::read(marker_path(&config.installation))?);
        let mut borrowed = Maintenance {
            config: Some(config),
            marker: Some(value),
            marker_digest: Some(digest),
            completed: true,
        };
        let result = start_candidate(&mut borrowed);
        // This borrowed guard does not own completion or its caller's token.
        borrowed.config = None;
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
    start_candidate(&mut guard)?;
    guard.finish()?;
    Ok(true)
}

fn start_explicit_locked() -> Result<()> {
    let root = respire::service::main_data_dir();
    let Some(config) = read_registration(&root)?.filter(|config| config.enabled) else {
        return crate::rpc::ensure_daemon_locked();
    };
    owned(&config)?;
    manager::inspect(&config)?;
    check_direct_access()?;
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
    start_candidate(&mut guard)?;
    guard.finish()
}

pub(crate) fn stop_managed_locked() -> Result<bool> {
    let Some(mut config) = read_registration(&respire::service::main_data_dir())? else {
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
    let root = respire::service::main_data_dir();
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
fn reset_attempts(config: &Registration) -> Result<()> {
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
    if let Ok(Some(config)) = read_registration(&respire::service::main_data_dir()) {
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
        ["starting", "paused", "crash_limit", "exit_ok", "exit_error",
            "restart_probe", "restart_managed", "restart_identity", "restart_stop",
            "restart_start", "restart_ready"].contains(&name),
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
    let root = respire::service::main_data_dir();
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
    anyhow::ensure!(
        !crate::rpc::worker_active(),
        "runtime lifecycle commands require the host CLI, not a runtime request"
    );
    match command {
        RuntimeCommand::Run {
            managed,
            installation_root,
            supervised_child,
        } => run_foreground(managed.as_deref(), installation_root.as_deref(), *supervised_child),
        RuntimeCommand::Stop => {
            crate::rpc::stop_if_running()?;
            emit("runtime.stop", json!({"state":"stopped"}))
        }
        RuntimeCommand::Restart => {
            let value = crate::rpc::restart_runtime(Duration::from_secs(10))?;
            emit("runtime.restart", value)
        }
        RuntimeCommand::Start => {
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
        RuntimeCommand::Install { file, version, mirror } => {
            install_runtime(file.as_deref(), version.as_deref(), mirror.as_deref())
        }
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
                crate::model_install::validate_mirror(origin)?;
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
        .map(|entry| {
            json!({"version": entry.version, "path": entry.path, "current": entry.current})
        })
        .collect();
    Ok(json!({
        "required": pin.required.clone(),
        "accept": pin.accept_raw.clone(),
        "installed": versions,
    }))
}

fn enable(now: bool) -> Result<()> {
    // A platform-rejected native path must not even create lifecycle state.
    manager::validate_executable(Platform::current()?, &crate::mcp::stable_bin_path())?;
    let _ownership = crate::runtime_policy::takeover_lock()?;
    let mut config = match read_registration(&respire::service::main_data_dir())? {
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
    if read_registration(&respire::service::main_data_dir())?.is_none() {
        return emit(command, status()?);
    }
    let _ownership = crate::runtime_policy::takeover_lock()?;
    let Some(mut config) = read_registration(&respire::service::main_data_dir())? else {
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
        config = read_registration(&respire::service::main_data_dir())?
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
    anyhow::ensure!(!supervised_child || (cfg!(windows) && id.is_some()), "supervised-child requires a Windows managed registration");
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
        anyhow::ensure!(!read_registration(&respire::service::main_data_dir())?.is_some_and(|config|config.enabled),"the service manager owns this runtime; use runtime start instead of an unmanaged foreground instance");
        check_direct_access()?;
    }
    verify_managed_boot()?;
    #[cfg(unix)]
    {
        let stopped = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
        std::thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(50));
            }
            crate::rpc::request_drain_exit();
        });
    }
    let result = crate::rpc::runtime_entry(crate::rpc::RuntimeFlags {
        port: Some(crate::net_rpc::rpc_port()),
        host: "127.0.0.1".into(),
        status: false,
        stop: false,
    });
    if managed_id().is_some() {
        let config = read_registration(&respire::service::main_data_dir())?
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
    if uptime >= Duration::from_secs(120) { *failures = 0; }
    *failures = failures.saturating_add(1);
    *failures < 3
}

#[cfg(windows)]
fn supervisor_may_run(expected: &Registration) -> Result<bool> {
    let current=read_registration(&expected.installation)?.context("supervised registration disappeared")?;
    anyhow::ensure!(current.id==expected.id && current.owner==expected.owner && current.executable==expected.executable,"supervised registration identity changed");
    if !current.enabled || current.manually_stopped { return Ok(false); }
    if let Some(value)=marker(&expected.installation)? {
        return Ok(value.phase != Phase::Paused && controller_alive(&value)?
            && value.id==expected.id && value.expected_version==env!("CARGO_PKG_VERSION"));
    }
    Ok(true)
}

#[cfg(windows)]
fn supervise_windows_runtime(config: &Registration) -> Result<()> {
    // Task Scheduler remains the current-user logon owner, but does not
    // reliably retry terminated Exec actions. Keep its action in the foreground
    // and supervise a foreground child; never open the library in this parent.
    respire_spawn::confine_supervisor_tree().context("cannot establish owned supervisor process tree")?;
    let mut failures=0;
    loop {
        if !supervisor_may_run(config)? { return Ok(()); }
        let mut command=std::process::Command::new(&config.executable);
        command.args(["runtime","run","--managed",&config.id,"--installation-root"])
            .arg(&config.installation).arg("--supervised-child")
            .env_remove("RSRS_RUNTIME_BOOT_TOKEN")
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        let started=Instant::now();
        let status=match respire_spawn::spawn_host_control(&mut command) {
            Ok(mut child)=>Some(child.wait().context("cannot confirm owned runtime child exit")?),
            Err(_)=>None,
        };
        if status.is_some_and(|status|status.success()) { return Ok(()); }
        event(config,"exit_error")?;
        if !supervisor_may_run(config)? { return Ok(()); }
        if !retry_supervised_child(&mut failures,started.elapsed()) {
            event(config,"crash_limit")?;
            return Ok(());
        }
        let deadline=Instant::now()+Duration::from_secs(60);
        while Instant::now()<deadline {
            if !supervisor_may_run(config)? { return Ok(()); }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreground_supervisor_retries_are_bounded_and_reset_only_after_stability() -> Result<()> {
        let mut failures=0;
        assert!(retry_supervised_child(&mut failures,Duration::from_secs(1)));
        assert!(retry_supervised_child(&mut failures,Duration::from_secs(1)));
        assert!(!retry_supervised_child(&mut failures,Duration::from_secs(1)));
        assert!(retry_supervised_child(&mut failures,Duration::from_secs(120)));
        assert_eq!(failures,1);
        Ok(())
    }

    #[test]
    fn registration_captures_nonsecret_opt_outs_and_legacy_names_canonically() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key,value) in &self.0 {
                    match value { Some(value) => std::env::set_var(key,value), None => std::env::remove_var(key) }
                }
            }
        }
        let keys=["RSRS_DATA_DIR","RSRS_BIN_DIR","RSRS_NO_AUTOSYNC","ONEMEMORY_NO_AUTOSYNC","RSRS_UPDATE_CHECK"];
        let _restore=Restore(keys.into_iter().map(|key|(key,std::env::var_os(key))).collect());
        let root=tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR",root.path());
        std::env::set_var("RSRS_BIN_DIR",root.path().join("bin"));
        std::env::remove_var("RSRS_NO_AUTOSYNC");
        std::env::set_var("ONEMEMORY_NO_AUTOSYNC","1");
        std::env::set_var("RSRS_UPDATE_CHECK","0");
        let config=new_registration()?;
        anyhow::ensure!(config.environment.get("RSRS_NO_AUTOSYNC").map(String::as_str)==Some("1"));
        anyhow::ensure!(config.environment.get("RSRS_UPDATE_CHECK").map(String::as_str)==Some("0"));
        anyhow::ensure!(!config.environment.keys().any(|key|key.starts_with("ONEMEMORY_")));
        anyhow::ensure!(!control_path(root.path()).exists(),"capturing settings registered startup");
        Ok(())
    }

    #[test]
    fn every_unfinished_phase_fences_requests_and_background_work() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE.with(|slot| *slot.borrow_mut() = None);
                match &self.0 {
                    Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
                    None => std::env::remove_var("RSRS_DATA_DIR"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("RSRS_DATA_DIR"));
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        anyhow::ensure!(!background_paused());
        for phase in [Phase::Paused, Phase::Starting, Phase::Verified] {
            let mut value = Marker {
                schema: 1,
                id: "synthetic-installation".into(),
                token: uuid::Uuid::new_v4().to_string(),
                phase,
                expected_profile: None,
                expected_version: env!("CARGO_PKG_VERSION").into(),
                owner_pid: std::process::id(),
                owner_birth: manager::process_birth(std::process::id())?
                    .context("test process birth missing")?,
            };
            let path = marker_path(&respire::service::main_data_dir());
            fs::create_dir_all(path.parent().context("test marker parent")?)?;
            fs::write(&path, serde_json::to_vec(&value)?)?;
            anyhow::ensure!(controller_alive(&value)?);
            anyhow::ensure!(background_paused() && check_direct_access().is_err());
            ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
            check_direct_access()?;
            // Owning the controller token never authorizes background threads.
            anyhow::ensure!(background_paused());
            ACTIVE.with(|slot| *slot.borrow_mut() = None);
            value.owner_birth.push_str("-reused-pid");
            anyhow::ensure!(!controller_alive(&value)?);
            fs::remove_file(path)?;
        }
        let path = marker_path(&respire::service::main_data_dir());
        fs::write(&path, b"malformed")?;
        anyhow::ensure!(background_paused() && check_direct_access().is_err());
        fs::remove_file(path)?;
        anyhow::ensure!(!background_paused());
        check_direct_access()?;
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
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_restart_recovers_every_phase_and_clears_manual_stop() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE.with(|slot| *slot.borrow_mut() = None);
                for (key, value) in &self.0 {
                    match value {
                        Some(v) => std::env::set_var(key, v),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
        let _restore = Restore(
            ["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_RPC_PORT"]
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
        );
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
        config.enabled = true;
        let (_scope, state) = manager::test_adapter::install(&config);
        manager::install(&mut config)?;
        save(&mut config)?;
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
        anyhow::ensure!(stop_managed_locked()?);
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
        state.borrow_mut().fail = Some("enable".into());
        let failed = enable(false)
            .err()
            .context("backend registration failure was not returned")?;
        anyhow::ensure!(
            format!("{failed:#}").contains("systemctl current-user operation failed"),
            "fixture did not reach backend registration failure"
        );
        anyhow::ensure!(
            marker(&root)?.is_some()
                && !read_registration(&root)?
                    .context("failed registration missing")?
                    .enabled
        );
        state.borrow_mut().fail = None;
        disable(true, true)?;
        anyhow::ensure!(
            marker(&root)?.is_none()
                && !manager::inspect(
                    &read_registration(&root)?.context("removed registration missing")?
                )?
                .registered
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

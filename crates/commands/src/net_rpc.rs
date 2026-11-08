//! Loopback HTTP client for the local runtime (`127.0.0.1:15169`).
//! Current loopback runtimes need no token; pre-1.0.10 runtimes require the
//! existing host token on the initial request. Non-loopback HTTP access uses
//! `RSRS_RPC_TOKEN` then `<data_dir>/runtime/token` on the host.

use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::runtime_error::RuntimeError;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: u16 = 15169;
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_POLLS: usize = 40;
const STOP_WAIT: Duration = Duration::from_millis(250);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Health {
    pub server: String,
    pub bin: String,
    #[serde(default)]
    pub runtime_version: String,
    pub pid: u32,
    pub v: u32,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub data_dir: String,
    #[serde(default)]
    pub inference: Value,
    #[serde(default)]
    pub store_ready: bool,
    #[serde(default)]
    pub snapshot_restore_id: Option<String>,
    #[serde(default)]
    pub installation_root: String,
    #[serde(default)]
    pub installation_id: String,
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub process_start_id: String,
    #[serde(default)]
    pub image_path: String,
    #[serde(default)]
    pub image_sha256: String,
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub managed_id: Option<String>,
    #[serde(default)]
    pub credential_state: String,
}

#[derive(Debug, Deserialize)]
pub struct StopAccepted {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub operation_id: String,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub timeout_state: Option<String>,
}

impl Health {
    pub fn inference_stalled(&self) -> bool {
        self.inference["host_recovery_required"] == true
    }
}

pub fn rpc_port() -> u16 {
    if let Ok(raw) = respire_app::env::var("RSRS_RPC_PORT") {
        let trimmed = raw.trim();
        if let Ok(port) = trimmed.parse::<u16>() {
            if port != 0 {
                return port;
            }
        }
    }
    DEFAULT_RPC_PORT
}

pub fn rpc_base_url() -> String {
    format!("http://{DEFAULT_RPC_HOST}:{}", rpc_port())
}

pub fn no_autostart() -> bool {
    crate::runtime_policy::client_only()
}

/// Stable path of the installed CLI binary. Runtime process identity checks
/// compare a suspect process image against this location (previously provided
/// by the CLI's mcp module; the transport owns the same rule in one place).
pub fn stable_bin_path() -> PathBuf {
    let name = if cfg!(windows) { "rsrs.exe" } else { "rsrs" };
    if let Ok(raw) = respire_app::env::var("RSRS_BIN_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join(name);
        }
    }
    respire_app::service::main_data_dir().join("bin").join(name)
}

pub fn token_path() -> PathBuf {
    crate::rpc_worker::runtime_dir_path().join("token")
}

#[cfg(test)]
fn load_token() -> Option<String> {
    read_token().ok().flatten()
}

fn read_token() -> Result<Option<String>> {
    if let Ok(raw) = respire_app::env::var("RSRS_RPC_TOKEN") {
        let trimmed = raw.trim().to_owned();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed));
        }
    }
    if let Some(token) = read_token_file(&token_path())? {
        return Ok(Some(token));
    }
    read_token_file(
        &respire_app::service::data_dir()
            .join("runtime")
            .join("token"),
    )
}

fn read_token_file(path: &std::path::Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(RuntimeError::TokenUnreadable(format!("{}: {error}", path.display())).into())
        }
    }
}

fn check_connection() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], rpc_port()));
    // Windows may take slightly over two seconds to report loopback refusal.
    // A shorter deadline misclassifies a stopped service as a network timeout.
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            Err(RuntimeError::Unavailable.into())
        }
        Err(error) => Err(RuntimeError::Transport(error.to_string()).into()),
    }
}

pub fn port_is_open() -> bool {
    port_is_open_on(rpc_port())
}

pub fn port_is_open_on(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

pub fn pid_listening_on(port: u16) -> Option<u32> {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let needle = format!(":{}", port);
        for line in text.lines() {
            let line = line.trim();
            if !line.contains("LISTENING")
                || !line
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|address| address.ends_with(&needle))
            {
                continue;
            }
            let pid = line.split_whitespace().last()?.parse().ok()?;
            if pid != 0 {
                return Some(pid);
            }
        }
        None
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|line| line.trim().parse().ok())
    }
}

pub fn pid_is_respire(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Accept both the combined legacy binary and the split rsrs-runtime child.
    #[cfg(windows)]
    {
        respire_spawn::process_identity(pid)
            .ok()
            .flatten()
            .and_then(|value| value.executable.file_name().map(|name| name.to_owned()))
            .is_some_and(|name| {
                name.to_str().is_some_and(|name| {
                    name.eq_ignore_ascii_case("rsrs.exe")
                        || name.eq_ignore_ascii_case("rsrs-runtime.exe")
                })
            })
    }
    #[cfg(target_os = "linux")]
    {
        // Use the same procfs authority as runtime_process_identity, without
        // assuming GNU ps options in minimal musl userspaces.
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|path| path.file_name().map(|name| name.to_owned()))
            .and_then(|name| {
                name.to_str().map(|name| {
                    name.strip_suffix(" (deleted)").unwrap_or(name) == "rsrs"
                        || name.strip_suffix(" (deleted)").unwrap_or(name) == "rsrs-runtime"
                })
            })
            .unwrap_or(false)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let out = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output();
        let Ok(out) = out else {
            return false;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let name = text.trim();
        name == "rsrs"
            || name.ends_with("/rsrs")
            || name == "rsrs-runtime"
            || name.ends_with("/rsrs-runtime")
    }
}

pub fn load_or_create_token() -> Result<String> {
    crate::runtime_policy::require_host("creating runtime credentials")?;
    if let Some(existing) = read_token()? {
        if respire_app::env::var("RSRS_RPC_TOKEN").is_ok() {
            return Ok(existing);
        }
        return Ok(existing);
    }
    let generated = respire_app::memory::crypto::random_hex(32);
    persist_token(&generated)?;
    Ok(generated)
}

pub fn persist_token(token: &str) -> Result<()> {
    let path = token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut file =
        fs::File::create(&path).with_context(|| format!("cannot write {}", path.display()))?;
    file.write_all(token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn origin_ok(origin: &str, bound_origin: &str) -> bool {
    let origin = origin.trim();
    if origin.is_empty() {
        return true;
    }
    let bound = bound_origin.trim_end_matches('/');
    origin == bound
        || bound
            .rsplit_once(':')
            .is_some_and(|(_, port)| origin == format!("http://localhost:{port}"))
        || (bound.starts_with("http://")
            && bound
                .strip_suffix(":80")
                .is_some_and(|canonical| origin == canonical || origin == "http://localhost"))
}

pub fn is_our_health(value: &Value) -> bool {
    value.get("server").and_then(|v| v.as_str()) == Some("respire")
        && value.get("bin").and_then(|v| v.as_str()).is_some()
}

pub fn version_cmp(ours: &str, theirs: &str) -> std::cmp::Ordering {
    fn nums(s: &str) -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    }
    let a = nums(ours);
    let b = nums(theirs);
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout(HTTP_TIMEOUT)
        .redirects(0)
        .build()
}

/// Preserve existing credentials on the first request, including health and stop.
/// New loopback servers ignore the header. Never replay a failed request.
fn send_loopback(
    request: ureq::Request,
    send: impl Fn(ureq::Request) -> std::result::Result<ureq::Response, ureq::Error>,
) -> Result<ureq::Response> {
    let request = match read_token()? {
        Some(token) => request.set("Authorization", &format!("Bearer {token}")),
        None => request,
    };
    let response = send(request).map_err(crate::runtime_error::http)?;
    if !(200..300).contains(&response.status()) {
        return Err(
            RuntimeError::Transport(format!("unexpected HTTP {}", response.status())).into(),
        );
    }
    Ok(response)
}

pub fn health() -> Result<Health> {
    check_connection()?;
    let url = format!("{}/api/health", rpc_base_url());
    let resp = send_loopback(
        agent().get(&url).timeout(Duration::from_secs(2)),
        |request| request.call(),
    )?;
    let parsed: Value = resp.into_json().context("runtime health is not JSON")?;
    if !is_our_health(&parsed) {
        bail!("port is not a rsrs runtime");
    }
    serde_json::from_value(parsed).context("runtime health shape mismatch")
}

pub fn request_stop() -> Result<StopAccepted> {
    request_stop_with_timeout(HTTP_TIMEOUT)
}

pub fn request_stop_with_timeout(timeout: Duration) -> Result<StopAccepted> {
    request_stop_for(&health()?, timeout)
}

pub fn request_stop_for(health: &Health, timeout: Duration) -> Result<StopAccepted> {
    crate::runtime_policy::require_host("runtime shutdown")?;
    anyhow::ensure!(
        !health.installation_id.is_empty()
            && !health.instance_id.is_empty()
            && !health.account_id.is_empty()
            && health.generation > 0,
        "runtime stop identity is incomplete"
    );
    let expected = json!({
        "installation_id": health.installation_id,
        "instance_id": health.instance_id,
        "account_id": health.account_id,
        "generation": health.generation,
    })
    .to_string();
    let url = format!("{}/api/runtime/stop", rpc_base_url());
    let response = send_loopback(
        agent()
            .post(&url)
            .timeout(timeout)
            .set("X-Respire-Lifecycle", "coordinator-v1"),
        |request| request.send_string(&expected),
    )?;
    let value: Value = response
        .into_json()
        .context("runtime stop reply is not JSON")?;
    anyhow::ensure!(
        value["ok"] == true && value["state"] == "accepted",
        "runtime did not accept a stop operation"
    );
    let accepted: StopAccepted = serde_json::from_value(value)?;
    anyhow::ensure!(
        !accepted.request_id.is_empty() && !accepted.operation_id.is_empty(),
        "runtime stop acknowledgement lacks request or operation ID"
    );
    Ok(accepted)
}

pub fn final_stop_receipt(health: &Health, operation_id: Option<&str>) -> Result<Value> {
    anyhow::ensure!(
        !health.instance_id.is_empty()
            && health.instance_id.len() <= 128
            && health
                .instance_id
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_'),
        "invalid runtime stop instance ID"
    );
    let root = respire_app::service::main_data_dir();
    anyhow::ensure!(
        !health.installation_root.is_empty()
            && fs::canonicalize(&health.installation_root)? == fs::canonicalize(&root)?,
        "stopped runtime belongs to another installation"
    );
    let path = root
        .join("runtime")
        .join(format!("stop-{}.json", health.instance_id));
    let file = fs::File::open(&path).context("final runtime stop receipt is missing")?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 1024 * 1024,
        "invalid stop receipt file"
    );
    let mut data = Vec::new();
    use std::io::Read;
    file.take(1024 * 1024 + 1).read_to_end(&mut data)?;
    anyhow::ensure!(data.len() <= 1024 * 1024, "stop receipt exceeds 1 MiB");
    let receipt: Value = serde_json::from_slice(&data).context("invalid final stop receipt")?;
    validate_final_stop_receipt(health, operation_id, &receipt)?;
    Ok(receipt)
}

pub fn validate_final_stop_receipt(
    health: &Health,
    operation_id: Option<&str>,
    receipt: &Value,
) -> Result<()> {
    let expected = serde_json::to_value(health)?;
    for key in [
        "installation_id",
        "instance_id",
        "process_start_id",
        "image_path",
        "image_sha256",
        "runtime_version",
        "account_id",
    ] {
        anyhow::ensure!(
            expected[key]
                .as_str()
                .is_some_and(|value| !value.is_empty())
                && receipt[key] == expected[key],
            "stop receipt identity mismatch: {key}"
        );
    }
    anyhow::ensure!(
        health.pid > 0
            && health.generation > 0
            && receipt["schema_version"] == 1
            && receipt["protocol_version"] == health.v
            && receipt["pid"] == health.pid
            && receipt["generation"] == health.generation
            && receipt["operation_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
            && operation_id.is_none_or(|id| receipt["operation_id"] == id),
        "stop receipt does not match the stopped instance and operation"
    );
    anyhow::ensure!(
        receipt["state"] == "drained"
            && receipt["unfinished"].as_array().is_some_and(Vec::is_empty),
        "runtime stopped without a proven complete drain"
    );
    Ok(())
}

pub fn instance_is_running(health: &Health) -> Result<bool> {
    anyhow::ensure!(
        health.pid > 0 && !health.process_start_id.is_empty(),
        "runtime process identity is incomplete"
    );
    #[cfg(windows)]
    {
        return Ok(respire_spawn::process_birth(health.pid)?
            .is_some_and(|birth| health.process_start_id == format!("windows-filetime-{birth}")));
    }
    #[cfg(target_os = "linux")]
    {
        let raw = match fs::read_to_string(format!("/proc/{}/stat", health.pid)) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context("cannot inspect runtime process identity"),
        };
        let fields = raw.rsplit_once(')').context("invalid process identity")?.1;
        if fields.split_whitespace().next() == Some("Z") {
            return Ok(false);
        }
        let birth = fields
            .split_whitespace()
            .nth(19)
            .context("process birth is missing")?;
        return Ok(health.process_start_id == format!("linux-starttime-{birth}"));
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = std::process::Command::new("ps")
            .args([
                "-p",
                &health.pid.to_string(),
                "-o",
                "lstart=",
                "-o",
                "stat=",
            ])
            .output()
            .context("cannot inspect runtime process identity")?;
        let text = String::from_utf8(output.stdout)?;
        if output.status.code() == Some(1) && text.trim().is_empty() {
            return Ok(false);
        }
        anyhow::ensure!(
            output.status.success(),
            "cannot inspect runtime process identity"
        );
        let (birth, state) = text
            .trim()
            .rsplit_once(char::is_whitespace)
            .context("invalid process identity")?;
        return Ok(!state.starts_with('Z')
            && health.process_start_id == format!("darwin-lstart-{}", birth.trim()));
    }
}

pub fn wait_for_instance_exit(health: &Health, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while instance_is_running(health)? {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "runtime drain is pending; no process was forced to exit"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

pub fn rpc_exec(args: Vec<String>) -> Result<Value> {
    rpc_method("cli.exec", args)
}

pub fn rpc_method(method: &str, args: Vec<String>) -> Result<Value> {
    rpc_method_with_timeout(method, args, None)
}

pub fn request_scope(health: &Health) -> Result<Value> {
    anyhow::ensure!(
        health.v == crate::rpc_worker::PROTOCOL_V
            && !health.account_id.is_empty()
            && !health.instance_id.is_empty()
            && health.generation > 0
            && !health.installation_root.is_empty(),
        "runtime request scope is incomplete or incompatible"
    );
    anyhow::ensure!(
        fs::canonicalize(&health.installation_root)?
            == fs::canonicalize(respire_app::service::main_data_dir())?,
        "runtime request belongs to another installation"
    );
    Ok(
        json!({"account_id":health.account_id,"instance_id":health.instance_id,"generation":health.generation}),
    )
}

fn rpc_timeout(method: &str, args: &[String], test_timeout: Option<Duration>) -> Duration {
    if let Some(timeout) = test_timeout {
        return timeout;
    }
    match method {
        "cli.progress" => return Duration::from_secs(1),
        "model.control" => return Duration::from_secs(3),
        "cli.exec" => {}
        _ => return HTTP_TIMEOUT,
    }
    // Native inference stays inside the runtime. Tracking IDs are values, not
    // command words, and longer write budgets never authorize a request replay.
    let command: Vec<_> = crate::rpc_worker::command_words(args).take(2).collect();
    if matches!(
        command.as_slice(),
        ["model", "install" | "install-m3" | "activate"]
    ) || command
        .first()
        .is_some_and(|c| matches!(*c, "reembed" | "sync" | "import"))
    {
        Duration::from_secs(30 * 60)
    } else {
        HTTP_TIMEOUT
    }
}

pub(crate) fn rpc_method_with_timeout(
    method: &str,
    args: Vec<String>,
    test_timeout: Option<Duration>,
) -> Result<Value> {
    let scope = if matches!(
        method,
        "cli.progress" | "runtime.status" | "assets.status" | "model.catalog" | "model.progress"
    ) {
        None
    } else {
        Some(request_scope(&health()?)?)
    };
    let url = format!("{}/api/rpc", rpc_base_url());
    let request_id = uuid::Uuid::new_v4().to_string();
    let operation_id = uuid::Uuid::new_v4().to_string();
    let body = json!({
        "v": crate::rpc_worker::PROTOCOL_V,
        "id": request_id,
        "operation_id": operation_id.clone(),
        "idempotency_key": operation_id,
        "scope": scope,
        "method": method,
        "args": args,
        "lifecycle": if method == "runtime.stop" { Some("coordinator-v1") } else { None },
    });
    let timeout = rpc_timeout(method, &args, test_timeout);
    let resp = send_loopback(agent().post(&url).timeout(timeout), |request| {
        request.send_json(body.clone())
    })
    .map_err(|error| {
        if method == "cli.exec"
            && matches!(
                error.downcast_ref::<RuntimeError>(),
                Some(RuntimeError::Transport(_))
            )
        {
            RuntimeError::OutcomeUnknown {
                request_id: body["id"].as_str().unwrap_or_default().to_owned(),
                operation_id: body["operation_id"].as_str().unwrap_or_default().to_owned(),
                detail: error.to_string(),
            }
            .into()
        } else {
            error
        }
    })?;
    let parsed: Value = resp.into_json().map_err(|error| {
        if method == "cli.exec" {
            anyhow::Error::from(RuntimeError::OutcomeUnknown {
                request_id: body["id"].as_str().unwrap_or_default().to_owned(),
                operation_id: body["operation_id"].as_str().unwrap_or_default().to_owned(),
                detail: format!("runtime reply unavailable: {error}"),
            })
        } else {
            anyhow::anyhow!("runtime rpc is not JSON: {error}")
        }
    })?;
    Ok(parsed)
}

pub fn wait_until_down() -> Result<()> {
    for _ in 0..STOP_POLLS {
        if !port_is_open() {
            return Ok(());
        }
        std::thread::sleep(STOP_WAIT);
    }
    bail!("runtime did not exit after stop")
}

/// A closed listener does not prove that the library holder has exited.
pub fn wait_until_exited(pid: u32) -> Result<()> {
    for _ in 0..STOP_POLLS {
        if !process_is_running(pid)? {
            return Ok(());
        }
        std::thread::sleep(STOP_WAIT);
    }
    bail!("runtime listener closed but process {pid} has not exited")
}

pub fn process_is_running(pid: u32) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        anyhow::ensure!(pid != 0, "invalid runtime process identity");
        let own = std::fs::read_to_string("/proc/self/stat")
            .context("runtime process inspection requires procfs")?;
        anyhow::ensure!(
            linux_stat_is_running(&own, std::process::id())?,
            "cannot verify current process namespace"
        );
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => linux_stat_is_running(&stat, pid),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).context("runtime process inspection failed"),
        }
    }
    #[cfg(windows)]
    {
        // Query-limited kernel handles avoid spawning tasklist on every drain
        // poll and retain fail-closed errors for inaccessible process identity.
        Ok(respire_spawn::process_birth(pid)?.is_some())
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid=", "-o", "stat="])
            .output()
            .context("cannot check stopped runtime process")?;
        let text = String::from_utf8_lossy(&output.stdout);
        anyhow::ensure!(
            output.status.success() || output.stderr.is_empty(),
            "runtime process inspection failed"
        );
        let mut fields = text.split_whitespace();
        // Zombies have released their listener, native session and database locks.
        Ok(fields.next() == Some(pid.to_string().as_str())
            && fields.next().is_some_and(|state| !state.starts_with('Z')))
    }
}

#[cfg(target_os = "linux")]
fn linux_stat_is_running(stat: &str, pid: u32) -> Result<bool> {
    anyhow::ensure!(
        stat.starts_with(&format!("{pid} (")),
        "runtime process PID mismatch"
    );
    let (_, fields) = stat
        .rsplit_once(')')
        .context("runtime process name delimiter missing")?;
    let state = fields
        .split_whitespace()
        .next()
        .context("runtime process state missing")?;
    anyhow::ensure!(
        state.len() == 1 && "RSDZTtXxKWPI".contains(state),
        "runtime process state is invalid"
    );
    // Zombies have exited and released library locks. Unknown states fail closed.
    Ok(state != "Z")
}

#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeProcessIdentity {
    pub started_at: String,
    pub executable: String,
}

/// An endpoint PID is only a locator. Verify runtime arguments and creation time
/// before waiting, then compare again before forcefully terminating the process.
fn runtime_role_arguments(executable: &Path, args: &[&str]) -> bool {
    let image_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.strip_suffix(" (deleted)").unwrap_or(name));
    let standalone = image_name == Some("rsrs-runtime");
    if standalone {
        if args.get(1) == Some(&"--runtime-internal") {
            return matches!(&args[2..], ["--runtime-background-internal", "--port", port]
                if port.parse::<u16>().is_ok_and(|port| port > 0));
        }
        let mut args = args.iter().copied().skip(1);
        while let Some(argument) = args.next() {
            match argument {
                "--json" | "--supervised" | "serve" => {}
                "runtime" if args.next() == Some("start") => {}
                "--host" if args.next().is_some_and(|value| !value.is_empty()) => {}
                "--port"
                    if args
                        .next()
                        .and_then(|value| value.parse::<u16>().ok())
                        .is_some_and(|port| port > 0) => {}
                "--data-dir" if args.next().is_some() => {}
                _ => return false,
            }
        }
        // Bare invocation serves too; consumed option values are never modes.
        return true;
    }
    if image_name != Some("rsrs") {
        return false;
    }
    if args.contains(&"--runtime-internal")
        || (args.contains(&"web") && args.contains(&"--internal"))
    {
        return true;
    }
    foreground_runtime_arguments(args)
}

fn foreground_runtime_arguments(args: &[&str]) -> bool {
    let standalone = args.first().is_some_and(|program|
        Path::new(program).file_name().and_then(|name| name.to_str()) == Some("rsrs-runtime"));
    let mut args = args.iter().copied().skip(1);
    let command = loop {
        match args.next() {
            Some("--json" | "--direct") => continue,
            other => break other,
        }
    };
    (standalone && command == Some("serve"))
        || (command == Some("runtime") && args.next() == Some("run"))
}

#[cfg(target_os = "linux")]
fn linux_process_arguments(command: &[u8]) -> Result<Vec<&str>> {
    command
        .strip_suffix(&[0])
        .context("runtime command line is not terminated")?
        .split(|byte| *byte == 0)
        .map(std::str::from_utf8)
        .collect::<std::result::Result<_, _>>()
        .context("runtime command line is not UTF-8")
}

pub fn runtime_process_identity(pid: u32) -> Result<RuntimeProcessIdentity> {
    anyhow::ensure!(
        pid != std::process::id() && pid_is_respire(pid),
        "cannot verify runtime process {pid}"
    );
    #[cfg(windows)]
    {
        let process = respire_spawn::runtime_process_identity(pid)?
            .context("runtime process disappeared or could not be identified")?;
        let executable = process
            .executable
            .to_str()
            .context("runtime process image is not UTF-8")?
            .to_owned();
        Ok(RuntimeProcessIdentity {
            started_at: process.birth.to_string(),
            executable,
        })
    }
    #[cfg(target_os = "linux")]
    {
        let directory = std::path::PathBuf::from(format!("/proc/{pid}"));
        let command = std::fs::read(directory.join("cmdline"))?;
        let args = linux_process_arguments(&command)?;
        let executable = std::fs::read_link(directory.join("exe"))?;
        anyhow::ensure!(
            runtime_role_arguments(&executable, &args),
            "process {pid} is not a runtime; restart refused"
        );
        let stat = std::fs::read_to_string(directory.join("stat"))?;
        let started_at = stat
            .rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .context("runtime process creation time missing")?
            .to_owned();
        let executable = executable.to_string_lossy().into_owned();
        Ok(RuntimeProcessIdentity {
            started_at,
            executable,
        })
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = std::process::Command::new("ps")
            .args(["-ww", "-p", &pid.to_string(), "-o", "lstart=", "-o", "args="])
            .env("LC_ALL", "C")
            .output()?;
        anyhow::ensure!(output.status.success(), "cannot inspect runtime process {pid}");
        let image = std::process::Command::new("ps")
            .args(["-ww", "-p", &pid.to_string(), "-o", "comm="])
            .env("LC_ALL", "C")
            .output()?;
        anyhow::ensure!(image.status.success(), "cannot inspect runtime process image");
        darwin_runtime_identity(&String::from_utf8(output.stdout)?, &String::from_utf8(image.stdout)?)
    }
}

/// The OS image is a path; the command line is only role evidence. Returning
/// the latter as the image makes background readiness canonicalize argv text.
#[cfg(any(test, all(unix, not(target_os = "linux"))))]
fn darwin_runtime_identity(process: &str, image: &str) -> Result<RuntimeProcessIdentity> {
    let process = process.trim_end();
    let executable = image.trim();
    anyhow::ensure!(executable.starts_with('/') && !executable.contains('\n'),
        "runtime process image is missing or ambiguous");
    let started_at = process.get(..24).context("runtime process creation time missing")?;
    let command = process.get(24..).context("runtime process command missing")?.trim();
    let tail = command.strip_prefix(executable)
        .filter(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace))
        .context("runtime command does not match its process image")?;
    let mut args = vec![executable];
    args.extend(tail.split_whitespace());
    anyhow::ensure!(args.contains(&"--runtime-internal")
        || (args.contains(&"web") && args.contains(&"--internal"))
        || foreground_runtime_arguments(&args), "process is not a runtime; restart refused");
    Ok(RuntimeProcessIdentity { started_at: started_at.to_owned(), executable: executable.to_owned() })
}

pub fn kill_runtime(pid: u32, identity: &RuntimeProcessIdentity) -> Result<()> {
    crate::runtime_policy::require_host("runtime recovery")?;
    anyhow::ensure!(
        pid != std::process::id() && pid_is_respire(pid),
        "refusing to terminate an unverified runtime process {pid}"
    );
    anyhow::ensure!(
        &runtime_process_identity(pid)? == identity,
        "runtime process {pid} changed during shutdown; termination refused"
    );
    #[cfg(windows)]
    {
        let expected = respire_spawn::ProcessIdentity {
            birth: identity
                .started_at
                .parse()
                .context("invalid verified process creation time")?,
            executable: std::path::PathBuf::from(&identity.executable),
        };
        respire_spawn::terminate_runtime(pid, &expected)?;
    }
    #[cfg(target_os = "linux")]
    {
        let expected = respire_spawn::ProcessIdentity {
            birth: identity
                .started_at
                .parse()
                .context("invalid verified process creation time")?,
            executable: std::path::PathBuf::from(&identity.executable),
        };
        respire_spawn::terminate_runtime(pid, &expected)?;
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let status = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()?;
        anyhow::ensure!(
            status.success(),
            "failed to terminate runtime process {pid}"
        );
    }
    Ok(())
}

pub fn kill_pid(pid: u32) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
}

/// Used by tests and doctor: ensure the token file exists without starting HTTP.
pub fn ensure_token_file() -> Result<PathBuf> {
    let token = load_or_create_token()?;
    let _ = token;
    Ok(token_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn darwin_readiness_keeps_the_image_separate_from_arguments() -> Result<()> {
        let birth = "Sun Nov  8 01:02:03 2026";
        let image = "/private/var/folders/long path/rsrs-runtime";
        for arguments in ["--runtime-internal --runtime-background-internal --port 15169",
            "serve --data-dir /private/var/folders/profile with spaces"] {
            let identity = darwin_runtime_identity(&format!("{birth}  {image} {arguments}\n"), &format!("{image}\n"))?;
            assert_eq!(identity.executable, image);
            assert_eq!(identity.started_at, birth);
        }
        for (command, claimed) in [
            (format!("{image} --runtime-internal"), "/foreign/rsrs-runtime"),
            (format!("{image}-other --runtime-internal"), image),
            (format!("{image} --version"), image),
        ] {
            assert!(darwin_runtime_identity(&format!("{birth}  {command}"), claimed).is_err());
        }
        assert!(darwin_runtime_identity("short", image).is_err());
        assert!(darwin_runtime_identity(&format!("{birth}  {image} serve"), "rsrs-runtime").is_err());
        Ok(())
    }


    #[test]
    fn foreground_identity_accepts_standalone_serving_modes_and_option_values() {
        for args in [
            vec!["/tmp/rsrs-runtime", "serve", "--port", "15169"],
            vec!["/tmp/path with spaces/rsrs-runtime", "--json", "serve"],
            vec!["/tmp/rsrs-runtime"],
            vec!["/tmp/rsrs-runtime", "--json", "runtime", "start"],
            vec!["/tmp/rsrs-runtime", "--port", "15169", "serve"],
            vec!["/tmp/rsrs-runtime", "serve", "--data-dir", "--status"],
            vec![
                "/tmp/rsrs-runtime",
                "serve",
                "--data-dir",
                "/tmp/profile",
                "--supervised",
            ],
            vec![
                "/tmp/rsrs-runtime",
                "serve",
                "--data-dir",
                "/tmp/profile",
                "--host",
                "127.0.0.1",
                "--port",
                "15169",
            ],
            vec!["/tmp/rsrs", "runtime", "run"],
            vec!["/tmp/rsrs", "--runtime-internal"],
            vec!["/tmp/rsrs", "web", "--internal"],
        ] {
            assert!(
                runtime_role_arguments(Path::new(args[0]), &args),
                "{args:?}"
            );
        }
    }

    #[test]
    fn foreground_identity_rejects_conflicting_or_incomplete_standalone_arguments() {
        for args in [
            vec!["/tmp/rsrs", "serve"],
            vec!["/tmp/unrelated", "serve"],
            vec!["/tmp/rsrs-runtime", "--status"],
            vec!["/tmp/rsrs-runtime", "serve", "--status"],
            vec!["/tmp/rsrs-runtime", "serve", "--stop"],
            vec!["/tmp/rsrs-runtime", "serve", "--version"],
            vec!["/tmp/rsrs-runtime", "runtime", "start", "--stop"],
            vec!["/tmp/rsrs-runtime", "runtime", "status"],
            vec!["/tmp/rsrs-runtime", "runtime"],
            vec!["/tmp/rsrs-runtime", "serve", "--data-dir"],
            vec!["/tmp/rsrs-runtime", "serve", "--host"],
            vec!["/tmp/rsrs-runtime", "serve", "--host", ""],
            vec!["/tmp/rsrs-runtime", "serve", "--port"],
            vec!["/tmp/rsrs-runtime", "serve", "--port", "0"],
            vec!["/tmp/rsrs-runtime", "serve", "--port", "65536"],
            vec!["/tmp/rsrs-runtime", "serve", "--port", "--status"],
            vec!["/tmp/rsrs-runtime", "serve", "--direct"],
            vec!["/tmp/rsrs-runtime", "serve", "--core-worker-internal"],
            vec!["/tmp/rsrs-runtime", "serve", "--runtime-internal"],
            vec!["/tmp/rsrs-runtime", "--runtime-internal"],
            vec!["/tmp/rsrs-runtime", "web", "--internal"],
            vec!["/tmp/rsrs-runtime", "--status", "--data-dir", "serve"],
            vec!["/tmp/rsrs-runtime", "serve", "unknown"],
        ] {
            assert!(
                !runtime_role_arguments(Path::new(args[0]), &args),
                "{args:?}"
            );
        }
    }

    #[test]
    fn background_identity_requires_the_exact_internal_launcher_shape() {
        for image in ["/tmp/rsrs-runtime", "/tmp/rsrs-runtime (deleted)"] {
            assert!(runtime_role_arguments(Path::new(image),
                &["rsrs-runtime", "--runtime-internal", "--runtime-background-internal", "--port", "15169"]));
        }
        for args in [
            vec!["rsrs-runtime", "--runtime-background-internal"],
            vec!["rsrs-runtime", "--runtime-internal", "--runtime-background-internal", "--port"],
            vec!["rsrs-runtime", "--runtime-internal", "--runtime-background-internal", "--port", "0"],
            vec!["rsrs-runtime", "--runtime-internal", "--runtime-background-internal", "--port", "15169", "--status"],
            vec!["rsrs-runtime", "--runtime-internal", "--runtime-background-internal", "--data-dir", "15169"],
        ] {
            assert!(!runtime_role_arguments(Path::new("/tmp/rsrs-runtime"), &args));
        }
        assert!(!runtime_role_arguments(Path::new("/tmp/foreign"),
            &["rsrs-runtime", "--runtime-internal", "--runtime-background-internal", "--port", "15169"]));
    }

    #[test]
    fn runtime_role_uses_the_executable_not_argv_zero() {
        assert!(!runtime_role_arguments(
            Path::new("/tmp/rsrs"),
            &["rsrs-runtime", "serve"]
        ));
        assert!(!runtime_role_arguments(
            Path::new("/tmp/foreign"),
            &["rsrs", "--runtime-internal"]
        ));
        assert!(!runtime_role_arguments(
            Path::new("/tmp/rsrs-runtime"),
            &["rsrs", "--runtime-internal"]
        ));
        assert!(runtime_role_arguments(
            Path::new("/tmp/rsrs-runtime"),
            &["rsrs", "serve"]
        ));
        assert!(runtime_role_arguments(
            Path::new("/tmp/rsrs-runtime (deleted)"),
            &["rsrs-runtime", "serve"]
        ));
        assert!(runtime_role_arguments(
            Path::new("/tmp/rsrs (deleted)"),
            &["rsrs", "runtime", "run"]
        ));
        assert!(!runtime_role_arguments(
            Path::new("/tmp/foreign (deleted)"),
            &["rsrs-runtime", "serve"]
        ));
        assert!(!runtime_role_arguments(
            Path::new("/tmp/rsrs-runtime (deleted) suffix"),
            &["rsrs-runtime", "serve"]
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_arguments_preserve_empty_values_and_reject_malformed_input() -> Result<()> {
        assert_eq!(
            linux_process_arguments(b"rsrs-runtime\0serve\0")?,
            ["rsrs-runtime", "serve"]
        );
        assert_eq!(
            linux_process_arguments(b"rsrs-runtime\0--host\0\0")?,
            ["rsrs-runtime", "--host", ""]
        );
        assert!(!runtime_role_arguments(
            Path::new("rsrs-runtime"),
            &linux_process_arguments(b"rsrs-runtime\0--host\0\0")?
        ));
        assert_eq!(
            linux_process_arguments(b"rsrs-runtime\0serve\0--data-dir\0\0")?,
            ["rsrs-runtime", "serve", "--data-dir", ""]
        );
        assert!(runtime_role_arguments(
            Path::new("rsrs-runtime"),
            &linux_process_arguments(b"rsrs-runtime\0serve\0--data-dir\0\0")?
        ));
        assert!(!runtime_role_arguments(
            Path::new("rsrs-runtime"),
            &linux_process_arguments(b"rsrs-runtime\0serve\0\0")?
        ));
        assert!(linux_process_arguments(b"").is_err());
        assert!(linux_process_arguments(b"rsrs-runtime\0serve").is_err());
        assert!(linux_process_arguments(b"rsrs-runtime\0\xff\0").is_err());
        Ok(())
    }
    fn valid_timeout_args(args: &[&str]) -> Vec<String> {
        use clap::Parser;
        crate::cli_def::Cli::try_parse_from(std::iter::once("rsrs").chain(args.iter().copied()))
            .expect("timeout regression must exercise valid CLI argv");
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn rpc_timeout_recognizes_commands_after_global_values_and_equals_forms() {
        for args in [
            vec!["sync"],
            vec!["--json", "--progress-id", "request-one", "sync"],
            vec!["--progress-id=import", "--model-task-id=task-one", "sync"],
            vec!["--model-task-id", "task-one", "import", "synthetic.json"],
            vec!["import", "synthetic.json"],
            vec!["reembed"],
            vec!["model", "install"],
            vec!["--json", "--progress-id", "model", "model", "install-m3"],
            vec!["model", "--model-task-id", "install", "activate", "m3"],
        ] {
            let parsed = valid_timeout_args(&args);
            assert_eq!(
                rpc_timeout("cli.exec", &parsed, None),
                Duration::from_secs(30 * 60),
                "{args:?}"
            );
        }
    }

    #[test]
    fn rpc_timeout_does_not_treat_tracking_values_or_other_methods_as_commands() {
        for args in [
            vec!["--progress-id", "sync", "list"],
            vec!["--model-task-id", "import", "status"],
            vec!["model", "--progress-id", "install", "engine"],
            vec!["show", "synthetic-id"],
        ] {
            let parsed = valid_timeout_args(&args);
            assert_eq!(
                rpc_timeout("cli.exec", &parsed, None),
                HTTP_TIMEOUT,
                "{args:?}"
            );
        }
        let long = valid_timeout_args(&["--progress-id", "request-one", "sync"]);
        assert_eq!(
            rpc_timeout("cli.progress", &long, None),
            Duration::from_secs(1)
        );
        assert_eq!(
            rpc_timeout("model.control", &long, None),
            Duration::from_secs(3)
        );
        assert_eq!(
            rpc_timeout("runtime.result", &["sync".into()], None),
            HTTP_TIMEOUT
        );
        assert_eq!(
            rpc_timeout("model.control", &long, Some(Duration::from_millis(7))),
            Duration::from_millis(7)
        );
    }

    #[test]
    fn response_after_client_deadline_reports_unknown_and_can_be_inspected_without_replay(
    ) -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let directory = tempfile::tempdir()?;
        let server =
            tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow::anyhow!("{error}"))?;
        let port = server
            .server_addr()
            .to_ip()
            .context("missing test address")?
            .port();
        let previous: Vec<_> = ["RSRS_RPC_PORT", "RSRS_DATA_DIR", "RSRS_RPC_TOKEN"]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("RSRS_RPC_PORT", port.to_string());
        std::env::set_var("RSRS_DATA_DIR", directory.path());
        std::env::remove_var("RSRS_RPC_TOKEN");
        let test_root = directory.path().to_path_buf();
        let actor = std::thread::spawn(move || -> Result<String> {
            fn receive_rpc(
                server: &tiny_http::Server,
                root: &std::path::Path,
            ) -> Result<tiny_http::Request> {
                loop {
                    let request = server
                        .recv_timeout(Duration::from_secs(2))?
                        .context("RPC never arrived")?;
                    if request.url() == "/api/health" {
                        request.respond(tiny_http::Response::from_string(json!({
                            "server":"respire", "bin":"fixture", "pid":4321, "v":1,
                            "installation_root":root, "account_id":"account-1", "instance_id":"instance-1", "generation":7,
                        }).to_string()))?;
                    } else {
                        return Ok(request);
                    }
                }
            }
            let mut request = receive_rpc(&server, &test_root)?;
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body)?;
            let write: Value = serde_json::from_str(&body)?;
            anyhow::ensure!(write["method"] == "cli.exec", "unexpected first request");
            anyhow::ensure!(
                write["id"].is_string()
                    && write["operation_id"].is_string()
                    && write["id"] != write["operation_id"],
                "request and operation identities must be distinct"
            );
            let id = write["id"].as_str().context("missing write ID")?.to_owned();
            let operation_id = write["operation_id"]
                .as_str()
                .context("missing operation ID")?
                .to_owned();
            std::thread::sleep(Duration::from_millis(150));
            let _ = request.respond(tiny_http::Response::from_string(
                json!({"v":1,"id":id,"ok":true}).to_string(),
            ));
            let mut inspect = receive_rpc(&server, &test_root)?;
            body.clear();
            inspect.as_reader().read_to_string(&mut body)?;
            let query: Value = serde_json::from_str(&body)?;
            anyhow::ensure!(
                write["scope"]
                    == json!({"account_id":"account-1","instance_id":"instance-1","generation":7})
                    && query["scope"] == write["scope"],
                "request scope changed or was omitted"
            );
            anyhow::ensure!(
                query["method"] == "runtime.result" && query["args"][0] == operation_id,
                "client replayed or inspected the wrong write"
            );
            inspect.respond(tiny_http::Response::from_string(json!({"v":1,"id":query["id"],"ok":true,"envelope":{"summary":{"state":"completed","request_id":query["id"],"operation_id":operation_id,"response":{"ok":true,"committed":true,"id":id}}}}).to_string()))?;
            Ok(operation_id)
        });
        let result = (|| -> Result<()> {
            let error = rpc_method_with_timeout(
                "cli.exec",
                vec!["remember".into(), "synthetic write".into()],
                Some(Duration::from_millis(50)),
            )
            .err()
            .context("delayed write unexpectedly completed within deadline")?;
            let id = match error.downcast_ref::<RuntimeError>() {
                Some(RuntimeError::OutcomeUnknown { operation_id, .. }) => operation_id.clone(),
                _ => anyhow::bail!(
                    "ambiguous transport failure was not marked outcome_unknown: {error}"
                ),
            };
            let inspected = rpc_method_with_timeout(
                "runtime.result",
                vec![id.clone()],
                Some(Duration::from_secs(2)),
            )?;
            anyhow::ensure!(
                inspected["envelope"]["summary"]["state"] == "completed",
                "inspection failed: {inspected}"
            );
            let seen = actor
                .join()
                .map_err(|_| anyhow::anyhow!("test transport actor panicked"))??;
            anyhow::ensure!(seen == id, "operation ID changed");
            Ok(())
        })();
        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        result
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_liveness_keeps_pid_and_state_checks_strict() -> Result<()> {
        assert!(linux_stat_is_running("123 (rsrs) S 1 2 3", 123)?);
        assert!(linux_stat_is_running(
            "123 (name with ) parentheses) R 1 2 3",
            123
        )?);
        assert!(!linux_stat_is_running("123 (rsrs) Z 1 2 3", 123)?);
        for invalid in [
            "124 (rsrs) S 1",
            "123 rsrs S",
            "123 (rsrs)",
            "123 (rsrs) ? 1",
        ] {
            assert!(linux_stat_is_running(invalid, 123).is_err());
        }
        assert!(process_is_running(std::process::id())?);
        assert!(process_is_running(0).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exited_child_is_not_a_running_library_holder() -> Result<()> {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()?;
        let exited = wait_until_exited(child.id());
        child.wait()?;
        exited
    }

    #[test]
    fn port_is_open_sees_local_listener() -> Result<(), String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
        let port = listener.local_addr().map_err(|err| err.to_string())?.port();
        if !port_is_open_on(port) {
            return Err(format!("listener on {port} should be open"));
        }
        Ok(())
    }

    #[test]
    fn default_port_is_15169() -> Result<(), String> {
        if DEFAULT_RPC_PORT != 15169 {
            return Err(format!("port {}", DEFAULT_RPC_PORT));
        }
        Ok(())
    }

    #[test]
    fn rpc_port_reads_env() -> Result<(), String> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = respire_app::env::var("RSRS_RPC_PORT").ok();
        std::env::set_var("RSRS_RPC_PORT", "26111");
        let got = rpc_port();
        match prev {
            Some(v) => std::env::set_var("RSRS_RPC_PORT", v),
            None => std::env::remove_var("RSRS_RPC_PORT"),
        }
        if got != 26111 {
            return Err(format!("got {got}"));
        }
        Ok(())
    }

    #[test]
    fn origin_empty_is_cli() -> Result<(), String> {
        if !origin_ok("", "http://127.0.0.1:15169") {
            return Err("empty origin should pass".into());
        }
        if origin_ok("https://evil.example", "http://127.0.0.1:15169") {
            return Err("evil origin should fail".into());
        }
        if !origin_ok("http://127.0.0.1:15169", "http://127.0.0.1:15169") {
            return Err("same origin should pass".into());
        }
        if !origin_ok("http://localhost:29123", "http://127.0.0.1:29123") {
            return Err("localhost must use the actual bound port".into());
        }
        if origin_ok("http://localhost:15169", "http://127.0.0.1:29123") {
            return Err("default-port origin must not match a different listener".into());
        }
        if !origin_ok("http://127.0.0.1", "http://127.0.0.1:80")
            || !origin_ok("http://localhost", "http://127.0.0.1:80")
            || !origin_ok("http://[::1]", "http://[::1]:80")
        {
            return Err("HTTP default-port origins must use their canonical form".into());
        }
        if origin_ok("http://localhost", "http://127.0.0.1:29123")
            || origin_ok("http://evil.example", "http://127.0.0.1:80")
        {
            return Err("canonical origins must not exempt other ports or hosts".into());
        }
        Ok(())
    }

    #[test]
    fn health_shape() -> Result<(), String> {
        let ours = json!({"server":"respire","bin":"1.0.6-dev.2","pid":1,"v":1,"exe":""});
        if !is_our_health(&ours) {
            return Err("ours".into());
        }
        if is_our_health(&json!({"server":"nginx"})) {
            return Err("nginx".into());
        }
        Ok(())
    }

    #[test]
    fn version_newer_dev() -> Result<(), String> {
        if version_cmp("1.0.6-dev.2", "1.0.6-dev.1") != std::cmp::Ordering::Greater {
            return Err("dev.2 should be newer".into());
        }
        if version_cmp("1.0.6-dev.1", "1.0.6-dev.1") != std::cmp::Ordering::Equal {
            return Err("equal".into());
        }
        Ok(())
    }

    #[test]
    fn token_env_beats_file() -> Result<(), String> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let prev_data = respire_app::env::var("RSRS_DATA_DIR").ok();
        let prev_tok = respire_app::env::var("RSRS_RPC_TOKEN").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::set_var("RSRS_RPC_TOKEN", "from-env");
        let got = load_token();
        match prev_data {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        match prev_tok {
            Some(v) => std::env::set_var("RSRS_RPC_TOKEN", v),
            None => std::env::remove_var("RSRS_RPC_TOKEN"),
        }
        if got.as_deref() != Some("from-env") {
            return Err(format!("{got:?}"));
        }
        Ok(())
    }

    #[test]
    fn persist_and_load_token_file() -> Result<(), String> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let prev_data = respire_app::env::var("RSRS_DATA_DIR").ok();
        let prev_tok = respire_app::env::var("RSRS_RPC_TOKEN").ok();
        std::env::remove_var("RSRS_RPC_TOKEN");
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        persist_token("file-token").map_err(|e| e.to_string())?;
        let got = load_token();
        match prev_data {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        match prev_tok {
            Some(v) => std::env::set_var("RSRS_RPC_TOKEN", v),
            None => std::env::remove_var("RSRS_RPC_TOKEN"),
        }
        if got.as_deref() != Some("file-token") {
            return Err(format!("{got:?}"));
        }
        Ok(())
    }
}

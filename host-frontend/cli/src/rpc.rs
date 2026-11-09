//! Local authenticated runtime transport (client face).
//!
//! Commands connect only to the independent Runtime over loopback HTTP and
//! auto-start it through the lifecycle coordinator. No in-process dispatch.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::output::{ResultEnvelope, Status as OutputStatus};

const START_POLLS: usize = 100;
const START_WAIT: Duration = Duration::from_millis(150);

pub(crate) type RpcResponse = respire_protocol::RpcResponse<ResultEnvelope>;

#[derive(Clone, Debug)]
pub(crate) struct RuntimeFlags {
    pub port: Option<u16>,
    pub host: String,
    pub status: bool,
    pub stop: bool,
}

pub fn call_from_argv() -> Result<()> {
    call_from_argv_with_start(true)
}

/// Poll the existing loopback runtime without lifecycle or recovery writes.
pub fn call_existing_from_argv() -> Result<()> {
    call_from_argv_with_start(false)
}

fn call_from_argv_with_start(auto_start: bool) -> Result<()> {
    let mut args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--direct" && arg != "--client-only")
        .collect();
    let json = args.iter().any(|arg| arg == "--json")
        || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true");
    crate::set_json_mode(json);
    if let Some(id) = crate::progress::remote_id() {
        let insertion = args
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or(args.len());
        let mut progress_args = vec!["--progress-id".to_owned(), id.clone()];
        if command_name(&args) == Some("model") && !args.iter().any(|arg| arg == "--model-task-id")
        {
            progress_args.extend(["--model-task-id".to_owned(), id]);
        }
        args.splice(insertion..insertion, progress_args);
    }
    let response = call_method("cli.exec", args, auto_start)?;
    render_response(response, json)
}

pub fn runtime_is_up() -> bool {
    call_method("runtime.status", Vec::new(), false).is_ok()
}

pub(crate) fn foreground_progress(id: &str) -> Result<Value> {
    let response = call_method("cli.progress", vec![id.to_owned()], false)?;
    anyhow::ensure!(response.ok, "runtime progress unavailable");
    Ok(response
        .envelope
        .map(|envelope| envelope.summary)
        .unwrap_or(Value::Null))
}

/// Run one command through the resident runtime and return its JSON envelope.
/// Starts the runtime if it is not up yet. The envelope is returned even when
/// the command status is fail, so a dashboard can show the failing checks.
pub fn query_json(args: Vec<String>) -> Result<serde_json::Value> {
    query_json_with_start(args, true)
}

/// TUI polling must not start or replace a runtime while a host action is running.
pub(crate) fn query_existing_json(args: Vec<String>) -> Result<serde_json::Value> {
    query_json_with_start(args, false)
}

fn query_json_with_start(args: Vec<String>, auto_start: bool) -> Result<serde_json::Value> {
    let mut full = Vec::with_capacity(args.len() + 1);
    full.push("--json".to_owned());
    full.extend(args);
    let response = call_method("cli.exec", full, auto_start)?;
    if let Some(mut envelope) = response.envelope {
        envelope.ensure_failure_diagnostics();
        return Ok(serde_json::to_value(envelope).context("runtime envelope could not be encoded")?);
    }
    let err = response
        .error
        .unwrap_or_else(|| "runtime returned an empty response".to_owned());
    bail!("{err}")
}

/// Pid, web URL and binary version of the resident runtime, if it answers.
pub fn runtime_brief() -> Option<(u32, String, String)> {
    let response = call_method("runtime.status", Vec::new(), false).ok()?;
    Some((
        response.pid.unwrap_or(0),
        response.web_url.unwrap_or_default(),
        response.bin,
    ))
}

pub fn stop_if_running() -> Result<()> {
    let _takeover = crate::runtime_policy::takeover_lock()?;
    if crate::autostart::stop_managed_locked()? {
        return Ok(());
    }
    if let Some(health) = probe_runtime()? {
        stop_occupant(health.pid)?;
    }
    Ok(())
}

/// Restart after an authenticated drain, or complete evidence of an exited owner.
pub(crate) fn restart_runtime(timeout: Duration) -> Result<Value> {
    crate::runtime_policy::require_host("runtime restart")?;
    crate::runtime_fetch::require_automatic_migration_safe()?;
    let _takeover = crate::runtime_policy::takeover_lock()?;
    crate::runtime_fetch::require_automatic_migration_safe()?;
    // An unavailable health response is not permission to discover or kill a PID.
    let health = probe_runtime().context(
        "runtime restart blocked: owner health is unavailable; no process was forced to exit",
    )?;
    let stale = if health.is_none() && endpoint_path().try_exists()? {
        Some(crate::autostart::StaleOwner::prepare_locked()
            .context("runtime restart blocked: stale owner could not be verified")?)
    } else {
        None
    };
    let mut maintenance = crate::autostart::restart_maintenance_locked()?;
    if let Some(stale) = stale {
        stale.remove_endpoint_locked()?;
    }
    crate::autostart::restart_stage("restart_probe");
    let stopped_pid = health.as_ref().map(|value| value.pid);
    if crate::autostart::managed_enabled()?
        && health
            .as_ref()
            .is_some_and(|value| !value.inference_stalled())
    {
        crate::autostart::restart_stage("restart_managed");
        ensure_daemon_locked()?;
    } else {
        if let Some(health) = health.as_ref() {
            crate::autostart::restart_stage("restart_stop");
            drain_occupant(health, timeout)?;
        }
        crate::autostart::restart_stage("restart_start");
        ensure_daemon_locked()?;
    }
    let ready = crate::net_rpc::health()?;
    if !respire_client_host::settings::off_mode()? {
        verify_open_store(&respire_client_host::config::control_roots()?.1)?;
    }
    maintenance.finish()?;
    crate::autostart::restart_stage("restart_ready");
    Ok(json!({"state":"ready", "stopped_pid":stopped_pid, "pid":ready.pid,
        "forced":false, "data_dir":ready.data_dir, "version":ready.bin}))
}

/// Host profile changes release the old library before starting its successor.
pub fn recover_interrupted_login() -> Result<()> {
    recover_login_for(LoginRecoveryCaller::OrdinaryRequest)
}

/// Account control resumes its own operation, but first recovers old journals.
pub fn recover_legacy_login_before_account_control() -> Result<()> {
    recover_login_for(LoginRecoveryCaller::AccountControl)
}

#[derive(Clone, Copy)]
enum LoginRecoveryCaller {
    OrdinaryRequest,
    AccountControl,
}

fn needs_legacy_login_recovery(
    state: respire_protocol::host_control::HostLoginRecoveryState,
    caller: LoginRecoveryCaller,
) -> Result<bool> {
    use respire_protocol::host_control::HostLoginRecoveryState;
    match state {
        HostLoginRecoveryState::Clear => Ok(false),
        HostLoginRecoveryState::LegacyPending => Ok(true),
        HostLoginRecoveryState::OperationPending => match caller {
            LoginRecoveryCaller::AccountControl => Ok(false),
            LoginRecoveryCaller::OrdinaryRequest => anyhow::bail!(
                "authentication recovery requires the original operation; query its result before continuing"),
        },
    }
}

fn recover_login_for(caller: LoginRecoveryCaller) -> Result<()> {
    respire_client_host::config::control_roots()?;
    // Presence is only a launch hint; Runtime alone parses the private journal.
    if !respire_client_host::paths::client_config_path()
        .with_file_name(".login-recovery.json").try_exists()? {
        return Ok(());
    }
    let takeover = crate::runtime_policy::takeover_lock()?;
    if !needs_legacy_login_recovery(crate::autostart::login_recovery_status(&takeover)?, caller)? {
        return Ok(());
    }
    let mut maintenance =
        crate::autostart::with_explicit_recovery(crate::autostart::begin_maintenance_locked)?;
    if let Some(health) = probe_runtime()? {
        maintenance.drain_runtime(&health)?;
    }
    let recovered = crate::autostart::recover_legacy_login_locked(&takeover, &mut maintenance)?;
    maintenance.resume_managed_runtime()?;
    maintenance.finish()?;
    if recovered {
        eprintln!(
            "Recovered an interrupted login; the original account and configuration were restored."
        );
    }
    Ok(())
}

/// Listener readiness alone is insufficient for a snapshot commit: the actor
/// must have opened, checked and bound the actual restored database first.
pub fn verify_snapshot_store(root: &std::path::Path, id: &str) -> Result<()> {
    verify_runtime_store(root, Some(id))
}
pub fn verify_open_store(root: &std::path::Path) -> Result<()> {
    verify_runtime_store(root, None)
}
fn verify_runtime_store(root: &std::path::Path, id: Option<&str>) -> Result<()> {
    for _ in 0..START_POLLS {
        let health = crate::net_rpc::health()?;
        anyhow::ensure!(
            !health.data_dir.is_empty()
                && crate::mcp::same_path(std::path::Path::new(&health.data_dir), root),
            "snapshot runtime profile changed during verification"
        );
        if health.store_ready
            && id.is_none_or(|id| health.snapshot_restore_id.as_deref() == Some(id))
        {
            return Ok(());
        }
        std::thread::sleep(START_WAIT);
    }
    bail!("restored runtime did not confirm an opened and verified snapshot store")
}

pub fn change_profile(change: impl FnOnce() -> Result<()>) -> Result<()> {
    change_profile_with_rollback(change, || Ok(()))
}

/// Asset maintenance restores a running owner without starting an idle runtime.
pub fn change_host_assets(change: impl FnOnce() -> Result<()>) -> Result<()> {
    change_profile_inner(change, || Ok(()), || Ok(()), false)
}

pub fn change_profile_with_rollback(
    change: impl FnOnce() -> Result<()>,
    rollback: impl FnOnce() -> Result<()>,
) -> Result<()> {
    change_profile_with_verification(change, rollback, || Ok(()))
}

pub fn change_profile_with_verification(
    change: impl FnOnce() -> Result<()>,
    rollback: impl FnOnce() -> Result<()>,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    change_profile_inner(change, rollback, verify, true)
}

fn change_profile_inner(
    change: impl FnOnce() -> Result<()>,
    rollback: impl FnOnce() -> Result<()>,
    verify: impl FnOnce() -> Result<()>,
    start_runtime: bool,
) -> Result<()> {
    crate::progress::phase("\u{534f}\u{8c03}\u{8d26}\u{6237}\u{64cd}\u{4f5c}\u{ff1b}\u{7b49}\u{5f85}\u{5f53}\u{524d} runtime \u{91ca}\u{653e}", "Coordinating account operation; waiting for current runtime to release");
    let _takeover = crate::runtime_policy::takeover_lock()?;
    let original_runtime = probe_runtime()?;
    anyhow::ensure!(
        original_runtime.is_some() || !endpoint_path().exists(),
        "profile change blocked: recorded owner has no verifiable health/drain receipt"
    );
    let was_running = original_runtime.is_some();
    let mut maintenance = crate::autostart::begin_maintenance_locked()?;
    let config_path = respire_client_host::paths::client_config_path();
    let original = match std::fs::read(&config_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let backup = if let Some(bytes) = original.as_ref() {
        let parent = config_path
            .parent()
            .context("configuration has no parent directory")?;
        let path = parent.join(format!(
            ".client-before-switch-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Some(path)
    } else {
        None
    };
    if let Some(health) = original_runtime.as_ref() {
        maintenance.drain_runtime(health)?;
    }
    let changed = change().and_then(|_| {
        if !start_runtime && !was_running {
            return Ok(());
        }
        crate::progress::phase("\u{542f}\u{52a8} runtime\u{ff1b}\u{6838}\u{5bf9}\u{8d26}\u{6237}\u{548c}\u{8def}\u{5f84}", "Starting runtime; verifying account and path");
        ensure_daemon_locked()
    }).and_then(|_| verify());
    if let Err(error) = changed {
        let cleanup = if start_runtime || was_running {
            probe_runtime().and_then(|health| match health {
                Some(health) => maintenance.drain_runtime(&health),
                None => Ok(()),
            })
        } else {
            Ok(())
        };
        let mut failures = Vec::new();
        if let Err(error) = &cleanup {
            failures.push(format!("target runtime cleanup failed: {error:#}"));
        }
        if let Err(error) = rollback() {
            failures.push(format!("account session rollback failed: {error:#}"));
        }
        // Startup failure must restore the original selection and all API fields,
        // including the distinction between an absent config and an empty one.
        let restored = match original {
            Some(bytes) => {
                let temporary = config_path.with_file_name(format!(
                    ".client-restore-{}.json",
                    uuid::Uuid::new_v4().simple()
                ));
                (|| -> Result<()> {
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    let mut file = options.open(&temporary)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    drop(file);
                    std::fs::rename(&temporary, &config_path)?;
                    Ok(())
                })()
            }
            None => match std::fs::remove_file(&config_path) {
                Ok(()) => Ok(()),
                Err(remove) if remove.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(remove) => Err(remove.into()),
            },
        };
        if let Err(error) = &restored {
            failures.push(format!("configuration rollback failed: {error:#}"));
        }
        if was_running && cleanup.is_ok() && restored.is_ok() {
            if let Err(error) = ensure_daemon_locked() {
                failures.push(format!("original runtime restart failed: {error:#}"));
            }
        }
        if !failures.is_empty() {
            if let Some(path) = backup {
                failures.push(format!("original configuration backup: {}", path.display()));
            }
            return Err(error.context(failures.join("; ")));
        }
        if let Some(path) = backup {
            if let Err(cleanup) = std::fs::remove_file(&path) {
                return Err(error.context(format!(
                    "configuration restored; backup retained at {}: {cleanup}",
                    path.display()
                )));
            }
        }
        maintenance.finish()?;
        return Err(error);
    }
    if let Some(path) = backup {
        if let Err(error) = std::fs::remove_file(&path) {
            eprintln!(
                "profile verified; configuration backup retained at {}: {error}",
                path.display()
            );
        }
    }
    maintenance.finish()?;
    Ok(())
}

pub fn runtime_entry(flags: RuntimeFlags) -> Result<()> {
    if flags.status {
        return match call_method("runtime.status", Vec::new(), false) {
            Ok(response) => {
                if crate::json_mode() {
                    return crate::emit_result(ResultEnvelope::new(
                        "runtime",
                        OutputStatus::Ok,
                        json!({"state":"up","pid":response.pid,"url":response.web_url,"data_dir":response.data_dir}),
                        Vec::new(),
                    ));
                }
                println!(
                    "runtime=up pid={} url={} data_dir={}",
                    response.pid.unwrap_or(0),
                    response.web_url.as_deref().unwrap_or(""),
                    response.data_dir.as_deref().unwrap_or("")
                );
                Ok(())
            }
            Err(error) => {
                if crate::json_mode() {
                    let mut envelope = ResultEnvelope::new(
                        "runtime",
                        OutputStatus::Warn,
                        json!({"state":"down"}),
                        Vec::new(),
                    );
                    envelope.errors.push(format!("{error:#}"));
                    return crate::emit_result(envelope);
                }
                eprintln!("{error:#}");
                crate::set_exit_code(2);
                Ok(())
            }
        };
    }
    if flags.stop {
        stop_if_running()?;
        if crate::json_mode() {
            return crate::emit_result(ResultEnvelope::new(
                "runtime",
                OutputStatus::Ok,
                json!({"state":"stopped"}),
                Vec::new(),
            ));
        }
        println!("runtime=stopped");
        return Ok(());
    }
    crate::runtime_policy::require_host("runtime startup")?;
    let executable = resolve_runtime_executable()?;
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "serve".into(),
        "--data-dir".into(),
        respire_client_host::paths::main_data_dir().into_os_string(),
        "--host".into(),
        flags.host.into(),
    ];
    if let Some(port) = flags.port {
        arguments.push("--port".into());
        arguments.push(port.to_string().into());
    }
    let managed_id = crate::autostart::managed_id();
    if managed_id.is_some() {
        arguments.push("--supervised".into());
    }
    let (mut child, _instance_id) =
        crate::autostart::spawn_authorized_runtime(&executable, &arguments, managed_id)
            .context("failed to start host runtime")?;
    // The forwarding host stays alive for the serving process's whole lifetime
    // and passes its exit code through unchanged.
    let status = child
        .wait()
        .context("failed to wait for the host runtime")?;
    crate::set_exit_code(status.code().unwrap_or(1));
    Ok(())
}

/// Detect an explicit CLI selection so callers can reject it, never authorize it.
pub(crate) fn explicit_cli_runtime(executable: &std::path::Path) -> Result<bool> {
    if let Some(selected) = crate::embedding::selection() {
        anyhow::ensure!(crate::mcp::same_path(executable, selected.verify()?.path()),
            "embedded host selected a different Runtime image");
        return Ok(false);
    }
    let Some(selected) = respire::env::var("RSRS_RUNTIME_BIN")
        .ok()
        .map(|value| PathBuf::from(value.trim()))
        .filter(|path| !path.as_os_str().is_empty())
    else {
        return Ok(false);
    };
    Ok(crate::mcp::same_path(executable, &selected)
        && crate::mcp::same_path(executable, &std::env::current_exe()?))
}

/// Resolution and installation failures stay errors, including typed repair errors.
/// Neither detached, foreground nor supervised startup synthesizes a shim plan.
pub(crate) fn resolve_runtime_executable() -> Result<PathBuf> {
    let executable = match crate::runtime_fetch::resolve_runtime_bin()? {
        crate::runtime_fetch::ResolvedRuntime::Ready(path) => path,
        crate::runtime_fetch::ResolvedRuntime::LegacyCombined(legacy) => {
            crate::runtime_fetch::download_and_install(None, None).with_context(|| {
                format!("independent Runtime installation required; legacy CLI at {} cannot serve automatically", legacy.display())
            })?
        }
    };
    anyhow::ensure!(
        crate::embedding::selection().is_some()
            || !crate::mcp::same_path(&executable, &std::env::current_exe()?),
        "CLI image cannot substitute for the independent Runtime; repair the selected Runtime"
    );
    Ok(executable)
}

fn render_response(response: RpcResponse, json: bool) -> Result<()> {
    if let Some(mut envelope) = response.envelope {
        envelope.ensure_failure_diagnostics();
        crate::progress::finish();
        if json || envelope.summary["skipped"] != true || envelope.summary["mode"] != "off" {
            println!("{}", envelope.render(json)?);
        }
        crate::mark_emitted();
        crate::set_exit_code(response.exit);
        return Ok(());
    }
    bail!(
        "{}",
        response
            .error
            .unwrap_or_else(|| "runtime returned an empty response".to_owned())
    )
}

pub(crate) fn call_method(
    method: &str,
    args: Vec<String>,
    auto_start: bool,
) -> Result<RpcResponse> {
    let auto = auto_start && !crate::net_rpc::no_autostart();
    // Validate/start the runtime for this data directory before submitting work.
    // Once submitted, a disconnect must not cause a mutating command to be replayed.
    if auto {
        ensure_daemon()?;
    } else if method == "cli.exec" && needs_inference(&args) && crate::runtime_policy::client_only()
    {
        anyhow::ensure!(!crate::net_rpc::health()?.inference_stalled(),
            "inference is unresponsive after cancellation; run rsrs from the host terminal to recover the runtime; this request was not submitted");
    }
    let response = http_roundtrip(method, &args)?;
    if !compatible(&response) {
        bail!("local runtime protocol/version mismatch");
    }
    Ok(response)
}

pub(crate) fn call_method_outcome(
    method: &str,
    args: Vec<String>,
    auto_start: bool,
) -> Result<respire_commands::host_hooks::MethodOutcome> {
    call_method(method, args, auto_start).map(|response| {
        respire_commands::host_hooks::MethodOutcome {
            ok: response.ok,
            error: response.error,
            envelope: response.envelope,
        }
    })
}

pub(crate) fn model_control(task_id: &str, cancel: bool) -> Result<Value> {
    let (method, args) = if cancel {
        ("model.control", vec![task_id.to_owned(), "true".to_owned()])
    } else {
        ("model.progress", Vec::new())
    };
    let response = call_method(method, args, false)?;
    anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
    let summary = response
        .envelope
        .map(|envelope| envelope.summary)
        .ok_or_else(|| anyhow::anyhow!("runtime did not return model progress"))?;
    let progress = if cancel {
        summary
    } else {
        summary["operation"].clone()
    };
    model_progress_for_task(progress, task_id, cancel)
}

fn model_progress_for_task(progress: Value, task_id: &str, cancel: bool) -> Result<Value> {
    anyhow::ensure!(
        progress.get("active").and_then(Value::as_bool).is_some(),
        "runtime returned invalid model progress"
    );
    if progress["active"] == true && progress["id"].as_str() != Some(task_id) {
        // Keep the stale contract without exposing a different task's progress.
        anyhow::ensure!(
            !cancel || progress["stale"] == true,
            "runtime returned a foreign model task"
        );
        return Ok(serde_json::json!({"active":true,"stale":true}));
    }
    Ok(progress)
}

pub(crate) fn prepare_model(mirror: &str) -> Result<()> {
    let response = call_method("model.prepare", vec![mirror.to_owned()], false)?;
    anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
    Ok(())
}

pub(crate) fn profile_request(method: &str, args: Vec<String>) -> Result<Value> {
    let response = call_method(method, args, true)?;
    anyhow::ensure!(
        response.ok,
        "{}",
        response
            .error
            .unwrap_or_else(|| "model profile request failed".to_owned())
    );
    Ok(serde_json::to_value(
        response
            .envelope
            .context("model profile response missing")?,
    )?)
}

fn http_roundtrip(method: &str, args: &[String]) -> Result<RpcResponse> {
    match method {
        "runtime.status" => {
            let health = crate::net_rpc::health()?;
            Ok(RpcResponse {
                v: health.v,
                id: "health".into(),
                operation_id: None,
                scope: None,
                idempotency_key: None,
                ok: true,
                exit: 0,
                bin: health.bin,
                envelope: None,
                error: None,
                code: None,
                web_url: Some(health.url),
                pid: Some(health.pid),
                data_dir: Some(health.data_dir),
            })
        }
        "runtime.stop" => {
            crate::net_rpc::request_stop()?;
            Ok(RpcResponse {
                v: PROTOCOL_V,
                id: "stop".into(),
                operation_id: None,
                scope: None,
                idempotency_key: None,
                ok: true,
                exit: 0,
                bin: env!("CARGO_PKG_VERSION").to_owned(),
                envelope: None,
                error: None,
                code: None,
                web_url: None,
                pid: None,
                data_dir: None,
            })
        }
        "cli.exec" | "cli.progress" | "model.control" | "model.prepare" | "index.prepare"
        | "model.catalog" | "model.configure" | "model.switch" | "model.resume"
        | "model.progress" => {
            let parsed = if method == "cli.exec" {
                crate::net_rpc::rpc_exec(args.to_vec())?
            } else {
                crate::net_rpc::rpc_method(method, args.to_vec())?
            };
            serde_json::from_value(parsed).context("runtime rpc response shape mismatch")
        }
        other => bail!("unknown runtime method {other}"),
    }
}

fn compatible(response: &RpcResponse) -> bool {
    response.v == PROTOCOL_V && response.code.as_deref() != Some("protocol_version_mismatch")
}

pub(crate) use respire_commands::rpc_client::{
    command_name, command_words, diary_lexical_mode, is_context_query, is_status, needs_inference,
    GLOBAL_VALUE_FLAGS, PROTOCOL_V,
};

pub(crate) fn endpoint_path() -> PathBuf {
    respire_client_host::paths::main_data_dir().join("runtime/endpoint.json")
}

fn endpoint_pid() -> Option<u32> {
    let data: Value = serde_json::from_slice(&std::fs::read(endpoint_path()).ok()?).ok()?;
    data.get("pid")?.as_u64().and_then(|pid| u32::try_from(pid).ok())
}

pub(crate) fn probe_runtime() -> Result<Option<crate::net_rpc::Health>> {
    match crate::net_rpc::health() {
        Ok(health) => Ok(Some(health)),
        Err(error) if matches!(error.downcast_ref::<crate::runtime_error::RuntimeError>(),
            Some(crate::runtime_error::RuntimeError::Unavailable)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Recovery must not wait on RPC, model locks or a library lock.
pub(crate) fn force_stop_for_reset() -> Result<Option<u32>> {
    let port = crate::net_rpc::rpc_port();
    let Some(pid) = crate::net_rpc::pid_listening_on(port) else {
        if crate::net_rpc::port_is_open() {
            bail!("CPU saved, but cannot identify runtime on port {port}");
        }
        return Ok(None);
    };
    if pid == std::process::id() || !crate::net_rpc::pid_is_respire(pid) {
        bail!("CPU saved; refusing to terminate non-runtime process {pid} on port {port}");
    }
    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    #[cfg(unix)]
    let status = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()?;
    if !status.success() {
        bail!("CPU saved, but failed to terminate runtime {pid}");
    }
    crate::net_rpc::wait_until_down().context("CPU saved, but runtime port is still occupied")?;
    if endpoint_pid() == Some(pid) && endpoint_path().exists() {
        std::fs::remove_file(endpoint_path())?;
    }
    Ok(Some(pid))
}

pub(crate) fn ensure_daemon() -> Result<()> {
    if crate::runtime_policy::client_only() {
        crate::net_rpc::health()?;
        return Ok(());
    }
    // Normal requests only inspect the resident owner. Lifecycle serialization
    // begins when startup, replacement or recovery is actually required.
    if let Some(health) = probe_runtime()? {
        if runtime_acceptable(&health)? {
            return Ok(());
        }
    }
    crate::runtime_fetch::require_automatic_migration_safe()?;
    let _takeover = crate::runtime_policy::takeover_lock()?;
    ensure_daemon_locked()
}

pub(crate) fn runtime_acceptable(health: &crate::net_rpc::Health) -> Result<bool> {
    let override_bin = respire::env::var("RSRS_RUNTIME_BIN")
        .ok()
        .map(|raw| std::path::PathBuf::from(raw.trim()))
        .filter(|path| !path.as_os_str().is_empty());
    let managed = if override_bin.is_none() {
        crate::runtime_fetch::managed_runtime_path()?
    } else {
        None
    };
    let portable = std::env::current_exe()?
        .parent()
        .map(|directory| directory.join(crate::runtime_fetch::RUNTIME_BINARY))
        .filter(|path| path.is_file());
    let Some(expected) = override_bin.or(managed).or(portable) else {
        return Ok(false);
    };
    if crate::embedding::selection().is_none()
        && crate::mcp::exe_matches_dest(&health.exe, &std::env::current_exe()?)
    {
        return Ok(false);
    }
    Ok(!health.data_dir.is_empty()
        && crate::mcp::same_path(
            std::path::Path::new(&health.data_dir),
            &respire_client_host::config::control_roots()?.1,
        )
        && crate::autostart::may_reuse_runtime(health)?
        && crate::runtime_fetch::version_in_accept(&health.runtime_version)
        && crate::mcp::exe_matches_dest(&health.exe, &expected)
        && !health.inference_stalled())
}

pub(crate) fn ensure_daemon_locked() -> Result<()> {
    crate::runtime_fetch::require_automatic_migration_safe()?;
    if crate::autostart::ensure_managed_locked()? {
        return Ok(());
    }
    crate::autostart::check_direct_access()?;
    let current = probe_runtime()?;
    if let Some(health) = &current {
        if runtime_acceptable(health)? {
            return Ok(());
        }
    }
    // Resolve before stopping the resident owner: a missing or damaged release
    // must fail without replacing it with a CLI shim.
    let executable = resolve_runtime_executable()?;
    if let Some(health) = current {
        if health.inference_stalled() {
            anyhow::ensure!(
                crate::net_rpc::pid_is_respire(health.pid),
                "cannot verify the unresponsive runtime process; no lifecycle action taken"
            );
            crate::progress::phase("\u{63a8}\u{7406}\u{65e0}\u{54cd}\u{5e94}\u{ff1b}\u{5bbf}\u{4e3b}\u{6b63}\u{5728}\u{6062}\u{590d} runtime", "Inference unresponsive; host recovering runtime");
        }
        stop_occupant(health.pid)?;
    }
    crate::autostart::authorize_detached_boot_locked()?;
    let arguments: Vec<std::ffi::OsString> = vec![
        "serve".into(),
        "--data-dir".into(),
        respire_client_host::paths::main_data_dir().into_os_string(),
    ];
    let (mut child, instance_id) =
        crate::autostart::spawn_authorized_runtime(&executable, &arguments, None)
            .context("failed to start host runtime")?;
    let result = wait_daemon_ready(&mut child, &executable, &instance_id);
    if result.is_err() && child.try_wait()?.is_none() {
        // Do not leave a delayed startup racing the next lock holder.
        child
            .kill()
            .context("failed to stop unready host runtime")?;
        child
            .wait()
            .context("failed to reap unready host runtime")?;
    }
    result
}

pub(crate) fn stop_occupant(pid: u32) -> Result<()> {
    let health = crate::net_rpc::health()?;
    anyhow::ensure!(health.pid == pid, "runtime owner changed before shutdown");
    drain_occupant(&health, Duration::from_secs(60))
}

pub(crate) fn drain_occupant(health: &crate::net_rpc::Health, timeout: Duration) -> Result<()> {
    let pid = health.pid;
    let (installation_root, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(
        crate::mcp::same_path(
            std::path::Path::new(&health.data_dir),
            &profile,
        ) && crate::mcp::same_path(
            std::path::Path::new(&health.installation_root),
            &installation_root,
        ),
        "runtime restart blocked: owner roots do not match this installation"
    );
    let birth = crate::autostart::process_birth(pid)?.context("runtime process already exited")?;
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    anyhow::ensure!(
        health.process_start_id == format!("{prefix}{birth}"),
        "runtime process start identity does not match health"
    );
    let operation_id = crate::net_rpc::request_stop_for(health, Duration::from_secs(120))?;
    let deadline = Instant::now() + timeout;
    loop {
        if crate::autostart::process_birth(pid)?.as_deref() != Some(birth.as_str()) {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "runtime drain is still pending; no process was forced to exit"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    crate::net_rpc::final_stop_receipt(health, Some(&operation_id))?;
    crate::net_rpc::wait_until_down()?;
    let released = respire::lock::LibraryLock::acquire(
        std::path::Path::new(&health.data_dir),
        Duration::from_secs(15),
    )
    .context("stopped runtime has not released its library lock")?;
    // Keep the library lock until the verified dead owner's locator is removed.
    if endpoint_path().exists() {
        anyhow::ensure!(
            endpoint_pid() == Some(pid) && crate::autostart::process_birth(pid)?.is_none(),
            "runtime endpoint owner changed after drain; record was not removed"
        );
        std::fs::remove_file(endpoint_path())?;
    }
    drop(released);
    Ok(())
}

fn wait_daemon_ready(
    child: &mut std::process::Child,
    executable: &std::path::Path,
    instance_id: &str,
) -> Result<()> {
    let off_mode = respire_client_host::settings::off_mode()?;
    let mut last_store_ready = None;
    let deadline = Instant::now() + START_WAIT * START_POLLS as u32;
    while Instant::now() < deadline {
        std::thread::sleep(START_WAIT);
        if let Some(status) = child.try_wait()? {
            bail!("host runtime exited before readiness: {status} (off_mode={off_mode}, last_store_ready={last_store_ready:?})");
        }
        if let Some(health) = probe_runtime()? {
            last_store_ready = Some(health.store_ready);
            // Off mode deliberately leaves the store closed; owner checks still apply.
            if !health.store_ready && !off_mode {
                continue;
            }
            let birth = crate::autostart::process_birth(child.id())?
                .context("starting runtime process exited")?;
            let birth_prefix = if cfg!(windows) {
                "windows-filetime-"
            } else if cfg!(target_os = "linux") {
                "linux-starttime-"
            } else {
                "darwin-lstart-"
            };
            anyhow::ensure!(
                health.pid == child.id()
                    && health.process_start_id == format!("{birth_prefix}{birth}")
                    && health.v == PROTOCOL_V
                    && health.generation > 0
                    && !health.account_id.is_empty()
                    && health.instance_id == instance_id
                    && crate::mcp::exe_matches_dest(&health.exe, executable)
                    && crate::runtime_fetch::version_in_accept(&health.runtime_version)
                    && !health.data_dir.is_empty()
                    && crate::mcp::same_path(
                        std::path::Path::new(&health.data_dir),
                        &respire_client_host::config::control_roots()?.1
                    ),
                "runtime owner changed during startup"
            );
            return Ok(());
        }
    }
    bail!("host runtime did not become ready (off_mode={off_mode}, last_store_ready={last_store_ready:?})")
}

#[cfg(test)]
mod runtime_resolution_tests {
    use super::*;

    #[test]
    fn startup_errors_propagate_and_cli_cannot_pass_as_runtime() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow::anyhow!("test environment lock poisoned: {error}"))?;
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
            "RSRS_CORE_TEST_MODE",
            "RSRS_RUNTIME_BIN",
            "ONEMEMORY_RUNTIME_BIN",
            "RESPIRE_RUNTIME_BIN",
            "RSRS_RPC_PORT",
        ];
        let _restore = Restore(
            keys.iter()
                .map(|key| (*key, std::env::var_os(key)))
                .collect(),
        );
        let directory = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", directory.path());
        std::env::set_var("RSRS_BIN_DIR", directory.path().join("bin"));
        std::env::set_var("RSRS_CORE_TEST_MODE", "1");
        for key in &keys[3..6] {
            std::env::remove_var(key);
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std::env::set_var("RSRS_RPC_PORT", listener.local_addr()?.port().to_string());
        drop(listener);

        // Idle asset maintenance must never resolve or spawn the selected runtime.
        std::env::set_var("RSRS_RUNTIME_BIN", directory.path().join("missing-runtime"));
        let config_path = respire_client_host::paths::client_config_path();
        change_host_assets(|| {
            std::fs::write(&config_path, b"{}")?;
            Ok(())
        })?;
        let error = change_host_assets(|| {
            std::fs::write(&config_path, b"{\"changed\":true}")?;
            bail!("synthetic asset failure")
        })
        .err()
        .context("asset failure was swallowed")?;
        anyhow::ensure!(format!("{error:#}") == "synthetic asset failure");
        anyhow::ensure!(std::fs::read(&config_path)? == b"{}");
        anyhow::ensure!(!endpoint_path().exists() && !directory.path().join("bin").exists());
        std::fs::remove_file(&config_path)?;
        let error = change_host_assets(|| bail!("synthetic absent-config failure"))
            .err()
            .context("absent-config asset failure was swallowed")?;
        anyhow::ensure!(format!("{error:#}") == "synthetic absent-config failure");
        anyhow::ensure!(!config_path.exists() && !endpoint_path().exists());
        let endpoint = endpoint_path();
        std::fs::create_dir_all(endpoint.parent().context("test endpoint parent missing")?)?;
        std::fs::write(&endpoint, br#"{"v":1,"pid":0}"#)?;
        let mut changed = false;
        anyhow::ensure!(change_host_assets(|| {
            changed = true;
            Ok(())
        })
        .is_err());
        anyhow::ensure!(!changed && endpoint.exists() && !config_path.exists());
        let endpoint_before = std::fs::read(&endpoint)?;
        let error = restart_runtime(Duration::from_secs(1))
            .err()
            .context("restart accepted an owner without persisted recovery evidence")?;
        anyhow::ensure!(
            error.is::<crate::runtime_fetch::LegacyRuntimeMigrationRequired>(),
            "restart did not defer the unbound legacy owner: {error:#}"
        );
        anyhow::ensure!(
            std::fs::read(&endpoint)? == endpoint_before
                && !config_path.exists()
                && !directory.path().join("bin").exists(),
            "rejected restart changed stale ownership or started materialization"
        );
        std::fs::remove_file(&endpoint)?;
        {
            use sha2::{Digest, Sha256};
            let _takeover = crate::runtime_policy::takeover_lock()?;
            let image = directory.path().join("recovery-runtime");
            std::fs::write(&image, b"isolated recovery image")?;
            let image = image.canonicalize()?;
            std::env::set_var("RSRS_RUNTIME_BIN", &image);
            let root = directory.path().canonicalize()?;
            let profile = respire_client_host::config::control_roots()?.1.canonicalize()?;
            let account = respire_client_host::identity::session_user_of_dir(&profile)?.unwrap_or_default();
            let account = if account.is_empty() { profile.display().to_string() } else { account };
            let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
            let version = &crate::runtime_fetch::pinned()?.required;
            let birth_prefix = if cfg!(windows) { "windows-filetime-" }
                else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
            let launch = root.join("runtime/autostart/launch");
            std::fs::create_dir_all(&launch)?;
            for mode in ["normal", "readonly", "off"] {
                std::fs::write(&config_path, serde_json::to_vec(&json!({"service_mode":mode}))?)?;
                let instance = uuid::Uuid::new_v4().to_string();
                let grant = serde_json::to_string(&json!({
                    "schema_version":1, "protocol_version":PROTOCOL_V,
                    "nonce":instance, "instance_id":instance,
                    "installation_root":root, "installation_id":digest(root.display().to_string().as_bytes()),
                    "profile":profile, "account_id":digest(account.as_bytes()), "sync_generation":0,
                    "image_path":image, "image_sha256":digest(b"isolated recovery image"),
                    "supervisor_pid":u32::MAX-1, "supervisor_birth":"456", "managed_id":null,
                    "registration_sha256":null, "maintenance":null,
                    "port":crate::net_rpc::rpc_port(), "issued_at_ms":1, "expires_at_ms":2,
                }))?;
                let receipt = serde_json::to_vec(&json!({
                    "schema_version":2, "protocol_version":PROTOCOL_V, "state":"consumed",
                    "grant_json":grant, "grant_sha256":digest(grant.as_bytes()), "registration_json":null,
                    "pid":u32::MAX, "process_start_id":"123",
                }))?;
                let claim = launch.join(format!("launch-{instance}.claimed"));
                std::fs::write(&claim, &receipt)?;
                let record = json!({
                    "schema_version":2, "server":"respire", "v":PROTOCOL_V, "bin":version,
                    "runtime_version":version, "url":crate::net_rpc::rpc_base_url(),
                    "pid":u32::MAX, "process_start_id":format!("{birth_prefix}123"),
                    "instance_id":instance, "installation_root":root, "data_dir":profile,
                    "installation_id":digest(root.display().to_string().as_bytes()),
                    "account_id":digest(account.as_bytes()), "generation":7,
                    "exe":image, "image_path":image, "image_sha256":digest(b"isolated recovery image"),
                    "managed_id":null, "launch_receipt_sha256":digest(&receipt),
                });
                for (field, invalid) in [
                    ("generation", json!(0)), ("account_id", json!("foreign-account")),
                    ("image_sha256", json!("f".repeat(64))), ("process_start_id", json!("reused-pid")),
                    ("launch_receipt_sha256", json!("f".repeat(64))), ("pid", json!(std::process::id())),
                ] {
                    let mut changed = record.clone();
                    changed[field] = invalid;
                    let bytes = serde_json::to_vec(&changed)?;
                    std::fs::write(&endpoint, &bytes)?;
                    anyhow::ensure!(crate::autostart::StaleOwner::prepare_locked().is_err(), "accepted changed {field} in {mode}");
                    anyhow::ensure!(std::fs::read(&endpoint)? == bytes && std::fs::read(&claim)? == receipt);
                }
                let bytes = serde_json::to_vec(&record)?;
                std::fs::write(&endpoint, &bytes)?;
                let session = profile.join("session.json");
                std::fs::write(&session, b"invalid account metadata")?;
                anyhow::ensure!(crate::autostart::StaleOwner::prepare_locked().is_err(),
                    "unreadable account identity became an anonymous profile in {mode}");
                anyhow::ensure!(std::fs::read(&endpoint)? == bytes && std::fs::read(&claim)? == receipt);
                std::fs::remove_file(session)?;
                let stale = crate::autostart::StaleOwner::prepare_locked()?;
                std::fs::write(&endpoint, b"changed after verification")?;
                anyhow::ensure!(stale.remove_endpoint_locked().is_err());
                anyhow::ensure!(endpoint.exists() && std::fs::read(&claim)? == receipt);
                std::fs::write(&endpoint, &bytes)?;
                crate::autostart::StaleOwner::prepare_locked()?.remove_endpoint_locked()?;
                anyhow::ensure!(!endpoint.exists() && std::fs::read(&claim)? == receipt
                    && !root.join("rsrs.db").exists(), "recovery touched the store or consumed tombstone in {mode}");
            }
            std::fs::remove_file(&config_path)?;
        }
        std::env::remove_var("RSRS_RUNTIME_BIN");
        let cli = std::env::current_exe()?;
        let health: crate::net_rpc::Health = serde_json::from_value(json!({
            "server": "rsrs", "bin": env!("CARGO_PKG_VERSION"), "pid": 42, "v": PROTOCOL_V,
            "exe": cli, "data_dir": respire_client_host::config::control_roots()?.1,
            "runtime_version": crate::runtime_fetch::pinned()?.required,
            "store_ready": true,
        }))?;
        anyhow::ensure!(
            !runtime_acceptable(&health)?,
            "unselected CLI passed as a Runtime"
        );

        // Invalid explicit selections fail without a download or materialized shim.
        std::env::set_var("RSRS_RUNTIME_BIN", directory.path().join("missing-runtime"));
        anyhow::ensure!(resolve_runtime_executable().is_err());
        anyhow::ensure!(!directory.path().join("bin").exists());
        std::env::remove_var("RSRS_RUNTIME_BIN");
        std::fs::write(
            crate::runtime_fetch::manifest_path(),
            serde_json::to_vec(&json!({
                "version": crate::runtime_fetch::pinned()?.required, "sha256": "1".repeat(64),
            }))?,
        )?;
        let error = resolve_runtime_executable()
            .err()
            .context("legacy proof was accepted")?;
        anyhow::ensure!(error.is::<crate::runtime_fetch::ManagedRuntimeRepairRequired>());
        let error = runtime_acceptable(&health)
            .err()
            .context("legacy proof was accepted during runtime reuse")?;
        anyhow::ensure!(error.is::<crate::runtime_fetch::ManagedRuntimeRepairRequired>());
        std::fs::remove_file(crate::runtime_fetch::manifest_path())?;

        // Even an explicit override cannot turn this CLI into a Runtime.
        std::env::set_var("RSRS_RUNTIME_BIN", &cli);
        anyhow::ensure!(explicit_cli_runtime(&cli)?);
        anyhow::ensure!(resolve_runtime_executable().is_err());
        anyhow::ensure!(
            !runtime_acceptable(&health)?,
            "CLI override passed as a Runtime"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn test_response(id: &str) -> RpcResponse {
        RpcResponse {
            v: PROTOCOL_V,
            id: id.to_owned(),
            operation_id: None,
            scope: None,
            idempotency_key: None,
            ok: true,
            exit: 0,
            bin: "rsrs-runtime".into(),
            envelope: None,
            error: None,
            code: None,
            web_url: None,
            pid: None,
            data_dir: None,
        }
    }

    struct TestEnvironment(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl Drop for TestEnvironment {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    struct OfficialRuntime {
        child: std::process::Child,
        port: u16,
        _environment: TestEnvironment,
        _root: tempfile::TempDir,
    }

    impl Drop for OfficialRuntime {
        fn drop(&mut self) {
            // Reap only this fixture's owned child, including failed assertions.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl OfficialRuntime {
        fn start() -> Result<Self> {
            // Same official managed-install fixture as cli/tests/support/mod.rs.
            // The override locates it; it is removed before exercising product code.
            let binary = PathBuf::from(std::env::var_os("RSRS_RUNTIME_BIN")
                .context("official managed Runtime fixture required")?).canonicalize()?;
            anyhow::ensure!(binary != std::env::current_exe()?.canonicalize()?,
                "test executable cannot substitute for the independent Runtime");
            let version_dir = binary.parent().context("fixture version directory missing")?;
            let source_root = version_dir.parent().and_then(std::path::Path::parent)
                .context("fixture installation root missing")?;
            let receipt = std::fs::read(source_root.join("runtime.json"))?;
            let selected: Value = serde_json::from_slice(&receipt)?;
            let version = crate::runtime_fetch::pinned()?.required.clone();
            anyhow::ensure!(selected["version"] == version
                && selected["release"]["metadata_json"].is_string()
                && source_root.join("runtime").join(&version) == version_dir,
                "fixture must be the official pinned managed installation");
            let root = tempfile::tempdir()?;
            let mut pending = vec![(version_dir.to_path_buf(), root.path().join("runtime").join(&version))];
            while let Some((source, target)) = pending.pop() {
                let metadata = std::fs::symlink_metadata(&source)?;
                anyhow::ensure!(!metadata.file_type().is_symlink(), "fixture contains a link");
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0,
                        "fixture contains a reparse point");
                }
                if metadata.is_dir() {
                    std::fs::create_dir_all(&target)?;
                    for entry in std::fs::read_dir(source)? {
                        let entry = entry?;
                        pending.push((entry.path(), target.join(entry.file_name())));
                    }
                } else {
                    anyhow::ensure!(metadata.is_file(), "fixture contains a non-file");
                    std::fs::copy(source, target)?;
                }
            }
            std::fs::write(root.path().join("runtime.json"), receipt)?;
            std::fs::write(root.path().join("client.json"), b"{\"service_mode\":\"normal\"}")?;
            let keys = ["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_RPC_PORT", "RSRS_CORE_TEST_MODE",
                "RSRS_NO_AUTOSYNC", "RSRS_RUNTIME_BIN", "ONEMEMORY_RUNTIME_BIN", "RESPIRE_RUNTIME_BIN",
                "RSRS_RPC_TOKEN", "RSRS_NO_AUTOSTART", "RSRS_CLIENT_ONLY"];
            let environment = TestEnvironment(keys.iter()
                .map(|key| (*key, std::env::var_os(key))).collect());
            for key in &keys { std::env::remove_var(key); }
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            drop(listener);
            std::env::set_var("RSRS_DATA_DIR", root.path());
            std::env::set_var("RSRS_BIN_DIR", root.path().join("bin"));
            std::env::set_var("RSRS_RPC_PORT", port.to_string());
            std::env::set_var("RSRS_CORE_TEST_MODE", "1");
            std::env::set_var("RSRS_NO_AUTOSYNC", "1");
            let executable = crate::runtime_fetch::managed_runtime_path()?
                .context("copied official Runtime fixture is not installed")?;
            let _takeover = crate::runtime_policy::takeover_lock()?;
            crate::autostart::authorize_detached_boot_locked()?;
            let arguments = vec!["serve".into(), "--data-dir".into(),
                root.path().as_os_str().to_owned(), "--port".into(), port.to_string().into()];
            let (child, instance_id) = crate::autostart::spawn_authorized_runtime(
                &executable, &arguments, None)?;
            let mut runtime = Self { child, port, _environment: environment, _root: root };
            wait_daemon_ready(&mut runtime.child, &executable, &instance_id)?;
            Ok(runtime)
        }

        fn request(&self, method: &str, args: Vec<&str>) -> Result<Value> {
            let scope = crate::net_rpc::request_scope(&crate::net_rpc::health()?)?;
            let operation = uuid::Uuid::new_v4().to_string();
            Ok(json!({"v":PROTOCOL_V,"id":uuid::Uuid::new_v4().to_string(),
                "scope":scope,"operation_id":operation,"idempotency_key":operation,
                "method":method,"args":args}))
        }

        fn post(&self, request: &Value) -> Result<Value> {
            Ok(ureq::post(&format!("http://127.0.0.1:{}/api/rpc", self.port))
                .timeout(Duration::from_secs(15)).send_json(request.clone())?.into_json()?)
        }
    }

    #[test]
    fn diary_inference_routing_honours_modes_and_literal_query_arguments() -> Result<()> {
        use clap::Parser;
        for (args, inference) in [
            (vec!["diary-search", "q"], true),
            (vec!["diary-search", "q", "--mode", "lexical"], false),
            (vec!["diary-search", "--mode=lexical", "q"], false),
            (
                vec!["diary-search", "--mode", "hybrid", "--", "--mode=lexical"],
                true,
            ),
            (vec!["diary-search", "--", "--mode=lexical"], true),
            (
                vec!["diary-search", "--mode", "lexical", "--", "--mode=hybrid"],
                false,
            ),
            (
                vec!["diary-fragment", "--neighbors", "1", "--", "s", "f"],
                false,
            ),
        ] {
            let arguments: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(needs_inference(&arguments), inference, "{arguments:?}");
            let parsed = crate::Cli::try_parse_from(std::iter::once("rsrs").chain(args))?;
            if let Some(crate::Command::DiarySearch { query, mode, .. }) = parsed.command {
                if query == "--mode=lexical" {
                    assert_eq!(mode, "hybrid");
                }
                if query == "--mode=hybrid" {
                    assert_eq!(mode, "lexical");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn shutdown_requires_a_matching_final_receipt() -> Result<()> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../contracts/runtime-control/fixtures");
        let fixture: Value =
            serde_json::from_slice(&std::fs::read(root.join("positive/health-identity.json"))?)?;
        let mut identity = fixture["payload"].clone();
        identity["server"] = json!("respire");
        identity["bin"] = json!("rsrs-runtime");
        identity["v"] = json!(1);
        let health: crate::net_rpc::Health = serde_json::from_value(identity)?;
        let fixture: Value = serde_json::from_slice(&std::fs::read(
            root.join("positive/stop-final-drained.json"),
        )?)?;
        let receipt = fixture["payload"].clone();
        let operation = receipt["operation_id"]
            .as_str()
            .context("fixture stop operation")?;
        crate::net_rpc::validate_final_stop_receipt(&health, Some(operation), &receipt)?;
        for (key, invalid) in [
            ("schema_version", json!(2)),
            ("protocol_version", json!(2)),
            ("operation_id", json!("other-operation")),
            ("installation_id", json!("other-installation")),
            ("instance_id", json!("other-instance")),
            ("pid", json!(999)),
            ("process_start_id", json!("reused-pid")),
            ("image_path", json!("other-runtime")),
            ("image_sha256", json!("other-digest")),
            ("runtime_version", json!("other-version")),
            ("account_id", json!("other-account")),
            ("generation", json!(8)),
            ("state", json!("forced_timeout")),
            ("unfinished", Value::Null),
        ] {
            let mut invalid_receipt = receipt.clone();
            invalid_receipt[key] = invalid;
            assert!(
                crate::net_rpc::validate_final_stop_receipt(
                    &health,
                    Some(operation),
                    &invalid_receipt
                )
                .is_err(),
                "accepted mismatched {key}"
            );
        }
        let incomplete: Value = serde_json::from_slice(&std::fs::read(
            root.join("negative/stop-final-unfinished.json"),
        )?)?;
        assert!(crate::net_rpc::validate_final_stop_receipt(
            &health,
            Some(operation),
            &incomplete["payload"]
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn routing_value_flags_match_the_actual_cli_contract() {
        use clap::CommandFactory;
        let mut command = crate::Cli::command();
        command.build();
        let actual: std::collections::BTreeSet<_> = command
            .get_arguments()
            .filter(|arg| arg.is_global_set() && arg.get_action().takes_values())
            .filter_map(|arg| arg.get_long().map(|name| format!("--{name}")))
            .collect();
        let expected = GLOBAL_VALUE_FLAGS
            .iter()
            .map(|flag| (*flag).to_owned())
            .collect();
        assert_eq!(
            actual, expected,
            "new valued globals must update the shared argv classifier"
        );
    }

    #[test]
    fn command_names_ignore_flags() {
        assert_eq!(command_name(&[]), None);
        assert_eq!(
            command_name(&["--json".into(), "status".into()]).as_deref(),
            Some("status")
        );
        assert!(is_status(&["--json".into(), "status".into()]));
        assert!(!is_status(&["remember".into()]));
        let tracked = [
            "--json",
            "--progress-id",
            "request-one",
            "--model-task-id",
            "task-one",
            "remember",
            "body",
        ]
        .map(String::from);
        assert_eq!(command_name(&tracked), Some("remember"));
        assert!(needs_inference(&tracked));
        assert!(!needs_inference(&["status".into()]));
    }

    #[test]
    fn compatible_requires_version_and_bin() {
        let mut response = test_response("s");
        assert!(compatible(&response));
        response.v = 99;
        assert!(!compatible(&response));
        response.v = PROTOCOL_V;
        response.bin = "other".into();
        assert!(compatible(&response));
        response.code = Some("protocol_version_mismatch".into());
        assert!(!compatible(&response));
    }

    #[test]
    fn scoped_operation_replays_and_retains_its_result_over_real_http() -> Result<()> {
        let _serial = crate::TEST_ENV_LOCK.lock()
            .map_err(|error| anyhow::anyhow!("test environment lock poisoned: {error}"))?;
        let mut runtime = OfficialRuntime::start()?;
        let request = runtime.request("cli.exec", vec!["--json", "status"])?;
        let first = runtime.post(&request)?;
        anyhow::ensure!(first["ok"] == true, "official Runtime status failed: {first}");
        let mut replay = request.clone();
        replay["id"] = json!(uuid::Uuid::new_v4().to_string());
        let repeated = runtime.post(&replay)?;
        assert_eq!(repeated["id"], replay["id"]);
        for field in ["operation_id", "idempotency_key", "scope", "ok", "exit", "envelope"] {
            assert_eq!(repeated[field], first[field], "replay changed {field}");
        }
        let operation: crate::runtime_error::OperationContext = serde_json::from_value(json!({
            "scope":request["scope"], "operation_id":request["operation_id"],
            "idempotency_key":request["idempotency_key"],
        }))?;
        let result = crate::net_rpc::rpc_result(&operation)?;
        assert_eq!(result["envelope"]["summary"]["state"], "completed");
        assert_eq!(result["envelope"]["summary"]["response"]["envelope"], first["envelope"]);
        replay["id"] = json!(uuid::Uuid::new_v4().to_string());
        replay["args"] = json!(["--json", "memory-revision"]);
        assert_eq!(runtime.post(&replay)?["code"], "idempotency_conflict");
        // Final drain must retain the original operation binding and prove release.
        let _takeover = crate::runtime_policy::takeover_lock()?;
        let health = crate::net_rpc::health()?;
        std::thread::scope(|scope| -> Result<()> {
            let draining = scope.spawn(|| drain_occupant(&health, Duration::from_secs(30)));
            while !draining.is_finished() {
                // Reap our child so Unix liveness checks do not wait on a zombie.
                runtime.child.try_wait()?;
                std::thread::sleep(Duration::from_millis(20));
            }
            draining.join().map_err(|_| anyhow::anyhow!("fixture drain panicked"))?
        })?;
        assert!(!endpoint_path().exists());
        assert!(!crate::net_rpc::port_is_open());
        Ok(())
    }

    #[test]
    fn http_pipeline_and_nonreading_peer_keep_runtime_available() -> Result<()> {
        let _serial = crate::TEST_ENV_LOCK.lock()
            .map_err(|error| anyhow::anyhow!("test environment lock poisoned: {error}"))?;
        let runtime = OfficialRuntime::start()?;
        let first = runtime.request("cli.exec", vec!["--json", "status"])?;
        let second = runtime.request("cli.exec", vec!["--json", "status"])?;
        let mut pipeline = std::net::TcpStream::connect(("127.0.0.1", runtime.port))?;
        pipeline.set_read_timeout(Some(Duration::from_secs(15)))?;
        for (body, close) in [(&first, false), (&second, true)] {
            let body = body.to_string();
            let connection = if close { "Connection: close\r\n" } else { "" };
            write!(pipeline, "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{connection}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", runtime.port, body.len())?;
        }
        // Do not read either reply until the separate control endpoint answers.
        assert_eq!(crate::net_rpc::health()?.pid, runtime.child.id());
        let mut wire = String::new();
        pipeline.read_to_string(&mut wire)?;
        let first_id = first["id"].as_str().context("first request ID missing")?;
        let second_id = second["id"].as_str().context("second request ID missing")?;
        let first_at = wire.find(first_id).context("first pipeline reply missing")?;
        let second_at = wire.find(second_id).context("second pipeline reply missing")?;
        assert!(first_at < second_at, "HTTP pipeline replies reordered");
        assert_eq!(wire.matches("HTTP/1.1 200").count(), 2, "pipeline response failed: {wire}");
        let response = call_method("cli.exec", vec!["--json".into(), "status".into()], false)?;
        assert!(response.ok);
        assert!(response.scope.is_some() && response.operation_id.is_some()
            && response.idempotency_key == response.operation_id);
        Ok(())
    }

    #[test]
    fn endpoint_path_follows_data_dir() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let previous = respire::env::var("RSRS_DATA_DIR").ok();
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", first.path());
        let first_path = endpoint_path();
        std::env::set_var("RSRS_DATA_DIR", second.path());
        let second_path = endpoint_path();
        match previous {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        if first_path == second_path {
            anyhow::bail!(
                "endpoint path stayed at {} after the data dir changed",
                first_path.display()
            );
        }
        if !first_path.starts_with(first.path()) || !second_path.starts_with(second.path()) {
            anyhow::bail!(
                "endpoint path left its data dir: {} / {}",
                first_path.display(),
                second_path.display()
            );
        }
        Ok(())
    }

    #[test]
    fn offline_entry_and_endpoint_roundtrip() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let previous = respire::env::var("RSRS_DATA_DIR").ok();
        let previous_port = respire::env::var("RSRS_RPC_PORT").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::set_var("RSRS_RPC_PORT", "18761");
        assert!(!runtime_is_up());
        assert!(call_method("runtime.status", Vec::new(), false).is_err());
        let down = RuntimeFlags {
            port: None,
            host: "127.0.0.1".into(),
            status: true,
            stop: false,
        };
        runtime_entry(down.clone())?;
        assert_eq!(crate::exit_code(), 2);
        runtime_entry(RuntimeFlags {
            status: false,
            stop: true,
            ..down
        })?;
        std::fs::create_dir_all(endpoint_path().parent().context("endpoint parent missing")?)?;
        std::fs::write(endpoint_path(), serde_json::to_vec(&json!({"v":PROTOCOL_V,
            "pid":std::process::id(),"url":"http://127.0.0.1:9"}))?)?;
        assert_eq!(endpoint_pid(), Some(std::process::id()));
        let bare = test_response("render-none");
        assert!(render_response(bare, true).is_err());
        let mut with_body = test_response("render-body");
        with_body.envelope = Some(crate::output::ResultEnvelope::new(
            "status",
            OutputStatus::Ok,
            json!({"ok": true}),
            Vec::new(),
        ));
        render_response(with_body, true)?;
        let mut failure = test_response("render-err");
        failure.ok = false;
        failure.exit = 2;
        failure.code = Some("timeout".into());
        failure.error = Some("slow".into());
        assert!(render_response(failure, false).is_err());
        // Live startup, ownership and shutdown are exercised in a separate
        // process by net_rpc_http::runtime_uses_only_tcp_and_preserves_owner.
        match previous {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        match previous_port {
            Some(value) => std::env::set_var("RSRS_RPC_PORT", value),
            None => std::env::remove_var("RSRS_RPC_PORT"),
        }
        Ok(())
    }

    #[test]
    fn progress_queries_keep_stale_without_exposing_another_task() -> Result<()> {
        let stale = serde_json::json!({"active":true,"stale":true});
        assert_eq!(model_progress_for_task(stale.clone(), "original", true)?, stale);
        let foreign = serde_json::json!({"active":true,"id":"other","phase":"private-progress"});
        assert_eq!(model_progress_for_task(foreign.clone(), "original", false)?, stale);
        assert!(model_progress_for_task(foreign, "original", true).is_err());
        let own = serde_json::json!({"active":true,"id":"original","cancelled":true});
        assert_eq!(model_progress_for_task(own.clone(), "original", true)?, own);
        assert!(model_progress_for_task(serde_json::Value::Null, "original", false).is_err());
        Ok(())
    }

    #[test]
    fn legacy_login_preflight_preserves_operation_owned_recovery() -> Result<()> {
        use respire_protocol::host_control::HostLoginRecoveryState;
        for caller in [LoginRecoveryCaller::OrdinaryRequest, LoginRecoveryCaller::AccountControl] {
            assert!(!needs_legacy_login_recovery(HostLoginRecoveryState::Clear, caller)?);
            assert!(needs_legacy_login_recovery(HostLoginRecoveryState::LegacyPending, caller)?);
        }
        assert!(!needs_legacy_login_recovery(
            HostLoginRecoveryState::OperationPending, LoginRecoveryCaller::AccountControl)?);
        assert!(needs_legacy_login_recovery(
            HostLoginRecoveryState::OperationPending, LoginRecoveryCaller::OrdinaryRequest).is_err());
        Ok(())
    }

}

//! Local authenticated runtime transport (client face).
//!
//! Commands connect only to loopback HTTP over TCP and auto-start the managed
//! runtime through the lifecycle coordinator. The serving half of this module
//! (dispatch, job queue, health, HTTP wiring) moved to
//! `respire_commands::rpc_serve` and is re-imported here so `rpc::...` call
//! sites keep resolving unchanged.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::output::{ResultEnvelope, Status as OutputStatus};

const START_POLLS: usize = 100;
const START_WAIT: Duration = Duration::from_millis(150);

// Worker-face state (worker flag, sync context, generation, index work,
// write gate, recall statistics) lives in the shared rpc_worker module;
// re-exported so `rpc::...` call sites keep resolving.
pub(crate) use respire_commands::rpc_worker::{
    check_sync_context, diary_commit, foreground_phase, index_has_work, index_loop,
    index_loop_inner, index_status, invalidate_sync_boundary, kick_index, mark_worker,
    recall_stats_status, request_index, set_worker_active, shared_exclusive, sync_boundary,
    sync_generation, sync_local, worker_active, MAX_PENDING_STATS,
    STATS_ENQUEUED, STATS_FAILED, STATS_PENDING, STATS_PERSISTED, STATS_REJECTED, STOPPING,
    SYNC_CONTEXT, GENERATION, INDEX_CV, INDEX_ON, INDEX_RUNNING, INDEX_WORK, EXCLUSIVE,
    RecallStats,
};

// Server face (Job/admission queue, dispatch, health, HTTP wiring) moved to the
// shared runtime crate; the glob keeps every `rpc::` call site in this binary
// textually unchanged.
pub(crate) use respire_commands::rpc_serve::*;

// The wake-delivery and dispatch-loop tests reach these through `use super::*`.
#[cfg(test)]
use std::sync::mpsc::{self, Receiver};
#[cfg(test)]
use std::sync::Mutex;

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
        let insertion = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
        let mut progress_args = vec!["--progress-id".to_owned(), id.clone()];
        if command_name(&args) == Some("model") && !args.iter().any(|arg| arg == "--model-task-id") {
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
    Ok(response.envelope.map(|envelope| envelope.summary).unwrap_or(Value::Null))
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
    if JOB_TX.get().is_some() {
        return execute_json(full).map_err(|err| anyhow::anyhow!("{err}"));
    }
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
    if crate::autostart::stop_managed_locked()? { return Ok(()); }
    if let Some(health) = probe_runtime()? {
        stop_occupant(health.pid)?;
    }
    Ok(())
}

/// Explicit host recovery also handles a runtime whose HTTP listener is stuck.
pub(crate) fn restart_runtime(timeout: Duration) -> Result<Value> {
    crate::runtime_policy::require_host("runtime restart")?;
    let _takeover = crate::runtime_policy::takeover_lock()?;
    let mut maintenance = crate::autostart::restart_maintenance_locked()?;
    crate::progress::phase("\u{68c0}\u{67e5} runtime \u{8fdb}\u{7a0b}", "Checking runtime process");
    crate::autostart::restart_stage("restart_probe");
    let health = match probe_runtime() {
        Ok(health) => health,
        Err(error) if matches!(error.downcast_ref::<crate::runtime_error::RuntimeError>(),
            Some(crate::runtime_error::RuntimeError::Transport(_))) => None,
        Err(error) => return Err(error),
    };
    if crate::autostart::managed_enabled()?
        && health.as_ref().is_some_and(|value| !value.inference_stalled()) {
        // The active maintenance guard forces the managed coordinator to drain
        // the authenticated, exact registered executable/profile and stop its
        // service owner before replacement. Do not route this healthy owner
        // through legacy unresponsive-process discovery (including WMI).
        crate::autostart::restart_stage("restart_managed");
        let stopped_pid = health.as_ref().map(|value| value.pid);
        ensure_daemon_locked()?;
        let ready = crate::net_rpc::health()?;
        if !respire::service::off_mode() { verify_open_store(&respire::service::data_dir())?; }
        maintenance.finish()?;
        crate::autostart::restart_stage("restart_ready");
        return Ok(json!({"state":"ready", "stopped_pid":stopped_pid, "pid":ready.pid,
            "forced":false, "data_dir":ready.data_dir, "version":ready.bin}));
    }
    let listener = crate::net_rpc::pid_listening_on(crate::net_rpc::rpc_port());
    let pid = health.as_ref().map(|health| health.pid).or(listener)
        .or_else(|| endpoint_pid().filter(|pid| crate::net_rpc::pid_is_respire(*pid)));
    let mut forced = false;
    if let Some(pid) = pid {
        anyhow::ensure!(pid != std::process::id() && crate::net_rpc::pid_is_respire(pid),
            "cannot verify runtime process {pid}; restart refused");
        anyhow::ensure!(listener.is_none() || listener == Some(pid), "runtime port owner changed");
        crate::autostart::restart_stage("restart_identity");
        let identity = crate::net_rpc::runtime_process_identity(pid)?;
        if health.is_none() {
            anyhow::ensure!(endpoint_pid() == Some(pid), "unresponsive process does not match this runtime endpoint");
        }
        crate::progress::phase("\u{8bf7}\u{6c42}\u{4f18}\u{96c5}\u{9000}\u{51fa}\u{ff1b}\u{7b49}\u{5f85}\u{8fdb}\u{7a0b}\u{91ca}\u{653e}", "Requesting graceful shutdown; waiting for process exit");
        crate::autostart::restart_stage("restart_stop");
        let deadline = Instant::now() + timeout;
        if crate::net_rpc::port_is_open() {
            match crate::net_rpc::request_stop_with_timeout(timeout.min(Duration::from_secs(2))) {
                Ok(()) => {},
                Err(error) if matches!(error.downcast_ref::<crate::runtime_error::RuntimeError>(),
                    Some(crate::runtime_error::RuntimeError::Transport(_) | crate::runtime_error::RuntimeError::Unavailable)) => {},
                Err(error) => return Err(error),
            }
        }
        while Instant::now() < deadline && crate::net_rpc::process_is_running(pid)? {
            std::thread::sleep(Duration::from_millis(100));
        }
        if crate::net_rpc::process_is_running(pid)? {
            let owner = crate::net_rpc::pid_listening_on(crate::net_rpc::rpc_port());
            anyhow::ensure!(owner.is_none() || owner == Some(pid), "runtime port owner changed before recovery");
            crate::progress::phase("\u{9000}\u{51fa}\u{8d85}\u{65f6}\u{ff1b}\u{7ec8}\u{6b62} runtime \u{8fdb}\u{7a0b}", "Shutdown timed out; terminating runtime process");
            crate::net_rpc::kill_runtime(pid, &identity)?;
            forced = true;
        }
        crate::net_rpc::wait_until_exited(pid)?;
        crate::net_rpc::wait_until_down()?;
        let data_dir = health.as_ref().map(|health| PathBuf::from(&health.data_dir))
            .unwrap_or_else(respire::service::data_dir);
        crate::progress::phase("\u{7b49}\u{5f85}\u{6570}\u{636e}\u{5e93}\u{9501}\u{91ca}\u{653e}", "Waiting for database lock release");
        let released = respire::lock::LibraryLock::acquire(&data_dir, Duration::from_secs(15))?;
        drop(released);
        if endpoint_pid() == Some(pid) && endpoint_path().exists() {
            std::fs::remove_file(endpoint_path())?;
        }
    } else {
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "cannot identify the process occupying the runtime port");
    }
    crate::progress::phase("\u{542f}\u{52a8} runtime\u{ff1b}\u{7b49}\u{5f85}\u{5c31}\u{7eea}", "Starting runtime; waiting for readiness");
    crate::autostart::restart_stage("restart_start");
    ensure_daemon_locked()?;
    let ready = crate::net_rpc::health()?;
    if !respire::service::off_mode() { verify_open_store(&respire::service::data_dir())?; }
    maintenance.finish()?;
    crate::autostart::restart_stage("restart_ready");
    Ok(json!({"state":"ready", "stopped_pid":pid, "pid":ready.pid,
        "forced":forced, "data_dir":ready.data_dir, "version":ready.bin}))
}

/// Host profile changes release the old library before starting its successor.
pub fn recover_interrupted_login() -> Result<()> {
    let _takeover = crate::runtime_policy::takeover_lock()?;
    if !respire_app::login_transaction::recovery_pending() { return Ok(()); }
    let managed = crate::autostart::managed_enabled()?;
    let mut maintenance = crate::autostart::with_explicit_recovery(crate::autostart::begin_maintenance_locked)?;
    if let Some(health) = probe_runtime()? { stop_occupant(health.pid)?; }
    respire_app::login_transaction::recover_interrupted()?;
    if managed { ensure_daemon_locked()?; }
    maintenance.finish()?;
    eprintln!("Recovered an interrupted login; the original account and configuration were restored.");
    Ok(())
}

/// Listener readiness alone is insufficient for a snapshot commit: the actor
/// must have opened, checked and bound the actual restored database first.
pub fn verify_snapshot_store(root:&std::path::Path,id:&str)->Result<()> {
    verify_runtime_store(root,Some(id))
}
pub fn verify_open_store(root:&std::path::Path)->Result<()> {
    verify_runtime_store(root,None)
}
fn verify_runtime_store(root:&std::path::Path,id:Option<&str>)->Result<()> {
    for _ in 0..START_POLLS {
        let health=crate::net_rpc::health()?;
        anyhow::ensure!(!health.data_dir.is_empty() && crate::mcp::same_path(std::path::Path::new(&health.data_dir),root),"snapshot runtime profile changed during verification");
        if health.store_ready && id.is_none_or(|id|health.snapshot_restore_id.as_deref()==Some(id)){return Ok(());}
        std::thread::sleep(START_WAIT);
    }
    bail!("restored runtime did not confirm an opened and verified snapshot store")
}

pub fn change_profile(change: impl FnOnce() -> Result<()>) -> Result<()> {
    change_profile_with_rollback(change, || Ok(()))
}

pub fn change_profile_with_rollback(change: impl FnOnce() -> Result<()>, rollback: impl FnOnce() -> Result<()>) -> Result<()> {
    change_profile_with_verification(change, rollback, || Ok(()))
}

pub fn change_profile_with_verification(change: impl FnOnce() -> Result<()>, rollback: impl FnOnce() -> Result<()>, verify: impl FnOnce() -> Result<()>) -> Result<()> {
    crate::progress::phase("\u{534f}\u{8c03}\u{8d26}\u{6237}\u{64cd}\u{4f5c}\u{ff1b}\u{7b49}\u{5f85}\u{5f53}\u{524d} runtime \u{91ca}\u{653e}", "Coordinating account operation; waiting for current runtime to release");
    let _takeover = crate::runtime_policy::takeover_lock()?;
    let mut maintenance = crate::autostart::begin_maintenance_locked()?;
    let config_path = respire::service::client_config_path();
    let original = match std::fs::read(&config_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let backup = if let Some(bytes) = original.as_ref() {
        let parent = config_path.parent().context("configuration has no parent directory")?;
        let path = parent.join(format!(".client-before-switch-{}.json", uuid::Uuid::new_v4().simple()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Some(path)
    } else { None };
    if let Some(health) = probe_runtime()? {
        stop_occupant(health.pid)?;
    }
    let changed = change().and_then(|_| {
        crate::progress::phase("\u{542f}\u{52a8} runtime\u{ff1b}\u{6838}\u{5bf9}\u{8d26}\u{6237}\u{548c}\u{8def}\u{5f84}", "Starting runtime; verifying account and path");
        ensure_daemon_locked()
    }).and_then(|_| verify());
    if let Err(error) = changed {
        let cleanup = probe_runtime().and_then(|health| match health {
            Some(health) => stop_occupant(health.pid), None => Ok(()),
        });
        let mut failures = Vec::new();
        if let Err(error) = &cleanup { failures.push(format!("target runtime cleanup failed: {error:#}")); }
        if let Err(error) = rollback() { failures.push(format!("account session rollback failed: {error:#}")); }
        // Startup failure must restore the original selection and all API fields,
        // including the distinction between an absent config and an empty one.
        let restored = match original {
            Some(bytes) => {
                let temporary = config_path.with_file_name(format!(".client-restore-{}.json", uuid::Uuid::new_v4().simple()));
                (|| -> Result<()> {
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
                    let mut file = options.open(&temporary)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    drop(file);
                    std::fs::rename(&temporary, &config_path)?;
                    Ok(())
                })()
            },
            None => match std::fs::remove_file(&config_path) {
                Ok(()) => Ok(()),
                Err(remove) if remove.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(remove) => Err(remove.into()),
            },
        };
        if let Err(error) = &restored { failures.push(format!("configuration rollback failed: {error:#}")); }
        if cleanup.is_ok() && restored.is_ok() {
            if let Err(error) = ensure_daemon_locked() { failures.push(format!("original runtime restart failed: {error:#}")); }
        }
        if !failures.is_empty() {
            if let Some(path) = backup { failures.push(format!("original configuration backup: {}", path.display())); }
            return Err(error.context(failures.join("; ")));
        }
        if let Some(path) = backup {
            if let Err(cleanup) = std::fs::remove_file(&path) { return Err(error.context(format!("configuration restored; backup retained at {}: {cleanup}", path.display()))); }
        }
        maintenance.finish()?;
        return Err(error);
    }
    if let Some(path) = backup {
        if let Err(error) = std::fs::remove_file(&path) { eprintln!("profile verified; configuration backup retained at {}: {error}", path.display()); }
    }
    maintenance.finish()?;
    Ok(())
}

pub fn runtime_entry(flags: RuntimeFlags) -> Result<()> {
    // Split-transition shim: when this CLI exe ends up serving in-process (no
    // managed runtime installed and none fetchable), health and replies must
    // report this binary's train so client version gates keep matching. A real
    // rsrs-runtime child publishes its own identity inside its own process.
    let _ = respire_commands::rpc_serve::publish_shim_identity(env!("CARGO_PKG_VERSION"));
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
    // Serving in-process is deprecated: forward to the managed runtime binary
    // for one release train, then drop this entry entirely. Environments with
    // no managed runtime installed (fresh test envs, offline hosts) fall back
    // to in-process serving until this entry is removed.
    crate::runtime_policy::require_host("runtime startup")?;
    eprintln!("deprecated: forward to the managed runtime; removal in an upcoming release train");
    let executable = match crate::runtime_fetch::resolve_runtime_bin() {
        Ok(crate::runtime_fetch::ResolvedRuntime::Ready(path)) => path,
        Ok(crate::runtime_fetch::ResolvedRuntime::LegacyCombined(_)) => {
            // First-launch migration: the pinned managed runtime is not on disk
            // yet; install it before starting it. Offline hosts cannot fetch it
            // and fall through to in-process serving below.
            match crate::runtime_fetch::download_and_install(None, None) {
                Ok(path) => path,
                Err(_) => return respire_commands::rpc_serve::serve(flags),
            }
        }
        Err(_) => return respire_commands::rpc_serve::serve(flags),
    };
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "serve".into(),
        "--data-dir".into(),
        respire::service::data_dir().into_os_string(),
    ];
    if let Some(port) = flags.port {
        arguments.push("--port".into());
        arguments.push(port.to_string().into());
    }
    let mut child = respire_spawn::spawn_binary_with_boot_token(
        &executable,
        &arguments,
        crate::autostart::lifecycle_boot_token().as_deref(),
    )
    .context("failed to start host runtime")?;
    // The forwarding host stays alive for the serving process's whole lifetime
    // and passes its exit code through unchanged.
    let status = child.wait().context("failed to wait for the host runtime")?;
    crate::set_exit_code(status.code().unwrap_or(1));
    Ok(())
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

pub(crate) fn call_method(method: &str, args: Vec<String>, auto_start: bool) -> Result<RpcResponse> {
    let auto = auto_start && !crate::net_rpc::no_autostart();
    // Validate/start the runtime for this data directory before submitting work.
    // Once submitted, a disconnect must not cause a mutating command to be replayed.
    if auto {
        ensure_daemon()?;
    } else if method == "cli.exec" && needs_inference(&args) && crate::runtime_policy::client_only() {
        anyhow::ensure!(!crate::net_rpc::health()?.inference_stalled(),
            "inference is unresponsive after cancellation; run rsrs from the host terminal to recover the runtime; this request was not submitted");
    }
    let response = http_roundtrip(method, &args)?;
    if !compatible(&response) {
        bail!("local runtime protocol/version mismatch");
    }
    Ok(response)
}

pub(crate) fn call_method_outcome(method: &str, args: Vec<String>, auto_start: bool) -> Result<respire_commands::host_hooks::MethodOutcome> {
    call_method(method, args, auto_start).map(|response| {
        respire_commands::host_hooks::MethodOutcome {
            ok: response.ok,
            error: response.error,
            envelope: response.envelope,
        }
    })
}

pub(crate) fn model_control(task_id: &str, cancel: bool) -> Result<Value> {
    let args = vec![task_id.to_owned(), cancel.to_string()];
    let response = call_method("model.control", args, false)?;
    anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
    response
        .envelope
        .map(|envelope| envelope.summary)
        .ok_or_else(|| anyhow::anyhow!("runtime did not return model progress"))
}

pub(crate) fn prepare_model(mirror: &str) -> Result<()> {
    let response = call_method("model.prepare", vec![mirror.to_owned()], false)?;
    anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
    Ok(())
}

pub(crate) fn profile_request(method: &str, args: Vec<String>) -> Result<Value> {
    let response = call_method(method,args,true)?;
    anyhow::ensure!(response.ok,"{}",response.error.unwrap_or_else(|| "model profile request failed".to_owned()));
    Ok(serde_json::to_value(response.envelope.context("model profile response missing")?)?)
}

fn http_roundtrip(method: &str, args: &[String]) -> Result<RpcResponse> {
    match method {
        "runtime.status" => {
            let health = crate::net_rpc::health()?;
            Ok(RpcResponse {
                v: health.v,
                id: "health".into(),
                ok: true,
                exit: 0,
                bin: health.bin,
                envelope: None,
                error: None,
                code: None,
                web_url: Some(health.url),
                pid: Some(health.pid),
                data_dir: Some(respire::service::data_dir().display().to_string()),
            })
        }
        "runtime.stop" => {
            crate::net_rpc::request_stop()?;
            Ok(RpcResponse {
                v: PROTOCOL_V,
                id: "stop".into(),
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
        "cli.exec" | "cli.progress" | "model.control" | "model.prepare" | "index.prepare" | "model.catalog" | "model.configure" | "model.switch" | "model.resume" | "model.progress" => {
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

// Argv classification and endpoint-record plumbing live in the shared
// rpc_worker module; re-exported so `rpc::...` call sites keep resolving.
pub(crate) use respire_commands::rpc_worker::{
    command_name, command_words, current_url, diary_lexical_mode, endpoint_path, endpoint_pid,
    needs_inference, runtime_dir_path, write_endpoint, GLOBAL_VALUE_FLAGS, PROTOCOL_V, WEB_URL,
    is_context_query, is_status, runtime_dir,
};

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
        if runtime_acceptable(&health)? { return Ok(()); }
    }
    let _takeover = crate::runtime_policy::takeover_lock()?;
    ensure_daemon_locked()
}

pub(crate) fn runtime_acceptable(health: &crate::net_rpc::Health) -> Result<bool> {
    let override_bin = respire::env::var("RSRS_RUNTIME_BIN").ok()
        .map(|raw| std::path::PathBuf::from(raw.trim()))
        .filter(|path| !path.as_os_str().is_empty());
    let managed = crate::runtime_fetch::managed_runtime_path()?;
    // Split-transition shim track: with neither an override nor a managed
    // runtime installed, only this CLI exe serving in-process (health
    // reporting this binary's train) is an acceptable owner; it keeps
    // offline hosts and isolated test environments working for the release
    // train the shim exists for.
    let shim = override_bin.is_none()
        && managed.is_none()
        && health.bin == env!("CARGO_PKG_VERSION")
        && std::env::current_exe()
            .map(|exe| crate::mcp::exe_matches_dest(&health.exe, &exe))
            .unwrap_or(false);
    Ok(!health.data_dir.is_empty() && crate::mcp::same_path(std::path::Path::new(&health.data_dir), &respire::service::data_dir())
        && crate::autostart::may_reuse_runtime(health)?
        && (crate::runtime_fetch::version_in_accept(&health.runtime_version) || shim)
        && override_bin.or(managed)
            .is_none_or(|expected| crate::mcp::exe_matches_dest(&health.exe, &expected))
        && !health.inference_stalled())
}

pub(crate) fn ensure_daemon_locked() -> Result<()> {
    if crate::autostart::ensure_managed_locked()? { return Ok(()); }
    crate::autostart::check_direct_access()?;
    if let Some(health) = probe_runtime()? {
        if runtime_acceptable(&health)? {
            return Ok(());
        }
        if health.inference_stalled() {
            anyhow::ensure!(crate::net_rpc::pid_is_respire(health.pid), "cannot verify the unresponsive runtime process; no lifecycle action taken");
            crate::progress::phase("\u{63a8}\u{7406}\u{65e0}\u{54cd}\u{5e94}\u{ff1b}\u{5bbf}\u{4e3b}\u{6b63}\u{5728}\u{6062}\u{590d} runtime", "Inference unresponsive; host recovering runtime");
        }
        stop_occupant(health.pid)?;
    }
    let self_exe = std::env::current_exe().ok();
    let executable = match crate::runtime_fetch::resolve_runtime_bin() {
        Ok(crate::runtime_fetch::ResolvedRuntime::Ready(path)) => path,
        Ok(crate::runtime_fetch::ResolvedRuntime::LegacyCombined(_)) | Err(_) => {
            // First-launch migration: the old owner was stopped above; bring
            // the pinned managed runtime down before starting the new one.
            // Offline hosts and isolated test environments cannot fetch it
            // and fall back to this CLI exe serving in-process (the
            // --runtime-internal shim) for the transition train.
            match crate::runtime_fetch::download_and_install(None, None) {
                Ok(path) => path,
                Err(_) => self_exe
                    .clone()
                    .context("no runtime binary resolved and no local fallback executable")?,
            }
        }
    };
    crate::autostart::authorize_detached_boot_locked()?;
    let shim = self_exe
        .as_ref()
        .is_some_and(|exe| crate::mcp::same_path(exe, &executable));
    let arguments: Vec<std::ffi::OsString> = if shim {
        // The shim child reuses this binary's --runtime-internal entry, whose
        // own fallback serves in-process; the data directory and port arrive
        // through the inherited environment.
        vec!["--runtime-internal".into()]
    } else {
        vec![
            "serve".into(),
            "--data-dir".into(),
            respire::service::data_dir().into_os_string(),
        ]
    };
    let mut child =
        respire_spawn::spawn_binary_with_boot_token(&executable, &arguments, crate::autostart::lifecycle_boot_token().as_deref()).context("failed to start host runtime")?;
    let result = wait_daemon_ready(&mut child, &executable);
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

// A shutdown can finish before its HTTP acknowledgement is flushed. Never
// replay the request: accept only an independently confirmed stopped owner.
fn confirm_stop_outcome(request: Result<()>, confirm: impl FnOnce() -> Result<()>) -> Result<()> {
    match request {
        Ok(()) => Ok(()),
        Err(error) => {
            if matches!(error.downcast_ref::<crate::runtime_error::RuntimeError>(),
                Some(crate::runtime_error::RuntimeError::Transport(_))) && confirm().is_ok() {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

pub(crate) fn stop_occupant(pid: u32) -> Result<()> {
    let health = crate::net_rpc::health()?;
    anyhow::ensure!(health.pid == pid, "runtime owner changed before shutdown");
    confirm_stop_outcome(crate::net_rpc::request_stop(), || {
        crate::net_rpc::wait_until_exited(pid)?;
        crate::net_rpc::wait_until_down()
    })?;
    if crate::autostart::lifecycle_boot_token().is_some() {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline && crate::net_rpc::process_is_running(pid)? {
            std::thread::sleep(Duration::from_millis(100));
        }
        anyhow::ensure!(!crate::net_rpc::process_is_running(pid)?, "managed runtime did not drain; maintenance remains paused without forcing database shutdown");
    }
    if crate::net_rpc::wait_until_down().is_err() {
        // Reauthenticate before escalation; a different owner may have bound.
        if let Some(health) = probe_runtime()? {
            anyhow::ensure!(health.pid == pid, "runtime owner changed during shutdown");
            crate::net_rpc::kill_pid(pid);
            crate::net_rpc::wait_until_down()?;
        }
    }
    crate::net_rpc::wait_until_exited(pid)?;
    // Prove lock.db has been released before a successor opens the library.
    let released = respire::lock::LibraryLock::acquire(
        std::path::Path::new(&health.data_dir), Duration::from_secs(15),
    ).context("stopped runtime has not released its library lock")?;
    drop(released);
    Ok(())
}

fn wait_daemon_ready(child: &mut std::process::Child, executable: &std::path::Path) -> Result<()> {
    let deadline = Instant::now() + START_WAIT * START_POLLS as u32;
    while Instant::now() < deadline {
        std::thread::sleep(START_WAIT);
        if let Some(status) = child.try_wait()? {
            bail!("host runtime exited before readiness: {status}");
        }
        if let Some(health) = probe_runtime()? {
            anyhow::ensure!(
                health.pid == child.id()
                    && crate::mcp::exe_matches_dest(&health.exe, executable)
                    // Legacy combined binaries carry this CLI's exact version;
                    // the standalone runtime reports its own train, accepted
                    // through the pinned version window instead.
                    && (health.bin == env!("CARGO_PKG_VERSION")
                        || crate::runtime_fetch::version_in_accept(&health.runtime_version))
                    && !health.data_dir.is_empty() && crate::mcp::same_path(std::path::Path::new(&health.data_dir), &respire::service::data_dir()),
                "runtime owner changed during startup"
            );
            return Ok(());
        }
    }
    bail!("host runtime did not become ready")
}

#[cfg(test)]
#[path = "rpc_dispatch_tests.rs"]
mod dispatch_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::atomic::Ordering;

    #[test]
    fn diary_inference_routing_honours_modes_and_literal_query_arguments() {
        use clap::Parser;
        for (args,inference) in [
            (vec!["diary-search","q"],true),
            (vec!["diary-search","q","--mode","lexical"],false),
            (vec!["diary-search","--mode=lexical","q"],false),
            (vec!["diary-search","--mode","hybrid","--","--mode=lexical"],true),
            (vec!["diary-search","--","--mode=lexical"],true),
            (vec!["diary-search","--mode","lexical","--","--mode=hybrid"],false),
            (vec!["diary-fragment","--neighbors","1","--","s","f"],false),
        ] {
            let arguments:Vec<String>=args.iter().map(|s|(*s).to_owned()).collect();
            assert_eq!(needs_inference(&arguments),inference,"{arguments:?}");
            let parsed=crate::Cli::try_parse_from(std::iter::once("rsrs").chain(args)).unwrap();
            if let Some(crate::Command::DiarySearch{query,mode,..})=parsed.command {
                if query=="--mode=lexical" {assert_eq!(mode,"hybrid");}
                if query=="--mode=hybrid" {assert_eq!(mode,"lexical");}
            }
        }
    }

    #[test]
    fn shutdown_transport_requires_confirmed_exit_without_replay() {
        use crate::runtime_error::RuntimeError;
        assert!(confirm_stop_outcome(Err(RuntimeError::Transport("lost ack".into()).into()), || Ok(())).is_ok());
        let rejected = confirm_stop_outcome(Err(RuntimeError::Transport("original lost ack".into()).into()), || anyhow::bail!("still alive"));
        assert!(rejected.is_err_and(|error| error.to_string().contains("original lost ack")));
        for error in [RuntimeError::Unauthorized, RuntimeError::Unavailable,
            RuntimeError::TokenUnreadable("synthetic".into()),
            RuntimeError::OutcomeUnknown { request_id: "synthetic".into(), detail: "unknown".into() }] {
            let mut called = false;
            assert!(confirm_stop_outcome(Err(error.into()), || { called = true; Ok(()) }).is_err());
            assert!(!called, "non-transport failures must never become a successful stop");
        }
        let mut called = false;
        assert!(confirm_stop_outcome(Ok(()), || { called = true; Ok(()) }).is_ok());
        assert!(!called);
    }

    fn req(method: &str, id: &str) -> RpcRequest {
        RpcRequest {
            v: PROTOCOL_V,
            id: id.to_owned(),
            method: method.to_owned(),
            args: Vec::new(),
            queue_wait_ms: None,
            lifecycle: None,
        }
    }

    #[test]
    fn supervised_drain_waits_past_legacy_deadline_until_work_finishes() -> Result<()> {
        let busy=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (managed_tx,managed_rx)=mpsc::channel();
        let work=busy.clone();
        let managed=std::thread::spawn(move || {wait_for_drain(true,||work.load(Ordering::Acquire));let _=managed_tx.send(());});
        let (legacy_tx,legacy_rx)=mpsc::channel();
        let work=busy.clone();
        let legacy=std::thread::spawn(move || {wait_for_drain(false,||work.load(Ordering::Acquire));let _=legacy_tx.send(());});
        let legacy_result=legacy_rx.recv_timeout(Duration::from_secs(6));
        let still_waiting=managed_rx.try_recv().is_err();
        busy.store(false,Ordering::Release);
        managed_rx.recv_timeout(Duration::from_secs(2))?;
        managed.join().map_err(|_|anyhow::anyhow!("managed drain panicked"))?;
        legacy.join().map_err(|_|anyhow::anyhow!("legacy drain panicked"))?;
        anyhow::ensure!(legacy_result.is_ok() && still_waiting,
            "supervised drain exited while work remained or legacy shutdown timing changed");
        Ok(())
    }

    #[test]
    fn worker_limit_follows_env_then_cpu() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let previous = respire::env::var("RSRS_RPC_PARALLELISM").ok();
        std::env::set_var("RSRS_RPC_PARALLELISM", "3");
        assert_eq!(worker_limit(), 3.min(cpu_count()));
        std::env::set_var("RSRS_RPC_PARALLELISM", "0");
        assert_eq!(worker_limit(), cpu_count());
        std::env::set_var("RSRS_RPC_PARALLELISM", "cpu");
        assert_eq!(worker_limit(), cpu_count());
        std::env::set_var("RSRS_RPC_PARALLELISM", "20");
        assert_eq!(worker_limit(), 20.min(cpu_count()));
        std::env::set_var("RSRS_RPC_PARALLELISM", "1000");
        assert_eq!(worker_limit(), 1000.min(cpu_count()));
        assert!(cpu_count() >= 1);
        match previous {
            Some(value) => std::env::set_var("RSRS_RPC_PARALLELISM", value),
            None => std::env::remove_var("RSRS_RPC_PARALLELISM"),
        }
    }

    #[test]
    fn writes_queue_and_reads_may_run_together() {
        for args in [vec!["account", "list"], vec!["config"], vec!["agent-config"],
            vec!["session", "list"], vec!["space", "list"], vec!["space", "members"]] {
            let args = args.into_iter().map(String::from).collect::<Vec<_>>();
            assert!(is_context_query(&args));
            assert!(!is_exclusive(&args));
        }
        for args in [vec!["account", "use", "main"], vec!["config", "--autosync", "false"],
            vec!["agent-config", "--set", "model_mirror=auto"], vec!["session", "revoke", "fixture"],
            vec!["space", "use", "fixture"]] {
            let args = args.into_iter().map(String::from).collect::<Vec<_>>();
            assert!(!is_context_query(&args));
            assert!(is_exclusive(&args));
        }
        assert!(is_exclusive(&["--json".into(), "sync".into()]));
        assert!(is_exclusive(&["reembed".into()]));
        assert!(!is_exclusive(&["remember".into(), "x".into()]));
        assert!(!is_exclusive(&["update".into(), "id".into()]));
        assert!(is_exclusive(&["forget".into(), "id".into()]));
        assert!(is_exclusive(&["attach".into(), "id".into()]));
        assert!(!is_exclusive(&["recall".into(), "respire".into()]));
        assert!(!is_exclusive(&["status".into()]));
        assert!(!is_exclusive(&["memory-revision".into()]));
        assert!(!is_exclusive(&["list".into()]));
        assert!(!is_exclusive(&["show".into(), "id".into()]));
        assert!(!is_exclusive(&["sync-history".into()]));
        assert!(!is_exclusive(&["diary".into()]));
        assert!(worker_limit() <= cpu_count());
    }

    #[test]
    fn routing_value_flags_match_the_actual_cli_contract() {
        use clap::CommandFactory;
        let mut command = crate::Cli::command();
        command.build();
        let actual: std::collections::BTreeSet<_> = command.get_arguments()
            .filter(|arg| arg.is_global_set() && arg.get_action().takes_values())
            .filter_map(|arg| arg.get_long().map(|name| format!("--{name}")))
            .collect();
        let expected = GLOBAL_VALUE_FLAGS.iter().map(|flag| (*flag).to_owned()).collect();
        assert_eq!(actual, expected, "new valued globals must update the shared argv classifier");
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
        let tracked = ["--json", "--progress-id", "request-one", "--model-task-id", "task-one", "remember", "body"]
            .map(String::from);
        assert_eq!(command_name(&tracked), Some("remember"));
        assert!(!is_exclusive(&tracked));
        assert!(needs_inference(&tracked));
        assert!(!needs_inference(&["status".into()]));
    }

    #[test]
    fn compatible_requires_version_and_bin() {
        let mut response = status_response(&req("runtime.status", "s"));
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
    fn cache_ignores_empty_ids_and_drops_oldest() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let response = error_response(&req("x", "id"), "timeout", "slow");
        remember("", &response);
        assert!(cached("").is_none());
        for index in 0..70 {
            let id = format!("id-{index}");
            remember(&id, &status_response(&req("runtime.status", &id)));
        }
        assert!(cached("id-0").is_none());
        assert!(cached("id-69").is_some());
    }

    #[test]
    fn dispatch_reports_status_mismatch_and_unknown() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let (tx, _rx) = mpsc::channel();
        let mut bad = req("runtime.status", "bad");
        bad.v = 0;
        let mismatch = dispatch(bad, &tx);
        assert_eq!(mismatch.code.as_deref(), Some("protocol_version_mismatch"));
        let status = dispatch(req("runtime.status", "status-1"), &tx);
        assert!(status.ok);
        assert_eq!(status.web_url.as_deref(), Some(current_url().as_str()));
        let again = dispatch(req("runtime.status", "status-1"), &tx);
        assert_eq!(again.id, "status-1");
        let unknown = dispatch(req("nope", "unknown-1"), &tx);
        assert_eq!(unknown.code.as_deref(), Some("protocol_version_mismatch"));
        assert!(unknown.error.unwrap_or_default().contains("unknown method"));
        let scope = crate::progress::Scope::start(Some("foreground-one".into()), false, false);
        crate::progress::phase("\u{7b49}\u{5f85}\u{670d}\u{52a1}\u{5668}", "Waiting for server");
        let mut request = req("cli.progress", "progress-one");
        request.args = vec!["foreground-one".into()];
        let response = dispatch(request, &tx);
        assert!(response.envelope.as_ref().is_some_and(|value| value.summary["phase"].is_string()));
        let mut request = req("cli.progress", "progress-other");
        request.args = vec!["foreground-other".into()];
        let unrelated = dispatch(request, &tx);
        assert!(unrelated.envelope.as_ref().is_some_and(|value| value.summary["phase"].is_null()));
        assert!(unrelated.envelope.as_ref().is_some_and(|value| value.summary["inference"]["capacity"] == 64
                && value.summary["inference"]["foreground"]["capacity"] == 32
                && value.summary["inference"]["background"]["capacity"] == 32));
        drop(scope);
        assert!(crate::progress::status("foreground-one").is_null());
    }

    #[test]
    fn deferred_requests_return_before_execution_and_reply_exactly_once() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let (tx, rx) = mpsc::channel();
        let (finished, response) = mpsc::channel();
        let mut request = req("cli.exec", "deferred-test-write");
        request.args = vec!["show".into(), "synthetic-id".into()];
        dispatch_deferred(request, &tx, move |value| { let _ = finished.send(value); });
        // Dispatch did not wait for a worker or create a waiting transport thread.
        let job = rx.recv_timeout(Duration::from_secs(1))?;
        assert!(response.try_recv().is_err());
        assert!(job.deadline.start());
        assert!(!job.deadline.cancel(), "an executing write must keep its actual result");
        let reply = job.reply.clone();
        reply.send(Err("synthetic native failure after execution".into())).map_err(anyhow::Error::msg)?;
        let result = response.recv_timeout(Duration::from_secs(1))?;
        assert!(result.error.as_deref().is_some_and(|error| error.contains("synthetic native failure")));
        assert!(reply.send(Err("duplicate".into())).is_err());
        assert!(response.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn cancelled_deferred_request_cannot_execute_a_write() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let (tx, rx) = mpsc::channel();
        let (finished, response) = mpsc::channel();
        let mut request = req("cli.exec", "deferred-test-cancelled");
        request.args = vec!["show".into(), "synthetic-id".into()];
        request.queue_wait_ms = Some(0);
        dispatch_deferred(request, &tx, move |value| { let _ = finished.send(value); });
        let job = rx.recv_timeout(Duration::from_secs(1))?;
        assert!(job.deadline.expired());
        assert!(!job.deadline.start());
        let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
        assert!(response.recv_timeout(Duration::from_secs(1))?.error.as_deref().is_some_and(|error| error.contains("not started")));
        // A subsequent accepted request has an independent deadline and succeeds.
        let (finished, response) = mpsc::channel();
        let mut request = req("cli.exec", "deferred-test-next");
        request.args = vec!["show".into(), "synthetic-id".into()];
        dispatch_deferred(request, &tx, move |value| { let _ = finished.send(value); });
        let job = rx.recv_timeout(Duration::from_secs(1))?;
        assert!(job.deadline.start());
        job.reply.send(Ok(crate::Captured { exit: 0, envelope: ResultEnvelope::new("show", OutputStatus::Ok, json!({}), Vec::new()) })).map_err(anyhow::Error::msg)?;
        assert!(response.recv_timeout(Duration::from_secs(1))?.ok);
        Ok(())
    }

    #[test]
    fn queue_expiry_does_not_require_a_responsive_worker() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let (tx, rx) = mpsc::channel();
        let (done, receive) = mpsc::channel();
        let mut request = req("cli.exec", "unresponsive-queue-write");
        request.args = vec!["remember".into(), "synthetic write".into()];
        request.queue_wait_ms = Some(30);
        dispatch_deferred(request, &tx, move |response| { let _ = done.send(response); });
        // Fault injection: no dispatcher/worker consumes this accepted job.
        let response = receive.recv_timeout(Duration::from_secs(1))?;
        assert!(response.error.as_deref().is_some_and(|error| error.contains("not started")));
        let job = rx.recv_timeout(Duration::from_secs(1))?;
        assert!(!job.deadline.start());
        Ok(())
    }

    #[test]
    fn started_write_keeps_result_across_client_deadline_and_duplicate_id() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let (tx, rx) = mpsc::channel();
        let (done, receive) = mpsc::channel();
        let mut request = req("cli.exec", "held-started-write");
        request.args = vec!["remember".into(), "synthetic write".into()];
        request.queue_wait_ms = Some(50);
        dispatch_deferred(request, &tx, move |response| { let _ = done.send(response); });
        let job = rx.recv_timeout(Duration::from_secs(1))?;
        assert!(job.deadline.start());
        // Controlled execution ignores cancellation while it is held, then returns.
        std::thread::sleep(Duration::from_millis(100));
        assert!(!job.deadline.cancel());
        assert!(receive.try_recv().is_err());
        let (done, duplicate) = mpsc::channel();
        let mut request = req("cli.exec", "held-started-write");
        request.args = vec!["remember".into(), "synthetic write".into()];
        dispatch_deferred(request, &tx, move |response| { let _ = done.send(response); });
        assert_eq!(duplicate.recv_timeout(Duration::from_secs(1))?.code.as_deref(), Some("request_in_progress"));
        assert!(rx.try_recv().is_err(), "same ID must not create another write");
        let mut inspect = req("runtime.result", "inspect-pending-write");
        inspect.args = vec!["held-started-write".into()];
        assert_eq!(dispatch(inspect, &tx).envelope.as_ref().map(|value| &value.summary["state"]), Some(&json!("pending")));
        job.reply.send(Ok(crate::Captured { exit: 0, envelope: ResultEnvelope::new("remember", OutputStatus::Ok, json!({"committed":true}), Vec::new()) })).map_err(anyhow::Error::msg)?;
        assert!(receive.recv_timeout(Duration::from_secs(1))?.ok);
        let mut inspect = req("runtime.result", "inspect-completed-write");
        inspect.args = vec!["held-started-write".into()];
        let response = dispatch(inspect, &tx);
        assert!(response.envelope.as_ref().is_some_and(|value| value.summary["state"] == "completed" && value.summary["response"]["envelope"]["summary"]["committed"] == true));
        Ok(())
    }

    #[test]
    fn http_pipeline_with_held_execution_and_nonreading_peer() -> Result<()> {
        use std::net::TcpStream;
        // A child gives the controlled dispatcher its own process-global sender.
        // No real account, model, or source records are modified by this test.
        if std::env::var_os("RSRS_TRANSPORT_TEST_CHILD").is_none() {
            let profile = tempfile::tempdir()?;
            let output = Command::new(std::env::current_exe()?)
                .args(["--exact", "rpc::tests::http_pipeline_with_held_execution_and_nonreading_peer", "--nocapture", "--test-threads=1"])
                .env("RSRS_TRANSPORT_TEST_CHILD", "1")
                .env("RSRS_DATA_DIR", profile.path())
                .env("RSRS_CORE_TEST_MODE", "1")
                .env_remove("RSRS_RPC_TOKEN")
                .output()?;
            anyhow::ensure!(output.status.success(), "isolated transport regression failed: {} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return Ok(());
        }
        let (tx, rx) = mpsc::channel();
        anyhow::ensure!(JOB_TX.set(Mutex::new(tx.clone())).is_ok(), "child sender already initialized");
        WORKERS.store(1, Ordering::Release);
        let bound = crate::runtime_http::bind_runtime(Some(0), "127.0.0.1")?;
        let address = bound.server.local_addr()?;
        let base = bound.url;
        std::thread::spawn(move || { let _ = crate::runtime_http::serve_loop(bound.server); });
        let url = format!("{base}/api/rpc");
        let blocker = std::thread::spawn(move || -> Result<serde_json::Value> {
            Ok(ureq::post(&url).timeout(Duration::from_secs(5)).send_json(json!({"v":1,"id":"held-slot","method":"cli.exec","args":["remember","controlled blocker"]}))?.into_json()?)
        });
        let held = rx.recv_timeout(Duration::from_secs(2))?;
        anyhow::ensure!(held.deadline.start(), "blocker expired before start");
        RUNNING.store(1, Ordering::Release);
        let mut pipeline = TcpStream::connect(address)?;
        pipeline.set_read_timeout(Some(Duration::from_secs(5)))?;
        for (id, wait) in [("held-pipeline-a", None), ("held-pipeline-b", Some(0u64))] {
            let mut body = json!({"v":1,"id":id,"method":"cli.exec","args":["remember","controlled queued write"]});
            if let Some(wait) = wait { body["queue_wait_ms"] = json!(wait); }
            let body = body.to_string();
            let connection = if wait.is_some() { "Connection: close\r\n" } else { "" };
            write!(pipeline, "POST /api/rpc HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\n{connection}Content-Length: {}\r\n\r\n{body}", body.len())?;
        }
        let queued = rx.recv_timeout(Duration::from_secs(2))?;
        anyhow::ensure!(!queued.deadline.running(), "queued request consumed the held execution slot");
        let health: Value = ureq::get(&format!("{base}/api/health")).timeout(Duration::from_secs(1)).call()?.into_json()?;
        anyhow::ensure!(health["pid"] == std::process::id(), "control channel was blocked");
        let captured = || crate::Captured { exit: 0, envelope: ResultEnvelope::new("remember", OutputStatus::Ok, json!({"committed":true}), Vec::new()) };
        held.reply.send(Ok(captured())).map_err(anyhow::Error::msg)?;
        RUNNING.store(0, Ordering::Release);
        anyhow::ensure!(blocker.join().map_err(|_| anyhow::anyhow!("blocker client panicked"))??["ok"] == true, "blocker result lost");
        anyhow::ensure!(queued.deadline.start(), "A expired before the held slot was released");
        // Sending a large reply while the peer does not read must not hold the
        // actor/worker. Only the async connection task may wait for socket space.
        let mut large = captured();
        large.envelope.details = json!({"controlled_payload":"x".repeat(8*1024*1024)});
        let start = Instant::now();
        queued.reply.send(Ok(large)).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(start.elapsed() < Duration::from_millis(200), "response I/O blocked the execution actor");
        std::thread::sleep(Duration::from_millis(100));
        let health: Value = ureq::get(&format!("{base}/api/health")).timeout(Duration::from_secs(1)).call()?.into_json()?;
        anyhow::ensure!(health["pid"] == std::process::id(), "slow-reader blocked control");
        let mut wire = String::new();
        pipeline.read_to_string(&mut wire)?;
        let first = wire.find("held-pipeline-a").ok_or_else(|| anyhow::anyhow!("pipeline A reply missing"))?;
        let second = wire.find("held-pipeline-b").ok_or_else(|| anyhow::anyhow!("pipeline B reply missing"))?;
        anyhow::ensure!(first < second, "pipeline replies reordered");
        anyhow::ensure!(wire.contains("command was not started"), "B did not expire before execution");
        let cancelled = rx.recv_timeout(Duration::from_secs(2))?;
        anyhow::ensure!(!cancelled.deadline.start(), "expired B executed a write");
        Ok(())
    }

    #[test]
    fn sync_snapshot_wait_does_not_stop_dispatching_reads_and_cancelled_sync_never_starts() -> Result<()> {
        if std::env::var_os("RSRS_SYNC_GATE_TEST_CHILD").is_none() {
            let profile = tempfile::tempdir()?;
            let output = Command::new(std::env::current_exe()?)
                .args(["--exact", "rpc::tests::sync_snapshot_wait_does_not_stop_dispatching_reads_and_cancelled_sync_never_starts", "--nocapture", "--test-threads=1"])
                .env("RSRS_SYNC_GATE_TEST_CHILD", "1")
                .env("RSRS_DATA_DIR", profile.path())
                .env("RSRS_CORE_TEST_MODE", "1")
                .env("RSRS_NO_AUTOSYNC", "1")
                .env_remove("RSRS_RPC_TOKEN")
                .output()?;
            anyhow::ensure!(output.status.success(), "isolated sync gate regression failed: {} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return Ok(());
        }
        let (tx, rx) = mpsc::channel();
        WORKERS.store(1, Ordering::Release);
        let library = respire::lock::LibraryLock::acquire(&respire::service::data_dir(), Duration::from_secs(120))?;
        std::thread::spawn(move || dispatch_loop(rx, 1, None, library));
        let commands = [vec!["--json".into(), "show".into(), "controlled-missing-id".into()],
            vec!["--json".into(), "recall".into(), "controlled empty-profile query".into(), "--no-related".into()]];
        let mut original = Vec::new();
        for args in &commands {
            original.push(submit(&tx, args.clone(), false).map_err(anyhow::Error::msg)?);
        }
        // This test concerns routing, not native retrieval: preserve the exact
        // original terminal outcomes of the isolated empty profile's reads.
        let gate = shared_exclusive();
        let held = gate.acquire(true);
        let (done, result) = mpsc::channel();
        let sync = enqueue_job(&tx, vec!["sync".into()], false,
            Reply::new(move |response| { let _ = done.send(response); }), Duration::from_millis(60)).map_err(anyhow::Error::msg)?;
        for (args, before) in commands.iter().zip(original.iter()) {
            let (done, result) = mpsc::channel();
            enqueue_job(&tx, args.clone(), false, Reply::new(move |response| { let _ = done.send(response); }), Duration::from_secs(1)).map_err(anyhow::Error::msg)?;
            let after = result.recv_timeout(Duration::from_secs(2))?.map_err(anyhow::Error::msg)?;
            anyhow::ensure!(after.exit == before.exit && std::mem::discriminant(&after.envelope.status) == std::mem::discriminant(&before.envelope.status) && after.envelope.errors == before.envelope.errors,
                "read changed outcome or stopped progressing while sync snapshot awaited the write gate");
        }
        let expired = result.recv_timeout(Duration::from_secs(1))?;
        anyhow::ensure!(expired.as_ref().err().is_some_and(|error| error.contains("not started")), "waiting sync did not expire");
        anyhow::ensure!(!sync.running() && sync.expired(), "sync ran before its snapshot gate was available");
        drop(held);
        let until = Instant::now() + Duration::from_secs(2);
        while SYNC_RUNNING.load(Ordering::Acquire) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        anyhow::ensure!(!sync.running(), "cancelled sync started after the gate was released");
        anyhow::ensure!(!SYNC_RUNNING.load(Ordering::Acquire), "sync worker did not recover after cancellation");
        Ok(())
    }

    #[test]
    fn submit_reports_busy_status_and_dead_worker() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        WORKERS.store(1, Ordering::Release);
        RUNNING.store(3, Ordering::Release);
        LIGHT_RUNNING.store(2, Ordering::Release);
        let (tx, _rx) = mpsc::channel();
        let busy = submit(&tx, vec!["--json".into(), "status".into()], false)
            .map_err(|err| anyhow::anyhow!(err))?;
        assert_eq!(busy.exit, 2);
        LIGHT_RUNNING.store(0, Ordering::Release);
        RUNNING.store(0, Ordering::Release);
        let (tx, rx) = mpsc::channel();
        drop(rx);
        assert!(submit(&tx, vec!["remember".into()], false).is_err());
        if JOB_TX.get().is_none() {
            assert!(execute_json(vec!["status".into()]).is_err());
        }
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
        STOPPING.store(false, Ordering::Release);
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
        write_endpoint("http://127.0.0.1:9")?;
        assert_eq!(endpoint_pid(), Some(std::process::id()));
        assert_eq!(current_url(), current_url());
        let bare = status_response(&req("runtime.status", "render-none"));
        assert!(render_response(bare, true).is_err());
        let mut with_body = status_response(&req("runtime.status", "render-body"));
        with_body.envelope = Some(crate::output::ResultEnvelope::new(
            "status",
            OutputStatus::Ok,
            json!({"ok": true}),
            Vec::new(),
        ));
        render_response(with_body, true)?;
        assert!(render_response(
            error_response(&req("cli.exec", "render-err"), "timeout", "slow"),
            false,
        )
        .is_err());
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
    fn diary_commit_rechecks_mode_generation_shutdown_and_lifecycle_ownership() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let root = tempfile::tempdir()?;
        let previous = std::env::var_os("RSRS_DATA_DIR");
        std::env::set_var("RSRS_DATA_DIR", root.path());
        let generation = GENERATION.load(Ordering::Acquire);
        let previous_stopping = STOPPING.swap(false, Ordering::AcqRel);
        let result = (|| -> Result<()> {
            let _operation = respire::model_progress::Operation::begin("index")?;
            let mut writes = 0;
            respire::service::set_workspace_mode("normal")?;
            diary_commit(generation, &mut || { writes += 1; Ok(()) })?;
            assert_eq!(writes, 1);
            for mode in ["readonly", "off"] {
                respire::service::set_workspace_mode(mode)?;
                assert!(diary_commit(generation, &mut || { writes += 1; Ok(()) }).is_err());
                assert_eq!(writes, 1);
            }
            respire::service::set_workspace_mode("normal")?;
            assert!(diary_commit(generation.wrapping_add(1), &mut || { writes += 1; Ok(()) }).is_err());
            STOPPING.store(true, Ordering::Release);
            assert!(diary_commit(generation, &mut || { writes += 1; Ok(()) }).is_err());
            STOPPING.store(false, Ordering::Release);
            let lifecycle = crate::runtime_policy::takeover_lock()?;
            assert!(diary_commit(generation, &mut || { writes += 1; Ok(()) }).is_err());
            assert_eq!(writes, 1);
            drop(lifecycle);
            diary_commit(generation, &mut || { writes += 1; Ok(()) })?;
            assert_eq!(writes, 2);
            Ok(())
        })();
        STOPPING.store(previous_stopping, Ordering::Release);
        match previous { Some(value) => std::env::set_var("RSRS_DATA_DIR", value), None => std::env::remove_var("RSRS_DATA_DIR") }
        result
    }

}

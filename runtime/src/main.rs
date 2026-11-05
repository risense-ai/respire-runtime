//! Standalone `rsrs-runtime` binary: the loopback RPC host split out of the
//! CLI binary (runtime split WP-3, milestone M1 "two runnable binaries").
//!
//! Argv contract (HANDOFF 2026-11-03 item 9; client2's `stopManaged`/
//! `startManaged` depends on these exact shapes):
//!
//! | argv                                   | behaviour                                  |
//! |----------------------------------------|--------------------------------------------|
//! | `serve [--host H] [--port P] [--data-dir D] [--supervised]` | serve until stopped |
//! | `--json runtime start` / `runtime start` | legacy foreground alias for `serve`; no readiness claim |
//! | `--json runtime stop` / `runtime stop` / `--stop` | ask the resident runtime to stop |
//! | `--status`                              | probe the resident runtime health          |
//! | `--version`                             | print the binary version                   |
//!
//! Unknown arguments print an error and exit with code 2. The boot token is
//! consumed with `respire_spawn` semantics: `RSRS_RUNTIME_BOOT_TOKEN` is read
//! and then removed from this process's environment.

mod startup_identity;
mod host_control;
mod maintenance_control;
mod snapshot_authority;
mod secret_control;
mod identity_control;
mod identity_write_control;
mod config_control;
mod key_control;
mod model_maintenance;
mod auth_control;

use std::io::Write;
use std::process::ExitCode;

use anyhow::{Context, Result};

use respire_commands::host_hooks::{self, HostHooks};
use respire_commands::net_rpc;
use respire_commands::rpc_serve::{self, RuntimeFlags};
use respire_protocol::{RuntimeCompat, RuntimeIdentity};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// CLI compatibility window for this runtime train (runtime-pin.json aligns).
const MIN_CLI: &str = "1.0.21-dev.5";
const MAX_CLI: &str = "*";

fn main() -> ExitCode {
    // Remove the inherited secret before any worker or business code can spawn.
    match consume_boot_token().and_then(run) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("rsrs-runtime: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn consume_boot_token() -> Result<Option<String>> {
    let token = std::env::var_os("RSRS_RUNTIME_BOOT_TOKEN");
    std::env::remove_var("RSRS_RUNTIME_BOOT_TOKEN");
    token
        .map(|token| {
            token
                .into_string()
                .map_err(|_| anyhow::anyhow!("runtime boot token is not valid Unicode"))
        })
        .transpose()
}

struct Flags {
    json: bool,
    serve: bool,
    stop: bool,
    status: bool,
    version: bool,
    host: String,
    port: Option<u16>,
    data_dir: Option<std::path::PathBuf>,
    supervised: bool,
}

impl Default for Flags {
    fn default() -> Self {
        Self {
            json: false,
            serve: false,
            stop: false,
            status: false,
            version: false,
            host: "127.0.0.1".to_owned(),
            port: None,
            data_dir: None,
            supervised: false,
        }
    }
}

fn usage() -> &'static str {
    "Usage: rsrs-runtime serve [--host 127.0.0.1] [--port 15169] [--data-dir DIR] [--supervised]\n       rsrs-runtime [--json] runtime start|stop|status\n       rsrs-runtime --stop | --status | --version\n"
}

fn run(boot_token: Option<String>) -> Result<i32> {
    if std::env::args().nth(1).as_deref() == Some("--host-control-internal") {
        anyhow::ensure!(
            boot_token.is_none() && std::env::args_os().count() == 2,
            "private host control accepts no boot token or public runtime arguments"
        );
        return host_control::run();
    }
    if std::env::args().nth(1).as_deref() == Some("--backend-load-probe-internal") {
        anyhow::ensure!(boot_token.is_none() && std::env::args_os().count() == 2,
            "private backend probe accepts no boot token or public runtime arguments");
        // Dispatch before flags, authorization, hooks, keyring, store or listener initialization.
        respire_commands::model_install::run_backend_probe_helper()?;
        return Ok(0);
    }
    if std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--core-worker-internal")
    {
        anyhow::ensure!(
            boot_token.is_none(),
            "core workers cannot consume runtime boot authorization"
        );
        return match respire_core_sdk::worker::run() {
            Ok(()) => Ok(0),
            Err(error) => {
                eprintln!("core worker: {error:#}");
                Ok(2)
            }
        };
    }
    let mut flags = Flags::default();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => flags.json = true,
            "serve" => flags.serve = true,
            "--stop" => flags.stop = true,
            "--status" => flags.status = true,
            "--version" => flags.version = true,
            "--supervised" => flags.supervised = true,
            "--host" => {
                let value = args.next().context("--host requires a value")?;
                anyhow::ensure!(!value.is_empty(), "--host requires a loopback address");
                flags.host = value;
            }
            "--port" => {
                let value = args.next().context("--port requires a value")?;
                let port: u16 = value.parse().map_err(|_| {
                    anyhow::anyhow!("--port requires a numeric port between 1 and 65535")
                })?;
                anyhow::ensure!(
                    port > 0,
                    "--port requires a numeric port between 1 and 65535"
                );
                flags.port = Some(port);
            }
            "--data-dir" => {
                let value = args.next().context("--data-dir requires a value")?;
                flags.data_dir = Some(std::path::PathBuf::from(value));
            }
            "runtime" => {
                let verb = args.next().unwrap_or_default();
                match verb.as_str() {
                    "start" => flags.serve = true,
                    "stop" => flags.stop = true,
                    "status" => flags.status = true,
                    "version" => flags.version = true,
                    other => {
                        eprintln!("unknown runtime verb: {other}\n{}", usage());
                        return Ok(2);
                    }
                }
            }
            other => {
                eprintln!("unknown argument: {other}\n{}", usage());
                return Ok(2);
            }
        }
    }
    let requested = [flags.serve, flags.stop, flags.status, flags.version]
        .into_iter()
        .filter(|requested| *requested)
        .count();
    anyhow::ensure!(
        requested <= 1,
        "combine at most one of start/serve, stop, status, version\n{}",
        usage()
    );

    anyhow::ensure!(
        !(flags.status || flags.stop || flags.version)
            || (!flags.supervised && boot_token.is_none()),
        "boot authorization and --supervised are only valid when serving"
    );
    if flags.version {
        if flags.json {
            print_envelope("version", true, 0, None, None);
        } else {
            println!("rsrs-runtime {VERSION}");
        }
        return Ok(0);
    }
    apply_data_dir(&flags);
    if let Err(error) = respire_app::service::validate_client_config() {
        if flags.json {
            print_envelope("configuration", false, 2, Some(&format!("{error:#}")), None);
            return Ok(2);
        }
        return Err(error).context("Runtime client configuration is invalid");
    }
    if flags.status {
        return status_command(flags.json);
    }
    if flags.stop {
        return stop_command(flags.json);
    }
    // Bare invocation defaults to serving, mirroring `--runtime-internal`.
    serve_command(&flags, boot_token.as_deref())
}

fn apply_data_dir(flags: &Flags) {
    if let Some(dir) = &flags.data_dir {
        std::env::set_var("RSRS_DATA_DIR", dir);
    }
}

fn publish_identity() {
    let _ = rpc_serve::set_runtime_identity(RuntimeIdentity {
        runtime_version: VERSION.to_owned(),
        runtime_compat: RuntimeCompat {
            min_cli: MIN_CLI.to_owned(),
            max_cli: MAX_CLI.to_owned(),
        },
    });
}

fn serve_command(flags: &Flags, boot_token: Option<&str>) -> Result<i32> {
    respire_commands::model_install::enable_backend_probe_host();
    startup_identity::authorize(
        flags.supervised,
        boot_token,
        flags.port.unwrap_or_else(net_rpc::rpc_port),
    )?;
    let installed = host_hooks::install(HostHooks {
        capture_run: Some(respire_commands::runtime_executor::capture_run),
        mcp_http_response: Some(respire_commands::runtime_mcp::http_response),
        managed_id: Some(startup_identity::managed_id),
        verify_managed_boot: Some(startup_identity::verify_managed_boot),
        ..HostHooks::default()
    });
    anyhow::ensure!(installed, "Runtime executor hooks were installed twice");
    anyhow::ensure!(
        respire_commands::rpc_worker::install_recall_stats_enqueue(
            rpc_serve::enqueue_recall_stats_local,
        ),
        "Runtime recall statistics hook was installed twice"
    );
    publish_identity();
    if !flags.json {
        println!(
            "runtime=starting host={host} port={port}",
            host = flags.host,
            port = flags
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "default".to_owned())
        );
    }
    rpc_serve::serve(RuntimeFlags {
        port: flags.port,
        host: flags.host.clone(),
        status: false,
        stop: false,
    })
    .map_err(|error| {
        if flags.json {
            print_envelope("start", false, 1, Some(&format!("{error:#}")), None);
        }
        error
    })?;
    Ok(0)
}

fn status_command(json: bool) -> Result<i32> {
    match net_rpc::health() {
        Ok(health) => {
            if json {
                let body = serde_json::json!({
                    "v": respire_commands::rpc_worker::PROTOCOL_V,
                    "id": "status",
                    "ok": true,
                    "exit": 0,
                    "bin": VERSION,
                    "pid": health.pid,
                    "url": health.url,
                    "data_dir": health.data_dir,
                    "runtime_version": health.runtime_version,
                });
                println!("{body}");
            } else {
                println!(
                    "runtime=up pid={} url={} data_dir={}",
                    health.pid, health.url, health.data_dir,
                );
            }
            Ok(0)
        }
        Err(error) => {
            if json {
                print_envelope("status", false, 2, Some(&format!("{error:#}")), None);
            } else {
                eprintln!("runtime=down: {error:#}");
            }
            Ok(2)
        }
    }
}

fn stop_command(json: bool) -> Result<i32> {
    let runtime = match net_rpc::health() {
        Ok(runtime) => runtime,
        Err(error)
            if matches!(
                error.downcast_ref::<respire_commands::runtime_error::RuntimeError>(),
                Some(respire_commands::runtime_error::RuntimeError::Unavailable)
            ) =>
        {
            if json {
                print_envelope("stop", true, 0, None, Some("not_running"));
            } else {
                println!("runtime=not_running");
            }
            return Ok(0);
        }
        Err(error) => return Err(error).context("cannot establish runtime stop identity"),
    };
    let root = respire_app::service::main_data_dir().canonicalize()?;
    let library = respire_app::service::data_dir().canonicalize()?;
    anyhow::ensure!(
        !runtime.installation_root.is_empty()
            && std::fs::canonicalize(&runtime.installation_root)? == root
            && !runtime.data_dir.is_empty()
            && std::fs::canonicalize(&runtime.data_dir)? == library,
        "runtime stop target differs from the selected installation or library"
    );
    anyhow::ensure!(
        net_rpc::instance_is_running(&runtime)?,
        "runtime instance changed before the stop request"
    );
    let accepted = net_rpc::request_stop_for(&runtime, std::time::Duration::from_secs(10))
        .context("runtime stop request failed")?;
    net_rpc::wait_for_instance_exit(&runtime, std::time::Duration::from_secs(120))
        .context("runtime instance exit is not proven; no drained result is available")?;
    net_rpc::final_stop_receipt(&runtime, Some(&accepted.operation_id))
        .context("runtime normal drain is not proven")?;
    // The receipt proves shutdown intent; taking the existing guard proves release.
    let released = respire_app::lock::LibraryLock::acquire(&library, std::time::Duration::ZERO)
        .context("runtime library lock was not released after its final drain receipt")?;
    drop(released);
    if json {
        print_envelope("stop", true, 0, None, Some("drained"));
    } else {
        println!("runtime=stopped result=drained");
    }
    Ok(0)
}

/// One-line envelope aligned with the CLI `rpc::` reply shape
/// (`{"v":1,"id":"start","ok":true,"exit":0,...}`).
fn print_envelope(id: &str, ok: bool, exit: i32, error: Option<&str>, result: Option<&str>) {
    let mut body = serde_json::json!({
        "v": respire_commands::rpc_worker::PROTOCOL_V,
        "id": id,
        "ok": ok,
        "exit": exit,
        "bin": VERSION,
    });
    if let Some(error) = error {
        body["error"] = serde_json::json!(error);
    }
    if let Some(result) = result {
        body["result"] = serde_json::json!(result);
    }
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{body}");
    let _ = handle.flush();
}

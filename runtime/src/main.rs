//! Standalone `rsrs-runtime` binary: the loopback RPC host split out of the
//! CLI binary (runtime split WP-3, milestone M1 "two runnable binaries").
//!
//! Argv contract (HANDOFF 2026-11-03 item 9; client2's `stopManaged`/
//! `startManaged` depends on these exact shapes):
//!
//! | argv                                   | behaviour                                  |
//! |----------------------------------------|--------------------------------------------|
//! | `serve [--host H] [--port P] [--data-dir D] [--supervised]` | serve until stopped |
//! | `--json runtime start` / `runtime start` | detached same-image startup with checked readiness |
//! | `--json runtime stop` / `runtime stop` / `--stop` | ask the resident runtime to stop |
//! | `--status`                              | probe the resident runtime health          |
//! | `--version`                             | print the binary version                   |
//!
//! Unknown arguments print an error and exit with code 2. The boot token is
//! consumed with `respire_spawn` semantics: `RSRS_RUNTIME_BOOT_TOKEN` is read
//! and then removed from this process's environment.

mod background_start;
mod startup_identity;
mod host_control;
mod maintenance_control;
mod snapshot_authority;
mod secret_control;
mod identity_control;
mod identity_write_control;
mod space_control;
mod profile_maintenance;
mod config_control;
mod key_control;
mod migration_control;
mod metadata_control;
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
const MIN_CLI: &str = "2.0.0-dev.11";
const MAX_CLI: &str = "*";

fn main() -> ExitCode {
    for name in ["RSRS_SUPER", "RSRS_PASS", "RESPIRE_SUPER", "RESPIRE_PASS", "ONEMEMORY_SUPER", "ONEMEMORY_PASS"] {
        std::env::remove_var(name);
    }
    // Remove the inherited secret before any worker or business code can spawn.
    match consume_boot_token().and_then(run) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            respire_logging::error(format_args!("rsrs-runtime failed"));
            eprintln!("rsrs-runtime: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|location| location.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        respire_logging::log_panic(info.payload(), &location);
        previous(info);
    }));
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
    start: bool,
    background_child: bool,
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
            start: false,
            background_child: false,
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
    #[cfg(target_os = "macos")]
    if std::env::args_os().nth(1).is_some_and(|arg| arg == "--runtime-exit-observer-internal") {
        anyhow::ensure!(boot_token.is_none(), "exit observer cannot consume boot authorization");
        return background_start::observe_exit();
    }
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
        respire_commands::model_assets::run_backend_probe_helper()?;
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
    let flags = match parse_flags(std::env::args().skip(1)) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("{error:#}\n{}", usage());
            return Ok(2);
        }
    };

    anyhow::ensure!(
        !(flags.status || flags.stop || flags.version || flags.start || flags.background_child)
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
    anyhow::ensure!(!flags.background_child || flags.serve,
        "background readiness is only valid for a serving process");
    apply_data_dir(&flags);
    if let Some(port) = flags.port {
        std::env::set_var("RSRS_RPC_PORT", port.to_string());
    }
    if let Err(error) = respire_app::service::validate_client_config() {
        if flags.json {
            print_envelope("configuration", false, 2, Some(&format!("{error:#}")), None);
            return Ok(2);
        }
        return Err(error).context("Runtime client configuration is invalid");
    }
    if flags.start {
        require_explicit_start_endpoint(&flags)?;
        return background_start::start(&flags);
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

fn require_explicit_start_endpoint(flags: &Flags) -> Result<()> {
    anyhow::ensure!(flags.host == "127.0.0.1",
        "background startup currently requires the existing 127.0.0.1 client endpoint");
    Ok(())
}

fn parse_flags(args: impl Iterator<Item = String>) -> Result<Flags> {
    let mut flags = Flags::default();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => flags.json = true,
            "serve" | "--runtime-internal" => flags.serve = true,
            "--runtime-background-internal" => {
                flags.serve = true;
                flags.background_child = true;
                flags.json = true;
            }
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
                let port: u16 = value.parse().context("--port requires a numeric port between 1 and 65535")?;
                anyhow::ensure!(port > 0, "--port requires a numeric port between 1 and 65535");
                flags.port = Some(port);
            }
            "--data-dir" => {
                flags.data_dir = Some(args.next().context("--data-dir requires a value")?.into());
            }
            "runtime" => {
                match args.next().as_deref() {
                    Some("start") => flags.start = true,
                    Some("stop") => flags.stop = true,
                    Some("status") => flags.status = true,
                    Some("version") => flags.version = true,
                    _ => anyhow::bail!("only runtime start, stop, status and version are supported; use the CLI or Client2 for host operations"),
                }
            }
            other => anyhow::bail!("unsupported Runtime argument: {other}; use the CLI or Client2 for host operations"),
        }
    }
    let requested = [flags.serve, flags.start, flags.stop, flags.status, flags.version]
        .into_iter().filter(|requested| *requested).count();
    anyhow::ensure!(requested <= 1, "combine at most one of start/serve, stop, status, version");
    Ok(flags)
}

#[cfg(test)]
mod frontend_route_tests {
    use super::parse_flags;
    fn parse(args: &[&str]) -> anyhow::Result<super::Flags> {
        parse_flags(args.iter().map(|arg| (*arg).to_owned()))
    }
    #[test]
    fn pending_start_preserves_parsed_endpoint_and_root_parameters() -> anyhow::Result<()> {
        let flags = parse(&["runtime", "start", "--port", "15321", "--data-dir", "synthetic-root"])?;
        super::require_explicit_start_endpoint(&flags)?;
        assert_eq!(flags.port, Some(15321));
        assert_eq!(flags.data_dir, Some(std::path::PathBuf::from("synthetic-root")));
        let flags = parse(&["runtime", "start", "--host", "0.0.0.0"])?;
        assert!(super::require_explicit_start_endpoint(&flags).is_err());
        Ok(())
    }

    #[test]
    fn original_client2_host_commands_require_an_external_host() {
        for command in ["config", "logout", "grant", "account", "space", "migrate", "login",
            "keygen", "keys-export", "inject", "inject-status", "inject-remove", "classify-config", "model"] {
            assert!(parse(&["--json", command]).is_err(), "{command}");
        }
        for args in [vec!["--host-rpc-stdio"], vec!["runtime", "install"],
            vec!["runtime", "enable"], vec!["runtime", "account-result", "original-operation"],
            vec!["model", "install-engines"]] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
    #[test]
    fn runtime_lifecycle_and_private_modes_keep_their_dispatcher() -> anyhow::Result<()> {
        assert!(!parse(&[])?.start);
        assert!(parse(&["--json", "runtime", "start"])?.start);
        assert!(parse(&["--runtime-internal"])?.serve);
        assert_eq!(parse(&["serve", "--port", "15169"])?.port, Some(15169));
        assert!(parse(&["--status"])?.status);
        assert!(parse(&["--version"])?.version);
        assert!(parse(&["--runtime-internal", "--runtime-background-internal", "--port", "15169"])?.background_child);
        assert!(parse(&["serve", "--port", "0"]).is_err());
        assert!(parse(&["runtime", "start", "--status"]).is_err());
        Ok(())
    }
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
    // Serving errors must survive detached stderr without persisting request data.
    let log_path = respire_app::service::main_data_dir()
        .join("logs")
        .join("runtime.log");
    let _ = respire_logging::init(respire_logging::LoggingConfig::new(log_path));
    install_panic_hook();
    if flags.background_child {
        anyhow::ensure!(flags.host == "127.0.0.1",
            "legacy host mode only accepts the existing loopback endpoint");
        startup_identity::enable_background_readiness()?;
    }
    respire_commands::model_assets::enable_backend_probe_host(
        respire_commands::model_assets::BackendProbeHost::Serving);
    startup_identity::authorize(
        flags.supervised,
        boot_token,
        flags.port.unwrap_or_else(net_rpc::rpc_port),
    )?;
    startup_identity::install_legacy_host()?;
    let installed = host_hooks::install(HostHooks {
        capture_run: Some(respire_commands::runtime_executor::capture_run),
        mcp_http_response: Some(respire_commands::runtime_mcp::http_response),
        managed_id: Some(startup_identity::managed_id),
        verify_managed_boot: Some(startup_identity::verify_managed_boot),
        runtime_listener_ready: Some(startup_identity::publish_legacy_ready),
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
                    "status": "ok",
                    "summary": { "running": true },
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
        Err(error) if background_start::is_unavailable(&error) => {
            if json {
                print_envelope("status", true, 0, None, Some("not_running"));
            } else {
                println!("runtime=not_running");
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
        "status": if ok { "ok" } else { "fail" },
        "ok": ok,
        "exit": exit,
        "bin": VERSION,
    });
    if let Some(error) = error {
        body["error"] = serde_json::json!(error);
        body["errors"] = serde_json::json!([error]);
    }
    if let Some(result) = result {
        body["result"] = serde_json::json!(result);
        body["summary"] = serde_json::json!({"result": result, "running": result == "started" || result == "already_running"});
    }
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{body}");
    let _ = handle.flush();
}

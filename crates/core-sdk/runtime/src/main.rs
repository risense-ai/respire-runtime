//! Standalone `rsrs-runtime` binary: the loopback RPC host split out of the
//! CLI binary (runtime split WP-3, milestone M1 "two runnable binaries").
//!
//! Argv contract (HANDOFF 2026-11-03 item 9; client2's `stopManaged`/
//! `startManaged` depends on these exact shapes):
//!
//! | argv                                   | behaviour                                  |
//! |----------------------------------------|--------------------------------------------|
//! | `serve [--host H] [--port P] [--data-dir D] [--supervised]` | serve until stopped |
//! | `--json runtime start` / `runtime start` | same as `serve`, plus a start envelope on stdout |
//! | `--json runtime stop` / `runtime stop` / `--stop` | ask the resident runtime to stop |
//! | `--status`                              | probe the resident runtime health          |
//! | `--version`                             | print the binary version                   |
//!
//! Unknown arguments print an error and exit with code 2. The boot token is
//! consumed with `respire_spawn` semantics: `RSRS_RUNTIME_BOOT_TOKEN` is read
//! and then removed from this process's environment.

use std::io::Write;
use std::process::ExitCode;

use anyhow::{Context, Result};

use respire_commands::net_rpc;
use respire_commands::rpc_serve::{self, RuntimeFlags};
use respire_protocol::{RuntimeCompat, RuntimeIdentity};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// CLI compatibility window for this runtime train (runtime-pin.json aligns).
const MIN_CLI: &str = "1.0.20";
const MAX_CLI: &str = "*";

fn main() -> ExitCode {
    // Consume the spawn-time boot token first: exactly one process may read it
    // and it must never leak into child processes.
    let boot_token = consume_boot_token();
    let _ = boot_token;
    match run() {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("rsrs-runtime: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn consume_boot_token() -> Option<String> {
    match std::env::var("RSRS_RUNTIME_BOOT_TOKEN") {
        Ok(token) => {
            std::env::remove_var("RSRS_RUNTIME_BOOT_TOKEN");
            Some(token)
        }
        Err(_) => None,
    }
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

fn run() -> Result<i32> {
    let mut flags = Flags::default();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => flags.json = true,
            "serve" => flags.serve = true,
            "--stop" => flags.stop = true,
            "--status" => flags.status = true,
            "--version" => flags.version = true,
            "--supervised" => {
                // Accepted for the P2 supervisor handshake; serving behaviour
                // is unchanged until lifecycle registration moves here.
                flags.supervised = true;
            }
            "--host" => {
                let value = args.next().context("--host requires a value")?;
                anyhow::ensure!(!value.is_empty(), "--host requires a loopback address");
                flags.host = value;
            }
            "--port" => {
                let value = args.next().context("--port requires a value")?;
                let port: u16 = value.parse().map_err(|_| anyhow::anyhow!("--port requires a numeric port between 1 and 65535"))?;
                anyhow::ensure!(port > 0, "--port requires a numeric port between 1 and 65535");
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
    anyhow::ensure!(requested <= 1, "combine at most one of start/serve, stop, status, version\n{}", usage());

    if flags.version {
        if flags.json {
            print_envelope("version", true, 0, None);
        } else {
            println!("rsrs-runtime {VERSION}");
        }
        return Ok(0);
    }
    if flags.status {
        return status_command(flags.json);
    }
    if flags.stop {
        return stop_command(flags.json);
    }
    // Bare invocation defaults to serving, mirroring `--runtime-internal`.
    serve_command(&flags)
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

fn serve_command(flags: &Flags) -> Result<i32> {
    publish_identity();
    apply_data_dir(flags);
    if flags.json {
        // client2 fires this argv shape and then polls /api/health; stdout is
        // detached from the supervisor, so the envelope is best-effort.
        print_envelope("start", true, 0, None);
    } else {
        println!("runtime=starting host={host} port={port}",
            host = flags.host,
            port = flags.port.map(|port| port.to_string()).unwrap_or_else(|| "default".to_owned()));
    }
    let _ = flags.supervised;
    rpc_serve::serve(RuntimeFlags {
        port: flags.port,
        host: flags.host.clone(),
        status: false,
        stop: false,
    })
    .map_err(|error| {
        if flags.json {
            print_envelope("start", false, 1, Some(&format!("{error:#}")));
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
                    health.pid,
                    health.url,
                    health.data_dir,
                );
            }
            Ok(0)
        }
        Err(error) => {
            if json {
                print_envelope("status", false, 2, Some(&format!("{error:#}")));
            } else {
                eprintln!("runtime=down: {error:#}");
            }
            Ok(2)
        }
    }
}

fn stop_command(json: bool) -> Result<i32> {
    let up = net_rpc::health().is_ok();
    if up {
        net_rpc::request_stop().context("runtime stop request failed")?;
        // A following start must not race the draining owner.
        net_rpc::wait_until_down().context("runtime did not release its endpoint")?;
    }
    if json {
        print_envelope("stop", true, 0, None);
    } else if up {
        println!("runtime=stopped");
    } else {
        println!("runtime=stopped (not running)");
    }
    Ok(0)
}

/// One-line envelope aligned with the CLI `rpc::` reply shape
/// (`{"v":1,"id":"start","ok":true,"exit":0,...}`).
fn print_envelope(id: &str, ok: bool, exit: i32, error: Option<&str>) {
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
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{body}");
    let _ = handle.flush();
}

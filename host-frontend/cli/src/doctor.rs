use anyhow::{ensure, Context, Result};

use crate::output::{self, Item, ResultEnvelope, Status};
use crate::{progress, rpc, runtime_policy};

pub(crate) fn run(remote: bool, check_update: bool, fix: bool) -> Result<()> {
    let client_only = runtime_policy::client_only();
    if check_update || fix {
        runtime_policy::require_host("doctor repair and CLI update checks")?;
    }
    if client_only {
        return crate::emit_result(runtime_doctor(remote)?);
    }

    crate::prepare_command_runtime()?;
    crate::autostart::check_managed_request()?;
    let mut host = host_rows(check_update);
    let mut result = runtime_doctor(remote)?;
    if fix {
        let repair = repair(&result)?;
        if !matches!(repair.status, Status::Skip) {
            result = runtime_doctor(remote)?;
        }
        host.push(repair);
    }
    if diagnostics_paused(&result) {
        result.command = "doctor".to_owned();
        result.items.push(Item::new(
            "Runtime diagnostics",
            Status::Warn,
            "Memory is off; Runtime diagnostics were not executed",
        ));
    }

    let runtime_status = result.status;
    result.items.extend(host);
    result.status = output::status_from_items(&result.items);
    if matches!(runtime_status, Status::Fail) || !result.errors.is_empty() {
        result.status = Status::Fail;
    } else if matches!(runtime_status, Status::Warn | Status::Pending)
        && matches!(result.status, Status::Ok)
    {
        result.status = Status::Warn;
    }
    let summary = result
        .summary
        .as_object_mut()
        .context("doctor summary missing")?;
    summary.insert("version".into(), serde_json::json!(respire::VERSION));
    summary.insert("scope".into(), serde_json::json!("host+runtime"));
    summary.insert("host_checks".into(), serde_json::json!("completed"));
    for (name, status) in [
        ("pass", Status::Ok),
        ("warn", Status::Warn),
        ("fail", Status::Fail),
        ("skip", Status::Skip),
    ] {
        let count = result
            .items
            .iter()
            .filter(|row| row.status.as_str() == status.as_str())
            .count();
        summary.insert(name.into(), serde_json::json!(count));
    }
    summary.insert("total".into(), serde_json::json!(result.items.len()));
    crate::emit_result(result)
}

fn runtime_doctor(remote: bool) -> Result<ResultEnvelope> {
    let mut args = vec!["doctor".to_owned()];
    if remote {
        args.push("--remote".to_owned());
    }
    if let Some(id) = progress::remote_id() {
        args.extend(["--progress-id".to_owned(), id]);
    }
    let result: ResultEnvelope = serde_json::from_value(rpc::query_json(args)?)?;
    // The off-mode gate returns before doctor dispatch and never opens the store.
    if result.command == "memory" && diagnostics_paused(&result) {
        return Ok(result);
    }
    ensure!(
        result.command == "doctor" && result.summary["scope"] == "runtime",
        "doctor requires an independent Runtime with scope=runtime diagnostics; upgrade the Runtime"
    );
    Ok(result)
}

fn diagnostics_paused(result: &ResultEnvelope) -> bool {
    result.summary["mode"] == "off" && result.summary["skipped"] == true
}

fn host_rows(check_update: bool) -> Vec<Item> {
    let mut rows = Vec::new();
    progress::phase("Checking host configuration", "Checking host configuration");
    match crate::profile_discovery::pending_legacy_profiles() {
        Ok(profiles) if !profiles.is_empty() => rows.push(Item::new(
            "migration",
            Status::Warn,
            format!(
                "{} legacy account(s) need explicit migration; use rsrs migrate",
                profiles.len()
            ),
        )),
        Ok(_) => {}
        Err(error) => rows.push(Item::new("migration", Status::Fail, format!("{error:#}"))),
    }
    rows.push(match respire::inject::targets() {
        Ok(targets) => {
            let detected = targets
                .iter()
                .filter(|target| target.likely_installed)
                .count();
            let fresh = targets
                .iter()
                .filter(|target| target.likely_installed && target.state == "fresh")
                .count();
            let status = if detected == 0 {
                Status::Skip
            } else if fresh == detected {
                Status::Ok
            } else if fresh == 0 {
                Status::Fail
            } else {
                Status::Warn
            };
            Item::new(
                "inject",
                status,
                format!("{fresh}/{detected} injected and fresh ({detected} detected)"),
            )
        }
        Err(error) => Item::new("inject", Status::Fail, format!("{error:#}")),
    });
    let binary = crate::mcp::stable_bin_path();
    rows.push(match std::fs::metadata(&binary) {
        Ok(metadata) if metadata.is_file() => {
            Item::new("mcp bin", Status::Ok, binary.display().to_string())
        }
        Ok(_) => Item::new(
            "mcp bin",
            Status::Fail,
            format!("{} is not a file", binary.display()),
        ),
        Err(error) => Item::new(
            "mcp bin",
            Status::Fail,
            format!("{}: {error}", binary.display()),
        ),
    });
    rows.push(if !respire::update_check::enabled() {
        Item::new("CLI version", Status::Skip, "Update check disabled")
    } else if !check_update {
        Item::new(
            "CLI version",
            Status::Skip,
            "Version check not requested; use doctor --check-update to refresh",
        )
    } else {
        progress::phase(
            "Checking CLI version; waiting for version registry",
            "Checking CLI version; waiting for version registry",
        );
        match respire::update_check::check(true) {
            Some(status) => Item::new(
                "CLI version",
                if status.outdated {
                    Status::Warn
                } else {
                    Status::Ok
                },
                format!(
                    "{} ({})",
                    status.comparison(),
                    if status.cached {
                        "cached"
                    } else {
                        "just checked"
                    }
                ),
            ),
            None => Item::new(
                "CLI version",
                Status::Skip,
                "Version check unavailable; no update result verified",
            ),
        }
    });
    rows
}

fn repair(diagnostic: &ResultEnvelope) -> Result<Item> {
    if diagnostics_paused(diagnostic) || respire_client_host::settings::off_mode()? {
        return Ok(Item::new(
            "host repair",
            Status::Skip,
            "Memory is off; repair skipped without reading selection or preparing models/indexes",
        ));
    }
    if diagnostic.details["model_operation"]["active"] == true {
        return Ok(Item::new(
            "host repair",
            Status::Warn,
            "Model operation in progress; repair deferred without changing assets",
        ));
    }
    let needs_assets = diagnostic
        .items
        .iter()
        .any(|row| row.name == "embedder" && !matches!(row.status, Status::Ok));
    let needs_index = diagnostic
        .items
        .iter()
        .any(|row| row.name == "model index" && !matches!(row.status, Status::Ok));
    if !needs_assets && !needs_index {
        return Ok(Item::new(
            "host repair",
            Status::Ok,
            "No asset or index repair requested by Runtime diagnostics",
        ));
    }
    respire_client_host::settings::ensure_writable()?;
    if needs_assets {
        crate::autostart::control_prepare_model(&respire_protocol::ModelInstallIntent::default())?;
        ensure!(
            !respire_client_host::settings::off_mode()?,
            "memory was paused after asset maintenance; Runtime preparation was not requested"
        );
    }
    ensure!(
        !respire_client_host::settings::off_mode()?,
        "memory is paused; Runtime index preparation was not requested"
    );
    let response = rpc::call_method("index.prepare", Vec::new(), false)?;
    ensure!(
        response.ok,
        "{}",
        response
            .error
            .as_deref()
            .unwrap_or("Runtime index preparation failed")
    );
    Ok(Item::new("host repair", Status::Ok, "Host assets prepared if needed; Runtime preparation/indexing requested; diagnostic results follow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use respire_commands::output_state;
    use serde_json::{json, Value};
    use std::{ffi::OsString, path::Path, time::Duration};

    fn isolated(test: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        struct Restore {
            env: Vec<(&'static str, Option<OsString>)>,
            captured: Option<ResultEnvelope>,
            host_output: bool,
            emitted: bool,
            exit: u8,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.env {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
                output_state::CAPTURED.with(|slot| *slot.borrow_mut() = self.captured.take());
                output_state::HOST_RPC_OUTPUT.set(self.host_output);
                output_state::OUTPUT_EMITTED.set(self.emitted);
                output_state::OUTPUT_EXIT_CODE.set(self.exit);
            }
        }
        let keys = [
            "RSRS_DATA_DIR",
            "RSRS_BIN_DIR",
            "RSRS_M3_DIR",
            "RSRS_NO_AUTOSYNC",
            "RSRS_SUPER",
            "HOME",
            "USERPROFILE",
            "RSRS_CLIENT_ONLY",
            "RSRS_NO_AUTOSTART",
            "RSRS_UPDATE_CHECK",
            "RSRS_REGISTRY",
            "RSRS_RUNTIME_BIN",
            "RSRS_CORE_TEST_MODE",
            "RSRS_RPC_TOKEN",
            "RSRS_RPC_PORT",
        ];
        let _restore = Restore {
            env: keys
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
            captured: output_state::CAPTURED.with(|slot| slot.borrow_mut().take()),
            host_output: output_state::HOST_RPC_OUTPUT.get(),
            emitted: output_state::OUTPUT_EMITTED.get(),
            exit: output_state::OUTPUT_EXIT_CODE.get(),
        };
        std::env::set_var("RSRS_DATA_DIR", root);
        std::env::set_var("RSRS_BIN_DIR", root.join("bin"));
        std::env::set_var("RSRS_M3_DIR", root.join("absent-model"));
        std::env::set_var("RSRS_NO_AUTOSYNC", "1");
        std::env::set_var("RSRS_CORE_TEST_MODE", "1");
        std::env::remove_var("RSRS_SUPER");
        std::env::remove_var("RSRS_RPC_PORT");
        let home = root.join("home");
        std::fs::create_dir(&home)?;
        std::env::set_var("HOME", &home);
        std::env::set_var("USERPROFILE", &home);
        std::env::set_var("RSRS_CLIENT_ONLY", "0");
        std::env::set_var("RSRS_NO_AUTOSTART", "0");
        std::env::set_var("RSRS_UPDATE_CHECK", "0");
        std::env::remove_var("RSRS_RPC_TOKEN");
        // This file supplies an identity to the HTTP fixture; it is never executed.
        let image = root.join("doctor-runtime-fixture");
        std::fs::write(&image, b"doctor HTTP fixture identity")?;
        std::env::set_var("RSRS_RUNTIME_BIN", image);
        output_state::HOST_RPC_OUTPUT.set(true);
        test(root)
    }

    fn diagnostic(status: Status) -> ResultEnvelope {
        ResultEnvelope::new("doctor", status, json!({"scope":"runtime"}), Vec::new())
    }

    fn with_runtime(
        replies: Vec<(&'static str, Value)>,
        test: impl FnOnce() -> Result<()>,
    ) -> Result<Vec<Value>> {
        let server =
            tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow::anyhow!("{error}"))?;
        let port = server
            .server_addr()
            .to_ip()
            .context("fixture IP address")?
            .port();
        std::env::set_var("RSRS_RPC_PORT", port.to_string());
        let health = json!({
            "server":"respire", "bin":"doctor-fixture", "v":1, "pid":std::process::id(),
            "runtime_version":crate::runtime_fetch::pinned()?.required,
            "installation_root":respire_client_host::paths::main_data_dir().canonicalize()?,
            "data_dir":respire_client_host::config::control_roots()?.1.canonicalize()?,
            "exe":std::path::PathBuf::from(std::env::var_os("RSRS_RUNTIME_BIN").context("fixture image")?),
            "account_id":"doctor-account", "instance_id":"doctor-instance", "generation":1,
            "store_ready":true,
        });
        let actor = std::thread::spawn(move || -> Result<Vec<Value>> {
            let mut requests = Vec::new();
            for (method, mut reply) in replies {
                loop {
                    let mut request = server
                        .recv_timeout(Duration::from_secs(3))?
                        .context("doctor fixture request did not arrive")?;
                    if request.url() == "/api/health" {
                        request.respond(tiny_http::Response::from_string(health.to_string()))?;
                        continue;
                    }
                    ensure!(
                        request.url() == "/api/rpc",
                        "unexpected doctor fixture route"
                    );
                    let mut body = String::new();
                    request.as_reader().read_to_string(&mut body)?;
                    let body: Value = serde_json::from_str(&body)?;
                    ensure!(
                        body["method"] == method,
                        "unexpected doctor RPC method: {body}"
                    );
                    for key in ["id", "operation_id", "idempotency_key", "scope"] {
                        reply[key] = body[key].clone();
                    }
                    reply["v"] = json!(1);
                    reply["bin"] = json!("doctor-fixture");
                    request.respond(tiny_http::Response::from_string(reply.to_string()))?;
                    requests.push(body);
                    break;
                }
            }
            Ok(requests)
        });
        let result = test();
        let requests = actor
            .join()
            .map_err(|_| anyhow::anyhow!("doctor fixture panicked"))?;
        result?;
        requests
    }

    fn reply(result: ResultEnvelope) -> Value {
        json!({"ok":true,"exit":0,"envelope":result})
    }

    #[test]
    fn host_rows_keep_configuration_failures_and_local_update_results() -> Result<()> {
        isolated(|root| {
            let row = |rows: Vec<Item>, name: &str| -> Result<Item> {
                rows.into_iter()
                    .find(|item| item.name == name)
                    .context("missing host row")
            };
            assert!(!host_rows(false).iter().any(|item| item.name == "session"));
            assert!(matches!(
                row(host_rows(false), "inject")?.status,
                Status::Fail
            ));
            assert!(row(host_rows(false), "CLI version")?
                .value
                .contains("disabled"));
            let home = root.join("home");
            respire::inject::inject_one("generic")?;
            assert!(matches!(
                row(host_rows(false), "inject")?.status,
                Status::Ok
            ));
            std::fs::create_dir(home.join(".codex"))?;
            assert!(matches!(
                row(host_rows(false), "inject")?.status,
                Status::Warn
            ));
            let binary = crate::mcp::stable_bin_path();
            std::fs::create_dir_all(&binary)?;
            assert!(row(host_rows(false), "mcp bin")?
                .value
                .contains("not a file"));
            std::fs::remove_dir(&binary)?;
            std::fs::write(&binary, b"not executed")?;
            assert!(matches!(
                row(host_rows(false), "mcp bin")?.status,
                Status::Ok
            ));
            let legacy = home.join(".respire");
            std::fs::create_dir(&legacy)?;
            std::fs::write(legacy.join("session.json"), b"{}")?;
            assert!(matches!(
                row(host_rows(false), "migration")?.status,
                Status::Warn
            ));
            std::fs::write(legacy.join("session.json"), b"{")?;
            assert!(matches!(
                row(host_rows(false), "migration")?.status,
                Status::Fail
            ));
            std::env::set_var("RSRS_UPDATE_CHECK", "1");
            assert!(row(host_rows(false), "CLI version")?
                .value
                .contains("not requested"));
            for (body, expected) in [
                (json!({"version":"999.0.0"}), Status::Warn),
                (json!({"version":respire::VERSION}), Status::Ok),
                (json!({}), Status::Skip),
            ] {
                let server = tiny_http::Server::http("127.0.0.1:0")
                    .map_err(|error| anyhow::anyhow!("{error}"))?;
                std::env::set_var("RSRS_REGISTRY", format!("http://{}", server.server_addr()));
                let actor = std::thread::spawn(move || -> Result<()> {
                    let request = server
                        .recv_timeout(Duration::from_secs(3))?
                        .context("local version request missing")?;
                    ensure!(
                        request.url() == "/rsrs-cli/latest",
                        "unexpected registry route"
                    );
                    request.respond(tiny_http::Response::from_string(body.to_string()))?;
                    Ok(())
                });
                let version = row(host_rows(true), "CLI version")?;
                actor
                    .join()
                    .map_err(|_| anyhow::anyhow!("registry fixture panicked"))??;
                assert_eq!(version.status.as_str(), expected.as_str());
                assert!(
                    version.value.contains("just checked") || version.value.contains("unavailable")
                );
            }
            Ok(())
        })
    }

    #[test]
    fn runtime_scope_and_paused_contracts_are_not_inferred_from_success() -> Result<()> {
        isolated(|_| {
            std::env::set_var("RSRS_CLIENT_ONLY", "1");
            for (command, summary, accepted) in [
                ("doctor", json!({"scope":"runtime"}), true),
                ("doctor", json!({"scope":"host"}), false),
                ("model", json!({"scope":"runtime"}), false),
                ("memory", json!({"mode":"off","skipped":true}), true),
                ("memory", json!({"mode":"off","skipped":false}), false),
            ] {
                let result = ResultEnvelope::new(command, Status::Ok, summary, Vec::new());
                let requests = with_runtime(vec![("cli.exec", reply(result))], || {
                    let actual = runtime_doctor(true);
                    assert_eq!(actual.is_ok(), accepted);
                    if !accepted {
                        assert!(actual
                            .err()
                            .context("expected scope error")?
                            .to_string()
                            .contains("scope=runtime"));
                    }
                    Ok(())
                })?;
                assert_eq!(requests[0]["args"], json!(["--json", "doctor", "--remote"]));
            }
            with_runtime(
                vec![(
                    "cli.exec",
                    json!({"ok":false,"exit":1,"error":"fixture diagnostic unavailable"}),
                )],
                || {
                    let error = runtime_doctor(false).err().context("missing RPC error")?;
                    assert!(format!("{error:#}").contains("fixture diagnostic unavailable"));
                    Ok(())
                },
            )?;
            for (update, fix) in [(true, false), (false, true)] {
                assert!(run(false, update, fix)
                    .err()
                    .context("sandbox accepted host action")?
                    .to_string()
                    .contains("client_only"));
            }
            with_runtime(vec![("cli.exec", reply(diagnostic(Status::Warn)))], || {
                run(false, false, false)?;
                let result = output_state::CAPTURED
                    .with(|slot| slot.borrow_mut().take())
                    .context("client result missing")?;
                assert_eq!(result.summary["scope"], "runtime");
                assert!(result.summary.get("host_checks").is_none());
                Ok(())
            })?;
            Ok(())
        })
    }

    #[test]
    fn repair_defers_or_preserves_the_actual_runtime_failure() -> Result<()> {
        isolated(|root| {
            let mut result = diagnostic(Status::Fail);
            result
                .items
                .push(Item::new("embedder", Status::Fail, "missing"));
            let database = root.join("rsrs.db");
            std::fs::write(
                &database,
                b"invalid database must not be opened by deferred repair",
            )?;
            let before = std::fs::read(&database)?;
            result.summary = json!({"mode":"off","skipped":true});
            assert!(matches!(repair(&result)?.status, Status::Skip));
            result.summary = json!({"scope":"runtime"});
            let config = respire_client_host::paths::client_config_path();
            std::fs::write(&config, br#"{"service_mode":"off"}"#)?;
            assert!(matches!(repair(&result)?.status, Status::Skip));
            std::fs::write(&config, b"{}")?;
            let operation = respire::model_progress::Operation::begin("download")?;
            result.details = json!({"model_operation":{"active":true}});
            assert!(matches!(repair(&result)?.status, Status::Warn));
            assert_eq!(respire::model_progress::status()?["phase"], "download");
            drop(operation);
            assert_eq!(std::fs::read(&database)?, before);
            assert!(!root.join("models").exists());
            result.details = Value::Null;
            result.items.clear();
            assert!(repair(&result)?.value.contains("No asset or index repair"));
            result
                .items
                .push(Item::new("model index", Status::Fail, "pending"));
            std::fs::write(&config, br#"{"service_mode":"readonly"}"#)?;
            assert!(repair(&result)
                .err()
                .context("readonly repair accepted")?
                .to_string()
                .contains("read-only"));
            std::fs::write(&config, b"{")?;
            assert!(respire_client_host::settings::ensure_writable().is_err());
            assert_eq!(std::fs::read(&database)?, before);
            std::fs::write(&config, b"{}")?;
            for error in [Some("fixture index refused"), None] {
                with_runtime(
                    vec![("index.prepare", json!({"ok":false,"exit":1,"error":error}))],
                    || {
                        let failure = repair(&result).err().context("index error swallowed")?;
                        assert!(failure
                            .to_string()
                            .contains(error.unwrap_or("Runtime index preparation failed")));
                        Ok(())
                    },
                )?;
            }
            with_runtime(vec![("index.prepare", json!({"ok":true,"exit":0}))], || {
                assert!(matches!(repair(&result)?.status, Status::Ok));
                Ok(())
            })?;
            // A client never opens the local store to inspect selection; missing Runtime fails closed.
            let unused = std::net::TcpListener::bind("127.0.0.1:0")?;
            std::env::set_var("RSRS_RPC_PORT", unused.local_addr()?.port().to_string());
            drop(unused);
            std::env::set_var("RSRS_CORE_TEST_MODE", "1");
            result.items = vec![Item::new("embedder", Status::Fail, "invalid selection")];
            let failure = repair(&result)
                .err()
                .context("invalid selection was accepted")?;
            assert!(failure.is::<crate::runtime_fetch::LegacyRuntimeMigrationRequired>());
            assert_eq!(std::fs::read(&database)?, before);
            assert!(!root.join("models").exists());
            Ok(())
        })
    }

    #[test]
    fn host_output_retains_runtime_severity_counts_and_repair_results() -> Result<()> {
        isolated(|_| {
            respire::inject::inject_one("generic")?;
            let binary = crate::mcp::stable_bin_path();
            std::fs::create_dir_all(binary.parent().context("fixture binary parent")?)?;
            std::fs::write(binary, b"not executed")?;
            for (status, errors, expected) in [
                (Status::Warn, Vec::new(), Status::Warn),
                (Status::Pending, Vec::new(), Status::Warn),
                (Status::Fail, Vec::new(), Status::Fail),
                (
                    Status::Ok,
                    vec!["runtime diagnostic failure".to_owned()],
                    Status::Fail,
                ),
            ] {
                let mut result = diagnostic(status);
                // Session diagnostics moved from the host to the Runtime response.
                result.items.push(Item::new(
                    "session",
                    Status::Ok,
                    "five-keys complete, can unlock",
                ));
                result.errors = errors;
                with_runtime(vec![("cli.exec", reply(result))], || {
                    run(false, false, false)?;
                    let result = output_state::CAPTURED
                        .with(|slot| slot.borrow_mut().take())
                        .context("host result missing")?;
                    assert_eq!(result.status.as_str(), expected.as_str());
                    assert_eq!(result.summary["scope"], "host+runtime");
                    assert_eq!(result.summary["version"], respire::VERSION);
                    assert_eq!(result.summary["host_checks"], "completed");
                    assert_eq!(result.summary["pass"], 3);
                    assert_eq!(result.summary["skip"], 1);
                    assert_eq!(result.summary["total"], result.items.len());
                    Ok(())
                })?;
            }
            let mut paused = diagnostic(Status::Skip);
            paused.command = "memory".into();
            paused.summary = json!({"mode":"off","skipped":true});
            with_runtime(vec![("cli.exec", reply(paused))], || {
                run(false, false, true)?;
                let result = output_state::CAPTURED
                    .with(|slot| slot.borrow_mut().take())
                    .context("paused result missing")?;
                assert_eq!(result.command, "doctor");
                assert!(matches!(result.status, Status::Warn));
                assert_eq!(result.summary["warn"], 1);
                assert_eq!(result.summary["skip"], 2);
                assert!(result
                    .items
                    .iter()
                    .any(|row| row.name == "host repair" && matches!(row.status, Status::Skip)));
                Ok(())
            })?;
            let mut refreshed = diagnostic(Status::Ok);
            refreshed.summary["refreshed"] = json!(true);
            with_runtime(
                vec![
                    ("cli.exec", reply(diagnostic(Status::Ok))),
                    ("cli.exec", reply(refreshed)),
                ],
                || {
                    run(false, false, true)?;
                    let result = output_state::CAPTURED
                        .with(|slot| slot.borrow_mut().take())
                        .context("repaired result missing")?;
                    assert_eq!(result.summary["refreshed"], true);
                    assert!(result
                        .items
                        .iter()
                        .any(|row| row.name == "host repair" && matches!(row.status, Status::Ok)));
                    Ok(())
                },
            )?;
            Ok(())
        })
    }
}

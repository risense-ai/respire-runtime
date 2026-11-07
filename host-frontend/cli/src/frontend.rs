// rsrs CLI: parse commands, manage components, and render Runtime replies.
// Business, database, credential and inference work stays in the independent
// Runtime. Host code prepares its assets, configuration and private controls.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use clap::Parser;

pub mod autostart;
mod classify_config;
mod client_config;
mod doctor;
mod host_rpc;
mod login;
mod mcp;
mod profile_control;
mod profile_discovery;
mod rpc;
mod runtime_fetch;
mod shell;
mod web;

// Shared command surface extracted into the respire_commands crate; the bin
// re-binds the module names so existing `crate::` paths keep resolving.
pub use respire_commands::app_version;
use respire_commands::capabilities::run_capabilities;
pub use respire_commands::classify;
use respire_commands::cli_def::{
    Cli, Command, ModelAction, PluginCommand, SessionCommand, SnapshotCmd,
};
use respire_commands::gates::{
    is_off_allowed, is_readonly_switch_off, is_write_command, is_write_command_fine,
};
pub use respire_commands::i18n;
pub use respire_commands::metadata;
pub use respire_commands::model_progress;
pub use respire_commands::net_rpc;
pub use respire_commands::output::{
    self, Item as OutputItem, ResultEnvelope, Status as OutputStatus,
};
use respire_commands::output_emit::{emit_details, emit_result};
use respire_commands::output_state::DIRECT_MODE;
use respire_commands::output_state::{
    exit_code, json_mode, mark_emitted, output_emitted, parse_failure, progress_enabled,
    set_exit_code, set_json_mode, status_exit_code, Captured,
};
use respire_commands::progress;
pub use respire_commands::runtime_error;
pub use respire_commands::runtime_policy;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn host_command(args: &Cli) -> Option<Result<()>> {
    match args.command.as_ref() {
        Some(command @ Command::Extract { .. }) => {
            match respire_commands::cli_def::extract_uses_tui(command) {
                Ok(true) => Some(run_extract_tui()),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            }
        }
        Some(Command::AgentConfig { set: None }) => Some(
            runtime_policy::require_host("agent configuration read")
                .and_then(|()| {
                    autostart::control_offline_read(
                        respire_protocol::metadata_control::HostOfflineRead::AgentConfigRead,
                    )
                })
                .and_then(emit_result),
        ),
        Some(Command::AgentConfig { set: Some(kv) }) => {
            Some(autostart::control_agent_config(kv).and_then(emit_result))
        }
        Some(Command::Session { command }) => Some(run_session(command)),
        Some(Command::SuperReset { super_pass }) => Some(run_super_reset(super_pass.as_deref())),
        Some(Command::Plugin { command }) => Some(run_plugin(command)),
        Some(Command::Passport) if !runtime_policy::client_only() => Some(run_passport()),
        Some(Command::Prompt) => {
            let text = respire::inject::INSTRUCTIONS_MD;
            Some(emit_result(ResultEnvelope::new(
                "prompt",
                OutputStatus::Ok,
                serde_json::json!({"instructions":text}),
                vec![OutputItem::new("instructions", OutputStatus::Ok, text)],
            )))
        }
        Some(Command::Keygen { pass, force }) => Some(run_keygen(pass.as_deref(), *force)),

        Some(Command::Inject {
            targets,
            id,
            remove,
            all,
            preview,
            expected,
            tui,
        }) => {
            // Default interactive: no args + real TTY -> TUI; client child/script (no tty) -> original full inject, same behavior
            let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout());
            let bare = !*targets && id.is_none() && !*remove && !*preview && expected.is_none();
            if *tui || (bare && !*all && interactive) {
                return Some(respire::inject_tui::run());
            }
            return Some(run_inject(
                *targets,
                id.as_deref(),
                *remove,
                *all,
                *preview,
                expected.as_deref(),
            ));
        }

        Some(Command::Logout { full }) => {
            Some(autostart::control_logout(*full).and_then(emit_result))
        }

        Some(Command::Account { action, name, yes }) => {
            Some(run_account(action, name.as_deref(), *yes))
        }

        Some(Command::Space {
            action,
            name,
            note,
            readonly,
            code,
            session,
            all,
            yes,
        }) => Some(run_space(
            action,
            name.as_deref(),
            note.as_deref(),
            *readonly,
            code.as_deref(),
            session.as_deref(),
            *all,
            *yes,
        )),

        Some(Command::UpdateCheck { force, clear }) => Some(run_update_check(*force, *clear)),

        Some(Command::KeysExport { out }) => Some(run_keys_export(out.as_deref())),

        Some(Command::Config {
            data_dir,
            addr,
            autosync,
            cure_auto,
            rpc_parallelism,
        }) => Some(run_config(
            data_dir.as_deref(),
            addr.as_deref(),
            *autosync,
            *cure_auto,
            *rpc_parallelism,
        )),

        Some(Command::Secret { reveal }) => Some(run_secret(*reveal)),

        Some(Command::Fivekeys {
            addr,
            user,
            pass,
            secret,
            kdf_salt,
            wrapped_urk,
            urk_nonce,
            super_pass,
        }) => Some(run_fivekeys(
            addr,
            user,
            pass,
            secret,
            kdf_salt,
            wrapped_urk,
            urk_nonce,
            super_pass,
        )),

        Some(Command::Register {
            addr,
            user,
            pass,
            super_pass,
        }) => Some(run_register(
            addr.as_deref(),
            user.as_deref(),
            pass.as_deref(),
            super_pass.as_deref(),
        )),
        _ => None,
    }
}

fn run_extract_tui() -> Result<()> {
    runtime_policy::require_host("extract source picker")?;
    anyhow::ensure!(
        std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout()),
        "extract --tui needs a real terminal (stdin/stdout must both be tty)"
    );
    // Finish host lifecycle work before the UI enters raw terminal mode.
    rpc::ensure_daemon()?;
    respire::extract_tui::run(|full| {
        let response = rpc::call_method("cli.exec", full, false)?;
        anyhow::ensure!(
            response.ok && response.exit == 0,
            "extract sources failed: {}",
            response
                .error
                .as_deref()
                .unwrap_or("Runtime source query failed")
        );
        response
            .envelope
            .context("extract sources: Runtime response missing envelope")
    })
}

fn run_passport() -> Result<()> {
    runtime_policy::require_host("passport agent inventory")?;
    let mut args = vec!["passport".to_owned()];
    if let Some(id) = progress::remote_id() {
        args.extend(["--progress-id".to_owned(), id]);
    }
    let mut result: ResultEnvelope = serde_json::from_value(rpc::query_json(args)?)?;
    if result.command == "memory"
        && result.summary["mode"] == "off"
        && result.summary["skipped"] == true
    {
        return emit_result(result);
    }
    anyhow::ensure!(
        result.command == "passport",
        "Runtime did not return a passport result"
    );
    let summary = result
        .summary
        .as_object_mut()
        .ok_or_else(|| anyhow!("Runtime passport summary missing"))?;
    let agents = match respire::inject::targets() {
        Ok(targets) => {
            let count = targets
                .iter()
                .filter(|target| matches!(target.state, "fresh" | "stale"))
                .count();
            summary.insert("agents".into(), serde_json::json!(count));
            OutputItem::new("agents", OutputStatus::Ok, count.to_string())
        }
        Err(error) => {
            summary.insert("agents".into(), serde_json::Value::Null);
            let message = format!("host agent inventory: {error:#}");
            result.errors.push(message.clone());
            result.status = OutputStatus::Fail;
            OutputItem::new("agents", OutputStatus::Fail, message)
        }
    };
    if let Some(row) = result.items.iter_mut().find(|row| row.name == "agents") {
        *row = agents;
    } else {
        result.items.push(agents);
    }
    emit_result(result)
}

fn run_super_reset(super_pass: Option<&str>) -> Result<()> {
    use respire_protocol::key_control::{HostKeyInput, HostKeyOutcome, HostKeyResult};
    runtime_policy::require_host("super password rotation")?;
    let mut input = HostKeyInput {
        password: None,
        super_password: super_pass.map(str::to_owned),
        ..HostKeyInput::default()
    };
    let mut supplied = std::collections::BTreeSet::new();
    if super_pass.is_some() {
        supplied.insert("super_password".to_owned());
    }
    let mut envelope = autostart::control_super_reset(super_pass)?;
    loop {
        if !matches!(envelope.status, OutputStatus::Pending) {
            return emit_result(envelope);
        }
        let receipt: HostKeyResult = serde_json::from_value(envelope.summary.clone())
            .map_err(|_| anyhow!("invalid key continuation receipt"))?;
        envelope.actions.push(format!(
            "runtime key-result --operation-id {} (use the original selected profile)",
            receipt.operation_id,
        ));
        // Scripts receive the original O without reading stdin or admitting another reset.
        if receipt.outcome != HostKeyOutcome::AwaitingInput
            || json_mode()
            || !std::io::IsTerminal::is_terminal(&std::io::stdin())
            || !std::io::IsTerminal::is_terminal(&std::io::stdout())
        {
            return emit_result(envelope);
        }
        let requested: std::collections::BTreeSet<_> = receipt.required_inputs.iter().collect();
        anyhow::ensure!(
            !requested.is_empty()
                && requested.len() == receipt.required_inputs.len()
                && requested
                    .iter()
                    .all(|field| matches!(field.as_str(), "password" | "super_password")),
            "Runtime requested invalid key continuation inputs"
        );
        if requested
            .iter()
            .any(|field| supplied.contains(field.as_str()))
        {
            return emit_result(envelope);
        }
        let continuation = (|| -> Result<ResultEnvelope> {
            for field in &receipt.required_inputs {
                let prompt = match field.as_str() {
                    "password" => "original v1 login password: ",
                    "super_password" => "super password (A3-...): ",
                    _ => anyhow::bail!("unsupported key continuation input"),
                };
                let value = respire::prompt::ask_secret(prompt)?;
                anyhow::ensure!(
                    !value.is_empty(),
                    "key input is empty; original operation retained"
                );
                match field.as_str() {
                    "password" => input.password = Some(value),
                    "super_password" => input.super_password = Some(value),
                    _ => anyhow::bail!("unsupported key continuation input"),
                }
                supplied.insert(field.clone());
            }
            autostart::control_super_reset_step(
                None,
                HostKeyInput {
                    password: input.password.clone(),
                    super_password: input.super_password.clone(),
                    ..HostKeyInput::default()
                },
                Some(&receipt),
            )
        })();
        envelope = continuation.map_err(|error| {
            error.context(autostart::KeyRecoveryRequired {
                operation_id: receipt.operation_id,
                source_profile: receipt.source_profile,
            })
        })?;
    }
}

fn run_session(command: &SessionCommand) -> Result<()> {
    runtime_policy::require_host("session identity management")?;
    let revoke = match command {
        SessionCommand::List => None,
        SessionCommand::Revoke { id } => Some(id.as_str()),
    };
    let action = if revoke.is_some() { "revoke" } else { "list" };
    let details = match revoke {
        Some(id) => autostart::control_session_revoke(id)?,
        None => autostart::control_session_list()?,
    };
    let rows = details.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let items = rows
        .iter()
        .map(|row| {
            OutputItem::new(
                row["id"]
                    .as_str()
                    .or_else(|| row["session_id"].as_str())
                    .unwrap_or("session"),
                OutputStatus::Ok,
                row.to_string(),
            )
        })
        .collect();
    let mut result = ResultEnvelope::new(
        "session",
        OutputStatus::Ok,
        serde_json::json!({"action":action,"count":rows.len()}),
        items,
    );
    result.details = details;
    emit_result(result)
}

fn run_plugin(command: &PluginCommand) -> Result<()> {
    runtime_policy::require_host("plugin management")?;
    use respire_commands::hooks;
    let (_, profile) = respire_client_host::config::control_roots()?;
    let path = profile.join("plugins.json");
    match command {
        PluginCommand::List => {
            let cfg = hooks::read_config_at(&path);
            let mut items = Vec::new();
            for (event, hooks) in &cfg.hooks {
                for hook in hooks {
                    let policy = if hook.on_error.is_empty() {
                        "default"
                    } else {
                        &hook.on_error
                    };
                    items.push(OutputItem::new(
                        event,
                        OutputStatus::Ok,
                        format!(
                            "{} timeout={}ms on_error={policy}",
                            hook.cmd, hook.timeout_ms
                        ),
                    ));
                }
            }
            if items.is_empty() {
                items.push(OutputItem::new(
                    "hooks",
                    OutputStatus::Skip,
                    format!("none configured; file={}", path.display()),
                ));
            }
            let mut result = ResultEnvelope::new(
                "plugin-list",
                if cfg.hooks.is_empty() {
                    OutputStatus::Skip
                } else {
                    OutputStatus::Ok
                },
                serde_json::json!({
                    "config_path": path.to_string_lossy(),
                    "events": hooks::EVENT_NAMES,
                    "count": cfg.hooks.values().map(Vec::len).sum::<usize>(),
                }),
                items,
            );
            result.details = serde_json::to_value(&cfg.hooks)?;
            result
                .actions
                .push("plugin test <EVENT> --payload <JSON>".into());
            emit_result(result)
        }
        PluginCommand::Test { event, payload } => {
            let event = hooks::HookEvent::parse(event).ok_or_else(|| {
                anyhow!(
                    "unknown event \"{event}\"; available: {}",
                    hooks::EVENT_NAMES.join(" / ")
                )
            })?;
            let data = serde_json::from_str(payload)
                .map_err(|error| anyhow!("--payload is not JSON: {error}"))?;
            let verdict = hooks::fire_at(&path, event, data);
            let status = if verdict.blocked {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            };
            let mut result = ResultEnvelope::new(
                "plugin-test",
                status,
                serde_json::json!({"event":event.as_str(),"blocked":verdict.blocked,"warning_count":verdict.warnings.len()}),
                vec![OutputItem::new(
                    "event",
                    status,
                    if verdict.blocked {
                        format!("{} blocked: {}", event.as_str(), verdict.reason)
                    } else {
                        format!("{} allowed", event.as_str())
                    },
                )],
            );
            result.details = serde_json::json!({"event":event.as_str(),"blocked":verdict.blocked,"reason":verdict.reason,"warnings":verdict.warnings});
            if verdict.blocked {
                result.actions.push("review plugin policy".into());
            }
            emit_result(result)
        }
    }
}

pub(crate) fn capture_run(args: Vec<String>) -> Captured {
    // Host capture parses and collects output once; Runtime owns business retries.
    respire_commands::capture::capture_exec(args, run)
}

fn run_inject(
    targets_only: bool,
    id: Option<&str>,
    remove: bool,
    all: bool,
    preview: bool,
    expected: Option<&str>,
) -> Result<()> {
    let _ = all; // --all: explicit full inject (skip TUI; no-args in a real TTY opens TUI, otherwise same)
    if preview || expected.is_some() {
        if id != Some("codex") {
            anyhow::bail!("preview and revision check currently support --id codex only");
        }
        if preview {
            emit_details(
                "inject",
                OutputStatus::Ok,
                serde_json::json!({"preview":true,"target":"codex"}),
                serde_json::to_value(respire::inject::preview_codex(remove)?)?,
            )?;
        } else if let Some(revision) = expected {
            let changed = respire::inject::apply_codex(remove, revision)?;
            emit_result(ResultEnvelope::new(
                "inject",
                OutputStatus::Ok,
                serde_json::json!({"changed":changed,"target":"codex"}),
                vec![OutputItem::new(
                    "codex",
                    OutputStatus::Ok,
                    if changed { "updated" } else { "unchanged" },
                )],
            ))?;
        }
        return Ok(());
    }
    if targets_only {
        let ts = respire::inject::targets()?;
        let items = ts
            .iter()
            .map(|t| {
                OutputItem::new(
                    t.id,
                    match t.state {
                        "fresh" => OutputStatus::Ok,
                        "stale" => OutputStatus::Warn,
                        _ => OutputStatus::Skip,
                    },
                    format!("{} {}", t.state, t.path),
                )
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "inject",
            OutputStatus::Ok,
            serde_json::json!({"count":ts.len()}),
            items,
        );
        result.details = serde_json::to_value(&ts)?;
        result.actions.push("inject --all".into());
        emit_result(result)?;
        return Ok(());
    }
    match id {
        Some(id) => {
            let changed = if remove {
                respire::inject::remove_one(id)?
            } else {
                respire::inject::inject_one(id)?
            };
            emit_result(ResultEnvelope::new(
                "inject",
                OutputStatus::Ok,
                serde_json::json!({"changed":changed,"id":id}),
                vec![OutputItem::new(
                    id,
                    OutputStatus::Ok,
                    if changed { "updated" } else { "unchanged" },
                )],
            ))?;
            Ok(())
        }
        None => {
            let mut any = false;
            let mut failures = Vec::new();
            let mut rows: Vec<serde_json::Value> = Vec::new();
            let mut items: Vec<OutputItem> = Vec::new();
            for t in respire::inject::targets()? {
                if !t.likely_installed && t.id != "generic" {
                    continue;
                }
                let changed = match respire::inject::inject_one(t.id) {
                    Ok(changed) => changed,
                    Err(error) => {
                        let message = format!("{}: {error:#}", t.id);
                        rows.push(
                            serde_json::json!({ "id": t.id, "error": message, "path": t.path }),
                        );
                        items.push(OutputItem::new(t.id, OutputStatus::Fail, "failed"));
                        failures.push(message);
                        continue;
                    }
                };
                any |= changed;
                rows.push(serde_json::json!({ "id": t.id, "changed": changed, "path": t.path }));
                items.push(OutputItem::new(
                    t.id,
                    OutputStatus::Ok,
                    if changed { "updated" } else { "unchanged" },
                ));
            }
            let status = if failures.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            let mut result = ResultEnvelope::new(
                "inject",
                status,
                serde_json::json!({"any":any,"count":rows.len()}),
                items,
            );
            result.details = serde_json::Value::Array(rows);
            if any {
                result
                    .actions
                    .push("restart the matching AI app or open a new session".into());
                result.actions.push("inject --targets".into());
            }
            result.errors.extend(failures);
            emit_result(result)?;
            Ok(())
        }
    }
}

fn run_keygen(pass: Option<&str>, force: bool) -> Result<()> {
    emit_result(autostart::control_keygen(pass, force)?)
}

/// Version check (`update-check`): query the npm registry for a newer CLI.
/// 24h throttle (`--force` skips it); `--clear` drops the cache. Any network failure reports "not found", not an error.
fn run_update_check(force: bool, clear: bool) -> Result<()> {
    use respire::update_check as uc;
    if clear {
        uc::clear_cache()?;
        if !force {
            return emit_result(ResultEnvelope::new(
                "update-check",
                OutputStatus::Ok,
                serde_json::json!({"cache":"cleared","checked":false}),
                vec![OutputItem::new("cache", OutputStatus::Ok, "cleared")]
                    .into_iter()
                    .map(|item| item.action("run update-check --force"))
                    .collect(),
            ));
        }
    }
    if !uc::enabled() {
        return emit_result(ResultEnvelope::new(
            "update-check",
            OutputStatus::Skip,
            serde_json::json!({"enabled":false}),
            vec![
                OutputItem::new("version check", OutputStatus::Skip, "disabled")
                    .action("unset RSRS_UPDATE_CHECK"),
            ],
        ));
    }
    let current = respire::VERSION;
    match uc::check(force) {
        Some(s) => {
            let status = if s.outdated {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            };
            let mut result = ResultEnvelope::new(
                "update-check",
                status,
                serde_json::json!({"current":s.current.clone(),"latest":s.latest.clone(),"outdated":s.outdated,"ahead":uc::is_newer(&s.current,&s.latest),"cached":s.cached}),
                vec![OutputItem::new("version", status, s.comparison())],
            );
            if s.outdated {
                result.actions.push("npm i -g rsrs-cli@latest".into());
            }
            emit_result(result)
        }
        None => {
            let mut result = ResultEnvelope::new(
                "update-check",
                OutputStatus::Warn,
                serde_json::json!({"current":current,"latest":null,"outdated":null,"cached":false}),
                vec![OutputItem::new("version", OutputStatus::Warn, current)],
            );
            result
                .errors
                .push("registry unavailable or request timed out".into());
            emit_result(result)
        }
    }
}

/// Self-check (OpenViking doctor absorbed): model/store/lock/remote/inject/scope in one pass.
/// --remote also probes server /health. Per-item ok/fail; exit code stays 0 (diagnosis is not failure).
/// Multiple accounts on one machine: list profiles / use switches / remove deletes.
fn run_account(action: &str, name: Option<&str>, yes: bool) -> Result<()> {
    match action {
        "list" => {
            let v = profile_discovery::account_list()?;
            let accounts = v["accounts"].as_array().cloned().unwrap_or_default();
            let items = accounts
                .iter()
                .map(|a| {
                    OutputItem::new(
                        a["name"].as_str().unwrap_or(""),
                        OutputStatus::Ok,
                        format!(
                            "{} {}",
                            a["dir"].as_str().unwrap_or(""),
                            a["user"].as_str().unwrap_or("")
                        ),
                    )
                })
                .collect();
            let mut result = ResultEnvelope::new(
                "account",
                OutputStatus::Ok,
                serde_json::json!({"count":accounts.len()}),
                items,
            );
            result.details = v;
            emit_result(result)
        }
        "use" => {
            let name = name.filter(|n| !n.trim().is_empty()).ok_or_else(|| {
                anyhow::anyhow!(
                    "use needs a profile name: rsrs account use <name> (main = primary)"
                )
            })?;
            emit_result(profile_control::account_use(name.trim())?)
        }
        "remove" => {
            let name = name.filter(|n| !n.trim().is_empty()).ok_or_else(|| {
                anyhow::anyhow!("remove needs a profile name: rsrs account remove <name> --yes")
            })?;
            if !yes {
                anyhow::bail!("deleting a profile wipes the local store and keys and is unrecoverable - add --yes to confirm");
            }
            emit_result(autostart::control_account_remove(name.trim())?)
        }
        // A profile name as the action = switch: rsrs account fslong ≡ account use fslong
        other => emit_result(profile_control::account_use(other)?),
    }
}

/// Space (virtual-account) command: an owner creates several virtual accounts, each a space; invite codes join people; kick drops membership.
fn run_space(
    action: &str,
    name: Option<&str>,
    note: Option<&str>,
    readonly: bool,
    code: Option<&str>,
    session: Option<&str>,
    all: bool,
    yes: bool,
) -> Result<()> {
    use respire::space;
    match action {
        "list" => {
            let v = profile_discovery::space_list()?;
            let spaces = v["spaces"].as_array().cloned().unwrap_or_default();
            let items = spaces.iter().map(|s| {
                let name = s["name"].as_str().unwrap_or("");
                let dir = s["dir"].as_str().unwrap_or("");
                let user = s["user"].as_str().unwrap_or("");
                let members = s["members"].as_u64().unwrap_or(0);
                let current = if s["current"].as_bool() == Some(true) { " current" } else { "" };
                OutputItem::new(name, OutputStatus::Ok, format!("dir={dir} user={user} members={members}{current}"))
            }).collect();
            let mut result = ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"list","count":spaces.len()}), items);
            result.details = v;
            emit_result(result)
        }
        "create" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| respire_client_host::input_error::InputError("create needs a space name: rsrs space create <name>".into()))?;
            emit_result(profile_control::space_create(n)?)
        }
        "use" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| respire_client_host::input_error::InputError("use needs a space name: rsrs space use <name>".into()))?;
            emit_result(profile_control::space_use(n)?)
        }
        "invite" => {
            emit_result(autostart::control_space_invite(note, readonly)?)
        }
        "join" => {
            let c = code.or(name).filter(|c| !c.trim().is_empty())
                .ok_or_else(|| respire_client_host::input_error::InputError("join needs an invite code: rsrs space join <code>".into()))?;
            emit_result(autostart::control_space_join(c)?)
        }
        "members" => {
            let v = space::space_members(name)?;
            let ms = v["members"].as_array().cloned().unwrap_or_default();
            let items = ms.iter().map(|m| OutputItem::new(m["session_id"].as_str().unwrap_or(""), OutputStatus::Ok, format!("device={} issued={}", m["device_name"].as_str().unwrap_or(""), m["issued_at"].as_str().unwrap_or("")))).collect();
            let status = if ms.is_empty() { OutputStatus::Skip } else { OutputStatus::Ok };
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"members","space":v["space"],"count":ms.len()}), items);
            if ms.is_empty() { result.actions.push("space invite".into()); }
            result.details = v;
            emit_result(result)
        }
        "kick" => {
            if !session.map(|s| !s.trim().is_empty()).unwrap_or(false) && !all {
                return Err(respire_client_host::input_error::InputError("kick needs --session <id> or --all".into()).into());
            }
            emit_result(autostart::control_space_kick(session, all)?)
        }
        "remove" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| respire_client_host::input_error::InputError("remove needs a space name: rsrs space remove <name> --yes".into()))?;
            if !yes {
                return Err(respire_client_host::input_error::InputError("deleting a space profile wipes the local store and keys and is unrecoverable - add --yes to confirm".into()).into());
            }
            emit_result(autostart::control_space_remove(n)?)
        }
        other => anyhow::bail!(
            "unknown space action \"{other}\" - use: list | create <name> | use <name> | invite | join <code> | members | kick | remove"
        ),
    }
}

/// Local config: --data-dir/--addr/--autosync/--cure-auto set (all empty = read only).
fn run_config(
    data_dir: Option<&str>,
    addr: Option<&str>,
    autosync: Option<bool>,
    cure_auto: Option<bool>,
    rpc_parallelism: Option<u32>,
) -> Result<()> {
    emit_result(autostart::run_config_control(
        data_dir,
        addr,
        autosync,
        cure_auto,
        rpc_parallelism,
    )?)
}

/// Under v3, Account Secret is no longer a decrypt key - export the v3 three-piece; old v1 material is listed as a side note.
fn run_keys_export(out: Option<&str>) -> Result<()> {
    emit_result(autostart::control_keys_export(out)?)
}

/// Secrets are read by the authorized Runtime; rendering remains in the CLI.
fn run_secret(reveal: bool) -> Result<()> {
    emit_result(autostart::control_secret(reveal)?)
}

fn run_fivekeys(
    addr: &str,
    user: &str,
    pass: &str,
    secret: &str,
    kdf_salt: &str,
    wrapped_urk: &str,
    urk_nonce: &str,
    super_pass: &str,
) -> Result<()> {
    use respire_protocol::key_control::{
        HostKeyInput, HostKeyOperation, HostKeyOutcome, HostKeyResult,
    };
    let operation = HostKeyOperation::Fivekeys {
        addr: addr.trim().trim_end_matches('/').to_owned(),
        user: user.to_owned(),
        kdf_salt: kdf_salt.to_owned(),
        wrapped_urk: wrapped_urk.to_owned(),
        urk_nonce: urk_nonce.to_owned(),
        use_super: !super_pass.is_empty(),
    };
    let mut input = HostKeyInput {
        password: Some(pass.to_owned()),
        super_password: if super_pass.is_empty() {
            None
        } else {
            Some(super_pass.to_owned())
        },
        account_secret: Some(secret.to_owned()),
        totp: None,
    };
    let mut envelope = autostart::control_fivekeys(
        operation.clone(),
        HostKeyInput {
            password: input.password.clone(),
            super_password: input.super_password.clone(),
            account_secret: input.account_secret.clone(),
            totp: None,
        },
        None,
    )?;
    loop {
        if !matches!(envelope.status, OutputStatus::Pending) {
            return emit_result(envelope);
        }
        let receipt: HostKeyResult = serde_json::from_value(envelope.summary.clone())
            .map_err(|_| anyhow!("invalid fivekeys continuation receipt"))?;
        envelope.actions.push(format!(
            "runtime key-result --operation-id {}",
            receipt.operation_id
        ));
        if json_mode()
            || !std::io::IsTerminal::is_terminal(&std::io::stdin())
            || !std::io::IsTerminal::is_terminal(&std::io::stdout())
            || receipt.outcome != HostKeyOutcome::AwaitingInput
            || receipt.required_inputs.as_slice() != ["totp"]
            || input.totp.is_some()
        {
            return emit_result(envelope);
        }
        input.totp = Some(respire::prompt::ask_secret("TOTP: ").map_err(|error| {
            error.context(autostart::KeyRecoveryRequired {
                operation_id: receipt.operation_id.clone(),
                source_profile: receipt.source_profile.clone(),
            })
        })?);
        envelope = autostart::control_fivekeys(
            operation.clone(),
            HostKeyInput {
                password: input.password.clone(),
                super_password: input.super_password.clone(),
                account_secret: input.account_secret.clone(),
                totp: input.totp.clone(),
            },
            Some(&receipt),
        )?;
    }
}

fn run_register(
    addr: Option<&str>,
    user: Option<&str>,
    pass: Option<&str>,
    super_pass: Option<&str>,
) -> Result<()> {
    let addr: &str = addr
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(crate::client_config::DEFAULT_SERVER_ADDR);
    // Missing args: interactive prompt (TTY and not --json); args the prompt cannot fill still error.
    let interactive = respire::prompt::interactive();
    let user: String = match user.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_owned(),
        None if interactive => {
            eprintln!("register server={addr}");
            respire::prompt::ask("username: ")?
        }
        None => {
            return Err(anyhow::anyhow!(
            "missing --user <username> (bare `rsrs register` in a TTY opens an interactive prompt)"
        ))
        }
    };
    let pass: String = match pass.filter(|s| !s.is_empty()) {
        Some(p) => p.to_owned(),
        None if interactive => {
            let p = respire::prompt::ask_secret("login password (for the server; can be reset): ")?;
            if p.len() < 8 {
                return Err(anyhow::anyhow!(
                    "login password must be at least 8 characters"
                ));
            }
            p
        }
        None => return Err(anyhow::anyhow!("missing --pass <login-password>")),
    };
    let super_pass: String = match super_pass.filter(|s| !s.is_empty()) {
        Some(s) => s.to_owned(),
        None => String::new(),
    };
    let response = autostart::control_register(
        addr,
        &user,
        &pass,
        (!super_pass.is_empty()).then_some(super_pass.as_str()),
    )?;
    let receipt: respire_protocol::host_control::HostAuthAccountResult =
        serde_json::from_value(response.summary.clone())?;
    anyhow::ensure!(
        receipt.outcome == respire_protocol::host_control::HostAuthAccountOutcome::Committed,
        "registration was not committed; retain and query the original account operation"
    );
    let super_key = receipt
        .super_password
        .filter(|value| !value.is_empty())
        .context("committed registration is missing the recovery code")?;
    let mut result = ResultEnvelope::new(
        "register",
        OutputStatus::Ok,
        serde_json::json!({"ok":true,"user":user,"addr":addr,"super":super_key}),
        vec![OutputItem::new("account", OutputStatus::Ok, user.clone())],
    );
    result.actions.push("secret --reveal".into());
    emit_result(result)
}

/// Whether this command writes the store (must refuse in read-only mode).
///
/// Wire the host services consumed by the shared worker/engine modules; the
/// shared code calls them through `respire_commands::host_hooks`. Installation
/// is idempotent (first wiring wins).
fn install_cli_host_hooks() -> bool {
    let installed =
        respire_commands::host_hooks::install(respire_commands::host_hooks::HostHooks {
            background_paused: Some(|| autostart::background_paused()),
            check_direct_access: Some(|| autostart::check_direct_access()),
            note_credential_access: Some(|available| autostart::note_credential_access(available)),
            context_changed: None,
            call_runtime_method: Some(rpc::call_method_outcome),
            update_hint: Some(respire::update_check::hint),
            update_enabled: Some(respire::update_check::enabled),
            update_check_run: Some(|force| {
                respire::update_check::check(force).map(|status| {
                    respire_commands::host_hooks::UpdateStatus {
                        current: status.current,
                        latest: status.latest,
                        outdated: status.outdated,
                        cached: status.cached,
                    }
                })
            }),
            materialize_bin: Some(mcp::materialize_bin),
            foreground_progress: Some(rpc::foreground_progress),
            runtime_brief: Some(rpc::runtime_brief),
            host_command: Some(host_command),
            extract_tui_run: Some(run_extract_tui),
            runtime_is_up: Some(rpc::runtime_is_up),
            change_profile: Some(|change| rpc::change_profile(|| change())),
            managed_id: Some(|| autostart::managed_id()),
            verify_managed_boot: Some(|| autostart::verify_managed_boot()),
            record_exit: Some(|success| autostart::record_exit(success)),
            credential_state: Some(|| autostart::credential_state()),
            capture_run: Some(capture_run),
            mcp_http_response: None,
        });
    installed
}

fn command_failure(error: &anyhow::Error) -> (ResultEnvelope, i32) {
    let (mut envelope, code) = respire_commands::output_emit::command_failure(error);
    if let Some(original) = error.downcast_ref::<autostart::AuthOutcomeUnknown>() {
        envelope.summary = serde_json::json!({"reason":"auth_outcome_unknown"});
        envelope.details = serde_json::json!({
            "error_type":"outcome_unknown", "operation_id":original.operation_id,
            "force":original.force, "result_command":"runtime auth-result", "replayed":false,
        });
    } else if let Some(original) = error.downcast_ref::<autostart::IdentityWriteRecoveryRequired>()
    {
        envelope.summary = serde_json::json!({"reason":"identity_write_recovery_required"});
        envelope.details = serde_json::json!({
            "error_type":"identity_write_recovery_required", "operation_id":original.operation_id,
            "idempotency_key":original.key, "source_profile":original.profile,
            "operation":original.operation, "query_only":original.query_only, "replayed":false,
            "result_command":"repeat the same logout/session revoke command",
        });
    } else if let Some(original) = error.downcast_ref::<autostart::KeyRecoveryRequired>() {
        envelope.summary = serde_json::json!({"reason":"key_outcome_unknown"});
        envelope.details = serde_json::json!({
            "error_type":"outcome_unknown", "operation_id":original.operation_id,
            "source_profile":original.source_profile, "result_command":"runtime key-result",
            "query_only":true, "replayed":false,
        });
    } else if let Some(original) =
        error.downcast_ref::<respire_host_control::AccountHandoffPending>()
    {
        let mut result_args = vec![
            "--operation-id".to_owned(),
            original.operation_id.clone(),
            "--source-profile".to_owned(),
            original.source_profile.to_string_lossy().into_owned(),
        ];
        if original.register {
            result_args.push("--register".to_owned());
        }
        envelope.summary = serde_json::json!({"reason":"account_handoff_pending"});
        envelope.details = serde_json::json!({
            "error_type":"handoff_pending", "operation_id":original.operation_id,
            "source_profile":original.source_profile, "register":original.register,
            "committed":true, "result_command":"runtime account-result", "result_args":result_args,
            "query_only":true, "replayed":false,
        });
    } else if let Some(original) = error.downcast_ref::<autostart::AccountOutcomeUnknown>() {
        envelope.summary = serde_json::json!({"reason":"account_outcome_unknown"});
        envelope.details = serde_json::json!({
            "error_type":"outcome_unknown", "operation_id":original.operation_id,
            "source_profile":original.source_profile, "register":original.register,
            "result_command":"runtime account-result", "replayed":false,
        });
    }
    (envelope, code)
}

/// Execute the process command line through the shared CLI host frontend.
/// The embedding binary must dispatch private Runtime entry points first.
pub fn run_frontend() -> i32 {
    if !install_cli_host_hooks() {
        eprintln!("host hooks were installed twice; keeping the first wiring");
    }
    // The command enum and the ONNX session are large. Debug builds on Windows
    // give the main thread a 1MB stack, which overflows inside clap. Do the work
    // on a thread with room.
    let handle = match std::thread::Builder::new()
        .name("rsrs".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(main_body)
    {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("failed to start the command thread: {error}");
            return 1;
        }
    };
    match handle.join() {
        Ok(exit) => exit,
        Err(payload) => {
            eprintln!("command thread panicked: {}", panic_message(payload));
            1
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "command thread panicked without a string payload".to_owned()
}

fn main_body() -> i32 {
    let roots_requested = std::env::args_os().any(|arg| arg == "--roots");
    if !roots_requested && std::env::args_os().any(|arg| arg == "--host-rpc-stdio") {
        set_json_mode(true);
        if std::env::args_os().any(|arg| arg == "--client-only") {
            std::env::set_var("RSRS_CLIENT_ONLY", "1");
        }
        return match respire_client_host::roots::validate_client_environment()
            .and_then(|()| host_rpc::serve())
        {
            Ok(code) => code,
            Err(error) => {
                let (envelope, code) = command_failure(&error);
                if let Err(output_error) = emit_result(envelope) {
                    eprintln!("host RPC reply failed: {output_error}");
                }
                code
            }
        };
    }
    set_json_mode(
        std::env::args_os().any(|arg| arg == "--json")
            || respire::env::var("RSRS_JSON").is_ok_and(|value| value == "1" || value == "true"),
    );
    if std::env::args_os().any(|arg| arg == "--client-only") {
        std::env::set_var("RSRS_CLIENT_ONLY", "1");
    }
    // Parse args, then run the command, so a Windows debug stack does not hold both at once.
    // The hidden runtime entry and `--direct` are peeled off before clap: the command enum is large enough that
    // extra derived fields overflow the debug main thread.
    let result = match preprocess_args() {
        Preparsed::Roots { data_dir } => {
            if let Some(dir) = data_dir {
                std::env::remove_var("RSRS_DEFAULT_DATA_DIR");
                std::env::set_var("RSRS_DATA_DIR", dir);
            }
            respire_client_host::roots::resolved_roots().and_then(|roots| {
                emit_result(ResultEnvelope::new(
                    "roots",
                    OutputStatus::Ok,
                    serde_json::to_value(roots)?,
                    Vec::new(),
                ))
            })
        }
        Preparsed::Version { json } => {
            set_json_mode(json);
            crate::app_version::emit(json)
        }
        Preparsed::RuntimeHelp { json } => {
            set_json_mode(json);
            emit_runtime_help()
        }
        Preparsed::Runtime { flags, json } => {
            set_json_mode(json);
            prepare_command_runtime().and_then(|()| rpc::runtime_entry(flags))
        }
        Preparsed::Invalid(error) => {
            Err(respire_client_host::input_error::InputError(error).into())
        }
        Preparsed::Cli { direct, args } => {
            DIRECT_MODE.store(direct, Ordering::Relaxed);
            match Cli::try_parse_from(std::iter::once(std::ffi::OsString::from("rsrs")).chain(args))
            {
                Ok(cli)
                    if matches!(
                        cli.command,
                        Some(
                            Command::MemoryRevision
                                | Command::Capabilities
                                | Command::Runtime { .. }
                                | Command::Doctor { .. }
                        )
                    ) =>
                {
                    run(cli)
                }
                Ok(cli) => prepare_command_runtime().and_then(|()| run(cli)),
                Err(error) if error.exit_code() == 0 => error.print().map_err(Into::into),
                Err(error) => {
                    let code = error.exit_code();
                    emit_result(parse_failure(&error)).map(|()| set_exit_code(code))
                }
            }
        }
    };
    if let Err(error) = result {
        let (failure, code) = command_failure(&error);
        if output_emitted() {
            eprintln!("ERROR: {error:#}");
        } else {
            if let Err(render_error) = emit_result(failure) {
                eprintln!("ERROR: {error:#}; output_error: {render_error:#}");
            }
        }
        return code;
    }
    let exit_code = exit_code();
    if exit_code != 0 {
        return exit_code;
    }
    0
}

/// Normal command bootstrap, intentionally omitted by the read-only revision probe.
fn prepare_command_runtime() -> Result<()> {
    respire_client_host::roots::validate_client_environment()?;
    if !runtime_policy::client_only() {
        respire_client_host::paths::ensure_default_home()
            .map_err(|error| anyhow!("default profile migration failed: {error:#}"))?;
    }
    Ok(())
}

enum Preparsed {
    Roots {
        data_dir: Option<String>,
    },
    RuntimeHelp {
        json: bool,
    },
    Version {
        json: bool,
    },
    Runtime {
        flags: rpc::RuntimeFlags,
        json: bool,
    },
    Invalid(String),
    Cli {
        direct: bool,
        args: Vec<std::ffi::OsString>,
    },
}

/// Static lifecycle help is also available to sandbox clients without starting a host.
fn emit_runtime_help() -> Result<()> {
    let usage = "Usage: rsrs --runtime-internal [--no-open] [--host 127.0.0.1] [--port PORT] [--status | --stop]\n\nHost runtime: loopback HTTP only. Without --status/--stop, serve until stopped.\n  --status   Inspect the existing host without starting it\n  --stop     Ask the owned host runtime to stop\n  --no-open  Do not open a browser (accepted for compatibility)\n\nClient-only tools connect to the host; lifecycle changes require the host terminal.\nFor Windows sign-in startup, see docs/runtime.md.\n";
    if json_mode() {
        emit_result(ResultEnvelope::new(
            "runtime-help",
            OutputStatus::Ok,
            serde_json::json!({"usage":usage,"lifecycle":"host-managed","transport":"loopback-http"}),
            Vec::new(),
        ))
    } else {
        print!("{usage}");
        mark_emitted();
        Ok(())
    }
}

fn is_short_v_version(args: &[String]) -> Option<bool> {
    let mut json = false;
    let mut version = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-v" => version = true,
            _ => return None,
        }
    }
    if version {
        Some(json)
    } else {
        None
    }
}

fn preprocess_args() -> Preparsed {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let direct = args.iter().any(|arg| arg == "--direct");
    args.retain(|arg| arg != "--direct" && arg != "--client-only");
    if args.iter().any(|arg| arg == "--roots") {
        let mut data_dir = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--roots" | "--json" => {}
                "--data-dir" if data_dir.is_none() => {
                    index += 1;
                    match args
                        .get(index)
                        .filter(|value| !value.trim().is_empty() && !value.starts_with("--"))
                    {
                        Some(value) => data_dir = Some(value.clone()),
                        None => {
                            return Preparsed::Invalid(
                                "--roots requires a nonempty --data-dir".to_owned(),
                            )
                        }
                    }
                }
                _ => {
                    return Preparsed::Invalid(
                        "use --roots [--data-dir PATH] [--json] without a command".to_owned(),
                    )
                }
            }
            index += 1;
        }
        return Preparsed::Roots { data_dir };
    }
    if let Some(json) = is_short_v_version(&args) {
        return Preparsed::Version { json };
    }
    if args
        .iter()
        .find(|arg| arg.as_str() != "--json")
        .is_some_and(|arg| arg == "--runtime-internal")
    {
        if args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
            && args.iter().all(|arg| {
                matches!(
                    arg.as_str(),
                    "--runtime-internal" | "--help" | "-h" | "--json"
                )
            })
        {
            return Preparsed::RuntimeHelp {
                json: json_mode() || args.iter().any(|arg| arg == "--json"),
            };
        }
        let mut flags = rpc::RuntimeFlags {
            port: None,
            host: "127.0.0.1".to_owned(),
            status: false,
            stop: false,
        };
        let mut json = false;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--runtime-internal" | "--no-open" => {}
                "--json" => json = true,
                "--status" => flags.status = true,
                "--stop" => flags.stop = true,
                "--port" => {
                    index += 1;
                    match args
                        .get(index)
                        .and_then(|value| value.parse::<u16>().ok())
                        .filter(|port| *port > 0)
                    {
                        Some(port) => flags.port = Some(port),
                        None => {
                            return Preparsed::Invalid(
                                "internal runtime requires a valid --port".to_owned(),
                            )
                        }
                    }
                }
                "--host" => {
                    index += 1;
                    match args.get(index).filter(|host| !host.is_empty()) {
                        Some(host) => flags.host = host.clone(),
                        None => {
                            return Preparsed::Invalid(
                                "internal runtime requires --host".to_owned(),
                            )
                        }
                    }
                }
                other => {
                    return Preparsed::Invalid(format!("unknown internal runtime flag: {other}"))
                }
            }
            index += 1;
        }
        if flags.status && flags.stop {
            return Preparsed::Invalid(
                "internal runtime cannot combine --status and --stop".to_owned(),
            );
        }
        return Preparsed::Runtime { flags, json };
    }
    Preparsed::Cli {
        direct,
        args: args.into_iter().map(std::ffi::OsString::from).collect(),
    }
}

fn run_classify_config(
    backend: Option<&str>,
    api_base: Option<&str>,
    model: Option<&str>,
    set: bool,
    key_stdin: bool,
) -> Result<()> {
    let value = if set {
        let selected = backend
            .map(str::to_owned)
            .or_else(respire_client_host::classification::load_classify_backend)
            .unwrap_or_else(|| "jev".to_owned());
        classify_config::configure(&selected, api_base, model, key_stdin)?
    } else {
        if key_stdin || model.is_some() {
            anyhow::bail!("--key-stdin and --model require classify-config --set");
        }
        classify_config::status(backend, api_base)?
    };
    emit_result(ResultEnvelope::new(
        "classify-config",
        OutputStatus::Ok,
        value,
        Vec::new(),
    ))
}

fn run(args: Cli) -> Result<()> {
    // The binary's main wires the host hooks before dispatch; test builds and
    // in-process capture callers reach run() without main(), so wire them
    // idempotently here too (the first installation always wins).
    let _ = install_cli_host_hooks();
    if let Some(Command::Doctor {
        remote,
        check_update,
        fix,
    }) = args.command.as_ref()
    {
        set_json_mode(
            args.json || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"),
        );
        let _progress = progress::Scope::start(args.progress_id.clone(), !json_mode(), true);
        return doctor::run(*remote, *check_update, *fix);
    }
    if let Some(Command::Runtime { command }) = args.command.as_ref() {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        return autostart::execute(command);
    }
    if let Some(Command::SuperReset { super_pass }) = args.command.as_ref() {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        // The private adapter owns Paused recovery; never wrap it in change_profile.
        return run_super_reset(super_pass.as_deref());
    }
    if let Some(Command::Migrate {
        source: Some(source),
        account: Some(account),
        vault: false,
        ..
    }) = args.command.as_ref()
    {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        // This private transaction owns Paused recovery, before generic login/profile gates.
        return emit_result(autostart::control_migrate_profile(source, account)?);
    }
    // Static CLI support is safe to inspect even on a fresh or inaccessible
    // profile. It makes no statement about account rights or model readiness.
    if matches!(args.command, Some(Command::Capabilities)) {
        return run_capabilities();
    }
    if matches!(
        args.command.as_ref(),
        Some(Command::Keygen { .. } | Command::Register { .. } | Command::Login { .. })
    ) {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        // Account control owns its recovery receipt; the legacy profile wrapper must not replay it.
        match args.command.as_ref() {
            Some(Command::Keygen { pass, force }) => return run_keygen(pass.as_deref(), *force),
            Some(Command::Register {
                addr,
                user,
                pass,
                super_pass,
            }) => {
                return run_register(
                    addr.as_deref(),
                    user.as_deref(),
                    pass.as_deref(),
                    super_pass.as_deref(),
                );
            }
            Some(Command::Login {
                addr,
                user,
                pass,
                super_pass,
                interactive,
                oauth,
                dashboard,
                no_open,
                migrate_local,
            }) => {
                return login::run(
                    addr.as_deref(),
                    user.as_deref(),
                    pass.as_deref(),
                    super_pass.as_deref(),
                    *interactive,
                    *oauth,
                    dashboard.as_deref(),
                    *no_open,
                    *migrate_local,
                );
            }
            _ => unreachable!("account command matched above"),
        }
    }
    if matches!(args.command.as_ref(), Some(Command::Space { action, .. })
        if matches!(action.as_str(), "invite" | "join" | "kick" | "create" | "remove"))
        || matches!(args.command.as_ref(), Some(Command::Account { action, .. }) if action == "remove")
    {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        // Membership owns its original Paused receipt, before generic profile/login recovery.
        return host_command(&args).context("private space host handler is missing")?;
    }
    // Legacy recovery owns its Paused transaction before ordinary requests hit the fence.
    if !runtime_policy::client_only()
        && !matches!(args.command, Some(Command::V | Command::MemoryRevision))
    {
        rpc::recover_interrupted_login()?;
    }
    if let Some(Command::AgentConfig { set: Some(kv) }) = args.command.as_ref() {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        // The original O owns recovery before the generic Paused/request gate.
        return emit_result(autostart::control_agent_config(kv)?);
    }
    autostart::check_managed_request()?;
    if matches!(
        args.command.as_ref(),
        Some(Command::Migrate {
            source: None,
            account: None,
            vault: false,
            ..
        })
    ) {
        runtime_policy::require_host("explicit legacy migration")?;
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        let value = profile_discovery::list_legacy_profiles()?;
        let mut envelope =
            ResultEnvelope::new("migrate", OutputStatus::Ok, value.clone(), Vec::new());
        envelope.details = value;
        return emit_result(envelope);
    }
    // Listings need host metadata only; switches own their config transaction.
    // Never enter the legacy change_profile -> run_local transaction for them.
    if matches!(args.command.as_ref(), Some(Command::Account { action, .. })
        if action != "remove")
        || matches!(args.command.as_ref(), Some(Command::Space { action, .. }) if matches!(action.as_str(), "list" | "use"))
    {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        return host_command(&args).context("profile switch host handler is missing")?;
    }
    if matches!(
        args.command.as_ref(),
        Some(Command::Secret { .. } | Command::KeysExport { .. })
    ) {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        return match args.command.as_ref() {
            Some(Command::Secret { reveal }) => run_secret(*reveal),
            Some(Command::KeysExport { out }) => run_keys_export(out.as_deref()),
            _ => unreachable!("private secret command matched above"),
        };
    }
    if DIRECT_MODE.load(Ordering::Relaxed)
        && matches!(
            args.command,
            Some(Command::Metadata {
                command: metadata::Command::Status
            })
        )
    {
        runtime_policy::require_host("direct metadata status")?;
        set_json_mode(
            args.json || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"),
        );
        return emit_result(autostart::control_offline_read(
            respire_protocol::metadata_control::HostOfflineRead::MetadataStatus,
        )?);
    }
    if let Some(Command::Metadata {
        command: command @ (metadata::Command::Enable { .. } | metadata::Command::Disable),
    }) = args.command.as_ref()
    {
        set_json_mode(
            args.json || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"),
        );
        return emit_result(autostart::control_metadata(
            command,
            DIRECT_MODE.load(Ordering::Relaxed),
        )?);
    }
    if let Some(Command::Snapshot {
        cmd: SnapshotCmd::Restore { id, confirm },
    }) = args.command.as_ref()
    {
        runtime_policy::require_host("snapshot restore")?;
        anyhow::ensure!(
            *confirm,
            "snapshot restore requires --confirm; it replaces local state and quarantines sync"
        );
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        return emit_result(autostart::snapshot_restore_control(id)?);
    }
    if let Some(Command::Snapshot {
        cmd: SnapshotCmd::Recover { confirm },
    }) = args.command.as_ref()
    {
        runtime_policy::require_host("snapshot recovery")?;
        anyhow::ensure!(*confirm, "snapshot recover requires --confirm");
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        return emit_result(autostart::snapshot_recover_control()?);
    }
    if let Some(Command::Model {
        action:
            ModelAction::InstallM3 {
                mirror,
                model,
                for_engine,
            },
    }) = args.command.as_ref()
    {
        set_json_mode(
            args.json
                || respire_client_host::env::var("RSRS_JSON")
                    .is_ok_and(|value| value == "1" || value == "true"),
        );
        let _task = respire_commands::model_progress::TaskScope::new(args.model_task_id.clone());
        let intent = respire_protocol::ModelInstallIntent {
            mirror: mirror.clone(),
            model: model.clone(),
            for_engine: for_engine.clone(),
        };
        let (assets, skipped) = autostart::control_prepare_model(&intent)?;
        let directory = assets
            .assets
            .iter()
            .find(|asset| {
                matches!(
                    asset.name.as_str(),
                    "bge-m3-tokenizer" | "profile-tokenizer"
                )
            })
            .and_then(|asset| asset.path.as_deref())
            .and_then(|path| std::path::Path::new(path).parent())
            .context("Runtime model receipt is missing its tokenizer directory")?;
        let mut result = ResultEnvelope::new("model install-m3", OutputStatus::Ok,
            serde_json::json!({"dir":directory,"skipped":skipped,"activated":false,"model":"m3"}),
            vec![OutputItem::new("model", OutputStatus::Ok,
                "Runtime verified model files and fresh backend loading; run rsrs reembed to rebuild an old index")]);
        result.details = serde_json::to_value(&assets)?;
        return emit_result(result);
    }
    // Business RPC retains Runtime's post-ownership snapshot gate and bootstrap.
    // Only local host writes need this offline check before they change files.
    let host_snapshot_write = match args.command.as_ref() {
        Some(
            Command::AgentConfig { set: Some(_) }
            | Command::ClassifyConfig { set: true, .. }
            | Command::Inject {
                targets: false,
                preview: false,
                ..
            }
            | Command::Plugin {
                command: PluginCommand::Test { .. },
            },
        ) => true,
        Some(Command::Config {
            data_dir,
            addr,
            autosync,
            cure_auto,
            rpc_parallelism,
        }) => {
            data_dir.is_some()
                || addr.is_some()
                || autosync.is_some()
                || cure_auto.is_some()
                || rpc_parallelism.is_some()
        }
        Some(Command::Account { action, .. }) => action == "remove",
        Some(Command::Space { action, .. }) => matches!(action.as_str(), "create" | "remove"),
        _ => false,
    };
    if host_snapshot_write && !runtime_policy::client_only() {
        runtime_policy::require_host("local host write snapshot preflight")?;
        if runtime_fetch::read_manifest()?.is_none() {
            runtime_fetch::download_and_install(None, None)?;
        }
        autostart::control_offline_read(
            respire_protocol::metadata_control::HostOfflineRead::SnapshotPreflight,
        ).context("snapshot preflight unavailable or blocked; inspect snapshot recovery before continuing")?;
    }
    let _model_task = respire::model_progress::TaskScope::new(args.model_task_id.clone());
    set_json_mode(
        args.json || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"),
    );
    if let Some(Command::Model { action }) = args.command.as_ref() {
        let request = match action {
            ModelAction::Catalog => Some(("model.catalog", Vec::new())),
            ModelAction::Configure { file } => {
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(file)?)?;
                Some(("model.configure", vec![serde_json::to_string(&value)?]))
            }
            ModelAction::Switch {
                model,
                backend,
                engine,
                variant,
            } => Some((
                "model.switch",
                vec![serde_json::to_string(
                    &serde_json::json!({"model":model,"backend":backend,"engine":engine,"variant":variant}),
                )?],
            )),
            ModelAction::Progress => Some(("model.progress", Vec::new())),
            ModelAction::Resume => Some(("model.resume", Vec::new())),
            _ => None,
        };
        if let Some((method, values)) = request {
            anyhow::ensure!(
                !DIRECT_MODE.load(Ordering::Relaxed),
                "model profiles require the resident runtime; omit --direct"
            );
            let value = rpc::profile_request(method, values)?;
            return emit_result(serde_json::from_value(value)?);
        }
    }
    if matches!(args.command, Some(Command::MemoryRevision)) {
        if !DIRECT_MODE.load(Ordering::Relaxed) && runtime_policy::client_only() {
            return rpc::call_existing_from_argv();
        }
        runtime_policy::require_host("memory revision control")?;
        let result = autostart::control_memory_revision()?;
        // Keep private control evidence out of the public CLI output shape.
        return emit_result(ResultEnvelope::new(
            "memory-revision",
            OutputStatus::Ok,
            result.summary,
            Vec::new(),
        ));
    }
    // Host-only migration and repair dispatch must obey the memory gate too.
    if respire_client_host::settings::off_mode()?
        && matches!(args.command.as_ref(), Some(Command::Review { .. }))
    {
        set_exit_code(1);
        let mut result = ResultEnvelope::new(
            "review",
            OutputStatus::Fail,
            serde_json::json!({"saved":false}),
            Vec::new(),
        );
        result.details = serde_json::json!({"code":"feature_disabled","saved":false});
        result
            .errors
            .push("memory service is off; due state is unavailable".to_owned());
        return emit_result(result);
    }
    if respire_client_host::settings::off_mode()?
        && args
            .command
            .as_ref()
            .is_some_and(|command| !is_off_allowed(command))
    {
        return rpc::call_from_argv();
    }
    let display = !json_mode()
        && args.command.is_some()
        && !matches!(
            args.command,
            Some(Command::Mcp | Command::Login { .. } | Command::V)
        );
    let _progress = progress::Scope::start(
        args.progress_id.clone(),
        display,
        matches!(args.command, Some(Command::Sync | Command::Doctor { .. })),
    );
    if let Some(Command::Space {
        action, code, name, ..
    }) = args.command.as_ref()
    {
        if action == "join" {
            let code = code.as_deref().or(name.as_deref()).ok_or_else(|| {
                respire_client_host::input_error::InputError("join needs an invite code".into())
            })?;
            let invite = respire::space::parse_invite(code)?;
            respire::space::validate_space_name(
                invite["space"].as_str().context("invite space missing")?,
            )?;
        }
    }
    if let Some(Command::Migrate {
        source,
        account,
        vault,
        addr,
        user,
        pass,
        super_pass,
        secret_key,
        new_super,
    }) = args.command.as_ref()
    {
        if *vault || source.is_some() {
            respire_client_host::settings::ensure_writable()?;
        }
        runtime_policy::require_host("explicit legacy migration")?;
        if *vault {
            return login::migrate_vault(
                addr.as_deref(),
                user.as_deref(),
                pass.as_deref(),
                super_pass.as_deref(),
                secret_key.as_deref(),
                new_super.as_deref(),
            );
        }
        let value = match (source.as_deref(), account.as_deref()) {
            (Some(source), Some(account)) => {
                return emit_result(autostart::control_migrate_profile(source, account)?);
            }
            (None, None) => profile_discovery::list_legacy_profiles()?,
            _ => anyhow::bail!("migration requires both --source and --account"),
        };
        let mut envelope =
            ResultEnvelope::new("migrate", OutputStatus::Ok, value.clone(), Vec::new());
        envelope.details = value;
        return emit_result(envelope);
    }
    if matches!(args.command, Some(Command::V)) {
        return crate::app_version::emit(json_mode());
    }
    if let Some(Command::ClassifyConfig {
        backend,
        api_base,
        model,
        set,
        key_stdin,
    }) = args.command.as_ref()
    {
        runtime_policy::require_host("classification configuration")?;
        return run_classify_config(
            backend.as_deref(),
            api_base.as_deref(),
            model.as_deref(),
            *set,
            *key_stdin,
        );
    }
    if let Some(Command::Restart { timeout }) = args.command.as_ref() {
        let result = rpc::restart_runtime(std::time::Duration::from_secs(*timeout))?;
        return emit_result(ResultEnvelope::new(
            "restart",
            OutputStatus::Ok,
            result,
            Vec::new(),
        ));
    }
    if matches!(
        args.command,
        Some(Command::Model {
            action: ModelAction::InstallEngines
        })
    ) {
        runtime_policy::require_host("inference engine installation")?;
        progress::phase(
            "\u{5b89}\u{88c5}\u{63a8}\u{7406}\u{5f15}\u{64ce}\u{ff1b}\u{7b49}\u{5f85} Windows ML",
            "Installing inference providers; waiting for Windows ML",
        );
        return emit_result(autostart::control_install_engines()?);
    }
    if matches!(
        args.command,
        Some(Command::Model {
            action: ModelAction::ResetCpu
        })
    ) {
        runtime_policy::require_host("CPU recovery and runtime shutdown")?;
        return emit_result(autostart::control_reset_cpu()?);
    }
    if matches!(
        args.command,
        Some(Command::Model {
            action: ModelAction::UninstallM3
        })
    ) {
        runtime_policy::require_host("M3 model removal")?;
        return emit_result(autostart::control_uninstall_m3()?);
    }
    if let Some(Command::Web { no_open }) = args.command.as_ref() {
        if !no_open {
            crate::web::open_browser(crate::web::DASHBOARD_URL)?;
        }
        return emit_result(ResultEnvelope::new(
            "web",
            OutputStatus::Ok,
            serde_json::json!({"url":crate::web::DASHBOARD_URL,"opened":!no_open}),
            Vec::new(),
        ));
    }
    if matches!(args.command, Some(Command::Mcp)) {
        if DIRECT_MODE.load(Ordering::Relaxed) {
            anyhow::bail!("mcp uses the resident runtime; do not pass --direct");
        }
        return mcp::serve();
    }
    // Profile and agent changes own their private maintenance transactions.
    // Other host commands never belong to Runtime business RPC.
    if let Some(outcome) = host_command(&args) {
        return outcome;
    }
    if DIRECT_MODE.load(Ordering::Relaxed) {
        // Deprecated downgrade: --direct used to bypass the resident runtime.
        // For one release train it forwards to the local runtime instead.
        eprintln!("deprecated: --direct now forwards to the local runtime; the in-process bypass is removed in an upcoming release train");
        return rpc::call_from_argv();
    }
    if args.command.is_none() {
        if std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout())
        {
            return shell::run();
        }
        eprintln!("{}", i18n::text("need_tty"));
        set_exit_code(2);
        return Ok(());
    }
    rpc::call_from_argv()
}

#[cfg(test)]
mod capture_tests {
    use clap::{CommandFactory, Parser};

    #[test]
    fn injected_chain_examples_follow_the_parser_contract() -> anyhow::Result<()> {
        for policy in [
            respire::inject::INSTRUCTIONS_MD,
            respire::inject::INSTRUCTIONS_LITE_MD,
        ] {
            let mut checked = 0;
            for example in policy
                .split('`')
                .skip(1)
                .step_by(2)
                .filter(|example| example.starts_with("rsrs chain ") && !example.contains('['))
            {
                let parsed = super::Cli::try_parse_from(example.split_whitespace())?;
                assert!(matches!(
                    parsed.command,
                    Some(super::Command::Chain { depth: 1..=3, .. })
                ));
                checked += 1;
            }
            assert!(
                checked > 0,
                "policy must retain an executable causal-chain example"
            );
        }
        assert!(super::Cli::try_parse_from([
            "rsrs",
            "chain",
            "synthetic-id",
            "--depth",
            "1-3",
            "--json"
        ])
        .is_err());
        Ok(())
    }

    #[test]
    fn help_matches_command_contracts() -> anyhow::Result<()> {
        let mut command = super::Cli::command();
        let split = command
            .find_subcommand_mut("split")
            .ok_or_else(|| anyhow::anyhow!("split command missing"))?
            .render_long_help()
            .to_string();
        assert!(split.contains("Split a mixed node"));
        assert!(!split.contains("Tree hygiene"));
        assert!(!split.contains("--parent"));
        let cure = command
            .find_subcommand_mut("tree-cure")
            .ok_or_else(|| anyhow::anyhow!("tree-cure command missing"))?
            .render_long_help()
            .to_string();
        assert!(cure.contains("Tree hygiene"));
        let plugin = command
            .find_subcommand_mut("plugin")
            .ok_or_else(|| anyhow::anyhow!("plugin command missing"))?
            .render_long_help()
            .to_string();
        assert!(plugin.contains("list shows config"));
        assert!(!plugin.contains("--list"));
        assert!(super::Cli::try_parse_from(["rsrs", "plugin", "list"]).is_ok());
        assert!(super::Cli::try_parse_from([
            "rsrs",
            "plugin",
            "test",
            "post-sync",
            "--payload",
            "{}"
        ])
        .is_ok());
        assert!(super::Cli::try_parse_from(["rsrs", "plugin", "--list"]).is_err());
        assert!(super::Cli::try_parse_from(["rsrs", "plugin", "test"]).is_err());
        assert!(super::Cli::try_parse_from(["rsrs", "chain", "entry-id"]).is_ok());
        assert!(super::Cli::try_parse_from(["rsrs", "chain", "--from", "entry-id"]).is_err());
        assert!(super::Cli::try_parse_from(["rsrs", "config", "--data-dir", "isolated"]).is_ok());
        let revision = super::Cli::try_parse_from(["rsrs", "memory-revision", "--json"])?;
        assert!(matches!(
            revision.command,
            Some(super::Command::MemoryRevision)
        ));
        assert!(!super::is_write_command(&super::Command::MemoryRevision));
        for (args, writes) in [
            (&["rsrs", "extract", "--targets"][..], false),
            (&["rsrs", "extract", "--targets", "--all"][..], false),
            (&["rsrs", "extract", "--id", "codex"][..], true),
        ] {
            let parsed = super::Cli::try_parse_from(args.iter().copied())?;
            let extract = parsed
                .command
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("extract command missing"))?;
            assert_eq!(super::is_write_command(extract), writes);
            assert_eq!(super::is_off_allowed(extract), !writes);
        }
        assert!(!super::is_write_command(&super::Command::Taxonomy {
            list: true,
            ensure: None
        }));
        assert!(super::is_write_command(&super::Command::Taxonomy {
            list: false,
            ensure: None
        }));
        assert!(super::is_write_command(&super::Command::Taxonomy {
            list: true,
            ensure: Some("synthetic".into())
        }));
        assert!(!super::is_write_command_fine(
            &super::Command::MemoryRevision
        ));
        assert!(super::is_off_allowed(&super::Command::MemoryRevision));
        assert!(super::Cli::try_parse_from(["rsrs", "v"]).is_ok());
        assert!(super::Cli::try_parse_from(["rsrs", "version"]).is_ok());
        let v_help = command
            .find_subcommand_mut("v")
            .ok_or_else(|| anyhow::anyhow!("v command missing"))?
            .render_long_help()
            .to_string();
        assert!(v_help.to_ascii_lowercase().contains("version"));
        Ok(())
    }

    use super::capture_run;

    #[test]
    fn input_failures_remain_distinct_from_runtime_failures() {
        let input: anyhow::Error =
            respire_client_host::input_error::InputError("no such entry: fixture".into()).into();
        let (envelope, code) = super::command_failure(&input.context("resort validation"));
        assert_eq!(code, 2);
        assert_eq!(envelope.summary["reason"], "invalid_input");
        assert_eq!(envelope.details["error_type"], "user");
        let runtime: anyhow::Error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "owned fixture I/O failure",
        )
        .into();
        let (envelope, code) = super::command_failure(&runtime);
        assert_eq!(code, 1);
        assert_eq!(envelope.summary["reason"], "runtime_error");
        assert_eq!(envelope.details["error_type"], "runtime");
        let original = "7c633a08-9077-4710-882e-ac3d2998ab8b";
        let unknown: anyhow::Error = super::autostart::AuthOutcomeUnknown {
            operation_id: original.into(),
            force: true,
        }
        .into();
        let (envelope, code) = super::command_failure(&unknown.context("private exchange"));
        assert_eq!(code, 1);
        assert_eq!(envelope.summary["reason"], "auth_outcome_unknown");
        assert_eq!(envelope.details["operation_id"], original);
        assert_eq!(envelope.details["force"], true);
        assert_eq!(envelope.details["replayed"], false);
        let unknown: anyhow::Error = super::autostart::AccountOutcomeUnknown {
            operation_id: original.into(),
            source_profile: std::path::PathBuf::from("original-profile"),
            register: true,
        }
        .into();
        let (envelope, _) = super::command_failure(&unknown);
        assert_eq!(envelope.summary["reason"], "account_outcome_unknown");
        assert_eq!(envelope.details["source_profile"], "original-profile");
        assert_eq!(envelope.details["register"], true);
        assert_eq!(envelope.details["result_command"], "runtime account-result");
        let parsed = capture_run(vec!["--json".into(), "--not-a-command".into()]);
        assert_eq!(parsed.exit, 2);
        assert_eq!(parsed.envelope.summary["reason"], "invalid_input");
        assert_eq!(parsed.envelope.details["error_type"], "user");
    }
}

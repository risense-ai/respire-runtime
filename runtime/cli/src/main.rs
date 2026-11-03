//! rsrs CLI - thin shell: parse args and assemble.
//!
//! local-first: remember/recall/list/forget all hit the local store (the authority);
//! `sync` does two-way ciphertext sync (local ↔ cloud backup).
//!
//! Three parts (locked 2026-09-06): (1) memory CLI (this file, memory operations)
//! (2) user client (account/keys/inject distribution) (3) server + frontend (respire-server).
//! The CLI logs in itself: `register` / `login` write session.json (addr/token/user).
//! Without a token, sync and post-write auto-sync cannot reach the server.
//! An existing session.json, or RSRS_ADDR/TOKEN, also works.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use uuid::Uuid;

mod autostart;
mod classify_config;
mod host_rpc;
mod login;
mod mcp;
mod rpc;
mod runtime_fetch;
mod shell;
mod web;

// Server-face modules moved into the shared runtime crate; these crate-root
// rebindings keep `crate::admission` / `crate::runtime_http` paths resolving.
use respire_commands::admission;
use respire_commands::runtime_http;

// Shared command surface extracted into the respire_commands crate; the bin
// re-binds the module names so existing `crate::` paths keep resolving.
use respire_commands::app_version;
use respire_commands::cli_def::{
    changes_profile, BenchCmd, Cli, Command, GrantCommand, ModelAction, QueryLogCmd,
    SessionCommand, SnapshotCmd,
};
use respire_commands::engine::{
    build_local, build_remote, build_session, build_session_with_owner,
    build_session_with_owner_inner, build_transport, read_session_json,
    remote_config_from_session_or_env,
};
use respire_commands::gates::{
    is_off_allowed, is_readonly_switch_off, is_write_command, is_write_command_fine,
};
use respire_commands::i18n;
use respire_commands::metadata;
use respire_commands::model_install;
use respire_commands::model_progress;
use respire_commands::net_rpc;
use respire_commands::progress;
pub(crate) use respire_commands::sync_flow::{
    is_retriable_sync_error, read_remote_sync_history, run_sync_attempts, sync_live, sync_phase,
    sync_tracked,
    sync_tracked_boundary, sync_with_retry,
};
pub(crate) use respire_commands::engine::{
    background_sync_once,
    change_metadata_profile, run_capabilities, run_local, run_memory_revision, run_metadata_host,
    run_metadata_status, schedule_autosync, select_diary_tracks, DIRECT_MODE, EMBEDDER_SLOT,
};
use respire_commands::output::{self, Item as OutputItem, ResultEnvelope, Status as OutputStatus};
use respire_commands::{bench, classify, recall_select, review, skill};
use respire_commands::output_emit::{command_failure, emit_details, emit_result};
use respire_commands::output_state::{
    exit_code, json_mode, mark_emitted, output_emitted, parse_failure, progress_enabled,
    set_exit_code, set_json_mode, status_exit_code, Captured, CAPTURED, DEFER_PROFILE_OUTPUT,
    HOST_RPC_OUTPUT, OUTPUT_EMITTED, OUTPUT_EXIT_CODE,
};
use respire_commands::runtime_error;
use respire_commands::runtime_policy;
use respire_commands::util::{
    current_user, dev_label, list_since_bound, local_day_of, now_stamp, short_id,
};

use respire::auth;
use respire::memory::bge::BgeEmbedder;
use respire::memory::model::Kind;
use respire::memory::search::Embedder;
use respire::memory::{MemoryEngine, MemoryQuery, SessionKeys};
use respire::sync::{remote_configured, SyncStats};

use respire::transport::local::LocalStore;
use respire::transport::remote::{RemoteConfig, RemoteTransport};
use respire::transport::MemoryTransport;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn host_command(args: &Cli) -> Option<Result<()>> {
    match args.command.as_ref() {
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
            let outcome = match logout_cli(*full) { Ok(value) => value, Err(error) => return Some(Err(error)) };
            let status = if outcome.session_found {
                OutputStatus::Ok
            } else {
                OutputStatus::Skip
            };
            let action = if outcome.full {
                if outcome.session_found {
                    "deleted"
                } else {
                    "absent"
                }
            } else if outcome.session_found {
                "cleared"
            } else {
                "absent"
            };
            let mut result = ResultEnvelope::new(
                "logout",
                status,
                serde_json::json!({
                    "mode": if outcome.full { "full" } else { "session" },
                    "action": action,
                    "session_found": outcome.session_found,
                }),
                vec![OutputItem::new("session", status, action)],
            );
            result.details = serde_json::json!({
                "path": outcome.path.display().to_string(),
                "identity_deleted": outcome.full && outcome.session_found,
                "credentials_cleared": !outcome.full && outcome.session_found,
            });
            if outcome.full && outcome.session_found {
                result
                    .actions
                    .push("register or import five-key material to reconnect".to_owned());
            } else if !outcome.full && outcome.session_found {
                result.actions.push("login to reconnect".to_owned());
            }
            return Some(emit_result(result));
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
        }) => {
            Some(run_space(
                action,
                name.as_deref(),
                note.as_deref(),
                *readonly,
                code.as_deref(),
                session.as_deref(),
                *all,
                *yes,
            ))
        }

        Some(Command::UpdateCheck { force, clear }) => Some(run_update_check(*force, *clear)),

        Some(Command::KeysExport { out }) => Some(run_keys_export(out.as_deref())),

        Some(Command::Config {
            data_dir,
            addr,
            autosync,
            cure_auto,
            rpc_parallelism,
        }) => {
            Some(run_config(
                data_dir.as_deref(),
                addr.as_deref(),
                *autosync,
                *cure_auto,
                *rpc_parallelism,
            ))
        }

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
        }) => {
            Some(run_fivekeys(
                addr,
                user,
                pass,
                secret,
                kdf_salt,
                wrapped_urk,
                urk_nonce,
                super_pass,
            ))
        }

        Some(Command::Register {
            addr,
            user,
            pass,
            super_pass,
        }) => {
            Some(run_register(
                addr.as_deref(),
                user.as_deref(),
                pass.as_deref(),
                super_pass.as_deref(),
            ))
        }
        _ => None,
    }
}

pub(crate) fn capture_run(args: Vec<String>) -> Captured {
    CAPTURED.with(|slot| *slot.borrow_mut() = None);
    OUTPUT_EMITTED.with(|flag| flag.set(false));
    OUTPUT_EXIT_CODE.with(|flag| flag.set(0));
    let parsed = Cli::try_parse_from(
        std::iter::once(std::ffi::OsString::from("rsrs"))
            .chain(args.iter().cloned().map(std::ffi::OsString::from)),
    );
    let defer_index = parsed.as_ref().is_ok_and(|cli| matches!(cli.command.as_ref(),
        Some(Command::Remember { .. } | Command::Update { .. } | Command::Import { .. }
            | Command::Attach { .. } | Command::Restore { .. })));
    let _deferred = defer_index.then(respire::core_sdk::defer_indexing);
    let ran = match parsed {
        Ok(cli) => match run(cli) {
            Err(error) if !HOST_RPC_OUTPUT.get() && error.downcast_ref::<respire::transport::local::MemorySourceChanged>().is_some() => {
                Cli::try_parse_from(std::iter::once("rsrs".to_owned()).chain(args.iter().cloned()))
                    .map_err(anyhow::Error::from).and_then(run)
            }
            result => result,
        },
        Err(error) => {
            let code = error.exit_code();
            let mut envelope = ResultEnvelope::new(
                "cli",
                if code == 0 {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Fail
                },
                serde_json::json!({"reason": "parse"}),
                Vec::new(),
            );
            if code != 0 {
                envelope = parse_failure(&error);
            }
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
            mark_emitted();
            set_exit_code(code);
            Ok(())
        }
    };
    if let Err(error) = ran {
        if !output_emitted() {
            let (envelope, code) = command_failure(&error);
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
            set_exit_code(code);
        }
    }
    let mut envelope = CAPTURED
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| {
            ResultEnvelope::new("cli", OutputStatus::Ok, serde_json::json!({}), Vec::new())
        });
    envelope.ensure_failure_diagnostics();
    Captured {
        exit: exit_code(),
        envelope,
    }
}

struct LogoutOutcome {
    full: bool,
    session_found: bool,
    path: PathBuf,
}

/// Perform logout in the CLI so the output contract does not depend on a
/// newer app-core helper. Keep the same session and full-logout semantics.
fn logout_cli(full: bool) -> Result<LogoutOutcome> {
    let path = auth::session_file()?;
    if full {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(LogoutOutcome {
                full,
                session_found: true,
                path,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(LogoutOutcome {
                full,
                session_found: false,
                path,
            }),
            Err(error) => Err(anyhow!("clear failed: {error}")),
        };
    }

    match auth::read_session_json() {
        Ok(mut data) => {
            if let Some(object) = data.as_object_mut() {
                object.remove("token");
                object.remove("session_id");
            }
            auth::write_session_json(&data)?;
            Ok(LogoutOutcome {
                full,
                session_found: true,
                path,
            })
        }
        Err(_error) if !path.exists() => Ok(LogoutOutcome {
            full,
            session_found: false,
            path,
        }),
        Err(error) => Err(error),
    }
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
    // v4: --pass is unused for encryption (super password is system-generated); kept for old scripts
    if pass.is_some() {
        eprintln!("INFO from v4, --pass is not used for encryption: the super password is system-generated; copy the output below");
    }
    // Overwrite guard: keygen issues a new key, and the old key is the only unwrap for store ciphertext -
    // 1. Overwriting while this machine has a cloud session (user/token) drops the session; cloud memories become unreadable.
    // 2. Rotating keys while the local store has memories locks those entries (worse offline: no cloud copy to fall back on).
    // Without --force, refuse and point at the right command.
    let has_wrap = auth::read_session_json()
        .ok()
        .map(|d| {
            let wrap = d["wrapped_urk"].as_str().is_some_and(|s| !s.is_empty());
            let user = d["user"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned);
            let token = d["token"].as_str().is_some_and(|s| !s.is_empty());
            (wrap, user, token)
        })
        .unwrap_or((false, None, false));
    if !force {
        if has_wrap.0 && (has_wrap.1.is_some() || has_wrap.2) {
            anyhow::bail!(
                "this machine already has cloud key material (user {}) - keygen would overwrite it and drop the cloud session, leaving cloud memories unreadable.\
                 To switch to offline keys, add --force. To keep using this machine's memories, rsrs login.\
                 Backup first: rsrs keys-export --out <file>",
                has_wrap.1.as_deref().unwrap_or("(unnamed)")
            );
        }
        // count is a MemoryTransport trait method; the trait must be in scope to call it
        use respire::MemoryTransport as _;
        let alive = respire::service::open_store()
            .and_then(|s| s.count())
            .unwrap_or(0);
        if has_wrap.0 && alive > 0 {
            anyhow::bail!(
                "this store already has {} memories encrypted with the current keys - another keygen would mint new keys and those memories would be unreadable forever.\
                 To start over (old memories discarded), add --force. To keep using this store, run other commands (no need to rebuild keys).",
                alive
            );
        }
    }
    let (path, super_pass) = auth::keygen()?;
    let mut result = ResultEnvelope::new(
        "keygen",
        OutputStatus::Ok,
        serde_json::json!({"path":path.to_string_lossy(),"super":super_pass}),
        vec![OutputItem::new(
            "keys",
            OutputStatus::Ok,
            path.display().to_string(),
        )],
    );
    result
        .actions
        .push("login --interactive --user <user> --pass <password>".into());
    emit_result(result)
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
                vec![OutputItem::new(
                    "version",
                    status,
                    s.comparison(),
                )],
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
            let v = respire::service::account_list()?;
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
            print_account_use(&respire::service::account_use(name.trim())?)
        }
        "remove" => {
            let name = name.filter(|n| !n.trim().is_empty()).ok_or_else(|| {
                anyhow::anyhow!("remove needs a profile name: rsrs account remove <name> --yes")
            })?;
            if !yes {
                anyhow::bail!("deleting a profile wipes the local store and keys and is unrecoverable - add --yes to confirm");
            }
            respire::service::account_remove(name.trim())?;
            emit_result(ResultEnvelope::new(
                "account",
                OutputStatus::Ok,
                serde_json::json!({"action":"remove","name":name}),
                vec![OutputItem::new("profile", OutputStatus::Ok, "deleted")],
            ))
        }
        // A profile name as the action = switch: rsrs account fslong ≡ account use fslong
        other => print_account_use(&respire::service::account_use(other)?),
    }
}

fn print_account_use(v: &serde_json::Value) -> Result<()> {
    emit_result(ResultEnvelope::new(
        "account",
        OutputStatus::Ok,
        serde_json::json!({"name":v["name"],"dir":v["dir"],"user":v["user"]}),
        vec![
            OutputItem::new(
                "profile",
                OutputStatus::Ok,
                v["name"].as_str().unwrap_or(""),
            ),
            OutputItem::new(
                "directory",
                OutputStatus::Ok,
                v["dir"].as_str().unwrap_or(""),
            ),
        ],
    ))
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
            let v = space::space_list()?;
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
                .ok_or_else(|| respire_app::input_error::InputError("create needs a space name: rsrs space create <name>".into()))?;
            let v = space::space_create(n)?;
            let mut result = ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"create","name":v["name"]}), vec![OutputItem::new("space", OutputStatus::Ok, v["name"].as_str().unwrap_or(""))]);
            result.actions.push(v["hint"].as_str().unwrap_or("").to_owned());
            result.details = v;
            emit_result(result)
        }
        "use" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| respire_app::input_error::InputError("use needs a space name: rsrs space use <name>".into()))?;
            let v = space::space_use(n)?;
            let mut result = ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"use","name":v["name"]}), vec![OutputItem::new("space", OutputStatus::Ok, v["name"].as_str().unwrap_or("")), OutputItem::new("directory", OutputStatus::Ok, v["dir"].as_str().unwrap_or(""))]);
            result.details = v;
            emit_result(result)
        }
        "invite" => {
            let v = space::space_invite(note, readonly)?;
            let status = if v["readonly"].as_bool() == Some(true) { OutputStatus::Warn } else { OutputStatus::Ok };
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"invite","space":v["space"]}), vec![OutputItem::new("code", status, v["code"].as_str().unwrap_or("")), OutputItem::new("session", OutputStatus::Ok, v["session_id"].as_str().unwrap_or(""))]);
            result.actions.push("space join <code>".into());
            result.details = v;
            emit_result(result)
        }
        "join" => {
            let c = code.or(name).filter(|c| !c.trim().is_empty())
                .ok_or_else(|| respire_app::input_error::InputError("join needs an invite code: rsrs space join <code>".into()))?;
            let v = space::space_join(c)?;
            let status = if v["readonly"].as_bool() == Some(true) || v["keyring"].as_bool() == Some(false) { OutputStatus::Warn } else { OutputStatus::Ok };
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"join","space":v["space"]}), vec![OutputItem::new("space", status, v["space"].as_str().unwrap_or(""))]);
            result.actions.push(v["hint"].as_str().unwrap_or("").to_owned());
            result.details = v;
            emit_result(result)
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
                return Err(respire_app::input_error::InputError("kick needs --session <id> or --all".into()).into());
            }
            let v = space::space_kick(session, all)?;
            let revoked = v["revoked"].as_array().cloned().unwrap_or_default();
            let failed = v["failed"].as_array().cloned().unwrap_or_default();
            let status = if failed.is_empty() { OutputStatus::Ok } else { OutputStatus::Warn };
            let items = revoked.iter().map(|r| OutputItem::new("revoked", OutputStatus::Ok, r.as_str().unwrap_or(""))).chain(failed.iter().map(|f| OutputItem::new("failed", OutputStatus::Warn, f.as_str().unwrap_or("")))).collect();
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"kick","revoked":revoked.len(),"failed":failed.len(),"remaining":v["remaining"]}), items);
            result.details = v;
            emit_result(result)
        }
        "remove" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| respire_app::input_error::InputError("remove needs a space name: rsrs space remove <name> --yes".into()))?;
            if !yes {
                return Err(respire_app::input_error::InputError("deleting a space profile wipes the local store and keys and is unrecoverable - add --yes to confirm".into()).into());
            }
            space::space_remove(n)?;
            emit_result(ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"remove","name":n}), vec![OutputItem::new("space", OutputStatus::Ok, "deleted")]))
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
    if let Some(d) = data_dir {
        respire::service::set_data_dir(d)?;
    }
    if let Some(a) = addr {
        respire::service::set_server_addr(a)?;
    }
    if let Some(v) = autosync {
        respire::service::set_autosync(v)?;
    }
    if let Some(v) = cure_auto {
        respire::service::set_cure_auto(v)?;
    }
    if let Some(v) = rpc_parallelism {
        respire::service::set_rpc_parallelism(v)?;
    }
    let workers = rpc::worker_limit();
    let mut worker_text = workers.to_string();
    if rpc_parallelism.is_some() {
        worker_text.push_str(" (after --runtime-internal --stop)");
    }
    let info = serde_json::json!({
        "data_dir": respire::service::data_dir().to_string_lossy(),
        "default_data_dir": respire::service::default_data_dir().to_string_lossy(),
        "addr": respire::service::server_addr(),
        "default_addr": respire::service::DEFAULT_SERVER_ADDR,
        "autosync": respire::service::autosync_enabled(),
        "cure_auto": respire::service::cure_auto_enabled(),
        "rpc_parallelism": respire::service::rpc_parallelism_setting(),
        "rpc_workers": workers,
    });
    let items = vec![
        OutputItem::new(
            "data dir",
            OutputStatus::Ok,
            info["data_dir"].as_str().unwrap_or(""),
        ),
        OutputItem::new(
            "server",
            OutputStatus::Ok,
            info["addr"].as_str().unwrap_or(""),
        ),
        OutputItem::new("auto-sync", OutputStatus::Ok, info["autosync"].to_string()),
        OutputItem::new("auto-cure", OutputStatus::Ok, info["cure_auto"].to_string()),
        OutputItem::new("rpc workers", OutputStatus::Ok, worker_text),
    ];
    emit_result(ResultEnvelope::new("config", OutputStatus::Ok, info, items))
}

/// Under v3, Account Secret is no longer a decrypt key - export the v3 three-piece; old v1 material is listed as a side note.
fn run_keys_export(out: Option<&str>) -> Result<()> {
    let data = respire::auth::read_session_json()?;
    let user = data["user"].as_str().unwrap_or("").to_owned();
    let addr = data["addr"].as_str().unwrap_or("").to_owned();
    let version = data["vault_version"].as_i64().unwrap_or(0);
    let kdf_salt = data["kdf_salt"].as_str().unwrap_or("").to_owned();
    let wrapped_urk = data["wrapped_urk"].as_str().unwrap_or("").to_owned();
    let urk_nonce = data["urk_nonce"].as_str().unwrap_or("").to_owned();
    if wrapped_urk.is_empty() {
        anyhow::bail!("no local key material (session.json missing wrapped_urk) - this machine never ran register/keys");
    }
    let is_v4 = version >= 4;
    // v4: super password = session["secret_key"] or the keyring; v3: passphrase + Secret Key two-factor
    let super_key = data["secret_key"].as_str().unwrap_or("").to_owned();
    let legacy_super = data["super"].as_str().map(ToOwned::to_owned)
        .or_else(|| respire::keystore::load_super(&user)).unwrap_or_default();
    let super_key = if is_v4 && super_key.is_empty() {
        respire::keystore::load_super(&user).unwrap_or_default()
    } else {
        super_key
    };
    if is_v4 && super_key.is_empty() {
        anyhow::bail!(
            "this machine has no super password (session and keyring are both empty) - \
             if the old machine can still unlock, run rsrs keys-export there; or rsrs super-reset with the current code"
        );
    }
    let is_v3 = version == 3;
    let body = if version == 1 {
        let account_secret = data["secret"].as_str().filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("v1 Account Secret is missing; retain the original device and library"))?;
        format!(
            "rsrs v1 key-recovery notes (keep private; losing the original factors makes data unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- original v1 decrypt factors (no independent super password) --\n\
             original login password: required, not included in this export\n\
             Account Secret: {account_secret}\n\n\
             -- unchanged vault wrap material --\n\
             vault_version: 1\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- new device, after explicit full-library and cloud migration --\n\
             rsrs login --interactive --user {user} --pass <original-login-password>\n\
             Enter the original Account Secret when prompted; do not use --super or ordinary --secret-key.\n\n\
             -- select the explicitly migrated library and publish the same v1 factors --\n\
             rsrs migrate --vault --user {user} --pass <original-login-password> --secret-key <original-account-secret>\n"
        )
    } else if is_v4 {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- super password (decrypt depends on this; v4 single factor) --\n\
             super password: {super_key}\n\n\
             -- vault wrap material (a new machine login fetches this; listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- import on a new machine --\n\
             rsrs login --interactive --user {user} --pass <login-password> --super {super_key}\n\
             (or fill the same super password on the website Keys & Recovery page after login)\n"
        )
    } else {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- original decrypt factors (migration retains the vault version and factors) --\n\
             super password (passphrase): {legacy_super}\n\
             Secret Key (recovery code): {super_key}\n\n\
             -- vault wrap material (listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- explicitly migrate the full library, select it, then publish its unchanged-factor vault --\n\
             rsrs migrate --vault --user {user} --pass <login-password> --super \"{legacy_super}\" --secret-key {super_key}\n"
        )
    };
    if !(is_v4 || is_v3) {
        eprintln!("WARN this profile retains its original v1/v2 factors; migrate the complete library explicitly before cloud namespace publication");
    }
    match out {
        Some(path) => {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?;
                f.write_all(body.as_bytes())?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, &body)?;
            let mut result = ResultEnvelope::new(
                "keys-export",
                OutputStatus::Ok,
                serde_json::json!({"path":path,"version":version,"user":user}),
                vec![OutputItem::new("file", OutputStatus::Ok, path)],
            );
            result
                .actions
                .push("protect file; it contains decrypt secrets".into());
            emit_result(result)?;
        }
        None => {
            let mut result = ResultEnvelope::new(
                "keys-export",
                OutputStatus::Warn,
                serde_json::json!({"version":version,"user":user,"inline":true}),
                vec![OutputItem::new("content", OutputStatus::Warn, body)],
            );
            result
                .actions
                .push("use --out <file> for protected storage".into());
            emit_result(result)?;
        }
    }
    Ok(())
}

/// Account Secret / five-keys view (--reveal shows full text; default is masked).
fn run_secret(reveal: bool) -> Result<()> {
    let info = respire::service::session_info();
    if !info.has_session {
        let mut result = ResultEnvelope::new(
            "secret",
            OutputStatus::Skip,
            serde_json::json!({"session":false}),
            vec![OutputItem::new(
                "session",
                OutputStatus::Skip,
                "not available",
            )],
        );
        result.actions.push("register or login".into());
        return emit_result(result);
    }
    let mut items = vec![
        OutputItem::new("user", OutputStatus::Ok, info.user.clone()),
        OutputItem::new("address", OutputStatus::Ok, info.addr.clone()),
        OutputItem::new(
            "token",
            OutputStatus::Ok,
            if info.has_token { "present" } else { "missing" },
        ),
    ];
    let mut details = serde_json::json!({"session":serde_json::to_value(&info)?});
    if reveal {
        let secret = respire::service::session_secret_full()?;
        let five = respire::service::session_five_keys()?;
        items.push(OutputItem::new(
            "secret",
            OutputStatus::Warn,
            secret.clone(),
        ));
        items.push(OutputItem::new(
            "keys",
            OutputStatus::Warn,
            serde_json::to_string(&five)?,
        ));
        details["secret"] = serde_json::json!(secret);
        details["five"] = five;
    } else {
        items.push(OutputItem::new(
            "secret",
            OutputStatus::Ok,
            info.secret_masked,
        ));
    }
    let mut result = ResultEnvelope::new(
        "secret",
        if reveal {
            OutputStatus::Warn
        } else {
            OutputStatus::Ok
        },
        serde_json::json!({"reveal":reveal,"user":info.user}),
        items,
    );
    result.details = details;
    if reveal {
        result.actions.push("protect secret output".into());
    }
    emit_result(result)
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
    auth::fivekeys_login(
        addr,
        user,
        pass,
        secret,
        kdf_salt,
        wrapped_urk,
        urk_nonce,
        super_pass,
    )?;
    emit_result(ResultEnvelope::new(
        "fivekeys",
        OutputStatus::Ok,
        serde_json::json!({"ok":true,"user":user,"addr":addr}),
        vec![OutputItem::new("session", OutputStatus::Ok, "ready")],
    ))
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
        .unwrap_or(respire::service::DEFAULT_SERVER_ADDR);
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
    let issued = respire::service::register(addr, &user, &pass, &super_pass)?;
    let data = auth::read_session_json().unwrap_or_else(|_| serde_json::json!({}));
    let secret_key = data["secret_key"].as_str().unwrap_or("").to_owned();
    let super_key = issued.unwrap_or_else(|| secret_key.clone());
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
    let installed = respire_commands::host_hooks::install(respire_commands::host_hooks::HostHooks {
        background_paused: Some(|| autostart::background_paused()),
        check_direct_access: Some(|| autostart::check_direct_access()),
        note_credential_access: Some(|available| autostart::note_credential_access(available)),
        context_changed: Some(rpc::context_changed),
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
        extract_tui_run: Some(respire::extract_tui::run),
        runtime_is_up: Some(rpc::runtime_is_up),
        change_profile: Some(|change| rpc::change_profile(|| change())),
        managed_id: Some(|| autostart::managed_id()),
        verify_managed_boot: Some(|| autostart::verify_managed_boot()),
        record_exit: Some(|success| autostart::record_exit(success)),
        credential_state: Some(|| autostart::credential_state()),
        capture_run: Some(capture_run),
        mcp_http_response: Some(|request| {
            mcp::http_response(mcp::HttpIn {
                method: request.method,
                path: request.path,
                origin: request.origin,
                accept: request.accept,
                body: request.body,
            })
        }),
    });
    if installed {
        respire_commands::rpc_worker::install_recall_stats_enqueue(rpc::enqueue_recall_stats_local);
    }
    installed
}

fn main() {
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
            std::process::exit(1);
        }
    };
    match handle.join() {
        Ok(exit) => std::process::exit(exit),
        Err(payload) => {
            eprintln!("command thread panicked: {}", panic_message(payload));
            std::process::exit(1);
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
    if std::env::args_os().any(|arg|arg=="--host-rpc-stdio") {
        set_json_mode(true);
        if std::env::args_os().any(|arg|arg=="--client-only") {
            std::env::set_var("RSRS_CLIENT_ONLY", "1");
        }
        return match host_rpc::serve() {
            Ok(code)=>code,
            Err(error)=>{let (envelope,code)=command_failure(&error);if let Err(output_error)=emit_result(envelope){eprintln!("host RPC reply failed: {output_error}");}code}
        };
    }
    if std::env::args_os().nth(1).is_some_and(|arg| arg == "--core-worker-internal") {
        return match respire_app::core_sdk::worker::run() {
            Ok(()) => 0,
            Err(error) => { eprintln!("Core worker stopped: {error:#}"); 1 }
        };
    }
    set_json_mode(std::env::args_os().any(|arg| arg == "--json")
        || respire::env::var("RSRS_JSON").is_ok_and(|value| value == "1" || value == "true"));
    if std::env::args_os().any(|arg| arg == "--client-only") {
        std::env::set_var("RSRS_CLIENT_ONLY", "1");
    }
    // Parse args, then run the command, so a Windows debug stack does not hold both at once.
    // The hidden runtime entry and `--direct` are peeled off before clap: the command enum is large enough that
    // extra derived fields overflow the debug main thread.
    let result = match preprocess_args() {
        Preparsed::Version { json } => {
            set_json_mode(json);
            prepare_command_runtime().and_then(|()| crate::app_version::emit(json))
        }
        Preparsed::RuntimeHelp { json } => {
            set_json_mode(json);
            emit_runtime_help()
        }
        Preparsed::Runtime { flags, json } => {
            set_json_mode(json);
            prepare_command_runtime().and_then(|()| rpc::runtime_entry(flags))
        }
        Preparsed::Invalid(error) => Err(respire_app::input_error::InputError(error).into()),
        Preparsed::Cli { direct, args } => {
            DIRECT_MODE.store(direct, Ordering::Relaxed);
            match Cli::try_parse_from(
                std::iter::once(std::ffi::OsString::from("rsrs")).chain(args),
            ) {
                Ok(cli) if matches!(cli.command, Some(Command::MemoryRevision | Command::Capabilities | Command::Runtime { .. })) => run(cli),
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
    if !runtime_policy::client_only() {
        respire::migration::ensure_default_home()
            .map_err(|error| anyhow!("default profile migration failed: {error:#}"))?;
    }
    Ok(())
}

enum Preparsed {
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
        emit_result(ResultEnvelope::new("runtime-help", OutputStatus::Ok,
            serde_json::json!({"usage":usage,"lifecycle":"host-managed","transport":"loopback-http"}), Vec::new()))
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
    if let Some(json) = is_short_v_version(&args) {
        return Preparsed::Version { json };
    }
    if args
        .iter()
        .find(|arg| arg.as_str() != "--json")
        .is_some_and(|arg| arg == "--runtime-internal")
    {
        if args.iter().any(|arg| matches!(arg.as_str(), "--help" | "-h"))
            && args.iter().all(|arg| matches!(arg.as_str(), "--runtime-internal" | "--help" | "-h" | "--json"))
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
            .or_else(respire::keystore::load_classify_backend)
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
    if let Some(Command::Runtime { command }) = args.command.as_ref() {
        return autostart::execute(command);
    }
    // Static CLI support is safe to inspect even on a fresh or inaccessible
    // profile. It makes no statement about account rights or model readiness.
    if matches!(args.command, Some(Command::Capabilities)) {
        return run_capabilities();
    }
    autostart::check_managed_request()?;
    let metadata_requested = match args.command.as_ref() {
        Some(Command::Remember { metadata, r#type, .. }) => metadata.patch().is_some()
            || r#type.as_deref().is_some_and(|kind| matches!(kind, "hypothesis" | "reflection" | "self")),
        Some(Command::Update { metadata, kind, .. }) => metadata.patch().is_some()
            || kind.as_deref().is_some_and(|kind| matches!(kind, "hypothesis" | "reflection" | "self")),
        _ => false,
    };
    if metadata_requested { respire_app::metadata_gate::require_support()?; }
    if DIRECT_MODE.load(Ordering::Relaxed) && matches!(args.command, Some(Command::Metadata { command: metadata::Command::Status })) {
        runtime_policy::require_host("direct metadata status")?;
        set_json_mode(args.json || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"));
        return run_metadata_status();
    }
    if let Some(Command::Metadata { command: command @ (metadata::Command::Enable { .. } | metadata::Command::Disable) }) = args.command.as_ref() {
        set_json_mode(args.json || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"));
        return run_metadata_host(command);
    }
    if let Some(Command::Snapshot {
        cmd: SnapshotCmd::Restore { id, confirm },
    }) = args.command.as_ref()
    {
        runtime_policy::require_host("snapshot restore")?;
        anyhow::ensure!(
            !rpc::worker_active(),
            "snapshot restore must run in the host CLI, not a runtime request"
        );
        anyhow::ensure!(
            *confirm,
            "snapshot restore requires --confirm; it replaces local state and quarantines sync"
        );
        respire::service::ensure_writable()?;
        anyhow::ensure!(
            !respire::service::off_mode(),
            "snapshot restore is unavailable while memory is paused"
        );
        let root = respire::service::data_dir();
        let account = respire::service::session_user_of_dir(&root);
        let keys = build_session()?;
        let receipt = std::cell::RefCell::new(None::<respire_app::snapshot::RestoreReceipt>);
        let cleanup_issue=std::cell::RefCell::new(None::<String>);
        rpc::change_profile_with_verification(
            || {
                let ownership =
                    respire::lock::LibraryLock::acquire(&root, std::time::Duration::from_secs(15))?;
                *receipt.borrow_mut() = Some(respire_app::snapshot::restore_locked(
                    &root, &account, &keys, id, &ownership,
                )?);
                Ok(())
            },
            || {
                if let Some(restored) = receipt.borrow().as_ref() {
                    let ownership = respire::lock::LibraryLock::acquire(
                        &root,
                        std::time::Duration::from_secs(15),
                    )?;
                    respire_app::snapshot::rollback_locked(&root,restored,&ownership)?;
                }
                Ok(())
            },
            || {
                let held=receipt.borrow();
                let receipt=held.as_ref().ok_or_else(||anyhow!("snapshot restore receipt missing"))?;
                rpc::verify_snapshot_store(&root,&receipt.restored)?;
                respire_app::snapshot::commit_restore(&root,receipt)?;
                // A durable commit is never rolled back for cleanup failure.
                // Both the release and any recovery remain under takeover.
                *cleanup_issue.borrow_mut()=respire_app::snapshot::release_restore(&root,receipt).err().map(|error|error.to_string());
                Ok(())
            },
        )?;
        let receipt=receipt.into_inner().ok_or_else(||anyhow!("snapshot restore receipt missing"))?;
        let cleanup=cleanup_issue.into_inner();
        let mut result = ResultEnvelope::new(
            "snapshot",
            if cleanup.is_some(){OutputStatus::Warn}else{OutputStatus::Ok},
            serde_json::json!({"action":"restored","sync_quarantined":true,"cloud_rollback":false,"runtime_verified":true,"service_released":respire_app::snapshot::ensure_no_incomplete_restore(&root).is_ok()}),
            Vec::new(),
        );
        result.details = serde_json::to_value(&receipt)?;
        if let Some(error)=cleanup {result.errors.push(format!("restored runtime verified; local rollback cleanup pending: {error}"));}
        return emit_result(result);
    }
    if let Some(Command::Snapshot { cmd: SnapshotCmd::Recover { confirm } }) = args.command.as_ref() {
        runtime_policy::require_host("snapshot recovery")?;
        anyhow::ensure!(!rpc::worker_active(),"snapshot recovery must run in the host CLI");
        anyhow::ensure!(*confirm,"snapshot recover requires --confirm");
        respire::service::ensure_writable()?;
        let root=respire::service::data_dir();let account=respire::service::session_user_of_dir(&root);
        autostart::with_explicit_recovery(|| rpc::change_profile_with_verification(|| {
            let ownership=respire::lock::LibraryLock::acquire(&root,std::time::Duration::from_secs(15))?;
            respire_app::snapshot::recover_locked(&root,&account,&ownership)
        },||Ok(()),||{
            if !respire::service::off_mode(){rpc::verify_open_store(&root)?;}
            Ok(())
        }))?;
        return emit_result(ResultEnvelope::new("snapshot",OutputStatus::Ok,serde_json::json!({"action":"recovered","runtime_verified":true}),Vec::new()));
    }
    respire_app::snapshot::ensure_no_incomplete_restore(&respire::service::data_dir())?;
    let _model_task = respire::model_progress::TaskScope::new(args.model_task_id.clone());
    set_json_mode(
        args.json || respire::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"),
    );
    if let Some(Command::Model { action }) = args.command.as_ref() {
        let request = match action {
            ModelAction::Catalog => Some(("model.catalog",Vec::new())),
            ModelAction::Configure { file } => {
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(file)?)?;
                Some(("model.configure",vec![serde_json::to_string(&value)?]))
            }
            ModelAction::Switch { model,backend,engine,variant } => Some(("model.switch",vec![serde_json::to_string(&serde_json::json!({"model":model,"backend":backend,"engine":engine,"variant":variant}))?])),
            ModelAction::Progress => Some(("model.progress",Vec::new())),
            ModelAction::Resume => Some(("model.resume",Vec::new())),
            _ => None,
        };
        if let Some((method,values)) = request {
            anyhow::ensure!(!DIRECT_MODE.load(Ordering::Relaxed),"model profiles require the resident runtime; omit --direct");
            let value = rpc::profile_request(method,values)?;
            return emit_result(serde_json::from_value(value)?);
        }
    }
    if matches!(args.command, Some(Command::MemoryRevision)) {
        if rpc::worker_active() {
            return run_memory_revision();
        }
        if DIRECT_MODE.load(Ordering::Relaxed) {
            runtime_policy::require_host("direct memory revision read")?;
            return run_memory_revision();
        }
        // No runtime creation, profile takeover, or retry of a failed request.
        return rpc::call_existing_from_argv();
    }
    // Host-only migration and repair dispatch must obey the memory gate too.
    if respire::service::off_mode() && matches!(args.command.as_ref(), Some(Command::Review { .. })) {
        set_exit_code(1);
        let mut result = ResultEnvelope::new("review", OutputStatus::Fail, serde_json::json!({"saved":false}), Vec::new());
        result.details = serde_json::json!({"code":"feature_disabled","saved":false});
        result.errors.push("memory service is off; due state is unavailable".to_owned());
        return emit_result(result);
    }
    if respire::service::off_mode() && args.command.as_ref().is_some_and(|command| !is_off_allowed(command)) {
        return run_local(args);
    }
    let display = !json_mode() && !rpc::worker_active() && args.command.is_some()
        && !matches!(args.command, Some(Command::Mcp | Command::Login { .. } | Command::V));
    let _progress = progress::Scope::start(args.progress_id.clone(), display,
        matches!(args.command, Some(Command::Sync | Command::Doctor { .. })));
    if let Some(Command::Space { action, code, name, .. }) = args.command.as_ref() {
        if action == "join" {
            let code = code.as_deref().or(name.as_deref())
                .ok_or_else(|| respire_app::input_error::InputError("join needs an invite code".into()))?;
            respire::space::validate_join(code)?;
        }
    }
    if !rpc::worker_active() && !runtime_policy::client_only()
        && !matches!(args.command, Some(Command::V))
        && respire_app::login_transaction::recovery_pending()
    {
        rpc::recover_interrupted_login()?;
    }
    if let Some(Command::Migrate { source, account, vault, addr, user, pass, super_pass, secret_key, new_super }) = args.command.as_ref() {
        if *vault || source.is_some() { respire::service::ensure_writable()?; }
        runtime_policy::require_host("explicit legacy migration")?;
        if *vault {
            return login::migrate_vault(addr.as_deref(), user.as_deref(), pass.as_deref(), super_pass.as_deref(), secret_key.as_deref(), new_super.as_deref());
        }
        let value = match (source.as_deref(), account.as_deref()) {
            (Some(source), Some(account)) => respire::migration::migrate_profile(source, account)?,
            (None, None) => respire::migration::list_legacy_profiles()?,
            _ => anyhow::bail!("migration requires both --source and --account"),
        };
        let mut envelope = ResultEnvelope::new("migrate", OutputStatus::Ok, value.clone(), Vec::new());
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
        if rpc::worker_active() && *key_stdin {
            anyhow::bail!("--key-stdin must run in the host CLI, not through runtime RPC");
        }
        return run_classify_config(
            backend.as_deref(),
            api_base.as_deref(),
            model.as_deref(),
            *set,
            *key_stdin,
        );
    }
    if let Some(Command::Login { addr, user, pass, super_pass, interactive, oauth, dashboard, no_open, migrate_local }) = args.command.as_ref() {
        return login::run(addr.as_deref(), user.as_deref(), pass.as_deref(), super_pass.as_deref(), *interactive, *oauth, dashboard.as_deref(), *no_open, *migrate_local);
    }
    if rpc::worker_active() {
        return run_local(args);
    }
    if let Some(Command::Restart { timeout }) = args.command.as_ref() {
        let result = rpc::restart_runtime(std::time::Duration::from_secs(*timeout))?;
        return emit_result(ResultEnvelope::new("restart", OutputStatus::Ok, result, Vec::new()));
    }
    if matches!(args.command, Some(Command::Model { action: ModelAction::InstallEngines })) {
        runtime_policy::require_host("inference engine installation")?;
        progress::phase("\u{5b89}\u{88c5}\u{63a8}\u{7406}\u{5f15}\u{64ce}\u{ff1b}\u{7b49}\u{5f85} Windows ML", "Installing inference providers; waiting for Windows ML");
        let mut providers = Vec::new();
        rpc::change_profile(|| { providers = respire::model_install::install_engines()?; Ok(()) })?;
        return emit_result(ResultEnvelope::new("model", OutputStatus::Ok,
            serde_json::json!({"providers":providers}), Vec::new()));
    }
    if matches!(
        args.command,
        Some(Command::Model {
            action: ModelAction::ResetCpu
        })
    ) {
        runtime_policy::require_host("CPU recovery and runtime shutdown")?;
        anyhow::ensure!(respire_app::embedding::saved_selection()?.is_none(),"library uses a model profile; use model switch PROFILE --backend onnx --engine cpu for CPU recovery");
        if autostart::managed_enabled()? {
            rpc::change_profile(respire::memory::onnx::reset_cpu_config)?;
            return emit_result(ResultEnvelope::new("model", OutputStatus::Ok,
                serde_json::json!({"engine":"cpu","force_cpu":true,"runtime_restarted":true}),Vec::new()));
        }
        let _takeover = runtime_policy::takeover_lock()?;
        respire::memory::onnx::reset_cpu_config()?;
        let stopped_pid = rpc::force_stop_for_reset()?;
        return emit_result(ResultEnvelope::new(
            "model",
            OutputStatus::Ok,
            serde_json::json!({"engine":"cpu", "force_cpu":true, "stopped_pid":stopped_pid}),
            vec![],
        ));
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
    let host_auth_change = HOST_RPC_OUTPUT.get() && matches!(args.command.as_ref(),
        Some(Command::Register { .. } | Command::Fivekeys { .. } | Command::SuperReset { .. }));
    if !DIRECT_MODE.load(Ordering::Relaxed) && (changes_profile(args.command.as_ref()) || host_auth_change) {
        runtime_policy::require_host("profile switching")?;
        CAPTURED.with(|slot| *slot.borrow_mut() = None);
        DEFER_PROFILE_OUTPUT.set(true);
        let switched = rpc::change_profile(|| {
            run_local(args)?;
            if CAPTURED.with(|slot| slot.borrow().as_ref().is_some_and(|value| matches!(value.status, OutputStatus::Fail))) {
                let errors = CAPTURED.with(|slot| slot.borrow().as_ref().map(|value| value.errors.join("; ")));
                anyhow::bail!("{}", errors.unwrap_or_else(|| "profile change failed".to_owned()));
            }
            Ok(())
        });
        DEFER_PROFILE_OUTPUT.set(false);
        OUTPUT_EMITTED.set(false);
        OUTPUT_EXIT_CODE.set(0);
        let result = CAPTURED.with(|slot| slot.borrow_mut().take());
        switched?;
        return emit_result(result.ok_or_else(|| anyhow!("profile command returned no result"))?);
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

    fn seed_capture_session() -> anyhow::Result<()> {
        // Fixed fixture material only; never use this session or key in production.
        const TEST_SUPER: &str = "A3-000000-000000-000000-000000-000000-000000";
        std::env::set_var("RSRS_SUPER", TEST_SUPER);
        let salt = "01".repeat(16);
        let kek = respire::memory::crypto::derive_rsrs_kek(TEST_SUPER, &salt)?;
        let (nonce, wrapped) = respire::memory::crypto::wrap_key(&[7; 32], &kek)?;
        respire::auth::write_session_json(&serde_json::json!({
            "user":"test", "vault_version":4, "kdf_salt":salt,
            "wrapped_urk":format!("{}{wrapped}", respire::memory::crypto::RSRS_PREFIX),
            "urk_nonce":nonce, "pass":"synthetic-capture-unused"
        }))?;
        Ok(())
    }

    pub(crate) fn with_isolated_session<T>(
        f: impl FnOnce(&std::path::Path) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        struct Restore {
            values: Vec<(&'static str, Option<std::ffi::OsString>)>,
            worker: bool,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.values {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
                crate::rpc::set_worker_active(self.worker);
            }
        }
        let _restore = Restore {
            values: ["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_M3_DIR", "RSRS_SUPER",
                "RSRS_NO_AUTOSYNC", "RSRS_RPC_PORT", "RSRS_CORE_TEST_MODE"]
                .into_iter().map(|key| (key, std::env::var_os(key))).collect(),
            worker: crate::rpc::worker_active(),
        };
        let _guard = EnvGuard {
            prev: respire::env::var("RSRS_DATA_DIR").ok(),
            prev_super: std::env::var_os("RSRS_SUPER"),
        };
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
        std::env::set_var("RSRS_M3_DIR", dir.path().join("absent-model"));
        std::env::set_var("RSRS_NO_AUTOSYNC", "1");
        std::env::set_var("RSRS_RPC_PORT", "29873");
        std::env::set_var("RSRS_CORE_TEST_MODE", "1");
        crate::rpc::set_worker_active(true);
        seed_capture_session()?;
        let result = f(dir.path());
        respire::resident::clear()?;
        result
    }

    mod metadata_coverage;
    mod brief_coverage;
    mod review_coverage;

    #[test]
    fn injected_chain_examples_follow_the_parser_contract() -> anyhow::Result<()> {
        for policy in [respire::inject::INSTRUCTIONS_MD, respire::inject::INSTRUCTIONS_LITE_MD] {
            let mut checked = 0;
            for example in policy.split('`').skip(1).step_by(2)
                .filter(|example| example.starts_with("rsrs chain ") && !example.contains('[')) {
                let parsed = super::Cli::try_parse_from(example.split_whitespace())?;
                assert!(matches!(parsed.command, Some(super::Command::Chain { depth: 1..=3, .. })));
                checked += 1;
            }
            assert!(checked > 0, "policy must retain an executable causal-chain example");
        }
        assert!(super::Cli::try_parse_from(["rsrs", "chain", "synthetic-id", "--depth", "1-3", "--json"]).is_err());
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
        assert!(matches!(revision.command, Some(super::Command::MemoryRevision)));
        assert!(!super::is_write_command(&super::Command::MemoryRevision));
        assert!(!super::is_write_command(&super::Command::Taxonomy {list:true,ensure:None}));
        assert!(super::is_write_command(&super::Command::Taxonomy {list:false,ensure:None}));
        assert!(super::is_write_command(&super::Command::Taxonomy {list:true,ensure:Some("synthetic".into())}));
        assert!(!super::is_write_command_fine(&super::Command::MemoryRevision));
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
        let input: anyhow::Error = respire_app::input_error::InputError("no such entry: fixture".into()).into();
        let (envelope, code) = super::command_failure(&input.context("resort validation"));
        assert_eq!(code, 2);
        assert_eq!(envelope.summary["reason"], "invalid_input");
        assert_eq!(envelope.details["error_type"], "user");
        let runtime: anyhow::Error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "owned fixture I/O failure").into();
        let (envelope, code) = super::command_failure(&runtime);
        assert_eq!(code, 1);
        assert_eq!(envelope.summary["reason"], "runtime_error");
        assert_eq!(envelope.details["error_type"], "runtime");
        let parsed = capture_run(vec!["--json".into(), "--not-a-command".into()]);
        assert_eq!(parsed.exit, 2);
        assert_eq!(parsed.envelope.summary["reason"], "invalid_input");
        assert_eq!(parsed.envelope.details["error_type"], "user");
    }

    struct EnvGuard {
        prev: Option<String>,
        prev_super: Option<std::ffi::OsString>,
    }

    #[test]
    fn residual_input_errors_use_user_envelopes() -> anyhow::Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let _guard = EnvGuard {
            prev: respire::env::var("RSRS_DATA_DIR").ok(),
            prev_super: std::env::var_os("RSRS_SUPER"),
        };
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        crate::rpc::set_worker_active(true);
        seed_capture_session()?;
        let missing = dir.path().join("missing.json").to_string_lossy().into_owned();
        let missing_output = dir.path().join("absent").join("export.json").to_string_lossy().into_owned();
        for command in [
            vec!["restore", "deadbeef"],
            vec!["grant", "create", "--root", "deadbeef", "--label", "probe"],
            vec!["grant", "create", "--root", "00000000-0000-0000-0000-000000000000", "--label", "probe"],
            vec!["space", "kick"],
            vec!["import", &missing],
            vec!["bench", "run", &missing],
            vec!["share-import", &missing],
            vec!["export", &missing_output],
            vec!["backup", &missing_output],
            vec!["agent-config", "--set", "workspace_mode=bogus"],
        ] {
            let mut args = vec!["--json".to_owned()];
            args.extend(command.iter().map(|arg| (*arg).to_owned()));
            let result = capture_run(args);
            assert_eq!(result.exit, 2, "{command:?}: {:?}", result.envelope);
            assert_eq!(result.envelope.summary["reason"], "invalid_input", "{command:?}");
            assert_eq!(result.envelope.details["error_type"], "user", "{command:?}");
            if matches!(command[0], "import" | "bench" | "share-import") {
                assert!(result.envelope.errors.iter().any(|error| error.contains("failed to read")), "{command:?}: {:?}", result.envelope.errors);
            }
        }
        let invalid = dir.path().join("invalid-utf8.json");
        std::fs::write(&invalid, [0xff])?;
        let error = respire_app::input_error::read_file(&invalid, "fixture").err()
            .ok_or_else(|| anyhow::anyhow!("invalid UTF-8 was accepted"))?;
        assert_eq!(super::command_failure(&error).1, 1);
        let existing = dir.path().join("existing-backup.db");
        std::fs::write(&existing, b"preserve existing backup")?;
        let error = respire::service::backup_db(&existing).err()
            .ok_or_else(|| anyhow::anyhow!("existing backup was overwritten"))?;
        assert_eq!(super::command_failure(&error).1, 1);
        assert_eq!(std::fs::read(&existing)?, b"preserve existing backup");
        assert!(!dir.path().join("absent").exists());
        Ok(())
    }

    #[test]
    fn bench_runs_on_pending_resident_snapshot_without_writing_index() -> anyhow::Result<()> {
        use respire::MemoryTransport;
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let _guard = EnvGuard {
            prev: respire::env::var("RSRS_DATA_DIR").ok(),
            prev_super: std::env::var_os("RSRS_SUPER"),
        };
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        crate::rpc::set_worker_active(true);
        seed_capture_session()?;
        let keys = super::build_session()?;
        let store = super::build_local()?;
        let entry: respire::MemoryEntry = serde_json::from_value(serde_json::json!({
            "id":"pending-bench","kind":"Context","tags":[],"title":"benchmark pending needle",
            "content":"benchmark pending needle","user":"test","computer":"test","project":"",
            "created_at":"2026-10-10T00:00:00Z","updated_at":"2026-10-10T00:00:00Z",
            "emotion":0,"parent_id":"","importance":"important"
        }))?;
        let stored = {
            let _defer = respire::core_sdk::defer_indexing();
            respire::MemoryEngine::seal(&keys, &respire::core_sdk::search::HashingEmbedder::new(1024), &entry, "test")?
        };
        store.put_checked(&stored, None)?;
        let eval = dir.path().join("eval.jsonl");
        let output = dir.path().join("bench.json");
        std::fs::write(&eval, r#"{"query":"benchmark pending needle","expect":["pending-bench"]}"#)?;
        let captured = capture_run(vec!["--json".into(), "bench".into(), "run".into(),
            eval.to_string_lossy().into_owned(), "--save".into(), output.to_string_lossy().into_owned()]);
        assert_eq!(captured.exit, 0, "{:?}", captured.envelope);
        let report: super::bench::BenchReport = serde_json::from_slice(&std::fs::read(output)?)?;
        assert_eq!(report.params.get("index_pending").map(String::as_str), Some("1"));
        assert_eq!(report.metrics.hit1, 1.0);
        assert_eq!(report.n_entries, 1);
        let current = store.all(false)?;
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].ciphertext, stored.ciphertext);
        assert!(current[0].local_artifact.is_empty());
        respire::resident::clear()?;
        Ok(())
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            crate::rpc::set_worker_active(false);
            match &self.prev {
                Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
                None => std::env::remove_var("RSRS_DATA_DIR"),
            }
            match &self.prev_super {
                Some(value) => std::env::set_var("RSRS_SUPER", value),
                None => std::env::remove_var("RSRS_SUPER"),
            }
        }
    }

    #[test]
    fn memory_revision_capture_preserves_identity_across_status_reads() -> anyhow::Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir()?;
        let _guard = EnvGuard {
            prev: std::env::var("RSRS_DATA_DIR").ok(),
            prev_super: std::env::var_os("RSRS_SUPER"),
        };
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let _store = respire::service::open_store()?;
        crate::rpc::set_worker_active(true);
        let before = capture_run(vec!["memory-revision".into(), "--json".into()]);
        assert_eq!(before.exit, 0);
        assert_eq!(before.envelope.command, "memory-revision");
        assert_eq!(before.envelope.summary["profile"], dir.path().to_string_lossy().as_ref());
        let status = capture_run(vec!["status".into(), "--json".into()]);
        assert_eq!(status.exit, 0);
        assert_eq!(status.envelope.summary["data_dir"], before.envelope.summary["profile"]);
        let after = capture_run(vec!["memory-revision".into(), "--json".into()]);
        assert_eq!(after.exit, 0);
        assert_eq!(after.envelope.summary, before.envelope.summary);
        assert!(!dir.path().join("session.json").exists());
        assert!(!dir.path().join("model").exists());
        Ok(())
    }

    #[test]
    fn doctor_json_keeps_command_envelope() -> Result<(), String> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let guard = EnvGuard {
            prev: respire::env::var("RSRS_DATA_DIR").ok(),
            prev_super: std::env::var_os("RSRS_SUPER"),
        };
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let prev_bin = respire::env::var("RSRS_BIN_DIR").ok();
        std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
        respire::service::set_server_addr("https://example.invalid")
            .map_err(|err| err.to_string())?;
        crate::rpc::set_worker_active(true);
        for args in [
            vec!["--json".to_owned(), "doctor".to_owned()],
            vec![
                "--json".to_owned(),
                "doctor".to_owned(),
                "--remote".to_owned(),
            ],
        ] {
            let captured = capture_run(args);
            if captured.envelope.command != "doctor" {
                return Err(format!(
                    "doctor JSON was captured as command {}",
                    captured.envelope.command
                ));
            }
            let total = captured
                .envelope
                .summary
                .get("total")
                .and_then(|value| value.as_u64())
                .ok_or("doctor summary is missing total")?;
            if total == 0 || captured.envelope.items.is_empty() {
                return Err("doctor envelope has no checks".to_owned());
            }
            if captured.envelope.summary["runtime_version"] != crate::app_version::embedded() {
                return Err("doctor did not report the executing runtime version".to_owned());
            }
            let runtime = captured.envelope.items.iter()
                .find(|item| item.name == "Runtime version")
                .ok_or("doctor did not include the runtime version check")?;
            if runtime.value != crate::app_version::embedded() || !matches!(runtime.status, crate::OutputStatus::Ok) {
                return Err("doctor runtime version check differs from the executing binary".to_owned());
            }
            let want = match captured.envelope.status {
                crate::OutputStatus::Ok | crate::OutputStatus::Skip => 0,
                crate::OutputStatus::Warn | crate::OutputStatus::Pending => 2,
                crate::OutputStatus::Fail => 1,
            };
            if captured.exit != want {
                return Err(format!(
                    "doctor exit {} does not match status {want}",
                    captured.exit
                ));
            }
        }
        // A live background task must not make --fix launch a second installer.
        let operation = respire::model_progress::Operation::begin("download")
            .map_err(|err| err.to_string())?;
        for fix in [false, true] {
            let mut args = vec!["--json".to_owned(), "doctor".to_owned()];
            if fix {
                args.push("--fix".to_owned());
            }
            let captured = capture_run(args);
            let embedder = captured.envelope.items.iter()
                .find(|item| item.name == "embedder")
                .ok_or("doctor did not report the embedder")?;
            if !matches!(embedder.status, crate::OutputStatus::Warn) {
                return Err("active model preparation must be WARN, not FAIL or PASS".to_owned());
            }
            if respire::model_progress::status().map_err(|err| err.to_string())?["phase"] != "download" {
                return Err("doctor replaced the active model task".to_owned());
            }
        }
        drop(operation);
        drop(guard);
        match prev_bin {
            Some(value) => std::env::set_var("RSRS_BIN_DIR", value),
            None => std::env::remove_var("RSRS_BIN_DIR"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod diary_identity_tests {
    use super::*;

    /// Construct selection-only metadata without opening a vault.
    fn track(id: &str, user: &str, title: &str, created: &str) -> respire::StoredMemory {
        let mut memory = respire::StoredMemory::new_pending(id.into(), user.into());
        memory.local_title = title.into();
        memory.local_created_at = created.into();
        memory
    }

    /// Stable identity wins over older same-title legacy rows.
    #[test]
    fn stable_id_precedes_legacy_titles_and_preserves_importance_compatibility() -> Result<()> {
        let mut legacy = track("legacy", "alice", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", "2026-10-13T00:00:00Z");
        legacy.local_importance = "normal".into();
        let canonical = track("stable", "server-routing-owner", "User's renamed day", "2026-10-13T01:00:00Z");
        let rows = vec![legacy, canonical];
        let tracks = select_diary_tracks(&rows, "stable", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", |row| Ok(row.id == "stable" || row.user == "alice"))?;
        assert_eq!(tracks.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(), ["stable", "legacy"]);
        Ok(())
    }

    /// An unrelated canonical payload must fail before legacy candidates can be merged.
    #[test]
    fn canonical_author_mismatch_is_not_a_legacy_fallback() -> Result<()> {
        let rows = vec![track("stable", "wire-owner", "renamed", "1"),
            track("legacy", "alice", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", "0")];
        let result = select_diary_tracks(&rows, "stable", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", |row| Ok(row.id != "stable"));
        assert!(result.is_err());
        Ok(())
    }

    /// Blank titles remain valid while deleted and unrelated tracks stay separate.
    #[test]
    fn blank_title_deleted_rows_other_users_and_days_are_handled_separately() -> Result<()> {
        let mut deleted = track("deleted", "alice", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", "0");
        deleted.deleted = true;
        let rows = vec![
            track("stable", "alice", "", "1"),
            deleted,
            track("other-user", "bob", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", "0"),
            track("other-day", "alice", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-12", "0"),
        ];
        let tracks = select_diary_tracks(&rows, "stable", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", |row| Ok(row.user == "alice"))?;
        assert_eq!(tracks.len(), 1);
        assert_eq!(tracks[0].id, "stable");
        assert!(select_diary_tracks(&rows, "charlie-stable", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-14", |row| Ok(row.user == "charlie"))?.is_empty());
        Ok(())
    }

    /// Live legacy tracks retain their deterministic earliest-created ordering.
    #[test]
    fn missing_or_deleted_stable_id_keeps_earliest_legacy_track() -> Result<()> {
        let mut deleted = track("stable", "alice", "renamed", "0");
        deleted.deleted = true;
        let rows = vec![
            track("later", "alice", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", "2"),
            track("earlier", "alice", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", "1"),
            deleted,
        ];
        let tracks = select_diary_tracks(&rows, "stable", "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13", |row| Ok(row.user == "alice"))?;
        assert_eq!(tracks.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(), ["earlier", "later"]);
        Ok(())
    }
}

#[cfg(test)]
mod sync_retry_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anyhow::anyhow;

    use super::run_sync_attempts;

    #[test]
    fn retries_transport_timeout_then_succeeds() -> anyhow::Result<()> {
        let hits = AtomicUsize::new(0);
        let value = run_sync_attempts(|| {
            let n = hits.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Err(anyhow!("connection timed out"))
            } else {
                Ok(7)
            }
        })?;
        assert_eq!(value, 7);
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[test]
    fn protocol_error_does_not_retry() {
        let hits = AtomicUsize::new(0);
        let err = run_sync_attempts(|| {
            hits.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow!("server sync epoch changed; local edits kept"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("epoch"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn worker_schedules_autosync_without_waiting_on_the_remote() -> anyhow::Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let prev_dir = respire::env::var("RSRS_DATA_DIR").ok();
        let prev_off = respire::env::var("RSRS_NO_AUTOSYNC").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::remove_var("RSRS_NO_AUTOSYNC");
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(sock) = conn else { break };
                std::thread::sleep(std::time::Duration::from_secs(60));
                drop(sock);
            }
        });
        std::fs::write(
            dir.path().join("session.json"),
            format!(r#"{{"addr":"http://127.0.0.1:{port}","token":"hang"}}"#),
        )?;
        // This scheduling fixture owns its temporary store, not the in-process runtime's boot profile.
        let store = respire::transport::local::LocalStore::open(&dir.path().join("onememory.db"))?;
        let keys = respire::SessionKeys::from_urk([9u8; 32])?;
        crate::rpc::set_worker_active(true);
        let started = std::time::Instant::now();
        super::schedule_autosync(&keys, &store);
        let elapsed = started.elapsed();
        crate::rpc::set_worker_active(false);
        match prev_dir {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        match prev_off {
            Some(value) => std::env::set_var("RSRS_NO_AUTOSYNC", value),
            None => std::env::remove_var("RSRS_NO_AUTOSYNC"),
        }
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "autosync blocked the worker for {elapsed:?}"
        );
        Ok(())
    }
}

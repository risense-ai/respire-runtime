//! Command engine assembly: library/store/session construction shared by the
//! engine arms and the runtime worker threads.
//!
//! The command arms themselves (`run_local`) and the per-command functions
//! migrate here from the CLI binary in later steps of the runtime split.

use std::sync::Arc;

use anyhow::{anyhow, Result};

use respire_app::auth;
use respire_app::env;
use respire_app::service;
use respire_app::transport::local::LocalStore;
use respire_app::transport::remote::{RemoteConfig, RemoteTransport};
use respire_app::{MemoryTransport, SessionKeys};


/// Assemble transport: RSRS_ADDR (or session.json addr) -> remote backup store; else local store.
pub fn build_transport() -> Result<Arc<dyn MemoryTransport>> {
    if let Some((addr, token)) = remote_config_from_session_or_env()? {
        return Ok(Arc::new(RemoteTransport::new(RemoteConfig {
            address: addr,
            token,
        })));
    }
    Ok(Arc::new(respire_app::service::open_store()?))
}

pub fn build_local() -> Result<LocalStore> {
    respire_app::service::open_store()
}

/// Remote config: session.json first (addr/token written by client login), then env vars.
pub fn remote_config_from_session_or_env() -> Result<Option<(String, String)>> {
    // 1) session.json
    if let Ok(data) = read_session_json() {
        if let (Some(addr), Some(token)) = (
            data["addr"].as_str().filter(|s| !s.is_empty()),
            data["token"].as_str().filter(|s| !s.is_empty()),
        ) {
            return Ok(Some((addr.to_owned(), token.to_owned())));
        }
    }
    // 2) env vars
    if let Ok(addr) = respire_app::env::var("RSRS_ADDR") {
        if !addr.trim().is_empty() {
            let token = respire_app::env::var("RSRS_TOKEN")
                .map_err(|_| anyhow!("remote mode needs RSRS_TOKEN"))?;
            return Ok(Some((addr, token)));
        }
    }
    Ok(None)
}

pub fn build_remote() -> Result<RemoteTransport> {
    let (addr, token) = remote_config_from_session_or_env()?
        .ok_or_else(|| anyhow!("remote store is not configured - have the client/account tool write session.json (addr/token), or set RSRS_ADDR and RSRS_TOKEN"))?;
    Ok(RemoteTransport::new(RemoteConfig {
        address: addr,
        token,
    }))
}

/// Unlock session keys: local keyfile first (from keygen/register), else env vars.
pub fn build_session() -> Result<SessionKeys> {
    build_session_with_owner().map(|(keys, _)| keys)
}

/// Preserve only the owner alias from the local snapshot that supplied these keys.
/// Environment-key fallback must never inherit identity from an unrelated profile.
pub fn build_session_with_owner() -> Result<(SessionKeys, Option<String>)> {
    let result = build_session_with_owner_inner();
    crate::host_hooks::note_credential_access(result.is_ok());
    result
}

pub fn build_session_with_owner_inner() -> Result<(SessionKeys, Option<String>)> {
    if let Ok(session) = auth::load_local_session_with_owner() {
        return Ok(session);
    }
    if read_session_json().is_err() {
        // no local session -> first-run guide
        anyhow::bail!(
            "no local session: rsrs keygen --pass <password> to start fully local (no cloud); \
             or rsrs register / login for a cloud identity; or set the five-keys env vars \
             (RSRS_PASS/SECRET/KDF_SALT/WRAPPED_URK/URK_NONCE)"
        );
    }
    let password = respire_app::env::var("RSRS_PASS")
        .map_err(|_| anyhow!("need RSRS_PASS (master password)"))?;
    let secret = respire_app::env::var("RSRS_SECRET")
        .map_err(|_| anyhow!("need RSRS_SECRET (recovery key)"))?;
    let kdf_salt = respire_app::env::var("RSRS_KDF_SALT")
        .map_err(|_| anyhow!("need RSRS_KDF_SALT (from keygen/register)"))?;
    let wrapped_urk = respire_app::env::var("RSRS_WRAPPED_URK")
        .map_err(|_| anyhow!("need RSRS_WRAPPED_URK (from keygen/login)"))?;
    let urk_nonce = respire_app::env::var("RSRS_URK_NONCE")
        .map_err(|_| anyhow!("need RSRS_URK_NONCE (from keygen/login)"))?;
    Ok((SessionKeys::unlock(&password, &secret, &kdf_salt, &wrapped_urk, &urk_nonce)?, None))
}

pub fn read_session_json() -> Result<serde_json::Value> {
    auth::read_session_json()
}

// ---- Command engine migrated from the CLI binary (runtime split WP-2b) ----
// Helpers, per-command functions, run_local/run_local_inner and the embedder
// cache, verbatim from their extraction source apart from rebinding `respire::`
// app-core paths, CLI-host services through `host_hooks`, and the host-command
// router that stays in the CLI binary.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::Context;
use uuid::Uuid;

use respire_app::memory::bge::BgeEmbedder;
use respire_app::memory::model::Kind;
use respire_app::memory::search::Embedder;
use respire_app::memory::{MemoryEngine, MemoryQuery, StoredMemory};
use respire_app::sync::remote_configured;

use crate::bench;
use crate::classify;
use crate::cli_def::{
    BenchCmd, Cli, Command, GrantCommand, ModelAction, QueryLogCmd, SessionCommand, SnapshotCmd,
};
use crate::gates::{is_off_allowed, is_readonly_switch_off, is_write_command, is_write_command_fine};
use crate::metadata;
use crate::output::{self, Item as OutputItem, ResultEnvelope, Status as OutputStatus};
use crate::output_emit::{command_failure, emit_details, emit_result};
use crate::output_state::{
    json_mode, progress_enabled, set_exit_code, set_json_mode, status_exit_code, CAPTURED,
    DEFER_PROFILE_OUTPUT, HOST_RPC_OUTPUT,
};
use crate::progress;
use crate::recall_select;
use crate::review;
use crate::rpc_worker as rpc;
use crate::runtime_policy;
use crate::skill;
use crate::sync_flow::{
    read_remote_sync_history, run_sync_attempts, sync_live, sync_phase, sync_tracked,
    sync_tracked_boundary, sync_with_retry,
};
use crate::util::{current_user, dev_label, list_since_bound, local_day_of, now_stamp, short_id};

pub static DIRECT_MODE: AtomicBool = AtomicBool::new(false);

pub static EMBEDDER_SLOT: std::sync::Mutex<Option<Box<BgeEmbedder>>> = std::sync::Mutex::new(None);

pub struct EmbedderHold(Option<Box<BgeEmbedder>>);

impl Drop for EmbedderHold {
    fn drop(&mut self) {
        if let Ok(mut slot) = EMBEDDER_SLOT.lock() {
            *slot = self.0.take();
        }
    }
}

pub fn scoped_candidates(store: &LocalStore) -> Result<Vec<respire_app::StoredMemory>> {
    let candidates = store.all(false)?;
    respire_app::service::require_candidates_ready(store, &candidates)?;
    Ok(candidates)
}

pub fn candidates_preview(store: &LocalStore) -> Result<Vec<respire_app::StoredMemory>> {
    scoped_candidates(store)
}

pub fn candidates_count_primary(all: &[respire_app::StoredMemory]) -> usize {
    all.iter()
        .filter(|m| m.local_importance == "important")
        .count()
}

pub fn candidates_count_normal(all: &[respire_app::StoredMemory]) -> usize {
    all.iter()
        .filter(|m| m.local_importance == "normal")
        .count()
}

/// Memory-tree outline (--outline): full depth, id+title indent tree, no bodies - the AI tidy's input surface.
pub fn collect_outline(nodes: &[respire_app::service::TreeNode], indent: usize, out: &mut Vec<String>) {
    for n in nodes {
        out.push(format!(
            "{}[{}] {}",
            "  ".repeat(indent),
            respire_app::service::short_id(&n.id),
            n.title
        ));
        collect_outline(&n.children, indent + 1, out);
    }
}

/// Same, but structured rows (for `--json`) - keep depth, id, title for programs.
pub fn collect_outline_json(
    nodes: &[respire_app::service::TreeNode],
    depth: usize,
    out: &mut Vec<serde_json::Value>,
) {
    for n in nodes {
        out.push(serde_json::json!({
            "depth": depth,
            "id": n.id,
            "short_id": respire_app::service::short_id(&n.id),
            "title": n.title,
        }));
        collect_outline_json(&n.children, depth + 1, out);
    }
}

/// Memory tidy (resort): one process batch-reparents - dry-run validates every op (parse/cycle/self-parent); --go writes and syncs once.
/// A successful write bumps the counter +1; at the threshold an alert is returned (§3.8 auto-trigger - the AI sees TIDY and runs three tidy rounds).
/// AI behavior config (agent.json): --set key=value writes a key; no args prints the whole file for the AI to read.

pub fn run_agent_config(set: Option<&str>) -> Result<()> {
    if let Some(kv) = set {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("format must be key=value (e.g. diary_mode=verbose)"))?;
        let val =
            serde_json::from_str::<serde_json::Value>(v).unwrap_or_else(|_| serde_json::json!(v));
        respire_app::service::write_agent_config_key(k, &val)?;
        let mut info = serde_json::json!({"action":"updated", "key":k, "value":val});
        if k.trim() == "read_heat" {
            info["read_heat_runtime"] = respire_app::read_heat::receipt()?;
        }
        return emit_result(ResultEnvelope::new(
            "agent-config",
            OutputStatus::Ok,
            info,
            vec![OutputItem::new(k, OutputStatus::Ok, v)],
        ));
    }
    let mut config = respire_app::service::read_agent_config();
    let object = config
        .as_object_mut()
        .ok_or_else(|| anyhow!("agent config must be an object"))?;
    object.insert("readonly".into(), serde_json::json!(respire_app::service::readonly_mode()));
    object.insert("memory_off".into(), serde_json::json!(respire_app::service::off_mode()));
    object.insert("workspace_mode".into(), serde_json::json!(respire_app::service::workspace_mode()));
    object.insert("read_heat_runtime".into(), respire_app::read_heat::receipt()?);
    object.insert("recall_fusion_runtime".into(), respire_app::recall_fusion::receipt()?);
    let rows = object
        .iter()
        .map(|(key, value)| OutputItem::new(key, OutputStatus::Ok, value.to_string()))
        .collect();
    emit_result(ResultEnvelope::new(
        "agent-config",
        OutputStatus::Ok,
        config,
        rows,
    ))
}

pub fn note_write_maintenance() -> Option<String> {
    // The tidy cycle is also when we check for a new CLI (2026-09-20): **only when TIDY fires**
    // we query npm - so every write does not hit the network (24h throttle, silent offline; see update_check).
    match respire_app::service::counter_bump(&respire_app::service::maintenance_path()) {
        Ok((n, t)) if n >= t => {
            let mut notes = vec![format!(
                "TIDY {n} new entries since last tidy (>= threshold {t}) - AI should judge whether to run the \u{a7}3.8 three-round tidy now (a successful resort --go resets the counter)"
            )];
            if let Some(h) = crate::host_hooks::update_hint(false) {
                notes.push(h);
            }
            Some(notes.join("\n"))
        }
        Ok(_) => None,
        Err(e) => {
            eprintln!("WARN maintenance counter failed: {e}");
            None
        }
    }
}

pub fn run_resort(
    go: bool,
    spec: Option<&str>,
    status: bool,
    reset: bool,
    threshold: Option<u64>,
) -> Result<()> {
    let mpath = respire_app::service::maintenance_path();
    if status {
        let (n, t) = respire_app::service::counter_peek(&mpath);
        let state = if n >= t {
            OutputStatus::Warn
        } else {
            OutputStatus::Ok
        };
        let mut result = ResultEnvelope::new(
            "resort",
            state,
            serde_json::json!({"count":n,"threshold":t}),
            vec![OutputItem::new("tidy counter", state, format!("{n}/{t}"))],
        );
        if n >= t {
            result.actions.push("resort --spec <json> --go".into());
        }
        return emit_result(result);
    }
    if reset {
        respire_app::service::counter_reset(&mpath, &now_stamp())?;
        return emit_result(ResultEnvelope::new(
            "resort",
            OutputStatus::Ok,
            serde_json::json!({"counter":"reset"}),
            vec![OutputItem::new("tidy counter", OutputStatus::Ok, "reset")],
        ));
    }
    if let Some(t) = threshold {
        respire_app::service::counter_set_threshold(&mpath, t)?;
        if spec.is_none() {
            return emit_result(ResultEnvelope::new(
                "resort",
                OutputStatus::Ok,
                serde_json::json!({"threshold":t}),
                vec![OutputItem::new(
                    "threshold",
                    OutputStatus::Ok,
                    t.to_string(),
                )],
            ));
        }
    }
    let spec = spec.ok_or_else(|| respire_app::input_error::InputError("need --spec (or --status to inspect the counter / --reset to zero it / --threshold to set it)".into()))?;
    let session = build_session()?;
    let store = build_local()?;
    let v: serde_json::Value = serde_json::from_str(spec).map_err(|e| {
        respire_app::input_error::InputError(format!("spec JSON failed to parse: {e} (shape {{\"ops\":[{{\"id\":\"child\",\"parent\":\"parent\"}}]}})"))
    })?;
    let ops = v["ops"].as_array().cloned().unwrap_or_default();
    if ops.is_empty() {
        return Err(respire_app::input_error::InputError("spec has no ops (shape {\"ops\":[{\"id\":...,\"parent\":...}]})".into()).into());
    }
    let all = store.all(true)?;
    let mut moved = 0usize;
    let mut rows = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let (Some(cid), Some(pid)) = (op["id"].as_str(), op["parent"].as_str()) else {
            return Err(respire_app::input_error::InputError(format!("op#{i} missing id/parent string")).into());
        };
        let child = respire_app::service::resolve_prefix(&all, cid)?;
        let parent = respire_app::service::resolve_prefix(&all, pid)?;
        if child == parent {
            return Err(respire_app::input_error::InputError(format!("op#{i} cannot parent itself: {child}")).into());
        }
        for anc in store.ancestor_chain(&parent)? {
            if anc == child {
                return Err(respire_app::input_error::InputError(format!(
                    "op#{i} cycle: new parent {} is a descendant of {}",
                    respire_app::service::short_id(&parent),
                    respire_app::service::short_id(&child)
                )).into());
            }
        }
        if go {
            respire_app::service::reparent(&session, &store, &child, &parent)?;
        }
        moved += 1;
        rows.push(OutputItem::new(
            respire_app::service::short_id(&child),
            if go {
                OutputStatus::Ok
            } else {
                OutputStatus::Pending
            },
            format!(
                "-> {} {}",
                respire_app::service::short_id(&parent),
                all.iter()
                    .find(|m| m.id == child)
                    .map(|m| m.local_title.as_str())
                    .unwrap_or("")
            ),
        ));
    }
    if go && moved > 0 {
        respire_app::service::counter_reset(&respire_app::service::maintenance_path(), &now_stamp())?;
        auto_sync(&session, &store);
        emit_result(ResultEnvelope::new(
            "resort",
            OutputStatus::Ok,
            serde_json::json!({"moved":moved,"applied":true,"counter":"reset"}),
            rows,
        ))?;
    } else {
        let mut result = ResultEnvelope::new(
            "resort",
            OutputStatus::Pending,
            serde_json::json!({"moved":moved,"applied":false}),
            rows,
        );
        result.actions.push("resort --spec <json> --go".into());
        emit_result(result)?;
    }
    Ok(())
}

/// Daily identity is stable even when its display title or importance changes.
/// Legacy same-user/title tracks still participate in the existing atomic merge.
pub fn select_diary_tracks<'a>(
    memories: &'a [respire_app::StoredMemory],
    track_id: &str,
    track_title: &str,
    mut accepted_author: impl FnMut(&respire_app::StoredMemory) -> Result<bool>,
) -> Result<Vec<&'a respire_app::StoredMemory>> {
    let mut tracks = Vec::new();
    for memory in memories.iter().filter(|memory| !memory.deleted) {
        // Envelope IDs and wire owners are not authenticated payload identity.
        // Accept authors only from the logical identity or unlocked local profile.
        if memory.id == track_id || memory.local_title == track_title {
            let accepted = accepted_author(memory)?;
            anyhow::ensure!(memory.id != track_id || accepted,
                "daily track author does not match this profile; append was not applied");
            if accepted { tracks.push(memory); }
        }
    }
    tracks.sort_by(|left, right| {
        (left.id != track_id).cmp(&(right.id != track_id))
            .then_with(|| left.local_created_at.cmp(&right.local_created_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(tracks)
}
/// Deepen the tree: --auto one-shots sub-roots under every flat large root; --root inspects/applies one root.

pub fn run_tree_deepen(
    root: Option<&str>,
    go: bool,
    titles_json: Option<&str>,
    auto: bool,
    min: f32,
) -> Result<()> {
    let app = respire_app::service::App::open()?;
    match (root, auto) {
        (_, true) => {
            let all = app.store.all(false)?;
            let roots: Vec<&respire_app::StoredMemory> = all
                .iter()
                .filter(|m| m.local_parent_id.is_empty())
                .collect();
            let mut total_built = 0usize;
            let mut total_moved = 0usize;
            let mut items = Vec::new();
            let mut details = Vec::new();
            for r in &roots {
                let plan = match respire_app::service::deepen_plan(&app.store, &r.id, min) {
                    Ok((_, p)) if !p.sub_roots.is_empty() => p,
                    Err(error) if error.downcast_ref::<respire_app::service::IndexPending>().is_some() => return Err(error),
                    _ => continue,
                };
                let titles: Vec<String> = plan.sub_roots.iter().map(|s| s.title.clone()).collect();
                let (b, m) = respire_app::service::deepen_apply(
                    &app.keys,
                    &app.embedder,
                    &app.store,
                    &r.id,
                    &plan,
                    &titles,
                )?;
                total_built += b;
                total_moved += m;
                let name = if r.local_title.is_empty() {
                    respire_app::service::short_id(&r.id)
                } else {
                    r.local_title.clone()
                };
                items.push(OutputItem::new(
                    name,
                    OutputStatus::Ok,
                    format!(
                        "built={b}; moved={m}; root={}",
                        respire_app::service::short_id(&r.id)
                    ),
                ));
                details.push(serde_json::json!({
                    "root": r.id,
                    "title": r.local_title,
                    "built": b,
                    "moved": m,
                    "sub_roots": titles,
                }));
            }
            let mut result = ResultEnvelope::new(
                "tree-deepen",
                OutputStatus::Ok,
                serde_json::json!({
                    "mode": "auto",
                    "roots": items.len(),
                    "built": total_built,
                    "moved": total_moved,
                }),
                items,
            );
            result.details = serde_json::Value::Array(details);
            emit_result(result)?;
        }
        (Some(root_id), false) => {
            let (rid, plan) = respire_app::service::deepen_plan(&app.store, root_id, min)?;
            if !go {
                let items = plan
                    .sub_roots
                    .iter()
                    .enumerate()
                    .map(|(index, sub)| {
                        OutputItem::new(
                            format!("sub_root_{}", index + 1),
                            OutputStatus::Pending,
                            format!("title={}; members={}", sub.title, sub.member_ids.len()),
                        )
                    })
                    .collect();
                let mut result = ResultEnvelope::new(
                    "tree-deepen",
                    OutputStatus::Pending,
                    serde_json::json!({
                        "mode": "plan",
                        "root": rid,
                        "sub_roots": plan.sub_roots.len(),
                        "min": min,
                    }),
                    items,
                );
                result.details = serde_json::to_value(&plan)?;
                result.actions.push(format!(
                    "tree-deepen --root {root_id} --go --titles '[\"title1\",\"title2\"]'"
                ));
                return emit_result(result);
            }
            let Some(tj) = titles_json else {
                anyhow::bail!("--go requires --titles '<sub-root title array JSON>'");
            };
            let titles: Vec<String> = serde_json::from_str(tj)
                .map_err(|e| anyhow!("title array failed to parse: {e}"))?;
            let (b, m) = respire_app::service::deepen_apply(
                &app.keys,
                &app.embedder,
                &app.store,
                &rid,
                &plan,
                &titles,
            )?;
            emit_result(ResultEnvelope::new(
                "tree-deepen",
                OutputStatus::Ok,
                serde_json::json!({
                    "mode": "apply",
                    "root": rid,
                    "built": b,
                    "moved": m,
                }),
                vec![OutputItem::new(
                    "tree-deepen",
                    OutputStatus::Ok,
                    format!(
                        "built={b}; moved={m}; root={}",
                        respire_app::service::short_id(&rid)
                    ),
                )],
            ))?;
        }
        (None, false) => {
            let all = app.store.all(false)?;
            let mut flat = 0usize;
            let mut items = Vec::new();
            let mut details = Vec::new();
            for r in all.iter().filter(|m| m.local_parent_id.is_empty()) {
                match respire_app::service::deepen_plan(&app.store, &r.id, min) {
                    Ok((_, plan)) => {
                        if plan.sub_roots.is_empty() {
                            continue;
                        }
                        flat += 1;
                        let title = if r.local_title.is_empty() {
                            "(untitled)"
                        } else {
                            &r.local_title
                        };
                        items.push(OutputItem::new(
                            respire_app::service::short_id(&r.id),
                            OutputStatus::Pending,
                            format!("title={title}; sub_roots={}", plan.sub_roots.len()),
                        ));
                        details.push(serde_json::json!({
                            "root": r.id,
                            "title": title,
                            "sub_roots": plan.sub_roots,
                        }));
                    }
                    Err(error) if error.downcast_ref::<respire_app::service::IndexPending>().is_some() => return Err(error),
                    Err(_) => {}
                }
            }
            let mut result = ResultEnvelope::new(
                "tree-deepen",
                if flat == 0 {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Pending
                },
                serde_json::json!({"mode":"scan","flat_roots":flat,"min":min}),
                items,
            );
            result.details = serde_json::Value::Array(details);
            if flat > 0 {
                result.actions.push("tree-deepen --root <id>".into());
                result.actions.push("tree-deepen --auto".into());
            }
            emit_result(result)?;
        }
    }
    Ok(())
}

/// TUI/non-TUI dispatch for `extract`, kept out of `run_local_inner` to bound its stack frame.
pub fn run_extract_command(command: &Command) -> Result<()> {
    let Command::Extract {
        targets,
        tui,
        all,
        id,
        dry_run,
        since,
        limit,
        cwd,
        model,
        session,
        kind,
        importance,
        parent,
        include_subagents,
        force,
    } = command
    else {
        return Ok(());
    };
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::io::IsTerminal::is_terminal(&std::io::stdout());
    let filters_absent = since.is_none()
        && limit.is_none()
        && cwd.is_none()
        && model.is_none()
        && session.is_none()
        && kind.as_str() == "context"
        && importance.as_str() == "important"
        && parent.is_empty()
        && !*include_subagents
        && !*force;
    let bare = !*targets && id.is_none() && !*all && !*dry_run && filters_absent && !json_mode();
    if *tui {
        if !bare {
            anyhow::bail!(
                "--tui opens the interactive picker and cannot be combined with extraction options \
                 (--since/--limit/--cwd/--model/--session/--kind/--importance/--parent/--include-subagents/--force) \
                 or --json; drop --tui to apply them."
            );
        }
        return crate::host_hooks::extract_tui_run();
    }
    if bare && interactive {
        return crate::host_hooks::extract_tui_run();
    }
    run_extract(
        *targets,
        id.as_deref(),
        *dry_run,
        since.as_deref(),
        *limit,
        cwd.as_deref(),
        model.as_deref(),
        session.as_deref(),
        kind,
        importance,
        parent,
        *include_subagents,
        *force,
    )
}

/// Extract local coding-agent sessions into rsrs memories (see `extract --help`).
pub fn run_extract(
    targets_only: bool,
    id: Option<&str>,
    dry_run: bool,
    since: Option<&str>,
    limit: Option<usize>,
    cwd: Option<&str>,
    model_filter: Option<&str>,
    session_filter: Option<&str>,
    kind: &str,
    importance: &str,
    parent: &str,
    include_subagents: bool,
    force: bool,
) -> Result<()> {
    if !matches!(importance, "important" | "trivial") {
        anyhow::bail!("--importance must be important or trivial");
    }
    if !matches!(
        kind,
        "context" | "decision" | "preference" | "task" | "emotion" | "time" | "skill" | "knowledge"
    ) {
        anyhow::bail!("--kind must be context|decision|preference|task|emotion|time|skill|knowledge");
    }
    if targets_only {
        let sources = respire_app::session_import::source_list();
        let installed = sources.iter().filter(|source| source.installed).count();
        let items = sources
            .iter()
            .map(|source| {
                OutputItem::new(
                    source.id.clone(),
                    if source.installed { OutputStatus::Ok } else { OutputStatus::Skip },
                    if source.installed {
                        format!("{} ({} root(s))", source.name, source.roots.len())
                    } else {
                        format!("{} not found", source.name)
                    },
                )
            })
            .collect();
        let details = serde_json::Value::Array(
            sources
                .iter()
                .map(|source| {
                    serde_json::json!({
                        "id": source.id,
                        "name": source.name,
                        "installed": source.installed,
                        "roots": source.roots.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        );
        let mut result = ResultEnvelope::new(
            "extract",
            OutputStatus::Ok,
            serde_json::json!({"count": sources.len(), "installed": installed}),
            items,
        );
        result.details = details;
        result.actions.push("extract --all --dry-run".into());
        return emit_result(result);
    }

    let scan_options = respire_app::session_import::ScanOptions {
        roots: Vec::new(),
        cwd: cwd.map(str::to_owned),
        model: model_filter.map(str::to_owned),
        since: match since {
            None => None,
            Some(value) => Some(
                respire_app::session_import::scan_util::date_bound(value, false).ok_or_else(|| {
                    respire_app::input_error::InputError(format!(
                        "invalid --since '{value}': use today|yesterday|Nd|YYYY-MM-DD"
                    ))
                })?,
            ),
        },
        until: None,
        limit: limit.unwrap_or(200),
        include_subagents,
    };

    let scanners: Vec<Box<dyn respire_app::session_import::SessionScanner>> = match id {
        Some(id) => vec![respire_app::session_import::find_scanner(id).ok_or_else(|| {
            anyhow::anyhow!("unknown platform '{id}' (run `rsrs extract --targets`)")
        })?],
        None => respire_app::session_import::scanners()
            .into_iter()
            .filter(|scanner| !scanner.roots().is_empty())
            .collect(),
    };
    if scanners.is_empty() {
        return emit_result(ResultEnvelope::new(
            "extract",
            OutputStatus::Skip,
            serde_json::json!({"reason": "no installed session stores detected"}),
            Vec::new(),
        ));
    }

    let mut sessions = Vec::new();
    for scanner in &scanners {
        let label = format!("Scanning {} sessions", scanner.name());
        progress::phase(&label, &label);
        let mut found = scanner.scan(&scan_options);
        found.retain(|session| scan_options.matches(session));
        if let Some(filter) = session_filter {
            found.retain(|session| session.id.contains(filter));
        }
        sessions.extend(found);
    }
    let sessions = respire_app::session_import::dedupe(sessions);
    let discovered = sessions.len();
    let mut cursor = respire_app::session_import::Cursor::load();
    let fresh: Vec<respire_app::session_import::Session> = sessions
        .into_iter()
        .filter(|session| force || !cursor.is_imported(session))
        .collect();
    let not_imported = fresh.len();
    let pending = respire_app::session_import::cap_per_platform(fresh, scan_options.limit);

    let convert_options = respire_app::session_import::ConvertOptions {
        kind: respire_app::Kind::try_from_str(&kind.trim().to_lowercase()).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?,
        importance: importance.to_owned(),
        parent: String::new(),
        user: respire_app::service::current_user(),
        device: respire_app::service::device_tag(),
        project: String::new(),
    };
    let mut entries: Vec<respire_app::MemoryEntry> = pending
        .iter()
        .map(|session| respire_app::session_import::session_entry(session, &convert_options))
        .collect();

    let platform_counts: Vec<(String, usize)> = scanners
        .iter()
        .map(|scanner| {
            let id = scanner.id();
            (
                id.to_owned(),
                pending.iter().filter(|session| session.platform == id).count(),
            )
        })
        .filter(|(_, count)| *count > 0)
        .collect();
    let items: Vec<OutputItem> = platform_counts
        .iter()
        .map(|(id, count)| OutputItem::new(id.clone(), OutputStatus::Ok, format!("{count} session(s)")))
        .collect();

    if dry_run {
        let mut result = ResultEnvelope::new(
            "extract",
            OutputStatus::Ok,
            serde_json::json!({
                "dry_run": true,
                "scanned": discovered,
                "pending": entries.len(),
                "skipped_imported": discovered - not_imported,
                "deferred_by_limit": not_imported - pending.len(),
                "by_platform": platform_counts.iter().map(|(id, count)| serde_json::json!({"id": id, "count": count})).collect::<Vec<_>>(),
            }),
            items,
        );
        result.details = serde_json::json!({
            "sessions": pending.iter().map(|session| session.to_json()).collect::<Vec<_>>(),
        });
        result.actions.push("extract --all".into());
        return emit_result(result);
    }

    if entries.is_empty() {
        let mut result = ResultEnvelope::new(
            "extract",
            OutputStatus::Skip,
            serde_json::json!({"imported": 0, "scanned": discovered, "skipped_imported": discovered - not_imported, "deferred_by_limit": not_imported}),
            Vec::new(),
        );
        if discovered > 0 && not_imported == 0 {
            result.actions.push("extract --all --force".into());
        }
        return emit_result(result);
    }

    progress::phase("Embedding and storing memories", "Embedding and storing memories");
    let outcome = respire_app::session_import::import_entries(
        &mut entries,
        parent,
        |done, total| progress::phase_count("\u{5199}\u{5165}\u{8bb0}\u{5fc6}", "Storing memories", done, total),
        |start, completed| {
            for (offset, ok) in completed.iter().enumerate() {
                if *ok {
                    cursor.mark(&pending[start + offset]);
                }
            }
            cursor.save()?;
            Ok(())
        },
    )?;
    let imported = outcome.imported;

    let mut result = ResultEnvelope::new(
        "extract",
        OutputStatus::Ok,
        serde_json::json!({
            "imported": imported,
            "scanned": discovered,
            "deferred_by_limit": not_imported - pending.len(),
            "by_platform": platform_counts.iter().map(|(id, count)| serde_json::json!({"id": id, "count": count})).collect::<Vec<_>>(),
        }),
        items,
    );
    result
        .actions
        .push("tidy imported roots: rsrs list --since-resort --json".into());
    emit_result(result)
}

/// Inject-source distribution: no args injects every detected host; --targets lists status; --id injects/uninstalls.

pub fn run_split(id: &str, go: bool, spec_json: Option<&str>) -> Result<()> {
    let app = respire_app::service::App::open()?;
    let detail = app.show(id)?;
    if !go {
        let m = respire_app::service::split_material(&detail.entry, &detail.ancestors);
        let mut result = ResultEnvelope::new(
            "split",
            OutputStatus::Skip,
            serde_json::json!({"id": id, "content_len": m.content_len}),
            vec![
                OutputItem::new("plan", OutputStatus::Skip, "inspection only")
                    .action(format!("rsrs split {id} --go --spec '<split-plan-json>'")),
                OutputItem::new("id", OutputStatus::Ok, m.id.clone()),
                OutputItem::new("title", OutputStatus::Ok, m.title.clone()),
                OutputItem::new("kind", OutputStatus::Ok, m.kind.clone()),
                OutputItem::new("content_len", OutputStatus::Ok, m.content_len.to_string()),
                OutputItem::new("parent", OutputStatus::Ok, m.parent_id.clone()),
                OutputItem::new("CONTENT", OutputStatus::Skip, m.content.clone()),
            ],
        );
        result.details = serde_json::to_value(&m)?;
        result
            .actions
            .push("read details and provide --spec JSON".to_owned());
        return emit_result(result);
    }
    let Some(spec_json) = spec_json else {
        return Err(respire_app::input_error::InputError(
            "--go requires --spec '<split-plan JSON>' (run with no flags first to get material)".into()
        ).into());
    };
    let spec: respire_app::service::SplitSpec =
        serde_json::from_str(spec_json).map_err(|e| respire_app::input_error::InputError(format!("plan JSON failed to parse: {e}")))?;
    let n =
        respire_app::service::split_exec(&app.keys, &app.embedder, &app.store, &detail.entry, &spec)?;
    let mut result = ResultEnvelope::new(
        "split",
        OutputStatus::Ok,
        serde_json::json!({"created": n, "root_replaced": spec.summary.is_some()}),
        vec![OutputItem::new("created", OutputStatus::Ok, n.to_string())],
    );
    result.details = serde_json::json!({"root_replaced": spec.summary.is_some()});
    emit_result(result)
}

/// Post-op orphan check: report, do not fix - CLI detects, the model decides; the AI patches with resort after reading.
/// purge resolver: **do not filter deleted entries** - purge's point is to clear tombstone ciphertext.
/// Exact id -> 8-char prefix (including deleted); multiple hits report "prefix not unique" so we do not delete the wrong one.
pub fn resolve_prefix_incl_deleted(
    store: &respire_app::transport::local::LocalStore,
    prefix: &str,
) -> Result<String> {
    let prefix = prefix.trim_start_matches('#');
    let all = store.all(true)?;
    if let Some(m) = all.iter().find(|s| s.id == prefix) {
        return Ok(m.id.clone());
    }
    let chars: Vec<char> = prefix.chars().collect();
    let p8: String = chars.iter().take(8).collect();
    let hits: Vec<String> = all
        .iter()
        .filter(|s| s.id.chars().take(8).collect::<String>() == p8)
        .map(|s| s.id.clone())
        .collect();
    match hits.len() {
        1 => Ok(hits[0].clone()),
        0 => anyhow::bail!("no such entry (including deleted): {prefix}"),
        n => anyhow::bail!("prefix not unique ({n} entries): {prefix}"),
    }
}

pub fn report_orphans(store: &respire_app::transport::local::LocalStore, action: &str) {
    let all = match store.all(true) {
        Ok(a) => a,
        Err(_) => return,
    };
    let by_id: std::collections::HashMap<&str, &respire_app::StoredMemory> =
        all.iter().map(|m| (m.id.as_str(), m)).collect();
    let orphans: Vec<&respire_app::StoredMemory> = all
        .iter()
        .filter(|m| !m.deleted)
        .filter(|m| {
            !m.local_parent_id.is_empty()
                && by_id
                    .get(m.local_parent_id.as_str())
                    .map_or(true, |pp| pp.deleted)
        })
        .collect();
    if orphans.is_empty() {
        return;
    }
    eprintln!("   WARN [{action}] {} orphan(s) (parent deleted/merged; reparent with resort) - `rsrs audit --json` for the whole store:", orphans.len());
    for m in &orphans {
        eprintln!(
            "     {} {} <-was parent {}",
            &m.id[..8.min(m.id.len())],
            m.local_title,
            m.local_parent_id
        );
    }
}

/// Record a procedure run outcome. Local-only (same contract as query_log):
/// the row never enters the encrypted payload and never syncs.
pub fn run_run_log(id: &str, status: &str, note: &str) -> Result<()> {
    let store = build_local()?;
    let all = store.all(false)?;
    let full = respire_app::service::resolve_prefix(&all, id)?;
    let target = all
        .iter()
        .find(|m| m.id == full)
        .ok_or_else(|| anyhow!("no live entry {}", respire_app::service::short_id(&full)))?;
    if !skill::is_procedure(&target.local_kind) {
        // A refusal is a business state, not a crash: the runtime turns `bail`
        // into an opaque runtime_error, so answer with a Skip envelope instead.
        let short = respire_app::service::short_id(&full);
        let kind = if target.local_kind.trim().is_empty() {
            "untyped"
        } else {
            target.local_kind.as_str()
        };
        let mut result = ResultEnvelope::new(
            "run-log",
            OutputStatus::Skip,
            serde_json::json!({"id": full, "kind": kind, "reason": "not a procedure"}),
            vec![OutputItem::new(
                short.clone(),
                OutputStatus::Skip,
                "not a procedure",
            )],
        );
        result.actions.push(format!(
            "{short} is {kind}; convert it with `rsrs update {short} --kind skill` if it is a procedure"
        ));
        emit_result(result)?;
        return Ok(());
    }
    store.log_skill_run(&full, status, note)?;
    let stats = store
        .skill_run_stats(std::slice::from_ref(&full))?
        .remove(&full)
        .unwrap_or_default();
    emit_result(ResultEnvelope::new(
        "run-log",
        OutputStatus::Ok,
        serde_json::json!({
            "id": full,
            "title": target.local_title,
            "status": status,
            "ok": stats.ok,
            "fail": stats.fail,
            "confounded": stats.confounded,
            "no_effect": stats.no_effect,
            "last_status": stats.last_status,
        }),
        vec![OutputItem::new(
            respire_app::service::short_id(&full),
            OutputStatus::Ok,
            format!(
                "{status} \u{b7} ok {} / fail {} / confounded {} / no_effect {}",
                stats.ok, stats.fail, stats.confounded, stats.no_effect
            ),
        )],
    ))
}

/// Whole-store health audit: orphans / illegal importance / duplicate titles / truncated titles / deep chains - a structured report for an AI to patch after.
/// Query log: list recent queries and adoption/self-grade, or stats (--stats), or report a self-grade (mark).
/// Post-training terms: candidates ≠ hits; chosen = model mark --good, rejected = mark --bad;
/// adopted (used when writing) is a weak signal only.
pub fn run_query_log(
    limit: usize,
    stats: bool,
    json_flag: bool,
    cmd: Option<&QueryLogCmd>,
) -> Result<()> {
    if json_flag {
        set_json_mode(true);
    }
    let store = build_local()?;
    // mark: model self-grade - the main post-training signal
    if let Some(QueryLogCmd::Mark { ids, good, bad, query_log_id, source }) = cmd {
        if *good == *bad {
            anyhow::bail!("pick exactly one of --good or --bad");
        }
        let id_list: Vec<String> = ids
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        anyhow::ensure!(!id_list.is_empty(), "ids is empty");
        let (unmatched,revision)=if let Some(request_id)=query_log_id {
            (Vec::new(),Some(store.mark_query_feedback(request_id,&id_list,*good,source)?))
        }else{
            anyhow::ensure!(source=="model","legacy grading without --query-log-id supports only --source model; use an explicit query request for human/task_outcome attribution");
            anyhow::ensure!(!respire_app::feedback::enabled()?,"enabled feedback requires --query-log-id from the recall summary and complete memory IDs");
            (store.mark_verdict(&id_list,*good)?,None)
        };
        let status = if unmatched.is_empty() {
            OutputStatus::Ok
        } else {
            OutputStatus::Warn
        };
        let mut result = ResultEnvelope::new(
            "query-log",
            status,
            serde_json::json!({"marked":id_list.len()-unmatched.len(),"good":*good,"query_log_id":query_log_id,"source":source,"revision":revision}),
            vec![
                OutputItem::new(
                    "marked",
                    status,
                    (id_list.len() - unmatched.len()).to_string(),
                ),
                OutputItem::new(
                    "verdict",
                    OutputStatus::Ok,
                    if *good { "good" } else { "bad" },
                ),
            ],
        );
        result.details = serde_json::json!({"unmatched":unmatched});
        if !unmatched.is_empty() {
            result.actions.push("query-log --stats".into());
        }
        emit_result(result)?;
        return Ok(());
    }
    if stats {
        let s = store.query_log_stats()?;
        let adopt_rate = if s.total > 0 {
            s.with_adopted as f64 / s.total as f64 * 100.0
        } else {
            0.0
        };
        let empty_rate = if s.total > 0 {
            s.empty_candidates as f64 / s.total as f64 * 100.0
        } else {
            0.0
        };
        let mut result = ResultEnvelope::new(
            "query-log",
            OutputStatus::Ok,
            serde_json::json!({"stats":true,"queries":s.total,"adopted":s.with_adopted,"empty_candidates":s.empty_candidates,"good":s.good_total,"bad":s.bad_total,"adopt_rate":adopt_rate,"empty_rate":empty_rate}),
            vec![
                OutputItem::new("queries", OutputStatus::Ok, s.total.to_string()),
                OutputItem::new(
                    "adopted",
                    OutputStatus::Ok,
                    format!("{} ({adopt_rate:.1}%)", s.with_adopted),
                ),
                OutputItem::new(
                    "empty candidates",
                    OutputStatus::Ok,
                    format!("{} ({empty_rate:.1}%)", s.empty_candidates),
                ),
                OutputItem::new(
                    "self grade",
                    OutputStatus::Ok,
                    format!("good {} / bad {}", s.good_total, s.bad_total),
                ),
            ],
        );
        result.details = serde_json::to_value(&s)?;
        result.items.extend(s.top.iter().map(|(id, c)| {
            OutputItem::new(
                "top adopted",
                OutputStatus::Ok,
                format!("{} count {}", respire_app::service::short_id(id), c),
            )
        }));
        emit_result(result)?;
        return Ok(());
    }
    let rows = store.query_log_rows(limit)?;
    if rows.is_empty() {
        let mut result = ResultEnvelope::new(
            "query-log",
            OutputStatus::Skip,
            serde_json::json!({"count":0}),
            vec![OutputItem::new("rows", OutputStatus::Skip, "0")],
        );
        result.actions.push("query-log --stats".into());
        emit_result(result)?;
        return Ok(());
    }
    let mut items = Vec::new();
    let mut detail_rows = Vec::new();
    for r in &rows {
        let fmt = |v: &Vec<String>| {
            if v.is_empty() {
                "-".to_owned()
            } else {
                v.iter()
                    .map(|a| respire_app::service::short_id(a))
                    .collect::<Vec<_>>()
                    .join(",")
            }
        };
        let project = if r.project.is_empty() {
            String::new()
        } else {
            format!(" [{}]", r.project)
        };
        items.push(OutputItem::new(
            "query",
            OutputStatus::Ok,
            format!(
                "{} {}{} cand={} adopted={} good={} bad={}",
                r.ts,
                r.query,
                project,
                fmt(&r.candidates),
                fmt(&r.adopted),
                fmt(&r.good),
                fmt(&r.bad)
            ),
        ));
        detail_rows.push(serde_json::to_value(r)?);
    }
    let mut result = ResultEnvelope::new(
        "query-log",
        OutputStatus::Ok,
        serde_json::json!({"count":rows.len()}),
        items,
    );
    result.details = serde_json::Value::Array(detail_rows);
    emit_result(result)?;
    Ok(())
}

/// Human-readable rank: Some(n) -> #n+1; None -> miss.
pub fn bench_pos(p: Option<usize>) -> String {
    match p {
        Some(n) => format!("#{}", n + 1),
        None => "miss".to_owned(),
    }
}

/// bench entry: run an evalset / mine an evalset from query-log.
pub fn run_bench(cmd: &BenchCmd) -> Result<()> {
    match cmd {
        BenchCmd::Run {
            file,
            topk,
            save,
            baseline,
            verbose,
        } => run_bench_run(file, *topk, save.as_deref(), baseline.as_deref(), *verbose),
        BenchCmd::Mine { out, limit, strict } => run_bench_mine(out, *limit, *strict),
    }
}

/// mine: draft an evalset from query-log - expect = good (strict uses only this) ∪ adopted;
/// keep only ids still active; merge same query. Writes JSONL.
pub fn run_bench_mine(out: &str, limit: usize, strict: bool) -> Result<()> {
    let store = build_local()?;
    let rows = store.query_log_rows(limit * 5)?;
    let active: std::collections::HashSet<String> = store.all(false)?
        .iter()
        .map(|m| m.id.clone())
        .collect();
    let cases = bench::mine_from_rows(&rows, strict, limit, &active);
    anyhow::ensure!(
        !cases.is_empty(),
        "nothing to mine: query-log needs a self-grade good (rsrs query-log mark --good) or an adopted record, and the entry must still be in the store"
    );
    let mut buf = String::new();
    for c in &cases {
        buf.push_str(&serde_json::to_string(c)?);
        buf.push('\n');
    }
    std::fs::write(out, buf).map_err(|e| anyhow!("write failed: {out} ({e})"))?;
    emit_result(ResultEnvelope::new(
        "bench-mine",
        OutputStatus::Ok,
        serde_json::json!({"cases":cases.len(),"path":out,"strict":strict}),
        vec![
            OutputItem::new("eval cases", OutputStatus::Ok, cases.len().to_string()),
            OutputItem::new("path", OutputStatus::Ok, out),
            OutputItem::new(
                "source",
                OutputStatus::Ok,
                if strict { "good" } else { "good and adopted" },
            ),
        ],
    ))?;
    Ok(())
}

/// run: execute an evalset - recall each case on the real retrieval path; emit hit-rate/MRR/noise; optional archive and baseline compare.
/// Eval is read-only: no query_log writes, no hit-count bump.
pub fn run_bench_run(
    file: &str,
    topk: usize,
    save: Option<&str>,
    baseline: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let text = respire_app::input_error::read_file(std::path::Path::new(file), "evalset")?;
    let cases = bench::parse_evalset(&text)?;
    anyhow::ensure!(!cases.is_empty(), "evalset is empty: {file}");

    // Read the baseline first: fail fast - eval is expensive (per-case recall); do not finish a run then fail on the baseline.
    let base_report: Option<bench::BenchReport> = match baseline {
        Some(bp) => {
            let btext = std::fs::read_to_string(bp)
                .map_err(|e| anyhow!("failed to read baseline: {bp} ({e})"))?;
            Some(
                serde_json::from_str(&btext)
                    .map_err(|e| anyhow!("baseline JSON failed to parse: {bp} ({e})"))?,
            )
        }
        None => None,
    };

    let session = build_session()?;
    let store = build_local()?;
    let (candidates, index_pending, resident) = respire_app::resident::recall_catalog(&session, &store)?;
    let _resident_scope = resident.enter();
    let active_ids: std::collections::HashSet<String> =
        candidates.iter().map(|m| m.id.clone()).collect();
    let embedder = BgeEmbedder::load_model(&store.retrieval_model()?)?;

    // Expected-id check: warn when not in the active store (deleted/merged) - those cases fail forever
    let mut missing: Vec<String> = Vec::new();
    for c in &cases {
        for e in &c.expect {
            if !active_ids.iter().any(|id| bench::id_match(id, e)) && !missing.contains(e) {
                missing.push(e.clone());
            }
        }
    }

    let mut results = Vec::with_capacity(cases.len());
    let mut latency = Vec::new();
    let mut selector_fallbacks = 0usize;
    for (i, c) in cases.iter().enumerate() {
        progress::phase(&format!("\u{8bc4}\u{4f30}\u{53ec}\u{56de} {}/{}", i + 1, cases.len()), &format!("Evaluating recall {}/{}", i + 1, cases.len()));
        let mut q = MemoryQuery::new(&c.query).limit(topk);
        if let Some(p) = &c.project {
            if !p.is_empty() {
                q = q.of_project(p);
            }
        }
        let started = std::time::Instant::now();
        let (ranked, _, fallback, _, _, _) = recall_select::recall(&session, &embedder, &candidates, &q, &store, None, None, None)?;
        latency.push(started.elapsed().as_micros());
        selector_fallbacks += usize::from(fallback.is_some());
        let ids: Vec<String> = ranked.iter().map(|r| r.entry.id.clone()).collect();
        let rank = bench::rank_of(&ids, &c.expect);
        let top1 = ranked.first();
        results.push(bench::CaseResult {
            query: c.query.clone(),
            expect: c.expect.clone(),
            project: c.project.clone(),
            rank,
            ids,
            top1_score: top1.map(|r| r.score),
            top1_title: top1.map(|r| r.entry.title.clone()).unwrap_or_default(),
        });
    }

    let metrics = bench::summarize(&results, topk);
    latency.sort_unstable();
    let mut params = bench::snapshot_params()?;
    params.insert("embedding_model".into(), embedder.model_name().into());
    params.insert("cli_version".into(), env!("CARGO_PKG_VERSION").into());
    params.insert(
        "recall_mode".into(),
        respire_app::service::read_agent_config()["recall_mode"]
            .as_str()
            .unwrap_or("fast")
            .into(),
    );
    params.insert("selector_fallbacks".into(), selector_fallbacks.to_string());
    params.insert("index_pending".into(), index_pending.to_string());
    params.insert("retrieval_policy".into(), "Core-owned".into());
    if !latency.is_empty() {
        params.insert("p50_us".into(), latency[latency.len() / 2].to_string());
        params.insert(
            "p95_us".into(),
            latency[(latency.len() * 95 / 100).min(latency.len() - 1)].to_string(),
        );
    }
    let report = bench::BenchReport {
        version: 1,
        ts: chrono::Utc::now().to_rfc3339(),
        evalset: file.to_owned(),
        topk,
        n_entries: candidates.len(),
        params,
        metrics: metrics.clone(),
        results,
    };

    // Baseline compare (optional; base_report was read up front)
    let cmp = base_report
        .as_ref()
        .map(|b| bench::compare(&b.results, &report.results));

    // Archive (optional)
    if let Some(sp) = save {
        let s = serde_json::to_string_pretty(&report)?;
        std::fs::write(sp, s).map_err(|e| anyhow!("failed to archive: {sp} ({e})"))?;
    }

    let m = &report.metrics;
    let mut status = if missing.is_empty() {
        OutputStatus::Ok
    } else {
        OutputStatus::Warn
    };
    let mut items = vec![
        OutputItem::new("evalset", OutputStatus::Ok, file),
        OutputItem::new(
            "cases",
            OutputStatus::Ok,
            format!("{} ({} positive, {} negative)", m.n, m.n_pos, m.n_neg),
        ),
        OutputItem::new("store", OutputStatus::Ok, report.n_entries.to_string()),
        OutputItem::new(
            "hit rate",
            OutputStatus::Ok,
            format!(
                "hit@1 {:.3}, hit@3 {:.3}, hit@{} {:.3}",
                m.hit1, m.hit3, topk, m.hitk
            ),
        ),
        OutputItem::new("MRR", OutputStatus::Ok, format!("{:.3}", m.mrr)),
        OutputItem::new(
            "noise",
            OutputStatus::Ok,
            format!(
                "empty {}, negative {}/{}",
                m.empty_results, m.neg_noise, m.n_neg
            ),
        ),
    ];
    if !missing.is_empty() {
        status = OutputStatus::Warn;
        items.push(
            OutputItem::new(
                "missing expected ids",
                OutputStatus::Warn,
                missing.join(", "),
            )
            .action("refresh evalset"),
        );
    }

    let missed: Vec<&bench::CaseResult> = report
        .results
        .iter()
        .filter(|r| !r.expect.is_empty() && r.rank.is_none())
        .collect();
    let mut detail = serde_json::json!({"report":report});
    if let (Some(b), Some(c)) = (&base_report, &cmp) {
        detail["baseline"] =
            serde_json::json!({ "file": baseline, "ts": b.ts, "metrics": b.metrics });
        detail["compare"] = serde_json::to_value(c)?;
    }
    if !missed.is_empty() {
        items.push(OutputItem::new(
            "misses",
            OutputStatus::Warn,
            missed.len().to_string(),
        ));
        if matches!(status, OutputStatus::Ok) {
            status = OutputStatus::Warn;
        }
    }
    if verbose {
        items.extend(report.results.iter().enumerate().map(|(i, r)| {
            let score = r
                .top1_score
                .map(|s| format!("{s:.3}"))
                .unwrap_or_else(|| "-".to_owned());
            OutputItem::new(
                format!("case {}", i + 1),
                if r.rank.is_some() {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Warn
                },
                format!("{} {} {}", bench_pos(r.rank), score, r.query),
            )
        }));
    }

    if let (Some(b), Some(c)) = (&base_report, &cmp) {
        items.push(OutputItem::new(
            "baseline",
            OutputStatus::Ok,
            format!(
                "{} hit@{} {:.3}->{:.3}, MRR {:.3}->{:.3}",
                baseline.unwrap_or(""),
                topk,
                b.metrics.hitk,
                m.hitk,
                b.metrics.mrr,
                m.mrr
            ),
        ));
        items.push(OutputItem::new(
            "comparison",
            if c.regressed.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            format!(
                "improved {}, regressed {}, same {}, only-new {}, only-baseline {}",
                c.improved.len(),
                c.regressed.len(),
                c.same,
                c.only_in_now,
                c.only_in_base
            ),
        ));
    }
    let mut result = ResultEnvelope::new(
        "bench",
        status,
        serde_json::json!({"evalset":file,"topk":topk,"cases":m.n,"hit1":m.hit1,"hit3":m.hit3,"hitk":m.hitk,"mrr":m.mrr,"missing":missing.len()}),
        items,
    );
    result.details = detail;
    if let Some(sp) = save {
        result.actions.push(format!("report saved to {sp}"));
    }
    emit_result(result)?;
    Ok(())
}

/// Render the final classification status supplied by Core.

pub fn classify_status(value: &str) -> OutputStatus {
    match value {
        "fail" => OutputStatus::Fail,
        "warn" => OutputStatus::Warn,
        "skip" => OutputStatus::Skip,
        "pending" => OutputStatus::Pending,
        _ => OutputStatus::Ok,
    }
}

pub fn emit_classify_report(
    report: classify::ClassifyReport,
    mut details: serde_json::Value,
) -> Result<()> {
    let summary = serde_json::to_value(&report.summary)?;
    if let serde_json::Value::Object(ref mut map) = details {
        map.insert("report".to_owned(), serde_json::to_value(&report)?);
    }
    let mut rows = vec![OutputItem::new(
        "summary",
        classify_status(&report.status),
        format!(
            "total={} matched={} mismatch={} unrooted={} low={} failed={}",
            report.summary.total,
            report.summary.matched,
            report.summary.mismatch,
            report.summary.unrooted,
            report.summary.low_confidence,
            report.summary.failed
        ),
    )];
    rows.extend(report.items.iter().map(|item| {
        let value = format!(
            "current={} choice={} confidence={} {}",
            item.current,
            item.choice,
            item.confidence
                .map(|v| format!("{v:.2}"))
                .unwrap_or_default(),
            item.error.clone().unwrap_or_default()
        );
        OutputItem::new(
            format!("{}:{}", item.class, item.id),
            classify_status(&item.status),
            value,
        )
    }));
    let mut envelope = ResultEnvelope::new(
        report.command,
        classify_status(&report.status),
        summary,
        rows,
    );
    envelope.errors = report.errors;
    envelope.details = details;
    emit_result(envelope)
}

pub fn emit_classify_details(
    command: &str,
    status: OutputStatus,
    summary: serde_json::Value,
    details: serde_json::Value,
    rows: Vec<OutputItem>,
) -> Result<()> {
    let mut result = ResultEnvelope::new(command, status, summary, rows);
    result.details = details;
    emit_result(result)
}

pub fn run_classify(
    limit: usize,
    all: bool,
    root: Option<&str>,
    max_chars: usize,
    min_confidence: f32,
    save: Option<&str>,
    api_base: Option<&str>,
    model: &str,
    dry_run: bool,
    ds: Option<&str>,
    backend: Option<&str>,
    samples: usize,
    tree: bool,
    batch: usize,
    tree_depth: usize,
    causal: bool,
    min_kids: usize,
    segments: usize,
    out: Option<&str>,
    auto: bool,
    plan: bool,
    rounds: usize,
) -> Result<()> {
    let generation = rpc::sync_generation();
    let (store, memories, selected_root, backend, session) =
        rpc::foreground_phase(generation, || {
            let store = build_local()?;
            let memories = store.all(false)?;
            let selected_root = root
                .map(|prefix| respire_app::service::resolve_prefix(&memories, prefix))
                .transpose()?;
            let backend = if plan {
                None
            } else {
                Some(build_classify_backend(
                    api_base, model, dry_run, ds, backend,
                )?)
            };
            let session = if auto && !dry_run && !plan {
                Some(build_session()?)
            } else {
                None
            };
            Ok((store, memories, selected_root, backend, session))
        })?;
    let source_revision = classify_source_revision(&memories);
    let mode = if plan {
        "preview"
    } else if auto {
        "auto"
    } else if causal {
        "causal"
    } else if tree {
        "tree"
    } else {
        "standard"
    };
    if progress_enabled() && !dry_run && !plan {
        eprintln!("Running classification...");
    }
    let mut result = classify::execute(
        &memories,
        backend.as_ref(),
        serde_json::json!({
            "mode": mode, "limit": limit, "all": all, "root": selected_root,
            "max_chars": max_chars, "min_confidence": min_confidence, "dry_run": dry_run,
            "samples": samples, "batch": batch, "tree_depth": tree_depth,
            "min_kids": min_kids, "segments": segments, "rounds": rounds,
        }),
    )?;

    rpc::foreground_phase(generation, || Ok(()))?;
    let mut applied = 0usize;
    if let Some(session) = session.as_ref() {
        applied = rpc::foreground_phase(generation, || {
            let current = store.all(false)?;
            anyhow::ensure!(
                classify_source_revision(&current) == source_revision,
                "memory data changed during classification; retry against the current library"
            );
            let ids: std::collections::HashSet<&str> =
                current.iter().map(|memory| memory.id.as_str()).collect();
            let mut changed = std::collections::HashSet::new();
            for action in &result.actions {
                anyhow::ensure!(
                    ids.contains(action.id.as_str()),
                    "classification refers to a missing memory: {}",
                    action.id
                );
                anyhow::ensure!(
                    action.parent_id.is_empty() || ids.contains(action.parent_id.as_str()),
                    "classification refers to a missing parent: {}",
                    action.parent_id
                );
                anyhow::ensure!(
                    changed.insert(action.id.as_str()),
                    "classification returned duplicate actions for {}",
                    action.id
                );
                anyhow::ensure!(
                    action.id != action.parent_id,
                    "classification cannot attach a memory to itself"
                );
            }
            store.write_transaction(|| {
                let current = store.all(false)?;
                for action in &result.actions {
                    let row = current.iter().find(|row| row.id == action.id)
                        .ok_or_else(|| anyhow!("classification memory disappeared: {}", action.id))?;
                    respire_app::metadata_gate::ensure_write(&store, &MemoryEngine::open(session, row)?)?;
                }
                for action in &result.actions {
                    respire_app::service::reparent(session, &store, &action.id, &action.parent_id)?;
                }
                Ok(())
            })?;
            if !result.actions.is_empty() {
                respire_app::service::counter_reset(
                    &respire_app::service::maintenance_path(),
                    &now_stamp(),
                )?;
            }
            Ok(result.actions.len())
        })?;
        if applied > 0 {
            auto_sync(session, &store);
        }
    }

    let operations: Vec<serde_json::Value> = result
        .actions
        .iter()
        .map(|action| serde_json::json!({"id": action.id, "parent": action.parent_id}))
        .collect();
    if let Some(path) = out {
        std::fs::write(
            path,
            serde_json::to_string_pretty(&serde_json::json!({"ops": operations}))?,
        )
        .map_err(|error| anyhow!("failed to write action preview: {path} ({error})"))?;
    }
    let details = serde_json::json!({
        "mode": mode, "dry_run": dry_run, "items": result.items,
        "ops": operations, "warnings": result.warnings, "applied": applied,
        "backend": backend.as_ref().map(|value| value.name),
        "api_base": backend.as_ref().map(|value| value.base_shown.as_str()),
        "model": backend.as_ref().map(|value| value.model.as_str()),
    });
    if let Some(path) = save {
        std::fs::write(path, serde_json::to_string_pretty(&details)?)
            .map_err(|error| anyhow!("failed to save suggestions: {path} ({error})"))?;
    }
    if let Some(report) = result.report.take() {
        return emit_classify_report(report, details);
    }
    let status = if dry_run {
        OutputStatus::Skip
    } else if result.warnings.is_empty() {
        OutputStatus::Ok
    } else {
        OutputStatus::Warn
    };
    emit_classify_details(
        if plan { "classify-plan" } else { "classify" },
        status,
        result.summary,
        details,
        vec![
            OutputItem::new("mode", status, mode),
            OutputItem::new("suggested_edits", status, result.actions.len().to_string()),
            OutputItem::new("applied", status, applied.to_string()),
        ],
    )
}

/// Configuration and credentials stay under the selected profile's local gate.
pub fn build_classify_backend(
    api_base: Option<&str>,
    model: &str,
    dry_run: bool,
    ds: Option<&str>,
    backend: Option<&str>,
) -> Result<classify::Backend> {
    use classify::Backend;
    // -- backend pick --
    // --backend (jev|ds) and --ds collapse: jev plus --ds is a conflict;
    // An explicit flag takes precedence over the stored default selection.
    let be = backend
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            if ds.is_none() {
                respire_app::keystore::load_classify_backend()
            } else {
                None
            }
        });
    let ds_sel: Option<String> = match (&be, ds) {
        (Some(b), _) if b == "jev" || b == "typesafe" => {
            if ds.is_some() {
                anyhow::bail!(
                    "--backend jev conflicts with --ds - jev is the default backend; drop --ds"
                );
            }
            None
        }
        (Some(b), Some(k)) if b == "ds" || b == "deepseek" => Some(k.to_owned()),
        (Some(b), None) if b == "ds" || b == "deepseek" => Some(String::new()),
        (Some(b), _) => anyhow::bail!("unknown backend \"{b}\" - choose: jev | ds"),
        (None, k) => k.map(|s| s.to_owned()),
    };
    let ds = ds_sel.as_deref();
    let backend = if let Some(dsk) = ds {
        // Endpoint first: key-ring slot is per host - official DS and b.ai keys are not interchangeable
        let base = match api_base {
            Some(b) => b.to_owned(),
            None => respire_app::keystore::load_ds_last_base()
                .unwrap_or_else(|| classify::DEFAULT_DS_BASE.to_owned()),
        };
        let host = respire_app::keystore::host_of(&base);
        let slot = format!("ds@{host}");
        // dry-run hits no network, so no key is required (same as the TypeSafe backend)
        let key = if dry_run {
            respire_app::keystore::load_classify_key(&slot).unwrap_or_default()
        } else if dsk.trim().is_empty() {
            // `--ds` with no value: load the stored key for this endpoint; else print a setup hint
            respire_app::keystore::load_classify_key(&slot).ok_or_else(|| {
                anyhow!(
                    "endpoint {host} has no key yet:\n  \
                     rsrs classify --ds <your-key>                      # run now and store in the system keyring\n  \
                     rsrs classify --ds <key> --api-base <endpoint>     # another endpoint (e.g. b.ai)\n  \
                     or  export DS_API_KEY=<your-key>                      # env bypass\n\
                     get a key: https://platform.deepseek.com/api_keys"
                )
            })?
        } else {
            let k = dsk.trim().to_owned();
            // dry-run is inspect-only - do not write the keyring or remember the endpoint (tests must not pollute real config)
            if !dry_run {
                match respire_app::keystore::save_classify_key(&slot, &k) {
                    Ok(()) => {
                        // remember the endpoint (path included) so the next `--ds` needs no extra flags
                        let _ = respire_app::keystore::save_ds_last_base(&base);
                        if !json_mode() {
                            eprintln!("KEY key stored in the system keyring (slot {slot}; endpoint {base} remembered)");
                        }
                    }
                    Err(e) => {
                        if !json_mode() {
                            eprintln!("WARN could not store the key in the keyring ({e}) - this run works; next time pass it again or set DS_API_KEY");
                        }
                    }
                }
            }
            k
        };
        let model = if model == classify::DEFAULT_MODEL {
            // model not given: prefer the last model used on this host (relays differ), else the official default
            respire_app::keystore::load_ds_model(&host)
                .unwrap_or_else(|| classify::DEFAULT_DS_MODEL.to_owned())
        } else {
            model.to_owned()
        };
        if !dry_run && model != classify::DEFAULT_MODEL {
            let _ = respire_app::keystore::save_ds_model(&host, &model);
        }
        Backend {
            name: "ds",
            key,
            model,
            endpoint: classify::ds_endpoint(&base),
            base_shown: base,
        }
    } else {
        let key = if dry_run {
            String::new()
        } else {
            classify_api_key()?
        };
        let base = api_base.unwrap_or(classify::DEFAULT_API_BASE);
        Backend {
            name: "typesafe",
            key,
            model: model.to_owned(),
            endpoint: base.to_owned(),
            base_shown: base.to_owned(),
        }
    };
    Ok(backend)
}

/// Compare decision inputs without read-only access/heat counters or derived indexes.
pub fn classify_source_revision(memories: &[respire_app::StoredMemory]) -> serde_json::Value {
    let mut ordered: Vec<&respire_app::StoredMemory> = memories.iter().collect();
    ordered.sort_by(|left, right| left.id.cmp(&right.id));
    serde_json::Value::Array(ordered.into_iter().map(|memory| serde_json::json!({
        "id": memory.id, "user": memory.user, "ciphertext": memory.ciphertext,
        "nonce": memory.nonce, "updated_at": memory.updated_at, "deleted": memory.deleted,
        "parent_id": memory.local_parent_id, "title": memory.local_title,
        "kind": memory.local_kind, "tags": memory.local_tags,
        "content_head": memory.local_content_head, "importance": memory.local_importance,
    })).collect())
}

/// JEV API key: TYPESAFE_API_KEY env first, then api_key in <data-dir>/classify.json.
pub fn classify_api_key() -> Result<String> {
    if let Ok(k) = respire_app::env::var("TYPESAFE_API_KEY") {
        let k = k.trim().to_owned();
        if !k.is_empty() {
            return Ok(k);
        }
    }
    // The GUI "AI backend" dropdown stores the key in the system keyring (slot typesafe) - file and keyring both count
    if let Some(k) = respire_app::keystore::load_classify_key("typesafe") {
        return Ok(k);
    }
    let p = respire_app::service::data_dir().join("classify.json");
    if let Ok(text) = std::fs::read_to_string(&p) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(k) = v.get("api_key").and_then(|x| x.as_str()) {
                if !k.trim().is_empty() {
                    return Ok(k.trim().to_owned());
                }
            }
        }
    }
    anyhow::bail!(
        "JEV API key is not set: export TYPESAFE_API_KEY, or write {{\"api_key\":\"...\"}} into {} (apply: console.typesafe.ai/keys, waitlist).\nHint: without a TypeSafe account, use the DS backend - `rsrs classify --ds <key>`",
        p.display()
    )
}


pub fn run_audit(json_flag: bool) -> Result<()> {
    if json_flag {
        set_json_mode(true);
    }
    let store = build_local()?;
    let all = store.all(true)?;
    let by_id: std::collections::HashMap<&str, &respire_app::StoredMemory> = all
        .iter()
        .filter(|m| !m.deleted)
        .map(|m| (m.id.as_str(), m))
        .collect();
    let active: Vec<&respire_app::StoredMemory> = all.iter().filter(|m| !m.deleted).collect();

    // 1. orphans
    let orphans: Vec<&&respire_app::StoredMemory> = active
        .iter()
        .filter(|m| {
            !m.local_parent_id.is_empty() && !by_id.contains_key(m.local_parent_id.as_str())
        })
        .collect();
    // 2. illegal importance
    let bad_imp: Vec<&&respire_app::StoredMemory> = active
        .iter()
        .filter(|m| {
            !matches!(
                m.local_importance.as_str(),
                "important" | "normal" | "trivial"
            )
        })
        .collect();
    // 3. duplicate-title groups
    let mut by_title: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for m in &active {
        let t = m.local_title.trim();
        if !t.is_empty() {
            by_title.entry(t).or_default().push(m.id.as_str());
        }
    }
    let same_title: Vec<(&str, usize)> = by_title
        .iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(k, v)| (*k, v.len()))
        .collect();
    // 4. Truncated titles: title is a prefix of the body AND the cut is **mid-word** (next char is not a separator).
    //    "title is a body prefix" alone false-positives - tree roots (CATALOG title + gist) and
    //    entries whose body starts with the title are both prefix-matches with a complete title.
    const TITLE_SEP: &str = "\u{ff1a}:\u{ff0c},\u{3002}.\u{3001}\u{ff1b};\u{ff1f}\u{ff01}!\u{ff09})\u{3011}\u{300d}\u{300f}\"\u{201c}\u{201d} \n\t--/|\u{ff08}(\u{3010}\u{300a}\u{300c}\u{300e}";
    let truncated: Vec<&&respire_app::StoredMemory> = active
        .iter()
        .filter(|m| {
            let t = m.local_title.trim();
            if t.is_empty() || t.chars().count() > 20 {
                return false;
            }
            let head = &m.local_content_head;
            if !head.starts_with(t) {
                return false;
            }
            if head.chars().count() <= t.chars().count() + 10 {
                return false;
            }
            match head[t.len()..].chars().next() {
                Some(c) => !TITLE_SEP.contains(c),
                None => false,
            }
        })
        .collect();
    // 5. deep chains
    let depth = |id: &str| -> usize {
        let mut d = 0usize;
        let mut cur = Some(id.to_owned());
        while let Some(c) = cur {
            if d > 30 {
                break;
            }
            if let Some(pp) = by_id.get(c.as_str()) {
                let pid = pp.local_parent_id.clone();
                if pid.is_empty() {
                    break;
                }
                cur = Some(pid);
                d += 1;
            } else {
                break;
            }
        }
        d
    };
    let max_depth = active.iter().map(|m| depth(&m.id)).max().unwrap_or(0);
    // 6. Procedure template gaps: skill entries should read as a manual, not an essay.
    //    Needs the body, so decryption is best-effort: a locked store reports `skipped` instead of failing audit.
    let skills: Vec<&&respire_app::StoredMemory> = active
        .iter()
        .filter(|m| m.local_kind == "skill")
        .collect();
    // 7. Hot but untyped: frequently recalled, not a skill, and reads like a manual.
    //    Advisory for tidy only - the AI decides whether it is worth an upgrade.
    let hot_candidates: Vec<&&respire_app::StoredMemory> = active
        .iter()
        .filter(|m| {
            m.local_kind != "skill" && m.local_recall_count >= skill::HOT_RECALL_THRESHOLD
        })
        .collect();
    let bodies = if skills.is_empty() && hot_candidates.is_empty() {
        None
    } else {
        build_session().ok()
    };
    let mut skill_gaps: Vec<(String, String, Vec<&'static str>)> = Vec::new();
    let mut hot_untyped: Vec<(String, String, i64)> = Vec::new();
    if let Some(session) = &bodies {
        for m in &skills {
            if let Ok(full) = MemoryEngine::open(session, m) {
                let missing = skill::missing_sections(&full.content);
                if !missing.is_empty() {
                    skill_gaps.push((m.id.clone(), m.local_title.clone(), missing));
                }
            }
        }
        for m in &hot_candidates {
            if let Ok(full) = MemoryEngine::open(session, m) {
                if skill::looks_operational(&full.content) {
                    hot_untyped.push((
                        m.id.clone(),
                        m.local_title.clone(),
                        m.local_recall_count,
                    ));
                }
            }
        }
    }
    let skill_gaps_skipped = !skills.is_empty() && bodies.is_none();
    let hot_untyped_skipped = !hot_candidates.is_empty() && bodies.is_none();
    // 8. Procedures whose latest three runs all failed: doc says "keep it" but it is broken.
    let failing_skills = store.failing_skills(3)?;

    // M2 (2026-09-20 audit): previously only the local --json flag was honored;
    // RSRS_JSON=1 (what the GUI bridge sets) still printed prose, breaking cli-api.md "equivalent" output.
    if json_mode() || json_flag {
        let summary = serde_json::json!({
            "total_active": active.len(),
            "orphans": orphans.len(), "invalid_importance": bad_imp.len(),
            "same_title_groups": same_title.len(), "truncated_titles": truncated.len(),
            "max_depth": max_depth,
            "skill_template_gaps": skill_gaps.len(),
            "skill_template_gaps_skipped": skill_gaps_skipped,
            "failing_skills": failing_skills.len(),
            "hot_untyped": hot_untyped.len(),
            "hot_untyped_skipped": hot_untyped_skipped,
        });
        let mut result = ResultEnvelope::new(
            "audit",
            if orphans.is_empty()
                && bad_imp.is_empty()
                && truncated.is_empty()
                && skill_gaps.is_empty()
                && failing_skills.is_empty()
            {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            summary,
            Vec::new(),
        );
        result.actions.push("audit --json".into());
        let details = serde_json::json!({
            "orphans": orphans.iter().map(|m| serde_json::json!({"id": m.id, "title": m.local_title, "missing_parent": m.local_parent_id})).collect::<Vec<_>>(),
            "invalid_importance": bad_imp.iter().map(|m| serde_json::json!({"id": m.id, "title": m.local_title, "importance": m.local_importance})).collect::<Vec<_>>(),
            "same_title_groups": same_title.iter().map(|(t, n)| serde_json::json!({"title": t, "count": n})).collect::<Vec<_>>(),
            "truncated_titles": truncated.iter().map(|m| serde_json::json!({"id": m.id, "title": m.local_title})).collect::<Vec<_>>(),
            "skill_template_missing": skill_gaps.iter().map(|(id, title, missing)| serde_json::json!({"id": id, "title": title, "missing": missing})).collect::<Vec<_>>(),
            "failing_skills": failing_skills.iter().map(|(id, streak)| serde_json::json!({"id": id, "fail_streak": streak})).collect::<Vec<_>>(),
            "hot_untyped": hot_untyped.iter().map(|(id, title, count)| serde_json::json!({"id": id, "title": title, "recall_count": count})).collect::<Vec<_>>(),
        });
        result.details = details;
        emit_result(result)?;
        return Ok(());
    }
    let status = if orphans.is_empty()
        && bad_imp.is_empty()
        && truncated.is_empty()
        && skill_gaps.is_empty()
        && failing_skills.is_empty()
    {
        OutputStatus::Ok
    } else {
        OutputStatus::Warn
    };
    let mut items = vec![
        OutputItem::new("active", OutputStatus::Ok, active.len().to_string()),
        OutputItem::new(
            "orphans",
            if orphans.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            orphans.len().to_string(),
        ),
        OutputItem::new(
            "illegal importance",
            if bad_imp.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            bad_imp.len().to_string(),
        ),
        OutputItem::new(
            "duplicate titles",
            if same_title.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            same_title.len().to_string(),
        ),
        OutputItem::new(
            "truncated titles",
            if truncated.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            truncated.len().to_string(),
        ),
        OutputItem::new("max depth", OutputStatus::Ok, max_depth.to_string()),
        OutputItem::new(
            "skill template gaps",
            if skill_gaps.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            if skill_gaps_skipped {
                "skipped (locked)".to_owned()
            } else {
                skill_gaps.len().to_string()
            },
        ),
        OutputItem::new(
            "failing skills",
            if failing_skills.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            failing_skills.len().to_string(),
        ),
        OutputItem::new(
            "hot untyped",
            OutputStatus::Ok,
            if hot_untyped_skipped {
                "skipped (locked)".to_owned()
            } else {
                hot_untyped.len().to_string()
            },
        ),
    ];
    items.extend(orphans.iter().map(|m| {
        OutputItem::new(
            "orphan",
            OutputStatus::Warn,
            format!(
                "{} parent {}",
                respire_app::service::short_id(&m.id),
                m.local_parent_id
            ),
        )
        .action("resort")
    }));
    items.extend(bad_imp.iter().map(|m| {
        OutputItem::new(
            "illegal importance",
            OutputStatus::Warn,
            format!(
                "{} {}",
                respire_app::service::short_id(&m.id),
                m.local_importance
            ),
        )
    }));
    items.extend(same_title.iter().map(|(t, n)| {
        OutputItem::new(
            "duplicate title",
            OutputStatus::Warn,
            format!("{} count {}", t, n),
        )
    }));
    items.extend(skill_gaps.iter().map(|(id, title, missing)| {
        OutputItem::new(
            "skill template gap",
            OutputStatus::Warn,
            format!(
                "{} {} missing {}",
                respire_app::service::short_id(id),
                title,
                missing.join("/")
            ),
        )
        .action("update")
    }));
    items.extend(failing_skills.iter().map(|(id, streak)| {
        OutputItem::new(
            "failing skill",
            OutputStatus::Warn,
            format!("{} {} consecutive fail", respire_app::service::short_id(id), streak),
        )
        .action("run-log")
    }));
    items.extend(hot_untyped.iter().map(|(id, title, count)| {
        OutputItem::new(
            "hot untyped",
            OutputStatus::Ok,
            format!(
                "{} {} {count} hits",
                respire_app::service::short_id(id),
                title
            ),
        )
        .action("review: upgrade to skill only with evidence (run-log ok or user sign-off); keeping it as-is is a valid verdict")
    }));
    let mut result = ResultEnvelope::new(
        "audit",
        status,
        serde_json::json!({"total_active":active.len(),"orphans":orphans.len(),"invalid_importance":bad_imp.len(),"same_title_groups":same_title.len(),"truncated_titles":truncated.len(),"max_depth":max_depth,"skill_template_gaps":skill_gaps.len(),"skill_template_gaps_skipped":skill_gaps_skipped,"failing_skills":failing_skills.len()}),
        items,
    );
    result.actions.push("audit --json".into());
    emit_result(result)?;
    Ok(())
}

pub fn run_repack() -> Result<()> {
    let session = build_session()?;
    let store = build_local()?;
    let fixed = store.write_transaction(|| {
        let mut pending = Vec::new();
        for stored in store.all(true)? {
            let payload_parent = MemoryEngine::payload_parent(&session, &stored)?;
            if payload_parent != stored.local_parent_id {
                respire_app::metadata_gate::ensure_write(&store, &MemoryEngine::open(&session, &stored)?)?;
                pending.push(stored);
            }
        }
        for stored in &pending {
            let out = MemoryEngine::reseal_parent(
                &session,
                stored,
                &stored.local_parent_id,
                &stored.updated_at,
            )?;
            store.put_inner(&out, true)?;
        }
        Ok(pending.len())
    })?;
    auto_sync(&session, &store);
    emit_result(ResultEnvelope::new(
        "repack",
        OutputStatus::Ok,
        serde_json::json!({"fixed":fixed}),
        vec![OutputItem::new(
            "resealed",
            OutputStatus::Ok,
            fixed.to_string(),
        )],
    ))
}


pub fn emit_diary_fragments(command: &str, fragments: respire_app::diary::FragmentResult) -> Result<()> {
    if !json_mode() {
        println!("{}", serde_json::to_string(&fragments)?);
        return Ok(());
    }
    let mut result = ResultEnvelope::new(command, OutputStatus::Ok,
        serde_json::json!({"count":fragments.items.len(), "semantic_ready":fragments.semantic_ready,
            "pending_fragments":fragments.pending_fragments,"truncated":fragments.truncated,
            "max_chars":fragments.max_chars,"offset_unit":fragments.offset_unit}), Vec::new());
    result.details = serde_json::to_value(fragments)?;
    emit_result(result)
}

/// Diary = whole-store time chain (trivia is merged in; not filtered by importance):
pub fn run_diary(
    limit: usize,
    date: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    contains: Option<&str>,
) -> Result<()> {
    // Date aliases and check: today/yesterday resolve directly; else YYYY-MM-DD, bad format fails fast
    let today = chrono::Local::now().date_naive();
    let resolve_day = |s: &str| -> Result<chrono::NaiveDate> {
        match s {
            "today" => Ok(today),
            "yesterday" => Ok(today - chrono::Duration::days(1)),
            _ => chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .map_err(|_| anyhow!("date must be YYYY-MM-DD (or today/yesterday), got: {s}")),
        }
    };
    let date_day = date.map(resolve_day).transpose()?;
    let from_day = from.map(resolve_day).transpose()?;
    let to_day = to.map(resolve_day).transpose()?;
    if date_day.is_some() && (from_day.is_some() || to_day.is_some()) {
        anyhow::bail!("pick one of --date or --from/--to");
    }
    if let (Some(f), Some(t)) = (from_day, to_day) {
        if f > t {
            anyhow::bail!("--from is after --to: {f} > {t}");
        }
    }
    let date_s = date_day.map(|d| d.format("%Y-%m-%d").to_string());
    let from_s = from_day.map(|d| d.format("%Y-%m-%d").to_string());
    let to_s = to_day.map(|d| d.format("%Y-%m-%d").to_string());
    let needle = contains.map(|s| s.to_lowercase());

    let store = build_local()?;
    let mut all: Vec<respire_app::StoredMemory> = store
        .all(false)?
        .into_iter()
        .filter(|m| {
            let d = local_day_of(&m.local_created_at);
            if let Some(dd) = &date_s {
                return d == *dd;
            }
            if let Some(f) = &from_s {
                if d < *f {
                    return false;
                }
            }
            if let Some(t) = &to_s {
                if d > *t {
                    return false;
                }
            }
            true
        })
        .collect();
    if let Some(needle) = &needle {
        let keys = build_session()?;
        let mut matched = Vec::new();
        for mut memory in all {
            let entry = MemoryEngine::open(&keys, &memory)
                .with_context(|| format!("cannot decode diary entry {}", memory.id))?;
            let lowered = entry.content.to_lowercase();
            let position = lowered.find(needle);
            if position.is_some() || entry.title.to_lowercase().contains(needle) {
                // Map the lowercased byte match back to original Unicode scalars.
                let offset = position.map(|byte| {
                    let mut folded_bytes = 0;
                    entry.content.chars().take_while(|ch| {
                        let before = folded_bytes;
                        folded_bytes += ch.to_lowercase().map(char::len_utf8).sum::<usize>();
                        before < byte
                    }).count()
                }).unwrap_or(0);
                let start = offset.saturating_sub(100);
                memory.local_content_head = entry.content.chars().skip(start).take(500).collect();
                matched.push(memory);
            }
        }
        all = matched;
    }
    let ranged = date_s.is_some() || from_s.is_some() || to_s.is_some();
    if ranged {
        all.sort_by(|a, b| a.local_created_at.cmp(&b.local_created_at));
    } else {
        all.sort_by(|a, b| b.local_created_at.cmp(&a.local_created_at));
        all.truncate(limit);
    }
    if json_mode() {
        let rows: Vec<serde_json::Value> = all
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id, "created_at": m.local_created_at,
                    "day": local_day_of(&m.local_created_at),
                    "kind": m.local_kind, "importance": m.local_importance,
                    "title": m.local_title,
                    "content": m.local_content_head,
                    // Device tag: how an AI tells which machine recorded this (old data is empty)
                    "device": m.local_device,
                    "modified_by": m.local_modified_by,
                })
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "diary",
            OutputStatus::Ok,
            serde_json::json!({"count":rows.len()}),
            rows.iter()
                .map(|row| {
                    OutputItem::new(
                        row["id"].as_str().unwrap_or(""),
                        OutputStatus::Ok,
                        row["title"].as_str().unwrap_or(""),
                    )
                })
                .collect(),
        );
        result.details = serde_json::Value::Array(rows);
        emit_result(result)?;
        return Ok(());
    }
    if all.is_empty() {
        emit_result(ResultEnvelope::new(
            "diary",
            OutputStatus::Skip,
            serde_json::json!({"count":0}),
            vec![
                OutputItem::new("entries", OutputStatus::Skip, "0").action("widen date or keyword")
            ],
        ))?;
        return Ok(());
    }
    let strip = |s: &str| -> String {
        s.strip_prefix("[diary]")
            .map(|r| r.to_owned())
            .unwrap_or_else(|| s.to_owned())
    };
    let title_of = |m: &respire_app::StoredMemory| -> String {
        let head = strip(&m.local_content_head);
        let head = head.lines().next().unwrap_or("").to_owned();
        if m.local_title.trim().is_empty() {
            head
        } else {
            m.local_title.trim().to_owned()
        }
    };
    let mut items = Vec::new();
    let mut detail_rows = Vec::new();
    for m in &all {
        let dt = chrono::DateTime::parse_from_rfc3339(&m.local_created_at).ok();
        let d = dt
            .as_ref()
            .map(|x| {
                x.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d")
                    .to_string()
            })
            .unwrap_or_else(|| local_day_of(&m.local_created_at));
        let t = dt
            .map(|x| x.with_timezone(&chrono::Local).format("%H:%M").to_string())
            .unwrap_or_else(|| "--:--".to_owned());
        // Device label: diary rows also say which machine recorded them, so paths/commands are not copied across devices.
        let dev = dev_label(&m.local_device, &m.local_computer);
        let title = title_of(m);
        items.push(OutputItem::new(
            "entry",
            OutputStatus::Ok,
            format!("{} {} {} {}", d, t, title, dev),
        ));
        detail_rows.push(serde_json::json!({"id":m.id,"day":d,"time":t,"title":title,"kind":m.local_kind,"importance":m.local_importance,"device":dev,"content":strip(&m.local_content_head)}));
    }
    let mut result = ResultEnvelope::new(
        "diary",
        OutputStatus::Ok,
        serde_json::json!({"count":all.len(),"date":date_s,"from":from_s,"to":to_s,"contains":needle}),
        items,
    );
    result.details = serde_json::Value::Array(detail_rows);
    emit_result(result)?;
    Ok(())
}

/// Built-in catalog: --list prints it; --ensure <root,...> creates/fills roots; no args shows current state (built roots + lone roots).
pub fn run_taxonomy(list: bool, ensure: Option<&str>) -> Result<()> {
    if list {
        let items = respire_app::taxonomy::CATALOG
            .iter()
            .map(|c| {
                OutputItem::new(
                    if c.ai { "AI-domain" } else { "human-domain" },
                    OutputStatus::Ok,
                    format!("{} - {}", c.title, c.gist),
                )
            })
            .collect();
        return emit_result(ResultEnvelope::new(
            "taxonomy",
            OutputStatus::Ok,
            serde_json::json!({"count":respire_app::taxonomy::CATALOG.len()}),
            items,
        ));
    }
    let app = respire_app::service::App::open()?;
    match ensure {
        Some(names) => {
            let mut built: Vec<(String, String)> = Vec::new();
            for name in names.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let Some(idx) = respire_app::taxonomy::find_by_title(name) else {
                    anyhow::bail!("\"{name}\" is not a built-in catalog root - see rsrs taxonomy --list; a root outside the catalog uses root-create (needs the user to say yes)");
                };
                let rid = respire_app::taxonomy::ensure_category_root(
                    &app.keys,
                    &app.embedder,
                    &app.store,
                    idx,
                )?;
                built.push((name.to_owned(), rid));
            }
            auto_sync(&app.keys, &app.store);
            let mut result = ResultEnvelope::new(
                "taxonomy",
                OutputStatus::Ok,
                serde_json::json!({"ensured":built.len()}),
                built
                    .iter()
                    .map(|(t, id)| {
                        OutputItem::new(t, OutputStatus::Ok, respire_app::service::short_id(id))
                    })
                    .collect(),
            );
            result.details = serde_json::json!(built
                .iter()
                .map(|(t, id)| serde_json::json!({"title":t,"root_id":id}))
                .collect::<Vec<_>>());
            emit_result(result)?;
        }
        None => {
            let all = app.store.all(false)?;
            let mut built = 0usize;
            let mut missing: Vec<&str> = Vec::new();
            for c in respire_app::taxonomy::CATALOG.iter() {
                let rid = respire_app::taxonomy::root_id(c.title);
                if all.iter().any(|m| m.id == rid) {
                    built += 1;
                } else {
                    missing.push(c.title);
                }
            }
            let lone = respire_app::taxonomy::lone_roots(&app.store)?;
            let mut result = ResultEnvelope::new(
                "taxonomy",
                if missing.is_empty() {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Warn
                },
                serde_json::json!({"total":respire_app::taxonomy::CATALOG.len(),"built":built,"missing":missing,"lone_roots":lone.len()}),
                vec![
                    OutputItem::new("built", OutputStatus::Ok, built.to_string()),
                    OutputItem::new(
                        "lone roots",
                        if lone.is_empty() {
                            OutputStatus::Ok
                        } else {
                            OutputStatus::Warn
                        },
                        lone.len().to_string(),
                    ),
                ],
            );
            result.actions.push("taxonomy --ensure <roots>".into());
            emit_result(result)?;
        }
    }
    Ok(())
}

/// Create a root outside the catalog: AI proposes -> user allows -> --yes writes. Without --yes, only print the ask; do not write.
pub fn run_root_create(title: &str, content: Option<&str>, yes: bool) -> Result<()> {
    if respire_app::taxonomy::find_by_title(title).is_some() {
        anyhow::bail!("\"{title}\" is already a built-in catalog root - rsrs taxonomy --ensure \"{title}\" creates it");
    }
    if !yes {
        let msg = format!(
            "creating a top-level root needs the user to say yes: ask \"create top-level '{title}'? gist: {}\" - rerun with --yes after they allow it; do not create without that",
            content.unwrap_or(title)
        );
        let mut result = ResultEnvelope::new(
            "root-create",
            OutputStatus::Pending,
            serde_json::json!({"title":title,"content":content.unwrap_or(title)}),
            vec![
                OutputItem::new("confirmation", OutputStatus::Pending, msg.clone())
                    .action("rerun with --yes after user approval"),
            ],
        );
        result.actions.push("root-create --yes".into());
        emit_result(result)?;
        return Ok(());
    }
    let app = respire_app::service::App::open()?;
    let clash = app
        .store
        .all(false)?
        .into_iter()
        .any(|m| m.local_title == title);
    if clash {
        anyhow::bail!("an entry titled \"{title}\" already exists - rename, or hang under it (rsrs show for the id)");
    }
    let rid = respire_app::taxonomy::root_id(title);
    let now = now_stamp();
    let entry = respire_app::MemoryEntry {
        metadata: Default::default(),
        unknown_fields: Default::default(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: Vec::new(),
        id: rid.clone(),
        kind: Kind::Knowledge,
        tags: vec!["catalog root".to_owned(), "custom".to_owned()],
        title: title.to_owned(),
        content: content.unwrap_or(title).to_owned(),
        user: current_user(),
        computer: respire_app::service::device_tag(),
        device: respire_app::service::device_tag(),
        modified_by: respire_app::service::device_tag(),
        project: String::new(),
        created_at: now.clone(),
        updated_at: now,
        emotion: -1.0,
        parent_id: String::new(),
        importance: "important".to_owned(),
    };
    let stored = MemoryEngine::seal(&app.keys, &app.embedder, &entry, &entry.user)?;
    app.store.put(&stored)?;
    auto_sync(&app.keys, &app.store);
    let mut result = ResultEnvelope::new(
        "root-create",
        OutputStatus::Ok,
        serde_json::json!({ "root_id": rid, "title": title }),
        vec![OutputItem::new(
            "root",
            OutputStatus::Ok,
            respire_app::service::short_id(&rid),
        )],
    );
    result.actions.push(format!(
        "remember <body> --parent {}",
        respire_app::service::short_id(&rid)
    ));
    emit_result(result)?;
    Ok(())
}

/// Tree hygiene: report (root sizes + attach suggestions) or apply (--id --parent).
pub fn run_tree_cure(
    top: usize,
    id: Option<&str>,
    parent: Option<&str>,
    auto: bool,
    min: f32,
) -> Result<()> {
    if auto {
        let app = respire_app::service::App::open()?;
        let candidates = app.store.all(false)?;
        respire_app::service::require_candidates_ready(&app.store, &candidates)?;
        let report: respire_app::core_sdk::reports::TreeCureReport = respire_app::core_sdk::execute(
            "tree_cure",
            serde_json::json!({
                "snapshots": respire_app::core_sdk::metadata_snapshots(&candidates),
                "top": top, "min": min, "auto": true,
            }),
        )?;
        app.store.write_transaction(|| {
            let current = app.store.all(false)?;
            for suggestion in &report.suggests {
                let row = current.iter().find(|row| row.id == suggestion.orphan.id)
                    .ok_or_else(|| anyhow!("tree-cure memory disappeared: {}", suggestion.orphan.id))?;
                respire_app::metadata_gate::ensure_write(&app.store, &MemoryEngine::open(&app.keys, row)?)?;
            }
            for suggestion in &report.suggests {
                respire_app::service::reparent(
                    &app.keys,
                    &app.store,
                    &suggestion.orphan.id,
                    &suggestion.target.id,
                )?;
            }
            Ok(())
        })?;
        if !report.suggests.is_empty() {
            auto_sync(&app.keys, &app.store);
        }
        let items = report
            .suggests
            .iter()
            .map(|suggestion| {
                OutputItem::new(
                    "attach",
                    OutputStatus::Ok,
                    format!(
                        "{} -> {}",
                        suggestion.orphan.title, suggestion.target_tree.title
                    ),
                )
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"attached": report.suggests.len(), "failed": 0, "threshold": min}),
            items,
        );
        result.details = serde_json::to_value(&report)?;
        emit_result(result)?;
        return Ok(());
    }
    let app = respire_app::service::App::open()?;
    if let (Some(id), Some(parent)) = (id, parent) {
        let (child, parent_full) = app.attach(id, parent)?;
        emit_result(ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"child":child,"parent":parent_full}),
            vec![
                OutputItem::new(
                    "child",
                    OutputStatus::Ok,
                    respire_app::service::short_id(&child),
                ),
                OutputItem::new(
                    "parent",
                    OutputStatus::Ok,
                    respire_app::service::short_id(&parent_full),
                ),
            ],
        ))?;
        return Ok(());
    }
    let report = app.tree_cure_with_min(top, min)?;
    if json_mode() {
        let mut result = ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"roots":report.roots,"suggestions":report.suggests.len()}),
            Vec::new(),
        );
        result.details = serde_json::to_value(&report)?;
        emit_result(result)?;
        return Ok(());
    }
    let mut items = vec![OutputItem::new(
        "roots",
        OutputStatus::Ok,
        format!(
            "{} total, {} lone leaf",
            report.roots.len(),
            report.lone_roots
        ),
    )];
    for r in report.roots.iter().take(top) {
        items.push(OutputItem::new(
            "root",
            OutputStatus::Ok,
            format!(
                "{} children {} {}",
                r.descendants,
                r.title,
                respire_app::service::short_id(&r.id)
            ),
        ));
    }
    if report.suggests.is_empty() {
        emit_result(ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"roots":report.roots.len(),"suggestions":0,"threshold":min}),
            items,
        ))?;
        return Ok(());
    }
    for s in &report.suggests {
        items.push(
            OutputItem::new(
                "suggestion",
                OutputStatus::Pending,
                format!(
                    "{} {} -> {} {} tree {}",
                    s.orphan.title,
                    respire_app::service::short_id(&s.orphan.id),
                    s.target.title,
                    respire_app::service::short_id(&s.target.id),
                    s.target_tree.title
                ),
            )
            .action("tree-cure --id <id> --parent <parent>"),
        );
    }
    let mut result = ResultEnvelope::new(
        "tree-cure",
        OutputStatus::Pending,
        serde_json::json!({"roots":report.roots.len(),"suggestions":report.suggests.len(),"threshold":min}),
        items,
    );
    result
        .actions
        .push("tree-cure --id <lone-id> --parent <target-id>".into());
    emit_result(result)?;
    Ok(())
}

/// Heat float: high-hit memories move up the cause chain (reattach to grandparent); the tree self-organizes by recall heat.
/// Dry-run prints a report (hot entry -> new cause); --go applies.
pub fn run_tree_float(go: bool, min: i64) -> Result<()> {
    let app = respire_app::service::App::open()?;
    let report = app.tree_float(go, min)?;
    if json_mode() {
        let mut result = ResultEnvelope::new(
            "tree-float",
            if report.items.is_empty() {
                OutputStatus::Ok
            } else if go {
                OutputStatus::Ok
            } else {
                OutputStatus::Pending
            },
            serde_json::json!({"items":report.items.len(),"applied":report.applied}),
            Vec::new(),
        );
        result.details = serde_json::to_value(&report)?;
        if !go && !report.items.is_empty() {
            result.actions.push("tree-float --go".into());
        }
        emit_result(result)?;
        return Ok(());
    }
    if report.items.is_empty() {
        emit_result(ResultEnvelope::new(
            "tree-float",
            OutputStatus::Ok,
            serde_json::json!({"items":0,"applied":report.applied,"min_hits":min}),
            vec![OutputItem::new("candidates", OutputStatus::Ok, "0")],
        ))?;
        return Ok(());
    }
    let mut items = Vec::new();
    for it in &report.items {
        items.push(
            OutputItem::new(
                "candidate",
                if go {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Pending
                },
                format!(
                    "{} hits {} {} -> {} {}",
                    it.recall_count,
                    it.title,
                    respire_app::service::short_id(&it.id),
                    it.new_parent_title,
                    respire_app::service::short_id(&it.new_parent)
                ),
            )
            .action(if go { "applied" } else { "tree-float --go" }),
        );
    }
    let mut result = ResultEnvelope::new(
        "tree-float",
        if go {
            OutputStatus::Ok
        } else {
            OutputStatus::Pending
        },
        serde_json::json!({"items":report.items.len(),"applied":report.applied,"min_hits":min}),
        items,
    );
    if !go {
        result.actions.push("tree-float --go".into());
    }
    emit_result(result)?;
    Ok(())
}

/// Ask Core for a read-only report of related entries and tree structure.
///
/// **Trivia is not in the tree** (fixed 2026-09-20): drop trivial the same way as `tree`/`tree_cure_with_min` -
/// trivia belongs in the diary (inject §3.4); mixing it in inflates the tree bill (once reported "27 roots" vs a real 23).
/// Orphans after the drop (parent was trivia) count as promoted-to-root, same as `tree`.
pub fn run_defrag(min: f32, top: usize) -> Result<()> {
    use respire_app::memory::defrag;
    let store = build_local()?;
    let list = respire_app::service::tree_scope_list(&store.all(false)?);
    respire_app::service::require_candidates_ready(&store, &list)?;
    let report = defrag::analyze(&list, min)?;
    if json_mode() {
        let mut result = ResultEnvelope::new(
            "defrag",
            OutputStatus::Ok,
            serde_json::json!({"roots":report.roots,"clusters":report.clusters.len()}),
            Vec::new(),
        );
        result.details = serde_json::to_value(&report)?;
        emit_result(result)?;
        return Ok(());
    }
    let mut items = vec![
        OutputItem::new("active", OutputStatus::Ok, list.len().to_string()),
        OutputItem::new(
            "tree",
            OutputStatus::Ok,
            format!(
                "{} roots, max depth {}, {} lone leaves",
                report.roots, report.max_depth, report.orphans
            ),
        ),
    ];
    if report.clusters.is_empty() {
        emit_result(ResultEnvelope::new(
            "defrag",
            OutputStatus::Ok,
            serde_json::json!({"active":list.len(),"clusters":0,"threshold":min}),
            items,
        ))?;
        return Ok(());
    }
    if report.settled > 0 {
        items.push(OutputItem::new(
            "settled clusters",
            OutputStatus::Ok,
            report.settled.to_string(),
        ));
    }
    for (i, c) in report.clusters.iter().take(top).enumerate() {
        items.push(OutputItem::new(
            format!("cluster {}", i + 1),
            OutputStatus::Pending,
            format!("{} members", c.members.len()),
        ));
        for m in &c.members {
            items.push(OutputItem::new(
                "member",
                OutputStatus::Pending,
                format!(
                    "depth {} date {} id {} {}",
                    m.depth,
                    m.date,
                    &m.id[..m.id.len().min(8)],
                    m.title
                ),
            ));
        }
    }
    if report.clusters.len() > top {
        items.push(
            OutputItem::new(
                "omitted clusters",
                OutputStatus::Skip,
                (report.clusters.len() - top).to_string(),
            )
            .action("raise --top"),
        );
    }
    let mut result = ResultEnvelope::new(
        "defrag",
        OutputStatus::Pending,
        serde_json::json!({"active":list.len(),"clusters":report.clusters.len(),"threshold":min,"shown":top.min(report.clusters.len())}),
        items,
    );
    result
        .actions
        .push("review clusters and use remember --merge-ids or --parent".into());
    emit_result(result)?;
    Ok(())
}

pub fn run_doctor(check_remote: bool, check_update: bool, fix: bool) -> Result<()> {
    progress::phase("\u{68c0}\u{67e5}\u{672c}\u{5730}\u{6570}\u{636e}\u{548c}\u{6587}\u{4ef6}", "Checking local data and files");
    let mut items: Vec<(String, bool, String)> = Vec::new();
    let mut model_warnings = Vec::new();
    let add = |items: &mut Vec<(String, bool, String)>, name: &str, ok: bool, note: String| {
        items.push((name.to_owned(), ok, note));
    };

    match respire_app::migration::pending_legacy_profiles() {
        Ok(profiles) if !profiles.is_empty() => {
            add(&mut items, "migration", true,
                format!("{} legacy account(s) not migrated: {}; use rsrs migrate or TUI Accounts > Migrate; no automatic migration", profiles.len(), profiles.iter().filter_map(|profile| profile["source"].as_str()).collect::<Vec<_>>().join(", ")));
            model_warnings.push("migration");
        }
        Ok(_) => {}
        Err(error) => add(&mut items, "migration", false, format!("discovery failed: {error:#}")),
    }

    // 1) data dir and store
    let dd = respire_app::service::data_dir();
    let db = respire_app::service::database_path(&dd)?;
    if db.exists() {
        let store = build_local();
        match store {
            Ok(s) => {
                let n = s.all(true).map(|v| v.len()).unwrap_or(0);
                add(
                    &mut items,
                    "store",
                    true,
                    format!("{} ({} entries)", db.display(), n),
                );
            }
            Err(e) => add(&mut items, "store", false, format!("open failed: {e}")),
        }
    } else {
        add(
            &mut items,
            "store",
            false,
            format!(
                "{} does not exist - register/login or keygen first",
                db.display()
            ),
        );
    }
    add(&mut items, "data dir", true, dd.display().to_string());

    match crate::host_hooks::materialize_bin() {
        Ok(path) => add(
            &mut items,
            "mcp bin",
            true,
            format!(
                "{} (MCP stdio command; not the npm JS shim)",
                path.display()
            ),
        ),
        Err(err) => add(&mut items, "mcp bin", false, err),
    }
    add(
        &mut items,
        "mcp http",
        true,
        format!(
            "The internal runtime serves POST /mcp and GET /sse (default {}/mcp)",
            crate::net_rpc::rpc_base_url()
        ),
    );

    // 2) session (can we unlock)
    progress::phase("\u{68c0}\u{67e5}\u{8d26}\u{6237}\u{548c}\u{89e3}\u{5bc6}\u{5bc6}\u{94a5}", "Checking account and decryption keys");
    match auth::load_local_session() {
        Ok(_) => add(
            &mut items,
            "session",
            true,
            "five-keys complete, can unlock".to_owned(),
        ),
        Err(e) => add(&mut items, "session", false, format!("{e}")),
    }

    // The resident index worker owns preparation. Do not start a second installer
    // while it downloads, or wait here while holding its foreground command slot.
    let store = build_local()?;
    let active_model = store.retrieval_model()?;
    progress::phase("\u{68c0}\u{67e5}\u{6a21}\u{578b}\u{548c}\u{7d22}\u{5f15}", "Checking model and index");
    let pending_index = store.index_pending(&active_model);
    let model_task = crate::model_progress::status()?;
    let model_busy = model_task["active"].as_bool() == Some(true);
    let mut index_state = rpc::index_status();
    let defer_preparation = rpc::worker_active()
        && pending_index.as_ref().is_ok_and(|pending| *pending)
        && (fix || model_busy || index_state["scheduled"].as_bool() == Some(true)
            || index_state["running"].as_bool() == Some(true));
    if defer_preparation {
        if fix {
            rpc::kick_index();
        }
        model_warnings.push("embedder");
        add(&mut items, "embedder", false,
            format!("{active_model} preparation/indexing {} through the runtime; model task: {}. No second installer started",
                if model_busy { "in progress" } else { "scheduled" }, model_task));
    } else if model_busy {
        model_warnings.push("embedder");
        add(&mut items, "embedder", false,
            format!("Model operation in progress: {model_task}; inference check deferred"));
    } else {
        // Diagnostics remain read-only unless --fix is explicit.
        match BgeEmbedder::load_model(&active_model) {
            Ok(e) => match e.probe("BGE-M3 doctor inference") {
                Ok(probe) => add(&mut items, "embedder", true, format!("{active_model} {} dims; inference verified ({})", e.dims(), probe["selected"])),
                Err(error) => add(&mut items, "embedder", false, format!("{active_model} inference failed: {error:#}")),
            },
            Err(e) if !fix => {
                add(
                    &mut items,
                    "embedder",
                    false,
                    format!("{active_model} unavailable: {e} (inspect model-task progress and the selected profile resources)"),
                );
            }
            Err(error) if store.active_selection()?.is_some() => {
                let selection = store.active_selection()?.context("active profile missing")?;
                let prepared = respire_app::embedding::prepare(&selection,|_,_,_|Ok(()))
                    .and_then(|_| BgeEmbedder::load_model(&active_model)?.probe("Respire doctor inference"));
                match prepared {
                    Ok(probe) => add(&mut items,"embedder",true,format!("{active_model}; inference verified ({})",probe["selected"])),
                    Err(repair) => add(&mut items,"embedder",false,format!("{active_model} unavailable: {error:#}; profile preparation failed: {repair:#}")),
                }
            }
            Err(_) => {
                progress::phase("\u{4e0b}\u{8f7d} BGE-M3 \u{6a21}\u{578b}", "Downloading BGE-M3 model");
                let mirror = crate::model_install::mirror_from_env();
                let install = crate::model_install::install_m3(mirror.as_deref());
                match install {
                    Ok(report) => match BgeEmbedder::load_model(&active_model) {
                        Ok(e) => match e.probe("BGE-M3 doctor inference") {
                            Ok(probe) => add(&mut items, "embedder", true, format!("BGE-M3 {} dims; inference verified ({}) (auto-installed {})", e.dims(), probe["selected"], report.dir.display())),
                            Err(error) => add(&mut items, "embedder", false, format!("BGE-M3 inference failed after install: {error:#}")),
                        },
                        Err(e) => add(
                            &mut items,
                            "embedder",
                            false,
                            format!("still failed to load after install: {e}"),
                        ),
                    },
                    Err(e) => add(
                        &mut items,
                        "embedder",
                        false,
                        format!(
                            "auto-install failed: {e}"
                        ),
                    ),
                }
            }
        }
    }

    match pending_index {
        Ok(true) => {
            let indexing = rpc::index_status();
            index_state = indexing.clone();
            let progressing = indexing["running"].as_bool() == Some(true)
                || indexing["scheduled"].as_bool() == Some(true)
                || (model_busy && indexing["state"].as_str() != Some("failed"));
            if progressing {
                model_warnings.push("model index");
            }
            add(&mut items, "model index", false,
                format!("BGE-M3 index pending; runtime status: {indexing}"));
        }
        Ok(false) => add(&mut items, "model index", true, "BGE-M3 index ready".to_owned()),
        Err(error) => add(&mut items, "model index", false, format!("BGE-M3 index check failed: {error:#}")),
    }

    // 4) lock: main already holds it exclusively (reaching here proves lock.db is takeable) - never take it twice; two connections in one process deadlock
    add(
        &mut items,
        "lock",
        true,
        "this process holds lock.db exclusively (other sessions wait)".to_owned(),
    );

    // 5) remote (config + optional reachability)
    let configured = remote_configured();
    progress::phase("\u{68c0}\u{67e5}\u{670d}\u{52a1}\u{5668}\u{8fde}\u{63a5}\u{ff1b}\u{7b49}\u{5f85}\u{54cd}\u{5e94}", "Checking server connection; waiting for response");
    if configured {
        let (addr, _tok) = remote_config_from_session_or_env()?.unwrap_or_default();
        if check_remote {
            match ureq::get(&format!("{}/health", addr.trim().trim_end_matches('/')))
                .timeout(std::time::Duration::from_secs(5))
                .call()
            {
                Ok(r) => add(
                    &mut items,
                    "remote",
                    true,
                    format!("{addr} /health -> {}", r.status()),
                ),
                Err(e) => add(
                    &mut items,
                    "remote",
                    false,
                    format!("{addr} unreachable: {e}"),
                ),
            }
        } else {
            add(
                &mut items,
                "remote",
                true,
                format!("{addr} (--remote probes reachability)"),
            );
        }
    } else {
        add(
            &mut items,
            "remote",
            true,
            "not configured (local-only)".to_owned(),
        );
    }

    // 6) inject status
    progress::phase("\u{68c0}\u{67e5}\u{5de5}\u{5177}\u{6ce8}\u{5165}\u{72b6}\u{6001}", "Checking tool injection status");
    match respire_app::inject::targets() {
        Ok(ts) => {
            let fresh = ts.iter().filter(|t| t.state == "fresh").count();
            let detected = ts.iter().filter(|t| t.likely_installed).count();
            add(
                &mut items,
                "inject",
                fresh > 0,
                format!("{fresh}/{detected} injected and fresh ({detected} detected)"),
            );
        }
        Err(e) => add(&mut items, "inject", false, format!("{e}")),
    }

    // 6.5) workspace three-state (added 2026-09-21): normal r/w | read-only | temporarily off
    {
        let (ok, note) = match respire_app::service::workspace_mode() {
            "normal" => (true, "read/write".to_owned()),
            "readonly" => (true, "read-only (writes rejected; team read-only is enforced by the server token)".to_owned()),
            _ => (
                false,
                "temporarily off - recall and store are stopped; `agent-config --set workspace_mode=normal` to restore".to_owned(),
            ),
        };
        add(&mut items, "memory status", ok, note);
    }

    // 8) tidy counter (auto: writes hitting the threshold print TIDY; resort --go resets)
    let (n, t) = respire_app::service::counter_peek(&respire_app::service::maintenance_path());
    add(
        &mut items,
        "tidy counter",
        n < t,
        format!("{n}/{t} - new since last tidy (TIDY when the threshold is hit; reset after tidy)"),
    );

    let runtime_version = if rpc::worker_active() {
        Some(crate::app_version::embedded().to_owned())
    } else {
        crate::host_hooks::runtime_brief().map(|(_, _, version)| version)
    };
    add(
        &mut items,
        "Runtime version",
        true,
        runtime_version.clone().unwrap_or_else(|| "not connected".to_owned()),
    );

    // 9) CLI version (--check-update or RSRS_UPDATE_CHECK=1 hits the network; default reads cache, no network)
    //    Doctor must not stall on the network, so it does not force a query - report known result, hint how to check if no cache.
    if crate::host_hooks::update_enabled() {
        progress::phase("\u{68c0}\u{67e5} CLI \u{7248}\u{672c}\u{ff1b}\u{7b49}\u{5f85}\u{7248}\u{672c}\u{6e90}", "Checking CLI version; waiting for version registry");
        let force = check_update;
        match crate::host_hooks::update_check_run(force) {
            Some(s) if s.outdated => add(
                &mut items,
                "CLI version",
                false,
                format!(
                    "{} -> {} newer available ({}) - npm i -g rsrs-cli@latest",
                    s.current,
                    s.latest,
                    if s.cached { "cache" } else { "just checked" }
                ),
            ),
            Some(s) => add(
                &mut items,
                "CLI version",
                true,
                format!("{} is latest ({})", s.current, if s.cached { "cache" } else { "just checked" }),
            ),
            None => add(
                &mut items,
                "CLI version",
                true,
                format!("{} (not checked - add --check-update to query, or set RSRS_UPDATE_CHECK=0 to disable)", crate::app_version::embedded()),
            ),
        }
    } else {
        add(
            &mut items,
            "CLI version",
            true,
            format!("{} (update check disabled)", crate::app_version::embedded()),
        );
    }

    let rows: Vec<OutputItem> = items
        .iter()
        .map(|(name, ok, note)| {
            let status = if name == "remote" && note.starts_with("not configured") {
                OutputStatus::Skip
            } else if name == "CLI version" && note.contains("not checked") {
                OutputStatus::Skip
            } else if name == "Runtime version" && runtime_version.is_none() {
                OutputStatus::Skip
            } else if name == "tidy counter" && *ok && note.contains("threshold is hit") {
                OutputStatus::Warn
            } else if model_warnings.contains(&name.as_str()) {
                OutputStatus::Warn
            } else if *ok {
                OutputStatus::Ok
            } else {
                OutputStatus::Fail
            };
            OutputItem::new(name, status, note)
        })
        .collect();
    let status = output::status_from_items(&rows);
    let pass = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Ok))
        .count();
    let warn = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Warn))
        .count();
    let fail = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Fail))
        .count();
    let skip = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Skip))
        .count();
    let mut result = ResultEnvelope::new(
        "doctor",
        status,
        serde_json::json!({ "version": crate::app_version::embedded(), "runtime_version": runtime_version, "pass": pass, "warn": warn, "fail": fail, "skip": skip, "total": rows.len() }),
        rows,
    );
    result.details = serde_json::json!({
        "model_operation": model_task,
        "retrieval_index": index_state,
    });
    emit_result(result)
}

/// One bounded network pass on the runtime synchronization worker.
pub fn background_sync_once() -> Result<bool> {
    if respire_app::service::service_paused() { return Ok(false); }
    let configured = sync_phase(|| Ok(respire_app::service::autosync_active() && remote_configured()))?;
    if !configured {
        return Ok(false);
    }
    let (session, local, remote) =
        sync_phase(|| Ok((build_session()?, build_local()?, build_remote()?)))?;
    let stats = sync_with_retry(&session, &local, &remote)?;
    eprintln!(
        "command=sync status=ok mode=auto pulled={} pushed={}",
        stats.pulled, stats.pushed
    );
    crate::hooks::fire(
        crate::hooks::HookEvent::PostSync,
        crate::hooks::sync_payload(stats.pulled, stats.pushed),
    );
    Ok(true)
}

/// Implicit synchronization only notifies the resident runtime after local commit.
/// Direct writes leave durable work for an explicit sync or runtime recovery.
pub fn schedule_autosync(_session: &SessionKeys, _local: &LocalStore) {
    if rpc::worker_active() && respire_app::service::autosync_active() && remote_configured() {
        rpc::kick_autosync();
    }
}
pub fn auto_sync(session: &SessionKeys, local: &LocalStore) {
    schedule_autosync(session, local);
}


pub fn run_passport() -> Result<()> {
    let si = respire_app::service::session_info();
    let st = respire_app::service::status_light().ok();
    let alive = st.as_ref().map(|s| s.local_alive).unwrap_or(0);
    let devices = respire_app::service::open_store()
        .and_then(|s| s.devices_count())
        .unwrap_or(0);
    let agents = respire_app::inject::targets()
        .map(|ts| {
            ts.iter()
                .filter(|t| t.state == "fresh" || t.state == "stale")
                .count()
        })
        .unwrap_or(0);
    let user = {
        let u = si.user.trim();
        if u.is_empty() {
            "local".to_owned()
        } else {
            u.to_owned()
        }
    };
    let items = vec![
        OutputItem::new("user", OutputStatus::Ok, user.clone()),
        OutputItem::new("memories", OutputStatus::Ok, alive.to_string()),
        OutputItem::new("agents", OutputStatus::Ok, agents.to_string()),
        OutputItem::new("devices", OutputStatus::Ok, devices.to_string()),
    ];
    let mut result = ResultEnvelope::new(
        "passport",
        OutputStatus::Ok,
        serde_json::json!({
            "user": user,
            "memories": alive,
            "agents": agents,
            "devices": devices,
        }),
        items,
    );
    result.details = serde_json::json!({
        "local_first": true,
        "encrypted_sync": true,
        "user_owned": true,
    });
    emit_result(result)
}

/// App::open success -> StatusInfo (unlocked); not unlocked -> None.
pub fn open_app_status() -> Option<respire_app::service::StatusInfo> {
    let app = respire_app::service::App::open().ok()?;
    app.status().ok()
}

/// Subtree material: export this node's subtree as Markdown (for an external AI/App to install).
/// 2026-09-21: moved here from `scope --material` (local-subtree feature dropped; material export stays for install).
pub fn run_tree_material(prefix: &str) -> Result<()> {
    let session = build_session()?;
    let store = build_local()?;
    let all = store.all(false)?;
    let root_id = respire_app::service::resolve_prefix(&all, prefix)?;
    let members = respire_app::service::subtree_members(&all, &root_id);
    let mut entries: Vec<respire_app::MemoryEntry> = all
        .iter()
        .filter(|m| members.contains(&m.id))
        .filter_map(|s| MemoryEngine::open(&session, s).ok())
        .collect();
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let mut md = String::new();
    md.push_str("# rsrs subtree material\n\n");
    md.push_str(&format!("Node: {root_id}\nCount: {}\n\n", entries.len()));
    for e in &entries {
        let title = if e.title.is_empty() {
            short_id(&e.id)
        } else {
            e.title.clone()
        };
        md.push_str(&format!("## {title}\n\n{}\n\n", e.content));
    }
    let mut result = ResultEnvelope::new(
        "tree-material",
        OutputStatus::Ok,
        serde_json::json!({"node": root_id, "count": entries.len()}),
        vec![OutputItem::new(
            "material",
            OutputStatus::Ok,
            format!("{} entries", entries.len()),
        )],
    );
    result.details = serde_json::json!({"material": md});
    emit_result(result)
}

/// Multiple accounts on one machine: list profiles / use switches / remove deletes.

pub fn run_export(file: &str) -> Result<()> {
    let n = respire_app::service::export_json(std::path::Path::new(file))?;
    emit_result(ResultEnvelope::new(
        "export",
        OutputStatus::Ok,
        serde_json::json!({"exported":n,"path":file}),
        vec![
            OutputItem::new("entries", OutputStatus::Ok, n.to_string()),
            OutputItem::new("path", OutputStatus::Ok, file),
        ],
    ))
}

pub fn run_backup(file: &str) -> Result<()> {
    let p = respire_app::service::backup_db(std::path::Path::new(file))?;
    emit_result(ResultEnvelope::new(
        "backup",
        OutputStatus::Ok,
        serde_json::json!({"backed_up":p.to_string_lossy()}),
        vec![OutputItem::new(
            "path",
            OutputStatus::Ok,
            p.display().to_string(),
        )],
    ))
}

/// Export decrypt keys: super password + Secret Key + vault material (how a new machine logs in).
/// Under v3, Account Secret is no longer a decrypt key - export the v3 three-piece; old v1 material is listed as a side note.

pub fn run_book_material(root: &str) -> Result<()> {
    let app = respire_app::service::App::open()?;
    let m = app.book_material(root)?;
    let mut result = ResultEnvelope::new(
        "book-material",
        OutputStatus::Ok,
        serde_json::json!({"title":m.root.title,"chapters":m.chapters.len(),"entries":m.total_entries,"chars":m.total_chars}),
        vec![
            OutputItem::new("volume", OutputStatus::Ok, m.root.title.clone()),
            OutputItem::new("chapters", OutputStatus::Ok, m.chapters.len().to_string()),
            OutputItem::new("entries", OutputStatus::Ok, m.total_entries.to_string()),
            OutputItem::new("chars", OutputStatus::Ok, m.total_chars.to_string()),
        ],
    );
    result.details = serde_json::to_value(&m)?;
    emit_result(result)
}

pub fn run_portrait_material(limit: usize) -> Result<()> {
    let app = respire_app::service::App::open()?;
    let m = app.portrait_material(limit)?;
    let count = m
        .get("entries")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    let mut result = ResultEnvelope::new(
        "portrait-material",
        OutputStatus::Ok,
        serde_json::json!({"limit":limit,"count":count}),
        vec![
            OutputItem::new("entries", OutputStatus::Ok, count.to_string()),
            OutputItem::new("limit", OutputStatus::Ok, limit.to_string()),
        ],
    );
    result.details = m;
    emit_result(result)
}

/// Share a subtree: emit a prompt another AI can paste.
///
/// Missing `--root` uses this machine's scope root; if that is also unset, error and list candidate roots -
/// sharing a subtree is an explicit action; do not silently pick one (2026-09-21).
pub fn run_share(root: Option<&str>, raw: bool, out: Option<&str>) -> Result<()> {
    let root_id = match root.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(r) => r.to_owned(),
        None => {
            return Err(anyhow!(
                "no subtree specified: `rsrs share --root <id>` (run `rsrs tree --outline` first to see subtree ids)"
            ));
        }
    };
    let (payload, encoded) = respire_app::service::export_subtree_payload(&root_id)?;
    let prompt = respire_app::share::build_prompt(&payload, &encoded);

    if let Some(path) = out.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        std::fs::write(path, &prompt).map_err(|e| anyhow!("write failed {path}: {e}"))?;
        let mut result = ResultEnvelope::new(
            "share",
            OutputStatus::Ok,
            serde_json::json!({"path":path,"root":payload.root_title,"count":payload.items.len(),"chars":payload.total_chars(),"prompt_chars":prompt.chars().count()}),
            vec![OutputItem::new("file", OutputStatus::Ok, path)],
        );
        result.actions.push("protect plaintext payload".into());
        emit_result(result)?;
        return Ok(());
    }

    let status = if raw {
        OutputStatus::Warn
    } else {
        OutputStatus::Ok
    };
    let mut result = ResultEnvelope::new(
        "share",
        status,
        serde_json::json!({"root":payload.root_title,"count":payload.items.len(),"chars":payload.total_chars(),"prompt_chars":prompt.chars().count()}),
        vec![OutputItem::new("prompt", status, prompt)],
    );
    result.details = serde_json::json!({"payload":encoded});
    result.actions.push("protect plaintext payload".into());
    emit_result(result)
}

/// Import a shared subtree: without `--go`, print attach-candidate bill (for the AI to judge); `--go` writes.
/// Refuse Core-reported conflicts before writing; `--force` is the explicit override.
pub fn run_share_import(
    file: &str,
    parent: &str,
    go: bool,
    title: Option<&str>,
    force: bool,
) -> Result<()> {
    let mut payload = respire_app::service::read_share_file(std::path::Path::new(file))?;
    if let Some(t) = title.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        payload.root_title = t.to_owned();
    }

    if !go {
        let embedder = BgeEmbedder::load_model(&build_local()?.retrieval_model()?)?;
        let bill = respire_app::service::share_candidates_with(&payload, &embedder)?;
        let cands = bill["candidates"].as_array().cloned().unwrap_or_default();
        let items = cands
            .iter()
            .take(8)
            .map(|c| {
                OutputItem::new(
                    c["short_id"].as_str().unwrap_or(""),
                    OutputStatus::Pending,
                    format!(
                        "score={} title={}",
                        c["score"].as_f64().unwrap_or(0.0),
                        c["title"].as_str().unwrap_or("")
                    ),
                )
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "share-import",
            OutputStatus::Pending,
            serde_json::json!({"need_go":true,"root":payload.root_title,"entries":payload.items.len(),"chars":payload.total_chars(),"candidates":cands.len()}),
            items,
        );
        result.details = bill;
        result.actions.push(format!("share-import {file} --go"));
        emit_result(result)?;
        return Ok(());
    }

    let embedder = BgeEmbedder::load_model(&build_local()?.retrieval_model()?)?;
    let report = respire_app::service::import_share_payload(&payload, parent, force, &embedder)?;
    let status = if report.orphaned > 0 || report.skipped > 0 {
        OutputStatus::Warn
    } else {
        OutputStatus::Ok
    };
    let items = vec![
        OutputItem::new("imported", status, report.imported.to_string()),
        OutputItem::new(
            "skipped",
            if report.skipped > 0 {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            },
            report.skipped.to_string(),
        ),
        OutputItem::new(
            "reattached",
            OutputStatus::Ok,
            report.reattached.to_string(),
        ),
        OutputItem::new(
            "orphaned",
            if report.orphaned > 0 {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            },
            report.orphaned.to_string(),
        ),
    ];
    emit_result(ResultEnvelope::new(
        "share-import",
        status,
        serde_json::json!({"root_title":payload.root_title,"imported":report.imported,"skipped":report.skipped,"reattached":report.reattached,"orphaned":report.orphaned,"parent":parent}),
        items,
    ))
}

/// Whether this command writes the store (must refuse in read-only mode).
///

pub fn run_memory_revision() -> Result<()> {
    crate::host_hooks::check_direct_access()?;
    emit_result(ResultEnvelope::new(
        "memory-revision",
        OutputStatus::Ok,
        serde_json::to_value(respire_app::service::memory_revision()?)?,
        Vec::new(),
    ))
}

pub fn run_capabilities() -> Result<()> {
    emit_result(ResultEnvelope::new("capabilities", OutputStatus::Ok,
        serde_json::json!({
            "schema_version": 1,
            "cli_version": crate::app_version::embedded(),
            "capabilities": {
                "host_rpc": {"version":1,"transport":"stdio","flag":"--host-rpc-stdio","methods":["auth.register","auth.login","auth.recover","auth.reset"]},
                "memory_list_metadata": true,
                "memory_metadata_flags": true,
                "memory_metadata_gate_default": false,
                "rerank": false,
                "model": {"install": true, "install_rerank": false, "profile_contract":1, "transport_contract":1, "methods":["model.catalog","model.configure","model.switch","model.resume","model.progress"], "selection_scope":"library"}
            }
        }), Vec::new()))
}

pub fn run_metadata_status() -> Result<()> {
    let root = respire_app::service::data_dir();
    let path = respire_app::service::database_path(&root)?;
    let details = if path.exists() {
        let store = respire_app::transport::local::LocalStore::open_read_only(&path)?;
        let backup = store.meta_get("memory_metadata_v1_backup")?
            .map(|value| serde_json::from_str::<serde_json::Value>(&value)).transpose()?;
        serde_json::json!({"enabled":store.memory_metadata_v1_enabled()?,
            "mode":respire_app::metadata_gate::mode(&store)?,
            "metadata_retained":store.has_memory_metadata()?,"backup":backup})
    } else {
        serde_json::json!({"enabled":false,"mode":"isolated","metadata_retained":false,"backup":null})
    };
    let capabilities: serde_json::Value = respire_app::core_sdk::execute("capabilities", serde_json::Value::Null)?;
    let mut result = ResultEnvelope::new("metadata", OutputStatus::Ok,
        serde_json::json!({"action":"status","enabled":details["enabled"],"mode":details["mode"],
            "sdk_supported":capabilities["memory_metadata_contract"].as_u64()==Some(1)}), Vec::new());
    result.details = details;
    emit_result(result)
}

pub fn change_metadata_profile(change: impl FnOnce() -> Result<()>) -> Result<()> {
    if DIRECT_MODE.load(Ordering::Relaxed) {
        let _takeover = runtime_policy::takeover_lock()?;
        anyhow::ensure!(!crate::host_hooks::runtime_is_up(), "stop the local runtime before direct metadata configuration");
        change()
    } else {
        crate::host_hooks::change_profile(Box::new(change))
    }
}

pub fn run_metadata_host(command: &metadata::Command) -> Result<()> {
    runtime_policy::require_host("metadata deployment configuration")?;
    anyhow::ensure!(!rpc::worker_active(), "metadata enable/disable must run in the host CLI");
    respire_app::service::ensure_writable()?;
    anyhow::ensure!(!respire_app::service::off_mode(), "restore normal service before changing the metadata gate");
    let root = respire_app::service::data_dir();
    let mut details = serde_json::Value::Null;
    match command {
        metadata::Command::Enable { mode, deployment_review } => {
            let (deployment, review) = metadata::deployment(mode, deployment_review.as_deref())?;
            respire_app::metadata_gate::require_support()?;
            let keys = build_session()?;
            let account = respire_app::service::session_user_of_dir(&root);
            change_metadata_profile(|| {
                let ownership = respire_app::lock::LibraryLock::acquire(&root, std::time::Duration::from_secs(15))?;
                let receipt = respire_app::metadata_gate::enable(&root, &ownership, &account, &keys, deployment)?;
                details = serde_json::json!({"receipt":receipt,"deployment_review":review,
                    "deployment_assurance":"operator_attestation_only","old_client_access_enforced":false});
                Ok(())
            })?;
        }
        metadata::Command::Disable => {
            change_metadata_profile(|| {
                let _ownership = respire_app::lock::LibraryLock::acquire(&root, std::time::Duration::from_secs(15))?;
                let store = respire_app::transport::local::LocalStore::open_existing(&respire_app::service::database_path(&root)?)?;
                details = store.write_transaction(|| {
                    let mode = respire_app::metadata_gate::mode(&store)?;
                    let retained = store.has_memory_metadata()?;
                    store.meta_set("memory_metadata_v1_enabled", "0")?;
                    Ok(serde_json::json!({"enabled":false,"mode":mode,
                        "metadata_retained":retained,"sync_isolation_retained":true}))
                })?;
                Ok(())
            })?;
        }
        metadata::Command::Status => return run_metadata_status(),
    }
    let mut result = ResultEnvelope::new("metadata", OutputStatus::Ok,
        serde_json::json!({"action":if matches!(command,metadata::Command::Enable{..}){"enabled"}else{"disabled"},
            "enabled":matches!(command,metadata::Command::Enable{..})}), Vec::new());
    result.details = details;
    emit_result(result)
}

pub fn run_local(args: Cli) -> Result<()> {
    set_json_mode(args.json || respire_app::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"));
    if respire_app::service::off_mode() && matches!(args.command, Some(Command::Status)) {
        let session = respire_app::service::session_info();
        return emit_result(ResultEnvelope::new("status", OutputStatus::Ok, serde_json::json!({
            "workspace":"off", "unlocked":session.has_local_keys, "session":session,
            "data_dir":respire_app::service::data_dir(), "autosync":false,
            "sync_scheduler":{"phase":"paused"}, "retrieval_index":rpc::index_status(),
            "local_total":null, "local_alive":null
        }), Vec::new()));
    }
    if respire_app::service::off_mode() && args.command.as_ref().is_some_and(|command| !is_off_allowed(command)) {
        if !json_mode() && !rpc::worker_active() { return Ok(()); }
        let command = match args.command.as_ref() { Some(Command::Recall { .. }) => "recall", Some(Command::Remember { .. }) => "remember", _ => "memory" };
        let mut result = ResultEnvelope::new(command, OutputStatus::Ok, serde_json::json!({"mode":"off", "skipped":true, "count":0}), Vec::new());
        result.details = serde_json::json!([]);
        return emit_result(result);
    }
    let command = match args.command.as_ref() {
        Some(Command::Review { .. }) => "review",
        Some(Command::Recall { .. }) => "recall",
        Some(Command::Remember { .. }) => "remember",
        Some(Command::Candidates { .. }) => "candidates",
        Some(Command::Bench { .. }) => "bench",
        Some(Command::TreeDeepen { .. }) => "tree-deepen",
        Some(Command::TreeCure { .. }) => "tree-cure",
        Some(Command::TreeFloat { .. }) => "tree-float",
        Some(Command::Defrag { .. }) => "defrag",
        Some(Command::ShareImport { .. }) => "share-import",
        _ => "cli",
    };
    match run_local_inner(args) {
        Err(error) if error.downcast_ref::<respire_app::service::IndexPending>().is_some() => {
            // run_local_inner has released its direct LibraryLock before this
            // authenticated request starts the resident index worker.
            let indexing = rpc::request_index()?;
            let mut result = ResultEnvelope::new(
                command, OutputStatus::Pending,
                serde_json::json!({"state":"index_pending", "retrieval_index":indexing}),
                vec![OutputItem::new("index", OutputStatus::Pending, error.to_string())],
            );
            result.actions.push("status".into());
            emit_result(result)
        }
        result => result,
    }
}

pub fn commit_prepared_write<T>(simple: bool, generation: usize, action: impl FnOnce() -> Result<T>) -> Result<T> {
    if simple && rpc::worker_active() { rpc::foreground_phase(generation, action) }
    else { action() }
}

pub fn run_local_inner(args: Cli) -> Result<()> {
    if matches!(args.command, Some(Command::Capabilities)) {
        return run_capabilities();
    }
    let write_generation = rpc::sync_generation();
    let short_write = matches!(args.command.as_ref(), Some(Command::Update { .. }))
        || matches!(args.command.as_ref(), Some(Command::Remember {
            merge_ids: None, supersedes: None, see_also, .. }) if see_also.is_empty());
    if rpc::worker_active() {
        respire_app::service::ensure_runtime_profile()?;
    }
    set_json_mode(
        args.json || respire_app::env::var("RSRS_JSON").is_ok_and(|v| v == "1" || v == "true"),
    );
    if matches!(args.command, Some(Command::V)) {
        return crate::app_version::emit(json_mode());
    }
    if matches!(args.command, Some(Command::Web { .. } | Command::Restart { .. })) {
        anyhow::bail!("the dashboard launcher does not run inside a command worker");
    }
    if matches!(args.command, Some(Command::MemoryRevision)) {
        return run_memory_revision();
    }
    // The runtime worker already holds lock.db for the process lifetime.
    progress::phase("\u{6253}\u{5f00}\u{672c}\u{5730}\u{5e93}\u{ff1b}\u{7b49}\u{5f85}\u{6570}\u{636e}\u{5e93}\u{9501}", "Opening local library; waiting for database lock");
    let _library_lock = if rpc::worker_active() {
        None
    } else {
        Some(respire_app::lock::LibraryLock::acquire(
            &respire_app::service::data_dir(),
            std::time::Duration::from_secs(120),
        )?)
    };
    // A direct caller can wait here while a restore installs maintenance. The
    // pre-dispatch check cannot authorize a mutation after that ownership wait.
    respire_app::snapshot::ensure_no_incomplete_restore(&respire_app::service::data_dir())?;
    progress::phase("\u{6267}\u{884c}\u{672c}\u{5730}\u{64cd}\u{4f5c}", "Executing local operation");
    crate::host_hooks::check_direct_access()?;
    // -- Read-only gate (added 2026-09-20; same-day audit moved it) --
    // When this space's agent.json has readonly=true, every write command is refused.
    //
    // **Must sit before the "no embedder needed" early-return match below** - it used to sit after
    // `let command = args.command.unwrap_or(...)` (~line 4882), while resort/
    // split/repack/tree-cure/defrag/root-create writes **returned early** from the match around 4688
    // and never hit the gate - read-only was a no-op (reproduced: those commands still reached unlock).
    // Raised here so every write goes through.
    if let Some(cmd) = args.command.as_ref() {
        // -- Temporarily-off gate (added 2026-09-21; one of the personal-space three states) --
        // memory_off=true refuses both read and write, leaving only admin/identity/inject infrastructure -
        // the owner restores with agent-config --set memory_off=false (unlike team read-only, which is
        // server-enforced: off is a local switch, no need to block self-unlock).
        if matches!(
            cmd,
            Command::Sync | Command::SyncResolve { .. } | Command::SyncReset
        ) {
            respire_app::snapshot::ensure_sync_allowed(&respire_app::service::data_dir())?;
        }
        if respire_app::service::off_mode() {
            if !is_off_allowed(cmd) {
                anyhow::bail!(
                    "the memory store is temporarily off - this turn provides no memory service (recall and store both stop).\n\
                     \x20  restore: `rsrs agent-config --set workspace_mode=normal` then `rsrs inject --all` to redistribute the prompt."
                );
            }
        } else {
            let device_sync_write = respire_app::service::service_paused()
                && matches!(cmd, Command::Sync | Command::SyncConflicts { .. } | Command::SyncHistory { remote: true, .. });
            if is_write_command(cmd) || is_write_command_fine(cmd) || device_sync_write {
                respire_app::service::ensure_writable()?;
            }
            // H2 anti-self-unlock: in read-only, do not allow readonly back to false - **team read-only only**
            // (readonly_team=true, written by space join --readonly). Personal read-only
            // (GUI/agent-config) is the owner's own switch and must be liftable.
            // Even if a team member bypasses the local gate, the server still refuses writes by session token (the real line).
            if respire_app::service::readonly_mode()
                && respire_app::service::readonly_team()
                && is_readonly_switch_off(cmd)
            {
                anyhow::bail!(
                    "this space is read-only - you cannot lift read-only yourself.\n\
                     \x20  the space owner must lift it (the server enforces by session token; editing local agent.json does nothing);\n\
                     \x20  if you are the owner and need to write, re-issue a read-write session on the server then `rsrs space join`."
                );
            }
        }
    }
    // keygen/defrag/scope/config etc. do not need the embedder - handle early
    // Host-managed commands route through the CLI binary dispatcher before
    // the shared engine arms.
    if let Some(outcome) = crate::host_hooks::host_command(&args) {
        return outcome;
    }
    match args.command.as_ref() {
        Some(Command::Metadata { command: metadata::Command::Status }) => return run_metadata_status(),
        Some(Command::Metadata { .. }) => anyhow::bail!("metadata enable/disable must run in the host CLI"),
        Some(Command::Review { args }) => return review::run(args),
        Some(Command::Grant { command }) => {
            let store = respire_app::service::open_store()?;
            let (action, result) = match command {
                GrantCommand::Create { root, label } => {
                    uuid::Uuid::parse_str(root).map_err(|error| respire_app::input_error::InputError(format!("grant root must be a full UUID: {error}")))?;
                    if label.trim().is_empty() || label.len() > 128 {
                        return Err(respire_app::input_error::InputError("grant label must be 1\u{2013}128 bytes of non-empty text".into()).into());
                    }
                    if !store.all(false)?.iter().any(|entry| entry.id == *root) {
                        return Err(respire_app::input_error::InputError("grant root does not exist or is deleted".into()).into());
                    }
                    let (grant, token) = store.create_grant(root, label)?;
                    (
                        "create",
                        serde_json::json!({"grant": grant, "token": token}),
                    )
                }
                GrantCommand::List => ("list", serde_json::json!({"grants": store.list_grants()?})),
                GrantCommand::Revoke { id } => (
                    "revoke",
                    serde_json::json!({"revoked": store.revoke_grant(id)?}),
                ),
            };
            let items = if action == "list" {
                result["grants"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|g| {
                        OutputItem::new(
                            g["id"].as_str().unwrap_or("grant"),
                            OutputStatus::Ok,
                            serde_json::to_string(g).unwrap_or_default(),
                        )
                    })
                    .collect()
            } else {
                vec![OutputItem::new(
                    "result",
                    OutputStatus::Ok,
                    serde_json::to_string(&result).unwrap_or_default(),
                )]
            };
            let mut envelope = ResultEnvelope::new(
                "grant",
                OutputStatus::Ok,
                serde_json::json!({"action":action}),
                items,
            );
            envelope.details = result;
            return emit_result(envelope);
        }
        Some(Command::Session { command }) => {
            let revoke = match command {
                SessionCommand::List => None,
                SessionCommand::Revoke { id } => Some(id.as_str()),
            };
            let action = if revoke.is_some() { "revoke" } else { "list" };
            let details = respire_app::auth::sessions(revoke)?;
            let rows = details.as_array().cloned().unwrap_or_default();
            let items = rows
                .iter()
                .map(|s| {
                    OutputItem::new(
                        s["id"]
                            .as_str()
                            .or_else(|| s["session_id"].as_str())
                            .unwrap_or("session"),
                        OutputStatus::Ok,
                        serde_json::to_string(s).unwrap_or_default(),
                    )
                })
                .collect();
            let mut envelope = ResultEnvelope::new(
                "session",
                OutputStatus::Ok,
                serde_json::json!({"action":action,"count":rows.len()}),
                items,
            );
            envelope.details = details;
            return emit_result(envelope);
        }
        Some(Command::Defrag { min, top }) => return run_defrag(*min, *top),
        Some(Command::TreeCure {
            top,
            id,
            parent,
            auto,
            min,
        }) => return run_tree_cure(*top, id.as_deref(), parent.as_deref(), *auto, *min),
        Some(Command::TreeFloat { go, min }) => return run_tree_float(*go, *min),
        Some(Command::Split { id, go, spec }) => return run_split(id, *go, spec.as_deref()),
        Some(command @ Command::Extract { .. }) => return run_extract_command(command),
        Some(Command::DiarySearch { query, limit, max_chars, mode }) => {
            let store = build_local()?;
            let keys = build_session()?;
            let result = respire_app::diary::search(&store, &keys, query, *limit, *max_chars, mode == "hybrid")?;
            if result.pending_fragments > 0 { respire_app::service::notify_index(); }
            return emit_diary_fragments("diary-search", result);
        }
        Some(Command::DiaryFragment { source_id, fragment_id, neighbors, max_chars }) => {
            let result = respire_app::diary::read_fragment(&build_local()?, &build_session()?, source_id, fragment_id, *neighbors, *max_chars)?;
            return emit_diary_fragments("diary-fragment", result);
        }
        Some(Command::Diary {
            limit,
            date,
            from,
            to,
            contains,
        }) => {
            return run_diary(
                *limit,
                date.as_deref(),
                from.as_deref(),
                to.as_deref(),
                contains.as_deref(),
            )
        }
        Some(Command::Repack) => return run_repack(),
        Some(Command::Tree {
            material: Some(root),
            ..
        }) => return run_tree_material(root),
        Some(Command::Tree {
            from,
            outline: true,
            ..
        }) => {
            let app = respire_app::service::App::open()?;
            let nodes = app.tree(from, usize::MAX)?;
            // --json contract: every command must emit JSON (this used to hard-take the text path,
            // the only CLI command that broke the contract - found in the 2026-09-20 audit).
            if json_mode() {
                let mut rows: Vec<serde_json::Value> = Vec::new();
                collect_outline_json(&nodes, 0, &mut rows);
                let mut result = ResultEnvelope::new(
                    "tree",
                    OutputStatus::Ok,
                    serde_json::json!({"count":rows.len(),"outline":true}),
                    rows.iter()
                        .map(|r| {
                            OutputItem::new(
                                r["short_id"].as_str().unwrap_or(""),
                                OutputStatus::Ok,
                                r["title"].as_str().unwrap_or(""),
                            )
                        })
                        .collect(),
                );
                result.details = serde_json::Value::Array(rows);
                emit_result(result)?;
                return Ok(());
            }
            let mut lines: Vec<String> = Vec::new();
            collect_outline(&nodes, 0, &mut lines);
            emit_result(ResultEnvelope::new(
                "tree",
                OutputStatus::Ok,
                serde_json::json!({"count":lines.len(),"outline":true}),
                lines
                    .iter()
                    .map(|line| OutputItem::new("node", OutputStatus::Ok, line))
                    .collect(),
            ))?;
            return Ok(());
        }
        Some(Command::Resort {
            go,
            spec,
            status,
            reset,
            threshold,
        }) => return run_resort(*go, spec.as_deref(), *status, *reset, *threshold),
        Some(Command::Prompt) => {
            let text = respire_app::inject::INSTRUCTIONS_MD;
            return emit_result(ResultEnvelope::new(
                "prompt",
                OutputStatus::Ok,
                serde_json::json!({"instructions":text}),
                vec![OutputItem::new("instructions", OutputStatus::Ok, text)],
            ));
        }
        Some(Command::AgentConfig { set }) => return run_agent_config(set.as_deref()),
        Some(Command::Tree { from, depth, .. }) if json_mode() => {
            let app = respire_app::service::App::open()?;
            let nodes = app.tree(from, *depth)?;
            let mut result = ResultEnvelope::new(
                "tree",
                OutputStatus::Ok,
                serde_json::json!({"count":nodes.len(),"depth":depth}),
                Vec::new(),
            );
            result.details = serde_json::to_value(&nodes)?;
            emit_result(result)?;
            return Ok(());
        }
        Some(Command::TreeDeepen {
            root,
            go,
            titles,
            auto,
            min,
        }) => return run_tree_deepen(root.as_deref(), *go, titles.as_deref(), *auto, *min),
        // Share: decrypt only, no retrieval (no BGE load), so it sits in the no-model section
        Some(Command::Share { root, raw, out }) => {
            return run_share(root.as_deref(), *raw, out.as_deref())
        }
        Some(Command::Doctor {
            remote,
            check_update,
            fix,
        }) => return run_doctor(*remote, *check_update, *fix),
        Some(Command::Audit { json }) => return run_audit(*json),
        Some(Command::Witness { verify: _ }) => {
            let report=build_local()?.witness_verify()?;
            let mut result=ResultEnvelope::new("witness",if report.intact{OutputStatus::Ok}else{OutputStatus::Fail},serde_json::to_value(&report)?,Vec::new());
            if !report.intact {result.errors.push(format!("witness verification failed at sequence {}: {}",report.broken_at.map_or_else(||"unknown".to_owned(),|seq|seq.to_string()),report.reason.as_deref().unwrap_or("invalid chain")));}
            result.details=serde_json::to_value(report)?;
            return emit_result(result);
        },
        Some(Command::SuperReset { super_pass }) => {
            let new_super = respire_app::auth::super_reset(None, super_pass.as_deref())?;
            emit_result(ResultEnvelope::new(
                "super-reset",
                OutputStatus::Ok,
                serde_json::json!({"ok":true,"super":new_super}),
                vec![OutputItem::new("password", OutputStatus::Ok, "issued")],
            ))?;
            return Ok(());
        }
        Some(Command::QueryLog {
            limit,
            stats,
            json,
            cmd,
        }) => return run_query_log(*limit, *stats, *json, cmd.as_ref()),
        Some(Command::Bench { cmd }) => return run_bench(cmd),
        Some(Command::RunLog { id, status, note }) => {
            return run_run_log(id, status, note);
        }
        Some(Command::Classify {
            limit,
            all,
            root,
            max_chars,
            min_confidence,
            save,
            dry_run,
            ds,
            backend,
            samples,
            tree,
            batch,
            tree_depth,
            causal,
            min_kids,
            segments,
            out,
            auto,
            plan,
            rounds,
            api_base,
            model,
        }) => {
            return run_classify(
                *limit,
                *all,
                root.as_deref(),
                *max_chars,
                *min_confidence,
                save.as_deref(),
                api_base.as_deref(),
                model,
                *dry_run,
                ds.as_deref(),
                backend.as_deref(),
                *samples,
                *tree,
                *batch,
                *tree_depth,
                *causal,
                *min_kids,
                *segments,
                out.as_deref(),
                *auto,
                *plan,
                *rounds,
            )
        }
        Some(Command::Model { action }) => {
            return match action {
                ModelAction::Catalog | ModelAction::Configure { .. } | ModelAction::Switch { .. } | ModelAction::Progress | ModelAction::Resume => anyhow::bail!("model profile command must use the runtime interface"),
                ModelAction::InstallM3 { mirror, model, for_engine } => {
                    let mirror_env = crate::model_install::mirror_from_env();
                    let resolved = mirror.as_deref().or(mirror_env.as_deref());
                    let prepare = || -> Result<_> {
                        // Reject bad variants before downloading the baseline.
                        if let Some(variant) = model.as_deref() { respire_app::memory::onnx::parse_variant(variant)?; }
                        let report = crate::model_install::install_m3(resolved)?;
                        if let Some(variant) = model.as_deref() { crate::model_install::install_variant(variant, resolved)?; }
                        Ok(report)
                    };
                    let report = if let Some(engine) = for_engine {
                        let engine = respire_app::memory::onnx::Engine::parse(engine)?;
                        respire_app::memory::onnx::with_selection(engine,
                            model.as_deref().unwrap_or(respire_app::memory::onnx::default_variant(engine)), prepare)?
                    } else { prepare()? };
                    emit_result(ResultEnvelope::new(
                        "model install-m3",
                        OutputStatus::Ok,
                        serde_json::json!({"dir":report.dir,"skipped":report.skipped,"activated":false,"model":"m3"}),
                        vec![OutputItem::new(
                            "model",
                            OutputStatus::Ok,
                            "BGE-M3 ready; run rsrs reembed to rebuild an old index",
                        )],
                    ))?;
                    Ok(())
                }
                ModelAction::Activate { model } => {
                    use crate::model_progress;
                    let _operation = model_progress::Operation::try_begin_background_index()?
                        .ok_or_else(|| anyhow::anyhow!("another model operation is running"))?;
                    let store = build_local()?;
                    anyhow::ensure!(store.retrieval_model()? == *model,"legacy model activate cannot change a profile selection; use model switch m3");
                    let keys = build_session()?;
                    let embedder = BgeEmbedder::load_model(model)?;
                    let count = store.rebuild_index_with_progress(
                        &keys,
                        &embedder,
                        model,
                        |done, total| {
                            model_progress::update("index", model, done as u64, Some(total as u64))
                        },
                    )?;
                    *EMBEDDER_SLOT
                        .lock()
                        .map_err(|_| anyhow!("embedder cache poisoned"))? = None;
                    emit_result(ResultEnvelope::new(
                        "model activate",
                        OutputStatus::Ok,
                        serde_json::json!({"model":model,"indexed":count,"dimensions":embedder.dims()}),
                        vec![OutputItem::new(
                            "active_model",
                            OutputStatus::Ok,
                            model.clone(),
                        )],
                    ))?;
                    Ok(())
                }
                ModelAction::ResetCpu => {
                    anyhow::bail!("run `rsrs model reset-cpu` directly in your terminal")
                }
                ModelAction::Engine { engine, model } => {
                    use respire_app::memory::onnx;
                    let selected = respire_app::embedding::saved_selection()?;
                    respire_app::core_sdk::profiles::set_active(selected.clone());
                    anyhow::ensure!(selected.is_none() || (engine.is_none() && model.is_none()),"library uses a model profile; use model switch instead of legacy engine settings");
                    if let Some(engine) = engine {
                        onnx::save_engine_with_variant(onnx::Engine::parse(engine)?, model.as_deref())?;
                        *EMBEDDER_SLOT
                            .lock()
                            .map_err(|_| anyhow!("embedder cache poisoned"))? = None;
                    } else if let Some(model) = model.as_deref() {
                        onnx::save_model_variant(model)?;
                        *EMBEDDER_SLOT.lock().map_err(|_| anyhow!("embedder cache poisoned"))? = None;
                    }
                    let engine = onnx::configured_engine()?;
                    emit_result(ResultEnvelope::new(
                        "model",
                        OutputStatus::Ok,
                        serde_json::json!({"engine":engine,
                            "model":onnx::configured_variant(engine)?.name,
                            "variants":crate::model_install::variant_inventory()?, "active_selection":selected}),
                        vec![],
                    ))?;
                    Ok(())
                }
                ModelAction::Load { engine, model } => {
                    let selected = respire_app::embedding::saved_selection()?;
                    respire_app::core_sdk::profiles::set_active(selected.clone());
                    anyhow::ensure!(selected.is_none(),"library uses a model profile; use model switch instead of legacy model load");
                    let _operation = crate::model_progress::Operation::begin_load()?;
                    let engine = respire_app::memory::onnx::Engine::parse(engine)?;
                    crate::model_progress::update("verify", model, 0, None)?;
                    respire_app::memory::onnx::validate_selection(engine, model)?;
                    crate::model_progress::update("load", model, 0, None)?;
                    let result = respire_app::memory::onnx::load_selection(engine, model)?;
                    *EMBEDDER_SLOT.lock().map_err(|_| anyhow!("embedder cache poisoned"))? = None;
                    emit_result(ResultEnvelope::new("model load", OutputStatus::Ok, result, vec![]))?;
                    Ok(())
                }
                ModelAction::InstallEngines => {
                    anyhow::bail!("inference engine installation is host-managed; run rsrs model install-engines from the host terminal")
                }
                ModelAction::Probe { text, model } => {
                    let current = build_local()?.retrieval_model()?;
                    let selected = model.clone().unwrap_or_else(||current.clone());
                    anyhow::ensure!(selected == current,"probe must name the active library profile; switch before probing");
                    let result = BgeEmbedder::load_model(&selected)?.probe(text)?;
                    emit_result(ResultEnvelope::new(
                        "model",
                        OutputStatus::Ok,
                        result,
                        vec![],
                    ))?;
                    Ok(())
                }
                ModelAction::UninstallM3 => {
                    let report = crate::model_install::uninstall_m3()?;
                    let status = if report.removed {
                        OutputStatus::Ok
                    } else {
                        OutputStatus::Skip
                    };
                    emit_result(ResultEnvelope::new(
                        "model",
                        status,
                        serde_json::json!({"dir":report.dir.display().to_string(),"removed":report.removed,"model":"bge-m3"}),
                        vec![OutputItem::new(
                            "model",
                            status,
                            if report.removed {
                                report.dir.display().to_string()
                            } else {
                                "not installed".to_owned()
                            },
                        )],
                    ))?;
                    Ok(())
                }
            };
        }
        Some(Command::Export { file }) => return run_export(file),
        Some(Command::Backup { file }) => return run_backup(file),
        Some(Command::Snapshot { cmd }) => {
            let root = respire_app::service::data_dir();
            let details = match cmd {
                SnapshotCmd::Create { note } => {
                    serde_json::to_value(respire_app::snapshot::create(
                        &root,
                        &respire_app::service::session_user_of_dir(&root),
                        note,
                        &build_session()?,
                    )?)?
                }
                SnapshotCmd::List => serde_json::to_value(respire_app::snapshot::list_report(&root)?)?,
                SnapshotCmd::ResumeSync { reviewed_revision } => {
                    respire_app::service::ensure_writable()?;
                    respire_app::snapshot::resume_sync(&root, reviewed_revision)?;
                    serde_json::json!({"sync_quarantined":false,"reviewed_revision":reviewed_revision})
                }
                SnapshotCmd::Restore { .. } | SnapshotCmd::Recover { .. } => {
                    anyhow::bail!("snapshot restore/recovery must run in the host CLI")
                }
            };
            let mut result = ResultEnvelope::new(
                "snapshot",
                OutputStatus::Ok,
                serde_json::json!({"action":match cmd {SnapshotCmd::Create{..}=>"created",SnapshotCmd::List=>"list",SnapshotCmd::ResumeSync{..}=>"sync_resumed",SnapshotCmd::Restore{..}=>"restored",SnapshotCmd::Recover{..}=>"recovered"}}),
                Vec::new(),
            );
            if matches!(cmd,SnapshotCmd::Create{..}) && details["witness_intact"]==false {
                result.status=OutputStatus::Warn;
                result.errors.push("snapshot file created, but its witness chain is invalid; preserved for explicit recovery/repair".into());
            }
            if matches!(cmd,SnapshotCmd::List) && details["problems"].as_array().is_some_and(|items|!items.is_empty()) {
                result.status=OutputStatus::Warn;
                result.errors.push("some snapshots failed verification; inspect details.problems; healthy snapshots remain usable".into());
            }
            result.details = details;
            return emit_result(result);
        }
        Some(Command::Login { .. }) => anyhow::bail!("login must run in the host terminal"),
        Some(Command::BookMaterial { root }) => return run_book_material(root),
        Some(Command::PortraitMaterial { limit }) => return run_portrait_material(*limit),
        Some(Command::Taxonomy { list, ensure }) => return run_taxonomy(*list, ensure.as_deref()),
        Some(Command::RootCreate {
            title,
            content,
            yes,
        }) => return run_root_create(title, content.as_deref(), *yes),
        _ => {}
    }
    let command = args.command.unwrap_or(Command::Status);
    // Lazy-load the embedder: Show/Sync/Status/tree ops do not pay BGE cost.
    // The runtime worker puts the loaded model back so the next request does not pay it again.
    let mut embedder_hold = EmbedderHold(
        EMBEDDER_SLOT
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take(),
    );
    macro_rules! embedder {
        () => {{
            let model = build_local()?.retrieval_model()?;
            let generation = respire_app::core_sdk::generation_key(&model)?;
            if embedder_hold
                .0
                .as_ref()
                .is_some_and(|e| e.model_name() != model || e.generation_key() != generation)
            {
                embedder_hold.0 = None;
            }
            if embedder_hold.0.is_none() {
                embedder_hold.0 = Some(Box::new(BgeEmbedder::load_model(&model)?));
            }
            match embedder_hold.0.as_deref() {
                Some(e) => e,
                None => return Err(anyhow::anyhow!("embedder not loaded")),
            }
        }};
    }
    match command {
        Command::Remember {
            content,
            r#type,
            metadata,
            tags,
            title,
            project,
            computer,
            emotion,
            importance,
            parent,
            force,
            merge_ids,
            supersedes,
            see_also,
        } => {
            let explicit_kind = r#type.is_some();
            let r#type = r#type.unwrap_or_else(|| "context".to_owned());
            let metadata_patch = metadata.patch();
            let requested_kind = Kind::try_from_str(&r#type.trim().to_lowercase())
                .ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?;
            let new_kind = matches!(requested_kind, Kind::Hypothesis | Kind::Reflection | Kind::SelfNote);
            if metadata_patch.is_some() || new_kind { respire_app::metadata_gate::require_support()?; }
            anyhow::ensure!((supersedes.is_none() && see_also.is_empty()) || importance == "important", "associations require important memory");
            // importance enum check: an illegal value (e.g. a kind name "task" by mistake) cannot be filtered by audit/UI after write
            // 2026-09-19 two-tier: normal is retired - new writes are important/trivial only (stock normal still reads)
            if !matches!(importance.as_str(), "important" | "trivial") {
                anyhow::bail!("importance must be important/trivial (normal is retired; normal is logged as diary trivia), got \"{}\"", importance);
            }
            // Procedure template: a skill is a manual, not an essay. Warn at write time; `rsrs audit` lists the gaps.
            if r#type == "skill" && importance == "important" {
                let missing = skill::missing_sections(&content);
                if !missing.is_empty() {
                    eprintln!(
                        "WARN skill template missing {} - add {} (see `rsrs audit`)",
                        missing.join("/"),
                        skill::SECTIONS.join("/")
                    );
                }
            }
            // -- Plugin hook pre-remember: may veto the write (sensitive scan etc.). Veto is a normal business state, exit 0 --
            {
                let hv = crate::hooks::fire(
                    crate::hooks::HookEvent::PreRemember,
                    crate::hooks::remember_payload(
                        &title,
                        &importance,
                        &r#type,
                        &project,
                        &content,
                    ),
                );
                if hv.blocked {
                    let mut result = ResultEnvelope::new(
                        "remember",
                        OutputStatus::Pending,
                        serde_json::json!({
                            "event": "pre-remember",
                            "state": "blocked",
                            "reason": hv.reason,
                        }),
                        vec![OutputItem::new(
                            "pre-remember hook",
                            OutputStatus::Pending,
                            "write blocked",
                        )],
                    );
                    result
                        .actions
                        .push("inspect the hook veto before retrying".into());
                    emit_result(result)?;
                    return Ok(());
                }
                for w in &hv.warnings {
                    eprintln!("WARN {w}");
                }
            }
            let (session, profile_owner) = build_session_with_owner()?;
            let store = build_local()?;
            if metadata_patch.is_some() || new_kind {
                anyhow::ensure!(store.memory_metadata_v1_enabled()?, "memory_metadata_v1_disabled");
            }
            let stamp = now_stamp();
            let mut id = Uuid::new_v4().to_string();
            // Auto-fill device tag: explicit --computer first, else hostname/platform - so recall across devices can tell whose paths they are
            let computer = if computer.trim().is_empty() {
                respire_app::service::device_tag()
            } else {
                computer
            };

            // -- Trivia = diary, two modes (agent.json diary_mode; the AI reads it from the inject source):
            //    concise (default) = untitled events append to one daily track;
            //    an explicit title names an independent entry in either mode.
            //    verbose = one diary entry each (old behavior) --
            let (mut content, mut title) = (content, title);
            if importance == "trivial" && merge_ids.is_none() && metadata_patch.is_none() && !new_kind {
                if respire_app::service::diary_mode() != "verbose" && title.trim().is_empty() {
                    // Stable identity survives retitling; dated titles remain a fallback
                    // for legacy tracks created before deterministic IDs were used.
                    let now_local = chrono::Local::now();
                    let day = now_local.format("%Y-%m-%d").to_string();
                    let track_title = format!("\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} {day}");
                    let line = format!("\u{3010}{}\u{3011}{}", now_local.format("%H:%M"), content.trim());
                    let all = store.all(false)?;
                    let user = current_user();
                    let track_id = uuid::Uuid::new_v5(
                        &uuid::Uuid::NAMESPACE_URL,
                        format!("activity-track/{user}/{day}").as_bytes(),
                    )
                    .to_string();
                    let tracks = select_diary_tracks(&all, &track_id, &track_title, |memory| {
                        let author = MemoryEngine::open(&session, memory)?.user;
                        Ok(author == user || profile_owner.as_deref() == Some(author.as_str()))
                    })?;
                    if !tracks.is_empty() {
                        // Prefer the stable ID; otherwise keep the earliest legacy track.
                        // The source-checked transaction still protects every merged row.
                        let main = tracks[0];
                        let mut merged = String::new();
                        for t in &tracks {
                            let full = MemoryEngine::open(&session, t)?;
                            for row in full.content.lines() {
                                if row.trim() == format!("\u{3010}\u{6d3b}\u{52a8}\u{8f68}\u{8ff9}\u{3011}{day}")
                                    || row.trim().is_empty()
                                {
                                    continue;
                                }
                                merged.push_str(row.trim_end());
                                merged.push('\n');
                            }

                        }
                        merged.push_str(&line);
                        // Appending must preserve a user's title and other metadata.
                        let mut e = MemoryEngine::open(&session, main)?;
                        e.content = merged;
                        e.updated_at = store.edit_stamp(&main.id)?;
                        e.modified_by = respire_app::service::device_tag();
                        let metadata_receipt = metadata::prepare(&session, &store, &e)?;
                        let stored = MemoryEngine::seal(&session, embedder!(), &e, &main.user)?;
                        anyhow::ensure!(commit_prepared_write(short_write, write_generation, || store.put_diary_checked(&stored, &main.ciphertext, &tracks[1..]))?, "diary was not saved");
                        crate::hooks::fire(
                            crate::hooks::HookEvent::PostRemember,
                            crate::hooks::remember_done_payload(&stored.id, &e.title, &e.importance),
                        );
                        // Return the same decrypted public entry that show exposes,
                        // never the sealed StoredMemory persistence representation.
                        let mut result = ResultEnvelope::new(
                            "remember",
                            OutputStatus::Ok,
                            serde_json::json!({
                                "action": "diary_appended",
                                "index_state": if stored.local_artifact.is_empty() { "pending" } else { "ready" },
                                "id": stored.id,
                                "title": e.title,
                            }),
                            vec![OutputItem::new(
                                "write",
                                OutputStatus::Ok,
                                format!("id={}", stored.id),
                            )],
                        );
                        metadata::add_receipt(&mut result, metadata_receipt);
                        result.details = serde_json::to_value(&e)?;
                        emit_result(result)?;
                        return Ok(());
                    }
                    // No track for today: create with a deterministic id (same id across devices that day; sync converges), then the generic create path
                    id = track_id;
                    content = format!("\u{3010}\u{6d3b}\u{52a8}\u{8f68}\u{8ff9}\u{3011}{day}\n{line}");
                    title = track_title;
                } else {
                    content = respire_app::taxonomy::diary_content(&content);
                }
            }
            // -- Untitled fallback: first 20 chars of the first body line (tree view must not show a blank title; an explicit --title is untouched) --
            if title.trim().is_empty() {
                title = respire_app::service::derive_title(&content);
            }

            // -- Judge-then-store (dedup first, then choose): unless --force/--merge-ids/--parent (explicit attach is intent)
            //    run an internal recall of similar candidates; diary trivia skips dedup (daily log is not a duplicate event; it goes on the time chain) --
            if !force && merge_ids.is_none() && supersedes.is_none() && see_also.is_empty() && parent.is_empty() && importance != "trivial" {
                let (candidates_all, pending, lease) = respire_app::resident::recall_catalog(&session, &store)?;
                let _resident = lease.enter();
                if pending > 0 { rpc::kick_index(); }
                let q = MemoryQuery::new(&content).limit(5);
                let candidates:respire_app::core_sdk::RememberCandidates=respire_app::core_sdk::execute("remember_candidates",serde_json::json!({
                    "model":embedder!().model_name(),"snapshots":respire_app::memory::engine::snapshots(&session,&candidates_all)?,
                    "query":q,"query_settings":respire_app::feedback::query_settings(&store,&q,&candidates_all)?
                }))?;
                let merge_cand = candidates.merge;
                let parent_cand = candidates.parent;

                if !merge_cand.is_empty() {
                    let mut result = ResultEnvelope::new(
                        "remember",
                        OutputStatus::Pending,
                        serde_json::json!({
                            "state": "candidates",
                            "merge_count": merge_cand.len(),
                            "parent_count": parent_cand.len(),
                            "written": false,
                        }),
                        merge_cand
                            .iter()
                            .take(3)
                            .map(|(score, entry)| {
                                OutputItem::new(
                                    respire_app::service::short_id(&entry.id),
                                    OutputStatus::Pending,
                                    format!(
                                        "similarity={:.0}% title={}",
                                        score * 100.0,
                                        entry.title
                                    ),
                                )
                                .action("merge or attach")
                            })
                            .collect(),
                    );
                    let ids = merge_cand
                        .iter()
                        .take(3)
                        .map(|(_, e)| e.id.clone())
                        .collect::<Vec<_>>()
                        .join(",");
                    result.actions.push(format!(
                        "rsrs remember \"<combined content>\" --merge-ids \"{ids}\""
                    ));
                    if !parent_cand.is_empty() {
                        result
                            .actions
                            .push("rsrs remember \"<content>\" --parent <candidate id>".into());
                    }
                    result
                        .actions
                        .push("Read candidate bodies; choose update, merge or a real --parent, or explicitly defer. Do not bypass candidate review with bare --force.".into());
                    result.actions.extend(respire_app::service::write_decision_actions().iter().map(|action| (*action).to_owned()));
                    emit_result(result)?;
                    return Ok(());
                }
                if !parent_cand.is_empty() {
                    let mut result = ResultEnvelope::new(
                        "remember",
                        OutputStatus::Pending,
                        serde_json::json!({
                            "state": "parent_candidates",
                            "written": false,
                            "count": parent_cand.len(),
                        }),
                        parent_cand
                            .iter()
                            .take(3)
                            .map(|(score, entry)| {
                                OutputItem::new(
                                    respire_app::service::short_id(&entry.id),
                                    OutputStatus::Pending,
                                    format!(
                                        "similarity={:.0}% title={}",
                                        score * 100.0,
                                        entry.title
                                    ),
                                )
                                .action("attach with --parent")
                            })
                            .collect(),
                    );
                    result
                        .actions
                        .push("rsrs remember \"<content>\" --parent <candidate id>".into());
                    result
                        .actions
                        .push("Read candidate bodies; choose update, merge or a real --parent, or explicitly defer. Do not bypass candidate review with bare --force.".into());
                    result.actions.extend(respire_app::service::write_decision_actions().iter().map(|action| (*action).to_owned()));
                    emit_result(result)?;
                    return Ok(());
                }
            }

            // -- --merge-ids: merge path - tombstone the listed old memories (children reattach to their cause), store a combined new entry (inherits the first cause chain) --
            if let Some(ids) = merge_ids {
                let to_merge: Vec<String> = ids
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                let kind = if explicit_kind {
                    requested_kind
                } else {
                    let all = store.all(false)?;
                    let first = to_merge.first().ok_or_else(|| anyhow!("merge needs at least one live entry"))?;
                    let full = respire_app::service::resolve_prefix(&all, first)?;
                    let row = all.iter().find(|row| row.id == full).ok_or_else(|| anyhow!("missing merge source"))?;
                    MemoryEngine::open(&session, row)?.kind
                };
                let mut entry = respire_app::MemoryEntry {
                    metadata: Default::default(),
                    unknown_fields: Default::default(),
                    supersedes: String::new(),
                    superseded_by: String::new(),
                    see_also: Vec::new(),
                    id,
                    kind,
                    tags: tags
                        .split(',')
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .map(ToOwned::to_owned)
                        .collect(),
                    title,
                    content,
                    user: current_user(),
                    computer,
                    project,
                    created_at: stamp.clone(),
                    updated_at: stamp,
                    emotion,
                    parent_id: String::new(),
                    importance,
                    device: respire_app::service::device_tag(),
                    modified_by: respire_app::service::device_tag(),
                };
                let (merged_full, record_revision) = respire_app::service::merge_entries_with_metadata_revision(
                    &session, &store, embedder!(), &mut entry, &to_merge, &parent, true,
                    metadata_patch.as_ref(),
                )?;
                let metadata_receipt = record_revision.as_deref().map(|revision| metadata::receipt(&entry, revision))
                    .unwrap_or_else(|| serde_json::json!({}));
                let dropped = merged_full.len();
                report_orphans(&store, "merge");
                crate::hooks::fire(
                    crate::hooks::HookEvent::PostRemember,
                    crate::hooks::remember_done_payload(
                        &entry.id,
                        &entry.title,
                        &entry.importance,
                    ),
                );
                // Adoption: a merge adopts the old entries (they were the preferred recall candidates)
                for mid in &merged_full {
                    let _ = store.mark_adopted(mid);
                }
                let hint = note_write_maintenance();
                let mut result = ResultEnvelope::new(
                    "remember",
                    OutputStatus::Ok,
                    serde_json::json!({
                        "action": "merged",
                        "dropped": dropped,
                        "id": entry.id,
                        "parent": entry.parent_id,
                        "maintenance_hint": hint,
                    }),
                    vec![OutputItem::new(
                        "merge",
                        OutputStatus::Ok,
                        format!("dropped={dropped} id={}", entry.id),
                    )],
                );
                if let Some(h) = hint {
                    result.actions.push(h);
                }
                metadata::add_receipt(&mut result, metadata_receipt);
                result.details = serde_json::to_value(&entry)?;
                emit_result(result)?;
                schedule_autosync(&session, &store);
                return Ok(());
            }

            // -- Causal attach: --parent is the cause (full id first; unique 8-char prefix also works) --
            // Unresolvable -> warn and actually clear (own cause), so we never warn "stored independently" then print "attached".
            let mut issues: Vec<String> = Vec::new();
            let parent_id = if !parent.is_empty() {
                let all = store.all(true)?;
                match respire_app::service::resolve_prefix(&all, &parent) {
                    Ok(full) => Some(full),
                    Err(e) => {
                        issues.push(format!(
                            "parent (cause) cannot be resolved ({e}); stored independently"
                        ));
                        None
                    }
                }
            } else {
                None
            };
            let parent_id = parent_id.unwrap_or_default();
            let mut entry = respire_app::MemoryEntry {
                metadata: Default::default(),
                unknown_fields: Default::default(),
                supersedes: String::new(),
                superseded_by: String::new(),
                see_also: Vec::new(),
                id,
                kind: Kind::try_from_str(&r#type.trim().to_lowercase()).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?,
                tags: tags
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
                title,
                content,
                user: current_user(),
                computer,
                project,
                created_at: stamp.clone(),
                updated_at: stamp,
                emotion,
                parent_id: parent_id.clone(),
                importance: importance.clone(),
                device: respire_app::service::device_tag(),
                modified_by: respire_app::service::device_tag(),
            };
            metadata.apply(&mut entry);
            let metadata_receipt = metadata::prepare(&session, &store, &entry)?;
            let skill_missing = if entry.kind == Kind::Skill && entry.importance == "important" {
                let missing = skill::missing_sections(&entry.content);
                if !missing.is_empty() {
                    issues.push(format!(
                        "skill template missing {}; add {}",
                        missing.join("/"),
                        skill::SECTIONS.join("/")
                    ));
                }
                missing
            } else {
                Vec::new()
            };
            let stored = if supersedes.is_some() || !see_also.is_empty() {
                respire_app::service::store_related(&session,&store,embedder!(),&mut entry,supersedes.as_deref(),&see_also)?
            } else {
                let sealed = MemoryEngine::seal(&session, embedder!(), &entry, &entry.user)?;
                anyhow::ensure!(commit_prepared_write(short_write, write_generation, || store.put_checked(&sealed, None))?, "memory was not saved");
                sealed
            };
            // Plugin hook post-remember: observe only, never blocks (failure policy is inside hooks::fire)
            {
                let hv = crate::hooks::fire(
                    crate::hooks::HookEvent::PostRemember,
                    crate::hooks::remember_done_payload(
                        &stored.id,
                        &entry.title,
                        &entry.importance,
                    ),
                );
                issues.extend(hv.warnings.iter().cloned());
            }
            // Adoption: explicit attach (--parent) adopts that cause node; --force with no hang is not adoption
            if !parent_id.is_empty() {
                let _ = store.mark_adopted(&parent_id);
            }
            let hint = note_write_maintenance();
            let status = if issues.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            let mut result = ResultEnvelope::new(
                "remember",
                status,
                serde_json::json!({
                    "action": "created",
                    "index_state": if stored.local_artifact.is_empty() { "pending" } else { "ready" },
                    "id": entry.id,
                    "parent": parent_id,
                    "maintenance_hint": hint,
                    "skill_template_missing": skill_missing,
                }),
                vec![OutputItem::new(
                    "write",
                    OutputStatus::Ok,
                    format!("id={}", entry.id),
                )],
            );
            if let Some(h) = hint {
                result.actions.push(h);
            }
            result.errors.extend(issues);
            metadata::add_receipt(&mut result, metadata_receipt);
            result.details = serde_json::to_value(&entry)?;
            emit_result(result)?;
            schedule_autosync(&session, &store);
        }
        Command::Import { file } => {
            let report = respire_app::service::import_json(std::path::Path::new(&file))?;
            let status = if report.orphaned > 0 || report.skipped > report.duplicates {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            };
            let mut result = ResultEnvelope::new(
                "import",
                status,
                serde_json::to_value(&report)?,
                vec![
                    OutputItem::new("written", OutputStatus::Ok, report.imported.to_string()),
                    OutputItem::new("duplicates", OutputStatus::Ok, report.duplicates.to_string()),
                    OutputItem::new(
                        "skipped",
                        if report.skipped > report.duplicates {
                            OutputStatus::Warn
                        } else {
                            OutputStatus::Ok
                        },
                        report.skipped.to_string(),
                    ),
                    OutputItem::new(
                        "parent links",
                        OutputStatus::Ok,
                        report.reattached.to_string(),
                    ),
                ],
            );
            if report.orphaned > 0 {
                result.errors.push(format!(
                    "{} records had a parent not in the backup; imported as roots",
                    report.orphaned
                ));
            }
            emit_result(result)?;
        }
        Command::ShareImport {
            file,
            parent,
            go,
            title,
            force,
        } => {
            return run_share_import(&file, &parent, go, title.as_deref(), force);
        }
        Command::Recall {
            query,
            mode,
            limit,
            r#type,
            project,
            trace,
            titles,
            brief,
            render_budget_base64,
            render_min_score,
            no_related,
            intent,
        } => {
            anyhow::ensure!(render_budget_base64.is_none() || titles || brief, "render budget requires --titles or --brief");
            anyhow::ensure!(render_min_score.is_none() || render_budget_base64.is_some() || brief, "render minimum score requires a render budget");
            let mut render_budget = recall_select::decode_render_budget(render_budget_base64.as_deref(), limit, &intent)?;
            if brief && render_budget.is_none() { render_budget=Some(recall_select::brief_layout(limit)?); }
            if brief { recall_select::require_metadata(true,render_min_score)?; }
            if render_budget.is_some() { recall_select::require_render_budget(render_min_score)?; }
            let recall_generation = rpc::sync_generation();
            let (session,owner) = build_session_with_owner()?;
            let owner=owner.unwrap_or_else(||"local".to_owned());
            let store = build_local()?;
            let review=respire_app::review::ReviewService::new(&session,&store,&owner)?;
            let source=review.recall_source()?;
            let metadata_aware=brief || source.has_metadata();
            // Dynamic blocks from new records need complete qualified variants.
            // Legacy-only title budgets retain their original WP3a bytes.
            let brief_render=brief || (metadata_aware && render_budget.is_some());
            if metadata_aware {recall_select::require_metadata(brief_render,render_min_score)?;}
            let (candidates,index_pending,resident)=if metadata_aware {
                let rows:Vec<_>=source.memories().iter().filter(|row|!row.deleted).cloned().collect();
                let pending=rows.iter().filter(|row|row.local_artifact.is_empty()).count();
                let lease=respire_app::core_sdk::ResidentLease::publish(uuid::Uuid::new_v4().to_string(),None,
                    &store.retrieval_model()?,source.snapshots(),&[])?;
                (Arc::new(rows),pending,Some(lease))
            } else {
                let (rows,pending,lease)=respire_app::resident::recall_catalog(&session,&store)?;
                (rows,pending,Some(lease))
            };
            let _resident_scope=resident.as_ref().map(|lease|lease.enter());
            if index_pending > 0 { rpc::kick_index(); }
            if trace {
                let preview = &candidates;
                let primary = candidates_count_primary(&preview);
                let normals = candidates_count_normal(&preview);
                eprintln!(
                    "[trace] {} active candidates | important {} / normal {} / trivia {} | retrieval policy is Core-owned",
                    preview.len(),
                    primary,
                    normals,
                    preview.len() - primary - normals,
                );
                std::env::set_var("RSRS_DEBUG_SCORE", "1");
            }
            let mut q = MemoryQuery::new(&query).limit(limit);
            if let Some(k) = &r#type {
                q = q.of_kind(Kind::try_from_str(&k.trim().to_lowercase()).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?);
            }
            if let Some(p) = &project {
                q = q.of_project(p);
            }
            let core_intent = if metadata_aware || render_budget.is_some() {Some(intent.as_str())}else{None};
            // 3. small-to-big: hit body + ancestor bodies (budget is built-in; RSRS_ANCESTOR_BUDGET=0 turns it off)
            let (mut ranked, recall_mode, selection_fallback, routing, retrieval, budget) = if metadata_aware {
                recall_select::recall_metadata(&review,&source,embedder!(),&q,&store,render_budget,render_min_score,&intent,mode.as_deref())?
            } else {
                let (ranked,recall_mode,selection_fallback,routing,retrieval,budget)=match mode {
                Some(mode) => {
                    recall_select::recall_with_mode(&session, embedder!(), &candidates, &q, &store, render_budget, render_min_score, core_intent, &mode)?
                }
                None => recall_select::recall(&session, embedder!(), &candidates, &q, &store, render_budget, render_min_score, core_intent)?,
                };
                (ranked,recall_mode,selection_fallback,routing,retrieval,budget.map(serde_json::to_value).transpose()?)
            };
            // Procedural-memory routing (P1/P2): a how-to question gets a second,
            // skill-only pass; the union keeps one procedure inside the top three.
            // Facts keep Core's order and score; run history only ranks procedures.
            let howto = if core_intent.is_some() {
                retrieval["intent"] == "howto"
            } else { match intent.as_str() {
                "howto" => true,
                "fact" => false,
                _ => r#type.is_none() && skill::howto_intent(&query),
            }};
            let mut procedure_pass = if core_intent.is_some() {
                serde_json::from_value::<usize>(retrieval["procedure_pass"].clone())?
            } else { 0 };
            let mut procedure_promoted = if core_intent.is_some() {
                serde_json::from_value::<bool>(retrieval["procedure_promoted"].clone())?
            } else { false };
            if core_intent.is_none() && howto && r#type.is_none() {
                let mut q_skill = q.clone().of_kind(Kind::Skill);
                q_skill.limit = limit;
                let (skills, _, _, _, _, _) = recall_select::recall_with_mode(
                    &session,
                    embedder!(),
                    &candidates,
                    &q_skill,
                    &store,
                    None,
                    None,
                    None,
                    &recall_mode,
                )?;
                procedure_pass = skills.len();
                if !skills.is_empty() {
                    let ids: Vec<String> = ranked
                        .iter()
                        .chain(skills.iter())
                        .map(|r| r.entry.id.clone())
                        .collect();
                    let runs = store
                        .skill_run_stats(&ids)?
                        .into_iter()
                        .map(|(id, st)| (id, skill::RunScore { ok: st.ok, fail: st.fail }))
                        .collect();
                    let (merged, promoted) = skill::merge_howto(ranked, skills, limit, &runs);
                    ranked = merged;
                    procedure_promoted = promoted;
                }
            }
            let intent_label = if core_intent.is_some() {
                retrieval["intent"].as_str().ok_or_else(|| anyhow::anyhow!("missing Core intent receipt"))?
            } else if r#type.is_some() {
                "typed"
            } else if howto {
                "howto"
            } else {
                "fact"
            };
            let hit_ids: Vec<String> = ranked.iter().map(|r| r.entry.id.clone()).collect();
            let associations: respire_app::memory::model::RelatedResult = if metadata_aware {
                Default::default()
            } else if budget.is_some() {
                respire_app::memory::model::RelatedResult {
                    related: Vec::new(), superseded: serde_json::from_value(retrieval["superseded"].clone())?,
                }
            } else if no_related {
                Default::default()
            } else { respire_app::core_sdk::execute("related_business",serde_json::json!({
                "model":embedder!().model_name(), "snapshots":respire_app::memory::engine::snapshots(&session,&candidates)?,
                "query":q,"ids":hit_ids,"pairs":store.recall_pairs(&hit_ids)?
            }))? };
            let query_log_id=if respire_app::service::workspace_mode()=="normal" {Some(uuid::Uuid::new_v4().to_string())}else{None};
            // Query log: each recall writes a candidate record (including empty - negatives are post-training material too).
            // Note: this is the candidate set, not a hit - a hit is the model query-log mark self-grade
            {
                let candidates: Vec<String> = ranked.iter().map(|r| r.entry.id.clone()).collect();
                let scores: Vec<f32> = ranked.iter().map(|r| r.score).collect();
                let stats = rpc::RecallStats {
                    request_id:query_log_id.clone().unwrap_or_else(||uuid::Uuid::new_v4().to_string()),
                    query: query.clone(),
                    project: project.clone().unwrap_or_default(),
                    candidates,
                    scores,
                };
                if rpc::worker_active() {
                    rpc::queue_recall_stats(stats, recall_generation);
                } else if let Err(error) = stats.persist(&store) {
                    eprintln!("recall statistics writeback failed: {error:#}");
                }
                // Hit-heat writeback: top hits recall_count+1 - source of the heat-axis hit_score (used to be read-only, always 0; this round fills it)
                // Plugin hook post-recall: query and hit summary (post-training / external telemetry)
                {
                    let hits: Vec<(String, f32)> = ranked
                        .iter()
                        .map(|r| (r.entry.id.clone(), r.score))
                        .collect();
                    crate::hooks::fire(
                        crate::hooks::HookEvent::PostRecall,
                        crate::hooks::recall_payload(
                            &query,
                            project.as_deref().unwrap_or(""),
                            &hits,
                        ),
                    );
                }
            }
            if ranked.is_empty() {
                let mut result=ResultEnvelope::new(
                    "recall",
                    OutputStatus::Skip,
                    serde_json::json!({"query":query,"budget":budget,"query_log_id":query_log_id,"count":0,"recall_mode":recall_mode,
                        "selection_fallback":selection_fallback,"embedding_model":store.retrieval_model()?,"routing":routing,"best_cos":retrieval["best_cos"],"best_pre_floor":retrieval["best_pre_floor"],
                        "dropped_by_floor":retrieval["dropped_by_floor"],"cos_gate":retrieval["cos_gate"],"retrieval":retrieval,"filtered_by_score":retrieval["filtered_by_score"],
                        "intent": intent_label,"procedure_pass":procedure_pass,"procedure_promoted":procedure_promoted,
                        "index_pending":index_pending,"indexed_candidates":candidates.len().saturating_sub(index_pending),"lexical_candidates":index_pending}),
                    vec![OutputItem::new("results", OutputStatus::Skip, "0")],
                );
                if metadata_aware {
                    result.summary["metadata_aware"]=serde_json::json!(true);
                    result.summary["brief"]=serde_json::json!(brief_render);
                    result.summary["filtered_by_evidence"]=retrieval["filtered_by_evidence"].clone();
                    result.summary["evidence"]=retrieval["evidence"].clone();
                    result.details=serde_json::json!([]);
                }
                emit_result(result)?;
                return Ok(());
            }
            let mut items = ranked
                .iter()
                .map(|r| {
                    OutputItem::new(
                        respire_app::service::short_id(&r.entry.id),
                        OutputStatus::Ok,
                        format!(
                            "{:.3} {}",
                            r.score,
                            if r.entry.title.is_empty() {
                                "(untitled)"
                            } else {
                                &r.entry.title
                            }
                        ),
                    )
                })
                .collect::<Vec<_>>();
            for (hit,row) in ranked.iter().zip(items.iter_mut()) {
                if associations.superseded.contains_key(&hit.entry.id) { row.value.push_str(" [superseded]"); }
            }
            let mut result = ResultEnvelope::new(
                "recall",
                OutputStatus::Ok,
                serde_json::json!({"query":query,"budget":budget,"query_log_id":query_log_id,"count":ranked.len(),"limit":limit,"project":project,
                    "recall_mode":recall_mode,"selection_fallback":selection_fallback,"embedding_model":store.retrieval_model()?,"related":associations.related.len(),"routing":routing,"best_cos":retrieval["best_cos"],"best_pre_floor":retrieval["best_pre_floor"],
                        "dropped_by_floor":retrieval["dropped_by_floor"],"cos_gate":retrieval["cos_gate"],"retrieval":retrieval,"filtered_by_score":retrieval["filtered_by_score"],
                    "intent": intent_label,"procedure_pass":procedure_pass,"procedure_promoted":procedure_promoted,
                    "index_pending":index_pending,"indexed_candidates":candidates.len().saturating_sub(index_pending),"lexical_candidates":index_pending}),
                items,
            );
            result.related = associations.related;
            result.details = if titles {
                serde_json::json!(ranked
                    .iter()
                    .map(|r| serde_json::json!({
                        "id":r.entry.id,"title":r.entry.title,"score":r.score,
                        "superseded_by":associations.superseded.get(&r.entry.id)
                    }))
                    .collect::<Vec<_>>())
            } else {
                serde_json::json!(ranked
                    .iter()
                    .map(|r| serde_json::json!({
                        "score":r.score,"entry":r.entry,"ancestors":r.ancestors,
                        "superseded_by":associations.superseded.get(&r.entry.id)
                    }))
                    .collect::<Vec<_>>())
            };
            if metadata_aware {
                result.summary["metadata_aware"]=serde_json::json!(true);
                result.summary["brief"]=serde_json::json!(brief_render);
                result.summary["filtered_by_evidence"]=retrieval["filtered_by_evidence"].clone();
                if let Some(details)=result.details.as_array_mut() {
                    for (detail,hit) in details.iter_mut().zip(ranked.iter()) {
                        detail["evidence"]=retrieval["evidence"].as_array().and_then(|values|values.iter().find(|value|value["id"]==hit.entry.id))
                            .ok_or_else(||anyhow!("Core omitted recall evidence"))?.clone();
                        detail["source_refs"]=serde_json::json!(hit.entry.metadata.source_refs);
                        detail["scope"]=serde_json::json!(hit.entry.metadata.verification.as_ref().map(|value|&value.scope));
                        detail["valid_until"]=serde_json::json!(hit.entry.metadata.valid_until);
                        detail["representation"]=budget.as_ref().and_then(|receipt|receipt["items"].as_array())
                            .and_then(|values|values.iter().find(|value|value["id"]==hit.entry.id)).map(|item|item["representation"].clone())
                            .unwrap_or_else(||serde_json::json!(if titles{"title"}else{"full"}));
                    }
                }
            }
            emit_result(result)?;
        }
        Command::Attach { id, parent } => {
            let session = build_session()?;
            let store = build_local()?;
            // Always resolve_prefix: exact id -> exact catalog title -> 8-char prefix (char-safe)
            let all = store.all(true)?;
            let child = respire_app::service::resolve_prefix(&all, &id)?;
            let parent_full = respire_app::service::resolve_prefix(&all, &parent)?;
            if child == parent_full {
                return Err(respire_app::input_error::InputError("cannot attach to itself".into()).into());
            }
            // Cycle guard: the new parent's cause chain must not contain the child
            for anc in store.ancestor_chain(&parent_full)? {
                if anc == child {
                    return Err(respire_app::input_error::InputError("cycle: new parent is a descendant of this entry".into()).into());
                }
            }
            respire_app::service::reparent(&session, &store, &child, &parent_full)?;
            // Adoption: explicit attach is adoption (parent and child both count - choosing the hang and the attached entry are recall decisions)
            let _ = store.mark_adopted(&parent_full);
            let _ = store.mark_adopted(&child);
            emit_result(ResultEnvelope::new(
                "attach",
                OutputStatus::Ok,
                serde_json::json!({"child":child,"parent":parent_full}),
                vec![
                    OutputItem::new(
                        "child",
                        OutputStatus::Ok,
                        respire_app::service::short_id(&child),
                    ),
                    OutputItem::new(
                        "parent",
                        OutputStatus::Ok,
                        respire_app::service::short_id(&parent_full),
                    ),
                ],
            ))?;
            auto_sync(&session, &store);
        }
        Command::Chain { id, depth } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(false)?;
            let full = match respire_app::service::resolve_prefix(&all, id.as_str()) {
                Ok(v) => v,
                Err(e) => {
                    emit_result(ResultEnvelope::new(
                        "chain",
                        OutputStatus::Fail,
                        serde_json::json!({"id": id, "depth": depth}),
                        vec![OutputItem::new(
                            "entry",
                            OutputStatus::Fail,
                            format!("not found ({e})"),
                        )],
                    ))?;
                    return Ok(());
                }
            };
            let by_id: std::collections::HashMap<String, &respire_app::StoredMemory> =
                all.iter().map(|m| (m.id.clone(), m)).collect();
            let title_of = |pid: &str| -> String {
                by_id
                    .get(pid)
                    .map(|m| {
                        if m.local_title.is_empty() {
                            short_id(pid)
                        } else {
                            m.local_title.clone()
                        }
                    })
                    .unwrap_or_else(|| short_id(pid))
            };
            // 1. Cause chain: root -> direct parent, full body per layer (no truncate - chain is an explicit "I want the whole picture")
            let anc_ids = store.ancestor_chain(&full).unwrap_or_default();
            let mut ancestors: Vec<respire_app::MemoryEntry> = Vec::new();
            for pid in &anc_ids {
                if let Some(s) = by_id.get(pid) {
                    if let Ok(e) = MemoryEngine::open(&session, s) {
                        ancestors.push(e);
                    }
                }
            }
            let entry = by_id
                .get(&full)
                .and_then(|s| MemoryEngine::open(&session, s).ok());
            // 2. Effect chain: BFS down `depth` layers
            let mut descendants: Vec<(usize, respire_app::MemoryEntry)> = Vec::new();
            let mut frontier: Vec<(String, usize)> = vec![(full.clone(), 1)];
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            while let Some((cur, lv)) = frontier.pop() {
                if lv > depth {
                    continue;
                }
                for c in store.children(&cur).unwrap_or_default() {
                    if !seen.insert(c.id.clone()) {
                        continue;
                    }
                    if let Ok(e) = MemoryEngine::open(&session, &c) {
                        let next = e.id.clone();
                        descendants.push((lv, e));
                        frontier.push((next, lv + 1));
                    }
                }
            }
            let anc_json: Vec<serde_json::Value> = ancestors
                .iter()
                .map(|a| serde_json::json!({ "id": a.id, "title": a.title, "content": a.content }))
                .collect();
            let des_json: Vec<serde_json::Value> = descendants
                .iter()
                .map(|(lv, d)| serde_json::json!({ "level": lv, "id": d.id, "title": d.title, "content": d.content }))
                .collect();
            let mut items = Vec::with_capacity(ancestors.len() + descendants.len() + 1);
            for a in &ancestors {
                items.push(OutputItem::new(
                    format!("cause-{}", short_id(&a.id)),
                    OutputStatus::Ok,
                    title_of(&a.id),
                ));
            }
            if let Some(e) = &entry {
                items.push(OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    format!("{} {}", short_id(&e.id), e.title),
                ));
            }
            for (lv, d) in &descendants {
                items.push(OutputItem::new(
                    format!("effect-{lv}-{}", short_id(&d.id)),
                    OutputStatus::Ok,
                    d.title.clone(),
                ));
            }
            let mut result = ResultEnvelope::new(
                "chain",
                OutputStatus::Ok,
                serde_json::json!({"id": full, "depth": depth, "ancestors": ancestors.len(), "descendants": descendants.len()}),
                items,
            );
            result.details =
                serde_json::json!({"entry": entry, "ancestors": anc_json, "descendants": des_json});
            emit_result(result)?;
        }
        Command::Show { id } => {
            let session = build_session()?;
            let store = build_local()?;
            // Full id or first-8 prefix match
            let candidates = store.all(false)?;
            let mut hit: Option<&respire_app::StoredMemory> = None;
            for s in &candidates {
                if s.id == id
                    || (s.id.len() >= 8
                        && id.len() >= 8
                        && respire_app::service::short_id(&s.id) == respire_app::service::short_id(&id))
                {
                    hit = Some(s);
                    break;
                }
            }
            match hit {
                Some(s) => {
                    let e = MemoryEngine::open(&session, s)?;
                    let all_t = store.all(true).unwrap_or_default();
                    let title_of = |pid: &str| -> String {
                        all_t
                            .iter()
                            .find(|m| m.id == pid)
                            .map(|m| {
                                if m.local_title.is_empty() {
                                    short_id(&m.id)
                                } else {
                                    m.local_title.clone()
                                }
                            })
                            .unwrap_or_else(|| pid.chars().take(8).collect())
                    };
                    let ancestors: Vec<serde_json::Value> = store
                        .ancestor_chain(&e.id)
                        .unwrap_or_default()
                        .iter()
                        .map(|pid| serde_json::json!({"id":pid,"title":title_of(pid)}))
                        .collect();
                    let children: Vec<serde_json::Value> = store.children(&e.id).unwrap_or_default().iter().map(|c| serde_json::json!({"id":c.id,"title":if c.local_title.is_empty(){c.id.chars().take(8).collect::<String>()}else{c.local_title.clone()},"summary":c.local_content_head.chars().take(80).collect::<String>()})).collect();
                    let mut result = ResultEnvelope::new(
                        "show",
                        OutputStatus::Ok,
                        serde_json::json!({"id":e.id,"title":e.title}),
                        vec![OutputItem::new("entry", OutputStatus::Ok, short_id(&e.id))],
                    );
                    result.details = serde_json::json!({"entry":e,"ancestors":ancestors,"children":children,
                        "recall_count": s.local_recall_count});
                    emit_result(result)?;
                }
                None => emit_result(ResultEnvelope::new(
                    "show",
                    OutputStatus::Fail,
                    serde_json::json!({"id":id}),
                    vec![OutputItem::new("entry", OutputStatus::Fail, "not found")],
                ))?,
            }
        }
        Command::List {
            limit,
            since,
            since_resort,
            metadata,
        } => {
            let session = build_session()?;
            let (profile, store) = respire_app::service::open_store_with_profile()?;
            let mut candidates = store.all(false)?;
            let mut filter_summary = serde_json::Value::Null;
            // Time filter (§3.8 tidy intake): --since-resort reads resort_at, --since takes an explicit time;
            // both together take the later (stricter). Old entries with empty created_at are excluded.
            if since_resort || since.is_some() {
                let from = list_since_bound(since.as_deref(), since_resort)?;
                let before = candidates.len();
                candidates.retain(|s| s.local_created_at.as_str() > from.as_str());
                filter_summary =
                    serde_json::json!({"from": from, "before": before, "after": candidates.len()});
            }
            candidates.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            candidates.truncate(limit);
            let out: Vec<(respire_app::MemoryEntry, i64)> = candidates
                .iter()
                .filter_map(|s| {
                    MemoryEngine::open(&session, s)
                        .ok()
                        .map(|e| (e, s.local_recall_count))
                })
                .collect();
            let items = out
                .iter()
                .map(|(e, _)| OutputItem::new(short_id(&e.id), OutputStatus::Ok, e.title.clone()))
                .collect();
            let mut result = ResultEnvelope::new(
                "list",
                OutputStatus::Ok,
                serde_json::json!({"count":out.len(),"limit":limit,"filter":filter_summary,"profile":profile.to_string_lossy()}),
                items,
            );
            result.details = serde_json::Value::Array(
                out.into_iter()
                    .filter_map(|(e, recall_count)| {
                        let mut row = serde_json::to_value(e).ok()?;
                        if let Some(obj) = row.as_object_mut() {
                            if metadata {obj.remove("content");}
                            obj.insert("recall_count".into(), serde_json::json!(recall_count));
                        }
                        Some(row)
                    })
                    .collect(),
            );
            emit_result(result)?;
        }
        Command::Forget { id } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            let full = respire_app::service::resolve_prefix(&all, &id)?;
            let deleted = store.forget(&full)?;
            report_orphans(&store, "forget");
            if deleted {
                // Plugin hook post-forget: observe only
                crate::hooks::fire(
                    crate::hooks::HookEvent::PostForget,
                    crate::hooks::forget_payload(&full),
                );
            }
            let status = if deleted {
                OutputStatus::Ok
            } else {
                OutputStatus::Fail
            };
            emit_result(ResultEnvelope::new(
                "forget",
                status,
                serde_json::json!({"deleted":deleted,"id":full}),
                vec![OutputItem::new(
                    "entry",
                    status,
                    if deleted { "deleted" } else { "not found" },
                )],
            ))?;
            if deleted {
                schedule_autosync(&session, &store);
            }
        }
        Command::Purge { id } => {
            let session = build_session()?;
            let store = build_local()?;
            // Hard-delete must handle **already-forgotten tombstones** (purge's point is to clear tombstone ciphertext) -
            // resolve_prefix always filter(!deleted), so this path uses a dedicated include-deleted resolver.
            let full = resolve_prefix_incl_deleted(&store, &id)?;
            let purged = store.purge_entry(&full)?;
            report_orphans(&store, "purge");
            let status = if purged {
                OutputStatus::Ok
            } else {
                OutputStatus::Fail
            };
            emit_result(ResultEnvelope::new(
                "purge",
                status,
                serde_json::json!({"purged":purged,"id":full}),
                vec![OutputItem::new(
                    "entry",
                    status,
                    if purged { "purged" } else { "not found" },
                )],
            ))?;
            if purged {
                auto_sync(&session, &store);
            }
        }
        Command::Restore { id } => {
            if !build_local()?.all(true)?.iter().any(|entry| entry.id == id) {
                return Err(respire_app::input_error::InputError(format!("not found #{id}")).into());
            }
            let app = respire_app::service::App::open()?;
            let entry = app.restore(&id)?;
            emit_result(ResultEnvelope::new(
                "restore",
                OutputStatus::Ok,
                serde_json::json!({"id":entry.id,"restored":true}),
                vec![OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    short_id(&entry.id),
                )],
            ))?;
        }
        Command::Promote { id } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            // Short prefix is ok (counted in chars, CJK/multibyte-safe)
            let full = respire_app::service::resolve_prefix(&all, &id)?;
            let by_id: std::collections::HashMap<String, &respire_app::StoredMemory> =
                all.iter().map(|m| (m.id.clone(), m)).collect();
            let Some(me) = by_id.get(&full) else {
                emit_result(ResultEnvelope::new(
                    "promote",
                    OutputStatus::Fail,
                    serde_json::json!({"id": id}),
                    vec![OutputItem::new("entry", OutputStatus::Fail, "not found")],
                ))?;
                return Ok(());
            };
            if me.deleted || me.local_parent_id.is_empty() {
                emit_result(ResultEnvelope::new(
                    "promote",
                    OutputStatus::Skip,
                    serde_json::json!({"id": full, "reason": "already_root_or_deleted"}),
                    vec![OutputItem::new("entry", OutputStatus::Skip, "no change")],
                ))?;
                return Ok(());
            }
            let parent_id = me.local_parent_id.clone();
            // New cause = the cause's cause (grandparent); none -> promote to root
            let grandparent = by_id
                .get(&parent_id)
                .and_then(|p| {
                    if p.local_parent_id.is_empty() {
                        None
                    } else {
                        Some(p.local_parent_id.clone())
                    }
                })
                .unwrap_or_default();
            respire_app::service::reparent(&session, &store, &full, &grandparent)?;
            emit_result(ResultEnvelope::new(
                "promote",
                OutputStatus::Ok,
                serde_json::json!({"id": full, "new_parent": grandparent}),
                vec![OutputItem::new("entry", OutputStatus::Ok, short_id(&full))],
            ))?;
            auto_sync(&session, &store);
        }
        Command::Demote { id, parent } => {
            let session = build_session()?;
            let store = build_local()?;
            // Same resolve_prefix as attach (fixed 2026-09-21): --parent used to be exact-equal,
            // so a short prefix/catalog title always said "target cause missing", unlike attach.
            let all = store.all(true)?;
            let id_full = respire_app::service::resolve_prefix(&all, &id)?;
            let parent_full = respire_app::service::resolve_prefix(&all, &parent)?;
            if id_full == parent_full {
                anyhow::bail!("cannot demote onto itself");
            }
            // Cycle guard: the new cause (parent) chain must not contain this id
            let chain = store.ancestor_chain(&parent_full)?;
            if chain.iter().any(|p| *p == id_full) {
                anyhow::bail!("target cause is a descendant of this entry; that would cycle");
            }
            respire_app::service::reparent(&session, &store, &id_full, &parent_full)?;
            // Adoption: a demote-attach is adoption
            let _ = store.mark_adopted(&parent_full);
            let _ = store.mark_adopted(&id_full);
            emit_result(ResultEnvelope::new(
                "demote",
                OutputStatus::Ok,
                serde_json::json!({"id": id_full, "parent": parent_full}),
                vec![
                    OutputItem::new("entry", OutputStatus::Ok, short_id(&id_full)),
                    OutputItem::new("parent", OutputStatus::Ok, short_id(&parent_full)),
                ],
            ))?;
            auto_sync(&session, &store);
        }
        Command::Tree { from, depth, .. } => {
            let from = from.as_str();
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            let by_id: std::collections::HashMap<String, &respire_app::StoredMemory> =
                all.iter().map(|m| (m.id.clone(), m)).collect();
            let children_of = |pid: &str| -> Vec<String> {
                all.iter()
                    .filter(|m| !m.deleted && m.local_parent_id == pid)
                    .map(|m| m.id.clone())
                    .collect()
            };
            let label = |id: &str| -> String {
                by_id
                    .get(id)
                    .map(|m| {
                        if m.local_title.is_empty() {
                            id[..id.len().min(8)].to_owned()
                        } else {
                            m.local_title.clone()
                        }
                    })
                    .unwrap_or_else(|| id[..id.len().min(8)].to_owned())
            };
            fn render(
                store: &LocalStore,
                by_id: &std::collections::HashMap<String, &respire_app::StoredMemory>,
                children_of: &dyn Fn(&str) -> Vec<String>,
                label: &dyn Fn(&str) -> String,
                node: &str,
                depth: usize,
                prefix: &str,
                out: &mut Vec<String>,
            ) {
                let title = label(node);
                let kids = children_of(node);
                let meta = by_id.get(node).map(|m| m.local_kind.as_str()).unwrap_or("");
                let leaf = kids.is_empty();
                let level = prefix.chars().filter(|c| *c == '|').count();
                out.push(format!(
                    "id={} title={} kind={} level={} leaf={}",
                    node[..node.len().min(8)].to_owned(),
                    title,
                    meta,
                    level,
                    leaf
                ));
                if depth == 0 {
                    return;
                }
                let n = kids.len();
                for (i, kid) in kids.iter().enumerate() {
                    let last = i == n - 1;
                    let branch = if last { "`-- " } else { "|-- " };
                    // M1 (2026-09-20 audit): child-layer prefix must use next_prefix - non-last-child
                    // descendants inherit the vertical bar, else a 3-level tree renders `|-- |-- A1` instead of
                    // `|  |-- A1`. Code used to compute next_prefix then pass prefix, with
                    // `let _ = next_prefix;` silencing the unused warning - that line hid the bug.
                    let next_prefix = format!("{prefix}{}", if last { "   " } else { "|  " });
                    render(
                        store,
                        by_id,
                        children_of,
                        label,
                        kid,
                        depth - 1,
                        &format!("{next_prefix}{branch}"),
                        out,
                    );
                }
            }
            let _ = &session;
            let mut out = Vec::new();
            if from.is_empty() {
                let roots: Vec<String> = by_id
                    .iter()
                    .filter(|(_, m)| !m.deleted && m.local_parent_id.is_empty())
                    .map(|(id, _)| id.clone())
                    .collect();
                if roots.is_empty() {
                    emit_result(ResultEnvelope::new(
                        "tree",
                        OutputStatus::Skip,
                        serde_json::json!({"roots": 0, "depth": depth}),
                        vec![OutputItem::new("tree", OutputStatus::Skip, "no roots")],
                    ))?;
                    return Ok(());
                }
                for r in roots {
                    out.push(format!(
                        "id={} title={} kind=root level=0 leaf={}",
                        r[..r.len().min(8)].to_owned(),
                        label(&r),
                        children_of(&r).is_empty()
                    ));
                    let kids = children_of(&r);
                    let n = kids.len();
                    for (i, kid) in kids.iter().enumerate() {
                        let last = i == n - 1;
                        let branch = if last { "`-- " } else { "|-- " };
                        render(
                            &store,
                            &by_id,
                            &children_of,
                            &label,
                            kid,
                            depth - 1,
                            &branch,
                            &mut out,
                        );
                    }
                }
            } else {
                let full_from = respire_app::service::resolve_prefix(&all, from)?;
                out.push(format!(
                    "root={} depth={} mode=from",
                    short_id(&full_from),
                    depth
                ));
                render(
                    &store,
                    &by_id,
                    &children_of,
                    &label,
                    &full_from,
                    depth,
                    "",
                    &mut out,
                );
            }
            let items = out
                .iter()
                .enumerate()
                .map(|(i, row)| {
                    OutputItem::new(format!("node-{}", i + 1), OutputStatus::Ok, row.clone())
                })
                .collect();
            let mut result = ResultEnvelope::new(
                "tree",
                OutputStatus::Ok,
                serde_json::json!({"count": out.len(), "depth": depth, "from": from}),
                items,
            );
            result.details = serde_json::json!({"rows": out});
            emit_result(result)?;
        }
        Command::Retitle { id, title } => {
            // M5: omitting --title used to silently blank the title (data damage). Now required.
            let Some(new_title) = title.as_ref().filter(|t| !t.trim().is_empty()) else {
                anyhow::bail!("need --title <new-title> (omitting it would blank the title, so there is no empty default)");
            };
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            // M4: use the shared prefix resolver (used to be exact match; 8-char short id said "not found").
            let full = respire_app::service::resolve_prefix(&all, id.as_str())?;
            let Some(stored) = all.iter().find(|m| m.id == full && !m.deleted) else {
                emit_result(ResultEnvelope::new(
                    "retitle",
                    OutputStatus::Fail,
                    serde_json::json!({"id": id}),
                    vec![OutputItem::new("entry", OutputStatus::Fail, "not found")],
                ))?;
                return Ok(());
            };
            let mut entry = MemoryEngine::open(&session, stored)?;
            respire_app::metadata_gate::ensure_write(&store, &entry)?;
            let old = entry.title.clone();
            entry.title = new_title.clone();
            // Bump updated_at (LWW needs a new timestamp so a remote old blob cannot push back)
            entry.updated_at = store.edit_stamp(&stored.id)?;
            entry.modified_by = respire_app::service::device_tag();
            let user = entry.user.clone();
            let new_stored = MemoryEngine::seal(&session, embedder!(), &entry, &user)?;
            store.put(&new_stored)?;
            // Adoption: a retitle is adoption
            let _ = store.mark_adopted(&stored.id);
            let mut result = ResultEnvelope::new(
                "retitle",
                OutputStatus::Ok,
                serde_json::json!({"id": entry.id, "old_title": old, "new_title": new_title}),
                vec![OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    short_id(&entry.id),
                )],
            );
            result.details = serde_json::json!({"entry": entry});
            emit_result(result)?;
            auto_sync(&session, &store);
        }
        Command::RetitleMany { file } => {
            let session = build_session()?;
            let store = build_local()?;
            let text = std::fs::read_to_string(&file)
                .map_err(|e| anyhow!("failed to read {file}: {e}"))?;
            let items: Vec<serde_json::Value> =
                serde_json::from_str(&text).map_err(|e| anyhow!("failed to parse {file}: {e}"))?;
            let all = store.all(true)?;
            let by_id: std::collections::HashMap<&str, &respire_app::StoredMemory> =
                all.iter().map(|m| (m.id.as_str(), m)).collect();
            for item in &items {
                let id = item["id"].as_str().unwrap_or_default();
                if let Some(stored) = by_id.get(id).copied().filter(|row| !row.deleted) {
                    respire_app::metadata_gate::ensure_write(&store, &MemoryEngine::open(&session, stored)?)?;
                }
            }
            let mut done = 0usize;
            let mut missing = 0usize;
            for it in &items {
                let id = it["id"].as_str().unwrap_or_default();
                let title = it["title"].as_str().unwrap_or_default().to_owned();
                if id.is_empty() {
                    continue;
                }
                let Some(stored) = by_id.get(id).copied().filter(|m| !m.deleted) else {
                    missing += 1;
                    continue;
                };
                let mut entry = MemoryEngine::open(&session, stored)?;
                entry.title = title;
                entry.updated_at = store.edit_stamp(&stored.id)?;
                entry.modified_by = respire_app::service::device_tag();
                let user = entry.user.clone();
                let new_stored = MemoryEngine::seal(&session, embedder!(), &entry, &user)?;
                store.put(&new_stored)?;
                done += 1;
            }
            let status = if missing == 0 {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            emit_result(ResultEnvelope::new(
                "retitle-many",
                status,
                serde_json::json!({"updated": done, "missing": missing}),
                vec![
                    OutputItem::new("updated", OutputStatus::Ok, done.to_string()),
                    OutputItem::new(
                        "missing",
                        if missing == 0 {
                            OutputStatus::Ok
                        } else {
                            OutputStatus::Warn
                        },
                        missing.to_string(),
                    ),
                ],
            ))?;
            auto_sync(&session, &store);
        }
        Command::SyncConflicts { id, all, refresh } => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            if refresh {
                sync_tracked(&session, &local, &sync_phase(build_remote)?)?;
            }
            let mut after = 0;
            while let Some(next) =
                sync_phase(|| local.classify_conflicts_batch(&session, false, after))?
            {
                after = next;
            }
            let conflicts = sync_phase(|| local.list_conflicts(&session, id.as_deref(), all))?;
            let status = if conflicts.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            let mut result = ResultEnvelope::new(
                "sync-conflicts",
                status,
                serde_json::json!({"count": conflicts.len(), "refresh": refresh}),
                vec![OutputItem::new(
                    "conflicts",
                    status,
                    conflicts.len().to_string(),
                )],
            );
            if !conflicts.is_empty() {
                result.actions.push("sync-conflicts --json".into());
            }
            result.details = serde_json::Value::Array(conflicts);
            emit_result(result)?;
        }
        Command::SyncResolve {
            epoch,
            rev,
            head_rev,
            action,
            content,
        } => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            let remote = sync_phase(build_remote)?;
            sync_tracked(&session, &local, &remote)?;
            sync_phase(|| {
                local.queue_conflict_resolution(
                    &session,
                    &epoch,
                    rev,
                    head_rev,
                    &action.replace('-', "_"),
                    content.as_deref(),
                )
            })?;
            let stats = sync_tracked(&session, &local, &remote)?;
            let processed = sync_phase(|| local.processed_conflict_action(&epoch, rev))?;
            emit_result(ResultEnvelope::new(
                "sync-resolve",
                if processed.is_some() {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Pending
                },
                serde_json::json!({"epoch":epoch,"rev":rev,"processed":processed.is_some(),"action":processed,"pending_conflicts":stats.conflicts}),
                vec![OutputItem::new(
                    "revision",
                    if processed.is_some() {
                        OutputStatus::Ok
                    } else {
                        OutputStatus::Pending
                    },
                    rev.to_string(),
                )],
            ))?;
            if processed.is_none() {
                anyhow::bail!("current version changed or the adopt conflicted; the record is still pending - re-run sync-conflicts");
            }
        }
        Command::SyncHistory { id, remote } => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            let mut history = sync_phase(|| local.sync_history(id.as_deref()))?;
            if remote {
                let transport = sync_phase(build_remote)?;
                let cap = transport
                    .capabilities()?
                    .ok_or_else(|| anyhow!("server does not support revision history"))?;
                let changes =
                    read_remote_sync_history(&transport, &cap.epoch, id.as_deref(), None, None)?;
                let local_operations: Vec<_> = history
                    .into_iter()
                    .filter(|row| row.get("rev").is_none())
                    .collect();
                history = changes
                    .into_iter()
                    .map(|change| {
                        serde_json::json!({
                            "epoch":cap.epoch, "rev":change.rev, "status":change.status,
                            "op_id":change.op_id, "blob":change.blob
                        })
                    })
                    .collect();
                history.extend(local_operations);
            }
            for row in &mut history {
                let b: respire_app::StoredMemory = serde_json::from_value(row["blob"].clone())?;
                match MemoryEngine::open(&session, &b) {
                    Ok(entry) => row["entry"] = serde_json::to_value(entry)?,
                    Err(e) => row["decode_error"] = serde_json::json!(e.to_string()),
                }
                if let Some(obj) = row.as_object_mut() {
                    obj.remove("blob");
                }
            }
            let mut result = ResultEnvelope::new(
                "sync-history",
                OutputStatus::Ok,
                serde_json::json!({"count": history.len(), "remote": remote}),
                vec![OutputItem::new(
                    "versions",
                    OutputStatus::Ok,
                    history.len().to_string(),
                )],
            );
            result.details = serde_json::Value::Array(history);
            if !result.details.as_array().is_some_and(Vec::is_empty) {
                result.actions.push("sync-history --json".into());
            }
            emit_result(result)?;
        }
        Command::SyncRestore { op_id, rev, epoch } => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            let id = match sync_phase(|| {
                local.restore_sync_version(&session, op_id.as_deref(), rev, epoch.as_deref())
            }) {
                Ok(id) => id,
                Err(error) if error.is::<respire_app::transport::local::SyncVersionNotFound>() => {
                    let transport = sync_phase(build_remote)?;
                    let cap = transport
                        .capabilities()?
                        .ok_or_else(|| anyhow!("server does not support revision history"))?;
                    if epoch.as_deref().is_some_and(|value| value != cap.epoch) {
                        anyhow::bail!("the server no longer retains the requested sync epoch");
                    }
                    let change = read_remote_sync_history(
                        &transport,
                        &cap.epoch,
                        None,
                        op_id.as_deref(),
                        if op_id.is_some() { None } else { rev },
                    )?
                    .pop()
                    .ok_or_else(|| anyhow!("version not found on the server"))?;
                    let page = respire_app::transport::protocol::Page {
                        epoch: cap.epoch,
                        until: change.rev,
                        cursor: change.rev,
                        has_more: false,
                        changes: vec![change],
                        total: 0,
                        alive: 0,
                    };
                    sync_phase(|| {
                        local.cache_history(&page)?;
                        local.restore_sync_version(
                            &session,
                            op_id.as_deref(),
                            rev,
                            epoch.as_deref(),
                        )
                    })?
                }
                Err(error) => return Err(error),
            };
            emit_result(ResultEnvelope::new(
                "sync-restore",
                OutputStatus::Pending,
                serde_json::json!({"restored":id,"pending_sync":true}),
                vec![OutputItem::new("restored", OutputStatus::Pending, &id).action("sync")],
            ))?;
            auto_sync(&session, &local);
        }
        Command::SyncReset => {
            build_local()?.reset_sync_snapshot()?;
            let mut result = ResultEnvelope::new(
                "sync-reset",
                OutputStatus::Ok,
                serde_json::json!({"history_kept":false,"current_snapshots_kept":true,"pending_outbound_kept":true}),
                vec![
                    OutputItem::new("snapshot", OutputStatus::Ok, "reset"),
                    OutputItem::new("history", OutputStatus::Ok, "kept"),
                    OutputItem::new("pending outbound", OutputStatus::Ok, "kept"),
                ],
            );
            result.actions.push("sync".into());
            emit_result(result)?;
        }
        Command::Sync => {
            progress::phase("\u{8bfb}\u{53d6}\u{8d26}\u{6237}\u{548c}\u{5f85}\u{540c}\u{6b65}\u{6570}\u{636e}", "Reading account and pending sync data");
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            let remote = sync_phase(build_remote)?;
            let mut stats = sync_with_retry(&session, &local, &remote)?;
            let mut purged = 0usize;
            // Auto-purge old tombstones (purge_days from agent.json; 0=immediate, default 30)
            let purge_days = respire_app::service::read_agent_config()
                .get("purge_days")
                .and_then(|v| v.as_i64())
                .unwrap_or(30);
            if purge_days >= 0 && !respire_app::service::readonly_mode() {
                let n = sync_phase(|| local.auto_purge_old(purge_days))?;
                purged = n;
                if n > 0 {
                    // Maintenance creates later operations; never extend the caller's upload boundary.
                    schedule_autosync(&session, &local);
                    stats.pending = sync_phase(|| local.sync_counts())?.0;
                }
            }
            // One hook after all rounds, with the same totals as the final report.
            crate::hooks::fire(
                crate::hooks::HookEvent::PostSync,
                crate::hooks::sync_payload(stats.pulled, stats.pushed),
            );
            // Missing vectors are durable index work, not part of network sync.
            let index_pending = sync_phase(|| local.missing_embedding())?.len();
            let local_blobs = sync_phase(|| local.all(true))?;
            let local_total = local_blobs.len();
            let local_alive = local_blobs.iter().filter(|m| !m.deleted).count();
            let total_matched = local_total == stats.remote_total;
            let converged = total_matched && local_alive == stats.remote_alive;
            let sync_status = if converged && stats.conflicts == 0 && stats.undecodable == 0 {
                OutputStatus::Ok
            } else if stats.conflicts > 0 || stats.undecodable > 0 || !total_matched {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            };
            if json_mode() {
                let summary = serde_json::json!({
                    "pulled": stats.pulled, "pushed": stats.pushed,
                    "remote_total": stats.remote_total, "remote_alive": stats.remote_alive,
                    "local_total": local_total, "local_alive": local_alive,
                    "total_matched": total_matched, "converged": converged,
                    "protocol": stats.protocol, "pending": stats.pending,
                    "conflicts": stats.conflicts, "conflict_history": stats.conflict_history,
                    "processed_conflicts": stats.processed_conflicts,
                    "historical_conflicts": stats.historical_conflicts,
                    "resolving_conflicts": stats.resolving_conflicts,
                    "resolution_supported": stats.resolution_supported,
                    "undecodable": stats.undecodable, "index_pending": index_pending,
                    "purged": purged,
                });
                let mut result = ResultEnvelope::new("sync", sync_status, summary, Vec::new());
                if stats.conflicts > 0 {
                    result.actions.push("sync-conflicts".into());
                }
                if index_pending > 0 {
                    result.actions.push("reembed".into());
                }
                emit_result(result)?;
                return Ok(());
            }
            let mut result = ResultEnvelope::new(
                "sync",
                sync_status,
                serde_json::json!({
                    "pulled": stats.pulled, "pushed": stats.pushed,
                    "remote_total": stats.remote_total, "remote_alive": stats.remote_alive,
                    "local_total": local_total, "local_alive": local_alive,
                    "total_matched": total_matched, "converged": converged,
                    "protocol": stats.protocol, "pending": stats.pending,
                    "conflicts": stats.conflicts, "conflict_history": stats.conflict_history,
                    "processed_conflicts": stats.processed_conflicts,
                    "historical_conflicts": stats.historical_conflicts,
                    "resolving_conflicts": stats.resolving_conflicts,
                    "resolution_supported": stats.resolution_supported,
                    "undecodable": stats.undecodable, "index_pending": index_pending,
                    "purged": purged,
                }),
                vec![
                    OutputItem::new(
                        "remote",
                        OutputStatus::Ok,
                        format!(
                            "{} total / {} active",
                            stats.remote_total, stats.remote_alive
                        ),
                    ),
                    OutputItem::new(
                        "local",
                        OutputStatus::Ok,
                        format!("{} total / {} active", local_total, local_alive),
                    ),
                    OutputItem::new(
                        "changes",
                        OutputStatus::Ok,
                        format!("pulled {} / pushed {}", stats.pulled, stats.pushed),
                    ),
                    OutputItem::new(
                        "state",
                        sync_status,
                        if converged {
                            "converged"
                        } else if total_matched {
                            "active-count-diff"
                        } else {
                            "not-converged"
                        },
                    ),
                    OutputItem::new(
                        "pending",
                        if stats.pending > 0
                            || stats.conflicts > 0
                            || stats.undecodable > 0
                            || index_pending > 0
                        {
                            OutputStatus::Warn
                        } else {
                            OutputStatus::Ok
                        },
                        format!(
                            "send {} / conflicts {} / decrypt {} / index {}",
                            stats.pending, stats.conflicts, stats.undecodable, index_pending
                        ),
                    ),
                    OutputItem::new("purged", OutputStatus::Ok, purged.to_string()),
                ],
            );
            if stats.conflicts > 0 {
                result.actions.push("sync-conflicts".into());
            }
            if index_pending > 0 {
                result.actions.push("reembed".into());
            }
            emit_result(result)?;
        }
        Command::Status => {
            if json_mode() {
                // Lightweight status (no session unlock, no embedder) - the client calls this often at start; must be fast
                let app_status = respire_app::service::status_light()?;
                let si = respire_app::service::session_info();
                // "local store is readable" = this machine has a key wrap (wrapped_urk) and can unwrap it - unrelated to "logged into the cloud".
                // Old code used has_token: offline local mode has no token, always showed locked, the client kept popping login
                // asking to "join the memory store" (user report 2026-09-16). Rule: a key wrap means the local store is joined;
                // an empty nominal user (offline keygen with no name) still counts as joined.
                let unlocked = si.has_local_keys;
                let mut v = serde_json::json!({
                    "unlocked": unlocked,
                    "offline": !remote_configured() && si.has_local_keys,
                    "data_dir": app_status.data_dir,
                    "session": si,
                    "server_addr": respire_app::service::server_addr(),
                    "autosync": respire_app::service::autosync_enabled(),
                    "remote_configured": remote_configured(),
                });
                v["local_total"] = serde_json::json!(app_status.local_total);
                v["local_alive"] = serde_json::json!(app_status.local_alive);
                v["max_updated_at"] = serde_json::json!(app_status.max_updated_at);
                v["workspace"] = serde_json::json!(respire_app::service::workspace_mode());
                let live = sync_live();
                v["sync_scheduler"] = rpc::sync_scheduler_status();
                v["recall_statistics"] = rpc::recall_stats_status();
                v["retrieval_index"] = rpc::index_status();
                v["model_operation"] = crate::model_progress::status()?;
                v["sync_live"] = serde_json::json!({
                    "phase": if live.phase.is_empty() { "idle" } else { live.phase.as_str() },
                    "pulled": live.pulled,
                    "pushed": live.pushed,
                    "remote_alive": live.remote_alive,
                    "pending": live.pending,
                    "conflicts": live.conflicts,
                    "error": live.error,
                });
                emit_result(ResultEnvelope::new(
                    "status",
                    OutputStatus::Ok,
                    v,
                    Vec::new(),
                ))?;
                return Ok(());
            }
            let app_status = respire_app::service::status_light()?;
            let count = app_status.local_alive;
            let user = read_session_json()
                .ok()
                .and_then(|d| d["user"].as_str().map(|s| s.to_owned()))
                .unwrap_or_else(|| "local".to_owned());
            let (mode, server) = match remote_config_from_session_or_env()? {
                Some((addr, _)) => {
                    let mode = if respire_app::service::autosync_enabled() {
                        "cloud sync (auto)"
                    } else {
                        "cloud sync (manual)"
                    };
                    (mode, Some(addr))
                }
                None => ("local authority store (offline)", None),
            };
            let mut items = vec![
                OutputItem::new("mode", OutputStatus::Ok, mode),
                OutputItem::new("user", OutputStatus::Ok, user),
                OutputItem::new("memories", OutputStatus::Ok, count.to_string()),
                OutputItem::new(
                    "local_total",
                    OutputStatus::Ok,
                    app_status.local_total.to_string(),
                ),
                OutputItem::new(
                    "max_updated_at",
                    OutputStatus::Ok,
                    app_status.max_updated_at.clone().unwrap_or_default(),
                ),
            ];
            if let Some(addr) = server.as_ref() {
                items.insert(2, OutputItem::new("server", OutputStatus::Ok, addr.clone()));
            }
            emit_result(ResultEnvelope::new(
                "status",
                OutputStatus::Ok,
                serde_json::json!({
                    "remote_configured": server.is_some(),
                    "local_alive": count,
                    "local_total": app_status.local_total,
                    "retrieval_index": rpc::index_status(),
                    "model_operation": crate::model_progress::status()?,
                    "max_updated_at": app_status.max_updated_at,
                }),
                items,
            ))?;
        }
        Command::Reembed => {
            let _operation = crate::model_progress::Operation::try_begin_background_index()?
                .ok_or_else(|| anyhow::anyhow!("another model operation is running"))?;
            let session = build_session()?;
            let store = build_local()?;
            let model = store.retrieval_model()?;
            let n = store.rebuild_index_with_progress(
                &session, embedder!(), &model,
                |done, total| crate::model_progress::update(
                    "index", &model, done as u64, Some(total as u64),
                ),
            )?;
            let dims = embedder!().dims();
            emit_result(ResultEnvelope::new(
                "reembed",
                OutputStatus::Ok,
                serde_json::json!({"reembedded":n,"dims":dims}),
                vec![
                    OutputItem::new("reembedded", OutputStatus::Ok, n.to_string()),
                    OutputItem::new("dimensions", OutputStatus::Ok, dims.to_string()),
                ],
            ))?;
        }
        Command::Candidates { content } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = scoped_candidates(&store)?;
            let report = respire_app::service::candidate_report(&session, embedder!(), &all, &content)?;
            let mut result = ResultEnvelope::new(
                "candidates",
                OutputStatus::Ok,
                serde_json::json!({"merge_count":report.merge.len(),"parent_count":report.parent.len()}),
                vec![
                    OutputItem::new(
                        "merge candidates",
                        OutputStatus::Ok,
                        report.merge.len().to_string(),
                    ),
                    OutputItem::new(
                        "parent candidates",
                        OutputStatus::Ok,
                        report.parent.len().to_string(),
                    ),
                ],
            );
            result.details = serde_json::json!({"merge":report.merge,"parent":report.parent});
            result.actions.push("candidates <content> --json".into());
            result.actions.extend(respire_app::service::write_decision_actions().iter().map(|action| (*action).to_owned()));
            emit_result(result)?;
        }
        Command::V => unreachable!("version is printed before run_local work"),
        Command::Mcp => unreachable!("mcp is served before run_local"),
        Command::Passport => {
            return run_passport();
        }
        Command::History { id, limit } => {
            let store = build_local()?;
            let full = match id.as_deref() {
                Some(i) => {
                    let all = store.all(true)?;
                    Some(respire_app::service::resolve_prefix(&all, i)?)
                }
                None => None,
            };
            let rows = store.entry_audit(full.as_deref(), limit)?;
            if json_mode() {
                let mut result = ResultEnvelope::new(
                    "history",
                    OutputStatus::Ok,
                    serde_json::json!({"count": rows.len()}),
                    Vec::new(),
                );
                result.details = serde_json::Value::Array(rows);
                emit_result(result)?;
                return Ok(());
            }
            let status = if rows.is_empty() {
                OutputStatus::Skip
            } else {
                OutputStatus::Ok
            };
            let items = rows
                .iter()
                .map(|r| {
                    let ts = r["ts"].as_str().unwrap_or("");
                    let action = r["action"].as_str().unwrap_or("");
                    let id = r["entry_id"].as_str().unwrap_or("").get(..8).unwrap_or("");
                    let title = r["title"].as_str().unwrap_or("");
                    OutputItem::new("change", status, format!("{ts} {action} {id} {title}"))
                })
                .collect::<Vec<_>>();
            let mut result = ResultEnvelope::new(
                "history",
                status,
                serde_json::json!({"count": rows.len()}),
                if items.is_empty() {
                    vec![OutputItem::new(
                        "history",
                        OutputStatus::Skip,
                        "no change records",
                    )]
                } else {
                    items
                },
            );
            result.details = serde_json::Value::Array(rows);
            emit_result(result)?;
        }
        Command::Plugin { command } => match command {
            PluginCommand::List => {
                let cfg = crate::hooks::read_config();
                let path = crate::hooks::config_path();
                let mut items = Vec::new();
                for (ev, hooks) in &cfg.hooks {
                    for h in hooks {
                        let policy = if h.on_error.is_empty() {
                            "default"
                        } else {
                            &h.on_error
                        };
                        items.push(OutputItem::new(
                            ev,
                            OutputStatus::Ok,
                            format!("{} timeout={}ms on_error={policy}", h.cmd, h.timeout_ms),
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
                        "events": crate::hooks::EVENT_NAMES,
                        "count": cfg.hooks.values().map(Vec::len).sum::<usize>(),
                    }),
                    items,
                );
                result.details = serde_json::to_value(&cfg.hooks)?;
                result
                    .actions
                    .push("plugin test <EVENT> --payload <JSON>".into());
                emit_result(result)?;
            }
            PluginCommand::Test { event, payload } => {
                let ev = crate::hooks::HookEvent::parse(event.as_str()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown event \"{event}\"; available: {}",
                        crate::hooks::EVENT_NAMES.join(" / ")
                    )
                })?;
                let data: serde_json::Value = serde_json::from_str(payload.as_str())
                    .map_err(|e| anyhow::anyhow!("--payload is not JSON: {e}"))?;
                let v = crate::hooks::fire(ev, data);
                let status = if v.blocked {
                    OutputStatus::Warn
                } else {
                    OutputStatus::Ok
                };
                let mut result = ResultEnvelope::new(
                    "plugin-test",
                    status,
                    serde_json::json!({"event": ev.as_str(), "blocked": v.blocked, "warning_count": v.warnings.len()}),
                    vec![OutputItem::new(
                        "event",
                        status,
                        if v.blocked {
                            format!("{} blocked: {}", ev.as_str(), v.reason)
                        } else {
                            format!("{} allowed", ev.as_str())
                        },
                    )],
                );
                result.details = serde_json::json!({"event": ev.as_str(), "blocked": v.blocked, "reason": v.reason, "warnings": v.warnings});
                if v.blocked {
                    result.actions.push("review plugin policy".into());
                }
                emit_result(result)?;
            }
        },
        Command::Update {
            id,
            metadata,
            title,
            content,
            tags,
            kind,
            importance,
        } => {
            if metadata.patch().is_some() || kind.as_deref().is_some_and(|kind| matches!(kind, "hypothesis" | "reflection" | "self")) {
                respire_app::metadata_gate::require_support()?;
            }
            if let Some(imp) = importance.as_deref() {
                // Two-tier: normal is retired; update may not set normal either
                if !matches!(imp, "important" | "trivial") {
                    anyhow::bail!(
                        "importance must be important/trivial (normal is retired), got \"{}\"",
                        imp
                    );
                }
            }
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            let full = respire_app::service::resolve_prefix(&all, &id)?;
            let stored = all
                .iter()
                .find(|m| m.id == full && !m.deleted)
                .ok_or_else(|| anyhow!("not found #{id}"))?;
            let mut entry = MemoryEngine::open(&session, stored)?;
            let original_entry = entry.clone();
            if let Some(t) = title {
                entry.title = t;
            }
            if let Some(c) = content {
                entry.content = c;
            }
            if let Some(tg) = tags {
                entry.tags = tg
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
            }
            if let Some(k) = kind {
                entry.kind = Kind::try_from_str(&k.trim().to_lowercase()).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?;
            }
            if let Some(imp) = importance {
                let imp = imp.trim().to_lowercase();
                if !matches!(imp.as_str(), "important" | "normal" | "trivial") {
                    anyhow::bail!(
                        "invalid importance: {imp} (choose important / trivial; normal is retired)"
                    );
                }
                entry.importance = imp;
            }
            metadata.apply(&mut entry);
            let metadata_receipt = metadata::prepare(&session, &store, &entry)?;
            let skill_missing = if entry.kind == Kind::Skill && entry.importance == "important" {
                let missing = skill::missing_sections(&entry.content);
                if !missing.is_empty() {
                    eprintln!(
                        "WARN skill template missing {} - add {} (see `rsrs audit`)",
                        missing.join("/"),
                        skill::SECTIONS.join("/")
                    );
                }
                missing
            } else {
                Vec::new()
            };
            entry.updated_at = store.edit_stamp(&stored.id)?;
            entry.modified_by = respire_app::service::device_tag();
            let user = entry.user.clone();
            let mut new_stored = MemoryEngine::seal(&session, embedder!(), &entry, &user)?;
            if respire_app::core_sdk::indexing_deferred() && !stored.local_artifact.is_empty() {
                let reusable: bool = respire_app::core_sdk::execute("index_reusable",
                    serde_json::json!({"before":original_entry,"after":entry}))?;
                if reusable { new_stored.local_artifact = stored.local_artifact.clone(); }
            }
            anyhow::ensure!(commit_prepared_write(short_write, write_generation, || store.put_checked(&new_stored, Some(&stored.ciphertext)))?, "memory was not saved");
            // Adoption: an update is adoption - if a query in the last 10 minutes hit this entry, record it in query_log
            let _ = store.mark_adopted(&stored.id);
            let hint = note_write_maintenance();
            let mut result = ResultEnvelope::new(
                "update",
                if skill_missing.is_empty() {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Warn
                },
                serde_json::json!({"action":"written", "id": stored.id, "maintenance_hint": hint,
                    "skill_template_missing": skill_missing,
                    "index_state": if new_stored.local_artifact.is_empty() { "pending" } else { "ready" }}),
                vec![OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    format!(
                        "{} {}",
                        stored.id.get(..8).unwrap_or(&stored.id),
                        entry.title
                    ),
                )],
            );
            if !skill_missing.is_empty() {
                result.actions.push(format!(
                    "skill template missing {}; add {}",
                    skill_missing.join("/"),
                    skill::SECTIONS.join("/")
                ));
            }
            metadata::add_receipt(&mut result, metadata_receipt);
            result.details = serde_json::to_value(entry)?;
            emit_result(result)?;
            schedule_autosync(&session, &store);
        }
        // The commands above already returned at the top of this function (no embedder needed); this arm is unreachable - only to exhaust the match.
        Command::MemoryRevision
        | Command::Metadata { .. }
        | Command::Review { .. }
        | Command::Capabilities
        | Command::Keygen { .. }
        | Command::Session { .. }
        | Command::Grant { .. } => {
            unreachable!("already returned at the top of main")
        }
        Command::Defrag { .. }
        | Command::TreeCure { .. }
        | Command::TreeFloat { .. }
        | Command::Split { .. }
        | Command::Extract { .. }
        | Command::Inject { .. }
        | Command::TreeDeepen { .. }
        | Command::Config { .. }
        | Command::Export { .. }
        | Command::Backup { .. }
        | Command::Snapshot { .. }
        | Command::Secret { .. }
        | Command::Fivekeys { .. }
        | Command::Register { .. }
        | Command::Login { .. }
        | Command::KeysExport { .. }
        | Command::SuperReset { .. }
        | Command::BookMaterial { .. }
        | Command::PortraitMaterial { .. }
        | Command::Doctor { .. }
        | Command::Audit { .. }
        | Command::Witness { .. }
        | Command::UpdateCheck { .. }
        | Command::Model { .. }
        | Command::Share { .. }
        | Command::Diary { .. }
        | Command::DiarySearch { .. }
        | Command::DiaryFragment { .. }
        | Command::Taxonomy { .. }
        | Command::RootCreate { .. }
        | Command::Repack
        | Command::Logout { .. }
        | Command::Account { .. }
        | Command::Migrate { .. }
        | Command::Space { .. }
        | Command::Resort { .. }
        | Command::AgentConfig { .. }
        | Command::Prompt
        | Command::QueryLog { .. }
        | Command::Bench { .. }
        | Command::RunLog { .. }
        | Command::Classify { .. }
        | Command::Web { .. }
        | Command::Restart { .. }
        | Command::ClassifyConfig { .. } => unreachable!(
            "commands that do not need the embedder already returned at the top of main"
        ),
    }
    Ok(())
}


//! Aside browser-agent scanner.
//!
//! Ported from the reference finder's `agent_sessions/aside_scanner.py`.
//!
//! Stores: `~/.aside/u/<n>/sessions/<date>_<id>/messages.jsonl` transcripts,
//! joined with the per-user `state.db` `sessions` table (title, parent_id, cwd,
//! model, timestamps) on the session id derived from the directory name. The
//! `agents/*/sessions/` hardlink mirror is intentionally not scanned. Child
//! sessions (those with a `parent_id`) surface the parent's title as `agent`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::common::{self, PlatformDef, SqlVal};
use crate::session_import::{scan_util, ScanOptions, Session};

const SESSIONS_SQL: &str =
    "select id, parent_id, title, cwd, model, created_at, updated_at from sessions";

/// One row of the per-user `state.db` `sessions` table.
struct StateRow {
    parent_id: Option<String>,
    title: Option<String>,
    cwd: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// Aside browser-agent scanner definition (`aside`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![PlatformDef {
        id: "aside",
        name: "Aside",
        roots,
        scan,
    }]
}

fn roots() -> Vec<PathBuf> {
    scan_util::existing([scan_util::home().map(|home| home.join(".aside"))].into_iter().flatten())
}

fn scan(opts: &ScanOptions) -> Vec<Session> {
    // Mirror the reference `_roots`: each extra root contributes itself and its
    // `.aside` child alongside the default `~/.aside`.
    let mut extra = Vec::new();
    for root in &opts.roots {
        extra.push(root.clone());
        extra.push(root.join(".aside"));
    }
    let roots = common::merge_roots(roots(), &extra);

    let mut sessions = Vec::new();
    for user_dir in user_dirs(&roots) {
        let index = state_index(&user_dir.join("state.db"));
        let mut paths = Vec::new();
        if let Ok(entries) = std::fs::read_dir(user_dir.join("sessions")) {
            for entry in entries.flatten() {
                let dir = entry.path();
                if dir.is_dir() {
                    let transcript = dir.join("messages.jsonl");
                    if transcript.is_file() {
                        paths.push(transcript);
                    }
                }
            }
        }
        for path in scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES) {
            sessions.push(aside_session(&path, &index));
        }
    }
    sessions
}

/// Per-user store directories: `root/u/*` when present, else `root` itself.
fn user_dirs(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for root in roots {
        let mut users = Vec::new();
        if let Ok(entries) = std::fs::read_dir(root.join("u")) {
            for entry in entries.flatten() {
                let path = entry.path();
                let visible = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| !name.starts_with('.'));
                if path.is_dir() && visible {
                    users.push(path);
                }
            }
        }
        users.sort();
        if !users.is_empty() {
            dirs.extend(users);
        } else if root.join("sessions").exists() {
            dirs.push(root.clone());
        }
    }
    dirs
}

/// Index the per-user `state.db` `sessions` table by session id.
fn state_index(db_path: &Path) -> HashMap<String, StateRow> {
    let mut index = HashMap::new();
    if !db_path.exists() {
        return index;
    }
    let Some(connection) = common::open_sqlite(db_path) else {
        return index;
    };
    for row in common::sqlite_rows(&connection, SESSIONS_SQL) {
        let Some(session_id) = cell_text(&row, 0) else {
            continue;
        };
        let (provider, model) = model_fields(cell_text(&row, 4).as_deref());
        index.insert(
            session_id,
            StateRow {
                parent_id: cell_text(&row, 1),
                title: cell_text(&row, 2),
                cwd: cell_text(&row, 3),
                provider,
                model,
                created_at: cell_number(&row, 5).and_then(scan_util::unix_seconds),
                updated_at: cell_number(&row, 6).and_then(scan_util::unix_seconds),
            },
        );
    }
    index
}

/// A SQLite cell as text, mirroring the reference `_cell_text`.
fn cell_text(row: &[SqlVal], index: usize) -> Option<String> {
    row.get(index).and_then(SqlVal::as_text).map(ToOwned::to_owned)
}

/// A SQLite numeric cell, mirroring the reference `_cell_number`.
fn cell_number(row: &[SqlVal], index: usize) -> Option<f64> {
    row.get(index).and_then(SqlVal::as_f64)
}

/// Split `{provider, modelId|model}` out of the stored model JSON.
fn model_fields(model_json: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw) = model_json.filter(|raw| !raw.is_empty()) else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return (None, None);
    };
    let Some(data) = value.as_object() else {
        return (None, None);
    };
    let provider = nonempty(data.get("provider"));
    let model = nonempty(data.get("modelId")).or_else(|| nonempty(data.get("model")));
    (provider, model)
}

fn nonempty(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

/// Build one session from a `messages.jsonl` transcript and its `state.db` row.
fn aside_session(path: &Path, index: &HashMap<String, StateRow>) -> Session {
    let session_id = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .map(dir_session_id)
        .unwrap_or_default();
    let row = index.get(&session_id);

    let mut first_user = String::new();
    let mut last_user = String::new();
    let mut provider = None;
    let mut model = None;
    let mut jsonl_created = None;
    let mut jsonl_updated = None;
    let mut usage = Map::new();

    for data in scan_util::iter_jsonl(path) {
        let moment = data
            .get("timestamp")
            .and_then(Value::as_f64)
            .and_then(|stamp| scan_util::unix_millis(stamp as i64));
        if jsonl_created.is_none() {
            jsonl_created = moment.clone();
        }
        if moment.is_some() {
            jsonl_updated = moment;
        }
        match data.get("role").and_then(Value::as_str) {
            Some("user") => {
                let prompt = scan_util::content_text(data.get("content").unwrap_or(&Value::Null));
                if !prompt.is_empty() {
                    if first_user.is_empty() {
                        first_user = prompt.clone();
                    }
                    last_user = prompt;
                }
            }
            Some("assistant") => {
                if provider.is_none() {
                    provider = nonempty(data.get("provider"));
                }
                if model.is_none() {
                    model = nonempty(data.get("model"));
                }
                if let Some(value) = data.get("usage").and_then(Value::as_object) {
                    common::merge_usage(&mut usage, value);
                }
            }
            _ => {}
        }
    }

    let created_at = row
        .and_then(|row| row.created_at.clone())
        .or(jsonl_created.clone())
        .or_else(|| scan_util::file_mtime_iso(path));
    let updated_at = row
        .and_then(|row| row.updated_at.clone())
        .or(jsonl_updated)
        .or(jsonl_created)
        .or_else(|| scan_util::file_mtime_iso(path));
    let provider = row.and_then(|row| row.provider.clone()).or(provider);
    let model = row.and_then(|row| row.model.clone()).or(model);
    let parent_id = row.and_then(|row| row.parent_id.clone());
    let agent = row.and_then(|row| {
        if row.parent_id.is_some() {
            row.title.clone()
        } else {
            None
        }
    });

    Session {
        platform: "aside".to_owned(),
        id: session_id,
        path: path.display().to_string(),
        cwd: row.and_then(|row| row.cwd.clone()),
        created_at,
        updated_at,
        provider,
        model,
        first_user_message: first_user,
        last_user_message: last_user,
        usage,
        parent_id,
        agent,
    }
}

/// `<date>_<id>` directory name → `<id>` (text after the first underscore).
fn dir_session_id(name: &str) -> String {
    name.splitn(2, '_').last().unwrap_or(name).to_owned()
}

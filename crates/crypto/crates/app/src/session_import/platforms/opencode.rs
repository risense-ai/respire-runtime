//! OpenCode scanner.
//!
//! Fast path is OpenCode's own SQLite `session` table; when that is absent the
//! scanner falls back to the file store (`storage/session/**/ses_*.json` and
//! `messages/ses_*/*.json` joined with `parts/msg_*/*.json`).
//!
//! Deviation from the reference finder: we do not shell out to `opencode db
//! path` (sandbox/DoS safety); we probe the documented default database paths.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::common::{self, PlatformDef, SqlVal};
use crate::session_import::{scan_util, ScanOptions, Session};

const MAX_OPENCODE_SESSIONS: usize = 50_000;
const SESSION_SQL: &str = "select id, title, directory, time_created, time_updated, cost, tokens_input, \
     tokens_output, tokens_reasoning, tokens_cache_read, tokens_cache_write, model, parent_id, agent \
     from session where time_archived is null order by time_updated desc limit 50000";
const LEGACY_SESSION_SQL: &str = "select id, title, directory, time_created, time_updated, cost, tokens_input, \
     tokens_output, tokens_reasoning, tokens_cache_read, tokens_cache_write, model \
     from session where time_archived is null order by time_updated desc limit 2000";

/// OpenCode scanner definition (`opencode`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![PlatformDef {
        id: "opencode",
        name: "OpenCode",
        roots,
        scan,
    }]
}

fn roots() -> Vec<PathBuf> {
    let appdata = scan_util::env_path("APPDATA");
    scan_util::existing(
        [
            scan_util::env_path("OPENCODE_HOME"),
            scan_util::home().map(|home| home.join(".opencode")),
            scan_util::home().map(|home| home.join(".local").join("share").join("opencode")),
            appdata.map(|base| base.join("opencode")),
        ]
        .into_iter()
        .flatten(),
    )
}

fn scan(opts: &ScanOptions) -> Vec<Session> {
    if opts.roots.is_empty() {
        let dbs = db_sessions();
        if !dbs.is_empty() {
            return dbs;
        }
    }
    let roots = common::merge_roots(roots(), &opts.roots);
    let mut sessions = Vec::new();
    for root in &roots {
        // File store: messages/ses_*/*.json joined with parts/msg_*/*.json.
        let messages_root = root.join("messages");
        if let Ok(entries) = std::fs::read_dir(&messages_root) {
            for entry in entries.flatten() {
                let dir = entry.path();
                let is_session_dir = dir.is_dir()
                    && dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|name| name.starts_with("ses_"));
                if is_session_dir {
                    if let Some(session) = file_session(root, &dir) {
                        sessions.push(session);
                    }
                }
            }
        }
        for path in scan_util::files_below(&root.join("storage").join("session"), 2, "ses_*.json") {
            if let Some(session) = storage_session(&path) {
                sessions.push(session);
            }
        }
    }
    sessions
}

fn db_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = scan_util::env_path("OPENCODE_HOME") {
        candidates.push(home.join("opencode.db"));
    }
    if let Some(home) = scan_util::home() {
        candidates.push(home.join(".local").join("share").join("opencode").join("opencode.db"));
        candidates.push(home.join(".opencode").join("opencode.db"));
    }
    if let Some(appdata) = scan_util::env_path("APPDATA") {
        candidates.push(appdata.join("opencode").join("opencode.db"));
    }
    candidates.into_iter().find(|path| path.exists())
}

fn db_sessions() -> Vec<Session> {
    let Some(path) = db_path() else {
        return Vec::new();
    };
    let Some(connection) = common::open_sqlite(&path) else {
        return Vec::new();
    };
    let mut rows = common::sqlite_rows(&connection, SESSION_SQL);
    if rows.is_empty() {
        rows = common::sqlite_rows(&connection, LEGACY_SESSION_SQL);
    }
    rows.iter().take(MAX_OPENCODE_SESSIONS).map(|row| db_session(row)).collect()
}

fn db_session(row: &[SqlVal]) -> Session {
    let session_id = cell_text(row, 0).unwrap_or_default();
    let title = cell_text(row, 1).unwrap_or_default();
    let (provider, model) = row
        .get(11)
        .and_then(SqlVal::as_text)
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .map(|value| {
            (
                value.get("providerID").and_then(Value::as_str).map(ToOwned::to_owned),
                value.get("id").and_then(Value::as_str).map(ToOwned::to_owned),
            )
        })
        .unwrap_or((None, None));

    let mut usage = Map::new();
    for (index, key) in [
        (5usize, "cost_total"),
        (6, "input"),
        (7, "output"),
        (8, "reasoning"),
        (9, "cacheRead"),
        (10, "cacheWrite"),
    ] {
        if let Some(value) = row.get(index).and_then(SqlVal::as_f64) {
            usage.insert(key.to_owned(), json!(value));
        }
    }

    Session {
        platform: "opencode".to_owned(),
        id: session_id.clone(),
        path: format!("opencode://{session_id}"),
        cwd: cell_text(row, 2),
        created_at: row.get(3).and_then(SqlVal::as_i64).and_then(scan_util::unix_millis),
        updated_at: row.get(4).and_then(SqlVal::as_i64).and_then(scan_util::unix_millis),
        provider,
        model,
        first_user_message: title.clone(),
        last_user_message: title,
        usage,
        parent_id: cell_text(row, 12),
        agent: cell_text(row, 13),
    }
}

fn storage_session(path: &Path) -> Option<Session> {
    let info = scan_util::read_json(path)?;
    let time = info.get("time").and_then(Value::as_object);
    let millis = |key: &str| {
        time.and_then(|time| time.get(key))
            .and_then(Value::as_i64)
            .and_then(scan_util::unix_millis)
    };
    let id = info
        .get("id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| path.file_stem().and_then(|s| s.to_str()).map(ToOwned::to_owned))?;
    Some(Session {
        platform: "opencode".to_owned(),
        id,
        path: path.display().to_string(),
        cwd: info.get("directory").and_then(Value::as_str).map(ToOwned::to_owned),
        created_at: millis("created"),
        updated_at: millis("updated"),
        provider: None,
        model: None,
        first_user_message: info
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        last_user_message: String::new(),
        usage: Map::new(),
        parent_id: info.get("parentID").and_then(Value::as_str).map(ToOwned::to_owned),
        agent: info.get("agent").and_then(Value::as_str).map(ToOwned::to_owned),
    })
}

fn file_session(root: &Path, message_dir: &Path) -> Option<Session> {
    let mut messages = scan_util::files_in(message_dir, "*.json");
    messages.sort();
    let first = messages.first().and_then(|path| scan_util::read_json(path))?;
    let session_id = first
        .get("sessionID")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| message_dir.file_name().and_then(|s| s.to_str()).map(ToOwned::to_owned))
        .unwrap_or_default();
    let model = first.get("model").and_then(Value::as_object);
    let cwd = first
        .get("path")
        .and_then(Value::as_object)
        .and_then(|path| path.get("cwd"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let stamps: Vec<i64> = messages.iter().filter_map(|path| message_millis(path)).collect();
    let created = stamps.iter().min().and_then(|value| scan_util::unix_millis(*value));
    let updated = stamps.iter().max().and_then(|value| scan_util::unix_millis(*value));
    let (first_prompt, last_prompt) = prompt_edges(root, &session_id, &messages);

    Some(Session {
        platform: "opencode".to_owned(),
        id: session_id,
        path: message_dir.display().to_string(),
        cwd,
        created_at: created,
        updated_at: updated,
        provider: model
            .and_then(|model| model.get("providerID"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        model: model
            .and_then(|model| model.get("modelID"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        first_user_message: first_prompt,
        last_user_message: last_prompt,
        usage: {
            let mut usage = Map::new();
            usage.insert("message_count".to_owned(), json!(messages.len()));
            usage
        },
        parent_id: None,
        agent: None,
    })
}

fn prompt_edges(root: &Path, session_id: &str, messages: &[PathBuf]) -> (String, String) {
    let mut first = String::new();
    let mut last = String::new();
    for path in messages {
        let Some(data) = scan_util::read_json(path) else {
            continue;
        };
        if data.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        let message_id = data.get("id").and_then(Value::as_str).unwrap_or_default();
        for part in scan_util::files_in(&root.join("parts").join(message_id), "*.json") {
            let Some(part) = scan_util::read_json(&part) else {
                continue;
            };
            if part.get("sessionID").and_then(Value::as_str) != Some(session_id) {
                continue;
            }
            if let Some(text) = part.get("text").and_then(Value::as_str) {
                if !text.is_empty() {
                    if first.is_empty() {
                        first = text.to_owned();
                    }
                    last = text.to_owned();
                }
            }
        }
    }
    (first, last)
}

fn message_millis(path: &Path) -> Option<i64> {
    scan_util::read_json(path)?
        .get("time")
        .and_then(Value::as_object)
        .and_then(|time| time.get("created"))
        .and_then(Value::as_i64)
}

fn cell_text(row: &[SqlVal], index: usize) -> Option<String> {
    match row.get(index) {
        Some(SqlVal::Text(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

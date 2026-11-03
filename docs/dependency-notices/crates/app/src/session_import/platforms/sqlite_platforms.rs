//! Cursor CLI and Kodu (VS Code extension) SQLite scanners.
//!
//! Ported from the reference finder's
//! `scripts/agent_sessions/sqlite_scanners.py` (`scan_cursor_cli` / `_cursor_db`
//! and `scan_kodu` / `_kodu_db`):
//!   · Cursor CLI — `~/.cursor/chats/<workspace>/<session>/store.db`; the
//!     `blobs` table holds one JSON message per row. The first and last
//!     `role == "user"` blobs supply the prompts, and the session dir name is
//!     the id.
//!   · Kodu — VS Code `globalStorage/kodu-ai.claude-dev-experimental/db/Azad.db`;
//!     one session per `tasks` row, prompts read from the `messages` table.
//!
//! Timestamp units and id derivation are preserved from the reference:
//! Kodu's `created_at`/`updated_at` are Unix milliseconds, Cursor falls back to
//! the store file's modification time.

use std::path::{Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::common::{self, PlatformDef, SqlVal};
use crate::session_import::{scan_util, ScanOptions, Session};

/// VS Code extension id whose `globalStorage` subdirectory holds the DB.
const KODU_APP: &str = "kodu-ai.claude-dev-experimental";
const KODU_TASKS_SQL: &str =
    "select id, name, dir_absolute_path, created_at, updated_at, tokens_in, \
     tokens_out, cache_reads, cache_writes, cost from tasks";
const KODU_MESSAGES_SQL: &str = "select role, content, model_id, started_at, finished_at, tokens_in, \
     tokens_out, cache_reads, cache_writes, cost from messages where task_id = ? order by started_at";
const CURSOR_BLOBS_SQL: &str = "select data from blobs";

/// SQLite scanner definitions (`kodu`, `cursor-cli`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![
        PlatformDef {
            id: "kodu",
            name: "Kodu",
            roots: kodu_roots,
            scan: scan_kodu,
        },
        PlatformDef {
            id: "cursor-cli",
            name: "Cursor CLI",
            roots: cursor_roots,
            scan: scan_cursor_cli,
        },
    ]
}

/// Default Kodu roots: macOS, Linux and Windows VS Code `globalStorage`.
fn kodu_roots() -> Vec<PathBuf> {
    let appdata = scan_util::env_path("APPDATA");
    scan_util::existing(
        [
            scan_util::home().map(|home| {
                home.join("Library")
                    .join("Application Support")
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join(KODU_APP)
            }),
            scan_util::home().map(|home| {
                home.join(".config")
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join(KODU_APP)
            }),
            appdata.map(|base| {
                base.join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join(KODU_APP)
            }),
        ]
        .into_iter()
        .flatten(),
    )
}

/// Default Cursor CLI root (`~/.cursor`).
fn cursor_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [scan_util::home().map(|home| home.join(".cursor"))]
            .into_iter()
            .flatten(),
    )
}

fn scan_kodu(opts: &ScanOptions) -> Vec<Session> {
    let roots = common::merge_roots(kodu_roots(), &opts.roots);
    let paths: Vec<PathBuf> = roots
        .iter()
        .map(|root| root.join("db").join("Azad.db"))
        .filter(|path| path.exists())
        .collect();
    scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES)
        .into_iter()
        .flat_map(|path| kodu_db(&path))
        .collect()
}

fn scan_cursor_cli(opts: &ScanOptions) -> Vec<Session> {
    let roots = common::merge_roots(cursor_roots(), &opts.roots);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(store_dbs(&root.join("chats")));
    }
    scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES)
        .into_iter()
        .flat_map(|path| cursor_db(&path))
        .collect()
}

/// `root/chats/*/*/store.db` (exactly two directory levels, hidden dirs excluded).
fn store_dbs(chats: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(workspaces) = std::fs::read_dir(chats) else {
        return out;
    };
    for workspace in workspaces.flatten().filter(|entry| visible(&entry.path())) {
        let Ok(sessions) = std::fs::read_dir(workspace.path()) else {
            continue;
        };
        for session in sessions.flatten().filter(|entry| visible(&entry.path())) {
            let db = session.path().join("store.db");
            if db.exists() {
                out.push(db);
            }
        }
    }
    out
}

fn visible(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| !name.starts_with('.'))
}

fn kodu_db(path: &Path) -> Vec<Session> {
    let Some(connection) = common::open_sqlite(path) else {
        return Vec::new();
    };
    common::sqlite_rows(&connection, KODU_TASKS_SQL)
        .iter()
        .map(|row| kodu_session(path, &connection, row))
        .collect()
}

fn kodu_session(path: &Path, connection: &Connection, row: &[SqlVal]) -> Session {
    let task_id = cell_text(row, 0).unwrap_or_default();
    let messages = kodu_messages(connection, &task_id);
    let mut first_user = String::new();
    let mut last_user = String::new();
    let mut model: Option<String> = None;
    for message in &messages {
        if model.is_none() {
            model = cell_text(message, 2);
        }
        if cell_text(message, 0).as_deref() == Some("user") {
            let prompt = content(cell_text(message, 1).map(Value::String).as_ref());
            if first_user.is_empty() {
                first_user = prompt.clone();
            }
            last_user = prompt;
        }
    }
    Session {
        platform: "kodu".to_owned(),
        id: task_id,
        path: path.display().to_string(),
        cwd: cell_text(row, 2),
        created_at: cell_int(row, 3).and_then(scan_util::unix_millis),
        updated_at: cell_int(row, 4)
            .and_then(scan_util::unix_millis)
            .or_else(|| scan_util::file_mtime_iso(path)),
        provider: None,
        model,
        first_user_message: first_user,
        last_user_message: last_user,
        usage: usage(
            row,
            &[
                (5, "input"),
                (6, "output"),
                (7, "cacheRead"),
                (8, "cacheWrite"),
                (9, "cost_total"),
            ],
        ),
        parent_id: None,
        agent: None,
    }
}

/// Materialize `messages` rows for one task (parameterized to avoid injection).
fn kodu_messages(connection: &Connection, task_id: &str) -> Vec<Vec<SqlVal>> {
    let Ok(mut statement) = connection.prepare(KODU_MESSAGES_SQL) else {
        return Vec::new();
    };
    let column_count = statement.column_count();
    let Ok(mut rows) = statement.query([task_id]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        let mut values = Vec::with_capacity(column_count);
        for index in 0..column_count {
            values.push(match row.get_ref(index) {
                Ok(ValueRef::Null) | Err(_) => SqlVal::Null,
                Ok(ValueRef::Integer(value)) => SqlVal::Int(value),
                Ok(ValueRef::Real(value)) => SqlVal::Real(value),
                Ok(ValueRef::Text(text)) => {
                    SqlVal::Text(String::from_utf8_lossy(text).into_owned())
                }
                Ok(ValueRef::Blob(_)) => SqlVal::Null,
            });
        }
        out.push(values);
    }
    out
}

fn cursor_db(path: &Path) -> Vec<Session> {
    let Some(connection) = common::open_sqlite(path) else {
        return Vec::new();
    };
    let blobs = cursor_blobs(&connection);
    let mut first_user = String::new();
    let mut last_user = String::new();
    for blob in blobs.iter().flatten() {
        let Some(data) = json_blob(blob) else {
            continue;
        };
        if data.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        let prompt = cursor_prompt(&content(data.get("content")));
        if prompt.is_empty() {
            continue;
        }
        if first_user.is_empty() {
            first_user = prompt.clone();
        }
        last_user = prompt;
    }
    if first_user.is_empty() {
        return Vec::new();
    }
    let id = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    let file_time = scan_util::file_mtime_iso(path);
    vec![Session {
        platform: "cursor-cli".to_owned(),
        id,
        path: path.display().to_string(),
        cwd: None,
        created_at: file_time.clone(),
        updated_at: file_time,
        provider: Some("cursor".to_owned()),
        model: None,
        first_user_message: first_user,
        last_user_message: last_user,
        usage: {
            let mut usage = Map::new();
            usage.insert("blob_count".to_owned(), json!(blobs.len()));
            usage
        },
        parent_id: None,
        agent: None,
    }]
}

/// Read the `blobs.data` column; non-blob cells stay `None` but still count.
fn cursor_blobs(connection: &Connection) -> Vec<Option<Vec<u8>>> {
    let Ok(mut statement) = connection.prepare(CURSOR_BLOBS_SQL) else {
        return Vec::new();
    };
    let Ok(mut rows) = statement.query([]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        out.push(match row.get_ref(0) {
            Ok(ValueRef::Blob(bytes)) => Some(bytes.to_vec()),
            _ => None,
        });
    }
    out
}

/// Decode a raw blob as UTF-8 JSON object (`None` when either step fails).
fn json_blob(value: &[u8]) -> Option<Map<String, Value>> {
    let text = std::str::from_utf8(value).ok()?;
    serde_json::from_str::<Value>(text)
        .ok()?
        .as_object()
        .cloned()
}

/// `_content`: unwrap JSON text/parts, falling back to the raw string.
fn content(value: Option<&Value>) -> String {
    let parsed = match value {
        None => Value::Null,
        Some(Value::String(raw)) => serde_json::from_str(raw).unwrap_or(Value::Null),
        Some(other) => other.clone(),
    };
    let text = scan_util::content_text(&parsed);
    if !text.is_empty() {
        return text;
    }
    match value {
        Some(Value::String(raw)) => raw.clone(),
        _ => String::new(),
    }
}

/// `_cursor_prompt`: extract the `<user_query>` block, drop `<user_info>`, else trim.
fn cursor_prompt(value: &str) -> String {
    const OPEN: &str = "<user_query>";
    const CLOSE: &str = "</user_query>";
    if let (Some(start), Some(end)) = (value.find(OPEN), value.find(CLOSE)) {
        if end > start {
            return value[start + OPEN.len()..end].trim().to_owned();
        }
    }
    if value.trim_start().starts_with("<user_info>") {
        return String::new();
    }
    value.trim().to_owned()
}

fn usage(row: &[SqlVal], fields: &[(usize, &str)]) -> Map<String, Value> {
    let mut usage = Map::new();
    for (index, key) in fields {
        match row.get(*index) {
            Some(SqlVal::Int(value)) => {
                usage.insert((*key).to_owned(), json!(value));
            }
            Some(SqlVal::Real(value)) => {
                usage.insert((*key).to_owned(), json!(value));
            }
            _ => {}
        }
    }
    usage
}

fn cell_text(row: &[SqlVal], index: usize) -> Option<String> {
    match row.get(index) {
        Some(SqlVal::Text(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn cell_int(row: &[SqlVal], index: usize) -> Option<i64> {
    row.get(index).and_then(SqlVal::as_i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_import::Cursor;

    #[test]
    fn cursor_wal_append_and_edit_change_content_cursor() -> anyhow::Result<()> {
        let isolate = crate::test_lock::Isolate::new()?;
        let path = isolate.path().join("fixture-session").join("store.db");
        std::fs::create_dir_all(isolate.path().join("fixture-session"))?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE blobs(data BLOB);",
        )?;
        let first = br#"{"role":"user","content":"first request"}"#;
        connection.execute("INSERT INTO blobs VALUES (?1)", [first.as_slice()])?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let initial = cursor_db(&path);
        let mut cursor = Cursor::load();
        cursor.mark(&initial[0]);
        let newer = br#"{"role":"user","content":"new request"}"#;
        connection.execute("INSERT INTO blobs VALUES (?1)", [newer.as_slice()])?;
        let updated = cursor_db(&path);
        assert_eq!(updated[0].last_user_message, "new request");
        assert_eq!(updated[0].updated_at, initial[0].updated_at);
        assert!(!cursor.is_imported(&updated[0]));
        cursor.mark(&updated[0]);
        let edit = br#"{"role":"user","content":"edited request"}"#;
        connection.execute("UPDATE blobs SET data=?1 WHERE rowid=2", [edit.as_slice()])?;
        let edited = cursor_db(&path);
        assert!(!cursor.is_imported(&edited[0]));
        cursor.mark(&edited[0]);
        connection.execute("DELETE FROM blobs WHERE rowid=2", [])?;
        assert!(!cursor.is_imported(&cursor_db(&path)[0]));
        Ok(())
    }
}

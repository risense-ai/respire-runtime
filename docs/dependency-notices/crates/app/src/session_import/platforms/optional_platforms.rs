//! Optional SQLite platform scanners: kilo-cli, hermes, goose, crush and zed.
//!
//! Ported from the reference finder's
//! `scripts/agent_sessions/sqlite_optional_scanners.py` (`scan_kilo_cli`,
//! `scan_hermes`, `scan_goose`, `scan_crush`, `scan_zed`).
//!
//! Each scanner probes a small set of known store roots and returns nothing when
//! the database or its schema is absent/unsupported (schema drift is expected
//! and never panics). kilo-cli/hermes/goose share the `{session_id, role, data,
//! created_at}` message-table shape, crush reads `{session_id, role, parts,
//! created_at}`, and zed reads one JSON blob per `threads` row. The reference
//! lists the default database *files* (not their parent directories), so the
//! `PlatformDef::roots` function mirrors each store's exact default path, and a
//! user `--root` is a directory that may hold that file. Timestamp units and id
//! derivation are preserved.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::common::{self, PlatformDef, SqlVal};
use crate::session_import::{scan_util, ScanOptions, Session};

/// Zed `threads` query: `typeof(data)` lets us keep the reference's "BLOB bytes
/// only" gate, and `cast(data as text)` recovers the row whose `SqlVal` cell
/// (`common::sqlite_rows`) would otherwise drop a BLOB.
const ZED_SQL: &str =
    "select id, data_type, cast(data as text), updated_at, typeof(data) from threads";

/// Optional SQLite scanner definitions (`kilo-cli`, `hermes`, `goose`, `crush`, `zed`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![
        PlatformDef {
            id: "kilo-cli",
            name: "Kilo CLI",
            roots: kilo_roots,
            scan: scan_kilo_cli,
        },
        PlatformDef {
            id: "hermes",
            name: "Hermes",
            roots: hermes_roots,
            scan: scan_hermes,
        },
        PlatformDef {
            id: "goose",
            name: "Goose",
            roots: goose_roots,
            scan: scan_goose,
        },
        PlatformDef {
            id: "crush",
            name: "Crush",
            roots: crush_roots,
            scan: scan_crush,
        },
        PlatformDef {
            id: "zed",
            name: "Zed",
            roots: zed_roots,
            scan: scan_zed,
        },
    ]
}

/// Default store roots: the reference's exact database files (home-relative,
/// which is `$HOME` on Unix/macOS and `%USERPROFILE%` on Windows).
fn kilo_roots() -> Vec<PathBuf> {
    scan_util::existing(home_join(&[".local", "share", "kilo", "kilo.db"]))
}

fn hermes_roots() -> Vec<PathBuf> {
    scan_util::existing(home_join(&[".hermes", "state.db"]))
}

fn goose_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [
            home_join(&[".local", "share", "goose", "sessions", "sessions.db"]),
            home_join(&[
                "Library",
                "Application Support",
                "goose",
                "sessions",
                "sessions.db",
            ]),
        ]
        .into_iter()
        .flatten(),
    )
}

fn crush_roots() -> Vec<PathBuf> {
    scan_util::existing(home_join(&[".local", "share", "crush", "crush.db"]))
}

fn zed_roots() -> Vec<PathBuf> {
    scan_util::existing(home_join(&[
        "Library",
        "Application Support",
        "Zed",
        "threads",
        "threads.db",
    ]))
}

/// `$HOME/<parts...>` when a home directory is known.
fn home_join(parts: &[&str]) -> Option<PathBuf> {
    let mut path = scan_util::home()?;
    for part in parts {
        path.push(part);
    }
    Some(path)
}

// ── Scanners ──

fn scan_kilo_cli(opts: &ScanOptions) -> Vec<Session> {
    message_table_sessions(
        "kilo-cli",
        "message",
        database_paths(kilo_roots(), "kilo.db", opts),
    )
}

fn scan_hermes(opts: &ScanOptions) -> Vec<Session> {
    message_table_sessions(
        "hermes",
        "messages",
        database_paths(hermes_roots(), "state.db", opts),
    )
}

fn scan_goose(opts: &ScanOptions) -> Vec<Session> {
    message_table_sessions(
        "goose",
        "messages",
        database_paths(goose_roots(), "sessions.db", opts),
    )
}

fn scan_crush(opts: &ScanOptions) -> Vec<Session> {
    let mut sessions = Vec::new();
    for path in database_paths(crush_roots(), "crush.db", opts) {
        let Some(connection) = common::open_sqlite(&path) else {
            continue;
        };
        let rows = common::sqlite_rows(
            &connection,
            "select session_id, role, parts, created_at from messages order by created_at",
        );
        sessions.extend(group_message_rows("crush", &path, &rows));
    }
    sessions
}

fn scan_zed(opts: &ScanOptions) -> Vec<Session> {
    let mut sessions = Vec::new();
    for path in database_paths(zed_roots(), "threads.db", opts) {
        let Some(connection) = common::open_sqlite(&path) else {
            continue;
        };
        let rows = common::sqlite_rows(&connection, ZED_SQL);
        sessions.extend(zed_sessions(&path, &rows));
    }
    sessions
}

/// Default database files plus `<user root>/<filename>` for each `--root`
/// directory, keeping existing paths (newest `MAX_PLATFORM_FILES`).
fn database_paths(defaults: Vec<PathBuf>, filename: &str, opts: &ScanOptions) -> Vec<PathBuf> {
    let candidates = defaults
        .into_iter()
        .chain(opts.roots.iter().map(|root| root.join(filename)));
    scan_util::recent(
        scan_util::existing(candidates),
        scan_util::MAX_PLATFORM_FILES,
    )
}

/// `select session_id, role, data, created_at` scanners, one session per id.
fn message_table_sessions(platform: &str, table: &str, paths: Vec<PathBuf>) -> Vec<Session> {
    let mut sessions = Vec::new();
    for path in paths {
        let Some(connection) = common::open_sqlite(&path) else {
            continue;
        };
        let sql =
            format!("select session_id, role, data, created_at from {table} order by created_at");
        let rows = common::sqlite_rows(&connection, &sql);
        sessions.extend(group_message_rows(platform, &path, &rows));
    }
    sessions
}

/// Group message rows by `session_id` (first-seen order) into sessions.
fn group_message_rows(platform: &str, path: &Path, rows: &[Vec<SqlVal>]) -> Vec<Session> {
    let mut grouped: Vec<(String, Vec<Value>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut stamps: HashMap<String, String> = HashMap::new();

    for row in rows {
        let Some(sid) = row_text(row, 0) else {
            continue;
        };
        let position = match index.get(&sid).copied() {
            Some(position) => position,
            None => {
                index.insert(sid.clone(), grouped.len());
                grouped.push((sid.clone(), Vec::new()));
                grouped.len() - 1
            }
        };
        grouped[position].1.push(message_json(row));

        if !stamps.contains_key(&sid) {
            let stamped = stamp(row, 3)
                .filter(|value| !value.is_empty())
                .or_else(|| file_time(path).filter(|value| !value.is_empty()))
                .unwrap_or_default();
            stamps.insert(sid, stamped);
        }
    }

    grouped
        .into_iter()
        .filter_map(|(sid, messages)| {
            let (first_user, last_user) = message_edges(&messages);
            if first_user.is_empty() {
                return None;
            }
            let created = stamps
                .get(&sid)
                .filter(|value| !value.is_empty())
                .cloned()
                .or_else(|| file_time(path).filter(|value| !value.is_empty()));
            Some(Session {
                platform: platform.to_owned(),
                id: sid,
                path: path.display().to_string(),
                cwd: None,
                created_at: created,
                updated_at: file_time(path),
                provider: provider_of(&messages),
                model: model_of(&messages),
                first_user_message: first_user,
                last_user_message: last_user,
                usage: {
                    let mut usage = Map::new();
                    usage.insert("message_count".to_owned(), json!(messages.len()));
                    usage
                },
                parent_id: None,
                agent: None,
            })
        })
        .collect()
}

/// Zed `threads` rows: only `data_type == "json"` rows whose `data` is a BLOB.
fn zed_sessions(path: &Path, rows: &[Vec<SqlVal>]) -> Vec<Session> {
    let mut sessions = Vec::new();
    for row in rows {
        if row_text(row, 1).as_deref() != Some("json")
            || row_text(row, 4).as_deref() != Some("blob")
        {
            continue;
        }
        let data = row_text(row, 2)
            .and_then(|raw| parse_json_text(&raw))
            .and_then(|value| value.as_object().cloned());
        let messages = json_messages(data.as_ref());
        let (first_user, last_user) = message_edges(&messages);
        if first_user.is_empty() {
            continue;
        }
        let id = row_text(row, 0)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default()
                    .to_owned()
            });
        let updated = row_text(row, 3)
            .filter(|value| !value.is_empty())
            .or_else(|| file_time(path).filter(|value| !value.is_empty()));
        sessions.push(Session {
            platform: "zed".to_owned(),
            id,
            path: path.display().to_string(),
            cwd: None,
            created_at: updated.clone(),
            updated_at: updated,
            provider: Some("zed.dev".to_owned()),
            model: zed_model(data.as_ref()),
            first_user_message: first_user,
            last_user_message: last_user,
            usage: {
                let mut usage = Map::new();
                usage.insert("message_count".to_owned(), json!(messages.len()));
                usage
            },
            parent_id: None,
            agent: None,
        });
    }
    sessions
}

/// `_message_json`: parse the JSON cell, else synthesize `{role, content}`.
fn message_json(row: &[SqlVal]) -> Value {
    let role = row_text(row, 1);
    match row_json(row, 2) {
        Some(mut map) => {
            if !map.contains_key("role") {
                map.insert("role".to_owned(), Value::String(role.unwrap_or_default()));
            }
            Value::Object(map)
        }
        None => {
            let mut map = Map::new();
            map.insert("role".to_owned(), Value::String(role.unwrap_or_default()));
            map.insert(
                "content".to_owned(),
                Value::String(row_text(row, 2).unwrap_or_default()),
            );
            Value::Object(map)
        }
    }
}

/// `_message_edges`: first and last non-empty `role == "user"` prompt.
fn message_edges(messages: &[Value]) -> (String, String) {
    let mut first = String::new();
    let mut last = String::new();
    for message in messages {
        let Some(map) = message.as_object() else {
            continue;
        };
        if map.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        let prompt = content(map);
        if !prompt.is_empty() {
            if first.is_empty() {
                first = prompt.clone();
            }
            last = prompt;
        }
    }
    (first, last)
}

/// `_content`: unwrap `content`/`parts`/`text`, falling back to the raw string.
fn content(message: &Map<String, Value>) -> String {
    for key in ["content", "parts", "text"] {
        let Some(value) = message.get(key) else {
            continue;
        };
        let parsed = match value {
            Value::String(raw) => parse_json_text(raw).unwrap_or(Value::Null),
            other => other.clone(),
        };
        let extracted = scan_util::content_text(&parsed);
        if !extracted.is_empty() {
            return extracted;
        }
        if let Value::String(raw) = value {
            if !raw.is_empty() {
                return raw.clone();
            }
        }
    }
    String::new()
}

/// First non-empty string among `keys`, scanning messages in order.
fn find_first_text(messages: &[Value], keys: &[&str]) -> Option<String> {
    for message in messages {
        let Some(map) = message.as_object() else {
            continue;
        };
        for key in keys {
            if let Some(value) = map.get(*key).and_then(Value::as_str) {
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

fn model_of(messages: &[Value]) -> Option<String> {
    find_first_text(messages, &["modelID", "model_id", "model"])
}

fn provider_of(messages: &[Value]) -> Option<String> {
    find_first_text(messages, &["providerID", "provider_id", "provider"])
}

/// `_json_messages`: first list-valued key among `messages`/`turns`/`entries`.
fn json_messages(data: Option<&Map<String, Value>>) -> Vec<Value> {
    let Some(data) = data else {
        return Vec::new();
    };
    for key in ["messages", "turns", "entries"] {
        if let Some(Value::Array(items)) = data.get(key) {
            return items
                .iter()
                .filter(|item| item.is_object())
                .cloned()
                .collect();
        }
    }
    Vec::new()
}

/// `_zed_model`: `data.model.model` when both are objects.
fn zed_model(data: Option<&Map<String, Value>>) -> Option<String> {
    data.and_then(|data| data.get("model"))
        .and_then(Value::as_object)
        .and_then(|model| model.get("model"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// `_stamp`: Unix milliseconds above the reference's 1e10 guard, else a string.
fn stamp(row: &[SqlVal], index: usize) -> Option<String> {
    match row.get(index) {
        Some(SqlVal::Int(value)) if *value > 10_000_000_000 => scan_util::unix_millis(*value),
        Some(SqlVal::Text(text)) => Some(text.clone()),
        _ => None,
    }
}

/// `_row_text`: string cells only (numbers, blobs and NULL become `None`).
fn row_text(row: &[SqlVal], index: usize) -> Option<String> {
    row.get(index)
        .and_then(SqlVal::as_text)
        .map(ToOwned::to_owned)
}

/// `_row_json`: parse a string cell as a JSON object.
fn row_json(row: &[SqlVal], index: usize) -> Option<Map<String, Value>> {
    let raw = row_text(row, index)?;
    parse_json_text(&raw).and_then(|value| value.as_object().cloned())
}

/// `parse_json_text`: silent `None` on any JSON error.
fn parse_json_text(value: &str) -> Option<Value> {
    serde_json::from_str::<Value>(value).ok()
}

/// `file_time`: the store file's modification time as an ISO-8601 string.
fn file_time(path: &Path) -> Option<String> {
    scan_util::file_mtime_iso(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_import::Cursor;
    use rusqlite::Connection;

    #[test]
    fn wal_summary_changes_reimport_but_other_sessions_and_checkpoint_do_not() -> anyhow::Result<()>
    {
        let isolate = crate::test_lock::Isolate::new()?;
        for platform in ["kilo-cli", "hermes", "goose", "crush"] {
            let path = isolate.path().join(format!("{platform}.db"));
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
                 CREATE TABLE messages(session_id TEXT, role TEXT, data TEXT, created_at INTEGER);
                 INSERT INTO messages VALUES ('fixture-session','user','{\"content\":\"first request\"}',1700000000000);
                 PRAGMA wal_checkpoint(TRUNCATE);"
            )?;
            let scan = || message_table_sessions(platform, "messages", vec![path.clone()]);
            let first = scan();
            assert_eq!(first.len(), 1);
            let mut cursor = Cursor::load();
            cursor.mark(&first[0]);
            cursor.save()?;
            let original_stamp = first[0].updated_at.clone();
            connection.execute_batch(
                "INSERT INTO messages VALUES ('fixture-session','user','{\"content\":\"new request\"}',1700000001000);"
            )?;
            let second = scan();
            assert_eq!(second[0].last_user_message, "new request");
            assert_eq!(
                second[0].updated_at, original_stamp,
                "main DB unchanged during WAL commit"
            );
            assert!(
                !Cursor::load().is_imported(&second[0]),
                "new message cannot be skipped"
            );
            cursor.mark(&second[0]);
            cursor.save()?;
            assert!(
                Cursor::load().is_imported(&scan()[0]),
                "retry skips unchanged summary"
            );

            connection.execute_batch("UPDATE messages SET data='{\"content\":\"edited request\"}' WHERE created_at=1700000001000;")?;
            let edited = scan();
            assert_eq!(edited[0].last_user_message, "edited request");
            assert!(
                !cursor.is_imported(&edited[0]),
                "same-timestamp edit is visible"
            );
            cursor.mark(&edited[0]);
            connection.execute_batch("DELETE FROM messages WHERE created_at=1700000001000;")?;
            let deleted = scan();
            assert_eq!(deleted[0].last_user_message, "first request");
            assert!(
                !cursor.is_imported(&deleted[0]),
                "delete changes imported summary"
            );
            cursor.mark(&deleted[0]);
            connection.execute_batch(
                "INSERT INTO messages VALUES ('other-session','user','{\"content\":\"unrelated\"}',1700000002000);
                 PRAGMA wal_checkpoint(TRUNCATE);"
            )?;
            let unchanged = scan()
                .into_iter()
                .find(|session| session.id == "fixture-session")
                .ok_or_else(|| anyhow::anyhow!("fixture session missing after checkpoint"))?;
            assert!(
                cursor.is_imported(&unchanged),
                "unrelated writes/checkpoint must not replay this session"
            );
        }
        Ok(())
    }
}

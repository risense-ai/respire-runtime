//! Codex scanner.
//!
//! Two surfaces (see the reference `codex.md`):
//!   · `$CODEX_HOME/state_*.sqlite` — `threads` metadata + `thread_spawn_edges`
//!   · `$CODEX_HOME/sessions/**/rollout-*.jsonl` (+ `archived_sessions/`)
//! SQLite rows win for linkage; rollout JSONL covers threads missing from the DB.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::common::{self, PlatformDef, SqlVal};
use crate::session_import::{scan_util, ScanOptions, Session};

const THREADS_SQL: &str = "SELECT id, rollout_path, cwd, created_at, updated_at, model_provider, model, \
     first_user_message, tokens_used, source, agent_nickname, agent_role FROM threads";
const LEGACY_THREADS_SQL: &str = "SELECT id, rollout_path, cwd, created_at, updated_at, model_provider, \
     model, first_user_message, tokens_used FROM threads";
const SPAWN_EDGES_SQL: &str = "SELECT child_thread_id, parent_thread_id FROM thread_spawn_edges";

/// Codex scanner definition (`codex`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![PlatformDef {
        id: "codex",
        name: "Codex",
        roots,
        scan,
    }]
}

fn roots() -> Vec<PathBuf> {
    scan_util::existing([
        scan_util::env_path("CODEX_HOME"),
        scan_util::home().map(|home| home.join(".codex")),
    ]
    .into_iter()
    .flatten())
}

fn scan(opts: &ScanOptions) -> Vec<Session> {
    let roots = common::merge_roots(roots(), &opts.roots);
    let mut db_paths = Vec::new();
    let mut rollouts = Vec::new();
    for root in &roots {
        db_paths.extend(scan_util::files_in(root, "state_*.sqlite"));
        rollouts.extend(scan_util::files_below(&root.join("sessions"), 12, "rollout-*.jsonl"));
        rollouts.extend(scan_util::files_in(&root.join("archived_sessions"), "rollout-*.jsonl"));
    }
    let mut sessions = Vec::new();
    for path in &db_paths {
        sessions.extend(codex_db(path));
    }
    for path in scan_util::recent(rollouts, scan_util::MAX_PLATFORM_FILES) {
        let fallback = scan_util::stem_id(&path, "rollout-");
        sessions.push(common::jsonl_session("codex", &path, fallback));
    }
    sessions
}

fn codex_db(path: &Path) -> Vec<Session> {
    let Some(connection) = common::open_sqlite(path) else {
        return Vec::new();
    };
    let edges = spawn_edges(&connection);
    let mut rows = common::sqlite_rows(&connection, THREADS_SQL);
    if rows.is_empty() {
        rows = common::sqlite_rows(&connection, LEGACY_THREADS_SQL);
    }
    rows.iter().map(|row| codex_row(path, row, &edges)).collect()
}

fn spawn_edges(connection: &rusqlite::Connection) -> HashMap<String, String> {
    let mut edges = HashMap::new();
    for row in common::sqlite_rows(connection, SPAWN_EDGES_SQL) {
        let child = cell_text(&row, 0);
        let parent = cell_text(&row, 1);
        if let (Some(child), Some(parent)) = (child, parent) {
            edges.insert(child, parent);
        }
    }
    edges
}

fn codex_row(path: &Path, row: &[SqlVal], edges: &HashMap<String, String>) -> Session {
    let thread_id = cell_text(row, 0).unwrap_or_default();
    let (source_parent, source_agent) = match cell_text(row, 9) {
        Some(text) => common::spawn_info(&Value::String(text)),
        None => (None, None),
    };
    let nickname = cell_text(row, 10);
    let role = cell_text(row, 11);
    let agent = scan_util::nick_role(nickname.as_deref(), role.as_deref()).or(source_agent);

    let mut usage = serde_json::Map::new();
    if let Some(tokens) = cell_num(row, 8) {
        usage.insert("total_tokens".to_owned(), serde_json::json!(tokens));
    }
    Session {
        platform: "codex".to_owned(),
        id: thread_id.clone(),
        path: cell_text(row, 1).unwrap_or_else(|| path.display().to_string()),
        cwd: cell_text(row, 2),
        created_at: cell_num(row, 3).and_then(scan_util::unix_seconds),
        updated_at: cell_num(row, 4).and_then(scan_util::unix_seconds),
        provider: cell_text(row, 5),
        model: cell_text(row, 6),
        first_user_message: cell_text(row, 7).unwrap_or_default(),
        last_user_message: String::new(),
        usage,
        parent_id: edges.get(&thread_id).cloned().or(source_parent),
        agent,
    }
}

fn cell_text(row: &[SqlVal], index: usize) -> Option<String> {
    match row.get(index) {
        Some(SqlVal::Text(text)) if !text.is_empty() => Some(text.clone()),
        Some(SqlVal::Int(value)) => Some(value.to_string()),
        Some(SqlVal::Real(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn cell_num(row: &[SqlVal], index: usize) -> Option<f64> {
    row.get(index).and_then(SqlVal::as_f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_db_reads_threads_and_spawn_edges() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("state_1.sqlite");
        let connection = rusqlite::Connection::open(&db)?;
        connection
            .execute_batch(
                "CREATE TABLE threads (id TEXT, rollout_path TEXT, cwd TEXT, created_at INTEGER, updated_at INTEGER, \
                 model_provider TEXT, model TEXT, first_user_message TEXT, tokens_used INTEGER, source TEXT, \
                 agent_nickname TEXT, agent_role TEXT); \
                 CREATE TABLE thread_spawn_edges (child_thread_id TEXT, parent_thread_id TEXT); \
                 INSERT INTO threads VALUES ('t-9','/r.jsonl','/work',1700000000,1700000600,'openai','gpt-5','hi',7,'{}','Tesla','explorer'); \
                 INSERT INTO thread_spawn_edges VALUES ('t-9','p-3');",
            )?;
        drop(connection);

        let sessions = codex_db(&db);
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.id, "t-9");
        assert_eq!(session.cwd.as_deref(), Some("/work"));
        assert_eq!(session.parent_id.as_deref(), Some("p-3"));
        assert_eq!(session.agent.as_deref(), Some("Tesla (explorer)"));
        assert_eq!(session.model.as_deref(), Some("gpt-5"));
        assert!(session.updated_at.as_deref().ok_or("updated_at")?.starts_with("2023-11-14"));
        Ok(())
    }
}

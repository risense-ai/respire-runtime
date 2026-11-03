//! Shared scanner plumbing: the [`PlatformDef`] registry entry, the generic
//! [`jsonl_session`] transcript parser (used by most JSONL stores), SQLite
//! row helpers, and small root/usage utilities.
//!
//! Ported from the reference finder's `transcript.py` / `jsonio.py`.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::session_import::{scan_util, ScanOptions, Session, SessionScanner};

/// Declarative platform entry used by [`super::registry`].
pub struct PlatformDef {
    pub id: &'static str,
    pub name: &'static str,
    /// Existing default store roots on this machine.
    pub roots: fn() -> Vec<PathBuf>,
    pub scan: fn(&ScanOptions) -> Vec<Session>,
}

/// Adapter turning a [`PlatformDef`] into a [`SessionScanner`].
pub struct FnScanner {
    id: &'static str,
    name: &'static str,
    roots: fn() -> Vec<PathBuf>,
    scan: fn(&ScanOptions) -> Vec<Session>,
}

impl FnScanner {
    /// Wrap a [`PlatformDef`] as a [`SessionScanner`].
    pub fn new(def: PlatformDef) -> Self {
        Self {
            id: def.id,
            name: def.name,
            roots: def.roots,
            scan: def.scan,
        }
    }
}

impl SessionScanner for FnScanner {
    fn id(&self) -> &'static str {
        self.id
    }
    fn name(&self) -> &'static str {
        self.name
    }
    fn roots(&self) -> Vec<PathBuf> {
        (self.roots)()
    }
    fn scan(&self, opts: &ScanOptions) -> Vec<Session> {
        (self.scan)(opts)
    }
}

/// Merge default roots with user-supplied extra roots (existing only).
pub fn merge_roots(defaults: Vec<PathBuf>, extra: &[PathBuf]) -> Vec<PathBuf> {
    scan_util::existing(defaults.into_iter().chain(extra.iter().cloned()))
}

/// Parse one JSONL transcript file into a normalized session.
///
/// Handles Codex rollout lines (`session_meta`), Claude/agent JSONL events and
/// the generic `{sessionId,type,payload,message}` shape.
pub fn jsonl_session(platform: &str, path: &Path, fallback_id: String) -> Session {
    let mut sid = fallback_id;
    let mut cwd: Option<String> = None;
    let mut provider: Option<String> = None;
    let mut model: Option<String> = None;
    let mut first_user: Option<String> = None;
    let mut last_user = String::new();
    let mut created: Option<String> = None;
    let mut updated: Option<String> = None;
    let mut usage = Map::new();
    let mut parent: Option<String> = None;
    let mut agent: Option<String> = None;

    for data in scan_util::iter_jsonl(path) {
        let event_type = data.get("type").and_then(Value::as_str);
        let session_line_id = if event_type == Some("session") {
            data.get("id").and_then(Value::as_str)
        } else {
            None
        };
        if let Some(value) = data.get("sessionId").and_then(Value::as_str).or(session_line_id) {
            sid = value.to_owned();
        }
        if cwd.is_none() {
            cwd = data.get("cwd").and_then(Value::as_str).map(ToOwned::to_owned);
        }
        if created.is_none() {
            created = data.get("timestamp").and_then(Value::as_str).map(ToOwned::to_owned);
        }
        if let Some(stamp) = data.get("timestamp").and_then(Value::as_str) {
            updated = Some(stamp.to_owned());
        }
        if provider.is_none() {
            provider = data.get("provider").and_then(Value::as_str).map(ToOwned::to_owned);
        }
        if model.is_none() {
            model = data
                .get("modelId")
                .and_then(Value::as_str)
                .or_else(|| data.get("model").and_then(Value::as_str))
                .map(ToOwned::to_owned);
        }
        let payload = data.get("payload").and_then(Value::as_object);
        if event_type == Some("session_meta") {
            if let Some(payload) = payload {
                if let Some(value) = payload.get("id").and_then(Value::as_str) {
                    sid = value.to_owned();
                }
                if cwd.is_none() {
                    cwd = payload.get("cwd").and_then(Value::as_str).map(ToOwned::to_owned);
                }
                if provider.is_none() {
                    provider = payload
                        .get("model_provider")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                }
                let (source_parent, source_agent) = spawn_info(
                    payload.get("source").unwrap_or(&Value::Null),
                );
                if parent.is_none() {
                    parent = source_parent;
                }
                if agent.is_none() {
                    agent = source_agent.or_else(|| {
                        scan_util::nick_role(
                            payload.get("agent_nickname").and_then(Value::as_str),
                            payload.get("agent_role").and_then(Value::as_str),
                        )
                    });
                }
            }
        }
        let message = data
            .get("message")
            .and_then(Value::as_object)
            .or(payload);
        if let Some(message) = message {
            if provider.is_none() {
                provider = message.get("provider").and_then(Value::as_str).map(ToOwned::to_owned);
            }
            if model.is_none() {
                model = message.get("model").and_then(Value::as_str).map(ToOwned::to_owned);
            }
        }
        let prompt = user_text(&data, message);
        if !prompt.is_empty() {
            if first_user.is_none() {
                first_user = Some(prompt.clone());
            }
            last_user = prompt;
        }
        if let Some(value) = message
            .and_then(|message| message.get("usage").and_then(Value::as_object))
            .or_else(|| data.get("usage").and_then(Value::as_object))
        {
            merge_usage(&mut usage, value);
        }
    }

    let created_at = created.or_else(|| scan_util::file_mtime_iso(path));
    let updated_at = updated
        .or_else(|| created_at.clone())
        .or_else(|| scan_util::file_mtime_iso(path));
    Session {
        platform: platform.to_owned(),
        id: sid,
        path: path.display().to_string(),
        cwd,
        created_at,
        updated_at,
        provider,
        model,
        first_user_message: first_user.unwrap_or_default(),
        last_user_message: last_user,
        usage,
        parent_id: parent,
        agent,
    }
}

/// Parse many JSONL files, keeping the newest `MAX_PLATFORM_FILES`.
pub fn jsonl_sessions(platform: &str, paths: Vec<PathBuf>) -> Vec<Session> {
    scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES)
        .into_iter()
        .map(|path| {
            let fallback = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            jsonl_session(platform, &path, fallback)
        })
        .collect()
}

/// Extract `(parent_thread_id, agent)` from a Codex `source` payload.
pub fn spawn_info(source: &Value) -> (Option<String>, Option<String>) {
    let parsed;
    let data = match source {
        Value::String(text) => {
            parsed = serde_json::from_str::<Value>(text).ok();
            parsed.as_ref().and_then(Value::as_object)
        }
        other => other.as_object(),
    };
    let Some(data) = data else {
        return (None, None);
    };
    let subagent = data.get("subagent");
    if let Some(name) = subagent.and_then(Value::as_str) {
        return (None, Some(name.to_owned()));
    }
    let spawn = subagent
        .and_then(Value::as_object)
        .and_then(|map| map.get("thread_spawn"))
        .and_then(Value::as_object);
    let Some(spawn) = spawn else {
        return (None, None);
    };
    (
        spawn
            .get("parent_thread_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        scan_util::nick_role(
            spawn.get("agent_nickname").and_then(Value::as_str),
            spawn.get("agent_role").and_then(Value::as_str),
        ),
    )
}

/// Copy token/cost usage fields, mirroring the finder's `merge_usage`.
pub fn merge_usage(target: &mut Map<String, Value>, value: &Map<String, Value>) {
    for key in ["totalTokens", "total_tokens", "input", "output", "cacheRead", "cacheWrite"] {
        if let Some(field) = value.get(key) {
            if field.is_number() {
                target.insert(key.to_owned(), field.clone());
            }
        }
    }
    if let Some(total) = value
        .get("cost")
        .and_then(Value::as_object)
        .and_then(|cost| cost.get("total"))
    {
        if total.is_number() {
            target.insert("cost_total".to_owned(), total.clone());
        }
    }
}

/// User prompt text from a JSONL event and its optional message payload.
pub fn user_text(data: &Value, message: Option<&Map<String, Value>>) -> String {
    if data.get("type").and_then(Value::as_str) == Some("user") {
        let value = prompt_text(data.get("content").unwrap_or(&Value::Null));
        if !value.is_empty() {
            return value;
        }
    }
    if let Some(message) = message {
        if message.get("role").and_then(Value::as_str) == Some("user") {
            return prompt_text(message.get("content").unwrap_or(&Value::Null));
        }
    }
    String::new()
}

/// Prompt text from user content, skipping non-text parts (Claude emits
/// `tool_result`/`tool_use` blocks under the user role).
pub fn prompt_text(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_owned();
    }
    let Some(items) = value.as_array() else {
        return String::new();
    };
    items
        .iter()
        .filter(|item| {
            !matches!(
                item.get("type").and_then(Value::as_str),
                Some("tool_result") | Some("tool_use") | Some("image")
            )
        })
        .filter_map(|item| {
            item.get("text")
                .and_then(Value::as_str)
                .or_else(|| item.get("content").and_then(Value::as_str))
        })
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>()
        .join("\n")
}

/// A single SQLite cell value.
#[derive(Debug, Clone)]
pub enum SqlVal {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
}

impl SqlVal {
    /// Text value, if this cell is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            SqlVal::Text(text) => Some(text),
            _ => None,
        }
    }
    /// Numeric value (integer or real) as `f64`, if numeric.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            SqlVal::Int(value) => Some(*value as f64),
            SqlVal::Real(value) => Some(*value),
            _ => None,
        }
    }
    /// Value as `i64`, if numeric.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SqlVal::Int(value) => Some(*value),
            SqlVal::Real(value) => Some(*value as i64),
            _ => None,
        }
    }
}

impl Default for SqlVal {
    fn default() -> Self {
        SqlVal::Null
    }
}

/// Open a SQLite database read-only with a short busy timeout.
pub fn open_sqlite(path: &Path) -> Option<Connection> {
    use rusqlite::OpenFlags;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let _ = connection.busy_timeout(std::time::Duration::from_secs(3));
    Some(connection)
}

/// Run a query and materialize all rows as string/number cells.
/// Returns an empty vec on any SQL error (schema drift is expected).
pub fn sqlite_rows(connection: &Connection, sql: &str) -> Vec<Vec<SqlVal>> {
    let Ok(mut statement) = connection.prepare(sql) else {
        return Vec::new();
    };
    let column_count = statement.column_count();
    let Ok(mut rows) = statement.query([]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        let mut values = Vec::with_capacity(column_count);
        for index in 0..column_count {
            use rusqlite::types::ValueRef;
            values.push(match row.get_ref(index) {
                Ok(ValueRef::Null) | Err(_) => SqlVal::Null,
                Ok(ValueRef::Integer(value)) => SqlVal::Int(value),
                Ok(ValueRef::Real(value)) => SqlVal::Real(value),
                Ok(ValueRef::Text(text)) => SqlVal::Text(String::from_utf8_lossy(text).into_owned()),
                Ok(ValueRef::Blob(_)) => SqlVal::Null,
            });
        }
        out.push(values);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonl_session_parses_codex_rollout() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("rollout-abc.jsonl");
        let lines = [
            r#"{"type":"session_meta","payload":{"id":"t-1","cwd":"/work","model_provider":"openai","source":{"subagent":{"thread_spawn":{"parent_thread_id":"p-0","agent_nickname":"Tesla","agent_role":"explorer"}}}}}"#,
            r#"{"type":"user","timestamp":"2026-10-01T00:00:00Z","content":"hello world"}"#,
            r#"{"type":"assistant","timestamp":"2026-10-01T00:05:00Z","message":{"role":"assistant","content":"ok","usage":{"total_tokens":42}}}"#,
        ]
        .join("\n");
        std::fs::write(&path, lines)?;

        let session = jsonl_session("codex", &path, "fallback".to_owned());
        assert_eq!(session.id, "t-1");
        assert_eq!(session.cwd.as_deref(), Some("/work"));
        assert_eq!(session.provider.as_deref(), Some("openai"));
        assert_eq!(session.first_user_message, "hello world");
        assert_eq!(session.parent_id.as_deref(), Some("p-0"));
        assert_eq!(session.agent.as_deref(), Some("Tesla (explorer)"));
        assert!(session.usage.contains_key("total_tokens"));
        assert!(session.updated_at.as_deref().ok_or("updated_at")?.starts_with("2026-10-01"));
        Ok(())
    }

    #[test]
    fn claude_tool_result_line_does_not_replace_prompt() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("claude-session.jsonl");
        let lines = [
            r#"{"type":"user","timestamp":"2026-10-01T00:00:00Z","message":{"role":"user","content":"add the extract command"}}"#,
            r#"{"type":"assistant","timestamp":"2026-10-01T00:01:00Z","message":{"role":"assistant","content":[{"type":"text","text":"ok"}]}}"#,
            r#"{"type":"user","timestamp":"2026-10-01T00:02:00Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"tool output"}]}}"#,
        ]
        .join("\n");
        std::fs::write(&path, lines)?;

        let session = jsonl_session("claude", &path, "fallback".to_owned());
        assert_eq!(session.first_user_message, "add the extract command");
        assert_eq!(session.last_user_message, "add the extract command");
        Ok(())
    }

    #[test]
    fn spawn_info_reads_thread_spawn_and_named_subagents() {
        let spawn = serde_json::json!({"subagent": {"thread_spawn": {"parent_thread_id": "p1", "agent_nickname": "Ada", "agent_role": "reviewer"}}});
        assert_eq!(
            spawn_info(&serde_json::Value::String(spawn.to_string())),
            (Some("p1".to_owned()), Some("Ada (reviewer)".to_owned()))
        );
        let named = serde_json::json!({"subagent": "memory_consolidation"});
        assert_eq!(spawn_info(&named), (None, Some("memory_consolidation".to_owned())));
    }
}

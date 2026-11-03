//! Kiro scanner — port of the reference finder's `kiro_scanner.py`.
//!
//! Kiro keeps one JSON info file per CLI session at
//! `~/.kiro/sessions/cli/*.json`, paired with a sibling `*.jsonl` of prompt
//! events. The JSON supplies `session_id`, `cwd`, the metadata turn count and
//! the Bedrock model; the JSONL supplies the first/last user prompts and the
//! creation timestamp.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::common::PlatformDef;
use crate::session_import::{scan_util, ScanOptions, Session};

/// Kiro scanner definition (`kiro`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![PlatformDef {
        id: "kiro",
        name: "Kiro",
        roots,
        scan,
    }]
}

fn roots() -> Vec<PathBuf> {
    scan_util::existing(scan_util::home().map(|home| home.join(".kiro")))
}

fn resolve_roots(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = scan_util::home() {
        candidates.push(home.join(".kiro"));
    }
    for root in extra {
        candidates.push(root.clone());
        candidates.push(root.join(".kiro"));
        candidates.push(root.join("kiro"));
    }
    scan_util::existing(candidates)
}

fn scan(opts: &ScanOptions) -> Vec<Session> {
    let roots = resolve_roots(&opts.roots);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(scan_util::files_in(&root.join("sessions").join("cli"), "*.json"));
    }
    scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES)
        .into_iter()
        .filter_map(|path| kiro_session(&path))
        .collect()
}

fn kiro_session(path: &Path) -> Option<Session> {
    let value = scan_util::read_json(path)?;
    let data = value.as_object()?;
    let state = data.get("session_state").and_then(Value::as_object);
    let rts_state = state
        .and_then(|state| state.get("rts_model_state"))
        .and_then(Value::as_object);
    let model_info = rts_state
        .and_then(|state| state.get("model_info"))
        .and_then(Value::as_object);
    let metadata = state
        .and_then(|state| state.get("conversation_metadata"))
        .and_then(Value::as_object);

    let (first_user, last_user, created) = prompt_edges(&path.with_extension("jsonl"));
    if first_user.is_empty() {
        return None;
    }

    let mut usage = Map::new();
    if let Some(Value::Array(turns)) = metadata.and_then(|meta| meta.get("user_turn_metadatas")) {
        usage.insert("turn_count".to_owned(), Value::from(turns.len() as u64));
    }

    let id = ["session_id", "sessionId"]
        .iter()
        .find_map(|key| {
            data.get(*key)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
        })
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned()
        });

    Some(Session {
        platform: "kiro".to_owned(),
        id,
        path: path.display().to_string(),
        cwd: data.get("cwd").and_then(Value::as_str).map(ToOwned::to_owned),
        created_at: created.or_else(|| scan_util::file_mtime_iso(path)),
        updated_at: scan_util::file_mtime_iso(path),
        provider: Some("amazon-bedrock".to_owned()),
        model: model_info
            .and_then(|info| info.get("model_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        first_user_message: first_user,
        last_user_message: last_user,
        usage,
        parent_id: None,
        agent: None,
    })
}

fn prompt_edges(path: &Path) -> (String, String, Option<String>) {
    let mut first_user = String::new();
    let mut last_user = String::new();
    let mut created = None;
    for row in scan_util::iter_jsonl(path) {
        if row.get("kind").and_then(Value::as_str) != Some("Prompt") {
            continue;
        }
        let data = row.get("data").and_then(Value::as_object);
        let prompt = data
            .map(|data| kiro_content(data.get("content").unwrap_or(&Value::Null)))
            .unwrap_or_default();
        if !prompt.is_empty() {
            if first_user.is_empty() {
                first_user = prompt.clone();
            }
            last_user = prompt;
        }
        if created.is_none() {
            if let Some(stamp) = data
                .and_then(|data| data.get("meta"))
                .and_then(Value::as_object)
                .and_then(|meta| meta.get("timestamp"))
                .and_then(Value::as_f64)
            {
                created = scan_util::unix_seconds(stamp);
            }
        }
    }
    (first_user, last_user, created)
}

fn kiro_content(value: &Value) -> String {
    match value.as_array() {
        Some(items) => items
            .iter()
            .map(kiro_content_part)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        None => value.as_str().unwrap_or_default().to_owned(),
    }
}

fn kiro_content_part(value: &Value) -> String {
    let Some(item) = value.as_object() else {
        return String::new();
    };
    if let Some(kind) = item.get("kind").and_then(Value::as_str) {
        if kind != "text" {
            return String::new();
        }
    }
    ["data", "text", "content"]
        .iter()
        .find_map(|key| item.get(*key).and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
}

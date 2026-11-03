//! Claude Code / Claude Desktop scanner.
//!
//! Main sessions: `transcripts/*.jsonl`, `projects/*/*.jsonl`,
//! `pre-compact-session-histories/*.jsonl`.
//! Subagents (Task tool): `projects/*/<session>/subagents/**/agent-*.jsonl`,
//! with `agent-*.meta.json` carrying `agentType` + task description.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::common::{self, PlatformDef};
use crate::session_import::{scan_util, ScanOptions, Session};

/// Claude Code scanner definition (`claude`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![PlatformDef {
        id: "claude",
        name: "Claude Code",
        roots,
        scan,
    }]
}

fn roots() -> Vec<PathBuf> {
    scan_util::existing(
        [
            scan_util::home().map(|home| home.join(".claude")),
            scan_util::env_path("APPDATA").map(|base| base.join("Claude")),
        ]
        .into_iter()
        .flatten(),
    )
}

fn scan(opts: &ScanOptions) -> Vec<Session> {
    let roots = common::merge_roots(roots(), &opts.roots);
    let mut mains = Vec::new();
    let mut subagents = Vec::new();
    for root in &roots {
        mains.extend(scan_util::files_in(&root.join("transcripts"), "*.jsonl"));
        mains.extend(scan_util::files_below(&root.join("projects"), 2, "*.jsonl"));
        mains.extend(scan_util::files_in(&root.join("pre-compact-session-histories"), "*.jsonl"));
        subagents.extend(
            scan_util::files_below(&root.join("projects"), 8, "agent-*.jsonl")
                .into_iter()
                .filter(|path| path.to_string_lossy().contains("subagents")),
        );
    }
    let mut sessions = common::jsonl_sessions("claude", mains);
    for path in scan_util::recent(subagents, scan_util::MAX_PLATFORM_FILES) {
        if let Some(session) = subagent_session(&path) {
            sessions.push(session);
        }
    }
    sessions
}

fn subagent_session(path: &Path) -> Option<Session> {
    let path_text = path.to_string_lossy();
    let components: Vec<&str> = path_text.split(['/', '\\']).collect();
    let index = components.iter().position(|part| *part == "subagents")?;
    if index == 0 {
        return None;
    }
    let parent_sid = components[index - 1].to_owned();

    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    let meta_path = path.with_file_name(format!("{stem}.meta.json"));
    let meta = scan_util::read_json(&meta_path).unwrap_or(Value::Null);
    let first = scan_util::iter_jsonl(path).into_iter().next().unwrap_or(Value::Null);
    let description = meta
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let task = first
        .get("message")
        .and_then(Value::as_object)
        .map(|message| common::prompt_text(message.get("content").unwrap_or(&Value::Null)))
        .unwrap_or_default();
    let prompt = [description, task]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    let created = first
        .get("timestamp")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| scan_util::file_mtime_iso(path));
    let updated = scan_util::file_mtime_iso(path).or_else(|| created.clone());

    Some(Session {
        platform: "claude".to_owned(),
        id: stem.strip_prefix("agent-").unwrap_or(stem).to_owned(),
        path: path.display().to_string(),
        cwd: first.get("cwd").and_then(Value::as_str).map(ToOwned::to_owned),
        created_at: created,
        updated_at: updated,
        provider: None,
        model: None,
        first_user_message: prompt.clone(),
        last_user_message: prompt,
        usage: serde_json::Map::new(),
        parent_id: Some(parent_sid),
        agent: meta.get("agentType").and_then(Value::as_str).map(ToOwned::to_owned),
    })
}

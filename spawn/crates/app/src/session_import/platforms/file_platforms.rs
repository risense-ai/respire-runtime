//! File-based platform scanners: openclaw, droid, amp, gemini, kimi, qwen,
//! codebuff, roo-code, kilo-code, cline and aider.
//!
//! Ported from the reference finder's `file_scanners.py` (plus the shared
//! `transcript.py` / `jsonio.py` helpers): default store roots, glob patterns,
//! session-id derivation, timestamp units and usage/subagent extraction are
//! preserved. The finder shells out for nothing here; every scanner reads local
//! files only (aider reads bounded `.aider.chat.history.md` files and never
//! spawns the `aider` binary).

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::common::{self, PlatformDef};
use crate::session_import::{scan_util, ScanOptions, Session};

/// File-based scanner definitions (openclaw, droid, amp, gemini, kimi, qwen, codebuff, roo/kilo-code, cline, aider).
pub fn platforms() -> Vec<PlatformDef> {
    vec![
        PlatformDef {
            id: "openclaw",
            name: "OpenClaw",
            roots: openclaw_roots,
            scan: scan_openclaw,
        },
        PlatformDef {
            id: "droid",
            name: "Factory Droid",
            roots: droid_roots,
            scan: scan_droid,
        },
        PlatformDef {
            id: "amp",
            name: "Amp",
            roots: amp_roots,
            scan: scan_amp,
        },
        PlatformDef {
            id: "gemini",
            name: "Gemini",
            roots: gemini_roots,
            scan: scan_gemini,
        },
        PlatformDef {
            id: "kimi",
            name: "Kimi",
            roots: kimi_roots,
            scan: scan_kimi,
        },
        PlatformDef {
            id: "qwen",
            name: "Qwen",
            roots: qwen_roots,
            scan: scan_qwen,
        },
        PlatformDef {
            id: "codebuff",
            name: "Codebuff",
            roots: codebuff_roots,
            scan: scan_codebuff,
        },
        PlatformDef {
            id: "roo-code",
            name: "Roo Code",
            roots: roo_roots,
            scan: scan_roocode,
        },
        PlatformDef {
            id: "kilo-code",
            name: "Kilo Code",
            roots: kilo_roots,
            scan: scan_kilocode,
        },
        PlatformDef {
            id: "cline",
            name: "Cline",
            roots: cline_roots,
            scan: scan_cline,
        },
        PlatformDef {
            id: "aider",
            name: "Aider",
            roots: aider_roots,
            scan: scan_aider,
        },
    ]
}

// ---------------------------------------------------------------- openclaw
// `~/.openclaw/agents/*/sessions/*.jsonl`, `sessions/*.jsonl` and
// `session-backups/…`; JSONL transcript per file.

const ROO_EXTENSION: &str = "rooveterinaryinc.roo-cline";
const KILO_EXTENSION: &str = "kilocode.kilo-code";
const CLINE_EXTENSION: &str = "saoudrizwan.claude-dev";

fn openclaw_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [scan_util::home().map(|home| home.join(".openclaw"))]
            .into_iter()
            .flatten(),
    )
}

fn scan_openclaw(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(openclaw_roots(), &opts.roots, &[".openclaw"]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "agents/*/sessions/*.jsonl"));
        paths.extend(glob_files(root, "sessions/*.jsonl"));
        paths.extend(glob_files(root, "session-backups/*/*.jsonl"));
        paths.extend(glob_files(root, "session-backups/*/sessions/*.jsonl"));
    }
    common::jsonl_sessions("openclaw", paths)
}

// ---------------------------------------------------------------- droid
// `~/.factory/sessions/*/*.jsonl` with adjacent `*.settings.json`.

fn droid_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [scan_util::home().map(|home| home.join(".factory"))]
            .into_iter()
            .flatten(),
    )
}

fn scan_droid(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(droid_roots(), &opts.roots, &[".factory"]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "sessions/*/*.jsonl"));
    }
    scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES)
        .iter()
        .map(|path| droid_session(path))
        .collect()
}

fn droid_session(path: &Path) -> Session {
    let mut sid = file_stem(path);
    let mut cwd: Option<String> = None;
    let mut first_user: Option<String> = None;
    let mut last_user = String::new();
    let mut created: Option<String> = None;
    let mut updated: Option<String> = None;

    for data in scan_util::iter_jsonl(path) {
        let stamp = data.get("timestamp").and_then(Value::as_str);
        if created.is_none() {
            created = stamp.map(ToOwned::to_owned);
        }
        if let Some(stamp) = stamp {
            updated = Some(stamp.to_owned());
        }
        if data.get("type").and_then(Value::as_str) == Some("session_start") {
            if let Some(id) = data.get("id").and_then(Value::as_str) {
                sid = id.to_owned();
            }
            if cwd.is_none() {
                cwd = data.get("cwd").and_then(Value::as_str).map(ToOwned::to_owned);
            }
        }
        if let Some(message) = data.get("message").and_then(Value::as_object) {
            if message.get("role").and_then(Value::as_str) == Some("user") {
                let prompt = without_system_reminders(message.get("content").unwrap_or(&Value::Null));
                if !prompt.is_empty() {
                    if first_user.is_none() {
                        first_user = Some(prompt.clone());
                    }
                    last_user = prompt;
                }
            }
        }
    }

    let settings = scan_util::read_json(&path.with_extension("settings.json"))
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();

    let created_at = created.clone().or_else(|| scan_util::file_mtime_iso(path));
    let updated_at = updated.or(created).or_else(|| scan_util::file_mtime_iso(path));

    Session {
        platform: "droid".to_owned(),
        id: sid,
        path: path.display().to_string(),
        cwd,
        created_at,
        updated_at,
        provider: None,
        model: settings
            .get("model")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        first_user_message: first_user.unwrap_or_default(),
        last_user_message: last_user,
        usage: token_usage(&settings),
        parent_id: None,
        agent: None,
    }
}

// ---------------------------------------------------------------- amp
// `~/.local/share/amp/threads/T-*.json` (one thread file → one session).

fn amp_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [scan_util::home().map(|home| home.join(".local").join("share").join("amp"))]
            .into_iter()
            .flatten(),
    )
}

fn scan_amp(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(amp_roots(), &opts.roots, &["amp", ".local/share/amp"]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "threads/T-*.json"));
    }
    let mut sessions = Vec::new();
    for path in scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES) {
        sessions.extend(amp_sessions(&path));
    }
    sessions
}

fn amp_sessions(path: &Path) -> Vec<Session> {
    let value = match scan_util::read_json(path) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let data = match value.as_object() {
        Some(map) => map,
        None => return Vec::new(),
    };
    let messages = data.get("messages").map(json_maps).unwrap_or_default();
    let (first_user, last_user) = message_edges(&messages, &["user"]);
    let env = data.get("env").and_then(Value::as_object);
    let initial = env.and_then(|env| env.get("initial")).and_then(Value::as_object);
    let tree = initial
        .and_then(|initial| initial.get("trees"))
        .and_then(Value::as_array)
        .and_then(|trees| trees.first())
        .and_then(Value::as_object);

    let mut usage = Map::new();
    usage.insert("message_count".to_owned(), json!(messages.len()));

    vec![Session {
        platform: "amp".to_owned(),
        id: data
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| file_stem(path)),
        path: path.display().to_string(),
        cwd: file_uri_path(tree.and_then(|tree| tree.get("uri")).and_then(Value::as_str)),
        created_at: data
            .get("created")
            .and_then(Value::as_i64)
            .and_then(scan_util::unix_millis)
            .or_else(|| scan_util::file_mtime_iso(path)),
        updated_at: scan_util::file_mtime_iso(path),
        provider: None,
        model: initial
            .and_then(|initial| initial.get("tags"))
            .and_then(tag_model),
        first_user_message: first_user,
        last_user_message: last_user,
        usage,
        parent_id: None,
        agent: None,
    }]
}

// ---------------------------------------------------------------- gemini
// `~/.gemini/tmp/*/chats/*.json`.

fn gemini_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [scan_util::home().map(|home| home.join(".gemini"))]
            .into_iter()
            .flatten(),
    )
}

fn scan_gemini(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(gemini_roots(), &opts.roots, &[".gemini"]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "tmp/*/chats/*.json"));
    }
    let mut sessions = Vec::new();
    for path in scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES) {
        sessions.extend(gemini_sessions(&path));
    }
    sessions
}

fn gemini_sessions(path: &Path) -> Vec<Session> {
    let value = match scan_util::read_json(path) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let data = match value.as_object() {
        Some(map) => map,
        None => return Vec::new(),
    };
    let messages = data.get("messages").map(json_maps).unwrap_or_default();
    let (first_user, last_user) = message_edges(&messages, &["user"]);

    let mut usage = Map::new();
    usage.insert("message_count".to_owned(), json!(messages.len()));

    vec![Session {
        platform: "gemini".to_owned(),
        id: data
            .get("sessionId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| file_stem(path)),
        path: path.display().to_string(),
        cwd: data
            .get("projectHash")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        created_at: data
            .get("startTime")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| scan_util::file_mtime_iso(path)),
        updated_at: data
            .get("lastUpdated")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| scan_util::file_mtime_iso(path)),
        provider: Some("google".to_owned()),
        model: None,
        first_user_message: first_user,
        last_user_message: last_user,
        usage,
        parent_id: None,
        agent: None,
    }]
}

// ---------------------------------------------------------------- kimi
// `~/.kimi/sessions/*/*/wire.jsonl` (session id = parent directory name).

fn kimi_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [scan_util::home().map(|home| home.join(".kimi"))]
            .into_iter()
            .flatten(),
    )
}

fn scan_kimi(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(kimi_roots(), &opts.roots, &[".kimi"]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "sessions/*/*/wire.jsonl"));
    }
    scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES)
        .iter()
        .map(|path| kimi_session(path))
        .collect()
}

fn kimi_session(path: &Path) -> Session {
    let mut first_user = String::new();
    let mut last_user = String::new();
    let mut created: Option<String> = None;
    let mut updated: Option<String> = None;

    for data in scan_util::iter_jsonl(path) {
        let stamp = data.get("timestamp").and_then(Value::as_f64);
        if created.is_none() {
            created = stamp.and_then(scan_util::unix_seconds);
        }
        if let Some(value) = stamp.and_then(scan_util::unix_seconds) {
            updated = Some(value);
        }
        if data.get("type").and_then(Value::as_str) == Some("TurnBegin") {
            let prompt = data
                .get("payload")
                .and_then(Value::as_object)
                .and_then(|payload| payload.get("user_input"))
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty());
            if let Some(prompt) = prompt {
                if first_user.is_empty() {
                    first_user = prompt.to_owned();
                }
                last_user = prompt.to_owned();
            }
        }
    }

    Session {
        platform: "kimi".to_owned(),
        id: dir_name(path),
        path: path.display().to_string(),
        cwd: None,
        created_at: created.or_else(|| scan_util::file_mtime_iso(path)),
        updated_at: updated.or_else(|| scan_util::file_mtime_iso(path)),
        provider: Some("moonshot".to_owned()),
        model: None,
        first_user_message: first_user,
        last_user_message: last_user,
        usage: Map::new(),
        parent_id: None,
        agent: None,
    }
}

// ---------------------------------------------------------------- qwen
// `~/.qwen/projects/*/chats/*.jsonl`; generic JSONL transcript.

fn qwen_roots() -> Vec<PathBuf> {
    scan_util::existing(
        [scan_util::home().map(|home| home.join(".qwen"))]
            .into_iter()
            .flatten(),
    )
}

fn scan_qwen(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(qwen_roots(), &opts.roots, &[".qwen"]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "projects/*/chats/*.jsonl"));
    }
    common::jsonl_sessions("qwen", paths)
}

// ---------------------------------------------------------------- codebuff
// `~/.config/{manicode,manicode-dev,manicode-staging,codebuff}/projects/*/chats/*/chat-messages.json`.

fn codebuff_roots() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = scan_util::home() {
        for name in ["manicode", "manicode-dev", "manicode-staging", "codebuff"] {
            candidates.push(home.join(".config").join(name));
        }
    }
    scan_util::existing(candidates)
}

fn scan_codebuff(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(codebuff_roots(), &opts.roots, &["manicode", "codebuff"]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "projects/*/chats/*/chat-messages.json"));
    }
    let mut sessions = Vec::new();
    for path in scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES) {
        sessions.extend(codebuff_sessions(&path));
    }
    sessions
}

fn codebuff_sessions(path: &Path) -> Vec<Session> {
    let data = scan_util::read_json(path).unwrap_or(Value::Null);
    let rows = json_maps(&data);
    if rows.is_empty() {
        return Vec::new();
    }
    let (first_user, last_user) = message_edges(&rows, &["user", "human"]);

    let mut usage = Map::new();
    usage.insert("message_count".to_owned(), json!(rows.len()));

    vec![Session {
        platform: "codebuff".to_owned(),
        id: dir_name(path),
        path: path.display().to_string(),
        cwd: None,
        created_at: scan_util::file_mtime_iso(path),
        updated_at: scan_util::file_mtime_iso(path),
        provider: None,
        model: None,
        first_user_message: first_user,
        last_user_message: last_user,
        usage,
        parent_id: None,
        agent: None,
    }]
}

// ------------------------------------------------- roo-code / kilo-code / cline
// VS Code `globalStorage/<extension>/tasks/*/api_conversation_history.json`.

fn roo_roots() -> Vec<PathBuf> {
    task_roots(ROO_EXTENSION)
}

fn scan_roocode(opts: &ScanOptions) -> Vec<Session> {
    scan_task_dirs("roo-code", ROO_EXTENSION, opts)
}

fn kilo_roots() -> Vec<PathBuf> {
    task_roots(KILO_EXTENSION)
}

fn scan_kilocode(opts: &ScanOptions) -> Vec<Session> {
    scan_task_dirs("kilo-code", KILO_EXTENSION, opts)
}

fn cline_roots() -> Vec<PathBuf> {
    task_roots(CLINE_EXTENSION)
}

fn scan_cline(opts: &ScanOptions) -> Vec<Session> {
    scan_task_dirs("cline", CLINE_EXTENSION, opts)
}

fn task_roots(extension: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = scan_util::home() {
        candidates.push(
            home.join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
                .join("globalStorage")
                .join(extension),
        );
        candidates.push(
            home.join(".config")
                .join("Code")
                .join("User")
                .join("globalStorage")
                .join(extension),
        );
    }
    if let Some(appdata) = scan_util::env_path("APPDATA") {
        candidates.push(
            appdata
                .join("Code")
                .join("User")
                .join("globalStorage")
                .join(extension),
        );
    }
    scan_util::existing(candidates)
}

fn scan_task_dirs(platform: &str, extension: &str, opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(task_roots(extension), &opts.roots, &[extension]);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(glob_files(root, "tasks/*/api_conversation_history.json"));
    }
    let mut sessions = Vec::new();
    for path in scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES) {
        sessions.extend(task_sessions(platform, &path));
    }
    sessions
}

fn task_sessions(platform: &str, path: &Path) -> Vec<Session> {
    let data = scan_util::read_json(path).unwrap_or(Value::Null);
    let rows = json_maps(&data);
    if rows.is_empty() {
        return Vec::new();
    }
    let (first_user, last_user) = message_edges(&rows, &["user"]);

    let mut usage = Map::new();
    usage.insert("message_count".to_owned(), json!(rows.len()));

    vec![Session {
        platform: platform.to_owned(),
        id: dir_name(path),
        path: path.display().to_string(),
        cwd: None,
        created_at: scan_util::file_mtime_iso(path),
        updated_at: scan_util::file_mtime_iso(path),
        provider: None,
        model: None,
        first_user_message: first_user,
        last_user_message: last_user,
        usage,
        parent_id: None,
        agent: None,
    }]
}

// ---------------------------------------------------------------- aider
// Bounded project roots (`~/local-workspaces`, `~/indent`) containing
// `.aider.chat.history.md`; one session per `# aider chat started at` block.

fn aider_roots() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = scan_util::home() {
        candidates.push(home.join("local-workspaces"));
        candidates.push(home.join("indent"));
    }
    scan_util::existing(candidates)
}

fn scan_aider(opts: &ScanOptions) -> Vec<Session> {
    let roots = scan_roots(aider_roots(), &opts.roots, &["local-workspaces"]);
    let mut paths = Vec::new();
    for root in &roots {
        for pattern in [
            ".aider.chat.history.md",
            "*/.aider.chat.history.md",
            "*/*/.aider.chat.history.md",
        ] {
            paths.extend(glob_files(root, pattern));
        }
    }
    let mut sessions = Vec::new();
    for path in scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES) {
        sessions.extend(aider_sessions(&path));
    }
    sessions
}

fn aider_sessions(path: &Path) -> Vec<Session> {
    let text = match scan_util::read_text(path) {
        Some(text) => text,
        None => return Vec::new(),
    };
    let parent = path
        .parent()
        .map(|parent| parent.display().to_string())
        .unwrap_or_default();
    let directory = dir_name(path);
    let mut sessions = Vec::new();

    for block in text.split("# aider chat started at ") {
        if block.trim().is_empty() {
            continue;
        }
        let (first_line, body) = match block.split_once('\n') {
            Some((line, rest)) => (line, rest),
            None => (block, ""),
        };
        let prompt = first_aider_prompt(body);
        let stamp = first_line.trim();
        let sid = format!(
            "{directory}-{}",
            stamp.replace(':', "-").replace(' ', "-")
        );
        sessions.push(Session {
            platform: "aider".to_owned(),
            id: sid,
            path: path.display().to_string(),
            cwd: Some(parent.clone()),
            created_at: Some(stamp.to_owned()),
            updated_at: scan_util::file_mtime_iso(path),
            provider: None,
            model: None,
            first_user_message: prompt.clone(),
            last_user_message: prompt,
            usage: Map::new(),
            parent_id: None,
            agent: None,
        });
    }
    sessions
}

// ----------------------------------------------------------------- helpers

/// Port of the finder's `_roots`: default roots plus each extra root and its
/// known child subdirectories, keeping existing paths only.
fn scan_roots(defaults: Vec<PathBuf>, extra: &[PathBuf], children: &[&str]) -> Vec<PathBuf> {
    let mut expanded = Vec::with_capacity(extra.len() * (children.len() + 1));
    for root in extra {
        expanded.push(root.clone());
        for &child in children {
            expanded.push(root.join(child));
        }
    }
    common::merge_roots(defaults, &expanded)
}

/// Walk `base` following a shallow `/`-separated glob pattern (final segment
/// matches files, earlier segments match directories).
fn glob_files(base: &Path, pattern: &str) -> Vec<PathBuf> {
    let segments: Vec<&str> = pattern.split('/').filter(|segment| !segment.is_empty()).collect();
    let mut out = Vec::new();
    walk_glob(base, &segments, &mut out);
    out
}

fn walk_glob(dir: &Path, segments: &[&str], out: &mut Vec<PathBuf>) {
    let Some((&segment, rest)) = segments.split_first() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if !scan_util::match_name(&name, segment) {
            continue;
        }
        let path = entry.path();
        if rest.is_empty() {
            if path.is_file() {
                out.push(path);
            }
        } else if path.is_dir() {
            walk_glob(&path, rest, out);
        }
    }
}

/// Non-list element of a JSON array, as objects.
fn json_maps(value: &Value) -> Vec<&Map<String, Value>> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

/// First/last user prompt across `role`/`type`-tagged messages.
fn message_edges(messages: &[&Map<String, Value>], role_keys: &[&str]) -> (String, String) {
    let mut first = String::new();
    let mut last = String::new();
    for message in messages {
        let role = message.get("role").and_then(Value::as_str).unwrap_or_default();
        let kind = message.get("type").and_then(Value::as_str).unwrap_or_default();
        if !role_keys.contains(&role) && !role_keys.contains(&kind) {
            continue;
        }
        let prompt = content_of(message.get("content").unwrap_or(&Value::Null));
        if !prompt.is_empty() {
            if first.is_empty() {
                first = prompt.clone();
            }
            last = prompt;
        }
    }
    (first, last)
}

/// Content text, parsing embedded JSON strings first (finder's `_content`).
fn content_of(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        if let Ok(parsed) = serde_json::from_str::<Value>(text) {
            let extracted = scan_util::content_text(&parsed);
            if !extracted.is_empty() {
                return extracted;
            }
        }
        return text.to_owned();
    }
    scan_util::content_text(value)
}

/// Droid prompt text with `<system-reminder>` parts dropped.
fn without_system_reminders(value: &Value) -> String {
    let Some(items) = value.as_array() else {
        return content_of(value);
    };
    let mut parts: Vec<String> = Vec::new();
    for item in items {
        let Some(map) = item.as_object() else {
            continue;
        };
        let text = map
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .or_else(|| map.get("content").and_then(Value::as_str))
            .unwrap_or_default();
        if text.starts_with("<system-reminder>") {
            continue;
        }
        if !text.is_empty() {
            parts.push(text.to_owned());
        }
    }
    parts.join("\n")
}

/// Numeric fields of `tokenUsage` (finder's `_usage`).
fn token_usage(settings: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(usage) = settings.get("tokenUsage").and_then(Value::as_object) {
        for (key, value) in usage {
            if value.is_number() {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    out
}

/// First `model:` tag in an amp `tags` array.
fn tag_model(value: &Value) -> Option<String> {
    let items = value.as_array()?;
    for item in items {
        if let Some(tag) = item.as_str() {
            if let Some(rest) = tag.strip_prefix("model:") {
                return Some(rest.to_owned());
            }
        }
    }
    None
}

/// Convert a `file:` URI to a filesystem path (port of `_file_uri_path`).
fn file_uri_path(value: Option<&str>) -> Option<String> {
    let value = value?;
    let (scheme, rest) = match value.find(':') {
        Some(index)
            if index > 0
                && value[..index]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') =>
        {
            (&value[..index], &value[index + 1..])
        }
        _ => ("", value),
    };
    if scheme != "file" {
        return Some(value.to_owned());
    }
    let (netloc, path) = match rest.strip_prefix("//") {
        Some(after) => match after.find('/') {
            Some(slash) => (&after[..slash], &after[slash..]),
            None => (after, ""),
        },
        None => ("", rest),
    };
    let path = percent_decode(path);
    if !netloc.is_empty() && netloc != "localhost" {
        return Some(format!("//{netloc}{path}"));
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[2] == b':' && bytes[1].is_ascii_alphabetic() {
        return Some(path[1..].to_owned());
    }
    Some(path)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// First `#### ` prompt line inside an aider chat block.
fn first_aider_prompt(body: &str) -> String {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("#### ") {
            return rest.trim().to_owned();
        }
    }
    String::new()
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_owned()
}

fn dir_name(path: &Path) -> String {
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned()
}

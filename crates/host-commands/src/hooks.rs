//! Plugin hook runner.
//!
//! Config is `<data-dir>/plugins.json`:
//! ```jsonc
//! { "hooks": {
//!     "pre-remember":  [{ "cmd": "sensitive-scan", "timeout_ms": 3000, "on_error": "block" }],
//!     "post-remember": [{ "cmd": "auto-tagger", "timeout_ms": 5000, "on_error": "warn" }]
//! } }
//! ```
//! Semantics: event JSON is written to the plugin stdin (`{"event":"...","ts":"...","data":{...}}`);
//! a `pre-*` hook that exits 0 with stdout `{"verdict":"block","reason":"..."}` vetoes the action;
//! a non-zero exit follows `on_error` (block=veto / warn=log and continue / skip=silent);
//! `post-*` failures do not block the main flow. Timeouts report failure; the child is not killed.
//! Safety: the child is stripped of all ONEMEMORY_* secrets; payloads are summaries, not keys.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Hook event. pre = before the action (can veto); post = after (observe only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    PreRemember,
    PostRemember,
    PostRecall,
    PostForget,
    PostSync,
}

impl HookEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookEvent::PreRemember => "pre-remember",
            HookEvent::PostRemember => "post-remember",
            HookEvent::PostRecall => "post-recall",
            HookEvent::PostForget => "post-forget",
            HookEvent::PostSync => "post-sync",
        }
    }
    pub fn parse(s: &str) -> Option<HookEvent> {
        Some(match s {
            "pre-remember" => HookEvent::PreRemember,
            "post-remember" => HookEvent::PostRemember,
            "post-recall" => HookEvent::PostRecall,
            "post-forget" => HookEvent::PostForget,
            "post-sync" => HookEvent::PostSync,
            _ => return None,
        })
    }
    /// Pre events may veto the action; post events only observe.
    pub fn is_pre(&self) -> bool {
        matches!(self, HookEvent::PreRemember)
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HookSpec {
    /// Plugin command (run via shell; may include args).
    pub cmd: String,
    /// Wait timeout in milliseconds (default 5000; `on_error` applies without killing the child).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Failure policy: block (pre may veto) / warn (stderr warning, action continues) / skip (silent).
    /// Pre defaults to warn; post defaults to skip.
    #[serde(default)]
    pub on_error: String,
}

fn default_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct HooksConfig {
    #[serde(default)]
    pub hooks: BTreeMap<String, Vec<HookSpec>>,
}

#[cfg(feature = "server")]

pub fn config_path() -> std::path::PathBuf {
    respire_app::service::data_dir().join("plugins.json")
}

/// Compatibility entry for Runtime callers using their current data directory.
#[cfg(feature = "server")]
pub fn read_config() -> HooksConfig {
    read_config_at(&config_path())
}

/// Preserve plugins.json compatibility: missing or corrupt files mean no hooks.
pub fn read_config_at(path: &Path) -> HooksConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Result of one fire() call.
#[derive(Debug, Default)]
pub struct HookVerdict {
    /// Pre events: true = the action was vetoed.
    pub blocked: bool,
    pub reason: String,
    /// Warnings (`on_error=warn` or plugin stderr summary); the caller may display them.
    pub warnings: Vec<String>,
}

impl HookVerdict {
    fn allow() -> HookVerdict {
        HookVerdict::default()
    }
}

/// Single-hook outcome: Ok=success / Blocked=explicit veto / Failed=handled per on_error.
enum HookOutcome {
    Ok(Vec<String>),
    Blocked(String),
    Failed(String),
}

/// Compatibility entry for Runtime callers using their current data directory.
#[cfg(feature = "server")]
pub fn fire(event: HookEvent, payload: serde_json::Value) -> HookVerdict {
    fire_at(&config_path(), event, payload)
}

/// Fire one event: run every hook for it in order.
/// payload is a summary-level business payload; combined with event/ts into JSON on plugin stdin.
pub fn fire_at(path: &Path, event: HookEvent, payload: serde_json::Value) -> HookVerdict {
    let cfg = read_config_at(path);
    let specs = match cfg.hooks.get(event.as_str()) {
        Some(v) if !v.is_empty() => v,
        _ => return HookVerdict::allow(),
    };
    let mut verdict = HookVerdict::allow();
    let envelope = serde_json::json!({
        "event": event.as_str(),
        "ts": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string(),
        "data": payload,
    });
    for spec in specs {
        match run_hook(spec, &envelope) {
            HookOutcome::Ok(mut w) => verdict.warnings.append(&mut w),
            HookOutcome::Blocked(reason) => {
                // Explicit veto always applies, regardless of on_error - skip only covers faults, not verdicts.
                verdict.blocked = true;
                verdict.reason = format!("hook {} blocked: {reason}", spec.cmd);
            }
            HookOutcome::Failed(fail) => {
                let policy = if spec.on_error.is_empty() && event.is_pre() {
                    "warn"
                } else if spec.on_error.is_empty() {
                    "skip"
                } else {
                    spec.on_error.as_str()
                };
                match (event.is_pre(), policy) {
                    (true, "block") => {
                        verdict.blocked = true;
                        verdict.reason = format!("hook {} failed: {fail}", spec.cmd);
                    }
                    (true, "warn") | (_, "warn") => {
                        verdict
                            .warnings
                            .push(format!("hook {} failed (continuing): {fail}", spec.cmd));
                    }
                    _ => {} // skip: silent
                }
            }
        }
        if verdict.blocked {
            break; // vetoed; remaining hooks are not run
        }
    }
    verdict
}

/// Run a single plugin.
fn run_hook(spec: &HookSpec, envelope: &serde_json::Value) -> HookOutcome {
    // Restore PATH/HOME and Windows SystemRoot, but no ONEMEMORY_* secrets.
    // New secret vars are also wiped by env_clear, so there is no "forgot to strip" hole.
    #[cfg(windows)]
    let mut spawn = {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/S", "/C"]);
        command.raw_arg(&spec.cmd);
        command
    };
    #[cfg(not(windows))]
    let mut spawn = {
        let mut command = Command::new("sh");
        command.arg("-c").arg(&spec.cmd);
        command
    };
    let spawn = spawn
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", crate::env::var("PATH").unwrap_or_default())
        .env("HOME", crate::env::var("HOME").unwrap_or_default())
        .env("RSRS_HOOK_EVENT", envelope["event"].as_str().unwrap_or(""));
    #[cfg(windows)]
    if let Some(root) = crate::env::var_os("SystemRoot") {
        spawn.env("SystemRoot", root);
    }
    let mut child = match spawn.spawn() {
        Ok(c) => c,
        Err(e) => return HookOutcome::Failed(format!("failed to start ({e})")),
    };
    let mut stdin = match child.stdin.take() {
        Some(s) => s,
        None => return HookOutcome::Failed("stdin unavailable".into()),
    };
    let body = match serde_json::to_string(envelope) {
        Ok(b) => b,
        Err(e) => return HookOutcome::Failed(e.to_string()),
    };
    // Write stdin on a side thread: a plugin that never reads stdin would block the writer.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(body.as_bytes());
    });

    let (tx, rx) = mpsc::channel::<std::io::Result<std::process::Output>>();
    let _ = &tx;
    let waiter = {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let out = child.wait_with_output();
            let _ = tx.send(out);
        })
    };
    let timeout = Duration::from_millis(spec.timeout_ms.max(1));
    let output = match rx.recv_timeout(timeout) {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return HookOutcome::Failed(format!("wait for plugin failed ({e})")),
        Err(_) => {
            // Timeout: the child was moved into the waiter thread so we cannot kill it -
            // treat as failure. The plugin is responsible for its own watchdog (documented).
            // writer/waiter wind down when the pipe closes.
            let _ = writer.join();
            return HookOutcome::Failed(format!("timeout (>{}ms)", spec.timeout_ms));
        }
    };
    drop(writer);
    drop(waiter);

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    for line in stderr.lines().filter(|l| !l.trim().is_empty()).take(5) {
        eprintln!("HOOK command={} message={}", spec.cmd, line);
    }
    if !output.status.success() {
        return HookOutcome::Failed(format!("{}", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Pre: last stdout JSON line {"verdict":"block","reason":"..."} -> veto
    if let Some(last) = stdout.lines().rev().find(|l| !l.trim().is_empty()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(last.trim()) {
            if v["verdict"] == "block" {
                return HookOutcome::Blocked(
                    v["reason"].as_str().unwrap_or("no reason given").to_owned(),
                );
            }
        }
    }
    HookOutcome::Ok(Vec::new())
}

#[cfg(feature = "server")]

/// Alias over fire(): public paths all go through fire.
pub fn verdict_of(event: HookEvent, payload: serde_json::Value) -> HookVerdict {
    fire(event, payload)
}

/// Full event-name table (plugin list / docs).
pub const EVENT_NAMES: &[&str] = &[
    "pre-remember",
    "post-remember",
    "post-recall",
    "post-forget",
    "post-sync",
];

// -- Event payload builders (summary-level: the smallest surface a hook needs) --

pub fn remember_payload(
    title: &str,
    importance: &str,
    kind: &str,
    project: &str,
    content: &str,
) -> serde_json::Value {
    serde_json::json!({
        "title": title,
        "importance": importance,
        "kind": kind,
        "project": project,
        "content_head": content.chars().take(200).collect::<String>(),
        "content_chars": content.chars().count(),
    })
}

pub fn remember_done_payload(id: &str, title: &str, importance: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "title": title, "importance": importance })
}

pub fn recall_payload(query: &str, project: &str, hits: &[(String, f32)]) -> serde_json::Value {
    serde_json::json!({
        "query": query,
        "project": project,
        "hits": hits.iter().map(|(id, s)| serde_json::json!({"id": id, "score": s})).collect::<Vec<_>>(),
    })
}

pub fn forget_payload(id: &str) -> serde_json::Value {
    serde_json::json!({ "id": id })
}

pub fn sync_payload(pulled: usize, pushed: usize) -> serde_json::Value {
    serde_json::json!({ "pulled": pulled, "pushed": pushed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_roundtrip() {
        for e in [
            HookEvent::PreRemember,
            HookEvent::PostRemember,
            HookEvent::PostRecall,
            HookEvent::PostForget,
            HookEvent::PostSync,
        ] {
            assert_eq!(HookEvent::parse(e.as_str()), Some(e));
        }
        assert_eq!(HookEvent::parse("nope"), None);
        assert!(HookEvent::PreRemember.is_pre());
        assert!(!HookEvent::PostSync.is_pre());
    }

    #[test]
    fn test_config_missing_is_empty() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("missing/plugins.json");
        let cfg = read_config_at(&path);
        assert!(cfg.hooks.is_empty());
        let v = fire_at(&path, HookEvent::PreRemember, serde_json::json!({}));
        assert!(!v.blocked);
        Ok(())
    }

    #[test]
    fn test_payload_summary_only() {
        let p = remember_payload("t", "normal", "context", "proj", "a very long body");
        assert_eq!(p["title"], "t");
        assert!(p["content_head"].is_string());
        assert!(p.get("id").is_none());
    }

    #[test]
    fn fire_runs_shell_hook() -> anyhow::Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("plugins.json");
        let cfg = serde_json::json!({
            "hooks": {
                "pre-remember": [{"cmd": "exit 0", "timeout_ms": 2000, "on_error": "warn"}]
            }
        });
        std::fs::write(&path, cfg.to_string())?;
        let v = fire_at(&path, HookEvent::PreRemember, serde_json::json!({"title":"t"}));
        assert!(!v.blocked);
        let cfg_block = serde_json::json!({
            "hooks": {
                "pre-remember": [{"cmd": "exit 1", "timeout_ms": 2000, "on_error": "block"}]
            }
        });
        std::fs::write(&path, cfg_block.to_string())?;
        let v = fire_at(&path, HookEvent::PreRemember, serde_json::json!({}));
        assert!(v.blocked);
        Ok(())
    }

    #[test]
    fn payload_builders_and_event_names() -> anyhow::Result<()> {
        assert_eq!(EVENT_NAMES.len(), 5);
        let done = remember_done_payload("id", "t", "important");
        assert_eq!(done["id"], "id");
        let rec = recall_payload("q", "p", &[("a".into(), 0.9)]);
        assert_eq!(rec["query"], "q");
        assert_eq!(forget_payload("x")["id"], "x");
        assert_eq!(sync_payload(1, 2)["pulled"], 1);
        let dir = tempfile::tempdir()?;
        let v = fire_at(&dir.path().join("plugins.json"), HookEvent::PostSync, serde_json::json!({}));
        assert!(!v.blocked);
        Ok(())
    }

    #[test]
    fn hook_failure_policies_and_explicit_veto() -> anyhow::Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("plugins.json");
        for (event, policy, blocked, warned) in [
            (HookEvent::PreRemember, "", false, true),
            (HookEvent::PreRemember, "warn", false, true),
            (HookEvent::PreRemember, "skip", false, false),
            (HookEvent::PreRemember, "block", true, false),
            (HookEvent::PostSync, "", false, false),
            (HookEvent::PostSync, "block", false, false),
            (HookEvent::PostSync, "warn", false, true),
        ] {
            let cfg = serde_json::json!({"hooks": {event.as_str(): [
                {"cmd": "exit 1", "on_error": policy, "timeout_ms": 2000}
            ]}});
            std::fs::write(&path, cfg.to_string())?;
            let verdict = fire_at(&path, event, serde_json::json!({}));
            assert_eq!(
                verdict.blocked,
                blocked,
                "{} policy={policy}",
                event.as_str()
            );
            assert_eq!(!verdict.warnings.is_empty(), warned);
            assert!(!verdict.reason.contains("failed to start"));
            assert!(verdict
                .warnings
                .iter()
                .all(|warning| !warning.contains("failed to start")));
        }
        let veto_command = if cfg!(windows) {
            "echo {\"verdict\":\"block\",\"reason\":\"private data\"}"
        } else {
            "echo '{\"verdict\":\"block\",\"reason\":\"private data\"}'"
        };
        let cfg = serde_json::json!({"hooks": {"pre-remember": [
            {"cmd": veto_command, "on_error": "skip"},
            {"cmd": "exit 1", "on_error": "warn"}
        ]}});
        std::fs::write(&path, cfg.to_string())?;
        let verdict = fire_at(&path, HookEvent::PreRemember, serde_json::json!({}));
        assert!(verdict.blocked);
        assert!(verdict.reason.contains("private data"));
        assert!(verdict.warnings.is_empty(), "a veto must stop later hooks");
        std::fs::write(&path, "invalid json")?;
        assert!(read_config_at(&path).hooks.is_empty());
        Ok(())
    }
}

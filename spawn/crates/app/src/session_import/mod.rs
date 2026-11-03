//! Coding-agent session import.
//!
//! Extract the process data local coding agents save on disk (Codex, OpenCode,
//! Claude Code and 23 more) and turn it into rsrs memories. This mirrors the
//! cross-platform `coding-agent-sessions` finder: every platform scanner
//! normalizes its own store into a common [`Session`], which [`convert`] turns
//! into a protocol [`MemoryEntry`] that the CLI seals and imports.
//!
//! Layout:
//!   · [`scan_util`] – dependency-free file/JSON/time helpers
//!   · [`platforms`] – one scanner per supported agent, plus the registry
//!   · [`convert`]   – Session → MemoryEntry (title/body/scrub)
//!   · [`cursor`]    – incremental "already imported" state
//!
//! Reads are best-effort and never panic; missing stores simply return nothing.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub mod convert;
pub mod cursor;
pub mod platforms;
pub mod scan_util;
pub mod store;

pub use convert::{scrub, session_entry, ConvertOptions};
pub use cursor::Cursor;
pub use store::import_entries;

/// One normalized coding-agent session (platform-agnostic).
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub platform: String,
    pub id: String,
    pub path: String,
    pub cwd: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub first_user_message: String,
    pub last_user_message: String,
    pub usage: serde_json::Map<String, Value>,
    pub parent_id: Option<String>,
    pub agent: Option<String>,
}

impl Session {
    /// Version of the imported summary for SQLite sources without a trustworthy
    /// per-session update time. Exclude database file timestamps: checkpoints and
    /// writes to other sessions must not re-import an unchanged summary.
    pub(crate) fn uses_content_cursor(&self) -> bool {
        matches!(
            self.platform.as_str(),
            "kilo-cli" | "hermes" | "goose" | "crush" | "cursor-cli"
        )
    }

    pub(crate) fn content_fingerprint(&self) -> Option<String> {
        if !self.uses_content_cursor() {
            return None;
        }
        use sha2::{Digest, Sha256};
        let summary = json!([
            self.cwd,
            self.provider,
            self.model,
            self.first_user_message,
            self.last_user_message,
            self.usage,
            self.parent_id,
            self.agent,
        ]);
        Some(format!(
            "{:x}",
            Sha256::digest(summary.to_string().as_bytes())
        ))
    }

    /// Stable identity used for cross-run dedup (`platform:id`).
    pub fn key(&self) -> String {
        format!("{}:{}", self.platform, self.id)
    }

    /// Display/JSON projection, mirroring the finder's output contract.
    pub fn to_json(&self) -> Value {
        let preview = |text: &str| -> String { convert::scrub(text).chars().take(300).collect() };
        let last = if self.last_user_message.is_empty() {
            self.first_user_message.clone()
        } else {
            self.last_user_message.clone()
        };
        json!({
            "platform": self.platform,
            "id": self.id,
            "path": convert::scrub(&self.path),
            "cwd": self.cwd.as_deref().map(convert::scrub),
            "created_at": self.created_at.as_deref().map(convert::scrub),
            "updated_at": self.updated_at.as_deref().map(convert::scrub),
            "provider": self.provider.as_deref().map(convert::scrub),
            "model": self.model.as_deref().map(convert::scrub),
            "first_user_message": preview(&self.first_user_message),
            "last_user_message": preview(&last),
            "usage": Value::Object(self.usage.clone()),
            "parent_id": self.parent_id.as_deref().map(convert::scrub),
            "agent": self.agent.as_deref().map(convert::scrub),
        })
    }
}

/// Filters applied while scanning.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Extra roots supplied by the user (in addition to per-platform defaults).
    pub roots: Vec<PathBuf>,
    pub cwd: Option<String>,
    pub model: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: usize,
    pub include_subagents: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            cwd: None,
            model: None,
            since: None,
            until: None,
            limit: 200,
            include_subagents: false,
        }
    }
}

impl ScanOptions {
    /// Whether a session passes the cwd/model/time/subagent filters.
    pub fn matches(&self, session: &Session) -> bool {
        if !self.include_subagents && session.parent_id.is_some() {
            return false;
        }
        if let Some(cwd) = self.cwd.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let hay = session.cwd.as_deref().unwrap_or_default();
            if !contains_ignore_case(hay, cwd) {
                return false;
            }
        }
        if let Some(model) = self
            .model
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let hay = format!(
                "{} {}",
                session.model.as_deref().unwrap_or_default(),
                session.provider.as_deref().unwrap_or_default()
            );
            if !contains_ignore_case(&hay, model) {
                return false;
            }
        }
        let stamp = session
            .updated_at
            .as_deref()
            .and_then(scan_util::parse_stamp)
            .or_else(|| {
                session
                    .created_at
                    .as_deref()
                    .and_then(scan_util::parse_stamp)
            });
        if (self.since.is_some() || self.until.is_some()) && stamp.is_none() {
            return false;
        }
        if let Some(since) = self.since {
            if let Some(stamp) = stamp {
                if stamp < since {
                    return false;
                }
            }
        }
        if let Some(until) = self.until {
            if let Some(stamp) = stamp {
                if stamp >= until {
                    return false;
                }
            }
        }
        true
    }
}

/// Static, machine-facing description of a platform (for `extract --targets`).
#[derive(Debug, Clone)]
pub struct Source {
    pub id: String,
    pub name: String,
    /// At least one default store root exists on this machine.
    pub installed: bool,
    /// Existing default roots (display).
    pub roots: Vec<PathBuf>,
}

/// A per-platform session scanner.
pub trait SessionScanner {
    /// Stable platform id (e.g. `codex`, `opencode`).
    fn id(&self) -> &'static str;
    /// Human label.
    fn name(&self) -> &'static str;
    /// Default store roots that exist on this machine.
    fn roots(&self) -> Vec<PathBuf>;
    /// Scan the platform's local store into normalized sessions.
    fn scan(&self, opts: &ScanOptions) -> Vec<Session>;
}

/// All supported platform scanners, in registry order.
pub fn scanners() -> Vec<Box<dyn SessionScanner>> {
    platforms::registry()
}

/// Find one scanner by id (case-insensitive, with a few common aliases).
pub fn find_scanner(id: &str) -> Option<Box<dyn SessionScanner>> {
    let wanted = platforms::normalize_alias(id);
    scanners()
        .into_iter()
        .find(|scanner| scanner.id() == wanted)
}

/// Current machine's source list, for `extract --targets`.
pub fn source_list() -> Vec<Source> {
    scanners()
        .into_iter()
        .map(|scanner| {
            let roots = scanner.roots();
            Source {
                id: scanner.id().to_owned(),
                name: scanner.name().to_owned(),
                installed: !roots.is_empty(),
                roots,
            }
        })
        .collect()
}

/// Drop duplicate `platform:id` sessions, preferring richer parent/agent linkage.
pub fn dedupe(sessions: Vec<Session>) -> Vec<Session> {
    let mut found: std::collections::HashMap<String, Session> = std::collections::HashMap::new();
    for session in sessions {
        let key = session.key();
        match found.get(&key) {
            Some(current) if linkage_score(current) >= linkage_score(&session) => {}
            _ => {
                found.insert(key, session);
            }
        }
    }
    found.into_values().collect()
}

/// Sort newest-first and keep at most `limit` sessions per platform, so a
/// high-volume source cannot crowd out every other source.
pub fn cap_per_platform(mut sessions: Vec<Session>, limit: usize) -> Vec<Session> {
    sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    sessions.retain(|session| {
        let count = counts.entry(session.platform.clone()).or_insert(0);
        if *count < limit {
            *count += 1;
            true
        } else {
            false
        }
    });
    sessions
}

fn linkage_score(session: &Session) -> u8 {
    u8::from(session.parent_id.is_some()) + u8::from(session.agent.is_some())
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(platform: &str, id: &str, parent: Option<&str>) -> Session {
        Session {
            platform: platform.into(),
            id: id.into(),
            parent_id: parent.map(ToOwned::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn dedupe_prefers_linkage() {
        let plain = session("codex", "t1", None);
        let linked = session("codex", "t1", Some("p0"));
        let out = dedupe(vec![plain, linked]);
        assert_eq!(out.len(), 1);
        assert!(out[0].parent_id.is_some());
    }

    #[test]
    fn filters_apply_cwd_and_subagents() {
        let mut opts = ScanOptions::default();
        opts.cwd = Some("respire".into());
        opts.include_subagents = false;
        let mut s = session("claude", "s1", Some("p"));
        s.cwd = Some("/work/respire".into());
        assert!(!opts.matches(&s), "subagent excluded");
        s.parent_id = None;
        s.agent = None;
        assert!(opts.matches(&s), "cwd matches");
        s.cwd = Some("/other".into());
        assert!(!opts.matches(&s), "cwd mismatch");
        s.cwd = Some("/work/respire".into());
        s.agent = Some("Sisyphus".into());
        assert!(
            opts.matches(&s),
            "agent label alone is not a child indicator"
        );
    }

    #[test]
    fn cap_per_platform_keeps_newest_per_platform() {
        let entry = |platform: &str, id: &str, updated: &str| Session {
            platform: platform.into(),
            id: id.into(),
            updated_at: Some(updated.into()),
            ..Default::default()
        };
        let out = cap_per_platform(
            vec![
                entry("a", "1", "2026-01-01T00:00:00Z"),
                entry("a", "2", "2026-01-03T00:00:00Z"),
                entry("a", "3", "2026-01-02T00:00:00Z"),
                entry("b", "1", "2026-01-01T00:00:00Z"),
            ],
            2,
        );
        assert_eq!(out.len(), 3);
        let a: Vec<&str> = out
            .iter()
            .filter(|s| s.platform == "a")
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(a, vec!["2", "3"]);
    }

    #[test]
    fn session_json_truncates_preview() -> Result<(), Box<dyn std::error::Error>> {
        let mut s = session("opencode", "ses_1", None);
        s.first_user_message = "x".repeat(500);
        let value = s.to_json();
        let first = value["first_user_message"].as_str().ok_or("first")?;
        assert_eq!(first.chars().count(), 300);
        assert_eq!(value["last_user_message"].as_str().ok_or("last")?, first);
        Ok(())
    }
}

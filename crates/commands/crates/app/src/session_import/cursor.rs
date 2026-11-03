//! Incremental import cursor.
//!
//! Records which `platform:id` sessions were already imported and at which
//! `updated_at`, so re-running `rsrs extract` skips unchanged sessions and only
//! re-imports ones that grew since. Stored as JSON under the active data dir
//! (`extract-state.json`); a missing or unreadable file means "nothing imported".

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{scan_util, Session};

/// Distinguishes each `save` within a process, so concurrent saves cannot reuse
/// the same temporary path.
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default, Serialize, Deserialize)]
struct CursorFile {
    /// `platform:id` → last imported `updated_at` (`*` = unknown timestamp).
    #[serde(default)]
    entries: BTreeMap<String, String>,
    /// Content versions for SQLite sources; legacy timestamp-only cursors get
    /// one refresh to establish a version that can see WAL changes.
    #[serde(default)]
    fingerprints: BTreeMap<String, String>,
}

/// Persistent set of already-imported sessions.
#[derive(Debug)]
pub struct Cursor {
    path: PathBuf,
    data: CursorFile,
}

impl Cursor {
    /// Cursor file path for the active profile.
    pub fn path() -> PathBuf {
        crate::service::data_dir().join("extract-state.json")
    }

    /// Load the cursor (empty when the file is absent or malformed).
    pub fn load() -> Self {
        let path = Self::path();
        let data = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<CursorFile>(&text).ok())
            .unwrap_or_default();
        Self { path, data }
    }

    /// Number of tracked sessions.
    pub fn len(&self) -> usize {
        self.data.entries.len()
    }

    /// Whether the session is already imported and unchanged since.
    pub fn is_imported(&self, session: &Session) -> bool {
        if let Some(current) = session.content_fingerprint() {
            return self.data.fingerprints.get(&session.key()) == Some(&current);
        }
        let Some(stored) = self.data.entries.get(&session.key()) else {
            return false;
        };
        if stored == "*" {
            return session
                .updated_at
                .as_deref()
                .map_or(true, |stamp| stamp.is_empty());
        }
        let current = session.updated_at.clone().unwrap_or_default();
        if current.is_empty() {
            return true;
        }
        match (
            scan_util::parse_stamp(&current),
            scan_util::parse_stamp(stored),
        ) {
            (Some(current), Some(previous)) => current <= previous,
            _ => stored == &current,
        }
    }

    /// Record a session as imported.
    pub fn mark(&mut self, session: &Session) {
        if let Some(fingerprint) = session.content_fingerprint() {
            self.data.fingerprints.insert(session.key(), fingerprint);
        }
        let stamp = session
            .updated_at
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "*".to_owned());
        self.data.entries.insert(session.key(), stamp);
    }

    /// Persist the cursor (creating the data dir when needed).
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(&self.data)?;
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .path
            .with_extension(format!("{}.{}.tmp", std::process::id(), unique));
        std::fs::write(&temp, json).with_context(|| format!("write {}", temp.display()))?;
        if let Err(error) = std::fs::rename(&temp, &self.path) {
            let _ = std::fs::remove_file(&temp);
            return Err(error).with_context(|| format!("replace {}", self.path.display()));
        }
        Ok(())
    }

    /// Drop all tracked sessions.
    pub fn clear(&mut self) {
        self.data.entries.clear();
        self.data.fingerprints.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: &str, updated: Option<&str>) -> Session {
        Session {
            platform: "codex".into(),
            id: id.into(),
            updated_at: updated.map(ToOwned::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn marks_and_detects_unchanged_sessions() {
        let mut cursor = Cursor {
            path: PathBuf::from("ignored.json"),
            data: CursorFile::default(),
        };
        let first = session("t1", Some("2026-10-01T00:00:00Z"));
        assert!(!cursor.is_imported(&first));
        cursor.mark(&first);
        assert!(cursor.is_imported(&first));

        // A newer update re-qualifies the session for import.
        let newer = session("t1", Some("2026-10-02T00:00:00Z"));
        assert!(!cursor.is_imported(&newer));
    }

    #[test]
    fn unknown_timestamp_is_treated_as_imported() {
        let mut cursor = Cursor {
            path: PathBuf::from("ignored.json"),
            data: CursorFile::default(),
        };
        let s = session("t2", None);
        cursor.mark(&s);
        assert!(cursor.is_imported(&s));
        assert_eq!(cursor.len(), 1);
    }

    #[test]
    fn unknown_timestamp_reimports_once_a_stamp_appears() {
        let mut cursor = Cursor {
            path: PathBuf::from("ignored.json"),
            data: CursorFile::default(),
        };
        let unknown = session("t3", None);
        cursor.mark(&unknown);
        assert!(cursor.is_imported(&unknown));

        let stamped = session("t3", Some("2026-10-02T00:00:00Z"));
        assert!(!cursor.is_imported(&stamped));
    }

    #[test]
    fn content_cursor_migrates_legacy_marks_and_ignores_checkpoint_time() {
        let mut cursor = Cursor {
            path: "ignored.json".into(),
            data: CursorFile::default(),
        };
        let mut current = session("wal", Some("2026-10-01T00:00:00Z"));
        current.platform = "hermes".into();
        current.first_user_message = "synthetic first request".into();
        cursor
            .data
            .entries
            .insert(current.key(), "2026-10-01T00:00:00Z".into());
        assert!(
            !cursor.is_imported(&current),
            "legacy mtime mark needs one refresh"
        );
        cursor.mark(&current);
        assert!(cursor.is_imported(&current));
        current.updated_at = Some("2026-10-02T00:00:00Z".into());
        current.created_at = current.updated_at.clone();
        assert!(
            cursor.is_imported(&current),
            "checkpoint alone changes no summary"
        );
        current.last_user_message = "new request".into();
        assert!(!cursor.is_imported(&current));
        cursor.mark(&current);
        assert!(cursor.is_imported(&current));
        cursor.clear();
        assert!(!cursor.is_imported(&current));
    }
}

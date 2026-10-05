//! memory::model — domain model (pure data, no IO)
//!
//! local-first architecture freeze (2026-09-02):
//!   · server = dumb ciphertext store, sees only {id, user, ciphertext, nonce, embedding_enc, updated_at, deleted}
//!   · plaintext metadata (kind/tags/title/created_at…) all lives in the ciphertext payload (v2 JSON)
//!   · embedding is derived: encrypted and synced (rebuild index on other devices), plus a local plaintext copy for search
//!   · search / dedup / merge are all local; the server has zero search APIs

use serde::{Deserialize, Serialize};

pub const VERSION_TAG: &str = env!("CARGO_PKG_VERSION");

/// Memory kind (seven classes + knowledge; software-agnostic semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Context,
    Decision,
    Preference,
    Task,
    Emotion,
    Time,
    Skill,
    Knowledge,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Context => "context",
            Kind::Decision => "decision",
            Kind::Preference => "preference",
            Kind::Task => "task",
            Kind::Emotion => "emotion",
            Kind::Time => "time",
            Kind::Skill => "skill",
            Kind::Knowledge => "knowledge",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "decision" => Kind::Decision,
            "preference" => Kind::Preference,
            "task" => Kind::Task,
            "emotion" => Kind::Emotion,
            "time" => Kind::Time,
            "skill" => Kind::Skill,
            "knowledge" => Kind::Knowledge,
            _ => Kind::Context,
        }
    }

    /// Chinese kind label (display).
    pub fn display_zh(&self) -> &'static str {
        match self {
            Kind::Context => "上下文",
            Kind::Decision => "决策",
            Kind::Preference => "偏好",
            Kind::Task => "任务",
            Kind::Emotion => "情绪",
            Kind::Time => "时间",
            Kind::Skill => "技能",
            Kind::Knowledge => "知识",
        }
    }
}

/// Plaintext form of one memory (client memory/display only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub supersedes: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub superseded_by: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub see_also: Vec<String>,
    pub id: String,
    pub kind: Kind,
    pub tags: Vec<String>,
    pub title: String,
    pub content: String,
    pub user: String,
    pub computer: String,
    pub project: String,
    pub created_at: String,
    pub updated_at: String,
    /// Emotion intensity 0.0~1.0; -1 means unlabeled.
    pub emotion: f32,
    /// Forward-star parent id (empty = root; tree is restored from the ciphertext payload across devices).
    pub parent_id: String,
    /// Importance (two-tier): important (main library) | trivial (diary); normal is retired (read for compatibility).
    #[serde(default = "default_importance")]
    pub importance: String,
    /// Storage device (host/platform, e.g. fslong-hasee/linux): first-write device. Empty on old data.
    #[serde(default)]
    pub device: String,
    /// Last-modified device: refreshed on update/append/merge (together with updated_at: which device changed it when). Empty on old data.
    #[serde(default)]
    pub modified_by: String,
}

/// Ciphertext payload v2 (AES-256-GCM of the whole object; decrypting on a client yields this struct).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadV2 {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub supersedes: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub superseded_by: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub see_also: Vec<String>,
    pub kind: String,
    pub tags: String, // comma-separated
    pub title: String,
    pub content: String,
    pub user: String,
    pub computer: String,
    pub project: String,
    pub created_at: String,
    pub updated_at: String,
    /// Emotion intensity 0.0~1.0; -1 means unlabeled. Missing on old data; serde default -1.
    #[serde(default = "default_emotion")]
    pub emotion: f32,
    /// Forward-star parent id (empty = root). Missing on old data; serde default empty.
    #[serde(default)]
    pub parent_id: String,
    /// Importance (two-tier): important | trivial; normal is retired (read for compatibility).
    /// important = distilled experience (main recall zone — "how to do this next time");
    /// trivial = diary (time-ordered archive of "what actually happened").
    /// Missing on old data; serde default normal. AI summarizes and grades on store (inject "grading rules").
    #[serde(default = "default_importance")]
    pub importance: String,
    /// Storage device (host/platform, e.g. fslong-hasee/linux): first-write device. Missing on old data; serde default empty.
    #[serde(default)]
    pub device: String,
    /// Last-modified device: refreshed on update/append/merge (with updated_at). Empty on old data.
    #[serde(default)]
    pub modified_by: String,
}

fn default_importance() -> String {
    "normal".to_owned()
}

fn default_emotion() -> f32 {
    -1.0
}

/// Server/sync form (local-first dumb-store contract).
///
/// Plaintext index fields are `#[serde(skip)]` — stripped on serialize (upload),
/// kept only by LocalStore for local search; the server never sees them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMemory {
    pub id: String,            // uuid v4 (client-generated, no multi-device clash)
    pub user: String,          // plaintext owner (server per-user routing)
    pub ciphertext: String,    // AES-GCM(payload JSON) hex
    pub nonce: String,         // nonce for ciphertext
    pub embedding_enc: String, // AES-GCM(f32 LE bytes) hex; may be empty (old data, no vector)
    pub updated_at: String,    // RFC3339 milliseconds
    pub deleted: bool,         // tombstone

    // ── local plaintext index (serde skip, never uploaded) ──
    #[serde(skip)]
    pub local_kind: String,
    #[serde(skip)]
    pub local_tags: String,
    #[serde(skip)]
    pub local_title: String,
    #[serde(skip)]
    pub local_project: String,
    #[serde(skip)]
    pub local_computer: String,
    #[serde(skip)]
    pub local_embedding: Option<Vec<u8>>,
    #[serde(skip)]
    pub local_parent_id: String,
    #[serde(skip)]
    pub local_created_at: String,
    /// Local plaintext content head (≤500 chars, BM25-style lexical search; serde skip, never uploaded).
    #[serde(skip)]
    pub local_content_head: String,
    /// Local hit count (incremented on recall; recency/heat axis; serde skip, never uploaded).
    #[serde(skip)]
    pub local_recall_count: i64,
    /// Importance (local plaintext index; serde skip — true value lives in the ciphertext payload).
    #[serde(skip)]
    pub local_importance: String,
    /// Storage device (local plaintext index; serde skip — true value lives in the ciphertext payload).
    #[serde(skip)]
    pub local_device: String,
    /// Last-modified device (local plaintext index; serde skip — true value lives in the ciphertext payload).
    #[serde(skip)]
    pub local_modified_by: String,
    /// Opaque local feature payloads; private Core owns their interpretation.
    #[serde(skip)]
    pub local_chunks: Vec<Vec<u8>>,
    /// Local-only opaque Core artifact; never part of the sync wire format.
    #[serde(skip)]
    pub local_artifact: Vec<u8>,
}

impl StoredMemory {
    pub fn new_pending(id: String, user: String) -> Self {
        Self {
            id,
            user,
            ciphertext: String::new(),
            nonce: String::new(),
            embedding_enc: String::new(),
            updated_at: String::new(),
            deleted: false,
            local_kind: String::new(),
            local_tags: String::new(),
            local_title: String::new(),
            local_project: String::new(),
            local_computer: String::new(),
            local_embedding: None,
            local_parent_id: String::new(),
            local_created_at: String::new(),
            local_content_head: String::new(),
            local_recall_count: 0,
            local_importance: "normal".to_owned(),
            local_device: String::new(),
            local_modified_by: String::new(),
            local_chunks: Vec::new(),
            local_artifact: Vec::new(),
        }
    }
}

/// Query (local search; text is lexical prefilter + the engine embeds a semantic vector).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryQuery {
    pub text: String,
    pub kind: Option<Kind>,
    pub limit: usize,
    pub project: Option<String>,
    pub computer: Option<String>,
}

impl MemoryQuery {
    pub fn new(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            kind: None,
            limit: 3,
            project: None,
            computer: None,
        }
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn of_kind(mut self, kind: Kind) -> Self {
        self.kind = Some(kind);
        self
    }

    pub fn of_project(mut self, project: &str) -> Self {
        self.project = Some(project.to_owned());
        self
    }

    pub fn of_computer(mut self, computer: &str) -> Self {
        self.computer = Some(computer.to_owned());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_roundtrip() {
        assert_eq!(Kind::from_str("decision"), Kind::Decision);
        assert_eq!(Kind::from_str("SKILL"), Kind::Skill);
        assert_eq!(Kind::from_str("knowledge"), Kind::Knowledge);
        assert_eq!(Kind::from_str("whatever"), Kind::Context);
        assert_eq!(Kind::Decision.as_str(), "decision");
        assert_eq!(Kind::Knowledge.display_zh(), "知识");
    }

    #[test]
    fn query_builder() {
        let q = MemoryQuery::new("rust").limit(5).of_kind(Kind::Task);
        assert_eq!(q.limit, 5);
        assert_eq!(q.kind, Some(Kind::Task));
    }

    #[test]
    fn stored_serde_drops_local_fields() -> anyhow::Result<()> {
        let mut s = StoredMemory::new_pending("id-1".to_owned(), "u".to_owned());
        s.local_title = "秘密标题".to_owned();
        s.local_embedding = Some(vec![1, 2]);
        let json = serde_json::to_string(&s)?;
        assert!(!json.contains("秘密标题"));
        assert!(!json.contains("local_title"));
        assert!(!json.contains("local_embedding"));
        Ok(())
    }

    #[test]
    fn kind_all_labels() {
        for (k, s) in [
            (Kind::Context, "context"),
            (Kind::Decision, "decision"),
            (Kind::Preference, "preference"),
            (Kind::Task, "task"),
            (Kind::Emotion, "emotion"),
            (Kind::Time, "time"),
            (Kind::Skill, "skill"),
            (Kind::Knowledge, "knowledge"),
        ] {
            assert_eq!(k.as_str(), s);
            assert_eq!(Kind::from_str(s), k);
            assert!(!k.display_zh().is_empty());
        }
    }

    #[test]
    fn payload_v2_defaults() -> anyhow::Result<()> {
        let raw = r#"{"kind":"context","tags":"","title":"t","content":"c","user":"u","computer":"h","project":"p","created_at":"t","updated_at":"t"}"#;
        let p: PayloadV2 = serde_json::from_str(raw)?;
        assert_eq!(p.emotion, -1.0);
        assert_eq!(p.parent_id, "");
        assert_eq!(p.importance, "normal");
        assert_eq!(p.device, "");
        assert_eq!(p.modified_by, "");
        Ok(())
    }
}

/// Final association result; no intermediate vector or ranking details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedMemory {
    pub id: String,
    pub title: String,
    pub source_id: String,
    pub relation: RelationKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind { NewVersion, OldVersion, SeeAlso, CoRecall, Neighbor }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallPair {
    pub a: String,
    pub b: String,
    pub n: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelatedResult {
    pub related: Vec<RelatedMemory>,
    pub superseded: std::collections::BTreeMap<String, String>,
}

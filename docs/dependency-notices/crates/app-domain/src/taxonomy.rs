//! taxonomy — built-in class lexicon (compile-time include, travels with the binary) + auto-classify + trivia diary
//!
//! Classes like an IME lexicon: on store the AI classifies first; a hit hangs under that outline (outline = tree root),
//! only when the lexicon cannot tell do we create a new subtree (root-create, user must agree; the AI must not overstep).
//! Trivia stays out of the tree: trivial is always diary flow (the serialized diary marker plus body); the time-ordered archive is its own chain.

use anyhow::Result;
use chrono::Local;

use crate::memory::engine::MemoryEngine;
use crate::memory::model::{Kind, MemoryEntry};
use crate::memory::search::Embedder;
use crate::memory::SessionKeys;
use crate::transport::local::LocalStore;
use crate::transport::MemoryTransport;

/// One built-in class.
pub struct Category {
    /// Outline name (the root entry title)
    pub title: &'static str,
    /// Domain: human / AI
    pub ai: bool,
    /// One-sentence gist (body when creating the outline; also the classify semantic anchor)
    pub gist: &'static str,
}

/// Built-in lexicon: 20 human-domain + 3 AI-domain.
pub const CATALOG: &[Category] = &[
    Category { title: "\u{5bb6}\u{5ead}\u{4eb2}\u{53cb}", ai: false, gist: "\u{5bb6}\u{4eba}\u{4eb2}\u{621a}\u{670b}\u{53cb}\u{4e4b}\u{4e8b}\u{ff1a}\u{76f8}\u{5904}\u{5f80}\u{6765}\u{3001}\u{5a5a}\u{604b}\u{5bb6}\u{5ead}\u{3001}\u{7ea2}\u{767d}\u{559c}\u{4e8b}\u{3001}\u{91cd}\u{8981}\u{65e5}\u{5b50}\u{3002}" },
    Category { title: "\u{5065}\u{5eb7}\u{533b}\u{7597}", ai: false, gist: "\u{8eab}\u{4f53}\u{5065}\u{5eb7}\u{4e4b}\u{4e8b}\u{ff1a}\u{75c5}\u{75c7}\u{5c31}\u{533b}\u{3001}\u{7528}\u{836f}\u{4f53}\u{68c0}\u{3001}\u{7761}\u{7720}\u{5fc3}\u{7406}\u{3001}\u{5eb7}\u{590d}\u{4fdd}\u{5065}\u{3002}" },
    Category { title: "\u{8d22}\u{52a1}\u{7406}\u{8d22}", ai: false, gist: "\u{94b1}\u{8d22}\u{4e4b}\u{4e8b}\u{ff1a}\u{6536}\u{652f}\u{50a8}\u{84c4}\u{3001}\u{6295}\u{8d44}\u{7406}\u{8d22}\u{3001}\u{501f}\u{8d37}\u{7a0e}\u{52a1}\u{3001}\u{4fdd}\u{9669}\u{8d26}\u{5355}\u{3002}" },
    Category { title: "\u{996e}\u{98df}\u{70f9}\u{996a}", ai: false, gist: "\u{5403}\u{559d}\u{4e4b}\u{4e8b}\u{ff1a}\u{505a}\u{996d}\u{83dc}\u{8c31}\u{3001}\u{5916}\u{5356}\u{9910}\u{5385}\u{3001}\u{53e3}\u{5473}\u{504f}\u{597d}\u{3001}\u{996e}\u{98df}\u{5b89}\u{6392}\u{3002}" },
    Category { title: "\u{4f4f}\u{623f}\u{5bb6}\u{5c45}", ai: false, gist: "\u{5c45}\u{4f4f}\u{4e4b}\u{4e8b}\u{ff1a}\u{79df}\u{623f}\u{4e70}\u{623f}\u{3001}\u{88c5}\u{4fee}\u{6539}\u{9020}\u{3001}\u{5bb6}\u{5177}\u{5bb6}\u{7535}\u{3001}\u{7ef4}\u{4fee}\u{4fdd}\u{6d01}\u{3002}" },
    Category { title: "\u{51fa}\u{884c}\u{4ea4}\u{901a}", ai: false, gist: "\u{51fa}\u{884c}\u{4e4b}\u{4e8b}\u{ff1a}\u{901a}\u{52e4}\u{8def}\u{7ebf}\u{3001}\u{9a7e}\u{8f66}\u{9a91}\u{8f66}\u{3001}\u{7968}\u{52a1}\u{8f66}\u{52a1}\u{3001}\u{4ea4}\u{901a}\u{89c4}\u{5219}\u{3002}" },
    Category { title: "\u{8d2d}\u{7269}\u{6d88}\u{8d39}", ai: false, gist: "\u{8d2d}\u{7269}\u{4e4b}\u{4e8b}\u{ff1a}\u{4e70}\u{4ec0}\u{4e48}\u{3001}\u{6bd4}\u{4ef7}\u{4f18}\u{60e0}\u{3001}\u{5feb}\u{9012}\u{9000}\u{6362}\u{3001}\u{4e8c}\u{624b}\u{8f6c}\u{5356}\u{3002}" },
    Category { title: "\u{804c}\u{4e1a}\u{5de5}\u{4f5c}", ai: false, gist: "\u{804c}\u{4e1a}\u{4e4b}\u{4e8b}\u{ff1a}\u{5c97}\u{4f4d}\u{4e8b}\u{52a1}\u{3001}\u{804c}\u{573a}\u{4eba}\u{9645}\u{3001}\u{6c42}\u{804c}\u{79bb}\u{804c}\u{3001}\u{5de5}\u{4f5c}\u{5b89}\u{6392}\u{3002}" },
    Category { title: "\u{4efb}\u{52a1}\u{8ba1}\u{5212}", ai: false, gist: "\u{4efb}\u{52a1}\u{8ba1}\u{5212}\u{4e4b}\u{4e8b}\u{ff1a}\u{5f85}\u{529e}\u{4efb}\u{52a1}\u{3001}\u{9879}\u{76ee}\u{89c4}\u{5212}\u{3001}\u{5de5}\u{7a0b}\u{62c6}\u{89e3}\u{3001}\u{8fdb}\u{5ea6}\u{8ddf}\u{8fdb}\u{3002}" },
    Category { title: "\u{7f16}\u{7a0b}\u{5f00}\u{53d1}", ai: false, gist: "\u{7f16}\u{7a0b}\u{5f00}\u{53d1}\u{4e4b}\u{4e8b}\u{ff1a}\u{4ee3}\u{7801}\u{9879}\u{76ee}\u{3001}\u{6280}\u{672f}\u{6808}\u{3001}\u{73af}\u{5883}\u{90e8}\u{7f72}\u{3001}\u{5f00}\u{53d1}\u{6d41}\u{7a0b}\u{3002}" },
    Category { title: "\u{5b66}\u{4e60}\u{6210}\u{957f}", ai: false, gist: "\u{6c42}\u{77e5}\u{4e4b}\u{4e8b}\u{ff1a}\u{8bfb}\u{4e66}\u{4e0a}\u{8bfe}\u{3001}\u{8003}\u{8bd5}\u{8003}\u{8bc1}\u{3001}\u{5b66}\u{4e60}\u{65b9}\u{6cd5}\u{3001}\u{6210}\u{957f}\u{8bb0}\u{5f55}\u{3002}" },
    Category { title: "\u{5174}\u{8da3}\u{5a31}\u{4e50}", ai: false, gist: "\u{6d88}\u{9063}\u{4e4b}\u{4e8b}\u{ff1a}\u{5f71}\u{97f3}\u{5a31}\u{4e50}\u{3001}\u{7231}\u{597d}\u{6536}\u{85cf}\u{3001}\u{6587}\u{827a}\u{521b}\u{4f5c}\u{6027}\u{6d88}\u{9063}\u{3002}" },
    Category { title: "\u{7535}\u{5b50}\u{6e38}\u{620f}", ai: false, gist: "\u{6e38}\u{620f}\u{4e4b}\u{4e8b}\u{ff1a}\u{8fdb}\u{5ea6}\u{5b58}\u{6863}\u{3001}\u{7248}\u{672c}\u{653b}\u{7565}\u{3001}\u{5e73}\u{53f0}\u{5916}\u{8bbe}\u{3001}\u{8054}\u{673a}\u{8d5b}\u{4e8b}\u{3002}" },
    Category { title: "\u{8fd0}\u{52a8}\u{5065}\u{8eab}", ai: false, gist: "\u{8fd0}\u{52a8}\u{4e4b}\u{4e8b}\u{ff1a}\u{953b}\u{70bc}\u{5065}\u{8eab}\u{3001}\u{7403}\u{7c7b}\u{8d5b}\u{4e8b}\u{3001}\u{88c5}\u{5907}\u{573a}\u{5730}\u{3001}\u{4f53}\u{80fd}\u{8bb0}\u{5f55}\u{3002}" },
    Category { title: "\u{793e}\u{4ea4}\u{7f51}\u{7edc}", ai: false, gist: "\u{793e}\u{4ea4}\u{4e4b}\u{4e8b}\u{ff1a}\u{7ebf}\u{4e0a}\u{5e73}\u{53f0}\u{8d26}\u{53f7}\u{3001}\u{7fa4}\u{804a}\u{52a8}\u{6001}\u{3001}\u{4eba}\u{60c5}\u{5f80}\u{6765}\u{793c}\u{6570}\u{3002}" },
    Category { title: "\u{65c5}\u{884c}\u{6e38}\u{5386}", ai: false, gist: "\u{65c5}\u{884c}\u{4e4b}\u{4e8b}\u{ff1a}\u{884c}\u{7a0b}\u{653b}\u{7565}\u{3001}\u{666f}\u{70b9}\u{4f4f}\u{5bbf}\u{3001}\u{8bc1}\u{4ef6}\u{7968}\u{52a1}\u{3001}\u{6e38}\u{8bb0}\u{89c1}\u{95fb}\u{3002}" },
    Category { title: "\u{5ba0}\u{7269}\u{690d}\u{7269}", ai: false, gist: "\u{517b}\u{5ba0}\u{79cd}\u{683d}\u{4e4b}\u{4e8b}\u{ff1a}\u{5582}\u{517b}\u{7167}\u{6599}\u{3001}\u{5065}\u{5eb7}\u{9a6f}\u{5bfc}\u{3001}\u{82b1}\u{8349}\u{517b}\u{62a4}\u{3002}" },
    Category { title: "\u{60c5}\u{611f}\u{5fc3}\u{5883}", ai: false, gist: "\u{5fc3}\u{7eea}\u{4e4b}\u{4e8b}\u{ff1a}\u{60c5}\u{7eea}\u{8d77}\u{4f0f}\u{3001}\u{538b}\u{529b}\u{5fc3}\u{7ed3}\u{3001}\u{611f}\u{609f}\u{91ca}\u{6000}\u{3002}" },
    Category { title: "\u{4e60}\u{60ef}\u{517b}\u{6210}", ai: false, gist: "\u{81ea}\u{6211}\u{7ba1}\u{7406}\u{4e4b}\u{4e8b}\u{ff1a}\u{4f5c}\u{606f}\u{4e60}\u{60ef}\u{3001}\u{6212}\u{65ad}\u{575a}\u{6301}\u{3001}\u{8ba1}\u{5212}\u{76ee}\u{6807}\u{3001}\u{590d}\u{76d8}\u{3002}" },
    Category { title: "\u{7075}\u{611f}\u{521b}\u{610f}", ai: false, gist: "\u{521b}\u{9020}\u{4e4b}\u{4e8b}\u{ff1a}\u{70b9}\u{5b50}\u{7075}\u{611f}\u{3001}\u{521b}\u{4f5c}\u{6784}\u{601d}\u{3001}\u{4f5c}\u{54c1}\u{6784}\u{60f3}\u{3002}" },
    Category { title: "\u{6280}\u{80fd}\u{5e93}", ai: true, gist: "\u{7ed9} AI \u{7528}\u{ff1a}\u{53ef}\u{91cd}\u{590d}\u{7684}\u{64cd}\u{4f5c}\u{5e8f}\u{5217}\u{2014}\u{2014}\u{4e0b}\u{6b21}\u{9047}\u{540c}\u{7c7b}\u{4e8b}\u{7167}\u{505a}\u{5373}\u{53ef}\u{7684}\u{6b65}\u{9aa4}\u{3001}\u{547d}\u{4ee4}\u{3001}\u{6d41}\u{7a0b}\u{3002}" },
    Category { title: "\u{7ecf}\u{9a8c}\u{5e93}", ai: true, gist: "\u{7ed9} AI \u{7528}\u{ff1a}\u{603b}\u{7ed3}\u{51fa}\u{7684}\u{89c4}\u{5f8b}\u{505a}\u{6cd5}\u{2014}\u{2014}\u{4ee5}\u{540e}\u{505a}\u{540c}\u{7c7b}\u{4e8b}\u{8be5}\u{53c2}\u{7167}\u{7684}\u{7ecf}\u{9a8c}\u{6c89}\u{6dc0}\u{3002}" },
    Category { title: "\u{8e29}\u{5751}\u{5f55}", ai: true, gist: "\u{7ed9} AI \u{7528}\u{ff1a}\u{8e29}\u{5751}\u{8bb0}\u{5f55}\u{2014}\u{2014}\u{75c7}\u{72b6}\u{3001}\u{539f}\u{56e0}\u{3001}\u{89e3}\u{6cd5}\u{4ff1}\u{5168}\u{ff0c}\u{540c}\u{4e00}\u{5751}\u{4e0d}\u{8e29}\u{7b2c}\u{4e8c}\u{6b21}\u{3002}" },
];

pub fn category(idx: usize) -> &'static Category {
    &CATALOG[idx]
}

pub fn find_by_title(title: &str) -> Option<usize> {
    CATALOG.iter().position(|c| c.title == title)
}

/// Outline entry id (deterministic uuid-v5-like: sha1(domain + name) formatted as 16 bytes).
/// Same outline, same id across devices; re-running the same lexicon does not recreate.
pub fn root_id(title: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    Digest::update(&mut h, b"respire-taxonomy-v1:");
    Digest::update(&mut h, title.as_bytes());
    let d = h.finalize();
    let b: [u8; 16] = d[..16].try_into().unwrap_or([0u8; 16]);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Classify semantic-anchor text (same source as the outline body).
pub fn anchor_text(c: &Category) -> String {
    format!("{}\u{ff1a}{}", c.title, c.gist)
}

/// Outline entry (Kind::Knowledge, importance=important, hangs at root).
fn category_entry(c: &Category) -> MemoryEntry {
    let now = Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    MemoryEntry {
        metadata: Default::default(),
        unknown_fields: Default::default(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: Vec::new(),
        id: root_id(c.title),
        kind: Kind::Knowledge,
        tags: vec!["\u{8bcd}\u{5e93}\u{7eb2}".to_owned(), if c.ai { "AI\u{57df}" } else { "\u{4eba}\u{57df}" }.to_owned()],
        title: c.title.to_owned(),
        content: anchor_text(c),
        user: crate::service::current_user(),
        computer: String::new(),
        device: crate::service::device_tag(),
        modified_by: crate::service::device_tag(),
        project: String::new(),
        created_at: now.clone(),
        updated_at: now,
        emotion: -1.0,
        parent_id: String::new(),
        importance: "important".to_owned(),
    }
}

/// Create outline (idempotent): exists → take it; missing → store. Returns root id. Does not auto-sync (caller auto_sync).
pub fn ensure_category_root<E: Embedder>(
    session: &SessionKeys,
    embedder: &E,
    store: &LocalStore,
    idx: usize,
) -> Result<String> {
    let c = category(idx);
    let rid = root_id(c.title);
    if store.all(false)?.iter().any(|m| m.id == rid && !m.deleted) {
        return Ok(rid);
    }
    let stored = MemoryEngine::seal(session, embedder, &category_entry(c), &category_entry(c).user)?;
    store.put(&stored)?;
    Ok(rid)
}

/// Lexical classify: lowercase body (including title) and count keyword hits.


/// Auto-classify: lexical hits (if tied, take the class with more keyword hits) → compare to the semantic anchor.
/// Returns (class index, anchor similarity). Lexical and semantic both use the hit class; semantic only rejects a false attach.
/// Decision: lexical hits ≥1 and anchor sim ≥0.42 → hit; no lexical hits → None (do not guess).
pub fn classify<E: Embedder>(
    embedder: &E,
    text: &str,
) -> Result<Option<(usize, f32)>> {
    respire_core_sdk::execute("taxonomy_classify", serde_json::json!({"model":embedder.model_name(), "text":text}))
}

/// Build a diary body from the serialized marker, date/time and original content.
pub fn diary_content(content: &str) -> String {
    format!("\u{3010}\u{65e5}\u{8bb0}\u{3011}{} {}", Local::now().format("%Y-%m-%d %H:%M"), content)
}

/// Orphan root: a live root with no parent and no children (the object of create-outline ask).
pub fn lone_roots(store: &LocalStore) -> Result<Vec<(String, String)>> {
    let all = store.all(false)?;
    let mut out = Vec::new();
    for m in &all {
        if !m.local_parent_id.is_empty() {
            continue;
        }
        let has_child = all.iter().any(|x| x.local_parent_id == m.id);
        if !has_child {
            out.push((m.id.clone(), if m.local_title.is_empty() { m.local_content_head.chars().take(24).collect() } else { m.local_title.clone() }));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_id_is_deterministic_uuid_like() {
        let a = root_id("\u{5bb6}\u{5ead}\u{4eb2}\u{53cb}");
        let b = root_id("\u{5bb6}\u{5ead}\u{4eb2}\u{53cb}");
        assert_eq!(a, b);
        assert_eq!(a.len(), 36);
        assert_ne!(a, root_id("\u{6280}\u{80fd}\u{5e93}"));
    }

    #[test]
    fn catalog_has_23_and_no_dup_titles() {
        assert_eq!(CATALOG.len(), 23);
        let mut titles: Vec<_> = CATALOG.iter().map(|c| c.title).collect();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(titles.len(), CATALOG.len(), "duplicate catalog titles");
        assert_eq!(CATALOG.iter().filter(|c| c.ai).count(), 3, "AI domain must have 3 classes");
    }


    #[test]
    fn diary_content_stamps_body() {
        let s = diary_content("hello trail");
        assert!(s.starts_with("\u{3010}\u{65e5}\u{8bb0}\u{3011}"));
        assert!(s.contains("hello trail"));
    }
    #[test]
    fn lone_roots_skips_parents() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        let mut root = crate::memory::model::StoredMemory::new_pending(
            "11111111-1111-4111-8111-111111111111".into(),
            "u".into(),
        );
        root.local_title = "root".into();
        let mut child = crate::memory::model::StoredMemory::new_pending(
            "22222222-2222-4222-8222-222222222222".into(),
            "u".into(),
        );
        child.local_parent_id = root.id.clone();
        child.local_title = "child".into();
        let mut lone = crate::memory::model::StoredMemory::new_pending(
            "33333333-3333-4333-8333-333333333333".into(),
            "u".into(),
        );
        lone.local_title = "orphan".into();
        MemoryTransport::put(&store, &root)?;
        MemoryTransport::put(&store, &child)?;
        MemoryTransport::put(&store, &lone)?;
        let roots = lone_roots(&store)?;
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].0, lone.id);
        Ok(())
    }
}

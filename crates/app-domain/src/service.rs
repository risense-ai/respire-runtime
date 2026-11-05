//! service — business layer (single source of truth for the CLI and the local client)
//!
//! Assembles session/store/embedder and owns CRUD, the causal tree, candidate-before-store, sync, accounts, and tools.
//! The CLI owns printing and interactive flow; the client (Tauri) calls this layer directly. Embedder is BGE everywhere, no fallback.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::memory::bge::BgeEmbedder;
use crate::memory::engine::MemoryEngine;
use crate::memory::model::{Kind, MemoryEntry, MemoryQuery};
use crate::memory::search::Embedder;
use crate::memory::SessionKeys;
use crate::sync::{remote_configured, sync_all};
use crate::transport::local::LocalStore;
use crate::transport::MemoryTransport;

mod merge;
pub use merge::{merge_entries, merge_entries_with_metadata, merge_entries_with_metadata_revision};

/// Shared candidate receipt contract for agent and client consumers.
pub fn write_decision_actions() -> &'static [&'static str] {
    &[
        "\u{2460} duplicate (bool): do both texts state the same fact with no new detail? If so, merge with merge-ids; inspect descendants and back up first.",
        "\u{2461} contradiction (bool): are they mutually exclusive at the same point in time? If so, merge, keep the newer text and record why the old one was dropped.",
        "\u{2462} obsolete (bool): does the new text clearly supersede the old one? If so, update the old entry, append a note on the supersession and do not delete it.",
        "\u{2463} linkable (bool): would linking them help later recall? If so, attach the cause with --parent.",
        "\u{2464} representation (keep_separate|merge|promote|uncertain): keep them apart, merge, promote or defer? Keep separate / write one synthesized entry / promote a repeated event into a principle / defer while uncertain.",
        "Choose update > merge > parent > create, or explicitly defer. Candidate/pending is not saved; verify returned IDs/content. For unknown outcomes inspect receipts read-only before any replay.",
    ]
}
mod related;
pub use related::{store_related, remap_relations};

static RUNTIME_PROFILE: OnceLock<PathBuf> = OnceLock::new();

/// A runtime keeps ownership of its boot library until host-managed restart.
pub fn install_runtime_profile(profile: PathBuf) {
    let _ = RUNTIME_PROFILE.set(profile);
}
pub fn require_profile_change_host() -> Result<()> {
    if RUNTIME_PROFILE.get().is_some() {
        anyhow::bail!("runtime owns its boot profile; stop it on the host with `rsrs --runtime-internal --stop`, run the profile command with `rsrs --direct`, then restart `rsrs --runtime-internal`");
    }
    Ok(())
}
pub fn check_runtime_user(user: &str) -> Result<()> {
    if RUNTIME_PROFILE.get().is_some() {
        if let Ok(session) = auth::read_session_json() {
            let current = session["user"].as_str().unwrap_or("");
            if !current.is_empty() && current != user {
                require_profile_change_host()?;
            }
        }
    }
    Ok(())
}

pub fn ensure_runtime_profile() -> Result<()> {
    check_runtime_profile(&data_dir())
}

fn check_runtime_profile(path: &Path) -> Result<()> {
    if let Some(owned) = RUNTIME_PROFILE.get() {
        if path != owned {
            require_profile_change_host()?;
        }
    }
    Ok(())
}

static AUTO_SYNC_NOTIFY: OnceLock<fn()> = OnceLock::new();
static INDEX_NOTIFY: OnceLock<fn()> = OnceLock::new();

pub fn install_index_notifier(notify: fn()) {
    let _ = INDEX_NOTIFY.set(notify);
}

/// Missing artifacts are durable work; the runtime notification only wakes its worker.
pub fn notify_index() {
    if let Some(notify) = INDEX_NOTIFY.get() {
        notify();
    }
}

#[derive(Debug)]
pub struct IndexPending;

impl std::fmt::Display for IndexPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("local retrieval index is being prepared; retry after indexing completes")
    }
}

impl std::error::Error for IndexPending {}

/// Validate the actual snapshot sent to Core, including its opaque index artifacts.
pub fn require_candidates_ready(store: &LocalStore, candidates: &[crate::StoredMemory]) -> Result<()> {
    if !store.candidates_index_ready(candidates)? {
        notify_index();
        return Err(IndexPending.into());
    }
    Ok(())
}

/// Recall stays available while synchronized sources await background indexing.
/// Only current, source-checked artifacts may participate in semantic retrieval.
pub fn recall_candidates(store: &LocalStore) -> Result<(Vec<crate::StoredMemory>, usize)> {
    let candidates = store.all(false)?;
    let (ready, pending): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|memory| !memory.local_artifact.is_empty());
    let pending_count = pending.len();
    if pending_count > 0 {
        notify_index();
        if ready.is_empty() {
            return Err(IndexPending.into());
        }
    }
    require_candidates_ready(store, &ready)?;
    Ok((ready, pending_count))
}

/// The resident runtime installs its single durable-outbox worker notifier.
pub fn install_autosync_notifier(notify: fn()) {
    let _ = AUTO_SYNC_NOTIFY.set(notify);
}
pub fn notify_autosync() {
    if autosync_active() && remote_configured() {
        if let Some(notify) = AUTO_SYNC_NOTIFY.get() {
            notify();
        }
    }
}

/// Unlocked session + local authoritative store + embedder, as one unit.
/// Production `open()` always loads BGE (no hashing fallback). Tests inject `HashingEmbedder`.
pub struct App {
    pub keys: crate::memory::SessionKeys,
    pub store: LocalStore,
    pub embedder: Box<dyn Embedder>,
}

impl App {
    /// Unlock the local session → open the store → load BGE. Missing model is an error (no fallback).
    pub fn open() -> Result<Self> {
        let keys = auth::load_local_session()
            .map_err(|e| anyhow!("session not unlocked ({e}) \u{2014} register/login or keygen first"))?;
        let store = open_store()?;
        let embedder = BgeEmbedder::load_model(&store.retrieval_model()?)?;
        notify_index();
        Ok(Self {
            keys,
            store,
            embedder: Box::new(embedder),
        })
    }

    // ── read ──

    pub fn status(&self) -> Result<StatusInfo> {
        let blobs = self.store.all(true)?;
        Ok(StatusInfo {
            local_total: blobs.len(),
            local_alive: blobs.iter().filter(|m| !m.deleted).count(),
            remote_configured: remote_configured(),
            max_updated_at: self.store.max_updated_at().ok().flatten(),
            data_dir: data_dir().to_string_lossy().into_owned(),
        })
    }

    /// List using Core's combined-score order; CLI list uses metadata ordering.
    pub fn list(&self, limit: usize) -> Result<Vec<MemoryEntry>> {
        let candidates = self.store.all(false)?;
        require_candidates_ready(&self.store, &candidates)?;
        let q = MemoryQuery::default().limit(limit);
        MemoryEngine::recall_local(&self.keys, &self.embedder, &candidates, &q)
    }

    /// Semantic search (with score; a hit bumps heat, same as CLI recall).
    pub fn search(
        &self,
        query: &str,
        limit: usize,
        kind: Option<Kind>,
    ) -> Result<Vec<ScoredEntry>> {
        let mut q = MemoryQuery::new(query).limit(limit);
        if let Some(k) = kind {
            q = q.of_kind(k);
        }
        let (candidates, _) = recall_candidates(&self.store)?;
        let ranked:Vec<(f32,MemoryEntry)>=crate::core_sdk::execute("query",serde_json::json!({
            "model":self.embedder.model_name(),"snapshots":crate::memory::engine::snapshots(&self.keys,&candidates)?,
            "query":q,"mode":"scored","query_settings":crate::feedback::query_settings(&self.store,&q,&candidates)?
        }))?;
        for (score, e) in &ranked {
            if !readonly_mode() && !off_mode() { let _ = self.store.bump_recall_count(&e.id); }
            let _ = score;
        }
        Ok(ranked
            .into_iter()
            .map(|(score, entry)| ScoredEntry { score, entry })
            .collect())
    }

    /// One entry full text + ancestor chain + descendant probe (8-char prefix ok).
    pub fn show(&self, id_prefix: &str) -> Result<EntryDetail> {
        let entry = self.resolve_entry(id_prefix)?;
        let ancestors: Vec<NodeRef> = self
            .store
            .ancestor_chain(&entry.id)?
            .into_iter()
            .filter_map(|pid| {
                self.stored_title(&pid)
                    .map(|title| NodeRef { id: pid, title })
            })
            .collect();
        let children: Vec<ChildRef> = self
            .store
            .children(&entry.id)?
            .iter()
            .map(|c| ChildRef {
                id: c.id.clone(),
                title: if c.local_title.is_empty() {
                    short_id(&c.id)
                } else {
                    c.local_title.clone()
                },
                summary: c
                    .local_content_head
                    .chars()
                    .take(80)
                    .collect::<String>()
                    .replace('\n', " "),
            })
            .collect();
        Ok(EntryDetail {
            entry,
            ancestors,
            children,
        })
    }

    /// Causal tree (structured for UI). Empty `from` → root forest; depth 0 = roots only.
    ///
    /// **Trivial stays out of the tree** (fixed 2026-09-20): inject §3.4 says trivia goes to the diary only,
    /// not the tree. This fn used to leave trivial in — 115 diary rows (including daily "activity trail"
    /// entries whose parent is empty) became stray roots. Now dropped the same way as `tree_cure_with_min`/`defrag`.
    /// Orphans whose parent was dropped become roots; important subtrees are unchanged.
    /// Explicit `--from <trivial-id>` still renders that one entry (a direct lookup, not blocked).
    pub fn tree(&self, from: &str, depth: usize) -> Result<Vec<TreeNode>> {
        let raw = self.store.all(true)?;
        // Tree-view scope: drop trivia, promote orphans (see tree_scope_list)
        let all = tree_scope_list(&raw);
        let children_of: HashMap<String, Vec<String>> = {
            let mut m: HashMap<String, Vec<String>> = HashMap::new();
            for s in &all {
                if !s.local_parent_id.is_empty() {
                    m.entry(s.local_parent_id.clone())
                        .or_default()
                        .push(s.id.clone());
                }
            }
            m
        };
        let title_of = |id: &str| -> String {
            all.iter()
                .find(|s| s.id == id)
                .map(|s| {
                    if s.local_title.is_empty() {
                        short_id(id)
                    } else {
                        s.local_title.clone()
                    }
                })
                .unwrap_or_else(|| short_id(id))
        };
        let kind_of = |id: &str| -> String {
            all.iter()
                .find(|s| s.id == id)
                .map(|s| s.local_kind.clone())
                .unwrap_or_default()
        };
        let build = |id: &str, depth: usize| -> TreeNode {
            Self::build_node(id, depth, &children_of, &title_of, &kind_of)
        };
        if from.is_empty() {
            let mut roots: Vec<String> = all
                .iter()
                .filter(|m| m.local_parent_id.is_empty())
                .map(|m| m.id.clone())
                .collect();
            // Roots by updated_at desc (newer outlines first, UI reading order)
            roots.sort_by(|a, b| {
                let ta = all
                    .iter()
                    .find(|s| s.id == *a)
                    .map(|s| s.updated_at.clone())
                    .unwrap_or_default();
                let tb = all
                    .iter()
                    .find(|s| s.id == *b)
                    .map(|s| s.updated_at.clone())
                    .unwrap_or_default();
                tb.cmp(&ta)
            });
            Ok(roots
                .iter()
                .map(|r| build(r, depth.saturating_sub(1)))
                .collect())
        } else {
            let full = self.resolve_id(from)?;
            Ok(vec![build(&full, depth)])
        }
    }

    fn build_node(
        id: &str,
        depth: usize,
        children_of: &HashMap<String, Vec<String>>,
        title_of: &dyn Fn(&str) -> String,
        kind_of: &dyn Fn(&str) -> String,
    ) -> TreeNode {
        let kids = children_of.get(id).cloned().unwrap_or_default();
        let children = if depth == 0 {
            Vec::new()
        } else {
            kids.iter()
                .map(|k| Self::build_node(k, depth - 1, children_of, title_of, kind_of))
                .collect()
        };
        let mut descendants = kids.len();
        let mut frontier: Vec<String> = kids.clone();
        while let Some(cur) = frontier.pop() {
            if let Some(grand) = children_of.get(&cur) {
                descendants += grand.len();
                frontier.extend(grand.iter().cloned());
            }
        }
        TreeNode {
            id: id.to_owned(),
            title: title_of(id),
            kind: kind_of(id),
            is_leaf: kids.is_empty(),
            descendants,
            children,
        }
    }

    // ── store (judge first, then pick one of three) ──

    /// Store candidates: recall-similar bill before write (does not write).
    /// Ask the private Core for candidate actions; persistence stays in the application.
    pub fn candidates(&self, content: &str) -> Result<CandidateReport> {
        let all = self.store.all(false)?;
        require_candidates_ready(&self.store, &all)?;
        candidate_report(&self.keys, &self.embedder, &all, content)
    }

    /// Store a memory (after picking one of three): force write / parent as cause / merge_ids merge (delete old, store new, rehang children, inherit first item's parent).
    pub fn create(&self, req: &CreateReq) -> Result<MemoryEntry> {
        ensure!(req.metadata.verification.is_none(), "verification is only accepted by review commit");
        anyhow::ensure!(req.merge_ids.is_none() || (req.supersedes.is_none() && req.see_also.is_empty()), "merge and associations are mutually exclusive");
        let stamp = now_stamp();
        let title = if req.title.trim().is_empty() {
            derive_title(&req.content)
        } else {
            req.title.clone()
        };
        let id = uuid::Uuid::new_v4().to_string();
        let mut final_parent = req.parent.clone().unwrap_or_default();
        if req.merge_ids.is_none() && !final_parent.is_empty() {
            // Prefix resolve (full id first); if it fails, really empty = own root (same as CLI)
            let all = self.store.all(true)?;
            final_parent = resolve_prefix(&all, &final_parent).unwrap_or_default();
        }
        let mut entry = MemoryEntry {
            metadata: req.metadata.clone(),
            unknown_fields: Default::default(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            id,
            kind: if req.kind.trim().is_empty() { Kind::Context } else {
                Kind::try_from_str(&req.kind.trim().to_lowercase()).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?
            },
            tags: split_tags(&req.tags),
            title,
            content: req.content.clone(),
            user: current_user(),
            computer: req.computer.clone(),
            device: device_tag(),
            modified_by: device_tag(),
            project: req.project.clone(),
            created_at: stamp.clone(),
            updated_at: stamp,
            emotion: req.emotion.unwrap_or(-1.0),
            parent_id: {
                // Empty parent means own root (after 2026-09-21 there is no default attach point)
                final_parent
            },
            importance: req
                .importance
                .clone()
                .unwrap_or_else(|| "trivial".to_owned()),
        };
        if req.merge_ids.is_none() {
            crate::metadata_gate::ensure_write(&self.store, &entry)?;
            crate::metadata_gate::ensure_sources(&self.keys, &self.store, &entry)?;
        }
        if let Some(ids) = &req.merge_ids {
            merge_entries_with_metadata(
                &self.keys,
                &self.store,
                &self.embedder,
                &mut entry,
                ids,
                req.parent.as_deref().unwrap_or_default(),
                false,
                req.merge_metadata.as_ref(),
            )?;
        } else if req.supersedes.is_some() || !req.see_also.is_empty() {
            store_related(&self.keys,&self.store,&self.embedder,&mut entry,req.supersedes.as_deref(),&req.see_also)?;
        } else {
            let stored = MemoryEngine::seal(&self.keys, &self.embedder, &entry, &entry.user)?;
            self.store.put(&stored)?;
        }
        self.auto_sync();
        Ok(entry)
    }

    /// Update an entry (any of title/body/tags/kind → decrypt, reseal, re-embed, LWW new stamp).
    pub fn update(
        &self,
        id: &str,
        title: Option<String>,
        content: Option<String>,
        tags: Option<String>,
        kind: Option<String>,
    ) -> Result<MemoryEntry> {
        self.update_with_metadata(id, title, content, tags, kind, None)
    }

    pub fn update_with_metadata(
        &self, id: &str, title: Option<String>, content: Option<String>,
        tags: Option<String>, kind: Option<String>, metadata: Option<&MetadataPatch>,
    ) -> Result<MemoryEntry> {
        let all = self.store.all(true)?;
        let full = resolve_prefix(&all, id)?;
        let stored = all
            .iter()
            .find(|m| m.id == full && !m.deleted)
            .ok_or_else(|| anyhow!("not found #{id}"))?;
        let mut entry = MemoryEngine::open(&self.keys, stored)?;
        if let Some(t) = title {
            entry.title = t;
        }
        if let Some(c) = content {
            entry.content = c;
        }
        if let Some(tg) = tags {
            entry.tags = split_tags(&tg);
        }
        if let Some(k) = kind {
            entry.kind = Kind::try_from_str(&k.trim().to_lowercase()).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?;
        }
        if let Some(patch) = metadata { patch.apply(&mut entry.metadata); }
        crate::metadata_gate::ensure_write(&self.store, &entry)?;
        crate::metadata_gate::ensure_sources(&self.keys, &self.store, &entry)?;
        entry.updated_at = self.store.edit_stamp(&stored.id)?;
        let user = entry.user.clone();
        let new_stored = MemoryEngine::seal(&self.keys, &self.embedder, &entry, &user)?;
        self.store.put(&new_stored)?;
        self.auto_sync();
        Ok(entry)
    }

    /// Delete (tombstone, propagates with sync). Full id or 8-char prefix.
    pub fn delete(&self, id: &str) -> Result<bool> {
        let all = self.store.all(true)?;
        let full = resolve_prefix(&all, id)?;
        let deleted = self.store.forget(&full)?;
        if deleted {
            self.auto_sync();
        }
        Ok(deleted)
    }

    /// Restore a tombstone: keep identity and content, republish with a new LWW stamp.
    pub fn restore(&self, id: &str) -> Result<MemoryEntry> {
        let all = self.store.all(true)?;
        let stored = all
            .iter()
            .find(|m| m.id == id)
            .ok_or_else(|| crate::input_error::InputError(format!("not found #{id}")))?;
        let mut entry = MemoryEngine::open(&self.keys, stored)?;
        if !stored.deleted {
            return Ok(entry);
        }
        entry.updated_at = self.store.edit_stamp(&stored.id)?;
        crate::metadata_gate::ensure_write(&self.store, &entry)?;
        crate::metadata_gate::ensure_sources(&self.keys, &self.store, &entry)?;
        let restored = MemoryEngine::seal(&self.keys, &self.embedder, &entry, &entry.user)?;
        self.store.put(&restored)?;
        self.auto_sync();
        Ok(entry)
    }

    // ── causal tree ops ──

    /// Attach (shared by attach/demote): prefix resolve + cycle guard + no self-parent.
    pub fn attach(&self, id: &str, parent: &str) -> Result<(String, String)> {
        let all = self.store.all(true)?;
        let child = resolve_prefix(&all, id)?;
        let parent_full = resolve_prefix(&all, parent)?;
        if child == parent_full {
            return Err(crate::input_error::InputError("cannot attach to self".into()).into());
        }
        for anc in self.store.ancestor_chain(&parent_full)? {
            if anc == child {
                return Err(crate::input_error::InputError("cycle: new parent is a descendant of this entry".into()).into());
            }
        }
        reparent(&self.keys, &self.store, &child, &parent_full)?;
        self.auto_sync();
        Ok((child, parent_full))
    }

    /// Promote: this entry becomes its grandparent/root (children move with it).
    pub fn promote(&self, id: &str) -> Result<(String, String)> {
        let all = self.store.all(true)?;
        let full = resolve_prefix(&all, id)?;
        let me = all
            .iter()
            .find(|m| m.id == full)
            .ok_or_else(|| anyhow!("not found #{id}"))?;
        if me.deleted || me.local_parent_id.is_empty() {
            anyhow::bail!("already a root (no parent) or deleted \u{2014} nothing to promote");
        }
        let parent_id = me.local_parent_id.clone();
        let grandparent = all
            .iter()
            .find(|m| m.id == parent_id)
            .and_then(|p| {
                if p.local_parent_id.is_empty() {
                    None
                } else {
                    Some(p.local_parent_id.clone())
                }
            })
            .unwrap_or_default();
        reparent(&self.keys, &self.store, &full, &grandparent)?;
        self.auto_sync();
        Ok((full, grandparent))
    }

    // ── sync ──

    /// Manual two-way sync.
    pub fn sync(&self) -> Result<SyncOutcome> {
        let remote = crate::sync::build_remote_from_env()?;
        let stats = sync_all(&self.keys, &self.store, &remote)?;
        let blobs = self.store.all(true)?;
        let local_total = blobs.len();
        let local_alive = blobs.iter().filter(|m| !m.deleted).count();
        Ok(SyncOutcome {
            pulled: stats.pulled,
            pushed: stats.pushed,
            remote_total: stats.remote_total,
            remote_alive: stats.remote_alive,
            local_total,
            local_alive,
            converged: local_alive == stats.remote_alive && local_total == stats.remote_total,
        })
    }

    /// Notify the owning runtime after a local commit; never wait for networking.
    pub fn auto_sync(&self) {
        notify_autosync();
    }

    // ── internals ──

    fn stored_title(&self, id: &str) -> Option<String> {
        self.store
            .all(true)
            .ok()?
            .iter()
            .find(|m| m.id == id)
            .map(|m| {
                if m.local_title.is_empty() {
                    short_id(&m.id)
                } else {
                    m.local_title.clone()
                }
            })
    }

    fn resolve_id(&self, prefix: &str) -> Result<String> {
        let all = self.store.all(true)?;
        resolve_prefix(&all, prefix)
    }

    fn resolve_entry(&self, prefix: &str) -> Result<MemoryEntry> {
        let all = self.store.all(false)?;
        let full = resolve_prefix(&all, prefix)?;
        let stored = all
            .iter()
            .find(|m| m.id == full)
            .ok_or_else(|| anyhow!("not found #{prefix}"))?;
        MemoryEngine::open(&self.keys, stored)
    }
}

// ── data shapes (CLI print and client serde share these) ──

#[derive(Debug, Serialize)]
pub struct StatusInfo {
    pub local_total: usize,
    pub local_alive: usize,
    pub remote_configured: bool,
    pub max_updated_at: Option<String>,
    pub data_dir: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ScoredEntry {
    pub score: f32,
    pub entry: MemoryEntry,
}

#[derive(Debug, Serialize)]
pub struct EntryDetail {
    pub entry: MemoryEntry,
    pub ancestors: Vec<NodeRef>,
    pub children: Vec<ChildRef>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct NodeRef {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Serialize)]
pub struct ChildRef {
    pub id: String,
    pub title: String,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct TreeNode {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub is_leaf: bool,
    /// Full descendant count (not truncated by depth — badge shows true size)
    pub descendants: usize,
    pub children: Vec<TreeNode>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct CandidateReport {
    pub merge: Vec<ScoredEntry>,
    pub parent: Vec<ScoredEntry>,
}

/// Outer None preserves a field; Some(None) explicitly clears it.
#[derive(Debug, Clone, Default)]
pub struct MetadataPatch {
    pub summary: Option<Option<String>>,
    pub source_refs: Option<Vec<crate::memory::model::SourceRef>>,
    pub valid_until: Option<Option<String>>,
    pub review_at: Option<Option<String>>,
    pub artifact: Option<Option<crate::memory::model::Artifact>>,
}

impl MetadataPatch {
    pub fn apply(&self, metadata: &mut crate::memory::model::MemoryMeta) {
        metadata.memory_contract = 1;
        if let Some(value) = &self.summary { metadata.summary = value.clone(); }
        if let Some(value) = &self.source_refs { metadata.source_refs = value.clone(); }
        if let Some(value) = &self.valid_until { metadata.valid_until = value.clone(); }
        if let Some(value) = &self.review_at { metadata.review_at = value.clone(); }
        if let Some(value) = &self.artifact { metadata.artifact = value.clone(); }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CreateReq {
    pub metadata: crate::memory::model::MemoryMeta,
    pub content: String,
    pub title: String,
    pub tags: String,
    pub kind: String,
    pub project: String,
    pub computer: String,
    pub emotion: Option<f32>,
    pub parent: Option<String>,
    pub merge_ids: Option<Vec<String>>,
    pub merge_metadata: Option<MetadataPatch>,
    pub supersedes: Option<String>,
    pub see_also: Vec<String>,
    pub force: bool,
    /// importance (two-tier): important (main library) | trivial (diary); default trivial (normal retired)
    pub importance: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SyncOutcome {
    pub pulled: usize,
    pub pushed: usize,
    pub remote_total: usize,
    pub remote_alive: usize,
    pub local_total: usize,
    pub local_alive: usize,
    pub converged: bool,
}

/// Store-candidate report shared by App and CLI, produced by the private Core.
pub fn candidate_report<E: crate::memory::search::Embedder>(
    keys: &crate::memory::SessionKeys,
    embedder: &E,
    all: &[crate::memory::model::StoredMemory],
    content: &str,
) -> Result<CandidateReport> {
    respire_core_sdk::execute(
        "candidate_report",
        serde_json::json!({
            "model":embedder.model_name(), "snapshots":respire_crypto::engine::snapshots(keys, all)?, "content":content,
        }),
    )
}

/// Attach (change parent) — reseal ciphertext: payload.parent_id and the plaintext column change together so the two sources cannot drift.
/// (Hit 2026-09-08: changing only the plaintext column left list/recall reading the old parent from payload; client tree broke, other devices too.)
pub fn reparent(
    keys: &SessionKeys,
    store: &LocalStore,
    id_prefix: &str,
    new_parent: &str,
) -> Result<(String, String)> {
    let all = store.all(true)?;
    let id = resolve_prefix(&all, id_prefix)?;
    let Some(stored) = all.iter().find(|m| m.id == id && !m.deleted) else {
        anyhow::bail!("no such entry: {id_prefix}");
    };
    if id == new_parent {
        anyhow::bail!("cannot attach to self");
    }
    for anc in store.ancestor_chain(new_parent)? {
        if anc == id {
            anyhow::bail!("cycle: new parent is a descendant of this entry");
        }
    }
    crate::metadata_gate::ensure_write(store, &MemoryEngine::open(keys, stored)?)?;
    let stamp = store.edit_stamp(&stored.id)?;
    let out = MemoryEngine::reseal_parent(keys, stored, new_parent, &stamp)?;
    store.put(&out)?;
    Ok((id, new_parent.to_owned()))
}

// ── accounts (no App state; session-level) ──

/// Local session overview (recovery key is masked; full text needs an explicit reveal).
pub fn session_info() -> SessionInfo {
    match auth::read_session_json() {
        Ok(d) => {
            // From v4, session.json no longer stores plaintext keys (super/secret_key/pass all removed),
            // the only test for "local key material exists" is whether wrapped_urk is present —
            // the old impl looked at secret_key/secret, which is always false on v4, so offline local mode was judged "not connected"
            // and kept prompting login (reported 2026-09-16).
            let has_wrap = d["wrapped_urk"].as_str().is_some_and(|s| !s.is_empty());
            let legacy = d["secret_key"].as_str().is_some_and(|s| !s.is_empty())
                || d["secret"].as_str().is_some_and(|s| !s.is_empty());
            let secret = d["secret_key"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| d["secret"].as_str())
                .unwrap_or("");
            SessionInfo {
                has_session: true,
                user: d["user"].as_str().unwrap_or("").to_owned(),
                addr: d["addr"].as_str().unwrap_or("").to_owned(),
                has_token: d["token"].as_str().is_some_and(|t| !t.is_empty()),
                secret_masked: mask_secret(secret),
                has_local_keys: has_wrap || legacy,
            }
        }
        Err(_) => SessionInfo {
            has_session: false,
            user: String::new(),
            addr: String::new(),
            has_token: false,
            secret_masked: String::new(),
            has_local_keys: false,
        },
    }
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub has_session: bool,
    pub user: String,
    pub addr: String,
    pub has_token: bool,
    pub secret_masked: String,
    pub has_local_keys: bool,
}

/// Full recovery key (local only; UI must confirm twice).
pub fn session_secret_full() -> Result<String> {
    let d = auth::read_session_json()?;
    Ok(d["secret_key"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| d["secret"].as_str())
        .unwrap_or("")
        .to_owned())
}

/// New-device five-piece kit (manual handoff across devices; local only).
pub fn session_five_keys() -> Result<serde_json::Value> {
    let d = auth::read_session_json()?;
    Ok(serde_json::json!({
        "pass": d["pass"],
        "super": d["super"],
        "secret": d["secret"],
        "secret_key": d["secret_key"],
        "kdf_salt": d["kdf_salt"],
        "wrapped_urk": d["wrapped_urk"],
        "urk_nonce": d["urk_nonce"],
        "vault_version": d["vault_version"],
    }))
}

pub fn register(addr: &str, user: &str, pass: &str, super_pass: &str) -> Result<Option<String>> {
    validate_client_config()?;
    auth::register(addr, user, pass, super_pass)
}

pub fn login(
    addr: &str,
    user: &str,
    pass: &str,
    super_pass: Option<&str>,
    secret_key: Option<&str>,
    reset_vault: bool,
) -> Result<Option<String>> {
    validate_client_config()?;
    auth::login(addr, user, pass, super_pass, secret_key, reset_vault)
}

pub fn keygen() -> Result<(PathBuf, String)> {
    validate_client_config()?;
    auth::keygen()
}

/// Default server address (client can change it; stored in ~/.rsrs/client.json, separate from session.json auth).
pub const DEFAULT_SERVER_ADDR: &str = "https://api.rsrs.rs";

/// Expand `~` (`~/` and Windows `~\` both count) — **the only impl**; do not rewrite elsewhere.
///
/// Why (2026-09-20 audit): this fn used to have three independent impls (two here + web.rs),
/// and they disagreed — inject.rs accepted `~\`, service.rs three sites only `~/`, so on Windows
/// `~\...` paths did not expand. Now collected here; every caller uses this.
pub fn expand_tilde(v: &str) -> PathBuf {
    if let Some(rest) = v.strip_prefix("~/").or_else(|| v.strip_prefix("~\\")) {
        if let Ok(h) = home_dir() {
            return h.join(rest);
        }
    }
    PathBuf::from(v)
}

/// Resolve `RSRS_DATA_DIR` to an absolute path (None if unset or empty).
/// Semantics: the env var names the profile root — the `main` profile is that root, space profiles live under its `accounts/`,
/// and client.json lives there too (an isolated instance must not write config into the real user dir).
pub fn env_root_dir() -> Option<PathBuf> {
    let v = crate::env::var("RSRS_DATA_DIR").ok()?;
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if internally_configured_root(v) {
        return None;
    }
    Some(expand_tilde(v))
}

// Sunk from the client-side migration module (WP-2c): engine flows must classify the
// internally configured default home, and the domain crate cannot reach back into the
// client crate. The client migration module re-imports this function.
const DEFAULT_ENV: &str = "RSRS_DEFAULT_DATA_DIR";

/// The SDK accepts the original data-root environment variable. This marker lets
/// app configuration retain its default-home and active-profile semantics.
pub fn internally_configured_root(value: &str) -> bool {
    crate::env::var(DEFAULT_ENV).ok().is_some_and(|marker| {
        equivalent_path(
            &crate::service::expand_tilde(&marker),
            &crate::service::expand_tilde(value),
        ) && equivalent_path(
            &crate::service::expand_tilde(value),
            &crate::service::default_data_dir(),
        )
    })
}

fn equivalent_path(left: &Path, right: &Path) -> bool {
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|root| root.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    };
    let normalize = |path: PathBuf| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        normalized
    };
    let left = normalize(absolute(left));
    let right = normalize(absolute(right));
    if cfg!(windows) {
        left.to_string_lossy()
            .replace('/', "\\")
            .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
    } else {
        left == right
    }
}

/// client.json path is special: it itself decides data_dir, so **usually** we always read the copy in the default dir
/// (otherwise after changing data_dir the new dir has no client.json and config locks itself).
///
/// **Exception (2026-09-20)**: when `RSRS_DATA_DIR` is set, client.json is read from that root
/// (`<root>/client.json`). Why: that env var is the only isolation entry for tests/multi-lib; if config still landed in the real
/// user dir, an isolated instance switching profiles would write the real client.json and pollute the user env (hit twice:
/// after teardown the real library status became "user local, 0 entries" until data_dir was cleared by hand).
/// An isolated root carries its own client.json — config follows the library — and cannot self-lock, because
/// data_dir is decided by the env var (in-tree first), not this file.
/// Host profile transactions preserve the complete configuration on failure.
pub fn client_config_path() -> PathBuf {
    if let Some(root) = env_root_dir() {
        return root.join("client.json");
    }
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".rsrs")
        .join("client.json")
}

fn read_client_config() -> Option<serde_json::Value> {
    std::fs::read_to_string(client_config_path())
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
}

pub fn validate_client_config() -> Result<()> {
    read_client_config_for_write().map(|_| ())
}

fn client_config_lock() -> Result<std::fs::File> {
    let path = client_config_path().with_extension("json.lock");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)
        .with_context(|| format!("cannot open client config lock {}", path.display()))?;
    file.lock().with_context(|| format!("cannot lock client config {}", path.display()))?;
    Ok(file)
}

fn write_client_config(data: &serde_json::Value) -> Result<()> {
    anyhow::ensure!(
        data.is_object(),
        "client config write rejected: value must be a JSON object, found {}",
        json_type_name(data)
    );
    let path = client_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(data)?;
    replace_client_config(&path, json.as_bytes())?;
    Ok(())
}

fn replace_client_config(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("client.json");
    let temp = path.with_file_name(format!(".{file_name}.tmp.{}.{}", std::process::id(), sequence));
    let write = || -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .with_context(|| format!("failed to create temporary client config {}", temp.display()))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .with_context(|| format!("failed to write temporary client config {}", temp.display()))?;
        drop(file);
        std::fs::rename(&temp, path)
            .with_context(|| format!("failed to replace client config {}", path.display()))?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    };
    let result = write();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn read_client_config_for_write() -> Result<serde_json::Value> {
    crate::memory::bge::m3_model_dir()?;
    let path = client_config_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(serde_json::json!({}));
        }
        Err(error) => return Err(error)
            .with_context(|| format!("cannot read client config {}", path.display())),
    };
    let value = serde_json::from_str::<serde_json::Value>(&text)
        .with_context(|| format!("client config {} contains invalid JSON", path.display()))?;
    anyhow::ensure!(
        value.is_object(),
        "client config {} must contain a JSON object, found {}",
        path.display(),
        json_type_name(&value)
    );
    for key in ["lang", "data_dir", "addr", "api_base", "service_mode", "engine", "model"] {
        if let Some(field) = value.get(key) {
            anyhow::ensure!(field.is_string(), "client config {} has a {key} of type {}, expected string", path.display(), json_type_name(field));
        }
    }
    for key in ["autosync", "cure_auto"] {
        if let Some(field) = value.get(key) {
            anyhow::ensure!(field.is_boolean(), "client config {} has a {key} of type {}, expected boolean", path.display(), json_type_name(field));
        }
    }
    if let Some(field) = value.get("rpc_parallelism") {
        anyhow::ensure!(field.as_u64().is_some_and(|value| value <= u32::MAX as u64), "client config {} has invalid rpc_parallelism", path.display());
    }
    Ok(value)
}

// ── data dir (client.json data_dir → RSRS_DATA_DIR → ~/.rsrs) ──
// For tests and multi-lib maintenance: changing data_dir switches the whole library (db/session/lock follow).
// Order: env var wins (one-shot override for CI/tests) → client.json data_dir → default ~/.rsrs.

pub fn default_data_dir() -> PathBuf {
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".rsrs")
}

/// Main-profile dir: `RSRS_DATA_DIR` when isolated, else default `~/.rsrs`.
/// **Every "back to main" path must use this**, not a hard `default_data_dir()` — otherwise an isolated instance
/// switching back to main would land in the real user dir (hit 2026-09-20).
pub fn main_data_dir() -> PathBuf {
    env_root_dir().unwrap_or_else(default_data_dir)
}

/// Effective data dir. Empty/missing fall back to default — never panics.
///
/// Order: `RSRS_DATA_DIR` (test/CI one-shot) > client.json data_dir > default.
///
/// **Exception (2026-09-20)**: if client.json data_dir sits inside the `RSRS_DATA_DIR` tree,
/// prefer it. Why: `space use` writes client.json data_dir, which always lives under
/// that root (`accounts_root()` also follows RSRS_DATA_DIR); if the env var still always won,
/// switching spaces in isolation would **silently fail** — session falls back to the root, the space profile is empty (hit in tests).
/// Semantically the env var names the root; switching moves inside the root; they do not conflict.
pub fn data_dir() -> PathBuf {
    data_dir_from_config(read_client_config().as_ref())
}

fn data_dir_from_config(config: Option<&serde_json::Value>) -> PathBuf {
    let env_root = env_root_dir();
    let from_config = config
        .and_then(|d| {
            d["data_dir"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
        })
        .map(|v| expand_tilde(&v));
    match (env_root, from_config) {
        (Some(root), Some(cfg)) if cfg.starts_with(&root) => cfg,
        (Some(root), _) => root,
        (None, Some(cfg)) => cfg,
        (None, None) => default_data_dir(),
    }
}

#[derive(serde::Serialize)]
pub struct ResolvedRoots {
    pub schema_version: u32,
    pub layout: &'static str,
    pub installation_root: PathBuf,
    pub device_config_root: PathBuf,
    pub client_config_path: PathBuf,
    pub account_data_root: PathBuf,
    pub accounts_root: PathBuf,
    pub asset_root: PathBuf,
    pub runtime_state_root: PathBuf,
    pub legacy_whole_isolation: bool,
    pub sources: std::collections::BTreeMap<&'static str, &'static str>,
}

pub fn resolved_roots() -> Result<ResolvedRoots> {
    // Do not clean parent traversals: symlinks can change their actual target.
    let absolute = |path: PathBuf| -> Result<PathBuf> {
        anyhow::ensure!(
            !path
                .components()
                .any(|part| part == std::path::Component::ParentDir),
            "root summary does not support parent traversal; use an explicit root without '..'"
        );
        Ok(std::path::absolute(path)?)
    };
    let asset_root = absolute(crate::memory::bge::m3_model_dir()?)?;
    let installation_root = absolute(main_data_dir())?;
    let client_config_path = absolute(client_config_path())?;
    let config = read_client_config_for_write()?;
    if let Some(value) = config["data_dir"]
        .as_str()
        .filter(|value| !value.is_empty())
    {
        absolute(expand_tilde(value))?;
    }
    let device_config_root = client_config_path
        .parent()
        .context("client config has no parent")?
        .to_path_buf();
    let account = data_dir_from_config(Some(&config));
    let legacy_whole_isolation = env_root_dir().is_some();
    let root_source = if legacy_whole_isolation {
        "RSRS_DATA_DIR"
    } else {
        "default_data_dir"
    };
    let account_source = if config["data_dir"]
        .as_str()
        .is_some_and(|value| !value.is_empty() && expand_tilde(value) == account)
    {
        "client.json:data_dir"
    } else {
        root_source
    };
    let asset_source = if crate::env::var("RSRS_M3_DIR").is_ok_and(|value| !value.trim().is_empty())
    {
        "RSRS_M3_DIR"
    } else {
        root_source
    };
    anyhow::ensure!(
        !legacy_whole_isolation || asset_source == "RSRS_M3_DIR" || asset_root.starts_with(&installation_root),
        "model root expansion conflicts with legacy isolation; use an explicit absolute data root or model root"
    );
    Ok(ResolvedRoots {
        schema_version: 1,
        layout: "phase1",
        runtime_state_root: installation_root.join("runtime"),
        installation_root,
        device_config_root,
        client_config_path,
        account_data_root: absolute(account)?,
        accounts_root: absolute(accounts_root())?,
        asset_root,
        legacy_whole_isolation,
        sources: std::collections::BTreeMap::from([
            ("installation_root", root_source),
            ("device_config_root", root_source),
            ("client_config_path", root_source),
            ("account_data_root", account_source),
            ("accounts_root", root_source),
            ("asset_root", asset_source),
            ("runtime_state_root", root_source),
        ]),
    })
}

/// Set the data dir (writes client.json). Empty string = clear back to default.
pub fn set_data_dir(dir: &str) -> Result<()> {
    let _config_lock = client_config_lock()?;
    let _ = read_client_config_for_write()?;
    let dir = dir.trim();
    let requested = if dir.is_empty() {
        main_data_dir()
    } else {
        expand_tilde(dir)
    };
    check_runtime_profile(&requested)?;
    let mut data = read_client_config_for_write()?;
    if dir.is_empty() {
        if let Some(o) = data.as_object_mut() {
            o.remove("data_dir");
        }
    } else {
        if !(dir.starts_with('/')
            || dir.starts_with("~/")
            || (dir.len() >= 2 && dir.as_bytes()[1] == b':'))
        {
            anyhow::bail!("data dir must be an absolute path (/\u{2026} or ~/\u{2026})");
        }
        data["data_dir"] = serde_json::json!(dir);
    }
    write_client_config(&data)
}

// ── multi-account profiles on one machine: each account has its own data dir (library/keys/session switch with data_dir) ──
// Profile root is accounts/ under the default dir (**does not follow client.json data_dir** — otherwise after a switch
// accounts_root would become <profile>/accounts and other profiles would vanish).
// But **when RSRS_DATA_DIR is set it must follow** (fixed 2026-09-20): that var is the only isolation entry
// for tests/multi-lib; if the profile root still landed in real HOME, isolated space profiles polluted the user dir (hit:
// a web isolation instance created work/sales under ~/.rsrs/accounts).
// Scene: several accounts on one machine (work/personal/test); login no longer needs logout --full to wipe key material.

pub fn accounts_root() -> PathBuf {
    env_root_dir().unwrap_or_else(default_data_dir).join("accounts")
}

/// Account profile dir (name check: letters/digits/-/_; no path traversal).
pub fn account_dir(name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("account profile name allows only letters/digits/-/_; got `{name}`");
    }
    Ok(accounts_root().join(name))
}

pub fn session_user_of_dir(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("session.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["user"].as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

/// List every local account profile: main (main-profile dir) + each dir under accounts/.
pub fn account_list() -> Result<serde_json::Value> {
    let current = data_dir();
    let main_dir = main_data_dir();
    let mut rows = vec![serde_json::json!({
        "name": "main",
        "dir": main_dir.to_string_lossy(),
        "user": session_user_of_dir(&main_dir),
        "current": current == main_dir,
    })];
    if let Ok(rd) = std::fs::read_dir(accounts_root()) {
        let mut names: Vec<std::ffi::OsString> =
            rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        names.sort();
        for n in names {
            let dir = accounts_root().join(&n);
            if !dir.join("session.json").exists() && !database_path(&dir)?.exists() {
                continue;
            }
            rows.push(serde_json::json!({
                "name": n.to_string_lossy(),
                "dir": dir.to_string_lossy(),
                "user": session_user_of_dir(&dir),
                "current": current == dir,
            }));
        }
    }
    Ok(serde_json::json!({ "accounts": rows, "current_dir": current.to_string_lossy() }))
}

/// Switch account profile: main = back to default dir; others = accounts/<name> (create empty if missing; hint to login/register).
pub fn account_use(name: &str) -> Result<serde_json::Value> {
    validate_client_config()?;
    require_profile_change_host()?;
    let is_main = name == "main";
    let dir = if is_main {
        main_data_dir()
    } else {
        let d = account_dir(name)?;
        std::fs::create_dir_all(&d)?;
        d
    };
    set_data_dir(&dir.to_string_lossy())?;
    let user = session_user_of_dir(&dir);
    let hint = if user.is_empty() {
        "this profile has no account yet \u{2014} run rsrs login (existing account) or rsrs register (new account)"
    } else {
        "switched to this profile \u{2014} local library/keys/session follow the profile and do not mix"
    };
    Ok(serde_json::json!({
        "name": if is_main { "main" } else { name },
        "dir": dir.to_string_lossy(),
        "user": user,
        "hint": hint,
    }))
}

/// Delete an account profile (library and keys are gone; needs --yes). Cannot delete the active profile.
pub fn account_remove(name: &str) -> Result<()> {
    validate_client_config()?;
    require_profile_change_host()?;
    let dir = account_dir(name)?;
    if !dir.exists() {
        return Err(crate::input_error::InputError(format!("no such account profile: {}", dir.display())).into());
    }
    if data_dir() == dir {
        return Err(crate::input_error::InputError("this profile is in use \u{2014} run rsrs account use <other> before deleting".into()).into());
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

// ── maintenance counter (auto-triggers memory resort) ──
// data_dir/maintenance.json: writes_since_resort write count (remember/merge success +1),
// at threshold the store output prints a broom alert — the AI then runs §3.8 resort; resort --go success zeros it.
// Default threshold 30; env RSRS_RESORT_HINT can override (tests).

pub fn maintenance_path() -> PathBuf {
    data_dir().join("maintenance.json")
}

/// Pure logic: count +1, return (new value, threshold). At threshold, alert (every write until reset, so resort happens now).
pub fn counter_bump(path: &Path) -> Result<(u64, u64)> {
    let mut v = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let n = v["writes_since_resort"].as_u64().unwrap_or(0) + 1;
    let threshold = crate::env::var("RSRS_RESORT_HINT")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|t| *t > 0)
        .or_else(|| v["resort_threshold"].as_u64().filter(|t| *t > 0))
        .unwrap_or(30);
    v["writes_since_resort"] = serde_json::json!(n);
    if let Some(o) = v.as_object_mut() {
        o.entry("resort_threshold".to_owned())
            .or_insert_with(|| serde_json::json!(threshold));
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, serde_json::to_vec(&v)?).map_err(|e| {
        anyhow::anyhow!(
            "failed to write maintenance counter ({}): {e}",
            path.display()
        )
    })?;
    Ok((n, threshold))
}

/// Reset (called after resort --go succeeds); records resort_at.
pub fn counter_reset(path: &Path, stamp: &str) -> Result<()> {
    let mut v = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    v["writes_since_resort"] = serde_json::json!(0);
    v["resort_at"] = serde_json::json!(stamp);
    std::fs::write(path, serde_json::to_vec(&v)?)
        .map_err(|e| anyhow::anyhow!("failed to write maintenance counter: {e}"))
}

/// Last resort time (maintenance.json resort_at, written by counter_reset).
/// §3.8 take-set: list --since-resort uses this to bound entries added since last resort.
/// Never resorted (no key) → None.
pub fn resort_at() -> Option<String> {
    std::fs::read_to_string(maintenance_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["resort_at"].as_str().map(ToOwned::to_owned))
        .filter(|s| !s.trim().is_empty())
}

/// Normalize --since: a bare date (YYYY-MM-DD) becomes that day's 00:00:00Z; otherwise keep as-is.
/// RFC3339 fixed-length prefixes mean lexicographic compare is time order; list filters by comparing strings.
pub fn normalize_since(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("--since must not be empty");
    }
    Ok(if s.len() == 10 && s.as_bytes().get(4) == Some(&b'-') {
        format!("{s}T00:00:00Z")
    } else {
        s.to_owned()
    })
}

/// Later of two lower bounds: explicit --since vs --since-resort's resort_at.
/// Neither → 1970 epoch (no filter); missing resort_at (never resorted) is the same.
pub fn later_bound(explicit: Option<String>, from_resort: Option<String>) -> String {
    match (explicit, from_resort) {
        (Some(a), Some(b)) => {
            if a > b {
                a
            } else {
                b
            }
        }
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

/// Read the current count only (for doctor).
pub fn counter_peek(path: &Path) -> (u64, u64) {
    let v = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    match v {
        Some(v) => (
            v["writes_since_resort"].as_u64().unwrap_or(0),
            v["resort_threshold"].as_u64().unwrap_or(30),
        ),
        None => (0, 30),
    }
}

/// Set the alert threshold.
pub fn counter_set_threshold(path: &Path, t: u64) -> Result<()> {
    if t == 0 {
        anyhow::bail!("threshold must be >0");
    }
    let mut v = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    v["resort_threshold"] = serde_json::json!(t);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, serde_json::to_vec(&v)?)
        .map_err(|e| anyhow::anyhow!("failed to write maintenance counter: {e}"))
}

// ── agent config (agent.json — AI controls, separate from the app's client.json) ──
// Written by the client settings page; the AI (via the inject source) reads it and behaves. agent.json in the data dir, JSON;
// missing keys have sane defaults; a missing file is not an error. First key diary_mode; later AI control keys go here too.

pub fn agent_config_path() -> PathBuf {
    data_dir().join("agent.json")
}

pub fn read_agent_config() -> serde_json::Value {
    std::fs::read_to_string(agent_config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

pub fn write_agent_config_key(key: &str, value: &serde_json::Value) -> Result<()> {
    let key = key.trim();
    if key == "recall_fusion" {
        crate::recall_fusion::effective(value)?;
    }
    if key == "read_heat" {
        anyhow::ensure!(value.is_boolean(), "read_heat must be true or false");
        crate::read_heat::configured()?;
        crate::read_heat::require_support()?;
    }
    if matches!(key, "memory_off" | "readonly") {
        let enabled = value.as_bool().ok_or_else(|| anyhow!("{key} must be true or false"))?;
        return set_workspace_mode(if !enabled { "normal" } else if key == "memory_off" { "off" } else { "readonly" });
    }
    if key == "workspace_mode" {
        return set_workspace_mode(value.as_str().ok_or_else(|| anyhow!("workspace_mode must be normal, readonly or off"))?);
    }
    if key == "recall_mode" && !matches!(value.as_str(), Some("fast" | "quality")) {
        anyhow::bail!("recall_mode must be fast or quality");
    }
    if key.trim().is_empty() {
        anyhow::bail!("key must not be empty");
    }
    let mut v = read_agent_config();
    if let Some(o) = v.as_object_mut() {
        o.insert(key.trim().to_owned(), value.clone());
    }
    if let Some(parent) = agent_config_path().parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(agent_config_path(), serde_json::to_vec_pretty(&v)?)
        .map_err(|e| anyhow::anyhow!("failed to write agent.json: {e}"))?;
    if key == "read_heat" {
        crate::read_heat::reload()?;
    }
    Ok(())
}

/// Read-only mode (team read-only members): local flag; when true every write command is refused.
///
/// Relation to `space`: owner issues a read-only session with `space invite --readonly`,
/// member `space join` sets local agent.json `readonly=true`;
/// the server also refuses writes by session token (belt and braces — the client can be bypassed).
pub fn readonly_mode() -> bool {
    readonly_team() || match device_service_mode().as_deref() {
        Some(mode) => mode == "readonly",
        None => read_agent_config()["readonly"].as_bool().unwrap_or(false),
    }
}

/// Read-only **source=team**: written on space join --readonly (personal self-set read-only has no this key).
/// H2 anti-self-unlock applies only to team read-only — personal read-only is the owner's flag and must be clearable;
/// even if a team member unlocks locally, the server still refuses writes by token (the real fence is the server).
pub fn readonly_team() -> bool {
    read_agent_config()["readonly_team"]
        .as_bool()
        .unwrap_or(false)
}

/// Device disable mode suppresses memory reads and writes until explicitly changed.
/// Existing account-local flags remain compatible when no device mode has been saved.
fn device_service_mode() -> Option<String> {
    read_client_config().and_then(|config| config["service_mode"].as_str()
        .filter(|mode| matches!(*mode, "normal" | "readonly" | "off")).map(str::to_owned))
}

pub fn off_mode() -> bool {
    match device_service_mode().as_deref() {
        Some(mode) => mode == "off",
        None => read_agent_config()["memory_off"].as_bool().unwrap_or(false),
    }
}

/// Pause device memory work without confusing a team's read-only access with a device setting.
pub fn service_paused() -> bool {
    off_mode() || match device_service_mode().as_deref() {
        Some(mode) => mode == "readonly",
        None => !readonly_team() && read_agent_config()["readonly"].as_bool().unwrap_or(false),
    }
}

/// Workspace three-state (GUI/status): off > readonly > normal.
pub fn workspace_mode() -> &'static str {
    if off_mode() {
        "off"
    } else if readonly_mode() {
        "readonly"
    } else {
        "normal"
    }
}

/// Device service mode lives beside the active-profile pointer, never in an account.
/// Existing team permissions remain effective even when the device returns to normal.
pub fn set_workspace_mode(mode: &str) -> Result<()> {
    let _config_lock = client_config_lock()?;
    let _ = read_client_config_for_write()?;
    if !matches!(mode, "normal" | "readonly" | "off") {
        return Err(crate::input_error::InputError(format!("unknown mode `{mode}` \u{2014} choose: normal | readonly | off")).into());
    }
    let mut config = read_client_config_for_write()?;
    anyhow::ensure!(config.is_object(), "client config must be an object");
    config["service_mode"] = serde_json::json!(mode);
    write_client_config(&config)
}

/// Read-only gate: write commands must pass this. Err aborts (message is for the user and the AI).
pub fn ensure_writable() -> Result<()> {
    if readonly_mode() {
        let hint = if readonly_team() {
            "read-only is enforced by the server via the session token; editing local agent.json has no effect. To write, ask the space owner for a read-write session and run rsrs space join."
        } else {
            "restore normal service on this device with `agent-config --set workspace_mode=normal`."
        };
        return Err(anyhow!(
            "this space is read-only \u{2014} recall/list/show/diary/tree are allowed; write/edit/delete are not.\n  {hint}"
        ));
    }
    Ok(())
}

/// Trivia recording mode: concise = one daily activity-trail entry (default; append one line per event);
/// verbose = one diary entry per event. The AI reads this via agent-config.
pub fn diary_mode() -> String {
    read_agent_config()["diary_mode"]
        .as_str()
        .filter(|s| *s == "verbose" || *s == "concise")
        .unwrap_or("concise")
        .to_owned()
}

/// Append a timestamped line to the activity trail for today.
pub fn activity_append(existing: &str, line: &str) -> String {
    let mut s = existing.to_owned();
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str(line);
    s
}

// ── subtree members (shared helper: share/grant take all descendants of a root) ──

/// Subtree members: root and all descendants (BFS). Root missing → empty.
pub fn subtree_members(
    all: &[crate::memory::model::StoredMemory],
    root: &str,
) -> std::collections::HashSet<String> {
    let mut children_of: HashMap<&str, Vec<&str>> = HashMap::new();
    for m in all {
        if !m.deleted && !m.local_parent_id.is_empty() {
            children_of
                .entry(m.local_parent_id.as_str())
                .or_default()
                .push(m.id.as_str());
        }
    }
    let mut out = std::collections::HashSet::new();
    if !all.iter().any(|m| m.id == root && !m.deleted) {
        return out;
    }
    let mut frontier = vec![root];
    while let Some(cur) = frontier.pop() {
        if !out.insert(cur.to_owned()) {
            continue;
        }
        if let Some(kids) = children_of.get(cur) {
            frontier.extend(kids.iter().copied());
        }
    }
    out
}

/// Lightweight status: no session unlock, no embedder load; only store counts and config.
///
/// Why (2026-09-14): the client calls status at startup, and the old path `App::open()` blindly loaded
/// a 389MB ONNX (~2s); on Windows each fork also popped a console, stacking into "startup freeze".
/// status does not need vectors, so this path skips one model load.
pub fn status_light() -> Result<StatusInfo> {
    let (root, store) = open_store_with_profile()?;
    let blobs = store.all(true)?;
    Ok(StatusInfo {
        local_total: blobs.len(),
        local_alive: blobs.iter().filter(|m| !m.deleted).count(),
        remote_configured: remote_configured(),
        max_updated_at: store.max_updated_at().ok().flatten(),
        data_dir: root.to_string_lossy().into_owned(),
    })
}

/// Local memory snapshot identity for clients. This is not a sync cursor.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MemoryRevision {
    pub profile: String,
    pub revision: String,
}

/// Capture the CLI-resolved profile once so identity and token name the same DB.
/// This path is strictly read-only and does not unlock, initialize, or scan memory.
pub fn memory_revision() -> Result<MemoryRevision> {
    let root = data_dir();
    check_runtime_profile(&root)?;
    let revision = crate::transport::local::read_memory_revision(&database_path(&root)?)?;
    Ok(MemoryRevision {
        profile: root.to_string_lossy().into_owned(),
        revision,
    })
}

pub fn server_addr() -> String {
    read_client_config()
        .and_then(|d| {
            d["addr"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| DEFAULT_SERVER_ADDR.to_owned())
}

/// Address the web form and resume use. Session addr wins, then client.json, then the public server.
/// Never returns an empty string.
pub fn preferred_addr(session_addr: &str) -> String {
    let session_addr = session_addr.trim().trim_end_matches('/');
    if session_addr.starts_with("http://") || session_addr.starts_with("https://") {
        return session_addr.to_owned();
    }
    let configured = server_addr();
    if !configured.is_empty() {
        return configured;
    }
    DEFAULT_SERVER_ADDR.to_owned()
}

/// Open the local web without asking the user to retype credentials.
///
/// Already-joined profiles (wrapped key on disk) return immediately. The super
/// password stays in the OS keyring and is loaded by the CLI when a command
/// unlocks. If the profile is not joined yet but this machine has stored the
/// login password, log in with that and the keyring super password.
/// The returned JSON never contains either password.
pub fn resume_session() -> Result<serde_json::Value> {
    let si = session_info();
    let addr = preferred_addr(&si.addr);
    let has_super = crate::keystore::load_super(&si.user).is_some();
    if si.has_local_keys {
        return Ok(serde_json::json!({
            "ok": true,
            "resumed": true,
            "need_login": false,
            "user": si.user,
            "addr": addr,
            "has_super": has_super,
        }));
    }
    if !si.user.is_empty() {
        if let Some(pass) = crate::keystore::load_login_pass(&si.user) {
            match login(&addr, &si.user, &pass, None, None, false) {
                Ok(issued) => {
                    return Ok(serde_json::json!({
                        "ok": true,
                        "resumed": true,
                        "need_login": false,
                        "user": si.user,
                        "addr": addr,
                        "has_super": true,
                        "super_issued": issued,
                    }));
                }
                Err(error) => {
                    return Ok(serde_json::json!({
                        "ok": false,
                        "resumed": false,
                        "need_login": true,
                        "user": si.user,
                        "addr": addr,
                        "has_super": has_super,
                        "error": format!("{error:#}"),
                    }));
                }
            }
        }
    }
    Ok(serde_json::json!({
        "ok": false,
        "resumed": false,
        "need_login": true,
        "user": si.user,
        "addr": addr,
        "has_super": has_super,
    }))
}

pub fn set_server_addr(addr: &str) -> Result<()> {
    let _config_lock = client_config_lock()?;
    let _ = read_client_config_for_write()?;
    if database_path(&data_dir())?.exists() { crate::metadata_gate::ensure_sync_allowed(&open_store()?)?; }
    let addr = addr.trim();
    if !(addr.starts_with("http://") || addr.starts_with("https://")) {
        anyhow::bail!("server address must start with http:// or https://");
    }
    let mut data = read_client_config_for_write()?;
    data["addr"] = serde_json::json!(addr);
    write_client_config(&data)
}

/// Auto-sync switch: RSRS_NO_AUTOSYNC env wins (set and not 0 → off);
/// then client.json autosync (the client "auto-sync after write" toggle);
/// default = on (if remote is configured, auto-sync; backward compatible).
pub fn autosync_enabled() -> bool {
    if crate::env::var("RSRS_NO_AUTOSYNC").is_ok_and(|v| v != "0") {
        return false;
    }
    read_client_config()
        .and_then(|d| d["autosync"].as_bool())
        .unwrap_or(true)
}

/// Actual write-path sync gate: always off inside tests.
///
/// Why (proven 2026-09-16): tests build fixtures with a fixed URK (`[7u8; 32]`); if the write path triggered
/// auto-sync, and that check read the **real** ~/.rsrs/session.json, a logged-in test machine
/// would push fake rows to the real cloud — ciphertext the local key cannot open (14 rows).
/// split_exec / deepen_apply each missed this and got one-off patches; this is the single gate:
/// every write-path auto-sync goes through this fn; new write paths do not need a private check.
pub fn autosync_active() -> bool {
    !cfg!(test) && autosync_enabled() && crate::snapshot::ensure_sync_allowed(&data_dir()).is_ok()
}

pub fn set_autosync(on: bool) -> Result<()> {
    let _config_lock = client_config_lock()?;
    let _ = read_client_config_for_write()?;
    if on && database_path(&data_dir())?.exists() { crate::metadata_gate::ensure_sync_allowed(&open_store()?)?; }
    let mut data = read_client_config_for_write()?;
    data["autosync"] = serde_json::json!(on);
    write_client_config(&data)
}

/// Periodic tree-cure switch (client.json cure_auto, default on): client background iterates cure every 10 minutes.
pub fn cure_auto_enabled() -> bool {
    read_client_config()
        .and_then(|d| d["cure_auto"].as_bool())
        .unwrap_or(true)
}

pub fn set_cure_auto(on: bool) -> Result<()> {
    let _config_lock = client_config_lock()?;
    let _ = read_client_config_for_write()?;
    let mut data = read_client_config_for_write()?;
    data["cure_auto"] = serde_json::json!(on);
    write_client_config(&data)
}

/// Saved RPC compute worker limit (`client.json` `rpc_parallelism`), bounded by available CPU parallelism.
/// Two extra lightweight read slots remain available. `0` is stored as absent.
/// The resident runtime reads this only at start.
pub fn rpc_parallelism_setting() -> Option<usize> {
    read_client_config()
        .and_then(|data| data.get("rpc_parallelism").and_then(|value| value.as_u64()))
        .map(|value| value as usize)
        .filter(|value| *value > 0)
}

pub fn set_rpc_parallelism(workers: u32) -> Result<()> {
    let _config_lock = client_config_lock()?;
    let _ = read_client_config_for_write()?;
    let mut data = read_client_config_for_write()?;
    if workers == 0 {
        if let Some(obj) = data.as_object_mut() {
            obj.remove("rpc_parallelism");
        }
    } else {
        data["rpc_parallelism"] = serde_json::json!(workers);
    }
    write_client_config(&data)
}

// ── book and portrait (material aggregation; the AI drafts) ──

#[derive(Debug, Clone, Serialize)]
pub struct BookEntry {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub content: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct BookChapter {
    pub id: String,
    pub title: String,
    pub entries: Vec<BookEntry>,
}

#[derive(Debug, Serialize)]
pub struct BookMaterial {
    pub root: NodeRef,
    pub chapters: Vec<BookChapter>,
    pub total_entries: usize,
    pub total_chars: usize,
}

impl App {
    /// Book material: one causal tree → volume (root) - chapter (direct children) - section (descendants), tree-order full text.
    /// The AI reads this and drafts the book (structure, narrative, cuts are the AI's call).
    pub fn book_material(&self, root_prefix: &str) -> Result<BookMaterial> {
        let all = self.store.all(false)?;
        let root_id = resolve_prefix(&all, root_prefix)?;
        let root = all
            .iter()
            .find(|m| m.id == root_id)
            .ok_or_else(|| anyhow!("root does not exist"))?;
        let to_entry = |m: &crate::memory::model::StoredMemory| -> BookEntry {
            BookEntry {
                id: m.id.clone(),
                title: if m.local_title.is_empty() {
                    short_id(&m.id)
                } else {
                    m.local_title.clone()
                },
                kind: m.local_kind.clone(),
                content: m.local_content_head.clone(),
                created_at: m.local_created_at.clone(),
            }
        };
        let direct: Vec<&crate::memory::model::StoredMemory> = all
            .iter()
            .filter(|m| m.local_parent_id == root_id)
            .collect();
        let mut chapters = Vec::new();
        let mut total_entries = 0usize;
        let mut total_chars = 0usize;
        for d in &direct {
            let mut entries = vec![to_entry(d)];
            // DFS collect grandchildren (depth cap 3 so a deep tree cannot explode)
            let mut stack: Vec<String> = vec![d.id.clone()];
            let mut depth = 0;
            while !stack.is_empty() && depth < 3 {
                let mut next = Vec::new();
                for cur in &stack {
                    for m in all.iter().filter(|m| m.local_parent_id == *cur) {
                        entries.push(to_entry(m));
                        next.push(m.id.clone());
                    }
                }
                stack = next;
                depth += 1;
            }
            total_entries += entries.len();
            total_chars += entries
                .iter()
                .map(|e| e.content.chars().count())
                .sum::<usize>();
            chapters.push(BookChapter {
                id: d.id.clone(),
                title: if d.local_title.is_empty() {
                    short_id(&d.id)
                } else {
                    d.local_title.clone()
                },
                entries,
            });
        }
        chapters.sort_by(|a, b| b.entries.len().cmp(&a.entries.len()));
        Ok(BookMaterial {
            root: NodeRef {
                id: root.id.clone(),
                title: if root.local_title.is_empty() {
                    short_id(&root.id)
                } else {
                    root.local_title.clone()
                },
            },
            chapters,
            total_entries,
            total_chars,
        })
    }

    /// Portrait material: preference/decision/emotion entries + theme-tree ranking + monthly timeline — the AI drafts a portrait.
    pub fn portrait_material(&self, limit: usize) -> Result<serde_json::Value> {
        let all = self.store.all(false)?;
        let pick = |kind: Kind| -> Vec<BookEntry> {
            let mut items: Vec<BookEntry> = all
                .iter()
                .filter(|m| m.local_kind == kind.as_str())
                .map(|m| BookEntry {
                    id: m.id.clone(),
                    title: if m.local_title.is_empty() {
                        short_id(&m.id)
                    } else {
                        m.local_title.clone()
                    },
                    kind: m.local_kind.clone(),
                    content: m.local_content_head.clone(),
                    created_at: m.local_created_at.clone(),
                })
                .collect();
            items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            items.truncate(limit);
            items
        };
        // Theme-tree ranking (subtree size top 10)
        let mut children_of: HashMap<String, Vec<String>> = HashMap::new();
        for m in &all {
            if !m.local_parent_id.is_empty() {
                children_of
                    .entry(m.local_parent_id.clone())
                    .or_default()
                    .push(m.id.clone());
            }
        }
        let subtree = |r: &str| -> usize {
            let mut n = 0;
            let mut st = vec![r.to_owned()];
            while let Some(c) = st.pop() {
                if let Some(kids) = children_of.get(&c) {
                    n += kids.len();
                    st.extend(kids.iter().cloned());
                }
            }
            n
        };
        let mut themes: Vec<(String, usize)> = all
            .iter()
            .filter(|m| m.local_parent_id.is_empty() && children_of.contains_key(m.id.as_str()))
            .map(|m| {
                (
                    if m.local_title.is_empty() {
                        short_id(&m.id)
                    } else {
                        m.local_title.clone()
                    },
                    subtree(&m.id),
                )
            })
            .collect();
        themes.sort_by(|a, b| b.1.cmp(&a.1));
        themes.truncate(10);
        // Monthly timeline
        let mut timeline: HashMap<String, usize> = HashMap::new();
        for m in &all {
            let key = &m.local_created_at[..m.local_created_at.len().min(7)];
            if key.len() == 7 {
                *timeline.entry(key.to_owned()).or_default() += 1;
            }
        }
        let mut timeline: Vec<(String, usize)> = timeline.into_iter().collect();
        timeline.sort();
        Ok(serde_json::json!({
            "preferences": pick(Kind::Preference),
            "decisions": pick(Kind::Decision),
            "emotions": pick(Kind::Emotion),
            "skills": pick(Kind::Skill),
            "top_themes": themes,
            "timeline": timeline,
            "total_entries": all.len(),
        }))
    }
}

// ── tools ──

/// Export all plaintext memories as JSON (backup/migrate).
pub fn export_json(path: &std::path::Path) -> Result<usize> {
    crate::input_error::validate_output_parent(path)?;
    let keys = auth::load_local_session()?;
    let store = open_store()?;
    let blobs = store.all(false)?;
    let mut items = Vec::new();
    for s in &blobs {
        let e = MemoryEngine::open(&keys, s)?;
        items.push(serde_json::to_value(&e)?);
    }
    std::fs::write(path, serde_json::to_string_pretty(&items)?)?;
    Ok(items.len())
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ImportTags {
    List(Vec<String>),
    Text(String),
}

impl Default for ImportTags {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(serde::Deserialize)]
struct ImportItem {
    #[serde(default, flatten)]
    metadata: crate::memory::model::MemoryMeta,
    #[serde(default, flatten)]
    unknown_fields: crate::memory::model::ExtraFields,
    #[serde(default, rename = "device")]
    _device: String,
    #[serde(default, rename = "modified_by")]
    _modified_by: String,
    #[serde(default)]
    supersedes: String,
    #[serde(default)]
    superseded_by: String,
    #[serde(default)]
    see_also: Vec<String>,
    #[serde(default)]
    id: String,
    #[serde(default, alias = "type")]
    kind: Option<String>,
    #[serde(default)]
    tags: ImportTags,
    #[serde(default)]
    title: String,
    content: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    computer: String,
    #[serde(default)]
    project: String,
    #[serde(default, alias = "createdAt")]
    created_at: Option<String>,
    #[serde(default, alias = "updatedAt")]
    updated_at: Option<String>,
    #[serde(default)]
    emotion: Option<f32>,
    #[serde(default, alias = "parentId")]
    parent_id: Option<String>,
    #[serde(default)]
    importance: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub duplicates: usize,
    pub reattached: usize,
    pub orphaned: usize,
}

pub fn import_json(path: &std::path::Path) -> Result<ImportReport> {
    let text = crate::input_error::read_file(path, "import file")?;
    import_json_text(&text)
}

/// Import exact-content-unique records; the same snapshot can be retried safely.
pub fn import_json_text(text: &str) -> Result<ImportReport> {
    ensure!(!off_mode(), "memory service is disabled; restore normal service before importing");
    ensure_writable()?;
    let items: Vec<ImportItem> = serde_json::from_str(text)
        .map_err(|e| anyhow!("failed to parse import JSON: {e}"))?;
    let mut report = ImportReport { imported: 0, skipped: 0, duplicates: 0, reattached: 0, orphaned: 0 };
    let mut entries: Vec<MemoryEntry> = Vec::new();
    let mut old_ids: HashMap<String, usize> = HashMap::new();
    for (index, item) in items.into_iter().enumerate() {
        if item.id.is_empty() && item.content.trim().is_empty() {
            report.skipped += 1;
            continue;
        }
        if !item.id.is_empty() {
            if let Some(previous) = old_ids.get(&item.id) {
                ensure!(entries[*previous].content == item.content, "duplicate id with different content at record {}", index + 1);
                let mut metadata = item.metadata.clone();
                metadata.verification = None;
                ensure!(entries[*previous].metadata == metadata && entries[*previous].unknown_fields == item.unknown_fields,
                    "duplicate id with different metadata at record {}", index + 1);
                report.skipped += 1;
                report.duplicates += 1;
                continue;
            }
            old_ids.insert(item.id, entries.len());
        }
        let kind = item.kind.unwrap_or_else(|| "context".to_owned()).to_lowercase();
        if !matches!(kind.as_str(), "context" | "decision" | "preference" | "task" | "emotion" | "time" | "skill" | "knowledge" | "hypothesis" | "reflection" | "self") {
            anyhow::bail!("invalid kind at record {}: {kind}", index + 1);
        }
        let importance = item.importance.unwrap_or_else(|| "trivial".to_owned());
        if !matches!(importance.as_str(), "normal" | "important" | "trivial") {
            anyhow::bail!("invalid importance at record {}", index + 1);
        }
        let emotion = item.emotion.unwrap_or(-1.0);
        if emotion != -1.0 && !(0.0..=1.0).contains(&emotion) {
            anyhow::bail!("invalid emotion at record {}", index + 1);
        }
        item.metadata.validate()?;
        crate::memory::model::metadata::validate_extra_fields(&item.unknown_fields)?;
        let created_at = item.created_at.filter(|s| !s.is_empty()).unwrap_or_else(now_stamp);
        let updated_at = item.updated_at.filter(|s| !s.is_empty()).unwrap_or_else(|| created_at.clone());
        entries.push(MemoryEntry {
            metadata: crate::memory::model::MemoryMeta { verification: None, ..item.metadata },
            unknown_fields: item.unknown_fields,
            supersedes: item.supersedes, superseded_by: item.superseded_by, see_also: item.see_also,
            id: uuid::Uuid::new_v4().to_string(), kind: Kind::try_from_str(&kind).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?,
            tags: match item.tags { ImportTags::List(tags) => tags, ImportTags::Text(tags) => split_tags(&tags) },
            title: item.title, content: item.content, user: item.user.unwrap_or_else(current_user),
            computer: item.computer, project: item.project, device: device_tag(), modified_by: device_tag(),
            created_at, updated_at, emotion, parent_id: item.parent_id.unwrap_or_default(), importance,
        });
    }
    let mut done = HashSet::new();
    for start in 0..entries.len() {
        let mut chain = HashSet::new();
        let mut cursor = Some(start);
        while let Some(index) = cursor {
            if done.contains(&index) { break; }
            if !chain.insert(index) { anyhow::bail!("import parent chain contains a cycle"); }
            cursor = old_ids.get(&entries[index].parent_id).copied();
        }
        done.extend(chain);
    }
    if entries.is_empty() { return Ok(report); }
    let app = App::open()?;
    app.store.write_transaction(|| {
        let mut contents = HashMap::new();
        let mut existing = app.store.all(false)?;
        existing.sort_by(|left, right| left.id.cmp(&right.id));
        let mut canonical = HashMap::new();
        for stored in existing {
            let entry = MemoryEngine::open(&app.keys, &stored)?;
            contents.entry(entry.content.clone()).or_insert(entry.id.clone());
            canonical.insert(entry.id.clone(), (stored, entry));
        }
        let incoming: HashMap<_, _> = entries.iter().map(|entry| (entry.id.clone(), entry.clone())).collect();
        let mut retained = Vec::new();
        for (index, entry) in entries.iter_mut().enumerate() {
            if let Some(id) = contents.get(&entry.content) {
                let existing = canonical.get(id).map(|(_, old)| old)
                    .or_else(|| incoming.get(id)).context("missing content duplicate")?;
                if entry.metadata.memory_contract != 0 || existing.metadata.memory_contract != 0 {
                    let mut previous = existing.metadata.clone();
                    previous.verification = None;
                    ensure!(entry.metadata == previous && entry.kind == existing.kind
                        && entry.title == existing.title && entry.unknown_fields == existing.unknown_fields,
                        "import duplicate content has different metadata; import was rolled back");
                }
                entry.id = id.clone();
                report.skipped += 1;
                report.duplicates += 1;
            } else {
                contents.insert(entry.content.clone(), entry.id.clone());
                retained.push(index);
            }
        }
        let ids: HashMap<String, String> = old_ids.iter()
            .map(|(id, index)| (id.clone(), entries[*index].id.clone())).collect();
        let mut fresh: Vec<MemoryEntry> = retained.into_iter().map(|index| entries[index].clone()).collect();
        remap_relations(&mut fresh, &ids)?;
        for entry in &mut fresh {
            entry.see_also.sort();
            entry.see_also.dedup();
            if entry.parent_id.is_empty() { continue; }
            match ids.get(&entry.parent_id) {
                Some(id) if id != &entry.id => {
                    entry.parent_id = id.clone();
                    report.reattached += 1;
                }
                Some(_) => anyhow::bail!("content deduplication would create a self parent; original library was preserved"),
                None => { entry.parent_id.clear(); report.orphaned += 1; }
            }
        }
        let parents: HashMap<_, _> = fresh.iter().map(|entry| (entry.id.as_str(), entry.parent_id.as_str())).collect();
        let mut complete = HashSet::new();
        for start in &fresh {
            let mut seen = HashSet::new();
            let mut cursor = start.id.as_str();
            while let Some(parent) = parents.get(cursor) {
                if complete.contains(cursor) { break; }
                if !seen.insert(cursor) { anyhow::bail!("content deduplication would create a parent cycle"); }
                cursor = parent;
            }
            complete.extend(seen);
        }
        let mut linked = HashSet::new();
        for entry in &fresh {
            if let Some((_, previous)) = canonical.get_mut(&entry.supersedes) {
                ensure!(previous.superseded_by.is_empty(), "deduplicated target already has a replacement; import was rolled back");
                previous.superseded_by = entry.id.clone();
                linked.insert(previous.id.clone());
            }
            for target in &entry.see_also {
                if let Some((_, other)) = canonical.get_mut(target) {
                    if !other.see_also.contains(&entry.id) {
                        other.see_also.push(entry.id.clone());
                        linked.insert(other.id.clone());
                    }
                }
            }
        }
        for id in &linked {
            let (_, entry) = canonical.get(id).context("missing deduplicated association target")?;
            crate::metadata_gate::ensure_write(&app.store, entry)?;
        }
        for entry in &fresh {
            crate::metadata_gate::ensure_write(&app.store, entry)?;
            crate::metadata_gate::ensure_sources(&app.keys, &app.store, entry)?;
        }
        for id in linked {
            let (row, entry) = canonical.get(&id).context("missing deduplicated association target")?;
            let stamp = app.store.edit_stamp(&id)?;
            let updated = MemoryEngine::reseal_edges(&app.keys, row, &stamp, |payload| {
                payload.superseded_by = entry.superseded_by.clone();
                payload.see_also = entry.see_also.clone();
                payload.modified_by = device_tag();
            })?;
            ensure!(app.store.put_inner(&updated, true)?, "deduplicated association target changed");
        }
        let stored = fresh.iter()
            .map(|entry| MemoryEngine::seal(&app.keys, &app.embedder, entry, &entry.user))
            .collect::<Result<Vec<_>>>()?;
        for memory in &stored {
            if !app.store.put_inner(memory, true)? { anyhow::bail!("import conflict: {}", memory.id); }
        }
        report.imported = stored.len();
        Ok(())
    })?;
    if report.imported > 0 { app.auto_sync(); }
    Ok(report)
}

/// Export a subtree as a share payload (plaintext, for someone else to import).
///
/// Walk order = root then descendants (parent before child), so the payload is self-contained: the importer need not topo-sort.
/// Skip a bad row (corrupt ciphertext) rather than abort — half a tree is better than none.
///
/// Do not load BGE: share export only decrypts, never searches; loading the model for seconds is waste (2026-09-21).
pub fn export_subtree_payload(root_prefix: &str) -> Result<(crate::share::SharePayload, String)> {
    let keys = auth::load_local_session()
        .map_err(|e| anyhow!("session not unlocked ({e}) \u{2014} register/login or keygen first"))?;
    let store = open_store()?;
    let all = store.all(false)?;
    let root_id = resolve_prefix(&all, root_prefix)?;
    let members = subtree_members(&all, &root_id);
    // Adjacency list + preorder walk (parent before child)
    let mut children_of: HashMap<&str, Vec<&str>> = HashMap::new();
    for m in &all {
        if !m.deleted && !m.local_parent_id.is_empty() {
            children_of
                .entry(m.local_parent_id.as_str())
                .or_default()
                .push(m.id.as_str());
        }
    }
    let mut order: Vec<String> = Vec::with_capacity(members.len());
    let mut stack = vec![root_id.clone()];
    while let Some(cur) = stack.pop() {
        if !members.contains(&cur) {
            continue;
        }
        order.push(cur.clone());
        if let Some(kids) = children_of.get(cur.as_str()) {
            // Push reversed so pop yields original order (same as subtree_ids)
            stack.extend(kids.iter().rev().map(|s| s.to_string()));
        }
    }
    let by_id: HashMap<&str, &crate::memory::model::StoredMemory> =
        all.iter().map(|m| (m.id.as_str(), m)).collect();
    let lookup = |id: &str| -> Option<MemoryEntry> {
        by_id
            .get(id)
            .and_then(|s| MemoryEngine::open(&keys, s).ok())
            .map(|entry| MemoryEntry {
                metadata: entry.metadata,
                unknown_fields: entry.unknown_fields,
                supersedes: entry.supersedes,
                superseded_by: entry.superseded_by,
                see_also: entry.see_also,
                id: entry.id,
                kind: entry.kind,
                tags: entry.tags,
                title: entry.title,
                content: entry.content,
                user: entry.user,
                computer: entry.computer,
                project: entry.project,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
                emotion: entry.emotion,
                parent_id: entry.parent_id,
                importance: entry.importance,
                device: entry.device,
                modified_by: entry.modified_by,
            })
    };
    let root_title = by_id
        .get(root_id.as_str())
        .map(|m| {
            if m.local_title.is_empty() {
                short_id(&m.id)
            } else {
                m.local_title.clone()
            }
        })
        .unwrap_or_else(|| short_id(&root_id));
    let items = crate::share::items_from(&root_id, &order, &lookup, &members);
    if items.is_empty() {
        anyhow::bail!("no shareable memories in this subtree ({root_id}) \u{2014} empty subtree or entries cannot be decrypted");
    }
    let payload = crate::share::SharePayload {
        v: 1,
        kind: "subtree".to_owned(),
        root_title,
        created_at: now_stamp(),
        device: device_tag(),
        source_user: current_user(),
        items,
    };
    let encoded = crate::share::encode(&payload)?;
    Ok((payload, encoded))
}

/// Read a share file → payload.
pub fn read_share_file(path: &std::path::Path) -> Result<crate::share::SharePayload> {
    let text = crate::input_error::read_file(path, "share file")?;
    crate::share::decode(&text)
}

/// For the AI to pick an attach point: payload vs nearby local entries (read-only, no write).
///
/// Return Core-proposed candidates and a suggested root when no candidate exists.
///
/// Rule from "AI picks the attach point": without --parent, only emit the bill; the attach decision stays with the AI (model lives in main).
pub fn share_candidates_with(
    payload: &crate::share::SharePayload,
    embedder: &BgeEmbedder,
) -> Result<serde_json::Value> {
    let keys = auth::load_local_session()
        .map_err(|e| anyhow!("session not unlocked ({e}) \u{2014} register/login or keygen first"))?;
    let store = open_store()?;
    let all = store.all(false)?;
    let query = crate::share::mount_query(payload);
    require_candidates_ready(&store, &all)?;
    let report = candidate_report(&keys, embedder, &all, &query)?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    for (bucket, verdict) in [
        (&report.merge, "same-topic/merge"),
        (&report.parent, "attach-under"),
    ] {
        for s in bucket {
            out.push(serde_json::json!({
                "id": s.entry.id,
                "short_id": short_id(&s.entry.id),
                "title": s.entry.title,
                "score": (s.score * 100.0).round() / 100.0,
                "suggest": verdict,
            }));
        }
    }
    out.sort_by(|a, b| {
        b["score"]
            .as_f64()
            .partial_cmp(&a["score"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(serde_json::json!({
        "root_title": payload.root_title,
        "count": payload.items.len(),
        "chars": payload.total_chars(),
        "from": payload.device,
        "candidates": out,
        "hint": "if a close candidate exists \u{2192} share-import <file> --parent <short_id> --go to attach under it; \
                 if none \u{2192} share-import <file> --go creates a same-titled root",
    }))
}

/// Write a share payload: always mint new ids, rebuild the parent chain, attach the root at `attach_parent` (empty = own root).
///
/// Before writing, ask Core to identify same-topic conflicts and refuse an implicit sibling write.
/// cannot rely on the AI reading the bill. Force needs explicit `force` (CLI `--force`).
pub fn import_share_payload(
    payload: &crate::share::SharePayload,
    attach_parent: &str,
    force: bool,
    embedder: &BgeEmbedder,
) -> Result<ImportReport> {
    let keys = auth::load_local_session()
        .map_err(|e| anyhow!("session not unlocked ({e}) \u{2014} register/login or keygen first"))?;
    let store = open_store()?;
    // Resolve the attach point first (prefix ok); fail loudly, do not silently become a root
    let parent = if attach_parent.trim().is_empty() {
        String::new()
    } else {
        let all = store.all(true)?;
        resolve_prefix(&all, attach_parent.trim())?
    };
    // Ask Core to identify conflicts before importing.
    // Block only when attach is not explicit: `--parent` means "I know where"; same-topic is then expected
    // (e.g. hanging the shared subtree under a same-topic local entry as a supplement) — same as attach skipping store-judge.
    if !force && parent.is_empty() {
        let all = store.all(false)?;
        require_candidates_ready(&store, &all)?;
        let mut conflicts: Vec<serde_json::Value> = Vec::new();
        for it in &payload.items {
            let q = if it.content.trim().is_empty() {
                it.title.clone()
            } else {
                format!("{}\n{}", it.title, it.content)
            };
            if q.trim().is_empty() {
                continue;
            }
            let report = candidate_report(&keys, embedder, &all, &q)?;
            for s in &report.merge {
                conflicts.push(serde_json::json!({
                    "incoming": it.title,
                    "existing_id": s.entry.id,
                    "existing_short": short_id(&s.entry.id),
                    "existing_title": s.entry.title,
                    "score": (s.score * 100.0).round() / 100.0,
                }));
            }
        }
        if !conflicts.is_empty() {
            // Dedup (one existing entry hit by several payload items)
            let mut seen = std::collections::HashSet::new();
            conflicts.retain(|c| {
                let k = format!(
                    "{}|{}",
                    c["incoming"].as_str().unwrap_or(""),
                    c["existing_short"].as_str().unwrap_or("")
                );
                seen.insert(k)
            });
            let mut lines: Vec<String> = conflicts
                .iter()
                .map(|c| {
                    format!(
                        "  {:.2}  `{}` \u{2248} existing [{}] {}",
                        c["score"].as_f64().unwrap_or(0.0),
                        c["incoming"].as_str().unwrap_or(""),
                        c["existing_short"].as_str().unwrap_or(""),
                        c["existing_title"].as_str().unwrap_or("")
                    )
                })
                .collect();
            lines.sort();
            anyhow::bail!(
                "import blocked: {} payload items match existing entries; writing them would create sibling duplicates.\n{}\n\
                 pick one explicitly:\n\
                 \x20 1) attach under the same-topic entry: share-import <file> --parent <short-id> --go\n\
                 \x20 2) merge into one (update > merge > attach > store):\n\
                 \x20      share-import <file> --go --force, then remember \"<merged>\" --merge-ids \"<old-id>,<new-id>\"\n\
                 \x20 3) confirm it is a new fact and should sit as a sibling: share-import <file> --go --force",
                conflicts.len(),
                lines.join("\n")
            );
        }
    }
    let new_ids: Vec<String> = payload
        .items
        .iter()
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect();
    let (parents, reattached, orphaned) =
        crate::share::remap_parents(&payload.items, &new_ids, &parent)?;
    let mut entries = Vec::with_capacity(payload.items.len());
    let mut skipped = 0usize;
    for (i, it) in payload.items.iter().enumerate() {
        if it.content.trim().is_empty() {
            skipped += 1;
            continue;
        }
        it.metadata.validate()?;
        crate::memory::model::metadata::validate_extra_fields(&it.unknown_fields)?;
        let kind = it.kind.trim().to_lowercase();
        let parsed_kind = Kind::try_from_str(&kind).ok_or_else(|| anyhow!("unsupported_metadata: unknown imported memory kind"))?;
        let importance = match it.importance.trim() {
            "important" => "important",
            _ => "trivial",
        };
        let created_at = if it.created_at.trim().is_empty() {
            now_stamp()
        } else {
            it.created_at.clone()
        };
        let updated_at = if it.updated_at.trim().is_empty() {
            created_at.clone()
        } else {
            it.updated_at.clone()
        };
        entries.push(MemoryEntry {
            metadata: crate::memory::model::MemoryMeta { verification: None, ..it.metadata.clone() },
            unknown_fields: it.unknown_fields.clone(),
            supersedes: it.supersedes.clone(),
            superseded_by: it.superseded_by.clone(),
            see_also: it.see_also.clone(),
            id: new_ids[i].clone(),
            kind: parsed_kind,
            tags: it.tags.clone(),
            title: it.title.clone(),
            content: it.content.clone(),
            // Own as this machine's account: import becomes local memory (do not inherit the sharer's user, or server routing breaks)
            user: current_user(),
            computer: String::new(),
            project: String::new(),
            device: device_tag(),
            modified_by: device_tag(),
            created_at,
            updated_at,
            emotion: -1.0,
            parent_id: parents[i].clone(),
            importance: importance.to_owned(),
        });
    }
    let relation_ids: HashMap<String,String> = payload.items.iter().zip(new_ids.iter())
        .filter(|(item,_)| !item.content.trim().is_empty()).map(|(item,id)| (item.id.clone(),id.clone())).collect();
    remap_relations(&mut entries,&relation_ids)?;
    let report = ImportReport {
        imported: entries.len(),
        skipped,
        duplicates: 0,
        reattached,
        orphaned,
    };
    if entries.is_empty() {
        return Ok(report);
    }
    for entry in &entries {
        crate::metadata_gate::ensure_write(&store, entry)?;
        crate::metadata_gate::ensure_sources(&keys, &store, entry)?;
    }
    let stored = entries
        .iter()
        .map(|e| MemoryEngine::seal(&keys, embedder, e, &e.user))
        .collect::<Result<Vec<_>>>()?;
    store.import_batch(&stored)?;
    // Auto-sync after write: same as App::auto_sync (existing env assembly entry)
    if autosync_active() && remote_configured() {
        if let Err(e) =
            crate::sync::build_remote_from_env().and_then(|remote| sync_all(&keys, &store, &remote))
        {
            eprintln!("warning: auto-sync failed (saved locally; retry later): {e}");
        }
    }
    Ok(report)
}

/// SQLite consistent snapshot, including committed WAL; dest must be a new file, never overwrite existing data.
pub fn backup_db(dest: &std::path::Path) -> Result<PathBuf> {
    crate::input_error::validate_output_parent(dest)?;
    let src = database_path(&data_dir())?;
    backup_database(&src, dest)
}

pub(crate) fn backup_database(src: &std::path::Path, dest: &std::path::Path) -> Result<PathBuf> {
    backup_database_policy(src,dest,true)
}

pub(crate) fn backup_database_policy(src: &std::path::Path, dest: &std::path::Path, strip_grants: bool) -> Result<PathBuf> {
    crate::input_error::validate_output_parent(dest)?;
    let connection =
        rusqlite::Connection::open_with_flags(src, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let target = dest
        .to_str()
        .ok_or_else(|| anyhow!("backup path must be valid UTF-8"))?;
    // Exclusively create an empty dest first; SQLite VACUUM INTO can write an empty file.
    // Reject same-path, existing backup, directories, so we never overwrite the live library or a user file.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(dest)?;
    let snapshot = (|| -> Result<()> {
        connection.execute("VACUUM INTO ?1", rusqlite::params![target])?;
        let backup = rusqlite::Connection::open(dest)?;
        let has_grants = backup
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='access_grants'")?
            .exists([])?;
        if has_grants && strip_grants {
            backup.execute_batch("PRAGMA secure_delete=ON; DELETE FROM access_grants; VACUUM;")?;
        }
        Ok(())
    })();
    if let Err(error) = snapshot {
        if let Err(cleanup) = std::fs::remove_file(dest) {
            anyhow::bail!("backup failed: {error}; failed to clean incomplete backup: {cleanup}");
        }
        return Err(error);
    }
    Ok(dest.to_path_buf())
}

/// Existing-library analysis (read-only; does not touch the store).
pub fn defrag_report(min: f32, top: usize) -> Result<crate::memory::defrag::Report> {
    let app = App::open()?;
    let list = tree_scope_list(&app.store.all(false)?);
    require_candidates_ready(&app.store, &list)?;
    crate::memory::defrag::analyze(&list, min).map(|mut r| {
        r.clusters.truncate(top);
        r
    })
}

/// Unified tree-view scope (2026-09-20): drop trivia and tombstones, and clear parent when the parent is trivia/deleted.
///
/// Why: inject §3.4 says trivia goes to the diary only; `tree` / `defrag` / `tree-cure`
/// each filtered differently (tree once reported 23 roots, defrag 27). This fn is the shared source:
/// orphans become roots after the drop; important subtrees are unchanged.
///
/// Caller args: `tree` uses `all(true)` (includes tombstones, to look up titles), so this also filters `deleted`;
/// `defrag` uses `all(false)` (already filtered); a second filter is harmless.
pub fn tree_scope_list(
    all: &[crate::memory::model::StoredMemory],
) -> Vec<crate::memory::model::StoredMemory> {
    use std::collections::HashSet;
    let out_of_tree: HashSet<&str> = all
        .iter()
        .filter(|m| m.deleted || m.local_importance == "trivial")
        .map(|m| m.id.as_str())
        .collect();
    let mut list: Vec<crate::memory::model::StoredMemory> = all
        .iter()
        .filter(|m| !m.deleted && m.local_importance != "trivial")
        .cloned()
        .collect();
    for m in list.iter_mut() {
        if !m.local_parent_id.is_empty() && out_of_tree.contains(m.local_parent_id.as_str()) {
            m.local_parent_id.clear();
        }
    }
    list
}

// ── tree health (orphan-leaf roots attach under an outline) ──

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct RootStat {
    pub id: String,
    pub title: String,
    pub descendants: usize,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CureSuggest {
    pub orphan: NodeRef,
    pub target: NodeRef,
    pub target_tree: NodeRef,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct TreeCureReport {
    pub roots: Vec<RootStat>,
    pub lone_roots: usize,
    pub suggests: Vec<CureSuggest>,
}

/// Obtain a tree maintenance proposal from Core; applying it remains public.
/// P0-2: pass explicit query-log --good counts; Core no longer reads recall_count.
pub fn float_up_candidates(
    all: &[crate::memory::model::StoredMemory],
    min_hits: i64,
    good_counts: &HashMap<String, i64>,
) -> Result<Vec<(String, String)>> {
    crate::core_sdk::execute(
        "tree_float",
        serde_json::json!({"snapshots":crate::core_sdk::metadata_snapshots(all), "min_hits":min_hits, "good_counts":good_counts}),
    )
}

#[derive(Debug, Serialize)]
pub struct TreeFloatItem {
    pub id: String,
    pub title: String,
    pub good_marks: i64,
    pub old_parent: String,
    pub old_parent_title: String,
    pub new_parent: String,
    pub new_parent_title: String,
}

#[derive(Debug, Serialize)]
pub struct TreeFloatReport {
    pub items: Vec<TreeFloatItem>,
    pub applied: usize,
}

impl App {
    /// Tree-health report (read-only): root-size bill + orphan-leaf attach suggestions.
    ///
    /// Ask the private Core for attachment suggestions for orphan roots.
    /// Orphan-leaf roots are not matched to each other (same-topic merge is defrag's cluster bill).
    pub fn tree_cure(&self, top: usize) -> Result<TreeCureReport> {
        self.tree_cure_with_min(top, 0.50)
    }

    /// Ask Core for tree adjustments; `go` applies the returned parent changes and syncs.
    /// P0-2: candidates float on explicit query-log --good marks (>= min_hits,
    /// strictly above the parent's marks), never on recall_count.
    pub fn tree_float(&self, go: bool, min_hits: i64) -> Result<TreeFloatReport> {
        let all = self.store.all(false)?;
        require_candidates_ready(&self.store, &all)?;
        let good_counts = self
            .store
            .query_good_counts(chrono::Utc::now().timestamp())?;
        let cands = float_up_candidates(&all, min_hits, &good_counts)?;
        let mut items = Vec::new();
        for (child_id, new_parent) in &cands {
            let Some(m) = all.iter().find(|s| &s.id == child_id) else {
                continue;
            };
            let title_of = |id: &str| -> String {
                all.iter()
                    .find(|s| s.id == id)
                    .map(|s| {
                        if s.local_title.is_empty() {
                            short_id(id)
                        } else {
                            s.local_title.clone()
                        }
                    })
                    .unwrap_or_else(|| short_id(id))
            };
            items.push(TreeFloatItem {
                id: m.id.clone(),
                title: title_of(&m.id),
                good_marks: good_counts.get(&m.id).copied().unwrap_or(0),
                old_parent: m.local_parent_id.clone(),
                old_parent_title: title_of(&m.local_parent_id),
                new_parent: new_parent.clone(),
                new_parent_title: title_of(new_parent),
            });
        }
        if !go {
            return Ok(TreeFloatReport { items, applied: 0 });
        }
        let applied = self.store.write_transaction(|| {
            let current = self.store.all(false)?;
            for (child_id, _) in &cands {
                if let Some(row) = current.iter().find(|row| &row.id == child_id) {
                    crate::metadata_gate::ensure_write(&self.store, &MemoryEngine::open(&self.keys, row)?)?;
                }
            }
            let mut applied = 0;
            for (child_id, new_parent) in &cands {
                if reparent(&self.keys, &self.store, child_id, new_parent).is_ok() {
                    applied += 1;
                }
            }
            Ok(applied)
        })?;
        self.auto_sync();
        Ok(TreeFloatReport { items, applied })
    }

    /// Request tree suggestions with a user-selected similarity floor.
    pub fn tree_cure_with_min(&self, top: usize, min_sim: f32) -> Result<TreeCureReport> {
        let candidates = self.store.all(false)?;
        require_candidates_ready(&self.store, &candidates)?;
        respire_core_sdk::execute(
            "tree_cure",
            serde_json::json!({
                "snapshots":respire_core_sdk::metadata_snapshots(&candidates), "top":top, "min":min_sim,
            }),
        )
    }
}

// ── tree deepen (flat fat root → root / sub-outline / leaf) ──

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct DeepenPlan {
    /// Proposed sub-outlines under the selected root.
    pub sub_roots: Vec<DeepenSubRoot>,
    /// Leaves that did not cluster (stay put, not under a sub-outline)
    pub leftovers: Vec<NodeRef>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct DeepenSubRoot {
    pub title: String,
    pub member_ids: Vec<String>,
    pub member_titles: Vec<String>,
}

/// Fat-root deepen plan (read-only): request grouping suggestions from the private Core,
/// and return material for the user to name the proposed sub-outlines.
pub fn deepen_plan(
    store: &LocalStore,
    root_prefix: &str,
    min_sim: f32,
) -> Result<(String, DeepenPlan)> {
    let candidates = store.all(false)?;
    let root_id = resolve_prefix(&candidates, root_prefix)?;
    let direct: HashSet<&str> = candidates.iter()
        .filter(|entry| entry.local_parent_id == root_id)
        .map(|entry| entry.id.as_str()).collect();
    let mut descendants = HashSet::new();
    let mut pending: Vec<&str> = direct.iter().copied().collect();
    while let Some(parent) = pending.pop() {
        for entry in candidates.iter().filter(|entry| entry.local_parent_id == parent) {
            if descendants.insert(entry.id.as_str()) {
                pending.push(entry.id.as_str());
            }
        }
    }
    // Core's deepen contract requires at least 15 children and a mostly flat root.
    if direct.len() < 15 || descendants.len() * 3 > direct.len() * 2 {
        return Err(crate::input_error::InputError(format!(
            "this root is not flat ({} direct children, {} in the grandchild chain) \u{2014} hierarchy already exists or too few entries to deepen",
            direct.len(), descendants.len(),
        )).into());
    }
    require_candidates_ready(store, &candidates)?;
    respire_core_sdk::execute(
        "deepen_plan",
        serde_json::json!({
            "snapshots":respire_core_sdk::metadata_snapshots(&candidates), "root":root_prefix, "min":min_sim,
        }),
    )
}

/// Apply deepen: write the AI-chosen sub-outline titles. spec.title = sub-outline title (sub_roots order).
/// Per sub-outline: create a child under root → move cluster members under it. Returns (sub-outlines created, members moved).
pub fn deepen_apply<E: crate::memory::search::Embedder>(
    keys: &crate::memory::SessionKeys,
    embedder: &E,
    store: &LocalStore,
    root_id: &str,
    plan: &DeepenPlan,
    titles: &[String],
) -> Result<(usize, usize)> {
    if titles.len() != plan.sub_roots.len() {
        anyhow::bail!(
            "title count {} != sub-root count {} \u{2014} supply them in plan order",
            titles.len(),
            plan.sub_roots.len()
        );
    }
    let (built, moved) = store.write_transaction(|| {
        let all = store.all(true)?;
        let root = all.iter().find(|m| m.id == root_id)
            .ok_or_else(|| anyhow!("root does not exist: {root_id}"))?;
        for mid in plan.sub_roots.iter().flat_map(|sub| &sub.member_ids) {
            if let Ok(full) = resolve_prefix(&all, mid) {
                if let Some(row) = all.iter().find(|row| row.id == full && !row.deleted) {
                    crate::metadata_gate::ensure_write(store, &MemoryEngine::open(keys, row)?)?;
                }
            }
        }
        let user = root.user.clone();
        let stamp = now_stamp();
        let mut built = 0usize;
        let mut moved = 0usize;
        for (sub, title) in plan.sub_roots.iter().zip(titles) {
            let node = MemoryEntry {
                metadata: Default::default(),
                unknown_fields: Default::default(),
                supersedes: String::new(),
                superseded_by: String::new(),
                see_also: Vec::new(),
                id: uuid::Uuid::new_v4().to_string(),
                kind: Kind::Context,
                tags: {
                    let mut t = root.local_tags.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ToOwned::to_owned).collect::<Vec<_>>();
                    t.push("\u{5b50}\u{7eb2}".to_owned());
                    t
                },
                title: title.clone(),
                content: format!("sub-outline of `{}` \u{2014} absorbs {} same-topic entries (auto-outline from tree-deepen 2026-09-06).", root.local_title, sub.member_ids.len()),
                user: user.clone(),
                computer: root.local_computer.clone(),
                device: device_tag(),
                modified_by: device_tag(),
                project: root.local_project.clone(),
                created_at: stamp.clone(),
                updated_at: stamp.clone(),
                emotion: -1.0,
                parent_id: root_id.to_owned(),
                importance: "normal".to_owned(),
            };
            let stored = MemoryEngine::seal(keys, embedder, &node, &user)?;
            store.put(&stored)?;
            built += 1;
            for mid in &sub.member_ids {
                if reparent(keys, store, mid, &node.id).is_ok() {
                    moved += 1;
                }
            }
        }
        Ok((built, moved))
    })?;
    // Write-path gate autosync_active(): always off in tests — otherwise fixtures would be pushed to the real cloud
    // (proven 2026-09-16: 14 test rows polluted the cloud).
    if autosync_active() && remote_configured() {
        let _ =
            crate::sync::build_remote_from_env().and_then(|remote| sync_all(keys, store, &remote));
    }
    Ok((built, moved))
}

// ── split engine (CLI emits material, AI decides, CLI executes) ──

#[derive(Debug, Serialize)]
pub struct SplitMaterial {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub tags: Vec<String>,
    pub parent_id: String,
    pub created_at: String,
    pub content: String,
    pub content_len: usize,
    pub ancestors: Vec<NodeRef>,
}

/// Split material: original full text + ancestor chain + owning tree — the AI reads this and writes the split spec.
pub fn split_material(entry: &MemoryEntry, ancestors: &[NodeRef]) -> SplitMaterial {
    SplitMaterial {
        id: entry.id.clone(),
        title: entry.title.clone(),
        kind: entry.kind.as_str().to_owned(),
        tags: entry.tags.clone(),
        parent_id: entry.parent_id.clone(),
        created_at: entry.created_at.clone(),
        content_len: entry.content.chars().count(),
        content: entry.content.clone(),
        ancestors: ancestors.to_vec(),
    }
}

#[derive(Debug, Deserialize)]
pub struct SplitOp {
    /// Child title (≤20 chars, one line on the tree)
    pub title: String,
    /// Child body (self-contained: cause + action + effect; readable three months later alone)
    pub content: String,
    /// One of the seven kinds
    pub kind: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Attach under this outline or an explicit parent ID/prefix.
    #[serde(default = "default_split_parent")]
    pub parent: String,
}

fn default_split_parent() -> String {
    "\u{7eb2}".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct SplitSpec {
    /// Optionally convert the original entry to an outline with a summary.
    #[serde(default)]
    pub summary: Option<String>,
    pub items: Vec<SplitOp>,
}

/// Execute the AI split spec: resolve each parent and seal the children,
/// if the original has a summary it becomes an outline (body replaced, resealed). Returns children actually split.
pub fn split_exec<E: crate::memory::search::Embedder>(
    keys: &crate::memory::SessionKeys,
    embedder: &E,
    store: &LocalStore,
    entry: &MemoryEntry,
    spec: &SplitSpec,
) -> Result<usize> {
    if spec.items.is_empty() {
        return Err(crate::input_error::InputError("split spec has no children".into()).into());
    }
    if spec.summary.is_none() && spec.items.len() == 1 {
        return Err(crate::input_error::InputError(
            "a single child without keeping the outline is a rewrite \u{2014} edit instead of split".into()
        ).into());
    }
    crate::metadata_gate::ensure_write(store, entry)?;
    let user = entry.user.clone();
    let all = store.all(true)?;
    for (i, op) in spec.items.iter().enumerate() {
        let parent_id = if op.parent.is_empty() || op.parent == "\u{7eb2}" {
            entry.id.clone()
        } else {
            resolve_prefix(&all, &op.parent)?
        };
        let stamp = now_stamp();
        let child = MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            id: uuid::Uuid::new_v4().to_string(),
            kind: Kind::try_from_str(&op.kind.trim().to_lowercase()).ok_or_else(|| anyhow!("unsupported_metadata: unknown memory kind"))?,
            tags: {
                let mut t = op.tags.clone();
                t.push("\u{62c6}\u{5206}".to_owned());
                t
            },
            title: op.title.clone(),
            content: op.content.clone(),
            user: user.clone(),
            computer: entry.computer.clone(),
            device: device_tag(),
            modified_by: device_tag(),
            project: entry.project.clone(),
            created_at: stamp.clone(),
            updated_at: stamp,
            emotion: entry.emotion,
            parent_id,
            importance: entry.importance.clone(),
        };
        let stored = MemoryEngine::seal(keys, embedder, &child, &user)?;
        store.put(&stored)?;
        let _ = i;
    }
    if let Some(summary) = &spec.summary {
        let mut e = entry.clone();
        e.content = summary.clone();
        e.updated_at = store.edit_stamp(&entry.id)?;
        let stored = MemoryEngine::seal(keys, embedder, &e, &user)?;
        store.put(&stored)?;
    }
    // Sync after split: write-path gate — old impl only looked at remote_configured(); after the user turned auto-sync off
    // split still hit the network, and test fixtures were pushed to the real cloud (proven 2026-09-16).
    if autosync_active() && remote_configured() {
        let _ =
            crate::sync::build_remote_from_env().and_then(|remote| sync_all(keys, store, &remote));
    }
    Ok(spec.items.len())
}

// ── small helpers ──

pub fn open_store() -> Result<LocalStore> {
    validate_client_config()?;
    crate::snapshot::ensure_no_incomplete_restore(&data_dir())?;
    open_store_with_profile().map(|(_, store)| store)
}

/// Return the identity captured for this exact connection, not a later config read.
pub fn open_store_with_profile() -> Result<(PathBuf, LocalStore)> {
    validate_client_config()?;
    let root = data_dir();
    crate::snapshot::ensure_no_incomplete_restore(&root)?;
    check_runtime_profile(&root)?;
    respire_core_sdk::set_index_root(&root)?;
    let db = database_path(&root)?;
    let store = if RUNTIME_PROFILE.get().is_some() {
        LocalStore::open_existing(&db)
    } else {
        LocalStore::open(&db)
    }?;
    respire_core_sdk::profiles::set_active(store.active_selection()?);
    crate::embedding::install_transport()?;
    Ok((root, store))
}

/// Bootstrap under actual runtime library ownership without opening business access.
pub fn open_runtime_store(ownership:&crate::lock::LibraryLock)->Result<(LocalStore,Option<String>)> {
    let root=data_dir();check_runtime_profile(&root)?;
    anyhow::ensure!(ownership.protects(&root)?,"runtime bootstrap requires matching library ownership");
    let expected=crate::snapshot::runtime_bootstrap_target(&root)?;
    respire_core_sdk::set_index_root(&root)?;
    let store=LocalStore::open(&database_path(&root)?)?;
    if let Some(id)=expected.as_ref() {
        store.verify_sqlite_integrity()?;
        anyhow::ensure!(store.snapshot_quarantine_id()?.as_ref()==Some(id),"opened library does not match the restored snapshot transaction");
    }
    respire_core_sdk::profiles::set_active(store.active_selection()?);
    crate::embedding::install_transport()?;
    Ok((store,expected))
}

/// Initialize the runtime's owned library after normal service is restored.
/// Disabled startup deliberately leaves a new database uncreated.
pub fn initialize_runtime_store() -> Result<LocalStore> {
    validate_client_config()?;
    anyhow::ensure!(!service_paused(), "database initialization requires normal service");
    let root = data_dir();
    crate::snapshot::ensure_no_incomplete_restore(&root)?;
    check_runtime_profile(&root)?;
    respire_core_sdk::set_index_root(&root)?;
    LocalStore::open(&database_path(&root)?)
}

/// New libraries use rsrs.db; opening an existing library never renames it.
pub fn database_path(root: &Path) -> Result<PathBuf> {
    let current = root.join("rsrs.db");
    let legacy = root.join("onememory.db");
    anyhow::ensure!(!(current.exists() && legacy.exists()),
        "both rsrs.db and the legacy database exist; select the intended library explicitly");
    Ok(if current.exists() || !legacy.exists() { current } else { legacy })
}

/// Read the selected source as one committed snapshot, without creating plaintext files.
/// Sunk from the client-side login_transaction module (WP-2c): the engine-side service
/// tests and the login flow both read this committed snapshot; the client module
/// re-exports the call through `crate::service::local_snapshot`.
pub fn local_snapshot(source_secret: Option<&str>) -> Result<String> {
    let session = crate::auth::read_session_json()?;
    let user = session["user"].as_str().unwrap_or("local");
    let alias = session["keyring_account"].as_str().unwrap_or(user);
    let version = session["vault_version"].as_i64().unwrap_or(1);
    let password = if version == 1 {
        source_secret.map(str::to_owned)
            .or_else(|| session["pass"].as_str().map(str::to_owned))
            .or_else(|| crate::keystore::load_login_pass(alias)).unwrap_or_default()
    } else { String::new() };
    let keys = crate::auth::unlock_session_keys(&session, &password,
        if version == 1 { None } else { source_secret }, alias)?;
    let directory = crate::service::data_dir();
    let path = crate::service::database_path(&directory)?;
    anyhow::ensure!(path.is_file(), "selected source has no local library; nothing was migrated");
    let database = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = database.prepare("SELECT id,ciphertext,nonce,COALESCE(parent_id,'') FROM memories WHERE COALESCE(deleted,0)=0 ORDER BY id")?;
    let mut rows = statement.query([])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        let mut stored = crate::memory::model::StoredMemory::new_pending(row.get(0)?, String::new());
        stored.ciphertext = row.get(1)?;
        stored.nonce = row.get(2)?;
        stored.local_parent_id = row.get(3)?;
        entries.push(crate::memory::MemoryEngine::open(&keys, &stored)
            .context("source record cannot be decrypted; original library was preserved")?);
    }
    Ok(serde_json::to_string(&entries)?)
}

pub fn home_dir() -> Result<PathBuf> {
    if let Ok(home) = crate::env::var("HOME") {
        if !home.trim().is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))
}

/// Auto title: untitled entries take the first body line (strip markers/time prefix), 20 chars — the tree no longer shows a blank title.
pub fn derive_title(content: &str) -> String {
    let mut t = content.trim();
    for p in [
        "\u{3010}\u{65e5}\u{8bb0}\u{3011}",
        "\u{3010}\u{6d41}\u{6c34}\u{3011}",
        "\u{3010}\u{7ecf}\u{9a8c}\u{3011}",
        "\u{3010}\u{5751}\u{3011}",
        "\u{3010}\u{6559}\u{8bad}\u{3011}",
        "\u{3010}\u{6280}\u{80fd}\u{3011}",
    ] {
        if let Some(rest) = t.strip_prefix(p) {
            t = rest.trim_start();
        }
    }
    let first = t.lines().next().unwrap_or("").trim();
    let toks: Vec<&str> = first.splitn(3, ' ').collect();
    let s = if toks.len() == 3
        && toks[0].len() == 10
        && toks[0].as_bytes().get(4) == Some(&b'-')
        && toks[1].contains(':')
    {
        format!("{} {}", toks[1], toks[2])
    } else {
        first.to_owned()
    };
    // First sentence (up to period/semicolon/newline), 40 chars — no more hard 20-char cut that made duplicate titles
    let sent: String = s
        .split(['\u{3002}', '\u{ff1b}', '\n'])
        .next()
        .unwrap_or(&s)
        .trim()
        .chars()
        .take(40)
        .collect();
    if sent.is_empty() {
        "(untitled)".to_owned()
    } else {
        sent
    }
}

pub fn now_stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn current_user() -> String {
    crate::env::var("RSRS_USER").unwrap_or_else(|_| "local".to_owned())
}

/// Filter candidates: trim, drop empty, take the first non-empty (an env var set to empty is also dropped —
/// the old impl did not filter, COMPUTERNAME="" became an empty hostname; fixed 2026-09-20)
fn first_non_empty<I: IntoIterator<Item = String>>(vals: I) -> Option<String> {
    vals.into_iter()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
}

/// Hostname. Four-tier order: /etc/hostname (Linux authoritative static name) → COMPUTERNAME (Windows)
/// → HOSTNAME (env, only on a login shell) → syscall gethostname (fallback).
/// Fourth tier added 2026-09-20: macOS has no /etc/hostname, and a GUI-launched process does not inherit
/// HOSTNAME (launchd does not set it); without the syscall the first tiers all missed and became unknown-host —
/// a user screenshot showed mac as unknown-host/mac when HOSTNAME/COMPUTERNAME were unset.
pub fn host_name() -> Option<String> {
    first_non_empty([
        std::fs::read_to_string("/etc/hostname").unwrap_or_default(),
        crate::env::var("COMPUTERNAME").unwrap_or_default(),
        crate::env::var("HOSTNAME").unwrap_or_default(),
        whoami::hostname().unwrap_or_default(),
    ])
}

/// Device tag (hostname/platform): remember/import fills computer when empty,
/// so recall across devices can tell which machine a path belongs to — the same path is not always valid on another device (frozen 2026-09-12)
pub fn device_tag() -> String {
    let host = host_name().unwrap_or_else(|| "unknown-host".to_owned());
    let os = if cfg!(target_os = "windows") {
        "win"
    } else if cfg!(target_os = "macos") {
        "mac"
    } else {
        "linux"
    };
    format!("{host}/{os}")
}

pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

pub fn split_tags(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn mask_secret(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        "****".to_owned()
    } else {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}\u{2026}{tail}")
    }
}

/// 8-char prefix → full id (exact id first, then exact outline title, then unique prefix; zero/many hits error).
/// Prefix compare is by chars (Chinese/multibyte ids are safe — [0..8] bytes would panic on a multibyte char; hit 2026-09-08).
pub fn resolve_prefix(all: &[crate::memory::model::StoredMemory], prefix: &str) -> Result<String> {
    // list/show print 🆔 with a # prefix (e.g. #dd9b4ade); paste as-is — this entry strips #
    let prefix = prefix.trim_start_matches('#');
    if let Some(m) = all.iter().find(|s| s.id == prefix && !s.deleted) {
        return Ok(m.id.clone());
    }
    // Attach by outline title: unique exact title hit (catalog outline names are attach names; the AI need not look up an id first)
    let by_title: Vec<String> = all
        .iter()
        .filter(|s| !s.deleted && s.local_title == prefix)
        .map(|s| s.id.clone())
        .collect();
    if by_title.len() == 1 {
        return Ok(by_title[0].clone());
    }
    let chars: Vec<char> = prefix.chars().collect();
    let p8: String = chars.iter().take(8).collect();
    let hits: Vec<String> = all
        .iter()
        .filter(|s| !s.deleted && short_id(&s.id) == p8)
        .map(|s| s.id.clone())
        .collect();
    match hits.len() {
        1 => Ok(hits[0].clone()),
        0 => Err(crate::input_error::InputError(format!("no such entry: {prefix}")).into()),
        n => Err(crate::input_error::InputError(format!("prefix is not unique ({n} hits): {prefix}")).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_bump_threshold_reset() -> anyhow::Result<()> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("om-mnt-{nonce}"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("maintenance.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({ "resort_threshold": 3 }))?,
        )?;
        assert_eq!(counter_bump(&path)?, (1, 3));
        assert_eq!(counter_bump(&path)?, (2, 3));
        assert_eq!(counter_bump(&path)?, (3, 3)); // at threshold (caller alerts)
        assert_eq!(counter_peek(&path), (3, 3));
        counter_reset(&path, "2026-09-10T00:00:00.000Z")?;
        assert_eq!(counter_peek(&path), (0, 3));
        counter_set_threshold(&path, 50)?;
        assert_eq!(counter_bump(&path)?, (1, 50));
        assert!(counter_set_threshold(&path, 0).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn split_tags_basic() {
        assert_eq!(split_tags("a, b,,c"), vec!["a", "b", "c"]);
        assert!(split_tags("").is_empty());
    }

    /// Empty-value filter: env set to empty/whitespace must be dropped (old impl did not filter, empty hostname)
    #[test]
    fn first_non_empty_skips_blank() {
        assert_eq!(
            first_non_empty(["".to_owned(), "  ".to_owned(), "real".to_owned()]),
            Some("real".to_owned())
        );
        assert_eq!(
            first_non_empty(["  padded  ".to_owned()]),
            Some("padded".to_owned())
        );
        assert_eq!(first_non_empty([String::new()]), None);
        assert_eq!(first_non_empty(Vec::<String>::new()), None);
    }

    /// Syscall fallback: simulate mac — no /etc/hostname, no HOSTNAME/COMPUTERNAME,
    /// when earlier tiers are blank gethostname must supply the name (dropping the whoami tier fails)
    #[test]
    fn syscall_fallback_used_when_earlier_tiers_blank() -> anyhow::Result<()> {
        let syscall = whoami::hostname().map_err(|e| anyhow!("hostname: {e}"))?;
        let host = first_non_empty(["".to_owned(), "".to_owned(), "".to_owned(), syscall.clone()]);
        assert_eq!(
            host.as_deref(),
            Some(syscall.as_str()),
            "syscall tier unused when first three tiers are blank"
        );
        assert!(!host
            .ok_or_else(|| anyhow!("missing host"))?
            .trim()
            .is_empty());
        Ok(())
    }

    /// Syscall fallback: a real host always has a hostname (/etc/hostname or env or gethostname),
    /// so device_tag must not fall to unknown-host — regression for mac without /etc/hostname and without HOSTNAME
    #[test]
    fn device_tag_never_unknown_on_real_host() -> anyhow::Result<()> {
        let host = host_name();
        assert!(
            host.is_some(),
            "all four tiers blank: syscall fallback failed"
        );
        assert!(
            !host
                .ok_or_else(|| anyhow!("missing host"))?
                .trim()
                .is_empty(),
            "hostname must not be blank"
        );
        let tag = device_tag();
        assert!(
            !tag.starts_with("unknown-host"),
            "device_tag fell back to unknown-host: {tag}"
        );
        assert!(
            tag.ends_with("/linux") || tag.ends_with("/mac") || tag.ends_with("/win"),
            "platform suffix unexpected: {tag}"
        );
        Ok(())
    }

    /// Time lower bound: a date becomes that day's midnight, RFC3339 kept, empty string errors
    #[test]
    fn normalize_since_rules() -> anyhow::Result<()> {
        assert_eq!(normalize_since("2026-09-20")?, "2026-09-20T00:00:00Z");
        assert_eq!(normalize_since("  2026-09-20  ")?, "2026-09-20T00:00:00Z");
        assert_eq!(
            normalize_since("2026-09-20T04:54:18.486Z")?,
            "2026-09-20T04:54:18.486Z"
        );
        assert!(normalize_since("").is_err(), "empty string must error");
        assert!(
            normalize_since("   ").is_err(),
            "whitespace-only must error"
        );
        Ok(())
    }

    /// Later bound: both given → max; one given → that one; neither → 1970 epoch (no filter).
    /// This is the real §3.8 case: when resort_at is later than explicit --since, use resort_at.
    #[test]
    fn later_bound_picks_later() {
        let a = Some("2026-09-19T00:00:00Z".to_owned());
        let b = Some("2026-09-20T04:54:18.486Z".to_owned());
        assert_eq!(
            later_bound(a.clone(), b.clone()),
            "2026-09-20T04:54:18.486Z"
        );
        assert_eq!(
            later_bound(b.clone(), a.clone()),
            "2026-09-20T04:54:18.486Z"
        );
        assert_eq!(later_bound(a.clone(), None), "2026-09-19T00:00:00Z");
        assert_eq!(later_bound(None, b.clone()), "2026-09-20T04:54:18.486Z");
        assert_eq!(later_bound(None, None), "1970-01-01T00:00:00Z");
    }

    /// resort_at read/write loop: after counter_reset, resort_at reads back the same value;
    /// no file / no key → None (list --since-resort then falls back to no filter)
    #[test]
    fn resort_at_roundtrip() -> anyhow::Result<()> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("om-resort-at-{nonce}"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("maintenance.json");
        assert!(counter_reset(&path, "").is_ok());
        // Write empty stamp → resort_at treated as missing (filter drops empty)
        let v = std::fs::read_to_string(&path)?;
        assert!(serde_json::from_str::<serde_json::Value>(&v)?["resort_at"].is_string());
        counter_reset(&path, "2026-09-20T04:54:18.486Z")?;
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(v["resort_at"], "2026-09-20T04:54:18.486Z");
        assert_eq!(v["writes_since_resort"], 0);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn mask_secret_shape() {
        assert_eq!(mask_secret("abcdefghijkl"), "abcd\u{2026}ijkl");
        assert_eq!(mask_secret("short"), "****");
    }

    /// Whole-library bound: `--since 1900` must be earlier than every real created_at (RFC3339 lexicographic compare),
    /// so it equals no filter — this is how "resort the whole library" takes its set; no extra mode (frozen 2026-09-20).
    #[test]
    fn since_1900_equals_whole_library() -> anyhow::Result<()> {
        let bound = normalize_since("1900")?;
        assert_eq!(bound, "1900");
        // Lexicographic order is time order: a 1900 prefix is less than any 20xx/21xx RFC3339 stamp
        for ts in [
            "2026-09-20T05:01:50.121Z",
            "2026-09-20T04:22:18.093Z",
            "2000-01-01T00:00:00Z",
            "2100-01-01T00:00:00Z",
        ] {
            assert!(
                ts > bound.as_str(),
                "{ts} should be later than the 1900 bound"
            );
        }
        // Combined with --since-resort, 1900 must not hide resort_at (take the later one)
        assert_eq!(
            later_bound(Some(bound), Some("2026-09-20T04:54:18.486Z".to_owned())),
            "2026-09-20T04:54:18.486Z"
        );
        Ok(())
    }

    /// v4 session contract: when session.json only has wrapped_urk, has_local_keys must be true —
    /// the old impl looked at secret_key/secret, always false on v4, so offline local mode was judged "not connected"
    /// and kept prompting login (reported 2026-09-16). Offline without a token still counts as "local library unlocked".
    #[test]
    fn session_info_v4_recognizes_wrapped_urk_as_local_keys() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let saved_dir = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        // v4 shape: wrap material only, no user/token/plaintext keys (keygen output looks like this)
        std::fs::write(
            dir.path().join("session.json"),
            serde_json::to_vec(&serde_json::json!({
                "kdf_salt": "aabb",
                "wrapped_urk": "deadbeef",
                "urk_nonce": "ccdd",
                "vault_version": 4,
            }))?,
        )?;
        let si = session_info();
        assert!(si.has_session, "session.json present means has_session");
        assert!(
            si.has_local_keys,
            "v4 with only wrapped_urk still counts as local keys"
        );
        assert!(!si.has_token, "offline mode has no token");
        match saved_dir {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        Ok(())
    }

    #[test]
    fn resume_session_skips_the_form_when_the_wrap_exists() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let saved_dir = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::fs::write(
            dir.path().join("session.json"),
            serde_json::to_vec(&serde_json::json!({
                "user": "alice",
                "addr": "https://example.invalid",
                "kdf_salt": "aabb",
                "wrapped_urk": "deadbeef",
                "urk_nonce": "ccdd",
                "vault_version": 4,
            }))?,
        )?;
        let got = resume_session()?;
        match saved_dir {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        if got["resumed"] != true {
            anyhow::bail!("wrapped key should resume without a form");
        }
        if got["user"] != "alice" || got["addr"] != "https://example.invalid" {
            anyhow::bail!("resume lost user or addr: {got}");
        }
        if got.get("pass").is_some() || got.get("super").is_some() {
            anyhow::bail!("resume must not return secrets");
        }
        Ok(())
    }

    #[test]
    fn resume_session_fills_the_public_server_when_nothing_is_stored() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let saved_dir = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let got = resume_session()?;
        match saved_dir {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        if got["need_login"] != true {
            anyhow::bail!("empty profile should still need a login password");
        }
        if got["addr"] != DEFAULT_SERVER_ADDR {
            anyhow::bail!("empty profile addr was {}", got["addr"]);
        }
        Ok(())
    }

    #[test]
    fn malformed_client_config_is_rejected_without_overwrite() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let saved_dir = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let path = dir.path().join("client.json");
        std::fs::write(&path, b"[]")?;
        let result = set_cure_auto(true);
        match saved_dir {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        let error = result.err().context("array client config must be rejected")?;
        assert!(error.to_string().contains("must contain a JSON object"), "unexpected error: {error:#}");
        assert_eq!(std::fs::read(&path)?, b"[]");
        Ok(())
    }

    #[test]
    fn client_config_wrong_data_dir_type_is_rejected_without_overwrite() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let saved_dir = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let path = dir.path().join("client.json");
        std::fs::write(&path, br#"{"custom":"preserved","data_dir":123}"#)?;
        let result = set_cure_auto(true);
        match saved_dir {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        let error = result.err().context("wrong data_dir type must be rejected")?;
        assert_eq!(std::fs::read(&path)?, br#"{"custom":"preserved","data_dir":123}"#);
        assert!(error.to_string().contains("data_dir"), "unexpected error: {error:#}");
        Ok(())
    }

    #[test]
    fn subtree_members_collects_root_and_descendants() {
        let mk = |id: &str, parent: &str, deleted: bool| {
            let mut m = crate::memory::model::StoredMemory::new_pending(id.into(), "u".into());
            m.local_parent_id = parent.into();
            m.deleted = deleted;
            m
        };
        let all = vec![
            mk("aaaaaaaa-root", "", false),
            mk("bbbbbbbb-child", "aaaaaaaa-root", false),
            mk("cccccccc-grand", "bbbbbbbb-child", false),
            mk("dddddddd-other", "", false),
            mk("eeeeeeee-dead", "aaaaaaaa-root", true),
        ];
        let members = subtree_members(&all, "aaaaaaaa-root");
        assert!(members.contains("aaaaaaaa-root"));
        assert!(members.contains("bbbbbbbb-child"));
        assert!(members.contains("cccccccc-grand"));
        assert!(!members.contains("dddddddd-other"));
        // Tombstones stay out (search uses store.all(false) live rows); missing root → empty
        assert!(!members.contains("eeeeeeee-dead"));
        assert!(subtree_members(&all, "ffffffff-none").is_empty());
        // Cycles do not explode: root and child point at each other, stop at dedup
        let cyclic = vec![
            mk("aaaaaaaa-root", "bbbbbbbb-child", false),
            mk("bbbbbbbb-child", "aaaaaaaa-root", false),
        ];
        let m2 = subtree_members(&cyclic, "aaaaaaaa-root");
        assert!(m2.contains("aaaaaaaa-root") && m2.contains("bbbbbbbb-child"));
    }

    #[test]
    fn data_dir_config_roundtrip() -> anyhow::Result<()> {
        let real_client = dirs::home_dir()
            .ok_or_else(|| anyhow!("home dir missing"))?
            .join(".rsrs")
            .join("client.json");
        let before = std::fs::read(&real_client).ok();
        let iso = crate::test_lock::Isolate::new()?;
        let custom = iso.path().join("mem-test");
        std::fs::create_dir_all(&custom)?;
        let absolute = custom.to_string_lossy().to_string();
        set_data_dir(&absolute)?;
        assert_eq!(data_dir(), custom);
        assert!(
            iso.path().join("client.json").is_file(),
            "client.json was not written inside the isolated root"
        );
        set_data_dir("")?;
        assert_eq!(data_dir(), iso.path());
        {
            struct ModelRootEnv([(&'static str, Option<std::ffi::OsString>); 4]);
            impl Drop for ModelRootEnv {
                fn drop(&mut self) {
                    for (name, value) in &self.0 {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
            }
            let _restore = ModelRootEnv([
                "RSRS_DATA_DIR", "RSRS_M3_DIR", "ONEMEMORY_M3_DIR", "RESPIRE_M3_DIR",
            ].map(|name| (name, std::env::var_os(name))));
            for name in ["RSRS_M3_DIR", "ONEMEMORY_M3_DIR", "RESPIRE_M3_DIR"] {
                std::env::remove_var(name);
            }
            let models = iso.path().join("models/bge-m3");
            let roots = resolved_roots()?;
            assert!(roots.legacy_whole_isolation);
            assert_eq!(roots.asset_root, models);
            assert_eq!(crate::memory::bge::discovered_model_dir()?, models);
            let config_before = std::fs::read(iso.path().join("client.json"))?;
            for name in ["RSRS_DATA_DIR", "RSRS_M3_DIR"] {
                for invalid in ["", " ", "\t\r\n"] {
                    std::env::set_var("RSRS_DATA_DIR", iso.path());
                    std::env::set_var("RSRS_M3_DIR", &models);
                    std::env::set_var(name, invalid);
                    assert!(crate::memory::bge::default_user_model_dir().is_err(), "{name}");
                    assert!(crate::memory::bge::cpu_ort_cache_path().is_err(), "{name}");
                    assert!(crate::memory::bge::m3_model_dir().is_err(), "{name}");
                    assert!(crate::memory::bge::discovered_model_dir().is_err(), "{name}");
                    assert!(validate_client_config().is_err(), "{name}");
                    assert!(resolved_roots().is_err(), "{name}");
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                for name in ["RSRS_DATA_DIR", "RSRS_M3_DIR"] {
                    std::env::set_var("RSRS_DATA_DIR", iso.path());
                    std::env::set_var("RSRS_M3_DIR", &models);
                    std::env::set_var(name, std::ffi::OsString::from_vec(vec![0xff]));
                    assert!(crate::memory::bge::default_user_model_dir().is_err(), "{name}");
                    assert!(crate::memory::bge::cpu_ort_cache_path().is_err(), "{name}");
                    assert!(crate::memory::bge::m3_model_dir().is_err(), "{name}");
                    assert!(crate::memory::bge::discovered_model_dir().is_err(), "{name}");
                    assert!(validate_client_config().is_err(), "{name}");
                    assert!(resolved_roots().is_err(), "{name}");
                }
            }
            assert_eq!(std::fs::read(iso.path().join("client.json"))?, config_before);
        }
        assert_eq!(
            std::fs::read(&real_client).ok(),
            before,
            "test rewrote the real client.json"
        );
        Ok(())
    }

    #[test]
    fn resolve_prefix_rules() -> anyhow::Result<()> {
        let mut a =
            crate::memory::model::StoredMemory::new_pending("11111111-aaaa".into(), "u".into());
        a.local_title = "\u{7532}".into();
        let mut b =
            crate::memory::model::StoredMemory::new_pending("11111111-bbbb".into(), "u".into());
        b.local_title = "\u{4e59}".into();
        let mut c =
            crate::memory::model::StoredMemory::new_pending("22222222-cccc".into(), "u".into());
        c.local_title = "\u{4e19}".into();
        c.deleted = true;
        let all = vec![a, b, c];
        assert!(resolve_prefix(&all, "11111111").is_err()); // many hits
        assert!(resolve_prefix(&all, "22222222").is_err()); // deleted
        assert_eq!(resolve_prefix(&all, "11111111-aaaa")?, "11111111-aaaa");
        Ok(())
    }

    /// Regression lock (reported 2026-09-06): --parent with a short prefix must resolve to a full id,
    /// and a miss must really empty — no "warned standalone store but printed attach success" contradiction.
    #[test]
    fn parent_prefix_resolution_contract() -> anyhow::Result<()> {
        let mut p = crate::memory::model::StoredMemory::new_pending(
            "04a7be06-5ebd-4ba5-9da3-eb9a066ed2d5".into(),
            "u".into(),
        );
        p.local_title = "\u{56e0}".into();
        let all = vec![p];
        // Unique prefix hit → full id
        assert_eq!(
            resolve_prefix(&all, "04a7be06")?,
            "04a7be06-5ebd-4ba5-9da3-eb9a066ed2d5"
        );
        // Missing → Err (caller unwrap_or_default empties it; must not refill the original prefix)
        assert!(resolve_prefix(&all, "deadbeef").is_err());
        let dangling: String = resolve_prefix(&all, "deadbeef").unwrap_or_default();
        assert!(dangling.is_empty());
        Ok(())
    }

    fn test_entry(content: &str) -> MemoryEntry {
        MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            id: "test-1".into(),
            kind: Kind::Context,
            tags: vec![],
            title: "\u{6d4b}\u{6761}".into(),
            content: content.into(),
            user: "u".into(),
            computer: String::new(),
            project: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
            emotion: -1.0,
            parent_id: String::new(),
            importance: "normal".to_owned(),
            device: "test-dev".to_owned(),
            modified_by: "test-dev".to_owned(),
        }
    }

    /// Auto-sync switch contract: RSRS_NO_AUTOSYNC non-empty and not 0 means off (every write path must use this).
    #[test]
    fn autosync_disabled_by_env_is_off() {
        let _guard = crate::test_lock::guard();
        let saved = crate::env::var("RSRS_NO_AUTOSYNC").ok();
        std::env::set_var("RSRS_NO_AUTOSYNC", "1");
        assert!(!autosync_enabled(), "auto-sync must be off when set to 1");
        std::env::set_var("RSRS_NO_AUTOSYNC", "yes");
        assert!(!autosync_enabled(), "any non-zero value must turn it off");
        match saved {
            Some(v) => std::env::set_var("RSRS_NO_AUTOSYNC", v),
            None => std::env::remove_var("RSRS_NO_AUTOSYNC"),
        }
    }

    /// Split contract: attach children to the outline, reseal it, and preserve the body when no summary is supplied.
    /// Isolation: split_exec used to auto-sync at the end via remote_configured(), which reads the **real**
    /// ~/.rsrs/session.json — if the test machine is logged in, cloud data is pulled into the temp library,
    /// and the "two children" assert is polluted (2026-09-16: got 7 not 2). This test forces auto-sync off.
    #[test]
    fn split_exec_lands_children_and_summary() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let saved = crate::env::var("RSRS_NO_AUTOSYNC").ok();
        std::env::set_var("RSRS_NO_AUTOSYNC", "1");
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        let keys = crate::memory::SessionKeys::from_urk([7u8; 32])?;
        let embedder = crate::memory::search::HashingEmbedder::default();
        let mut entry = test_entry("\u{4e00}\u{5927}\u{5768}\u{6df7}\u{88c5}\u{5185}\u{5bb9}");
        entry.id = "11111111-parent".into();
        let stored0 = MemoryEngine::seal(&keys, &embedder, &entry, "u")?;
        store.put(&stored0)?;
        let spec = SplitSpec {
            summary: Some("\u{672c}\u{56de}\u{5408}\u{5ba1}\u{8ba1}\u{4e86} backend\u{ff08}\u{7eb2}\u{ff1a}\u{8be6}\u{60c5}\u{62c6}\u{89c1}\u{5b50}\u{679c}\u{ff09}".into()),
            items: vec![
                SplitOp {
                    title: "\u{2460}classes.py \u{5047} import".into(),
                    content: "\u{3010}\u{524d}\u{56e0}\u{3011}\u{5ba1}\u{8ba1}\u{53d1}\u{73b0}\u{3010}\u{884c}\u{4e3a}\u{3011}classes.py \u{91cd} import \u{4e0d}\u{5b58}\u{5728}\u{6a21}\u{5757}\u{3010}\u{540e}\u{679c}\u{3011}POST \u{5fc5}\u{4e94}\u{767e}\u{ff0c}\u{5220}\u{9664}\u{8be5}\u{6bb5}\u{5373}\u{6108}\u{3002}".into(),
                    kind: "skill".into(),
                    tags: vec!["audit".into()],
                    parent: "\u{7eb2}".into(),
                },
                SplitOp {
                    title: "\u{2461}admin \u{8c41}\u{514d}\u{7f3a}\u{5931}".into(),
                    content: "\u{3010}\u{884c}\u{4e3a}\u{3011}assignments.py update/archive \u{65e0}\u{8c41}\u{514d}\u{3010}\u{540e}\u{679c}\u{3011}\u{7ba1}\u{7406}\u{5458}\u{80fd}\u{770b}\u{4e0d}\u{80fd}\u{6539}\u{ff0c}\u{8865}\u{9f50}\u{4e00}\u{81f4}\u{6027}\u{3002}".into(),
                    kind: "decision".into(),
                    tags: vec![],
                    parent: "\u{7eb2}".into(),
                },
            ],
        };
        let n = split_exec(&keys, &embedder, &store, &entry, &spec)?;
        assert_eq!(n, 2);
        let kids = store.children("11111111-parent")?;
        assert_eq!(kids.len(), 2, "both children hang under the outline");
        assert!(kids.iter().all(|k| k.local_parent_id == "11111111-parent"));
        // Original becomes an outline: body replaced
        let upd = store
            .all(true)?
            .into_iter()
            .find(|m| m.id == "11111111-parent")
            .ok_or_else(|| anyhow!("not found"))?;
        assert!(
            upd.local_content_head.contains("\u{7eb2}\u{ff1a}\u{8be6}\u{60c5}\u{62c6}\u{89c1}"),
            "original should become an outline"
        );
        // summary=original body: become an outline without changing content (keep-original path)
        let spec2 = SplitSpec {
            summary: Some("\u{4e00}\u{5927}\u{5768}\u{6df7}\u{88c5}\u{5185}\u{5bb9}".into()),
            items: vec![SplitOp {
                title: "\u{2462}\u{7b2c}\u{4e09}\u{679c}".into(),
                content: "\u{3010}\u{6559}\u{8bad}\u{3011}\u{518d}\u{8865}\u{4e00}\u{679c}\u{9a8c}\u{8bc1}\u{539f}\u{6761}\u{4fdd}\u{7559}\u{8def}\u{5f84}\u{4e0d}\u{88ab}\u{8bef}\u{8f6c}\u{3002}".into(),
                kind: "skill".into(),
                tags: vec![],
                parent: "\u{7eb2}".into(),
            }],
        };
        assert!(split_exec(&keys, &embedder, &store, &entry, &spec2).is_ok());
        match saved {
            Some(v) => std::env::set_var("RSRS_NO_AUTOSYNC", v),
            None => std::env::remove_var("RSRS_NO_AUTOSYNC"),
        }
        Ok(())
    }

    /// Split refuse: a single child and no outline kept = a rewrite, not a split.
    #[test]
    fn split_exec_refuses_single_child_no_summary() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        let keys = crate::memory::SessionKeys::from_urk([7u8; 32])?;
        let embedder = crate::memory::search::HashingEmbedder::default();
        let mut entry = test_entry("\u{5185}\u{5bb9}");
        entry.id = "22222222-single".into();
        let stored0 = MemoryEngine::seal(&keys, &embedder, &entry, "u")?;
        store.put(&stored0)?;
        let spec = SplitSpec {
            summary: None,
            items: vec![SplitOp {
                title: "\u{4e00}\u{679c}".into(),
                content: "\u{552f}\u{4e00}\u{4e00}\u{679c}\u{7b49}\u{540c}\u{6539}\u{5199}\u{3002}".into(),
                kind: "context".into(),
                tags: vec![],
                parent: "\u{7eb2}".into(),
            }],
        };
        assert!(split_exec(&keys, &embedder, &store, &entry, &spec).is_err());
        Ok(())
    }

    #[test]
    fn expand_tilde_and_activity_append() {
        let p = expand_tilde("plain");
        assert_eq!(p, PathBuf::from("plain"));
        let home = expand_tilde("~/x");
        assert!(home.ends_with("x"));
        assert_eq!(activity_append("", "a"), "a");
        assert_eq!(activity_append("hi", "line"), "hi\nline");
        assert_eq!(activity_append("hi\n", "line"), "hi\nline");
    }

    #[test]
    fn account_dir_rejects_bad_names() {
        assert!(account_dir("").is_err());
        assert!(account_dir("a/b").is_err());
        assert!(account_dir("ok-name_1").is_ok());
    }

    #[test]
    fn workspace_and_agent_config_roundtrip() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let saved = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        assert_eq!(workspace_mode(), "normal");
        assert_eq!(diary_mode(), "concise");
        write_client_config(&serde_json::json!({"api_base":"https://fixture.invalid", "custom":"preserved"}))?;
        set_workspace_mode("readonly")?;
        assert_eq!(workspace_mode(), "readonly");
        assert!(service_paused());
        assert!(readonly_mode());
        assert!(ensure_writable().is_err());
        assert!(import_json_text("[]").is_err());
        account_use("work")?;
        assert_eq!(workspace_mode(), "readonly", "device mode survives account switching");
        assert_eq!(read_client_config().ok_or_else(|| anyhow::anyhow!("missing client config"))?["custom"], "preserved");
        set_workspace_mode("off")?;
        assert_eq!(workspace_mode(), "off");
        assert!(off_mode());
        assert!(import_json_text("[]").is_err());
        account_use("main")?;
        assert_eq!(workspace_mode(), "off");
        let before = std::fs::read(client_config_path())?;
        assert!(set_workspace_mode("nope").is_err());
        assert_eq!(std::fs::read(client_config_path())?, before);
        set_workspace_mode("normal")?;
        assert_eq!(workspace_mode(), "normal");
        assert!(ensure_writable().is_ok());
        write_agent_config_key("memory_off", &serde_json::json!(true))?;
        assert_eq!(workspace_mode(), "off");
        write_agent_config_key("memory_off", &serde_json::json!(false))?;
        write_agent_config_key("readonly", &serde_json::json!(true))?;
        assert_eq!(workspace_mode(), "readonly");
        write_agent_config_key("readonly", &serde_json::json!(false))?;
        assert_eq!(workspace_mode(), "normal");
        write_agent_config_key("readonly_team", &serde_json::json!(true))?;
        set_workspace_mode("normal")?;
        assert_eq!(workspace_mode(), "readonly", "normal mode cannot lift shared-space permissions");
        assert!(!service_paused(), "team read-only access must still pull and index shared memory");
        assert!(ensure_writable().is_err());
        set_workspace_mode("readonly")?;
        assert!(service_paused(), "device read-only mode must pause even a shared-space replica");
        std::fs::write(agent_config_path(), serde_json::to_vec(&serde_json::json!({"readonly":true,"readonly_team":true}))?)?;
        write_client_config(&serde_json::json!({"custom":"preserved"}))?;
        assert!(!service_paused(), "legacy shared-space flags are account permissions, not device mode");
        set_workspace_mode("normal")?;
        write_agent_config_key("readonly_team", &serde_json::json!(false))?;
        write_agent_config_key("diary_mode", &serde_json::json!("verbose"))?;
        assert_eq!(diary_mode(), "verbose");
        assert!(set_workspace_mode("nope").is_err());
        match saved {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        Ok(())
    }

    #[test]
    fn accounts_list_use_remove() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let saved = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let listed = account_list()?;
        assert_eq!(listed["accounts"][0]["name"], "main");
        let used = account_use("work")?;
        assert_eq!(used["name"], "work");
        std::fs::write(account_dir("work")?.join("session.json"), r#"{"user":"w"}"#)?;
        let listed = account_list()?;
        assert!(listed["accounts"].as_array().map(|a| a.len()).unwrap_or(0) >= 2);
        account_use("main")?;
        account_remove("work")?;
        assert!(account_remove("missing").is_err());
        match saved {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        Ok(())
    }

    fn test_app(dir: &std::path::Path) -> anyhow::Result<App> {
        let keys = crate::memory::SessionKeys::from_urk([7u8; 32])?;
        let store = LocalStore::open(&dir.join("t.db"))?;
        Ok(App {
            keys,
            store,
            embedder: Box::new(crate::memory::search::HashingEmbedder::default()),
        })
    }

    fn important(title: &str, content: &str) -> CreateReq {
        CreateReq {
            title: title.to_owned(),
            content: content.to_owned(),
            importance: Some("important".to_owned()),
            kind: "context".to_owned(),
            ..CreateReq::default()
        }
    }

    #[test]
    fn recall_keeps_indexed_memories_available_during_sync() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let app = test_app(dir.path())?;
        let (empty, pending) = recall_candidates(&app.store)?;
        assert!(empty.is_empty());
        assert_eq!(pending, 0);
        let indexed = app.create(&important("indexed", "rust memory"))?;
        let mut incoming = app.create(&important("incoming", "rust memory"))?;
        incoming.updated_at = "2099-01-01T00:00:00Z".into();
        incoming.content = "synchronized rust memory".into();
        let mut source = MemoryEngine::seal(&app.keys,
            &crate::memory::search::HashingEmbedder::default(), &incoming, "fixture")?;
        source.local_artifact.clear();
        app.store.put_synced(&source)?;
        let (ready, pending) = recall_candidates(&app.store)?;
        assert_eq!(pending, 1);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, indexed.id);
        let hits = app.search("rust memory", 10, None)?;
        assert!(hits.iter().any(|hit| hit.entry.id == indexed.id));
        assert!(hits.iter().all(|hit| hit.entry.id != incoming.id));
        assert_eq!(app.store.rebuild_index_with_progress(
            &app.keys, &crate::memory::search::HashingEmbedder::default(), "m3", |_, _| Ok(())
        )?, 1);
        let (ready, pending) = recall_candidates(&app.store)?;
        assert_eq!(ready.len(), 2);
        assert_eq!(pending, 0);
        Ok(())
    }

    #[test]
    fn recall_preserves_all_pending_and_corrupt_index_errors() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let app = test_app(dir.path())?;
        let mut memory = app.create(&important("source", "rust memory"))?;
        memory.updated_at = "2099-01-01T00:00:00Z".into();
        let mut source = MemoryEngine::seal(&app.keys,
            &crate::memory::search::HashingEmbedder::default(), &memory, "fixture")?;
        source.local_artifact.clear();
        app.store.put_synced(&source)?;
        let error = recall_candidates(&app.store).err()
            .ok_or_else(|| anyhow!("all-pending recall succeeded"))?;
        assert!(error.downcast_ref::<IndexPending>().is_some());
        source.local_artifact = b"invalid artifact".to_vec();
        app.store.put_inner(&source, false)?;
        assert!(recall_candidates(&app.store).is_err());
        Ok(())
    }

    #[test]
    fn app_crud_tree_attach_promote() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let app = test_app(dir.path())?;
        let parent = app.create(&important("parent-node", "parent body about rust memory"))?;
        let child = app.create(&CreateReq {
            parent: Some(parent.id.clone()),
            ..important("child-node", "child body about rust ownership")
        })?;
        let status = app.status()?;
        assert_eq!(status.local_alive, 2);
        let listed = app.list(10)?;
        assert!(!listed.is_empty());
        let found = app.search("rust memory", 5, None)?;
        assert!(!found.is_empty());
        let detail = app.show(&parent.id[..8])?;
        assert_eq!(detail.entry.id, parent.id);
        assert!(detail.children.iter().any(|c| c.id == child.id));
        let forest = app.tree("", 3)?;
        assert!(forest.iter().any(|n| n.id == parent.id));
        let updated = app.update(
            &child.id[..8],
            Some("child-renamed".to_owned()),
            Some("updated child body rust".to_owned()),
            Some("rust,mem".to_owned()),
            Some("decision".to_owned()),
        )?;
        assert_eq!(updated.title, "child-renamed");
        let (cid, pid) = app.attach(&child.id, &parent.id)?;
        assert_eq!(cid, child.id);
        assert_eq!(pid, parent.id);
        let (promoted, gp) = app.promote(&child.id)?;
        assert_eq!(promoted, child.id);
        assert!(gp.is_empty());
        assert!(app.delete(&child.id)?);
        let restored = app.restore(&child.id)?;
        assert_eq!(restored.id, child.id);
        let _ = app.candidates("rust memory ownership")?;
        let members = subtree_members(&app.store.all(true)?, &parent.id);
        assert!(members.contains(&parent.id));
        let _ = app.tree_cure(3)?;
        let _ = app.tree_float(false, 1)?;
        let _ = app.portrait_material(5)?;
        Ok(())
    }

    #[test]
    fn rejected_associations_restore_and_attach_are_input_errors_without_writes() -> anyhow::Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let app = test_app(dir.path())?;
        let diary = app.create(&CreateReq { title: "diary".into(), content: "diary body".into(), ..CreateReq::default() })?;
        let parent = app.create(&important("parent", "parent body"))?;
        let child = app.create(&CreateReq { parent: Some(parent.id.clone()), ..important("child", "child body") })?;
        let before = serde_json::to_value(app.store.all(true)?)?;
        let supersede = app.create(&CreateReq { supersedes: Some(diary.id.clone()), ..important("replacement", "replacement body") });
        let link = app.create(&CreateReq { see_also: vec![diary.id.clone()], ..important("linked", "linked body") });
        for error in [supersede.err(), link.err(), app.restore("deadbeef").err(), app.attach(&child.id, &child.id).err(), app.attach(&parent.id, &child.id).err()] {
            let error = error.ok_or_else(|| anyhow!("invalid input was accepted"))?;
            assert!(error.downcast_ref::<crate::input_error::InputError>().is_some(), "{error:#}");
        }
        assert_eq!(serde_json::to_value(app.store.all(true)?)?, before);
        // A cryptographic failure is still a runtime error, not malformed command input.
        let wrong = App { keys: crate::memory::SessionKeys::from_urk([9; 32])?, store: app.store, embedder: app.embedder };
        let error = wrong.restore(&child.id).err().ok_or_else(|| anyhow!("wrong key was accepted"))?;
        assert!(error.downcast_ref::<crate::input_error::InputError>().is_none());
        Ok(())
    }

    #[test]
    fn status_light_and_titles() -> anyhow::Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let info = status_light()?;
        assert_eq!(info.local_total, 0);
        assert_eq!(derive_title("\u{3010}\u{7ecf}\u{9a8c}\u{3011}first line\nsecond"), "first line");
        assert_eq!(derive_title(""), "(untitled)");
        assert!(diary_mode() == "concise" || diary_mode() == "verbose");
        let saved_super = std::env::var_os("RSRS_SUPER");
        let code = crate::memory::crypto::generate_secret_key();
        std::env::set_var("RSRS_SUPER", &code);
        let result = (|| -> Result<()> {
            let (salt, wrapped, nonce) = crate::auth::wrap_with_rsrs(&code, &[7; 32])?;
            crate::auth::write_session_json(&serde_json::json!({
                "user":"fixture","vault_version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce
            }))?;
            let _deferred = respire_core_sdk::defer_indexing();
            let snapshot = r#"[{"id":"parent","content":"unique parent","title":"parent"},{"id":"child","content":"unique child","parent_id":"parent"},{"id":"parent-copy","content":"unique parent"},{"id":"new-child","content":"third body","parent_id":"parent-copy","see_also":["parent","parent-copy"]},{"id":"parent","content":"unique parent"}]"#;
            let first = import_json_text(snapshot)?;
            assert_eq!((first.imported, first.duplicates), (3, 2));
            let again = import_json_text(snapshot)?;
            assert_eq!((again.imported, again.duplicates), (0, 5));
            let keys = auth::load_local_session()?;
            let entries: Vec<_> = open_store()?.all(false)?.iter()
                .map(|stored| MemoryEngine::open(&keys, stored)).collect::<Result<_>>()?;
            let parent = entries.iter().find(|entry| entry.content == "unique parent").ok_or_else(|| anyhow!("parent missing"))?;
            let child = entries.iter().find(|entry| entry.content == "third body").ok_or_else(|| anyhow!("child missing"))?;
            assert_eq!(child.parent_id, parent.id);
            assert_eq!(child.see_also, vec![parent.id.clone()]);
            assert!(import_json_text(r#"[{"id":"a","content":"a","parent_id":"b"},{"id":"b","content":"b","parent_id":"a"}]"#).is_err());
            assert_eq!(open_store()?.all(false)?.len(), 3);
            let snapshot = local_snapshot(Some(&code))?;
            assert_eq!(serde_json::from_str::<Vec<MemoryEntry>>(&snapshot)?.len(), 3);
            let extra = r#"[{"id":"existing","content":"unique parent"},{"id":"new","content":"fourth body","supersedes":"existing","see_also":["existing"]}]"#;
            assert_eq!((import_json_text(extra)?.imported, import_json_text(extra)?.duplicates), (1, 2));
            let store = open_store()?;
            let all = store.all(false)?;
            let entries = all.iter().map(|stored| MemoryEngine::open(&keys, stored)).collect::<Result<Vec<_>>>()?;
            let parent = entries.iter().find(|entry| entry.content == "unique parent").ok_or_else(|| anyhow!("parent missing"))?;
            let replacement = entries.iter().find(|entry| entry.content == "fourth body").ok_or_else(|| anyhow!("replacement missing"))?;
            assert_eq!(parent.superseded_by, replacement.id);
            assert!(parent.see_also.contains(&replacement.id));
            Ok(())
        })();
        match saved_super {
            Some(value) => std::env::set_var("RSRS_SUPER", value),
            None => std::env::remove_var("RSRS_SUPER"),
        }
        result
    }
}

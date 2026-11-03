//! sync — two-way sync engine (CLI and web console share this)
//!
//! local-first: local store = authoritative working library; cloud = dumb ciphertext backup.
//! Sync = git fetch/push semantics: fetch pulls cloud **increment** (server arrival-order rev>cursor; first pull is full)
//! → local LWW merge; push local dirty objects → cloud LWW. Delete = tombstone propagation.
//!
//! Incremental cursor = **server arrival order** (rev incremented on each push in server.rs), not a client timestamp —
//! a fast local clock cannot skip pulls (the updated_at-cursor bug: any local stamp ahead makes since ahead,
//! and a truly new remote object is skipped forever). Cursor lives in local meta.sync_cursor and advances on success.

use anyhow::{anyhow, Result};

use crate::memory::engine::SessionKeys;
use crate::memory::model::StoredMemory;
use crate::transport::local::LocalStore;
use crate::transport::remote::RemoteTransport;
use crate::transport::MemoryTransport;

/// Sync stats.
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    pub protocol: u32,
    pub pending: i64,
    pub conflicts: i64,
    pub undecodable: i64,
    pub conflict_history: i64,
    pub processed_conflicts: i64,
    pub historical_conflicts: i64,
    pub resolving_conflicts: i64,
    pub resolution_supported: bool,
    /// New/changed rows pulled from cloud into local (increment — not a full count)
    pub pulled: usize,
    /// New/changed rows pushed to the cloud
    pub pushed: usize,
    /// Remote object count (including tombstones)
    pub remote_total: usize,
    /// Remote live object count
    pub remote_alive: usize,
}

/// Two-way sync (git fetch/push semantics):
///
/// 1) **fetch** — incremental pull of cloud new/changed from the local cursor (meta.sync_cursor), including tombstones;
///    no cursor → full. Cursor is server arrival-order rev; LWW merge (not dirty).
/// 2) **push** — push local dirty rows (including tombstones) → cloud LWW → clear_dirty on success.
/// 3) On success, advance local meta.sync_cursor to the server cursor.
#[derive(Debug)]
pub struct SyncBoundaryChanged;
impl std::fmt::Display for SyncBoundaryChanged {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("queue identities migrated; local data preserved; run sync again")
    }
}
impl std::error::Error for SyncBoundaryChanged {}

/// Controls local consistency phases independently from network calls.
pub trait SyncControl {
    fn progress(&self, _phase: &str) {}
    fn boundary_changed(&self) -> Result<()> {
        Ok(())
    }
    fn local<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T>;
    fn remote<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T>;
}
pub struct DirectSync;
impl SyncControl for DirectSync {
    fn local<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        action()
    }
    fn remote<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        action()
    }
}
pub fn sync_all(
    keys: &SessionKeys,
    local: &LocalStore,
    remote: &impl MemoryTransport,
) -> Result<SyncStats> {
    sync_controlled(keys, local, remote, &DirectSync, None)
}
pub fn sync_controlled(
    keys: &SessionKeys,
    local: &LocalStore,
    remote: &impl MemoryTransport,
    control: &impl SyncControl,
    boundary: Option<i64>,
) -> Result<SyncStats> {
    control.local(|| {
        local.ensure_snapshot_sync_allowed()?;
        crate::metadata_gate::ensure_sync_allowed(local)?;
        local.maintain_sync_storage()
    })?;
    let captured_boundary = boundary.is_some();
    let mut boundary = match boundary {
        Some(value) => value,
        None => control.local(|| local.outgoing_boundary())?,
    };
    let started = std::time::Instant::now();
    let mut stats = SyncStats::default();
    let cached_epoch = control.local(|| local.meta_get("sync_v2_epoch"))?;
    control.progress("capabilities");
    let cached_support = control.local(|| local.meta_get("sync_v2_resolution_support"))?;
    let capability =
        if let Some(epoch) = cached_epoch.filter(|_| cached_support.as_deref() == Some("1")) {
            // Once negotiated, use v2 directly. A 404/epoch error must not downgrade.
            Some(crate::transport::protocol::Capabilities {
                protocols: vec![2],
                epoch,
                push_items: crate::transport::protocol::PUSH_ITEMS,
                push_bytes: crate::transport::protocol::BATCH_BYTES,
                conflict_resolution: true,
            })
        } else {
            control.remote(|| remote.capabilities())?
        };
    if let Some(cap) = capability {
        if !cap.protocols.contains(&2) {
            anyhow::bail!("server does not offer a compatible sync protocol");
        }
        let requeued = control.local(|| {
            let requeued = local.begin_sync_epoch_requeued(&cap.epoch)?;
            if requeued {
                control.boundary_changed()?;
            }
            Ok(requeued)
        })?;
        if requeued && captured_boundary {
            anyhow::bail!(SyncBoundaryChanged);
        }
        if !captured_boundary {
            boundary = control.local(|| local.outgoing_boundary())?;
        }
        control.local(|| {
            local.meta_set(
                "sync_v2_resolution_support",
                if cap.conflict_resolution { "1" } else { "0" },
            )
        })?;
        stats.resolution_supported = cap.conflict_resolution;
        stats.protocol = 2;
        let snapshot = control
            .local(|| local.meta_get("sync_v2_snapshot_done"))?
            .as_deref()
            != Some("1");
        pull_pages(
            keys, local, remote, control, &cap.epoch, snapshot, &mut stats,
        )?;
        let mut had_outgoing = false;
        loop {
            let items = control.local(|| local.outgoing_through(boundary))?;
            if items.is_empty() {
                break;
            }
            had_outgoing = true;
            let request = crate::transport::protocol::PushRequest {
                epoch: cap.epoch.clone(),
                items,
            };
            control.progress("push");
            let reply = control.remote(|| remote.push_v2(&request))?;
            control.progress("apply");
            stats.pushed +=
                control.local(|| local.acknowledge(&request.items, &reply.results, false))?;
        }
        if had_outgoing {
            pull_pages(keys, local, remote, control, &cap.epoch, false, &mut stats)?;
        }
        let mut materialized_after = String::new();
        control.progress("materialize");
        while let Some(next) =
            control.local(|| local.materialize_received_batch(keys, &materialized_after))?
        {
            materialized_after = next;
        }
        if cap.conflict_resolution {
            pull_resolution_pages(local, remote, control, &cap.epoch)?;
        }
        let mut classified_after = 0;
        control.progress("conflicts");
        while let Some(next) = control.local(|| {
            local.classify_conflicts_batch(keys, cap.conflict_resolution, classified_after)
        })? {
            classified_after = next;
        }
        if cap.conflict_resolution {
            let mut sent = false;
            let mut resolution_after = 0;
            let resolution_until = control.local(|| local.resolution_boundary())?;
            loop {
                let items = control.local(|| {
                    local.outgoing_resolutions_through(resolution_after, resolution_until)
                })?;
                if items.is_empty() {
                    break;
                }
                let request = crate::transport::protocol::ResolveRequest {
                    epoch: cap.epoch.clone(),
                    items,
                };
                if let Some(last) = request.items.last() {
                    resolution_after = last.conflict_rev;
                }
                let reply = control.remote(|| remote.resolve_conflicts(&request))?;
                control
                    .local(|| local.acknowledge_resolutions(&cap.epoch, &request.items, &reply))?;
                sent = true;
            }
            if sent {
                pull_resolution_pages(local, remote, control, &cap.epoch)?;
            }
            // A processed explicit decision can release a protected diary
            // working branch. Apply that decision in this sync, not a later one.
            let mut after = String::new();
            control.progress("materialize");
            while let Some(next) = control.local(|| local.materialize_received_batch(keys, &after))? {
                after = next;
            }
        }
    } else {
        if control.local(|| local.meta_get("sync_v2_epoch"))?.is_some() {
            anyhow::bail!("server sync capability degraded; refusing silent fallback; pending local changes kept");
        }
        stats.protocol = 1;
        let cursor = control
            .local(|| local.meta_get("sync_cursor"))?
            .and_then(|s| s.parse().ok());
        control.progress("pull");
        let reply = control.remote(|| remote.fetch_rev(cursor))?;
        stats.remote_total = reply.total as usize;
        stats.remote_alive = reply.alive as usize;
        control.progress("apply");
        stats.pulled += control.local(|| local.apply_legacy(keys, reply.blobs, reply.cursor))?;
        let mut sent = false;
        loop {
            let items = control.local(|| local.outgoing_through(boundary))?;
            if items.is_empty() {
                break;
            }
            sent = true;
            let blobs: Vec<_> = items.iter().map(|o| o.blob.clone()).collect();
            control.progress("push");
            let replaced = control.remote(|| remote.put_batch(&blobs))?;
            if replaced.len() != items.len() {
                anyhow::bail!("batch response length mismatch");
            }
            let receipts: Vec<_> = items
                .iter()
                .zip(replaced)
                .map(|(o, ok)| crate::transport::protocol::Receipt {
                    op_id: o.op_id.clone(),
                    status: if ok { "applied" } else { "legacy_rejected" }.to_owned(),
                    stored_rev: 0,
                    head_rev: 0,
                })
                .collect();
            stats.pushed += control.local(|| local.acknowledge(&items, &receipts, true))?;
        }
        if sent {
            control.progress("pull");
            let again = control.remote(|| remote.fetch_rev(Some(reply.cursor)))?;
            stats.remote_total = again.total as usize;
            stats.remote_alive = again.alive as usize;
            stats.pulled +=
                control.local(|| local.apply_legacy(keys, again.blobs, again.cursor))?;
        }
    }
    control.progress("verify");
    control.local(|| {
        local.ensure_snapshot_sync_allowed()?;
        crate::metadata_gate::ensure_sync_allowed(local)?;
        local.maintain_sync_storage()
    })?;
    (stats.pending, stats.conflicts, stats.undecodable) = control.local(|| local.sync_counts())?;
    (
        stats.conflict_history,
        stats.processed_conflicts,
        stats.historical_conflicts,
        stats.resolving_conflicts,
    ) = control.local(|| local.conflict_metrics())?;
    if crate::env::var_os("RSRS_SYNC_TIMING").is_some() {
        eprintln!(
            "sync protocol={} elapsed_ms={} pulled={} pushed={} pending={} conflicts={}",
            stats.protocol,
            started.elapsed().as_millis(),
            stats.pulled,
            stats.pushed,
            stats.pending,
            stats.conflicts
        );
    }
    Ok(stats)
}

fn pull_resolution_pages(
    local: &LocalStore,
    remote: &impl MemoryTransport,
    control: &impl SyncControl,
    epoch: &str,
) -> Result<()> {
    let mut after = control
        .local(|| local.meta_get("sync_v2_resolution_cursor"))?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut until = None;
    loop {
        let page = control.remote(|| remote.fetch_resolutions(epoch, after, until))?;
        if page.epoch != epoch || until.is_some_and(|h| h != page.until) {
            anyhow::bail!("resolution snapshot changed");
        }
        control.local(|| local.apply_resolution_page(&page))?;
        after = page.cursor;
        until = Some(page.until);
        if !page.has_more {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
fn merge_blobs(keys: &SessionKeys, local: &LocalStore, blobs: Vec<StoredMemory>) -> Result<usize> {
    local.apply_legacy(keys, blobs, 0)
}

fn pull_pages(
    keys: &SessionKeys,
    local: &LocalStore,
    remote: &impl MemoryTransport,
    control: &impl SyncControl,
    epoch: &str,
    snapshot: bool,
    stats: &mut SyncStats,
) -> Result<()> {
    let key = if snapshot {
        "sync_v2_snapshot_cursor"
    } else {
        "sync_v2_cursor"
    };
    let mut after = control
        .local(|| local.meta_get(key))?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut until = if snapshot {
        control
            .local(|| local.meta_get("sync_v2_snapshot_until"))?
            .and_then(|s| s.parse().ok())
    } else {
        None
    };
    let mut restarted = false;
    loop {
        control.progress("pull");
        let page = match control.remote(|| remote.pull_v2(epoch, after, until, snapshot)) {
            Ok(page) => page,
            Err(error)
                if !restarted
                    && error
                        .to_string()
                        .contains("sync history compacted; restart snapshot") =>
            {
                restarted = true;
                if snapshot {
                    control.local(|| {
                        local.meta_set("sync_v2_snapshot_cursor", "0")?;
                        local.meta_set("sync_v2_snapshot_until", "")
                    })?;
                    after = 0;
                }
                until = None;
                continue;
            }
            Err(error) => return Err(error),
        };
        if page.epoch != epoch || until.is_some_and(|h| h != page.until) {
            anyhow::bail!("server page snapshot changed");
        }
        control.progress("apply");
        stats.pulled += control.local(|| local.apply_page(keys, &page, snapshot))?;
        stats.remote_total = page.total as usize;
        stats.remote_alive = page.alive as usize;
        after = page.cursor;
        until = Some(page.until);
        if !page.has_more {
            break;
        }
    }
    Ok(())
}

/// Build the remote store: prefer session.json (addr/token from register/login), then env vars.
pub fn build_remote_from_env() -> Result<RemoteTransport> {
    // 1) session.json (written by register/login)
    let path = crate::service::data_dir().join("session.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
            if let (Some(addr), Some(token)) = (
                data["addr"].as_str().filter(|s| !s.is_empty()),
                data["token"].as_str().filter(|s| !s.is_empty()),
            ) {
                return Ok(RemoteTransport::new(
                    crate::transport::remote::RemoteConfig {
                        address: addr.to_owned(),
                        token: token.to_owned(),
                    },
                ));
            }
        }
    }
    // 2) env vars
    let addr = crate::env::var("RSRS_ADDR").map_err(|_| {
        anyhow::anyhow!("sync needs RSRS_ADDR (server address) or a prior register/login")
    })?;
    let token = crate::env::var("RSRS_TOKEN")
        .map_err(|_| anyhow::anyhow!("sync needs RSRS_TOKEN"))?;
    Ok(RemoteTransport::new(
        crate::transport::remote::RemoteConfig {
            address: addr,
            token,
        },
    ))
}

/// Whether a remote store is configured (session.json or env).
pub fn remote_configured() -> bool {
    let path = crate::service::data_dir().join("session.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
            if data["addr"].as_str().is_some_and(|s| !s.is_empty())
                && data["token"].as_str().is_some_and(|s| !s.is_empty())
            {
                return true;
            }
        }
    }
    crate::env::var("RSRS_ADDR")
        .map(|a| !a.trim().is_empty())
        .unwrap_or(false)
}

/// Build a blob for tests (not a production path).
#[allow(dead_code)]
fn test_blob(id: &str) -> StoredMemory {
    StoredMemory {
        id: id.to_owned(),
        user: "u".to_owned(),
        ciphertext: "aa".to_owned(),
        nonce: "11".to_owned(),
        embedding_enc: String::new(),
        updated_at: "2026-09-02T00:00:00.000Z".to_owned(),
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
        local_meta: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::Kind;
    use crate::memory::search::HashingEmbedder;
    use crate::memory::{MemoryEngine, MemoryEntry, MemoryQuery};

    fn entry(id: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            id: id.to_owned(),
            kind: Kind::Context,
            tags: vec!["t".to_owned()],
            title: id.to_owned(),
            content: content.to_owned(),
            user: "u".to_owned(),
            computer: "c".to_owned(),
            project: "p".to_owned(),
            created_at: "2026-09-02T00:00:00.000Z".to_owned(),
            updated_at: "2026-09-02T00:00:00.000Z".to_owned(),
            emotion: -1.0,
            parent_id: String::new(),
            importance: "normal".to_owned(),
            device: "test-dev".to_owned(),
            modified_by: "test-dev".to_owned(),
        }
    }

    #[test]
    fn put_synced_keeps_local_artifact_when_ciphertext_unchanged() -> anyhow::Result<()> {
        // A same-content pull must preserve the local Core index locator.
        let keys = SessionKeys::from_urk([42u8; 32])?;
        let dir = tempfile::tempdir()?;
        let local = LocalStore::open(&dir.path().join("local.db"))?;
        let embedder = HashingEmbedder::default();
        let e = entry("keep-1", "\u{4fdd}\u{7559}\u{5411}\u{91cf}");
        let stored = MemoryEngine::seal(&keys, &embedder, &e, "local")?;
        assert!(!stored.local_artifact.is_empty());
        local.put(&stored)?;

        // Simulate a remote pull: same ciphertext, no vector, updated_at newer
        let mut from_remote = stored.clone();
        from_remote.local_embedding = None;
        from_remote.local_artifact.clear();
        from_remote.embedding_enc = String::new();
        from_remote.updated_at = "2027-01-01T00:00:00.000Z".to_owned();
        assert!(local.put_synced(&from_remote)?);

        let got = local
            .all(true)?
            .into_iter()
            .find(|m| m.id == stored.id)
            .ok_or_else(|| anyhow!("not found"))?;
        assert!(
            got.local_artifact == stored.local_artifact,
            "an unchanged source must retain its local Core index locator"
        );
        Ok(())
    }

    #[test]
    fn put_synced_drops_local_artifact_when_content_changed() -> anyhow::Result<()> {
        // A changed source invalidates the old local Core index locator.
        let keys = SessionKeys::from_urk([43u8; 32])?;
        let dir = tempfile::tempdir()?;
        let local = LocalStore::open(&dir.path().join("local.db"))?;
        let embedder = HashingEmbedder::default();
        let e = entry("chg-1", "\u{539f}\u{5185}\u{5bb9}");
        let stored = MemoryEngine::seal(&keys, &embedder, &e, "local")?;
        local.put(&stored)?;

        let mut changed = entry("chg-1", "\u{88ab}\u{4ed6}\u{7aef}\u{6539}\u{8fc7}\u{7684}\u{65b0}\u{5185}\u{5bb9}");
        changed.updated_at = "2027-01-01T00:00:00.000Z".to_owned();
        let mut blob = MemoryEngine::seal(&keys, &embedder, &changed, "local")?;
        blob.local_embedding = None; // Remote records carry no local feature copy.
        blob.local_artifact.clear();
        blob.embedding_enc = String::new();
        assert!(local.put_synced(&blob)?);

        let got = local
            .all(true)?
            .into_iter()
            .find(|m| m.id == stored.id)
            .ok_or_else(|| anyhow!("not found"))?;
        assert!(
            got.local_artifact.is_empty(),
            "a changed source must be indexed again from its decrypted entry"
        );
        Ok(())
    }

    #[test]
    fn merge_blobs_lww_skips_stale_remote() -> anyhow::Result<()> {
        let keys = SessionKeys::from_urk([42u8; 32])?;
        let dir = tempfile::tempdir()?;
        let local = LocalStore::open(&dir.path().join("local.db"))?;
        let embedder = HashingEmbedder::default();
        let e = entry("lww-1", "LWW \u{5185}\u{5bb9}");
        let stored = MemoryEngine::seal(&keys, &embedder, &e, "local")?;
        local.put(&stored)?;
        // Local updated_at=T; remote blob older → skip
        let mut stale = stored.clone();
        stale.updated_at = "2026-01-01T00:00:00.000Z".to_owned();
        let pulled = merge_blobs(&keys, &local, vec![stale])?;
        assert_eq!(pulled, 0, "\u{65e7}\u{526f}\u{672c}\u{4e0d}\u{5f97}\u{8986}\u{76d6}\u{672c}\u{5730}\u{65b0}\u{72b6}\u{6001}");
        assert_eq!(local.all(false)?.len(), 1);
        // Remote blob newer (same id, new payload: new title, updated_at newer) → store
        let mut fresh = e.clone();
        fresh.title = "LWW \u{65b0}\u{6807}\u{9898}".to_owned();
        fresh.updated_at = "2027-01-01T00:00:00.000Z".to_owned();
        let fresh_blob = MemoryEngine::seal(&keys, &embedder, &fresh, "local")?;
        let pulled = merge_blobs(&keys, &local, vec![fresh_blob])?;
        assert_eq!(pulled, 1);
        assert_eq!(local.all(false)?[0].local_title, "LWW \u{65b0}\u{6807}\u{9898}");
        Ok(())
    }

    fn remote_configured_flag() -> anyhow::Result<()> {
        // Isolate: temp HOME (no session.json), only test the env-var branch
        let saved_home = crate::env::var("HOME").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("HOME", dir.path());
        let saved = crate::env::var("RSRS_ADDR").ok();
        std::env::remove_var("RSRS_ADDR");
        assert!(!remote_configured());
        std::env::set_var("RSRS_ADDR", "http://x");
        assert!(remote_configured());
        // restore
        match saved {
            Some(v) => std::env::set_var("RSRS_ADDR", v),
            None => std::env::remove_var("RSRS_ADDR"),
        }
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        Ok(())
    }

    /// End-to-end: two local stores as two devices, via a fake remote, verify sync merge and tombstone.
    #[test]
    fn sync_merges_two_devices() -> anyhow::Result<()> {
        // Local store as "cloud": device A writes → sync to hub → device B sync pulls
        let dir = tempfile::tempdir()?;
        let keys = SessionKeys::from_urk([7u8; 32])?;
        let embedder = HashingEmbedder::default();

        // Hub store (stands in for the cloud)
        let cloud = LocalStore::open(&dir.path().join("cloud.db"))?;

        // Device A: write two rows
        let a = LocalStore::open(&dir.path().join("a.db"))?;
        let e1 = entry("a-1", "Rust \u{6240}\u{6709}\u{6743} \u{5185}\u{5b58}\u{5b89}\u{5168}");
        let s1 = MemoryEngine::seal(&keys, &embedder, &e1, "u")?;
        a.put(&s1)?;
        let e2 = entry("a-2", "Python \u{6570}\u{636e}\u{5206}\u{6790}");
        let s2 = MemoryEngine::seal(&keys, &embedder, &e2, "u")?;
        a.put(&s2)?;

        // Device A sync → hub
        let cloud_transport = fake_remote(&cloud);
        let stats = sync_all(&keys, &a, &cloud_transport)?;
        assert_eq!(stats.pushed, 2);

        // Device B: empty store, sync ← hub
        let b = LocalStore::open(&dir.path().join("b.db"))?;
        let cloud_transport2 = fake_remote(&cloud);
        let stats = sync_all(&keys, &b, &cloud_transport2)?;
        assert_eq!(stats.pulled, 2);

        // B can semantically recall what A wrote (HashingEmbedder vectors differ from BGE semantics,
        // Core may omit test fixtures; this checks successful recall after sync, not retrieval quality.
        let all = b.all(false)?;
        let q = MemoryQuery::new("\u{5185}\u{5b58}\u{5b89}\u{5168} \u{501f}\u{7528}").limit(5);
        let ranked = MemoryEngine::recall_local(&keys, &embedder, &all, &q)?;
        if !ranked.is_empty() {
            assert_eq!(ranked[0].id, "a-1");
        }

        // Device B deletes one → sync → device A pulls the tombstone and the row is gone
        b.forget("a-2")?;
        let cloud_transport3 = fake_remote(&cloud);
        sync_all(&keys, &b, &cloud_transport3)?;
        let cloud_transport4 = fake_remote(&cloud);
        sync_all(&keys, &a, &cloud_transport4)?;
        let a_all = a.all(false)?;
        assert!(a_all.iter().all(|m| m.id != "a-2"));
        Ok(())
    }

    #[test]
    fn snapshot_quarantine_refuses_sync_before_any_remote_callback() -> Result<()> {
        struct UnreachableRemote;
        impl MemoryTransport for UnreachableRemote {
            fn capabilities(&self) -> Result<Option<crate::transport::protocol::Capabilities>> {
                panic!("quarantined remote capabilities")
            }
            fn put(&self, _: &StoredMemory) -> Result<bool> {
                panic!("quarantined push")
            }
            fn all(&self, _: bool) -> Result<Vec<StoredMemory>> {
                panic!("quarantined pull")
            }
            fn max_updated_at(&self) -> Result<Option<String>> {
                panic!("quarantined cursor")
            }
            fn forget(&self, _: &str) -> Result<bool> {
                panic!("quarantined delete")
            }
            fn count(&self) -> Result<i64> {
                panic!("quarantined count")
            }
        }
        let root = tempfile::tempdir()?;
        let local = LocalStore::open(&root.path().join("rsrs.db"))?;
        local.meta_set("snapshot_sync_quarantine_v1", "synthetic")?;
        let error = sync_all(&SessionKeys::from_urk([7; 32])?, &local, &UnreachableRemote)
            .err()
            .ok_or_else(|| anyhow::anyhow!("quarantined sync succeeded"))?;
        anyhow::ensure!(
            error.to_string().contains("quarantined"),
            "unexpected sync error: {error}"
        );
        Ok(())
    }

    /// Wrap a local store as a "remote" (fake cloud for tests).
    fn fake_remote(store: &LocalStore) -> FakeRemote<'_> {
        FakeRemote(store)
    }

    struct FakeRemote<'a>(&'a LocalStore);

    impl MemoryTransport for FakeRemote<'_> {
        fn put(&self, memory: &StoredMemory) -> Result<bool> {
            self.0.put(memory)
        }
        fn all(&self, include_deleted: bool) -> Result<Vec<StoredMemory>> {
            self.0.all(include_deleted)
        }
        fn max_updated_at(&self) -> Result<Option<String>> {
            self.0.max_updated_at()
        }
        fn forget(&self, id: &str) -> Result<bool> {
            self.0.forget(id)
        }
        fn count(&self) -> Result<i64> {
            self.0.count()
        }
    }

    /// Batch-push failure path: first batch ok, second fails — succeeded batch is undirtied, leftover stays dirty for a retry.
    #[test]
    fn sync_push_batch_failure_keeps_uncleaned_dirty() -> anyhow::Result<()> {
        let keys = SessionKeys::from_urk([42u8; 32])?;
        let dir = tempfile::tempdir()?;
        let embedder = HashingEmbedder::default();
        let cloud = LocalStore::open(&dir.path().join("cloud.db"))?;
        let a = LocalStore::open(&dir.path().join("a.db"))?;
        for i in 0..101 {
            let e = entry(&format!("bulk-{i}"), &format!("\u{6279}\u{91cf}\u{6761}\u{76ee} {i}"));
            let s = MemoryEngine::seal(&keys, &embedder, &e, "u")?;
            a.put(&s)?;
        }
        let remote = FlakyBatchRemote {
            cloud: &cloud,
            calls: std::cell::Cell::new(0),
        };
        let err = sync_all(&keys, &a, &remote).unwrap_err();
        assert!(err.to_string().contains("batch 2 failed"));
        // First batch (100 rows) pushed and undirtied; leftover 1 stays dirty for the next push
        assert_eq!(a.all_dirty()?.len(), 1);
        assert_eq!(cloud.count()?, 100);
        // Retry: a healthy remote finishes and takes the leftover
        let stats = sync_all(&keys, &a, &fake_remote(&cloud))?;
        assert_eq!(stats.pushed, 1);
        assert_eq!(cloud.count()?, 101);
        Ok(())
    }

    struct FlakyBatchRemote<'a> {
        cloud: &'a LocalStore,
        calls: std::cell::Cell<usize>,
    }

    impl MemoryTransport for FlakyBatchRemote<'_> {
        fn put(&self, memory: &StoredMemory) -> Result<bool> {
            self.cloud.put(memory)
        }
        fn put_batch(&self, memories: &[StoredMemory]) -> Result<Vec<bool>> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            if n >= 1 {
                anyhow::bail!("batch 2 failed");
            }
            let mut out = Vec::with_capacity(memories.len());
            for m in memories {
                out.push(self.cloud.put(m)?);
            }
            Ok(out)
        }
        fn all(&self, include_deleted: bool) -> Result<Vec<StoredMemory>> {
            self.cloud.all(include_deleted)
        }
        fn max_updated_at(&self) -> Result<Option<String>> {
            self.cloud.max_updated_at()
        }
        fn forget(&self, id: &str) -> Result<bool> {
            self.cloud.forget(id)
        }
        fn count(&self) -> Result<i64> {
            self.cloud.count()
        }
    }
}

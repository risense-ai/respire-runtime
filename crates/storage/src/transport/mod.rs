//! transport — memory transport abstraction
//!
//! local-first freeze (2026-09-02): server = dumb ciphertext store (cloud backup);
//! sync is two-way ciphertext copy: local library ↔ cloud. Search / dedup / merge are local.
//!
//! Sole contract: `MemoryTransport`. Implementors move `StoredMemory` and never see
//! plaintext (`local_*` fields are serde skip, not uploaded).

pub mod local;
pub mod protocol;

use anyhow::Result;

use crate::memory::model::StoredMemory;

/// Compare RFC3339 versions by real time; an empty legacy stamp is less than any valid time.
pub fn compare_timestamps(left: &str, right: &str) -> Result<std::cmp::Ordering> {
    if left.is_empty() || right.is_empty() {
        return Ok(left.cmp(right));
    }
    Ok(chrono::DateTime::parse_from_rfc3339(left)?
        .cmp(&chrono::DateTime::parse_from_rfc3339(right)?))
}

/// This edit must be later than the record's current version, even if the local clock stepped back or two edits share a millisecond.
pub fn timestamp_after(previous: Option<&str>) -> Result<String> {
    let now = chrono::Utc::now();
    // Empty stamp on old records means "no version time yet".
    let stamp = if let Some(previous) = previous.filter(|value| !value.is_empty()) {
        let old = chrono::DateTime::parse_from_rfc3339(previous)?.with_timezone(&chrono::Utc);
        let next = old.checked_add_signed(chrono::Duration::milliseconds(1))
            .ok_or_else(|| anyhow::anyhow!("record timestamp is outside the advanceable range"))?;
        now.max(next)
    } else {
        now
    };
    Ok(stamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// Incremental fetch result.
#[derive(Debug, Clone, Default)]
pub struct FetchReply {
    /// Objects to store this round (since=None → full set; else server arrival-order rev>since, including tombstones)
    pub blobs: Vec<StoredMemory>,
    /// Server arrival-order cursor (pass as since on the next fetch)
    pub cursor: u64,
    /// Remote object count (including tombstones)
    pub total: u64,
    /// Remote live object count
    pub alive: u64,
}

/// Unified memory store/sync interface.
///
/// Local impl = authoritative working library; remote impl = cloud backup store.
/// Conflict: same id, last-write-wins on updated_at.
pub trait MemoryTransport {
    /// None denotes a legacy server; transport failures must not imply downgrade.
    fn capabilities(&self) -> Result<Option<protocol::Capabilities>> { Ok(None) }

    fn resolve_conflicts(&self,_request:&protocol::ResolveRequest)->Result<protocol::ResolveReply> {
        anyhow::bail!("remote does not support conflict resolution")
    }

    fn fetch_resolutions(&self,_epoch:&str,_after:i64,_until:Option<i64>)->Result<protocol::ResolutionPage> {
        anyhow::bail!("remote does not support conflict resolution")
    }

    fn push_v2(&self, _request: &protocol::PushRequest) -> Result<protocol::PushReply> {
        anyhow::bail!("remote does not support sync v2")
    }

    fn pull_v2(&self, _epoch: &str, _after: i64, _until: Option<i64>, _snapshot: bool)
        -> Result<protocol::Page> {
        anyhow::bail!("remote does not support sync v2")
    }

    /// Upsert one row (overwrite if same id exists and updated_at is newer).
    /// Returns whether a write happened (false = server/local already has a newer version; drop this).
    fn put(&self, memory: &StoredMemory) -> Result<bool>;

    /// Batch upsert: one round-trip carries a batch; returns per-item replaced, same length as input.
    /// Default impl calls put one by one (local store / test doubles); remote should override with
    /// /push/batch to fold N HTTP round-trips into one (server writes in a single transaction).
    /// Contract: result length equals input length and is in the same order.
    fn put_batch(&self, memories: &[StoredMemory]) -> Result<Vec<bool>> {
        let mut replaced = Vec::with_capacity(memories.len());
        for m in memories {
            replaced.push(self.put(m)?);
        }
        Ok(replaced)
    }

    /// Full fetch (sync/mirror). include_deleted=true includes tombstones.
    fn all(&self, include_deleted: bool) -> Result<Vec<StoredMemory>>;

    /// Incremental fetch (sync main path): since=None → full set; Some(n) → server arrival-order rev>n.
    ///
    /// Cursor = **server arrival order** (integer incremented on each push), not a client timestamp —
    /// a fast local clock cannot skip remote objects.
    /// Default impl is a full fetch (cursor=0) for local store / test doubles; remote must push down (/pull?since).
    fn fetch_rev(&self, _since: Option<u64>) -> Result<FetchReply> {
        let blobs = self.all(true)?;
        let total = blobs.len() as u64;
        let alive = blobs.iter().filter(|b| !b.deleted).count() as u64;
        Ok(FetchReply {
            blobs,
            cursor: 0,
            total,
            alive,
        })
    }

    /// Sync cursor: latest updated_at already synced (None if empty).
    fn max_updated_at(&self) -> Result<Option<String>>;

    /// Delete: mark tombstone (deleted=true + refresh updated_at); propagates with sync.
    fn forget(&self, id: &str) -> Result<bool>;

    /// Count (excluding tombstones).
    fn count(&self) -> Result<i64>;
}

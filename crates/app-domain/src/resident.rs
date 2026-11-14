//! Host-side authorized catalog cache; private retrieval state stays in Core.
use anyhow::{Context, Result};
use respire_crypto::{MemoryEngine, SessionKeys};
use respire_protocol::StoredMemory;
use respire_storage::transport::local::LocalStore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

struct Cache {
    identity: Vec<u8>,
    revision: i64,
    memories: Arc<Vec<StoredMemory>>,
    lease: Arc<respire_core_sdk::ResidentLease>,
    pending: usize,
}

struct AuthorizedCache {
    identity: Vec<u8>,
    snapshot: Vec<u8>,
    ids: HashSet<String>,
    lease: Arc<respire_core_sdk::ResidentLease>,
}

#[cfg(test)]
#[path = "resident_tests.rs"]
mod tests;

static CACHE: Mutex<Option<Arc<Cache>>> = Mutex::new(None);
static AUTHORIZED_CACHE: Mutex<Option<Arc<AuthorizedCache>>> = Mutex::new(None);
static REFRESH: Mutex<()> = Mutex::new(());
static EPOCH: AtomicU64 = AtomicU64::new(0);

pub fn clear() -> Result<()> {
    let mut slot = CACHE.lock().map_err(|_| anyhow::anyhow!("resident catalog cache poisoned"))?;
    let mut authorized = AUTHORIZED_CACHE.lock().map_err(|_| anyhow::anyhow!("authorized resident cache poisoned"))?;
    EPOCH.fetch_add(1, Ordering::AcqRel);
    *slot = None;
    *authorized = None;
    Ok(())
}

/// Retain only a Core lease; every request still obtains its own authorized source and proofs.
pub fn recall_authorized_lease(keys: &SessionKeys, store: &LocalStore, owner: &str,
    source: &crate::review::AuthorizedRecallSource) -> Result<Arc<respire_core_sdk::ResidentLease>> {
    let epoch = EPOCH.load(Ordering::Acquire);
    let model = store.retrieval_model()?;
    let mut hash = Sha256::new();
    hash.update(serde_json::to_vec(&(store.library_identity()?, store.active_generation_key()?, owner, &model))?);
    hash.update(keys.urk);
    let identity = hash.finalize().to_vec();
    // Include the complete authorized snapshot, including artifacts and heat. Content
    // revision alone deliberately excludes those fields and cannot identify a Core view.
    let snapshot = Sha256::digest(serde_json::to_vec(source.snapshots())?).to_vec();
    let _refresh = REFRESH.lock().map_err(|_| anyhow::anyhow!("resident refresh poisoned"))?;
    let cached = AUTHORIZED_CACHE.lock().map_err(|_| anyhow::anyhow!("authorized resident cache poisoned"))?.clone();
    let matching = cached.as_ref().filter(|cached| cached.identity == identity && cached.lease.current());
    if let Some(cached) = matching.filter(|cached| cached.snapshot == snapshot) {
        return Ok(Arc::clone(&cached.lease));
    }
    let source_current = store.memory_revision()? == source.memory_revision();
    let ids: HashSet<String> = source.memories().iter().map(|memory| memory.id.clone()).collect();
    let removed: Vec<String> = matching.map(|cached| cached.ids.difference(&ids).cloned().collect()).unwrap_or_default();
    let lease = respire_core_sdk::ResidentLease::publish(uuid::Uuid::new_v4().to_string(),
        matching.map(|cached| cached.lease.as_ref()), &model, source.snapshots(), &removed)?;
    let mut slot = AUTHORIZED_CACHE.lock().map_err(|_| anyhow::anyhow!("authorized resident cache poisoned"))?;
    // A cleared context cannot be repopulated by an earlier in-flight publication.
    if source_current && store.memory_revision()? == source.memory_revision()
        && EPOCH.load(Ordering::Acquire) == epoch && lease.current() {
        *slot = Some(Arc::new(AuthorizedCache { identity, snapshot, ids, lease: Arc::clone(&lease) }));
    }
    Ok(lease)
}

pub fn recall_catalog(keys: &SessionKeys, store: &LocalStore)
    -> Result<(Arc<Vec<StoredMemory>>, usize, Arc<respire_core_sdk::ResidentLease>)> {
    let mut hash = Sha256::new();
    hash.update(store.library_identity()?.as_bytes());
    hash.update(store.active_generation_key()?.as_bytes());
    hash.update(keys.urk);
    let identity = hash.finalize().to_vec();
    let revision = store.retrieval_revision()?;
    let cached = CACHE.lock().map_err(|_| anyhow::anyhow!("resident catalog cache poisoned"))?.clone();
    if let Some(cache) = cached.as_ref().filter(|cache| cache.lease.current() && cache.identity == identity && cache.revision == revision) {
        return Ok((Arc::clone(&cache.memories), cache.pending, Arc::clone(&cache.lease)));
    }
    // Serialize refreshes, keeping decryption and Core publication outside the reader lock.
    let _refresh = REFRESH.lock().map_err(|_| anyhow::anyhow!("resident refresh poisoned"))?;
    let epoch = EPOCH.load(Ordering::Acquire);
    let cached = CACHE.lock().map_err(|_| anyhow::anyhow!("resident catalog cache poisoned"))?.clone();
    let revision = store.retrieval_revision()?;
    let matching = cached.as_ref().filter(|cache| cache.lease.current() && cache.identity == identity);
    if let Some(cache) = matching.filter(|cache| cache.revision == revision) {
        return Ok((Arc::clone(&cache.memories), cache.pending, Arc::clone(&cache.lease)));
    }
    let matching = matching.filter(|cache| cache.revision <= revision);
    let (revision, mut delta, removed) = store.retrieval_delta(matching.map(|cache| cache.revision))?;
    let mut snapshots = Vec::with_capacity(delta.len());
    for memory in &mut delta {
        let entry = MemoryEngine::open(keys, memory).context("decrypt changed resident entry")?;
        snapshots.push(respire_core_sdk::Snapshot::new(memory, Some(entry)));
        // Catalog metadata suffices after Core has received the authorized body.
        // Clear would retain the encrypted-body allocation in the long-lived cache.
        memory.ciphertext = String::new();
        memory.nonce = String::new();
        memory.embedding_enc = String::new();
    }
    let lease = respire_core_sdk::ResidentLease::publish(uuid::Uuid::new_v4().to_string(),
        matching.map(|cache| cache.lease.as_ref()), &store.retrieval_model()?, &snapshots, &removed)?;
    drop(snapshots);
    let changed: HashSet<&str> = delta.iter().map(|memory| memory.id.as_str()).collect();
    let removed: HashSet<&str> = removed.iter().map(String::as_str).collect();
    let mut memories = Vec::new();
    if let Some(cache) = matching {
        memories.extend(cache.memories.iter().filter(|memory|
            !changed.contains(memory.id.as_str()) && !removed.contains(memory.id.as_str())).cloned());
    }
    memories.extend(delta);
    let pending = memories.iter().filter(|memory| memory.local_artifact.is_empty()).count();
    let memories = Arc::new(memories);
    let mut slot = CACHE.lock().map_err(|_| anyhow::anyhow!("resident catalog cache poisoned"))?;
    anyhow::ensure!(EPOCH.load(Ordering::Acquire) == epoch, "library changed during resident refresh");
    *slot = Some(Arc::new(Cache { identity, revision, memories:Arc::clone(&memories), lease:Arc::clone(&lease), pending }));
    Ok((memories, pending, lease))
}

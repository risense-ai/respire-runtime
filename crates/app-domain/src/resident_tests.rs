use super::*;
use respire_protocol::{MemoryEntry, MemoryQuery};
use respire_storage::transport::MemoryTransport;

fn seal_pending(keys: &SessionKeys, id: &str, title: &str, stamp: &str) -> Result<StoredMemory> {
    let entry: MemoryEntry = serde_json::from_value(serde_json::json!({
        "id":id,"kind":"Context","tags":[],"title":title,"content":format!("{}resident regression keyword", "synthetic prefix ".repeat(64)),
        "user":"test","computer":"test","project":"","created_at":stamp,"updated_at":stamp,
        "emotion":0,"parent_id":"","importance":"important"
    }))?;
    let _defer = respire_core_sdk::defer_indexing();
    MemoryEngine::seal(keys, &respire_core_sdk::search::HashingEmbedder::new(1024), &entry, "test")
}

/// Populate the legacy persisted field with valid synthetic encrypted float bytes.
fn legacy_embedding(keys: &SessionKeys, value: f32) -> Result<String> {
    let key = respire_crypto::crypto::derive_subkey(&keys.urk, b"rsrs:embedding:v1")?;
    let (nonce, ciphertext) = respire_crypto::crypto::encrypt_bytes(&key, &value.to_le_bytes())?;
    Ok(format!("rsrs:v1:{nonce}:{ciphertext}"))
}

fn recall(lease: &respire_core_sdk::ResidentLease) -> Result<Vec<MemoryEntry>> {
    let _scope = lease.enter();
    let provider = respire_core_sdk::bge::BgeEmbedder::load_model("m3")?;
    respire_core_sdk::query(&provider, &[], &MemoryQuery::new("resident regression keyword").limit(5), "plain")
}

#[test]
fn unchanged_catalog_reuses_arcs_and_old_readers_survive_updates_and_deletes() -> Result<()> {
    let _guard = crate::test_lock::guard();
    clear()?;
    let dir = tempfile::tempdir()?;
    let store = LocalStore::open(&dir.path().join("resident.db"))?;
    let keys = SessionKeys::from_urk([7; 32])?;
    let mut original = seal_pending(&keys, "one", "before", "2026-10-10T00:00:00Z")?;
    // Legacy encrypted embedding bytes still exist in imported stored rows.
    original.embedding_enc = legacy_embedding(&keys, 0.25)?;
    store.put_checked(&original, None)?;
    let persisted = store.all(true)?.into_iter().find(|row| row.id == "one").context("seed row missing")?;
    assert!(!persisted.embedding_enc.is_empty() && persisted.embedding_enc.capacity() > 0);
    let (first, pending, old_lease) = recall_catalog(&keys, &store)?;
    assert_eq!(pending, 1);
    assert!(first[0].ciphertext.is_empty());
    assert_eq!(first[0].ciphertext.capacity(), 0);
    assert_eq!(first[0].nonce.capacity(), 0);
    assert_eq!(first[0].embedding_enc.capacity(), 0);
    let (same, _, same_lease) = recall_catalog(&keys, &store)?;
    assert!(Arc::ptr_eq(&first, &same));
    assert!(Arc::ptr_eq(&old_lease, &same_lease));
    let saved = store.all(true)?.into_iter().find(|row| row.id == "one").context("persisted row missing")?;
    assert_eq!((&saved.ciphertext, &saved.nonce, &saved.embedding_enc),
        (&original.ciphertext, &original.nonce, &original.embedding_enc));
    let mut newer = seal_pending(&keys, "one", "after", &store.edit_stamp("one")?)?;
    newer.embedding_enc = legacy_embedding(&keys, 0.75)?;
    store.put_checked(&newer, Some(&original.ciphertext))?;
    let (refreshed, _, new_lease) = recall_catalog(&keys, &store)?;
    assert_eq!(refreshed[0].ciphertext.capacity(), 0);
    assert_eq!(refreshed[0].nonce.capacity(), 0);
    assert_eq!(refreshed[0].embedding_enc.capacity(), 0);
    let saved = store.all(true)?.into_iter().find(|row| row.id == "one").context("updated row missing")?;
    assert_eq!((&saved.ciphertext, &saved.nonce, &saved.embedding_enc),
        (&newer.ciphertext, &newer.nonce, &newer.embedding_enc));
    std::thread::scope(|scope| -> Result<()> {
        let readers = (0..4).map(|_| scope.spawn(|| -> Result<()> {
            assert_eq!(recall(&old_lease)?.first().context("old concurrent reader empty")?.title, "before");
            assert_eq!(recall(&new_lease)?.first().context("new concurrent reader empty")?.title, "after");
            Ok(())
        })).collect::<Vec<_>>();
        for reader in readers { reader.join().map_err(|_| anyhow::anyhow!("concurrent reader panicked"))??; }
        Ok(())
    })?;
    let old_entry = recall(&old_lease)?.into_iter().next().context("retained pending snapshot was not recalled")?;
    assert_eq!(old_entry.title, "before");
    assert_eq!(old_entry.content, MemoryEngine::open(&keys, &original)?.content);
    assert_eq!(recall(&new_lease)?.first().context("updated pending snapshot was not recalled")?.title, "after");
    store.forget("one")?;
    let (empty, pending, empty_lease) = recall_catalog(&keys, &store)?;
    assert!(empty.is_empty());
    assert_eq!(pending, 0);
    assert!(recall(&empty_lease)?.is_empty());
    let old_entry = recall(&old_lease)?.into_iter().next().context("retained pending snapshot was not recalled")?;
    assert_eq!(old_entry.title, "before");
    assert_eq!(old_entry.content, MemoryEngine::open(&keys, &original)?.content);
    clear()?;
    Ok(())
}

/// A reader-owned generation survives publication and cache clear on another thread.
#[test]
fn concurrent_reader_survives_refresh_and_clear_with_full_body() -> Result<()> {
    let _guard = crate::test_lock::guard();
    clear()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("concurrent-resident.db");
    let store = LocalStore::open(&path)?;
    let keys = SessionKeys::from_urk([7; 32])?;
    let original = seal_pending(&keys, "threaded", "before", "2026-10-10T00:00:00Z")?;
    store.put_checked(&original, None)?;
    let expected = MemoryEngine::open(&keys, &original)?.content;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (phase_tx, phase_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| -> Result<()> {
        let reader_path = path.clone();
        let reader = scope.spawn(move || -> Result<()> {
            let reader_store = LocalStore::open_existing(&reader_path)?;
            let reader_keys = SessionKeys::from_urk([7; 32])?;
            let (catalog, _, lease) = recall_catalog(&reader_keys, &reader_store)?;
            ready_tx.send(())?;
            for _ in 0..2 {
                phase_rx.recv_timeout(std::time::Duration::from_secs(5))?;
                let entry = recall(&lease)?.into_iter().next().context("retained reader empty")?;
                assert_eq!(entry.title, "before");
                assert_eq!(entry.content, expected);
                assert_eq!(catalog[0].ciphertext.capacity(), 0);
                ready_tx.send(())?;
            }
            Ok(())
        });
        ready_rx.recv_timeout(std::time::Duration::from_secs(5))?;
        let newer = seal_pending(&keys, "threaded", "after", &store.edit_stamp("threaded")?)?;
        store.put_checked(&newer, Some(&original.ciphertext))?;
        let (_, _, fresh) = recall_catalog(&keys, &store)?;
        assert_eq!(recall(&fresh)?.first().context("fresh reader empty")?.title, "after");
        phase_tx.send(())?;
        ready_rx.recv_timeout(std::time::Duration::from_secs(5))?;
        clear()?;
        let (_, _, rebuilt) = recall_catalog(&keys, &store)?;
        assert_eq!(recall(&rebuilt)?.first().context("rebuilt reader empty")?.title, "after");
        phase_tx.send(())?;
        ready_rx.recv_timeout(std::time::Duration::from_secs(5))?;
        reader.join().map_err(|_| anyhow::anyhow!("retained reader panicked"))??;
        Ok(())
    })?;
    clear()?;
    Ok(())
}

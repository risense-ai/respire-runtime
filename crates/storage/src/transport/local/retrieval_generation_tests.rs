use super::*;
use crate::memory::search::{Embedder, HashingEmbedder};
use crate::memory::{MemoryEngine, SessionKeys};
use crate::transport::MemoryTransport;
use crate::MemoryEntry;
use anyhow::Context;
use respire_core_sdk::{profiles, Prepared};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FixtureEmbedder {
    calls: AtomicUsize,
    model: String,
}

impl Embedder for FixtureEmbedder {
    fn model_name(&self) -> &str {
        &self.model
    }

    fn dims(&self) -> usize {
        32
    }

    fn prepare(&self, entry: &MemoryEntry) -> Result<Prepared> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        // Generate a real native-format test artifact independently of the
        // fictional profile. Real model activation is exercised separately.
        HashingEmbedder::new(self.dims()).prepare(entry)
    }
}

fn profile(model: &str, revision: &str) -> Result<profiles::Selection> {
    Ok(serde_json::from_value(json!({
        "model": model,
        "backend": "onnx",
        "engine": "cpu",
        "profile": {
            "id": model,
            "onnx": {"input_ids": "input_ids"},
            "embedding": {
                "model_id": model, "revision": revision, "dimensions": 32,
                "max_tokens": 32, "pooling": "mean", "normalize": true,
                "query_prefix": "", "document_prefix": ""
            },
            "weights": {"path": "unused-weights", "size": 1, "sha256": "0".repeat(64)},
            "tokenizer": {"path": "unused-tokenizer", "size": 1, "sha256": "0".repeat(64)}
        },
        "backend_profile": {"id": "onnx", "backend": "onnx"}
    }))?)
}

fn source(keys: &SessionKeys, id: &str, timestamp: &str) -> Result<crate::StoredMemory> {
    let entry: MemoryEntry = serde_json::from_value(json!({
        "id": id, "kind":"Context", "tags":[], "title": "Synthetic fixture",
        "content": format!("Synthetic index repair fixture {id}"),
        "user":"fixture", "computer":"", "project":"", "parent_id":"", "emotion":-1.0,
        "created_at":"2026-11-20T00:00:00Z", "updated_at":timestamp
    }))?;
    let _deferred = respire_core_sdk::defer_indexing();
    MemoryEngine::seal(keys, &HashingEmbedder::new(32), &entry, "fixture")
}

fn fixture(target: &profiles::Selection) -> FixtureEmbedder {
    FixtureEmbedder {
        calls: AtomicUsize::new(0),
        model: target.model.clone(),
    }
}

fn generation_records(store: &LocalStore, generation: &str) -> Result<Vec<String>> {
    let mut query = store
        .connection
        .prepare("SELECT memory_id FROM core_artifacts WHERE model=?1 ORDER BY memory_id")?;
    let rows = query.query_map([generation], |row| row.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[derive(Debug)]
struct FixtureCancelled;

impl std::fmt::Display for FixtureCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("fixture cancelled")
    }
}

impl std::error::Error for FixtureCancelled {}

#[test]
fn candidate_cancellation_retains_completed_checkpoints_and_retries_only_missing() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let store = LocalStore::open(&temporary.path().join("db.sqlite"))?;
    let keys = SessionKeys::from_urk([7; 32])?;
    store.put(&source(&keys, "first", "2026-11-22T00:00:00Z")?)?;
    store.put(&source(&keys, "second", "2026-11-21T00:00:00Z")?)?;
    let target = profile("fixture-target", "target-r1")?;
    let incumbent = profile("fixture-target", "incumbent-r1")?;
    let target_key = profiles::generation_key_for_profile(&target)?;
    let incumbent_key = profiles::generation_key_for_profile(&incumbent)?;
    assert_ne!(target_key, incumbent_key);
    let embedder = fixture(&target);
    profiles::scoped(incumbent.clone(), || {
        let result =
            store.build_candidate_index_with_progress(&keys, &embedder, &target, |done, total| {
                let selected = profiles::current()?.context("candidate profile missing")?;
                assert_eq!(selected.profile.embedding["revision"], "target-r1");
                if done == 1 && total == 2 {
                    return Err(FixtureCancelled.into());
                }
                Ok(())
            });
        let error = result.err().context("candidate ignored cancellation")?;
        assert!(error.downcast_ref::<FixtureCancelled>().is_some());
        let selected = profiles::current()?.context("incumbent profile not restored")?;
        assert_eq!(selected.profile.embedding["revision"], "incumbent-r1");
        assert_eq!(embedder.calls.load(Ordering::Relaxed), 1);
        assert_eq!(generation_records(&store, &target_key)?, ["first"]);
        assert!(generation_records(&store, &incumbent_key)?.is_empty());
        assert_eq!(store.meta_get("retrieval_model")?, None);

        assert_eq!(
            store.build_candidate_index_with_progress(&keys, &embedder, &target, |_, _| Ok(()))?,
            1
        );
        assert_eq!(embedder.calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            generation_records(&store, &target_key)?,
            ["first", "second"]
        );
        assert!(generation_records(&store, &incumbent_key)?.is_empty());
        assert_eq!(store.meta_get("retrieval_model")?, None);
        assert!(store.active_selection()?.is_none());
        Ok(())
    })
}

#[test]
fn candidate_checkpoint_cannot_publish_over_replaced_source() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("db.sqlite");
    let store = LocalStore::open(&path)?;
    let writer = LocalStore::open_existing(&path)?;
    let keys = SessionKeys::from_urk([9; 32])?;
    let first = source(&keys, "source", "2026-11-21T00:00:00Z")?;
    let changed = source(&keys, "source", "2026-11-22T00:00:00Z")?;
    assert!(store.put(&first)?);
    let target = profile("fixture-target", "target-r1")?;
    let target_key = profiles::generation_key_for_profile(&target)?;
    let embedder = fixture(&target);
    let mut edited = false;
    let result =
        store.build_candidate_index_with_progress(&keys, &embedder, &target, |done, total| {
            if total == 1 && done == 0 && embedder.calls.load(Ordering::Relaxed) == 1 && !edited {
                assert!(writer.put(&changed)?);
                edited = true;
            }
            Ok(())
        });
    assert!(edited);
    let error = result.err().context("stale source was indexed")?;
    assert_eq!(
        error
            .downcast_ref::<IndexSourceChanged>()
            .map(|e| e.pending),
        Some(1)
    );
    assert!(generation_records(&store, &target_key)?.is_empty());
    assert_eq!(
        store.build_candidate_index_with_progress(&keys, &embedder, &target, |_, _| Ok(()))?,
        1
    );
    assert_eq!(generation_records(&store, &target_key)?, ["source"]);
    let actual_source: String = store.connection.query_row(
        "SELECT source FROM core_artifacts WHERE memory_id='source' AND model=?1",
        [&target_key],
        |row| row.get(0),
    )?;
    assert_eq!(actual_source, changed.ciphertext);
    Ok(())
}

#[test]
fn candidate_cancellation_still_precedes_the_row_artifact_decode_error() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let store = LocalStore::open(&temporary.path().join("db.sqlite"))?;
    let keys = SessionKeys::from_urk([7; 32])?;
    let memory = source(&keys, "source", "2026-11-22T00:00:00Z")?;
    assert!(store.put(&memory)?);
    let target = profile("fixture-target", "target-r1")?;
    let target_key = profiles::generation_key_for_profile(&target)?;
    store.connection.execute(
        "INSERT INTO core_artifacts(memory_id,model,source,artifact) VALUES (?1,?2,?3,'invalid SQLite type')",
        params![memory.id, target_key, memory.ciphertext],
    )?;
    let embedder = fixture(&target);
    let mut row_checkpoints = 0;
    let interrupted =
        store.build_candidate_index_with_progress(&keys, &embedder, &target, |_, total| {
            if total == 1 {
                row_checkpoints += 1;
                if row_checkpoints == 2 {
                    return Err(FixtureCancelled.into());
                }
            }
            Ok(())
        });
    let interrupted = interrupted
        .err()
        .context("candidate ignored cancellation")?;
    assert!(interrupted.downcast_ref::<FixtureCancelled>().is_some());
    let failed =
        store.build_candidate_index_with_progress(&keys, &embedder, &target, |_, _| Ok(()));
    let failed = failed.err().context("invalid artifact type accepted")?;
    assert!(matches!(
        failed.downcast_ref::<rusqlite::Error>(),
        Some(rusqlite::Error::InvalidColumnType(0, name, rusqlite::types::Type::Text)) if name == "artifact"
    ));
    assert_eq!(embedder.calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn candidate_observes_newly_published_artifact_after_progress_checkpoint() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("db.sqlite");
    let store = LocalStore::open(&path)?;
    let writer = LocalStore::open_existing(&path)?;
    let keys = SessionKeys::from_urk([7; 32])?;
    let memory = source(&keys, "source", "2026-11-22T00:00:00Z")?;
    assert!(store.put(&memory)?);
    let target = profile("fixture-target", "target-r1")?;
    let target_key = profiles::generation_key_for_profile(&target)?;
    let embedder = fixture(&target);
    let opened = MemoryEngine::open(&keys, &memory)?;
    let prepared = HashingEmbedder::new(32).prepare(&opened)?;
    let mut row_checkpoints = 0;
    assert_eq!(
        store.build_candidate_index_with_progress(&keys, &embedder, &target, |_, total| {
            if total == 1 {
                row_checkpoints += 1;
                if row_checkpoints == 2 {
                    writer.connection.execute(
                        "INSERT INTO core_artifacts(memory_id,model,source,artifact) VALUES (?1,?2,?3,?4)",
                        params![memory.id, target_key, memory.ciphertext, prepared.artifact],
                    )?;
                }
            }
            Ok(())
        })?,
        0
    );
    assert_eq!(embedder.calls.load(Ordering::Relaxed), 0);
    assert_eq!(generation_records(&store, &target_key)?, ["source"]);
    Ok(())
}

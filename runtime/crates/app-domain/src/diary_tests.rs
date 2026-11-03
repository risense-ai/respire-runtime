use super::*;

fn fixture(content: String) -> Result<(crate::test_lock::Isolate, LocalStore, SessionKeys)> {
    let isolate = crate::test_lock::Isolate::new()?;
    let store = LocalStore::open(&isolate.path().join("diary.db"))?;
    let keys = SessionKeys::from_urk([37; 32])?;
    let entry = MemoryEntry {
        metadata: Default::default(),
        unknown_fields: Default::default(),
        id: "synthetic-diary-source".into(),
        kind: crate::Kind::Time,
        tags: vec![],
        title: "Synthetic diary".into(),
        content,
        user: "synthetic".into(),
        computer: "fixture".into(),
        project: "fixture".into(),
        created_at: "2026-10-27T09:00:00Z".into(),
        updated_at: "2026-10-27T09:00:00Z".into(),
        emotion: -1.0,
        parent_id: String::new(),
        importance: "trivial".into(),
        device: "fixture".into(),
        modified_by: "fixture".into(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: vec![],
    };
    let stored = MemoryEngine::seal(
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        &entry,
        "synthetic",
    )?;
    assert!(store.put(&stored)?);
    Ok((isolate, store, keys))
}

#[test]
fn lexical_finds_long_keyword_across_index_fragment_boundary() -> Result<()> {
    let query: String = (0..200)
        .map(|n| char::from_u32(0x4e00 + n).unwrap())
        .collect();
    let content = format!("{}{}{}", "x".repeat(700), query, "x".repeat(700));
    let (_isolate, store, keys) = fixture(content.clone())?;
    let result = search(&store, &keys, &query, 5, 4000, false)?;
    assert!(
        !result.items.is_empty(),
        "full-text keyword must not disappear at an indexing boundary"
    );
    assert!(result.items[0].text.contains(&query));
    let hit = &result.items[0];
    assert_eq!(
        hit.text,
        content
            .chars()
            .skip(hit.start)
            .take(hit.end - hit.start)
            .collect::<String>()
    );
    let read = read_fragment(&store, &keys, &hit.source_id, &hit.fragment_id, 0, 4000)?;
    assert!(read.items.iter().any(|item| item.text.contains(&query)));
    Ok(())
}

#[test]
fn lexical_does_not_depend_on_corrupt_derived_cache() -> Result<()> {
    let (isolate, store, keys) = fixture("authoritative original diary keyword".into())?;
    std::fs::write(
        isolate.path().join("diary-fragments-v1.db"),
        b"corrupt derived cache",
    )?;
    let result = search(&store, &keys, "keyword", 5, 4000, false)?;
    assert_eq!(result.items.len(), 1);
    assert!(!result.semantic_ready);
    Ok(())
}

#[test]
fn unicode_case_expansion_and_multiple_terms_keep_original_offsets() -> Result<()> {
    let content = format!("{}\u{130}STANBUL \u{4e2d}\u{6587}🧠{}", "🙂".repeat(795), "x".repeat(900));
    let (_isolate, store, keys) = fixture(content.clone())?;
    let result = search(&store, &keys, "i\u{307}stanbul \u{4e2d}\u{6587}", 5, 4000, false)?;
    assert_eq!(result.items.len(), 1);
    let hit = &result.items[0];
    assert!(hit.text.contains("\u{130}STANBUL \u{4e2d}\u{6587}🧠"));
    assert_eq!(
        hit.text,
        content
            .chars()
            .skip(hit.start)
            .take(hit.end - hit.start)
            .collect::<String>()
    );
    assert_eq!(hit.evidence_state, "reference");
    assert_eq!(hit.source_kind, "diary");
    Ok(())
}

#[test]
fn full_maximum_keyword_is_found_and_invalid_query_does_not_create_cache() -> Result<()> {
    let query: String = (0..500)
        .map(|n| char::from_u32(0x4e00 + n).unwrap())
        .collect();
    let (_isolate, store, keys) =
        fixture(format!("{}{}{}", "x".repeat(700), query, "x".repeat(700)))?;
    let result = search(&store, &keys, &query, 5, 4000, false)?;
    assert!(result.items.iter().any(|hit| hit.text.contains(&query)));
    assert!(search(&store, &keys, &format!("{query}x"), 5, 4000, false).is_err());
    assert!(search(&store, &keys, " \n ", 5, 4000, false).is_err());
    assert!(!cache_path().exists());
    Ok(())
}

#[test]
fn hybrid_falls_back_and_background_reconstructs_bad_derived_bytes() -> Result<()> {
    let (isolate, store, keys) = fixture("original diary keyword".into())?;
    let path = isolate.path().join("diary-fragments-v1.db");
    let original = b"broken derived cache";
    std::fs::write(&path, original)?;
    let result = search(&store, &keys, "keyword", 5, 4000, true)?;
    assert_eq!(result.items.len(), 1);
    assert!(!result.semantic_ready);
    assert!(result.pending_fragments > 0 && needs_rebuild(&store)?);
    assert_eq!(std::fs::read(&path)?, original);
    rebuild(
        &store,
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        || Ok(()),
        |action| action(),
    )?;
    let db = cache(true)?.unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM diary_sources", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert!(std::fs::read_dir(isolate.path())?
        .filter_map(|e| e.ok())
        .any(|e| e
            .file_name()
            .to_string_lossy()
            .starts_with("diary-fragments-corrupt-")));
    Ok(())
}

struct CancelOnPrepare(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Embedder for CancelOnPrepare {
    fn model_name(&self) -> &str {
        "test-hash:8"
    }
    fn dims(&self) -> usize {
        8
    }
    fn prepare(&self, entry: &MemoryEntry) -> Result<core_sdk::Prepared> {
        let prepared = core_sdk::search::HashingEmbedder::new(8).prepare(entry)?;
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(prepared)
    }
}

#[test]
fn cancellation_during_prepare_cannot_publish_a_cache_artifact() -> Result<()> {
    let (_isolate, store, keys) = fixture("synthetic cancelled source".into())?;
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let before = store.meta_get("memory_revision_v1")?;
    let result = rebuild(
        &store,
        &keys,
        &CancelOnPrepare(cancelled.clone()),
        || Ok(()),
        |action| {
            anyhow::ensure!(
                !cancelled.load(std::sync::atomic::Ordering::SeqCst),
                "cancelled"
            );
            action()
        },
    );
    assert!(result.is_err());
    let db = cache(true)?.unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM diary_artifacts", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM diary_sources", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(before, store.meta_get("memory_revision_v1")?);
    Ok(())
}

struct DeleteOnPrepare(std::path::PathBuf);
impl Embedder for DeleteOnPrepare {
    fn model_name(&self) -> &str {
        "test-hash:8"
    }
    fn dims(&self) -> usize {
        8
    }
    fn prepare(&self, entry: &MemoryEntry) -> Result<core_sdk::Prepared> {
        let other = LocalStore::open_existing(&self.0)?;
        assert!(other.forget("synthetic-diary-source")?);
        core_sdk::search::HashingEmbedder::new(8).prepare(entry)
    }
}

#[test]
fn source_changes_during_prepare_reject_the_derived_commit() -> Result<()> {
    let (isolate, store, keys) = fixture("synthetic source deletion".into())?;
    let result = rebuild(
        &store,
        &keys,
        &DeleteOnPrepare(isolate.path().join("diary.db")),
        || Ok(()),
        |action| action(),
    );
    assert!(result.unwrap_err().to_string().contains("source changed"));
    let db = cache(true)?.unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM diary_artifacts", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert!(store.all(false)?.is_empty());
    Ok(())
}

#[test]
fn cache_cannot_be_an_unrelated_database() -> Result<()> {
    let (isolate, store, keys) = fixture("synthetic source keyword".into())?;
    let path = isolate.path().join("diary-fragments-v1.db");
    let other = Connection::open(&path)?;
    other.execute("CREATE TABLE memories(secret TEXT)", [])?;
    drop(other);
    let before = std::fs::read(&path)?;
    assert!(rebuild(
        &store,
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        || Ok(()),
        |action| action()
    )
    .is_err());
    assert_eq!(std::fs::read(&path)?, before);
    assert_eq!(
        search(&store, &keys, "keyword", 5, 4000, false)?
            .items
            .len(),
        1
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn cache_symlink_never_mutates_the_source_database() -> Result<()> {
    let (isolate, store, keys) = fixture("synthetic source keyword".into())?;
    std::os::unix::fs::symlink(isolate.path().join("diary.db"), cache_path())?;
    let revision = store.meta_get("memory_revision_v1")?;
    assert!(rebuild(
        &store,
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        || Ok(()),
        |action| action()
    )
    .is_err());
    assert_eq!(revision, store.meta_get("memory_revision_v1")?);
    assert_eq!(
        search(&store, &keys, "keyword", 5, 4000, false)?
            .items
            .len(),
        1
    );
    Ok(())
}

#[test]
fn limit_omission_is_reported_even_when_the_character_budget_is_large() -> Result<()> {
    let (_isolate, store, keys) = fixture("first matching keyword".into())?;
    let first = store.all(false)?.remove(0);
    let mut second = first.clone();
    second.id = "another-synthetic-diary".into();
    assert!(store.put(&second)?);
    let result = search(&store, &keys, "keyword", 1, 4000, false)?;
    assert_eq!(result.items.len(), 1);
    assert!(result.truncated);
    let result = search(&store, &keys, "keyword", 2, 4000, false)?;
    assert_eq!(result.items.len(), 2);
    assert!(!result.truncated);
    Ok(())
}

#[test]
fn fixed_overlapping_neighbors_are_immediately_adjacent() -> Result<()> {
    let (_isolate, store, keys) = fixture("x".repeat(2400))?;
    let source = store.all(false)?.remove(0);
    let entry = MemoryEngine::open(&keys, &source)?;
    let pieces = split(&entry, &version(&source));
    assert_eq!((pieces[1].start, pieces[1].end), (720, 1520));
    let result = read_fragment(&store, &keys, &source.id, &pieces[1].fragment_id, 1, 12000)?;
    assert_eq!(
        result
            .items
            .iter()
            .map(|f| (f.start, f.end))
            .collect::<Vec<_>>(),
        [(0, 800), (720, 1520), (1440, 2240)]
    );
    Ok(())
}

#[test]
fn dynamic_lexical_neighbors_extend_both_sides_without_skipping_overlap() -> Result<()> {
    let content = format!("{}uniquekeyword{}", "x".repeat(800), "x".repeat(1600));
    let (_isolate, store, keys) = fixture(content)?;
    let hit = search(&store, &keys, "uniquekeyword", 1, 4000, false)?
        .items
        .remove(0);
    assert!(hit.start > 0 && hit.start < 720);
    let result = read_fragment(&store, &keys, &hit.source_id, &hit.fragment_id, 1, 12000)?;
    assert_eq!(result.items.len(), 3);
    assert_eq!(result.items[0].start, 0);
    assert_eq!(result.items[1].fragment_id, hit.fragment_id);
    assert_eq!(result.items[2].start, 720);
    Ok(())
}

#[test]
fn deleting_last_diary_cleans_derived_rows_without_a_model_provider() -> Result<()> {
    let (_isolate, store, keys) = fixture("synthetic former diary".into())?;
    rebuild(
        &store,
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        || Ok(()),
        |action| action(),
    )?;
    assert!(store.forget("synthetic-diary-source")?);
    assert!(needs_rebuild(&store)?);
    assert!(clear_if_empty(&store, |action| action())?);
    let db = cache(true)?.unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM diary_artifacts", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM diary_sources", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert!(!needs_rebuild(&store)?);
    Ok(())
}

#[test]
fn escaped_json_budget_and_target_priority_hold_at_all_supported_sizes() -> Result<()> {
    let content = format!(
        "{}needle{}",
        "\"\\\u{0001}\n🙂".repeat(250),
        "\"\\\u{0001}\n🙂".repeat(250)
    );
    let (_isolate, store, keys) = fixture(content.clone())?;
    for maximum in [512, 640, 1024, 4000, 12000] {
        let result = search(&store, &keys, "needle", 5, maximum, false)?;
        assert!(serde_json::to_string(&result)?.chars().count() <= maximum);
        if result.items.is_empty() {
            assert!(result.truncated);
            continue;
        }
        let target = &result.items[0];
        if maximum >= 1024 {
            assert!(
                target.text.contains("needle"),
                "budgeted search lost its matched text at {maximum}"
            );
        }
        assert_eq!(
            target.text,
            content
                .chars()
                .skip(target.start)
                .take(target.end - target.start)
                .collect::<String>()
        );
        let read = read_fragment(
            &store,
            &keys,
            &target.source_id,
            &target.fragment_id,
            1,
            maximum,
        )?;
        assert!(serde_json::to_string(&read)?.chars().count() <= maximum);
        if !read.items.is_empty() {
            assert!(read
                .items
                .iter()
                .any(|f| f.fragment_id == target.fragment_id));
        }
    }
    assert!(search(&store, &keys, "needle", 5, 511, false).is_err());
    assert!(read_fragment(&store, &keys, "s", "f", 2, 4000).is_err());
    Ok(())
}

#[test]
fn appending_rotates_public_locators_but_keeps_unchanged_embedding_keys() -> Result<()> {
    let (_isolate, store, keys) = fixture(format!("needle{}", "x".repeat(1800)))?;
    let old_source = store.all(false)?.remove(0);
    let mut entry = MemoryEngine::open(&keys, &old_source)?;
    let before = split(&entry, &version(&old_source));
    let old_locator = before[0].fragment_id.clone();
    entry.content.push_str("\n\u{3010}10:00\u{3011}new synthetic tail");
    entry.updated_at = "2026-10-27T09:00:01Z".into();
    let updated = MemoryEngine::seal(
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        &entry,
        "synthetic",
    )?;
    assert!(store.put(&updated)?);
    let after = split(&entry, &version(&updated));
    assert_eq!(before[0].index_id, after[0].index_id);
    assert_ne!(before[0].fragment_id, after[0].fragment_id);
    assert!(read_fragment(&store, &keys, &old_source.id, &old_locator, 0, 4000).is_err());
    assert_eq!(
        read_fragment(&store, &keys, &updated.id, &after[0].fragment_id, 0, 4000)?.items[0].text,
        after[0].text
    );
    Ok(())
}

#[test]
fn promoting_the_final_diary_cleans_derived_cache_and_excludes_the_source() -> Result<()> {
    let (_isolate, store, keys) = fixture("synthetic promotion keyword".into())?;
    rebuild(
        &store,
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        || Ok(()),
        |action| action(),
    )?;
    let old = store.all(false)?.remove(0);
    let mut entry = MemoryEngine::open(&keys, &old)?;
    entry.importance = "important".into();
    entry.updated_at = "2026-10-27T09:00:01Z".into();
    let updated = MemoryEngine::seal(
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        &entry,
        "synthetic",
    )?;
    assert!(store.put(&updated)?);
    assert!(search(&store, &keys, "keyword", 5, 4000, false)?
        .items
        .is_empty());
    assert!(needs_rebuild(&store)? && clear_if_empty(&store, |action| action())?);
    assert!(!needs_rebuild(&store)?);
    Ok(())
}

#[test]
fn rebuild_progress_counts_committed_and_cached_fragments() -> Result<()> {
    let (_isolate, store, keys) = fixture("synthetic diary content ".repeat(100))?;
    let provider = core_sdk::search::HashingEmbedder::new(8);
    for _ in 0..2 {
        let mut progress = Vec::new();
        rebuild_with_progress(
            &store,
            &keys,
            &provider,
            || Ok(()),
            |action| action(),
            |done| {
                progress.push(done);
                Ok(())
            },
        )?;
        assert!(progress.len() > 2);
        assert_eq!(progress, (0..progress.len()).collect::<Vec<_>>());
    }
    Ok(())
}

#[test]
fn account_and_library_sources_remain_isolated_with_a_shared_disposable_cache() -> Result<()> {
    let (isolate, first, first_keys) = fixture("private first-account needle".into())?;
    let provider = core_sdk::search::HashingEmbedder::new(8);
    rebuild(&first, &first_keys, &provider, || Ok(()), |action| action())?;
    let other = LocalStore::open(&isolate.path().join("other-account.db"))?;
    let other_keys = SessionKeys::from_urk([83; 32])?;
    assert!(search(&other, &other_keys, "needle", 5, 4000, true)?
        .items
        .is_empty());
    let mut entry = MemoryEngine::open(&first_keys, &first.all(false)?[0])?;
    // Even coincident IDs in another account cannot select the old account's text.
    entry.content = "independent other-account pineapple".into();
    assert!(other.put(&MemoryEngine::seal(
        &other_keys,
        &provider,
        &entry,
        "other"
    )?)?);
    assert!(search(&other, &other_keys, "needle", 5, 4000, false)?
        .items
        .is_empty());
    rebuild(&other, &other_keys, &provider, || Ok(()), |action| action())?;
    assert!(search(&first, &first_keys, "pineapple", 5, 4000, false)?
        .items
        .is_empty());
    let result = search(&first, &first_keys, "needle", 5, 4000, false)?;
    assert_eq!(result.items.len(), 1);
    assert!(result.items[0].text.contains("first-account"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn existing_library_directory_alias_does_not_disable_cache_file_link_protection() -> Result<()> {
    let (isolate, store, keys) = fixture("existing library through a directory alias".into())?;
    let alias = isolate.path().join("library-alias");
    std::os::unix::fs::symlink(isolate.path(), &alias)?;
    std::env::set_var("RSRS_DATA_DIR", &alias);
    let provider = core_sdk::search::HashingEmbedder::new(8);
    rebuild(&store, &keys, &provider, || Ok(()), |action| action())?;
    // This path test uses the explicit test-hash generation, not m3 readiness.
    let db = cache(true)?.context("canonical directory cache must open read-only")?;
    assert!(
        db.query_row("SELECT count(*) FROM diary_artifacts", [], |row| row
            .get::<_, i64>(0))?
            > 0
    );
    drop(db);
    assert!(isolate.path().join("diary-fragments-v1.db").is_file());
    std::fs::remove_file(isolate.path().join("diary-fragments-v1.db"))?;
    let unrelated = isolate.path().join("untouched.db");
    std::fs::write(&unrelated, b"unrelated cache target")?;
    std::os::unix::fs::symlink(&unrelated, isolate.path().join("diary-fragments-v1.db"))?;
    assert!(rebuild(&store, &keys, &provider, || Ok(()), |action| action()).is_err());
    assert_eq!(std::fs::read(&unrelated)?, b"unrelated cache target");
    Ok(())
}

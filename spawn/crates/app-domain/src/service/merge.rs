use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, bail, Result};

use super::resolve_prefix;
use crate::memory::search::Embedder;
use crate::transport::local::LocalStore;
use crate::{MemoryEngine, MemoryEntry, MemoryTransport, SessionKeys, StoredMemory};

/// Replace the selected entries atomically. Surviving children keep the existing
/// promotion semantics: skip merged ancestors, rather than attach to the new row.
/// CLI inherits the first source's importance; App preserves the request's value.
pub fn merge_entries<E: Embedder>(
    keys: &SessionKeys, store: &LocalStore, embedder: &E, entry: &mut MemoryEntry,
    ids: &[String], explicit_parent: &str, inherit_importance: bool,
) -> Result<Vec<String>> {
    merge_entries_with_metadata(keys, store, embedder, entry, ids, explicit_parent, inherit_importance, None)
}

pub fn merge_entries_with_metadata<E: Embedder>(
    keys: &SessionKeys, store: &LocalStore, embedder: &E, entry: &mut MemoryEntry,
    ids: &[String], explicit_parent: &str, inherit_importance: bool,
    metadata: Option<&super::MetadataPatch>,
) -> Result<Vec<String>> {
    Ok(merge_entries_with_metadata_revision(keys, store, embedder, entry, ids, explicit_parent,
        inherit_importance, metadata)?.0)
}

pub fn merge_entries_with_metadata_revision<E: Embedder>(
    keys: &SessionKeys,
    store: &LocalStore,
    embedder: &E,
    entry: &mut MemoryEntry,
    ids: &[String],
    explicit_parent: &str,
    inherit_importance: bool,
    metadata: Option<&super::MetadataPatch>,
) -> Result<(Vec<String>, Option<String>)> {
    store.write_transaction(|| {
        let all = store.all(true)?;
        let by_id: HashMap<&str, &StoredMemory> =
            all.iter().map(|row| (row.id.as_str(), row)).collect();
        if by_id.contains_key(entry.id.as_str()) {
            bail!("merge replacement id already exists: {}", entry.id);
        }
        let mut selected = HashSet::new();
        let mut resolved = Vec::new();
        for id in ids {
            let full = match by_id.get(id.as_str()).filter(|row| !row.deleted) {
                Some(row) => row.id.clone(),
                None => resolve_prefix(&all, id)?,
            };
            if selected.insert(full.clone()) {
                resolved.push(full);
            }
        }
        let first = resolved
            .first()
            .ok_or_else(|| anyhow!("merge needs at least one live entry"))?;
        let source = by_id
            .get(first.as_str())
            .ok_or_else(|| anyhow!("missing merge source"))?;
        // Select once. An empty parent is a valid root, not an uninitialized value.
        let mut parents = SurvivingParents {
            by_id: &by_id,
            selected: &selected,
            cache: HashMap::new(),
        };
        let final_parent = if explicit_parent.is_empty() {
            parents.resolve(&source.local_parent_id)?
        } else {
            let full = resolve_prefix(&all, explicit_parent)?;
            if selected.contains(&full) {
                bail!("merge parent is also a merge target: {full}");
            }
            full
        };

        let mut moves = Vec::new();
        for row in all
            .iter()
            .filter(|row| !row.deleted && !selected.contains(&row.id))
        {
            if selected.contains(&row.local_parent_id) {
                moves.push((row, parents.resolve(&row.local_parent_id)?));
            }
        }
        // Validate the resulting ancestry, including promoted children. Existing
        // broken ancestry must fail before any write, not silently become a root.
        let projected: HashMap<&str, &str> = moves
            .iter()
            .map(|(row, parent)| (row.id.as_str(), parent.as_str()))
            .collect();
        let mut checked = HashSet::new();
        for start in std::iter::once(final_parent.as_str())
            .chain(moves.iter().map(|(row, _)| row.id.as_str()))
        {
            validate_chain(start, &by_id, &selected, &projected, &mut checked)?;
        }

        entry.parent_id = final_parent;
        if inherit_importance {
            entry.importance = source.local_importance.clone();
        }
        let selected_entries = resolved.iter().map(|id| {
            MemoryEngine::open(keys,by_id.get(id.as_str()).copied().ok_or_else(|| anyhow!("missing merge source"))?)
        }).collect::<Result<Vec<_>>>()?;
        for old in &selected_entries { crate::metadata_gate::ensure_write(store, old)?; }
        if selected_entries.iter().any(|old| old.metadata.memory_contract == 1) || entry.metadata.memory_contract == 1 || metadata.is_some() {
            let kind = &selected_entries[0].kind;
            anyhow::ensure!(entry.kind == *kind && selected_entries.iter().all(|old| old.kind == *kind),
                "invalid_metadata: merge requires the same kind");
            entry.metadata.memory_contract = 1;
            entry.metadata.verification = None;
            entry.metadata.summary = None;
            let mut refs = std::collections::BTreeMap::<String, crate::memory::model::SourceRef>::new();
            for source in selected_entries.iter().flat_map(|old| &old.metadata.source_refs) {
                if let Some(previous) = refs.get_mut(&source.id) {
                    anyhow::ensure!(previous.revision == source.revision, "invalid_metadata: merge source revision conflict: {}", source.id);
                    previous.required |= source.required;
                } else { refs.insert(source.id.clone(), source.clone()); }
            }
            entry.metadata.source_refs = refs.into_values().collect();
            entry.metadata.valid_until = selected_entries.iter().filter_map(|old| old.metadata.valid_until.as_ref()).min().cloned();
            entry.metadata.review_at = selected_entries.iter().filter_map(|old| old.metadata.review_at.as_ref()).min().cloned();
            let artifact = &selected_entries[0].metadata.artifact;
            if metadata.and_then(|patch| patch.artifact.as_ref()).is_none() {
                anyhow::ensure!(selected_entries.iter().all(|old| old.metadata.artifact == *artifact),
                    "invalid_metadata: merge artifacts differ; explicitly select the final artifact");
            }
            entry.metadata.artifact = artifact.clone();
        }
        if let Some(patch) = metadata { patch.apply(&mut entry.metadata); }
        crate::metadata_gate::ensure_write(store, entry)?;
        crate::metadata_gate::ensure_sources(keys, store, entry)?;
        let mut links = std::collections::BTreeSet::new();
        let mut replaces = std::collections::BTreeSet::new();
        for old in &selected_entries {
            links.extend(old.see_also.iter().filter(|id| !selected.contains(*id)).cloned());
            if !old.supersedes.is_empty() && !selected.contains(&old.supersedes) { replaces.insert(old.supersedes.clone()); }
        }
        anyhow::ensure!(replaces.len() <= 1, "merge would combine distinct supersedes chains");
        entry.supersedes = replaces.into_iter().next().unwrap_or_default();
        entry.see_also = links.into_iter().collect();
        // Collapsing nonadjacent versions must not close a replacement cycle.
        let mut cursor = entry.supersedes.clone();
        let mut seen = HashSet::new();
        while !cursor.is_empty() {
            anyhow::ensure!(cursor != entry.id && seen.insert(cursor.clone()),
                "merge would create a supersedes cycle");
            let Some(row) = by_id.get(cursor.as_str()).filter(|row| !row.deleted) else { break };
            cursor = MemoryEngine::open(keys, row)?.supersedes;
            if selected.contains(&cursor) { cursor = entry.id.clone(); }
        }
        for (row, _) in &moves {
            crate::metadata_gate::ensure_write(store, &MemoryEngine::open(keys, row)?)?;
        }
        let mut successors = HashSet::new();
        for row in all.iter().filter(|row| !row.deleted && !selected.contains(&row.id)) {
            let current = MemoryEngine::open(keys, row)?;
            if selected.contains(&current.supersedes) {
                successors.insert(row.id.clone());
            }
            if selected.contains(&current.supersedes) || selected.contains(&current.superseded_by)
                || current.see_also.iter().any(|id| selected.contains(id)) {
                crate::metadata_gate::ensure_write(store, &current)?;
            }
        }
        anyhow::ensure!(successors.len() <= 1, "merge would combine competing active replacements");
        entry.superseded_by = successors.into_iter().next().unwrap_or_default();
        let record_revision = if entry.metadata.memory_contract == 1 {
            let validated: serde_json::Value = crate::core_sdk::execute("memory_metadata_validate", serde_json::json!({"entry":entry}))?;
            let revision = validated["record_revision"].as_str().ok_or_else(|| anyhow!("Core omitted record_revision"))?;
            crate::memory::model::metadata::validate_revision(revision)?;
            Some(revision.to_owned())
        } else { None };
        let replacement = MemoryEngine::seal(keys, embedder, entry, &entry.user)?;
        for (row, parent) in moves {
            let moved =
                MemoryEngine::reseal_parent(keys, row, &parent, &store.edit_stamp(&row.id)?)?;
            if !store.put(&moved)? {
                bail!("merge child changed during write: {}", row.id);
            }
        }
        if !store.put(&replacement)? {
            bail!("merge replacement was not written: {}", entry.id);
        }
        // Read after parent edits so relation resealing cannot revert a reparent.
        for row in store.all(false)?.iter().filter(|r| r.id != entry.id && !selected.contains(&r.id)) {
            let current = MemoryEngine::open(keys,row)?;
            if selected.contains(&current.supersedes) || selected.contains(&current.superseded_by)
                || current.see_also.iter().any(|id| selected.contains(id)) {
                let updated = MemoryEngine::reseal_edges(keys,row,&store.edit_stamp(&row.id)?,|p| {
                    if selected.contains(&p.supersedes) { p.supersedes = entry.id.clone(); }
                    if selected.contains(&p.superseded_by) { p.superseded_by = entry.id.clone(); }
                    p.see_also = p.see_also.iter().map(|id| if selected.contains(id) { entry.id.clone() } else { id.clone() })
                        .collect::<std::collections::BTreeSet<_>>().into_iter().collect();
                    p.modified_by = super::device_tag();
                })?;
                anyhow::ensure!(store.put(&updated)?, "merge association was not saved");
            }
        }
        for id in &resolved {
            if !store.forget(id)? {
                bail!("merge source was not deleted: {id}");
            }
        }
        Ok((resolved, record_revision))
    })
}

struct SurvivingParents<'a> {
    by_id: &'a HashMap<&'a str, &'a StoredMemory>,
    selected: &'a HashSet<String>,
    cache: HashMap<String, String>,
}

impl SurvivingParents<'_> {
    fn resolve(&mut self, start: &str) -> Result<String> {
        let mut current = start.to_owned();
        let mut path = HashSet::new();
        while !current.is_empty() {
            if let Some(parent) = self.cache.get(&current) {
                current = parent.clone();
                break;
            }
            if !path.insert(current.clone()) {
                bail!("cycle in merge ancestry: {current}");
            }
            let row = self
                .by_id
                .get(current.as_str())
                .filter(|row| !row.deleted)
                .ok_or_else(|| anyhow!("missing or deleted merge ancestor: {current}"))?;
            if !self.selected.contains(&current) {
                break;
            }
            current = row.local_parent_id.clone();
        }
        for id in path {
            if self.selected.contains(&id) {
                self.cache.insert(id, current.clone());
            }
        }
        Ok(current)
    }
}

fn validate_chain<'a>(
    start: &'a str,
    by_id: &HashMap<&'a str, &'a StoredMemory>,
    selected: &HashSet<String>,
    projected: &HashMap<&'a str, &'a str>,
    checked: &mut HashSet<&'a str>,
) -> Result<()> {
    let mut current = start;
    let mut path = HashSet::new();
    while !current.is_empty() && !checked.contains(current) {
        if !path.insert(current) {
            bail!("cycle in merged tree: {current}");
        }
        let row = by_id
            .get(current)
            .filter(|row| !row.deleted && !selected.contains(current))
            .ok_or_else(|| anyhow!("missing or deleted merged parent: {current}"))?;
        current = projected
            .get(current)
            .copied()
            .unwrap_or(&row.local_parent_id);
    }
    checked.extend(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::search::HashingEmbedder;
    use crate::{Kind, MemoryQuery};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingEmbedder(AtomicUsize);

    impl Embedder for CountingEmbedder {
        fn dims(&self) -> usize {
            HashingEmbedder::default().dims()
        }

        fn model_name(&self) -> &str { "test-hash:256" }
        fn prepare(&self, entry: &MemoryEntry) -> Result<respire_core_sdk::Prepared> {
            self.0.fetch_add(1, Ordering::Relaxed);
            HashingEmbedder::default().prepare(entry)
        }
    }

    fn entry(id: &str, parent: &str) -> MemoryEntry {
        MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            id: id.into(),
            kind: Kind::Context,
            tags: vec![],
            title: id.into(),
            content: format!("memory {id}"),
            user: "test".into(),
            computer: "test".into(),
            project: "merge".into(),
            created_at: "2026-01-01T00:00:00.000Z".into(),
            updated_at: "2026-01-01T00:00:00.000Z".into(),
            emotion: -1.0,
            parent_id: parent.into(),
            importance: "important".into(),
            device: "test".into(),
            modified_by: "test".into(),
        }
    }

    fn seed(store: &LocalStore, keys: &SessionKeys, rows: &[(&str, &str)]) -> Result<()> {
        for (id, parent) in rows {
            let row = entry(id, parent);
            let sealed = MemoryEngine::seal(keys, &HashingEmbedder::default(), &row, &row.user)?;
            assert!(store.put(&sealed)?);
        }
        Ok(())
    }

    fn assert_tree(store: &LocalStore, keys: &SessionKeys) -> Result<()> {
        let all = store.all(false)?;
        let by_id: HashMap<&str, &StoredMemory> = all.iter().map(|r| (r.id.as_str(), r)).collect();
        let mut checked = HashSet::new();
        for row in &all {
            assert_eq!(
                MemoryEngine::payload_parent(keys, row)?,
                row.local_parent_id
            );
            validate_chain(
                &row.id,
                &by_id,
                &HashSet::new(),
                &HashMap::new(),
                &mut checked,
            )?;
        }
        Ok(())
    }

    #[test]
    fn merge_parent_child_orders_roots_and_deep_chains() -> Result<()> {
        for root in [true, false] {
            for order in [
                vec!["a", "b", "c"],
                vec!["c", "b", "a"],
                vec!["b", "a", "c"],
            ] {
                let dir = tempfile::tempdir()?;
                let store = LocalStore::open(&dir.path().join("merge.db"))?;
                let keys = SessionKeys::from_urk([7; 32])?;
                let parent = if root { "" } else { "p" };
                seed(
                    &store,
                    &keys,
                    &[
                        ("p", ""),
                        ("a", parent),
                        ("b", "a"),
                        ("c", "b"),
                        ("leaf", "c"),
                        ("other", "p"),
                    ],
                )?;
                let before = store.all(false)?;
                let old_leaf = before
                    .iter()
                    .find(|r| r.id == "leaf")
                    .ok_or_else(|| anyhow!("no leaf"))?;
                let embedder = CountingEmbedder::default();
                let mut merged = entry("merged", "");
                let ids: Vec<String> = order.iter().map(|s| (*s).to_owned()).collect();
                assert_eq!(
                    merge_entries(&keys, &store, &embedder, &mut merged, &ids, "", true)?.len(),
                    3
                );
                assert_eq!(merged.parent_id, parent);
                assert_eq!(
                    embedder.0.load(Ordering::Relaxed),
                    1,
                    "only the combined content is embedded"
                );
                let after = store.all(false)?;
                let leaf = after
                    .iter()
                    .find(|r| r.id == "leaf")
                    .ok_or_else(|| anyhow!("lost leaf"))?;
                assert_eq!(leaf.local_parent_id, parent);
                assert_eq!(leaf.local_artifact, old_leaf.local_artifact);
                assert_eq!(MemoryEngine::open(&keys, leaf)?.content, "memory leaf");
                let old_other = before
                    .iter()
                    .find(|r| r.id == "other")
                    .ok_or_else(|| anyhow!("no other"))?;
                let other = after
                    .iter()
                    .find(|r| r.id == "other")
                    .ok_or_else(|| anyhow!("lost other"))?;
                assert_eq!(other.ciphertext, old_other.ciphertext);
                assert_eq!(other.updated_at, old_other.updated_at);
                assert_tree(&store, &keys)?;
            }
        }
        Ok(())
    }

    #[test]
    fn merge_siblings_aliases_duplicates_and_explicit_parent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("merge.db"))?;
        let keys = SessionKeys::from_urk([7; 32])?;
        let a = "aaaaaaaa-0000-4000-8000-000000000001";
        let b = "bbbbbbbb-0000-4000-8000-000000000002";
        seed(
            &store,
            &keys,
            &[("p", ""), ("q", ""), (a, "p"), (b, "p"), ("leaf", a)],
        )?;
        let mut renamed = MemoryEngine::open(
            &keys,
            &store
                .all(false)?
                .into_iter()
                .find(|r| r.id == b)
                .ok_or_else(|| anyhow!("no b"))?,
        )?;
        renamed.title = "unique title".into();
        renamed.updated_at = store.edit_stamp(b)?;
        assert!(store.put(&MemoryEngine::seal(
            &keys,
            &HashingEmbedder::default(),
            &renamed,
            "test"
        )?)?);
        let ids = vec!["aaaaaaaa".into(), "unique title".into(), a.into()];
        let mut merged = entry("merged", "");
        merged.importance = "trivial".into();
        let resolved = merge_entries(
            &keys,
            &store,
            &HashingEmbedder::default(),
            &mut merged,
            &ids,
            "q",
            false,
        )?;
        assert_eq!(resolved, vec![a.to_owned(), b.to_owned()]);
        assert_eq!(merged.parent_id, "q");
        assert_eq!(
            merged.importance, "trivial",
            "App keeps explicit importance"
        );
        assert_tree(&store, &keys)?;
        Ok(())
    }

    #[test]
    fn merge_rejects_invalid_targets_parents_and_cycles_without_changes() -> Result<()> {
        for (rows, ids, parent) in [
            (vec![("a", ""), ("b", "a")], vec!["a", "b"], "a"),
            (vec![("a", ""), ("b", "a")], vec!["a", "b"], "missing"),
            (vec![("a", ""), ("b", "a")], vec!["a", "missing"], ""),
            (vec![("a", ""), ("b", "a")], vec![], ""),
            (vec![("a", "b"), ("b", "a")], vec!["a", "b"], ""),
            (vec![("a", "missing"), ("b", "a")], vec!["a", "b"], ""),
            (vec![("a", "b"), ("b", "a")], vec!["a"], ""),
        ] {
            let dir = tempfile::tempdir()?;
            let store = LocalStore::open(&dir.path().join("merge.db"))?;
            let keys = SessionKeys::from_urk([7; 32])?;
            seed(&store, &keys, &rows)?;
            let before = serde_json::to_value(store.all(true)?)?;
            let ids: Vec<String> = ids.iter().map(|s| (*s).into()).collect();
            let embedder = CountingEmbedder::default();
            assert!(merge_entries(
                &keys,
                &store,
                &embedder,
                &mut entry("merged", ""),
                &ids,
                parent,
                true
            )
            .is_err());
            assert_eq!(embedder.0.load(Ordering::Relaxed), 0);
            assert_eq!(serde_json::to_value(store.all(true)?)?, before);
        }
        Ok(())
    }

    #[test]
    fn merge_rolls_back_replacement_reparents_and_tombstones_on_write_failure() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("merge.db");
        let store = LocalStore::open(&path)?;
        let keys = SessionKeys::from_urk([7; 32])?;
        seed(
            &store,
            &keys,
            &[("p", ""), ("a", "p"), ("b", "a"), ("leaf", "b")],
        )?;
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch("CREATE TRIGGER fail_merge BEFORE UPDATE OF deleted ON memories WHEN NEW.id = 'b' AND NEW.deleted = 1 BEGIN SELECT RAISE(ABORT, 'injected merge failure'); END;")?;
        let before = serde_json::to_value(store.all(true)?)?;
        let ids = vec!["a".into(), "b".into()];
        let error = merge_entries(
            &keys,
            &store,
            &HashingEmbedder::default(),
            &mut entry("merged", ""),
            &ids,
            "",
            true,
        )
        .err()
        .ok_or_else(|| anyhow!("expected injected failure"))?;
        assert!(error.to_string().contains("injected merge failure"));
        assert_eq!(serde_json::to_value(store.all(true)?)?, before);
        assert_tree(&store, &keys)?;
        Ok(())
    }

    #[test]
    fn merge_restores_context_and_matches_correct_tree_ranking() -> Result<()> {
        let _guard = crate::test_lock::guard();
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("merge.db"))?;
        let keys = SessionKeys::from_urk([7; 32])?;
        seed(
            &store,
            &keys,
            &[("p", ""), ("a", "p"), ("b", "a"), ("other", "p")],
        )?;
        let embedder = HashingEmbedder::default();
        let mut merged = entry("merged", "");
        merge_entries(
            &keys,
            &store,
            &embedder,
            &mut merged,
            &["b".into(), "a".into()],
            "",
            true,
        )?;
        let actual = store.all(false)?;
        // Independently build the expected healthy tree, with the same text,
        // timestamps and vectors, to compare the unchanged ranking algorithm.
        let expected: Vec<StoredMemory> =
            [entry("p", ""), entry("other", "p"), entry("merged", "p")]
                .iter()
                .map(|e| MemoryEngine::seal(&keys, &embedder, e, &e.user))
                .collect::<Result<_>>()?;
        let query = MemoryQuery::new("memory merged").limit(3);
        let score = |rows: &[StoredMemory]| -> Result<Vec<(String, f32)>> {
            Ok(
                MemoryEngine::recall_local_scored(&keys, &embedder, rows, &query)?
                    .into_iter()
                    .map(|(score, e)| (e.id, score))
                    .collect(),
            )
        };
        assert_eq!(score(&actual)?, score(&expected)?);
        let contexts = MemoryEngine::recall_local_contextual(&keys, &embedder, &actual, &query)?;
        let hit = contexts
            .iter()
            .find(|hit| hit.entry.id == "merged")
            .ok_or_else(|| anyhow!("merged hit missing"))?;
        assert_eq!(
            hit.ancestors
                .iter()
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>(),
            vec!["p"]
        );
        Ok(())
    }

    #[test]
    fn app_create_uses_atomic_merge_and_keeps_requested_importance() -> Result<()> {
        let isolate = crate::test_lock::Isolate::new()?;
        let app = super::super::App {
            keys: SessionKeys::from_urk([7; 32])?,
            store: LocalStore::open(&isolate.path().join("merge.db"))?,
            embedder: Box::new(HashingEmbedder::default()),
        };
        seed(
            &app.store,
            &app.keys,
            &[("a", ""), ("b", "a"), ("leaf", "b")],
        )?;
        let merged = app.create(&super::super::CreateReq {
            title: "merged".into(),
            content: "combined memory".into(),
            importance: Some("important".into()),
            merge_ids: Some(vec!["a".into(), "b".into()]),
            ..Default::default()
        })?;
        assert!(merged.parent_id.is_empty());
        assert_eq!(merged.importance, "important");
        assert_eq!(app.store.all(false)?.len(), 2);
        assert_tree(&app.store, &app.keys)?;
        Ok(())
    }
}

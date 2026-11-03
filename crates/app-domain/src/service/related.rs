//! Explicit association edits share the existing encrypted local transaction.
use super::{device_tag, resolve_prefix};
use crate::memory::search::Embedder;
use crate::memory::{MemoryEngine, SessionKeys};
use crate::transport::{local::LocalStore, MemoryTransport};
use crate::{MemoryEntry, StoredMemory};
use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, HashSet};

pub fn store_related<E: Embedder>(
    keys: &SessionKeys,
    store: &LocalStore,
    embedder: &E,
    entry: &mut MemoryEntry,
    supersedes: Option<&str>,
    see_also: &[String],
) -> Result<StoredMemory> {
    crate::core_sdk::require_associations()?;
    ensure!(
        entry.importance == "important",
        "associations require important memory"
    );
    store.write_transaction(|| {
        let all = store.all(false)?;
        ensure!(
            !all.iter().any(|r| r.id == entry.id),
            "association replacement already exists"
        );
        let mut edits = BTreeMap::<String, (&StoredMemory, MemoryEntry)>::new();
        if let Some(old) = supersedes {
            let old = resolve_prefix(&all, old)?;
            ensure!(old != entry.id, "cannot supersede itself");
            let row = all
                .iter()
                .find(|r| r.id == old)
                .context("missing superseded memory")?;
            let mut previous = MemoryEngine::open(keys, row)?;
            if previous.importance != "important" {
                return Err(crate::input_error::InputError("cannot supersede diary memory".into()).into());
            }
            ensure!(
                !all.iter()
                    .filter(|r| r.id != entry.id)
                    .map(|r| MemoryEngine::open(keys, r))
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .any(|e| e.supersedes == old),
                "memory already has an active replacement"
            );
            let mut cursor = previous.supersedes.clone();
            let mut visited = HashSet::from([old.clone()]);
            while !cursor.is_empty() {
                ensure!(
                    cursor != entry.id && visited.insert(cursor.clone()),
                    "supersedes chain contains a cycle"
                );
                let Some(row) = all.iter().find(|r| r.id == cursor) else {
                    break;
                };
                cursor = MemoryEngine::open(keys, row)?.supersedes;
            }
            entry.supersedes = old.clone();
            previous.superseded_by = entry.id.clone();
            edits.insert(old, (row, previous));
        }
        let mut linked = std::collections::BTreeSet::new();
        for id in see_also {
            let full = resolve_prefix(&all, id)?;
            ensure!(full != entry.id, "cannot link itself");
            if !linked.insert(full.clone()) {
                continue;
            }
            let row = all
                .iter()
                .find(|r| r.id == full)
                .context("missing association target")?;
            if !edits.contains_key(&full) {
                edits.insert(full.clone(), (row, MemoryEngine::open(keys, row)?));
            }
            let (_, other) = edits.get_mut(&full).context("missing association edit")?;
            if other.importance != "important" {
                return Err(crate::input_error::InputError("cannot link diary memory".into()).into());
            }
            if !other.see_also.contains(&entry.id) {
                other.see_also.push(entry.id.clone());
            }
        }
        entry.see_also = linked.into_iter().collect();
        crate::metadata_gate::ensure_write(store, entry)?;
        crate::metadata_gate::ensure_sources(keys, store, entry)?;
        for (_, other) in edits.values() { crate::metadata_gate::ensure_write(store, other)?; }
        let sealed = MemoryEngine::seal(keys, embedder, entry, &entry.user)?;
        ensure!(store.put(&sealed)?, "association entry was not saved");
        for (id, (row, other)) in edits {
            let stamp = store.edit_stamp(&id)?;
            let updated = MemoryEngine::reseal_edges(keys, row, &stamp, |p| {
                p.supersedes = other.supersedes;
                p.superseded_by = other.superseded_by;
                p.see_also = other.see_also;
                p.modified_by = device_tag();
            })?;
            ensure!(store.put(&updated)?, "association target changed: {id}");
        }
        Ok(sealed)
    })
}

/// Minted-ID imports and subtree sharing must not link to unrelated local IDs.
pub fn remap_relations(
    entries: &mut [MemoryEntry],
    ids: &std::collections::HashMap<String, String>,
) -> Result<()> {
    for entry in entries.iter_mut() {
        entry.supersedes = ids.get(&entry.supersedes).cloned().unwrap_or_default();
        entry.superseded_by = ids.get(&entry.superseded_by).cloned().unwrap_or_default();
        entry.see_also = entry
            .see_also
            .iter()
            .filter_map(|id| ids.get(id).cloned())
            .collect();
        ensure!(
            entry.supersedes != entry.id && !entry.see_also.contains(&entry.id),
            "import contains a self association"
        );
        entry.superseded_by.clear();
    }
    let mut replacements = BTreeMap::new();
    for entry in entries.iter() {
        if !entry.supersedes.is_empty() {
            ensure!(
                replacements
                    .insert(entry.supersedes.clone(), entry.id.clone())
                    .is_none(),
                "import has competing replacements"
            );
        }
    }
    for entry in entries.iter() {
        let mut cursor = entry.id.as_str();
        let mut seen = HashSet::new();
        while let Some(next) = replacements.get(cursor) {
            ensure!(
                seen.insert(cursor),
                "import supersedes chain contains a cycle"
            );
            cursor = next;
        }
    }
    for entry in entries.iter_mut() {
        entry.superseded_by = replacements.get(&entry.id).cloned().unwrap_or_default();
    }
    Ok(())
}

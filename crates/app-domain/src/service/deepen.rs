use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use anyhow::Result;

use super::{require_candidates_ready, resolve_prefix, DeepenPlan};
use crate::input_error::InputError;
use crate::transport::local::LocalStore;
use crate::MemoryTransport;

/// Load the current planning materials and ask Core for grouping suggestions.
pub fn deepen_plan(
    store: &LocalStore,
    root_prefix: &str,
    min_sim: f32,
) -> Result<(String, DeepenPlan)> {
    let candidates = store.all(false)?;
    let root_id = resolve_prefix(&candidates, root_prefix)?;
    let counts = TreeLinks::new(
        candidates
            .iter()
            .map(|row| (row.id.as_str(), row.local_parent_id.as_str())),
    )
    .counts(&root_id);
    if !counts.is_flat() {
        return Err(InputError(format!(
            "this root is not flat ({} direct children, {} in the grandchild chain) \u{2014} hierarchy already exists or too few entries to deepen",
            counts.direct, counts.descendants,
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

pub struct DeepenRoot {
    pub id: String,
    pub title: String,
}

/// Command-local cache of negative eligibility facts, never of write plans.
pub struct DeepenAuto<'a> {
    store: &'a LocalStore,
    snapshot: Option<(String, TreeLinks<String>)>,
}

impl<'a> DeepenAuto<'a> {
    pub fn open(store: &'a LocalStore) -> Result<(Vec<DeepenRoot>, Self)> {
        let before = store.memory_revision().ok();
        // The initial full read preserves catalog decoding errors, root order,
        // and root titles, including when no planner ever runs.
        let rows = store.all(false)?;
        let roots = rows
            .iter()
            .filter(|row| row.local_parent_id.is_empty())
            .map(|row| DeepenRoot {
                id: row.id.clone(),
                title: row.local_title.clone(),
            })
            .collect();
        let snapshot = before
            .filter(|revision| {
                store
                    .memory_revision()
                    .is_ok_and(|current| &current == revision)
            })
            .map(|revision| {
                let links =
                    TreeLinks::new(rows.into_iter().map(|row| (row.id, row.local_parent_id)));
                (revision, links)
            });
        Ok((roots, Self { store, snapshot }))
    }

    /// Plan against the live catalog unless the snapshot rules out this exact ID.
    pub fn plan(&mut self, root: &str, min_sim: f32) -> Result<Option<DeepenPlan>> {
        if !self.needs_plan(root) {
            return Ok(None);
        }
        deepen_plan(self.store, root, min_sim).map(|(_, plan)| Some(plan))
    }

    fn needs_plan(&mut self, root: &str) -> bool {
        // Removed roots and IDs changed by the legacy resolver must take its
        // authoritative path, as must any uncertain projection.
        if root.is_empty() || root.starts_with('#') {
            return true;
        }
        self.can_skip(root).map_or(true, |skip| !skip)
    }

    fn can_skip(&mut self, root: &str) -> Result<bool> {
        let revision = self.store.memory_revision()?;
        if !self
            .snapshot
            .as_ref()
            .is_some_and(|(seen, _)| seen == &revision)
        {
            let links = TreeLinks::new(self.store.active_tree_links()?.into_iter());
            if self.store.memory_revision()? != revision {
                return Ok(false);
            }
            self.snapshot = Some((revision, links));
        }
        let Some((seen, links)) = &self.snapshot else {
            return Ok(false);
        };
        if !links.ids.contains(root) || links.counts(root).is_flat() {
            return Ok(false);
        }
        // Another connection may have changed topology during traversal.
        Ok(&self.store.memory_revision()? == seen)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Counts {
    direct: usize,
    descendants: usize,
}

impl Counts {
    fn is_flat(&self) -> bool {
        // Preserve the historical threshold and reachable-node counting;
        // Core still owns the actual grouping.
        self.direct >= 15 && self.descendants * 3 <= self.direct * 2
    }
}

struct TreeLinks<Id> {
    ids: HashSet<Id>,
    by_parent: HashMap<Id, Vec<Id>>,
}

impl<Id> TreeLinks<Id>
where
    Id: Borrow<str> + Clone + Eq + Hash,
{
    fn new(links: impl Iterator<Item = (Id, Id)>) -> Self {
        let mut ids = HashSet::new();
        let mut by_parent: HashMap<_, Vec<_>> = HashMap::new();
        for (id, parent) in links {
            ids.insert(id.clone());
            by_parent.entry(parent).or_default().push(id);
        }
        Self { ids, by_parent }
    }

    fn counts(&self, root: &str) -> Counts {
        let Some(direct) = self.by_parent.get(root) else {
            return Counts {
                direct: 0,
                descendants: 0,
            };
        };
        let mut pending = direct.iter().collect::<Vec<_>>();
        let mut descendants = HashSet::new();
        while let Some(parent) = pending.pop() {
            let parent: &str = parent.borrow();
            if let Some(children) = self.by_parent.get(parent) {
                for child in children {
                    if descendants.insert(child) {
                        pending.push(child);
                    }
                }
            }
        }
        Counts {
            direct: direct.len(),
            descendants: descendants.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::local::register_witness_functions;
    use rusqlite::Connection;

    fn fixture_writer(path: &std::path::Path) -> Result<Connection> {
        let writer = Connection::open(path)?;
        register_witness_functions(&writer)?;
        Ok(writer)
    }

    fn historical_counts(rows: &[(&str, &str)], root: &str) -> Counts {
        let direct: HashSet<&str> = rows
            .iter()
            .filter(|(_, parent)| *parent == root)
            .map(|(id, _)| *id)
            .collect();
        let mut descendants = HashSet::new();
        let mut pending: Vec<&str> = direct.iter().copied().collect();
        while let Some(parent) = pending.pop() {
            for &(id, _) in rows.iter().filter(|(_, link)| *link == parent) {
                if descendants.insert(id) {
                    pending.push(id);
                }
            }
        }
        Counts {
            direct: direct.len(),
            descendants: descendants.len(),
        }
    }

    #[test]
    fn topology_keeps_exact_historical_counts_including_cycles() {
        for size in [0, 1, 14, 15, 16, 30] {
            let ids: Vec<_> = (0..size).map(|id| format!("id-{id}")).collect();
            for layout in 0..5 {
                let rows: Vec<_> = ids
                    .iter()
                    .enumerate()
                    .map(|(position, id)| {
                        let parent = match layout {
                            0 => "",
                            1 if position > 0 => ids[position - 1].as_str(),
                            2 if position > 1 => ids[position / 2].as_str(),
                            3 => ids[(position + 1) % size].as_str(),
                            4 => id.as_str(),
                            _ => "external",
                        };
                        (id.as_str(), parent)
                    })
                    .collect();
                let links = TreeLinks::new(rows.iter().copied());
                for root in ids.iter().map(String::as_str).chain(["", "external"]) {
                    assert_eq!(links.counts(root), historical_counts(&rows, root));
                }
            }
        }
        assert!(!Counts {
            direct: 14,
            descendants: 0
        }
        .is_flat());
        assert!(Counts {
            direct: 15,
            descendants: 10
        }
        .is_flat());
        assert!(!Counts {
            direct: 15,
            descendants: 11
        }
        .is_flat());
    }

    #[test]
    fn auto_reevaluates_topology_after_commits_without_adding_roots() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("rsrs.db");
        let store = LocalStore::open(&path)?;
        let mut writer = fixture_writer(&path)?;
        writer.execute_batch(
            "INSERT INTO memories(id,title,deleted) VALUES
             ('root-b','B',0),('root-a','A',0),('#alias','Alias',0),('', 'Empty',0),
             ('deleted-root','Gone',1);
             WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<15)
             INSERT INTO memories(id,parent_id,deleted) SELECT 'child-' || n,'root-a',n=15 FROM numbers;",
        )?;
        let initial: Vec<_> = store
            .all(false)?
            .into_iter()
            .filter(|row| row.local_parent_id.is_empty())
            .map(|row| (row.id, row.local_title))
            .collect();
        let (roots, mut batch) = DeepenAuto::open(&store)?;
        assert!(!batch.needs_plan("root-b"));
        assert!(!batch.needs_plan("root-a"));
        assert!(batch.needs_plan("#alias"));
        assert!(batch.needs_plan(""));
        assert!(batch.needs_plan("deleted-root"));
        assert!(batch.needs_plan("root-"));

        let uncommitted = writer.transaction()?;
        uncommitted.execute("UPDATE memories SET deleted=0 WHERE id='child-15'", [])?;
        assert!(
            !batch.needs_plan("root-a"),
            "uncommitted eligibility is invisible"
        );
        uncommitted.commit()?;
        assert!(
            batch.needs_plan("root-a"),
            "newly eligible root must go through the old planner"
        );
        let error = match batch.plan("root-a", 0.5) {
            Err(error) => error,
            Ok(_) => panic!("missing artifacts must not produce a plan"),
        };
        assert!(error.downcast_ref::<super::super::IndexPending>().is_some());

        writer.execute_batch(
            "UPDATE memories SET parent_id='root-b' WHERE parent_id='root-a';
             UPDATE memories SET title='New title' WHERE id='root-b';
             INSERT INTO memories(id) VALUES ('new-root');",
        )?;
        assert!(!batch.needs_plan("root-a"));
        assert!(batch.needs_plan("root-b"));
        assert_eq!(
            roots
                .into_iter()
                .map(|root| (root.id, root.title))
                .collect::<Vec<_>>(),
            initial
        );
        Ok(())
    }

    #[test]
    fn auto_preserves_initial_decode_failure_and_falls_back_when_topology_is_unavailable(
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("rsrs.db");
        let store = LocalStore::open(&path)?;
        let writer = fixture_writer(&path)?;
        writer.execute_batch(
            "INSERT INTO memories(id,title,recall_count) VALUES ('root','Title','invalid-count');",
        )?;
        let baseline_error = match store.all(false) {
            Err(error) => error,
            Ok(_) => panic!("the catalog must reject a malformed row"),
        };
        let candidate_error = match DeepenAuto::open(&store) {
            Err(error) => error,
            Ok(_) => panic!("auto must preserve the first catalog error"),
        };
        assert_eq!(candidate_error.to_string(), baseline_error.to_string());

        writer.execute_batch("UPDATE memories SET recall_count=0 WHERE id='root';")?;
        let (_, mut batch) = DeepenAuto::open(&store)?;
        assert!(!batch.needs_plan("root"));
        writer
            .execute_batch("UPDATE meta SET value='bad-token' WHERE key='memory_revision_v1';")?;
        assert!(
            batch.needs_plan("root"),
            "a failed projection cannot veto planning"
        );
        assert!(store.all(false).is_ok());
        Ok(())
    }

    #[test]
    fn auto_uses_no_per_root_catalog_hydration_for_negative_topology() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("rsrs.db");
        let store = LocalStore::open(&path)?;
        let writer = fixture_writer(&path)?;
        writer.execute_batch(
            "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<1000)
             INSERT INTO memories(id) SELECT 'root-' || n FROM numbers;",
        )?;
        let (roots, mut batch) = DeepenAuto::open(&store)?;
        // Break a column outside the topology projection, after the original
        // catalog snapshot. A new full catalog read would fail now.
        writer.execute_batch(
            "UPDATE memories SET title='Edited',recall_count='invalid-count' WHERE id='root-1';",
        )?;
        assert!(store.all(false).is_err());
        assert_eq!(roots.len(), 1000);
        for root in roots {
            assert!(batch.plan(&root.id, 0.5)?.is_none());
        }
        Ok(())
    }
}

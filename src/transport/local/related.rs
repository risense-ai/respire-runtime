use super::LocalStore;
use anyhow::Result;
use respire_protocol::RecallPair;
use rusqlite::params;
use std::collections::BTreeSet;

impl LocalStore {
    /// One unordered pair per recall. Only original final hits participate.
    pub fn bump_recall_pairs(&self, ids: &[String]) -> Result<()> {
        let ids: Vec<_> = ids
            .iter()
            .take(5)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                self.connection.execute("INSERT INTO recall_pairs(a,b,n) VALUES(?1,?2,1) ON CONFLICT(a,b) DO UPDATE SET n=n+1", params![a,b])?;
            }
        }
        Ok(())
    }

    /// Return local evidence; Core owns thresholds and association selection.
    pub fn recall_pairs(&self, ids: &[String]) -> Result<Vec<RecallPair>> {
        let mut result = std::collections::BTreeMap::new();
        let mut statement = self
            .connection
            .prepare("SELECT a,b,n FROM recall_pairs WHERE a=?1 OR b=?1")?;
        for id in ids {
            for row in statement.query_map([id], |r| {
                Ok(RecallPair {
                    a: r.get(0)?,
                    b: r.get(1)?,
                    n: r.get(2)?,
                })
            })? {
                let pair = row?;
                result.insert((pair.a.clone(), pair.b.clone()), pair);
            }
        }
        Ok(result.into_values().collect())
    }
}

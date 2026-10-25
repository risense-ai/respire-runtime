//! Host-owned attribution and per-request feedback. No process-global counters.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, serde::Serialize)]
pub struct FeedbackCounts {
    pub good: BTreeMap<String, u64>,
    pub bad: BTreeMap<String, u64>,
}

/// Unicode scalar bigrams; repeated pairs count once. Lowercase and trim only.
fn normalized(query: &str) -> String {
    query.trim().to_lowercase()
}
fn bigrams(query: &str) -> BTreeSet<String> {
    let chars: Vec<_> = normalized(query).chars().collect();
    if chars.len() == 1 {
        return BTreeSet::from([chars.into_iter().collect()]);
    }
    chars.windows(2).map(|pair| pair.iter().collect()).collect()
}
fn similarity(left: &str, right: &str) -> f64 {
    let (left, right) = (bigrams(left), bigrams(right));
    let union = left.union(&right).count();
    if union == 0 {
        return 0.0;
    }
    left.intersection(&right).count() as f64 / union as f64
}

impl LocalStore {
    /// Exact request identity is returned to callers and later used for grading.
    pub fn log_query_request(
        &self,
        request_id: &str,
        query: &str,
        project: &str,
        scope: &str,
        candidates: &[String],
        scores: &[f32],
    ) -> Result<()> {
        anyhow::ensure!(
            uuid::Uuid::parse_str(request_id).is_ok(),
            "invalid query log request id"
        );
        let now = chrono::Utc::now();
        self.connection.execute("INSERT INTO query_log(ts_unix,ts,query,project,scope,candidates,candidate_scores,adopted,request_id) VALUES(?1,?2,?3,?4,?5,?6,?7,'[]',?8)",params![now.timestamp(),now.to_rfc3339(),query,project,scope,serde_json::to_string(candidates)?,serde_json::to_string(scores)?,request_id])?;
        Ok(())
    }

    /// Explicit provenance; accepted changes and their revision commit together.
    /// Repeating the same verdict/source is idempotent. A changed verdict wins.
    pub fn mark_query_feedback(
        &self,
        request_id: &str,
        ids: &[String],
        good: bool,
        source: &str,
    ) -> Result<u64> {
        anyhow::ensure!(
            matches!(source, "human" | "model" | "task_outcome"),
            "feedback source must be human, model, or task_outcome"
        );
        anyhow::ensure!(!ids.is_empty(), "feedback ids are empty");
        let transaction = self.connection.unchecked_transaction()?;
        let row: Option<(i64, String)> = transaction
            .query_row(
                "SELECT id,candidates FROM query_log WHERE request_id=?1",
                [request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (log_id, candidates) = row.context(
            "query log request not found or not yet persisted; retry the explicit request id",
        )?;
        let candidates: Vec<String> = serde_json::from_str(&candidates)?;
        for id in ids {
            anyhow::ensure!(
                candidates.contains(id),
                "feedback must name a complete candidate memory id from that request"
            );
        }
        let mut revision = 0;
        for id in ids.iter().collect::<BTreeSet<_>>() {
            let old:Option<(bool,String,u64)>=transaction.query_row("SELECT good,source,revision FROM query_feedback WHERE query_log_id=?1 AND memory_id=?2",params![log_id,id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
            let next = if let Some((_, _, existing)) =
                old.filter(|(verdict, old_source, _)| *verdict == good && old_source == source)
            {
                existing
            } else {
                let next: u64 = transaction.query_row(
                    "SELECT COALESCE(MAX(revision),0)+1 FROM query_feedback",
                    [],
                    |row| row.get(0),
                )?;
                transaction.execute("INSERT INTO query_feedback(query_log_id,memory_id,good,source,marked_at,revision) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(query_log_id,memory_id) DO UPDATE SET good=excluded.good,source=excluded.source,marked_at=excluded.marked_at,revision=excluded.revision",params![log_id,id,good,source,chrono::Utc::now().timestamp(),next])?;
                next
            };
            // Keep the public query-log report and existing benchmark format compatible.
            let (good_json, bad_json): (String, String) = transaction.query_row(
                "SELECT good_ids,bad_ids FROM query_log WHERE id=?1",
                [log_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let mut yes: Vec<String> = serde_json::from_str(&good_json)?;
            let mut no: Vec<String> = serde_json::from_str(&bad_json)?;
            yes.retain(|candidate| candidate != id);
            no.retain(|candidate| candidate != id);
            if good {
                yes.push(id.clone());
            } else {
                no.push(id.clone());
            }
            transaction.execute(
                "UPDATE query_log SET good_ids=?2,bad_ids=?3 WHERE id=?1",
                params![
                    log_id,
                    serde_json::to_string(&yes)?,
                    serde_json::to_string(&no)?
                ],
            )?;
            revision = revision.max(next);
        }
        transaction.commit()?;
        Ok(revision)
    }

    /// Scientist baseline: 180-day query-conditional bigram Jaccard, latest wins.
    /// Authorized IDs, project and scope constrain every request. Repeating a
    /// query/entry mark cannot manufacture extra heat. Different query contexts
    /// can contribute separately; source is retained in the attribution table.
    pub fn feedback_counts(
        &self,
        query: &str,
        project: &str,
        scope: &str,
        authorized: &BTreeSet<String>,
        mark_sim: f64,
        now: i64,
    ) -> Result<FeedbackCounts> {
        anyhow::ensure!(
            mark_sim.is_finite() && (0.0..=1.0).contains(&mark_sim),
            "MARK_SIM must be between 0 and 1"
        );
        let transaction = self.connection.unchecked_transaction()?;
        let mut observations: BTreeMap<(String, String), (i64, u64, i64, bool)> = BTreeMap::new();
        let mut statement=transaction.prepare("SELECT id,ts_unix,query,good_ids,bad_ids FROM query_log WHERE ts_unix>=?1 AND ts_unix<=?2 AND project=?3 AND scope=?4 ORDER BY ts_unix,id")?;
        let rows = statement.query_map(params![now - 180 * 86400, now, project, scope], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (log_id, ts, text, yes, no) = row?;
            if similarity(query, &text) < mark_sim {
                continue;
            }
            let context = normalized(&text);
            let mut current: BTreeMap<String, bool> = BTreeMap::new();
            for (encoded, verdict) in [(&yes, true), (&no, false)] {
                for id in serde_json::from_str::<Vec<String>>(encoded)? {
                    current.insert(id, verdict);
                }
            }
            // Explicit events override imported legacy arrays for the same row.
            let mut events=transaction.prepare("SELECT memory_id,good,marked_at,revision FROM query_feedback WHERE query_log_id=?1")?;
            let events = events.query_map([log_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })?;
            let mut times = BTreeMap::new();
            for event in events {
                let (id, verdict, time, revision) = event?;
                current.insert(id.clone(), verdict);
                times.insert(id, (time, revision));
            }
            for (id, verdict) in current {
                if !authorized.contains(&id) {
                    continue;
                }
                let (timestamp, revision) = times.get(&id).copied().unwrap_or((ts, 0));
                if timestamp < now - 180 * 86400 || timestamp > now {
                    continue;
                }
                let key = (context.clone(), id);
                let candidate = (timestamp, revision, log_id, verdict);
                if observations
                    .get(&key)
                    .is_none_or(|old| (old.0, old.1, old.2) <= (timestamp, revision, log_id))
                {
                    observations.insert(key, candidate);
                }
            }
        }
        drop(statement);
        let mut counts = FeedbackCounts::default();
        for ((_, id), (_, _, _, good)) in observations {
            let target = if good {
                &mut counts.good
            } else {
                &mut counts.bad
            };
            *target.entry(id).or_default() += 1;
        }
        transaction.commit()?;
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_feedback_is_explicit_latest_wins_and_request_isolated() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = LocalStore::open(&root.path().join("db"))?;
        let id = "synthetic-full-memory-id".to_string();
        let authorized = BTreeSet::from([id.clone()]);
        let first = uuid::Uuid::new_v4().to_string();
        store.log_query_request(
            &first,
            "Rust memory",
            "p",
            "account-a",
            &[id.clone()],
            &[0.8],
        )?;
        let revision = store.mark_query_feedback(&first, &[id.clone()], true, "model")?;
        assert_eq!(
            store.mark_query_feedback(&first, &[id.clone()], true, "model")?,
            revision
        );
        let counts = || {
            store.feedback_counts(
                "Rust memory",
                "p",
                "account-a",
                &authorized,
                0.5,
                chrono::Utc::now().timestamp(),
            )
        };
        assert_eq!(counts()?.good.get(&id), Some(&1));
        assert!(store
            .mark_query_feedback(&first, &["synthetic".into()], false, "human")
            .is_err());
        assert!(store
            .mark_query_feedback(&first, &[id.clone()], false, "unknown")
            .is_err());
        assert!(store
            .mark_query_feedback("missing", &[id.clone()], false, "human")
            .is_err());
        assert!(store.mark_query_feedback(&first, &[id.clone()], false, "human")? > revision);
        assert!(counts()?.good.is_empty());
        assert_eq!(counts()?.bad.get(&id), Some(&1));
        let second = uuid::Uuid::new_v4().to_string();
        store.log_query_request(
            &second,
            "Rust memory",
            "p",
            "account-a",
            &[id.clone()],
            &[0.8],
        )?;
        store.mark_query_feedback(&second, &[id.clone()], true, "task_outcome")?;
        assert_eq!(counts()?.good.get(&id), Some(&1));
        assert!(counts()?.bad.is_empty());
        store.mark_query_feedback(&first, &[id.clone()], false, "task_outcome")?;
        assert_eq!(counts()?.bad.get(&id), Some(&1));
        assert!(counts()?.good.is_empty());
        assert!(store
            .feedback_counts(
                "Rust memory",
                "other",
                "account-a",
                &authorized,
                0.5,
                chrono::Utc::now().timestamp()
            )?
            .good
            .is_empty());
        assert!(store
            .feedback_counts(
                "Rust memory",
                "p",
                "account-b",
                &authorized,
                0.5,
                chrono::Utc::now().timestamp()
            )?
            .good
            .is_empty());
        assert!(store
            .feedback_counts(
                "unrelated query",
                "p",
                "account-a",
                &authorized,
                0.5,
                chrono::Utc::now().timestamp()
            )?
            .good
            .is_empty());
        assert!(store
            .feedback_counts(
                "Rust memory",
                "p",
                "account-a",
                &BTreeSet::new(),
                0.5,
                chrono::Utc::now().timestamp()
            )?
            .good
            .is_empty());
        Ok(())
    }
    #[test]
    fn legacy_regrade_and_explicit_idempotent_repair_share_one_authority() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = LocalStore::open(&root.path().join("db"))?;
        let id = "synthetic-complete-id".to_owned();
        let request = uuid::Uuid::new_v4().to_string();
        store.log_query_request(&request, "query", "p", "s", &[id.clone()], &[1.0])?;
        let old = store.mark_query_feedback(&request, &[id.clone()], true, "human")?;
        // This is the legacy path still allowed with FEEDBACK=0.
        assert!(store.mark_verdict(&[id.clone()], false)?.is_empty());
        let allowed = BTreeSet::from([id.clone()]);
        let counts = store.feedback_counts(
            "query",
            "p",
            "s",
            &allowed,
            0.5,
            chrono::Utc::now().timestamp(),
        )?;
        assert!(counts.good.is_empty());
        assert_eq!(counts.bad.get(&id), Some(&1));
        let row = store.query_log_rows(1)?.remove(0);
        assert!(row.good.is_empty());
        assert_eq!(row.bad, [id.clone()]);
        let revision = store.mark_query_feedback(&request, &[id.clone()], false, "model")?;
        assert!(revision > old);
        // Simulate a mirror left inconsistent by an earlier implementation.
        store.connection.execute(
            "UPDATE query_log SET good_ids=?1,bad_ids='[]'",
            [serde_json::to_string(&[id.clone()])?],
        )?;
        assert_eq!(
            store.mark_query_feedback(&request, &[id.clone()], false, "model")?,
            revision
        );
        let row = store.query_log_rows(1)?.remove(0);
        assert!(row.good.is_empty());
        assert_eq!(row.bad, [id.clone()]);
        store.log_query("legacy query", "p", "s", &[id.clone()], &[1.0])?;
        assert!(store.mark_verdict(&[id.clone()], true)?.is_empty());
        let legacy = store.query_log_rows(1)?.remove(0);
        assert!(legacy.request_id.is_some());
        assert_eq!(
            store
                .feedback_counts(
                    "legacy query",
                    "p",
                    "s",
                    &allowed,
                    0.5,
                    chrono::Utc::now().timestamp()
                )?
                .good
                .get(&id),
            Some(&1)
        );
        Ok(())
    }

    #[test]
    fn unicode_short_queries_window_and_legacy_marks_are_supported() -> Result<()> {
        assert_eq!(similarity("中文记忆", "中文记忆"), 1.0);
        assert_eq!(similarity("中", "中"), 1.0);
        assert_eq!(similarity("", ""), 0.0);
        assert!(similarity("enable feature", "do not enable feature") < 1.0); // Not semantic negation detection.
        let root = tempfile::tempdir()?;
        let store = LocalStore::open(&root.path().join("db"))?;
        let id = "full-entry".to_string();
        store.log_query("中文记忆", "p", "s", &[id.clone()], &[1.0])?;
        store.mark_verdict(&[id.clone()], true)?;
        let now = chrono::Utc::now().timestamp();
        let allowed = BTreeSet::from([id.clone()]);
        assert_eq!(
            store
                .feedback_counts("中文记忆", "p", "s", &allowed, 0.5, now)?
                .good
                .get(&id),
            Some(&1)
        );
        assert!(store
            .feedback_counts("中文记忆", "p", "s", &allowed, 0.5, now + 181 * 86400)?
            .good
            .is_empty());
        assert!(store
            .feedback_counts("中文记忆", "p", "s", &allowed, f64::NAN, now)
            .is_err());
        Ok(())
    }
}

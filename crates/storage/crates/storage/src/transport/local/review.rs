//! Local review history; authorization and evidence checks belong to the caller.

use anyhow::Result;
use rusqlite::params;

use super::LocalStore;

/// JSON object columns retain their full serialized values, including extensions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ReviewHistoryRow {
    pub seq: Option<i64>,
    pub entry_id: String,
    pub record_revision: String,
    pub action: String,
    pub actor: String,
    pub happened_at: String,
    pub previous_verification: Option<String>,
    pub next_verification: Option<String>,
    pub previous_review_at: Option<String>,
    pub next_review_at: Option<String>,
    pub reason: Option<String>,
}

impl LocalStore {
    /// Commit only a caller-validated review; this does not authenticate approval.
    pub fn commit_review(
        &self,
        expected_memory_revision: &str,
        memory: &crate::StoredMemory,
        history: &ReviewHistoryRow,
    ) -> Result<()> {
        use respire_protocol::metadata::{validate_revision, validate_timestamp};
        use respire_protocol::Verification;

        self.write_transaction(|| {
            anyhow::ensure!(self.memory_metadata_v1_enabled()?, "memory_metadata_v1_disabled");
            anyhow::ensure!(self.memory_revision()? == expected_memory_revision, "review_conflict");
            anyhow::ensure!(history.entry_id == memory.id && history.seq.is_none(), "invalid review history target");
            validate_revision(&history.record_revision)?;
            validate_timestamp(&history.happened_at)?;
            memory.local_meta.validate()?;
            anyhow::ensure!(memory.local_meta.memory_contract == 1, "review requires memory contract 1");
            let actor: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&history.actor)?;

            let (old_verification, old_review_at, old_ciphertext, old_owner, deleted):
                (Option<String>, Option<String>, String, String, bool) = self.connection.query_row(
                "SELECT verification,review_at,ciphertext,user,deleted FROM memories WHERE id=?1",
                [&memory.id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )?;
            anyhow::ensure!(!deleted && !memory.deleted && old_owner == memory.user, "review target is unavailable");
            let old_verification = old_verification.as_deref()
                .map(serde_json::from_str::<Verification>).transpose()?;
            let previous_verification = history.previous_verification.as_deref()
                .map(serde_json::from_str::<Verification>).transpose()?;
            let next_verification = history.next_verification.as_deref()
                .map(serde_json::from_str::<Verification>).transpose()?;
            anyhow::ensure!(
                previous_verification == old_verification && history.previous_review_at == old_review_at,
                "review_conflict: previous review state changed"
            );
            anyhow::ensure!(
                next_verification == memory.local_meta.verification
                    && history.next_review_at == memory.local_meta.review_at,
                "review history does not match the saved projection"
            );
            match history.action.as_str() {
                "confirm" => anyhow::ensure!(
                    next_verification.as_ref().is_some_and(|value| value.record_revision == history.record_revision),
                    "confirmation must match the target record revision"
                ),
                "revoke" => anyhow::ensure!(
                    next_verification.is_none()
                        && history.reason.as_ref().is_some_and(|reason| !reason.trim().is_empty()),
                    "revocation requires a nonempty reason and cleared verification"
                ),
                "reschedule" => anyhow::ensure!(
                    next_verification == old_verification && history.next_review_at.is_some(),
                    "reschedule must preserve verification and provide review_at"
                ),
                "clear_review_at" => anyhow::ensure!(
                    next_verification == old_verification && history.next_review_at.is_none(),
                    "clear_review_at must preserve verification and clear review_at"
                ),
                _ => anyhow::bail!("unsupported review action"),
            }
            if history.action == "confirm" {
                let actor: respire_protocol::ConfirmedBy = serde_json::from_str(&history.actor)?;
                anyhow::ensure!(
                    next_verification.as_ref().is_some_and(|value| value.confirmed_by == actor),
                    "confirmation actor does not match verification"
                );
            } else {
                anyhow::ensure!(
                    actor.get("kind").and_then(|value| value.as_str()) == Some("owner_client")
                        && actor.get("id").and_then(|value| value.as_str()) == Some(old_owner.as_str()),
                    "review action requires the owner_client actor"
                );
            }
            anyhow::ensure!(memory.ciphertext != old_ciphertext, "review requires a newly sealed payload");
            anyhow::ensure!(self.put_inner(memory, true)?, "review_conflict: target write was rejected");
            self.connection.execute(
                "INSERT INTO review_history(entry_id,record_revision,action,actor,happened_at,
                 previous_verification,next_verification,previous_review_at,next_review_at,reason)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![history.entry_id,history.record_revision,history.action,history.actor,history.happened_at,
                    history.previous_verification,history.next_verification,
                    history.previous_review_at,history.next_review_at,history.reason],
            )?;
            Ok(())
        })
    }

    /// The caller supplies an already-authorized full ID; never resolve prefixes here.
    pub fn review_history(&self, id: &str, limit: usize) -> Result<Vec<ReviewHistoryRow>> {
        anyhow::ensure!(!id.is_empty(), "review history requires a full entry ID");
        anyhow::ensure!((1..=200).contains(&limit), "limit must be 1..=200");
        let mut statement = self.connection.prepare(
            "SELECT seq,entry_id,record_revision,action,actor,happened_at,
             previous_verification,next_verification,previous_review_at,next_review_at,reason
             FROM review_history WHERE entry_id=?1 ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![id, i64::try_from(limit)?], |row| {
            Ok(ReviewHistoryRow {
                seq: Some(row.get(0)?),
                entry_id: row.get(1)?,
                record_revision: row.get(2)?,
                action: row.get(3)?,
                actor: row.get(4)?,
                happened_at: row.get(5)?,
                previous_verification: row.get(6)?,
                next_verification: row.get(7)?,
                previous_review_at: row.get(8)?,
                next_review_at: row.get(9)?,
                reason: row.get(10)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

//! Recognition and user decisions are separate from immutable content history.
use super::LocalStore;
use crate::transport::protocol::*;
use crate::{MemoryEngine, SessionKeys, StoredMemory};
use anyhow::{bail, Result};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

impl LocalStore {
    fn conflict_head(&self, epoch: &str, id: &str) -> Result<Option<(i64, StoredMemory)>> {
        let row=self.connection.query_row("SELECT h.rev,i.wire FROM sync_remote_heads h JOIN sync_inbox i ON i.epoch=?1 AND i.id=h.id AND i.rev=h.rev WHERE h.id=?2",
            params![epoch,id],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?))).optional()?;
        row.map(|(rev, wire)| Ok((rev, serde_json::from_str(&wire)?)))
            .transpose()
    }

    /// Only content-equivalent records can be processed automatically. A legacy
    /// rejection with different content stays needs_review regardless of its age.
    pub fn classify_conflicts(&self, keys: &SessionKeys, can_resolve: bool) -> Result<()> {
        let mut after = 0;
        while let Some(next) = self.classify_conflicts_batch(keys, can_resolve, after)? {
            after = next;
        }
        Ok(())
    }

    pub fn classify_conflicts_batch(
        &self,
        keys: &SessionKeys,
        can_resolve: bool,
        after: i64,
    ) -> Result<Option<i64>> {
        // Acquire the writer before snapshot reads; a later promotion can fail with SQLITE_BUSY_SNAPSHOT.
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let epoch = self.meta_get("sync_v2_epoch")?.unwrap_or_default();
        let mut stmt=self.connection.prepare("SELECT i.rev,i.status,i.wire FROM sync_inbox i LEFT JOIN sync_resolutions r ON r.epoch=i.epoch AND r.conflict_rev=i.rev
            WHERE i.rev>?2 AND i.epoch=?1 AND i.status IN ('conflict_saved','legacy_rejected') AND r.conflict_rev IS NULL ORDER BY i.rev LIMIT ?3")?;
        let rows = stmt
            .query_map(params![epoch, after, PUSH_ITEMS as i64], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let next = rows.last().map(|row| row.0);
        for (rev, status, wire) in rows {
            let candidate: StoredMemory = serde_json::from_str(&wire)?;
            let head = self.conflict_head(&epoch, &candidate.id)?;
            let (head_rev, kind, reason) = match head {
                None => (0, "needs_review", "head_not_available"),
                Some((head_rev, current)) => {
                    match MemoryEngine::equivalent_versions(keys, &candidate, &current) {
                        Ok(true) => (
                            head_rev,
                            "equivalent",
                            "same_payload_except_version_timestamp",
                        ),
                        Ok(false) if status == "legacy_rejected" => (
                            head_rev,
                            "needs_review",
                            "legacy_rejection_has_distinct_content",
                        ),
                        Ok(false) => (head_rev, "conflict", "concurrent_distinct_content"),
                        Err(_) => (head_rev, "needs_review", "cannot_decrypt_for_comparison"),
                    }
                }
            };
            self.connection.execute("INSERT INTO sync_conflict_analysis(epoch,rev,kind,head_rev,reason) VALUES(?1,?2,?3,?4,?5)
                ON CONFLICT(epoch,rev) DO UPDATE SET kind=excluded.kind,head_rev=excluded.head_rev,reason=excluded.reason",
                params![epoch,rev,kind,head_rev,reason])?;
            if kind == "equivalent" && can_resolve {
                self.connection.execute("INSERT INTO sync_resolution_outbox(epoch,conflict_rev,action,expected_head_rev) VALUES(?1,?2,'equivalent',?3) ON CONFLICT DO NOTHING",
                    params![epoch,rev,head_rev])?;
            }
        }
        tx.commit()?;
        Ok(next)
    }

    fn store_resolution(&self, epoch: &str, r: &Resolution) -> Result<()> {
        self.connection.execute("INSERT INTO sync_resolutions(epoch,conflict_rev,seq,id,action,head_rev,restore_op_id,processed_at)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(epoch,conflict_rev) DO UPDATE SET seq=excluded.seq,action=excluded.action,
            head_rev=excluded.head_rev,restore_op_id=excluded.restore_op_id,processed_at=excluded.processed_at",
            params![epoch,r.conflict_rev,r.seq,r.id,r.action,r.head_rev,r.restore_op_id,r.processed_at])?;
        self.connection.execute(
            "DELETE FROM sync_resolution_outbox WHERE epoch=?1 AND conflict_rev=?2",
            params![epoch, r.conflict_rev],
        )?;
        Ok(())
    }

    /// Store dispositions and their independent watermark in one local transaction.
    pub fn apply_resolution_page(&self, page: &ResolutionPage) -> Result<()> {
        if self.meta_get("sync_v2_epoch")?.as_deref() != Some(page.epoch.as_str()) {
            bail!("resolution epoch mismatch");
        }
        let previous = self
            .meta_get("sync_v2_resolution_cursor")?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if page.cursor < previous
            || page.cursor > page.until
            || (page.has_more && page.cursor == previous)
        {
            bail!("invalid resolution page cursor");
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut last = previous;
        for r in &page.resolutions {
            if r.seq <= last || r.seq > page.cursor {
                bail!("invalid resolution page order");
            }
            last = r.seq;
            self.store_resolution(&page.epoch, r)?;
        }
        self.meta_set("sync_v2_resolution_cursor", &page.cursor.to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Content operations must be acknowledged first; pending restores cannot be
    /// mistaken for successfully handled conflicts after a crash or disconnection.
    pub fn outgoing_resolutions(&self) -> Result<Vec<ResolutionDecision>> {
        self.outgoing_resolutions_through(0, i64::MAX)
    }
    pub fn resolution_boundary(&self) -> Result<i64> {
        Ok(self.connection.query_row("SELECT coalesce(max(conflict_rev),0) FROM sync_resolution_outbox WHERE epoch=(SELECT value FROM meta WHERE key='sync_v2_epoch')", [], |r| r.get(0))?)
    }
    pub fn outgoing_resolutions_through(
        &self,
        after: i64,
        until: i64,
    ) -> Result<Vec<ResolutionDecision>> {
        let epoch = self.meta_get("sync_v2_epoch")?.unwrap_or_default();
        let mut stmt=self.connection.prepare("SELECT r.conflict_rev,r.expected_head_rev,r.action,r.restore_op_id FROM sync_resolution_outbox r
            LEFT JOIN sync_outbox o ON o.op_id=r.restore_op_id WHERE r.epoch=?1 AND r.conflict_rev>?3 AND r.conflict_rev<=?4
            AND (r.restore_op_id IS NULL OR o.state IN ('applied','conflict_saved')) ORDER BY r.conflict_rev LIMIT ?2")?;
        let rows = stmt
            .query_map(params![epoch, PUSH_ITEMS as i64, after, until], |r| {
                Ok(ResolutionDecision {
                    conflict_rev: r.get(0)?,
                    expected_head_rev: r.get(1)?,
                    action: r.get(2)?,
                    restore_op_id: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn acknowledge_resolutions(
        &self,
        epoch: &str,
        sent: &[ResolutionDecision],
        reply: &ResolveReply,
    ) -> Result<()> {
        if sent.len() != reply.results.len() {
            bail!("resolution receipt length mismatch");
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        for (decision, result) in sent.iter().zip(&reply.results) {
            if decision.conflict_rev != result.conflict_rev {
                bail!("resolution receipt identity mismatch");
            }
            match (&*result.outcome, &result.resolution) {
                ("processed", Some(record)) if record.conflict_rev == decision.conflict_rev => {
                    self.store_resolution(epoch, record)?
                }
                ("stale", None) => {
                    self.connection.execute(
                        "DELETE FROM sync_resolution_outbox WHERE epoch=?1 AND conflict_rev=?2",
                        params![epoch, decision.conflict_rev],
                    )?;
                    self.connection.execute("UPDATE sync_conflict_analysis SET reason='head_changed_or_restoration_conflicted' WHERE epoch=?1 AND rev=?2",params![epoch,decision.conflict_rev])?;
                }
                _ => bail!("invalid resolution receipt"),
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Link an explicit recovery to the immutable outgoing operation in the same
    /// transaction that saved the recovered content (also used by sync-restore).
    pub(super) fn track_restoration(
        &self,
        epoch: &str,
        rev: i64,
        id: &str,
        action: &str,
    ) -> Result<()> {
        if self.meta_get("sync_v2_epoch")?.as_deref() != Some(epoch) {
            return Ok(());
        }
        let eligible:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sync_inbox i WHERE i.epoch=?1 AND i.rev=?2 AND i.id=?3
            AND i.status IN ('conflict_saved','legacy_rejected') AND NOT EXISTS(SELECT 1 FROM sync_resolutions r WHERE r.epoch=i.epoch AND r.conflict_rev=i.rev))",
            params![epoch,rev,id],|r|r.get(0))?;
        if !eligible {
            return Ok(());
        }
        let op:String=self.connection.query_row("SELECT op_id FROM sync_outbox WHERE id=?1 AND state='pending' ORDER BY seq DESC LIMIT 1",[id],|r|r.get(0))?;
        self.connection.execute("INSERT INTO sync_resolution_outbox(epoch,conflict_rev,action,expected_head_rev,restore_op_id)
            VALUES(?1,?2,?3,0,?4) ON CONFLICT(epoch,conflict_rev) DO UPDATE SET action=excluded.action,restore_op_id=excluded.restore_op_id,expected_head_rev=0",
            params![epoch,rev,action,op])?;
        Ok(())
    }

    /// Explicit decisions preserve history. Merge edits current metadata; take_incoming
    /// preserves the candidate's deletion intent rather than silently resurrecting it.
    pub fn queue_conflict_resolution(
        &self,
        keys: &SessionKeys,
        epoch: &str,
        rev: i64,
        inspected_head_rev: i64,
        action: &str,
        content: Option<&str>,
    ) -> Result<()> {
        if self.meta_get("sync_v2_epoch")?.as_deref() != Some(epoch) {
            bail!("sync the current epoch first; older epoch versions can be restored with sync-restore");
        }
        if self.meta_get("sync_v2_resolution_support")?.as_deref() != Some("1") {
            bail!("server does not support conflict handling yet; upgrade the server");
        }
        if !matches!(action, "keep_current" | "take_incoming" | "merge") {
            bail!("invalid resolution action");
        }
        if (action == "merge") != content.is_some() {
            bail!("only merge needs --content");
        }
        // Keep the inspected state and its resolution in one reserved write transaction.
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let processed: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_resolutions WHERE epoch=?1 AND conflict_rev=?2)",
            params![epoch, rev],
            |r| r.get(0),
        )?;
        if processed {
            if action != "keep_current" {
                bail!("this record is already resolved and no new version was created; use update or sync-restore to change it again");
            }
            tx.commit()?;
            return Ok(());
        }
        let wire:String=self.connection.query_row("SELECT wire FROM sync_inbox WHERE epoch=?1 AND rev=?2 AND status IN ('conflict_saved','legacy_rejected')",params![epoch,rev],|r|r.get(0))?;
        let candidate: StoredMemory = serde_json::from_str(&wire)?;
        let (head_rev, current) = self
            .conflict_head(epoch, &candidate.id)?
            .ok_or_else(|| anyhow::anyhow!("sync the current version first"))?;
        if head_rev != inspected_head_rev {
            bail!(
                "current version changed; re-run sync-conflicts --refresh and use its current.rev"
            );
        }
        if action == "keep_current" {
            self.connection.execute("INSERT INTO sync_resolution_outbox(epoch,conflict_rev,action,expected_head_rev) VALUES(?1,?2,'keep_current',?3)
                ON CONFLICT(epoch,conflict_rev) DO UPDATE SET action=excluded.action,expected_head_rev=excluded.expected_head_rev,restore_op_id=NULL",params![epoch,rev,head_rev])?;
        } else {
            let pending: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sync_outbox WHERE id=?1 AND state='pending')",
                [&candidate.id],
                |r| r.get(0),
            )?;
            let base: Option<i64> = self
                .connection
                .query_row(
                    "SELECT rev FROM sync_base WHERE id=?1",
                    [&candidate.id],
                    |r| r.get(0),
                )
                .optional()?;
            if pending || base != Some(head_rev) {
                bail!("current content is not applied or still has pending local changes; finish sync first");
            }
            let mut selected = if action == "merge" {
                current
            } else {
                candidate
            };
            let deleted = selected.deleted && action == "take_incoming";
            let stamp = self.edit_stamp(&selected.id)?;
            if selected.ciphertext.is_empty() {
                if !deleted {
                    bail!("this version has no mergeable content");
                }
                selected.updated_at = stamp;
            } else {
                MemoryEngine::prepare_resolution(keys, &mut selected, &stamp, content)?;
            }
            selected.deleted = deleted;
            if !self.put_inner(&selected, true)? {
                bail!("resolution version was not written");
            }
            self.track_restoration(epoch, rev, &selected.id, action)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn conflict_metrics(&self) -> Result<(i64, i64, i64, i64)> {
        let epoch = self.meta_get("sync_v2_epoch")?.unwrap_or_default();
        let total: i64 = self.connection.query_row(
            "SELECT count(*) FROM sync_inbox WHERE status IN ('conflict_saved','legacy_rejected')",
            [],
            |r| r.get(0),
        )?;
        let processed:i64=self.connection.query_row("SELECT count(*) FROM sync_inbox i JOIN sync_resolutions r ON r.epoch=i.epoch AND r.conflict_rev=i.rev WHERE i.epoch=?1 AND i.status IN ('conflict_saved','legacy_rejected')",[&epoch],|r|r.get(0))?;
        let old:i64=self.connection.query_row("SELECT count(*) FROM sync_inbox WHERE epoch<>?1 AND status IN ('conflict_saved','legacy_rejected')",[&epoch],|r|r.get(0))?;
        let resolving: i64 = self.connection.query_row(
            "SELECT count(*) FROM sync_resolution_outbox WHERE epoch=?1",
            [&epoch],
            |r| r.get(0),
        )?;
        Ok((total, processed, old, resolving))
    }

    pub fn processed_conflict_action(&self, epoch: &str, rev: i64) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT action FROM sync_resolutions WHERE epoch=?1 AND conflict_rev=?2",
                params![epoch, rev],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// A review view contains plaintext only on the user's own client, never on the server.
    pub fn list_conflicts(
        &self,
        keys: &SessionKeys,
        id: Option<&str>,
        include_processed: bool,
    ) -> Result<Vec<serde_json::Value>> {
        let epoch = self.meta_get("sync_v2_epoch")?.unwrap_or_default();
        let mut stmt=self.connection.prepare("SELECT i.epoch,i.rev,i.id,i.status,i.wire,a.kind,a.reason,r.action,o.action FROM sync_inbox i
            LEFT JOIN sync_conflict_analysis a ON a.epoch=i.epoch AND a.rev=i.rev
            LEFT JOIN sync_resolutions r ON r.epoch=i.epoch AND r.conflict_rev=i.rev
            LEFT JOIN sync_resolution_outbox o ON o.epoch=i.epoch AND o.conflict_rev=i.rev
            WHERE i.status IN ('conflict_saved','legacy_rejected') AND (?1 IS NULL OR i.id=?1)
            AND (?2 OR (i.epoch=?3 AND r.conflict_rev IS NULL)) ORDER BY i.rev DESC LIMIT 200")?;
        let rows = stmt
            .query_map(params![id, include_processed, epoch], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let describe = |b: &StoredMemory| -> serde_json::Value {
            match MemoryEngine::open(keys, b) {
                Ok(entry) => serde_json::json!({"deleted":b.deleted,"entry":entry}),
                Err(e) => serde_json::json!({"deleted":b.deleted,"decode_error":e.to_string()}),
            }
        };
        let mut result = Vec::new();
        for (scope, rev, id, status, wire, kind, reason, processed, queued) in rows {
            let candidate: StoredMemory = serde_json::from_str(&wire)?;
            let head = if scope == epoch {
                self.conflict_head(&scope, &id)?
            } else {
                None
            };
            let state = if scope != epoch {
                "historical_epoch"
            } else if processed.is_some() {
                "processed"
            } else if queued.is_some() {
                "resolving"
            } else {
                "pending"
            };
            result.push(serde_json::json!({"epoch":scope,"rev":rev,"id":id,"original_status":status,"kind":kind,"reason":reason,
                "state":state,"resolution":processed,"queued_action":queued,"candidate":describe(&candidate),
                "current":head.map(|(rev,b)|serde_json::json!({"rev":rev,"value":describe(&b)}))}));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(keys: &SessionKeys, content: &str, stamp: &str) -> Result<StoredMemory> {
        let entry: crate::MemoryEntry = serde_json::from_value(
            serde_json::json!({"id":"entry","kind":"Context","tags":[],
            "title":"record","content":content,"user":"u","computer":"test","project":"sync",
            "created_at":"2026-09-19T00:00:00.000Z","updated_at":stamp,"emotion":-1.0,"parent_id":""}),
        )?;
        crate::MemoryEngine::seal(
            keys,
            &crate::memory::search::HashingEmbedder::default(),
            &entry,
            "u",
        )
    }

    fn fixture() -> Result<(tempfile::TempDir, LocalStore, SessionKeys)> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("local.db"))?;
        store.begin_sync_epoch("epoch")?;
        store.meta_set("sync_v2_resolution_support", "1")?;
        let keys = SessionKeys::from_urk([7; 32])?;
        let old = sealed(&keys, "current", "2026-09-19T00:00:00.001Z")?;
        let distinct = sealed(&keys, "unique old edit", "2026-09-19T00:00:00.002Z")?;
        let current = sealed(&keys, "current", "2026-09-19T00:00:00.003Z")?;
        store.apply_page(
            &keys,
            &Page {
                epoch: "epoch".into(),
                until: 3,
                cursor: 3,
                has_more: false,
                total: 1,
                alive: 1,
                changes: vec![
                    Change {
                        rev: 1,
                        status: "legacy_rejected".into(),
                        op_id: None,
                        blob: old,
                    },
                    Change {
                        rev: 2,
                        status: "legacy_rejected".into(),
                        op_id: None,
                        blob: distinct,
                    },
                    Change {
                        rev: 3,
                        status: "applied".into(),
                        op_id: None,
                        blob: current,
                    },
                ],
            },
            false,
        )?;
        Ok((dir, store, keys))
    }

    #[test]
    fn sync_only_equivalent_legacy_versions_are_automatically_processed() -> Result<()> {
        let (_dir, store, keys) = fixture()?;
        store.classify_conflicts(&keys, true)?;
        let outgoing = store.outgoing_resolutions()?;
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].conflict_rev, 1);
        assert_eq!(store.sync_counts()?.1, 2);
        let record = Resolution {
            seq: 1,
            conflict_rev: 1,
            id: "entry".into(),
            action: "equivalent".into(),
            head_rev: 3,
            restore_op_id: None,
            processed_at: "now".into(),
        };
        let reply = ResolveReply {
            results: vec![ResolutionResult {
                conflict_rev: 1,
                outcome: "processed".into(),
                resolution: Some(record.clone()),
            }],
        };
        store.acknowledge_resolutions("epoch", &outgoing, &reply)?;
        store.acknowledge_resolutions("epoch", &outgoing, &reply)?;
        store.apply_resolution_page(&ResolutionPage {
            epoch: "epoch".into(),
            cursor: 1,
            until: 1,
            has_more: false,
            resolutions: vec![record],
        })?;
        assert_eq!(store.sync_counts()?.1, 1);
        assert_eq!(store.conflict_metrics()?, (2, 1, 0, 0));
        let pending = store.list_conflicts(&keys, None, false)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["kind"], "needs_review");
        assert_eq!(
            pending[0]["candidate"]["entry"]["content"],
            "unique old edit"
        );
        Ok(())
    }

    #[test]
    fn sync_merge_waits_for_content_acceptance_and_conflicted_restore_stays_open() -> Result<()> {
        let (_dir, store, keys) = fixture()?;
        store.queue_conflict_resolution(
            &keys,
            "epoch",
            2,
            3,
            "merge",
            Some("current plus unique old edit"),
        )?;
        assert!(store.outgoing_resolutions()?.is_empty());
        let operations = store.outgoing()?;
        assert_eq!(operations.len(), 1);
        assert_eq!(
            MemoryEngine::open(&keys, &operations[0].blob)?.content,
            "current plus unique old edit"
        );
        store.acknowledge(
            &operations,
            &[Receipt {
                op_id: operations[0].op_id.clone(),
                status: "conflict_saved".into(),
                stored_rev: 4,
                head_rev: 3,
            }],
            false,
        )?;
        let decisions = store.outgoing_resolutions()?;
        assert_eq!(decisions.len(), 1);
        store.acknowledge_resolutions(
            "epoch",
            &decisions,
            &ResolveReply {
                results: vec![ResolutionResult {
                    conflict_rev: 2,
                    outcome: "stale".into(),
                    resolution: None,
                }],
            },
        )?;
        assert_eq!(store.processed_conflict_action("epoch", 2)?, None);
        assert_eq!(store.sync_counts()?.1, 2);
        assert!(store.outgoing_resolutions()?.is_empty());
        Ok(())
    }

    #[test]
    fn sync_keep_current_stale_head_and_epoch_reset_do_not_fake_completion() -> Result<()> {
        let (_dir, store, keys) = fixture()?;
        store.queue_conflict_resolution(&keys, "epoch", 2, 3, "keep_current", None)?;
        let decisions = store.outgoing_resolutions()?;
        assert_eq!(decisions[0].expected_head_rev, 3);
        store.acknowledge_resolutions(
            "epoch",
            &decisions,
            &ResolveReply {
                results: vec![ResolutionResult {
                    conflict_rev: 2,
                    outcome: "stale".into(),
                    resolution: None,
                }],
            },
        )?;
        assert_eq!(store.sync_counts()?.1, 2);
        store.reset_sync_snapshot()?;
        store.begin_sync_epoch("new")?;
        assert_eq!(store.sync_counts()?.1, 0);
        assert_eq!(store.conflict_metrics()?, (2, 0, 2, 0));
        assert!(store
            .queue_conflict_resolution(&keys, "epoch", 2, 3, "keep_current", None)
            .is_err());
        Ok(())
    }

    #[test]
    fn sync_take_incoming_preserves_delete_intent() -> Result<()> {
        let (_dir, store, keys) = fixture()?;
        let mut deleted = sealed(&keys, "delete me", "2026-09-19T00:00:00.001Z")?;
        deleted.deleted = true;
        store.apply_page(
            &keys,
            &Page {
                epoch: "epoch".into(),
                until: 4,
                cursor: 4,
                has_more: false,
                total: 1,
                alive: 1,
                changes: vec![Change {
                    rev: 4,
                    status: "conflict_saved".into(),
                    op_id: None,
                    blob: deleted,
                }],
            },
            false,
        )?;
        store.queue_conflict_resolution(&keys, "epoch", 4, 3, "take_incoming", None)?;
        let outgoing = store.outgoing()?;
        assert_eq!(outgoing.len(), 1);
        assert!(outgoing[0].blob.deleted);
        assert_eq!(store.processed_conflict_action("epoch", 4)?, None);
        Ok(())
    }

    #[test]
    fn sync_reviewed_head_must_match_before_creating_a_merge() -> Result<()> {
        let (_dir, store, keys) = fixture()?;
        assert!(store
            .queue_conflict_resolution(
                &keys,
                "epoch",
                2,
                2,
                "merge",
                Some("based on an obsolete view")
            )
            .is_err());
        assert!(store.outgoing()?.is_empty());
        assert!(store.outgoing_resolutions()?.is_empty());
        assert_eq!(store.sync_counts()?.1, 2);
        Ok(())
    }
}

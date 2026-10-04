//! Durable outgoing versions and atomic incoming pages.
use super::LocalStore;
use crate::transport::protocol::*;
use crate::{hydrate_local, SessionKeys, StoredMemory};
use anyhow::{bail, Result};
use rusqlite::params;

impl LocalStore {
    /// Read a bounded immutable batch; the same op_id always carries the same bytes.
    pub fn outgoing(&self) -> Result<Vec<Operation>> {
        self.outgoing_through(i64::MAX)
    }

    pub fn outgoing_boundary(&self) -> Result<i64> {
        Ok(self.connection.query_row(
            "SELECT coalesce(max(seq),0) FROM sync_outbox WHERE state='pending'",
            [],
            |r| r.get(0),
        )?)
    }

    pub fn outgoing_through(&self, boundary: i64) -> Result<Vec<Operation>> {
        let mut stmt=self.connection.prepare("SELECT op_id,id,base_rev,parent_op_id,user,ciphertext,nonce,embedding_enc,updated_at,deleted FROM sync_outbox WHERE state='pending' AND seq<=?2 ORDER BY seq LIMIT ?1")?;
        let rows = stmt.query_map([PUSH_ITEMS as i64, boundary], |r| {
            Ok(Operation {
                op_id: r.get(0)?,
                base_rev: r.get(2)?,
                parent_op_id: r.get(3)?,
                blob: StoredMemory {
                    id: r.get(1)?,
                    user: r.get(4)?,
                    ciphertext: r.get(5)?,
                    nonce: r.get(6)?,
                    embedding_enc: r.get(7)?,
                    updated_at: r.get(8)?,
                    deleted: r.get::<_, i64>(9)? != 0,
                    ..StoredMemory::new_pending(String::new(), String::new())
                },
            })
        })?;
        let mut batch = Vec::new();
        let mut bytes = 256;
        for row in rows {
            let op = row?;
            let size = serde_json::to_vec(&op)?.len() + 1;
            if !batch.is_empty() && bytes + size > BATCH_BYTES {
                break;
            }
            if bytes + size > BATCH_BYTES {
                bail!(
                    "single sync item exceeds server batch limit: {} (kept locally)",
                    op.blob.id
                );
            }
            bytes += size;
            batch.push(op);
        }
        Ok(batch)
    }

    /// Scope prevents accidentally acknowledging an outbox against a different vault.
    pub fn begin_sync_epoch(&self, epoch: &str) -> Result<()> {
        self.begin_sync_epoch_requeued(epoch).map(|_| ())
    }

    /// Report an identity migration so a finite caller cannot silently expand its scope.
    pub fn begin_sync_epoch_requeued(&self, epoch: &str) -> Result<bool> {
        let mut requeued = false;
        if let Some(old) = self.meta_get("sync_v2_epoch")? {
            if old != epoch {
                bail!(
                    "server sync epoch changed; local edits kept; rebuild the snapshot explicitly"
                );
            }
        } else {
            let tx = self.connection.unchecked_transaction()?;
            let legacy_parent:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sync_outbox p JOIN sync_outbox c ON c.parent_op_id=p.op_id WHERE p.state='legacy' AND c.state='pending')",[],|r|r.get(0))?;
            if legacy_parent {
                self.requeue_pending()?;
                requeued = true;
            }
            self.meta_set("sync_v2_epoch", epoch)?;
            tx.commit()?;
        }
        Ok(requeued)
    }

    /// Receipts clear only the sent version, never a later local edit.
    pub fn acknowledge(
        &self,
        sent: &[Operation],
        receipts: &[Receipt],
        legacy: bool,
    ) -> Result<usize> {
        if sent.len() != receipts.len() {
            bail!("sync ack count mismatch");
        }
        let tx = self.connection.unchecked_transaction()?;
        let mut applied = 0;
        for (op, r) in sent.iter().zip(receipts) {
            if r.op_id != op.op_id
                || !matches!(
                    r.status.as_str(),
                    "applied" | "conflict_saved" | "legacy_rejected"
                )
            {
                bail!("sync ack does not match operations");
            }
            self.connection.execute(
                "UPDATE sync_outbox SET state=?2 WHERE op_id=?1 AND state='pending'",
                params![op.op_id, if legacy { "legacy" } else { r.status.as_str() }],
            )?;
            self.connection.execute("UPDATE memories SET dirty=0 WHERE id=?1 AND ciphertext=?2 AND nonce=?3 AND updated_at=?4 AND deleted=?5",
                params![op.blob.id,op.blob.ciphertext,op.blob.nonce,op.blob.updated_at,i64::from(op.blob.deleted)])?;
            if r.status == "applied" {
                applied += 1;
            }
        }
        tx.commit()?;
        Ok(applied)
    }

    /// Raw ciphertext and cursor commit together, even if local keys cannot decode it.
    pub fn apply_page(&self, keys: &SessionKeys, page: &Page, snapshot: bool) -> Result<usize> {
        let key = if snapshot {
            "sync_v2_snapshot_cursor"
        } else {
            "sync_v2_cursor"
        };
        let previous = self
            .meta_get(key)?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if page.cursor < previous
            || page.cursor > page.until
            || (page.has_more && page.cursor == previous)
        {
            bail!("server returned an invalid page cursor");
        }
        let mut last = previous;
        let tx = self.connection.unchecked_transaction()?;
        for change in &page.changes {
            if change.rev <= last || change.rev > page.cursor {
                bail!("server page version order is wrong");
            }
            last = change.rev;
            let wire = serde_json::to_string(&change.blob)?;
            let mut b = change.blob.clone();
            // Vectors are device-local derived state, not a legacy encrypted cache.
            b.embedding_enc.clear();
            let error = if b.deleted && b.ciphertext.is_empty() {
                String::new()
            } else {
                hydrate_local(keys, &mut b)
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default()
            };
            self.connection.execute("INSERT INTO sync_inbox(epoch,rev,id,status,op_id,wire,decode_error) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(epoch,rev) DO UPDATE SET decode_error=excluded.decode_error",
                params![page.epoch,change.rev,b.id,change.status,change.op_id,wire,error])?;
            if change.status == "applied" {
                self.connection.execute("INSERT INTO sync_remote_heads(id,rev) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET rev=excluded.rev WHERE excluded.rev>sync_remote_heads.rev",params![b.id,change.rev])?;
                let pending: bool = self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sync_outbox WHERE id=?1 AND state='pending')",
                    [&b.id],
                    |r| r.get(0),
                )?;
                if !pending && error.is_empty() {
                    self.put_inner_policy(&b, false, true)?;
                    self.connection.execute("INSERT INTO sync_base(id,rev) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET rev=excluded.rev",params![b.id,change.rev])?;
                }
            }
        }
        self.meta_set(key, &page.cursor.to_string())?;
        if snapshot {
            self.meta_set("sync_v2_snapshot_until", &page.until.to_string())?;
            if !page.has_more {
                self.meta_set("sync_v2_cursor", &page.cursor.to_string())?;
                self.meta_set("sync_v2_snapshot_done", "1")?;
            }
        }
        tx.commit()?;
        Ok(page.changes.len())
    }

    /// Restore the latest received canonical state after acknowledgments without
    /// re-downloading the full account or destroying pending outgoing versions.
    pub fn materialize_received(&self, keys: &SessionKeys) -> Result<()> {
        let mut after = String::new();
        while let Some(next) = self.materialize_received_batch(keys, &after)? {
            after = next;
        }
        Ok(())
    }

    pub fn materialize_received_batch(
        &self,
        keys: &SessionKeys,
        after: &str,
    ) -> Result<Option<String>> {
        let tx = self.connection.unchecked_transaction()?;
        let mut stmt=self.connection.prepare("SELECT i.id,i.wire,i.rev FROM sync_inbox i JOIN sync_remote_heads b ON b.id=i.id AND b.rev=i.rev
            LEFT JOIN sync_base e ON e.id=i.id
            WHERE i.id>?2 AND i.epoch=?1 AND i.status='applied' AND i.decode_error='' AND (e.rev IS NULL OR e.rev<>i.rev) AND NOT EXISTS (
            SELECT 1 FROM sync_outbox o WHERE o.id=i.id AND o.state='pending') ORDER BY i.id LIMIT ?3")?;
        let epoch = self.meta_get("sync_v2_epoch")?.unwrap_or_default();
        let wires = stmt
            .query_map(params![epoch, after, PUSH_ITEMS as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let next = wires.last().map(|row| row.0.clone());
        for (id, wire, rev) in wires {
            let pending: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sync_outbox WHERE id=?1 AND state='pending')",
                [&id],
                |r| r.get(0),
            )?;
            if pending {
                continue;
            }
            let mut b: StoredMemory = serde_json::from_str(&wire)?;
            let unchanged:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM memories WHERE id=?1 AND ciphertext=?2 AND updated_at=?3 AND deleted=?4)",
                params![b.id,b.ciphertext,b.updated_at,i64::from(b.deleted)],|r|r.get(0))?;
            if !unchanged {
                b.embedding_enc.clear();
                if !(b.deleted && b.ciphertext.is_empty()) {
                    hydrate_local(keys, &mut b)?;
                }
                self.put_inner_policy(&b, false, true)?;
            }
            self.connection.execute("INSERT INTO sync_base(id,rev) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET rev=excluded.rev",params![b.id,rev])?;
        }
        tx.commit()?;
        Ok(next)
    }

    /// Counts have distinct meanings: transport completion is not content equality.
    pub fn sync_counts(&self) -> Result<(i64, i64, i64)> {
        Ok((
            self.connection.query_row(
                "SELECT count(*) FROM sync_outbox WHERE state='pending'",
                [],
                |r| r.get(0),
            )?,
            self.connection.query_row(
                "SELECT count(*) FROM sync_inbox i WHERE i.epoch=(SELECT value FROM meta WHERE key='sync_v2_epoch')
                AND i.status IN ('conflict_saved','legacy_rejected') AND NOT EXISTS(SELECT 1 FROM sync_resolutions r WHERE r.epoch=i.epoch AND r.conflict_rev=i.rev)",
                [],
                |r| r.get(0),
            )?,
            self.connection.query_row(
                "SELECT count(*) FROM sync_inbox WHERE decode_error<>''",
                [],
                |r| r.get(0),
            )?,
        ))
    }

    /// Explicit recovery after restoring a server backup. Preserve all old envelopes;
    /// pending edits get fresh identities with unknown bases, never automatic rebases.
    pub fn reset_sync_snapshot(&self) -> Result<()> {
        let tx = self.connection.unchecked_transaction()?;
        self.requeue_pending()?;
        self.connection.execute("DELETE FROM sync_base", [])?;
        self.connection
            .execute("DELETE FROM sync_remote_heads", [])?;
        self.connection
            .execute("DELETE FROM meta WHERE key LIKE 'sync_v2_%'", [])?;
        tx.commit()?;
        Ok(())
    }

    fn requeue_pending(&self) -> Result<()> {
        let archived = format!("rebased:{}", uuid::Uuid::new_v4());
        self.connection.execute(
            "UPDATE sync_outbox SET state=?1 WHERE state='pending'",
            [&archived],
        )?;
        self.connection.execute("INSERT INTO sync_outbox(op_id,id,user,ciphertext,nonce,embedding_enc,updated_at,deleted)
            SELECT lower(hex(randomblob(16))),id,user,ciphertext,nonce,embedding_enc,updated_at,deleted
            FROM sync_outbox WHERE state=?1 ORDER BY seq",[&archived])?;
        self.connection.execute("UPDATE sync_outbox AS c SET parent_op_id=(SELECT p.op_id FROM sync_outbox p WHERE p.state='pending' AND p.id=c.id AND p.seq<c.seq ORDER BY p.seq DESC LIMIT 1) WHERE c.state='pending'",[])?;
        Ok(())
    }

    /// Read recoverable encrypted versions without moving either sync cursor.
    pub fn sync_history(&self, id: Option<&str>) -> Result<Vec<serde_json::Value>> {
        let mut stmt=self.connection.prepare("SELECT epoch,rev,status,op_id,wire FROM sync_inbox WHERE (?1 IS NULL OR id=?1) ORDER BY rev DESC LIMIT 200")?;
        let mut out=stmt.query_map([id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,String>(4)?)))?
            .map(|row| {let (epoch,rev,status,op_id,wire)=row?;Ok(serde_json::json!({"epoch":epoch,"rev":rev,"status":status,"op_id":op_id,"blob":serde_json::from_str::<serde_json::Value>(&wire)?}))})
            .collect::<Result<Vec<_>>>()?;
        let mut stmt=self.connection.prepare("SELECT op_id,id,user,ciphertext,nonce,updated_at,deleted,state FROM sync_outbox WHERE (?1 IS NULL OR id=?1) ORDER BY seq DESC LIMIT 200")?;
        for row in stmt.query_map([id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, bool>(6)?,
                r.get::<_, String>(7)?,
            ))
        })? {
            let (op_id, id, user, ciphertext, nonce, updated_at, deleted, status) = row?;
            out.push(serde_json::json!({"op_id":op_id,"status":status,"blob":{"id":id,"user":user,"ciphertext":ciphertext,"nonce":nonce,"updated_at":updated_at,"deleted":deleted,"embedding_enc":""}}));
        }
        Ok(out)
    }

    /// Cache remote history for inspection/restoration, not as a new editing base.
    pub fn cache_history(&self, page: &Page) -> Result<()> {
        let tx = self.connection.unchecked_transaction()?;
        for c in &page.changes {
            self.connection.execute("INSERT INTO sync_inbox(epoch,rev,id,status,op_id,wire) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT DO NOTHING",
                params![page.epoch,c.rev,c.blob.id,c.status,c.op_id,serde_json::to_string(&c.blob)?])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Restore ciphertext locally as a new version, updating encrypted timestamps
    /// without loading the embedding model. Existing history is never overwritten.
    pub fn restore_sync_version(
        &self,
        keys: &SessionKeys,
        op_id: Option<&str>,
        rev: Option<i64>,
        epoch: Option<&str>,
    ) -> Result<String> {
        use rusqlite::OptionalExtension;
        let wire = if let Some(op) = op_id {
            let tuple=self.connection.query_row("SELECT id,user,ciphertext,nonce,updated_at,deleted FROM sync_outbox WHERE op_id=?1",[op],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,bool>(5)?))).optional()?;
            let Some((id, user, ciphertext, nonce, updated_at, deleted)) = tuple else {
                bail!("local operation not found");
            };
            serde_json::to_string(&StoredMemory {
                id,
                user,
                ciphertext,
                nonce,
                updated_at,
                deleted,
                ..StoredMemory::new_pending(String::new(), String::new())
            })?
        } else if let Some(rev) = rev {
            let epoch = epoch.ok_or_else(|| {
                anyhow::anyhow!("restoring a remote version requires both --epoch and --rev")
            })?;
            self.connection
                .query_row(
                    "SELECT wire FROM sync_inbox WHERE epoch=?1 AND rev=?2",
                    params![epoch, rev],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    anyhow::anyhow!("version not found; try sync-history --remote first")
                })?
        } else {
            bail!("--op-id or --rev required");
        };
        let mut b: StoredMemory = serde_json::from_str(&wire)?;
        if b.ciphertext.is_empty() {
            bail!("this version has no restorable content");
        }
        let tx = self.connection.unchecked_transaction()?;
        let stamp = self.edit_stamp(&b.id)?;
        crate::MemoryEngine::restore_version(keys, &mut b, &stamp)?;
        if !self.put_inner(&b, true)? {
            bail!("restored version was not written");
        }
        if let (Some(epoch), Some(rev)) = (epoch, rev) {
            self.track_restoration(epoch, rev, &b.id, "restore")?;
        }
        tx.commit()?;
        Ok(b.id)
    }

    /// Legacy download and cursor update share a transaction; outgoing snapshots
    /// have already been captured by triggers before any remote version is applied.
    pub fn apply_legacy(
        &self,
        keys: &SessionKeys,
        blobs: Vec<StoredMemory>,
        cursor: u64,
    ) -> Result<usize> {
        let tx = self.connection.unchecked_transaction()?;
        let mut changed = 0;
        for mut b in blobs {
            b.embedding_enc.clear();
            if !(b.deleted && b.ciphertext.is_empty()) {
                hydrate_local(keys, &mut b)?;
            }
            if self.put_synced(&b)? {
                changed += 1;
            }
        }
        self.meta_set("sync_cursor", &cursor.to_string())?;
        tx.commit()?;
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MemoryTransport;

    #[test]
    fn encrypted_history_restore_uses_explicit_old_epoch() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let s = LocalStore::open(&dir.path().join("a.db"))?;
        let keys = SessionKeys::from_urk([9; 32])?;
        let entry: crate::MemoryEntry = serde_json::from_value(serde_json::json!({
            "id":"entry","kind":"Context","tags":[],"title":"first","content":"retained original",
            "user":"u","computer":"test","project":"sync","created_at":"2026-09-19T00:00:00.001Z",
            "updated_at":"2026-09-19T00:00:00.001Z","emotion":-1.0,"parent_id":""
        }))?;
        let stored = crate::MemoryEngine::seal(
            &keys,
            &crate::memory::search::HashingEmbedder::default(),
            &entry,
            "u",
        )?;
        s.begin_sync_epoch("e")?;
        s.apply_page(&keys, &page(1, stored), false)?;
        s.reset_sync_snapshot()?;
        s.begin_sync_epoch("new")?;
        let mut new_page = page(1, tomb("entry", "2026-09-19T00:00:00.002Z"));
        new_page.epoch = "new".into();
        s.apply_page(&keys, &new_page, false)?;
        assert!(s.restore_sync_version(&keys, None, Some(1), None).is_err());
        assert_eq!(
            s.restore_sync_version(&keys, None, Some(1), Some("e"))?,
            "entry"
        );
        let outgoing = s.outgoing()?;
        assert_eq!(outgoing.len(), 1);
        assert_eq!(
            crate::MemoryEngine::open(&keys, &outgoing[0].blob)?.content,
            "retained original"
        );
        assert_eq!(outgoing[0].base_rev, Some(1));
        Ok(())
    }

    fn tomb(id: &str, ts: &str) -> StoredMemory {
        let mut b = StoredMemory::new_pending(id.to_owned(), "u".to_owned());
        b.updated_at = ts.to_owned();
        b.deleted = true;
        b
    }

    fn page(rev: i64, b: StoredMemory) -> Page {
        Page {
            epoch: "e".into(),
            until: rev,
            cursor: rev,
            has_more: false,
            changes: vec![Change {
                rev,
                status: "applied".into(),
                op_id: None,
                blob: b,
            }],
            total: 1,
            alive: 0,
        }
    }

    #[test]
    fn outbox_ack_cannot_clear_later_save_and_survives_restart() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("local.db");
        let s = LocalStore::open(&path)?;
        s.put(&tomb("a", "2026-09-19T00:00:00.001Z"))?;
        let first = s.outgoing()?;
        s.put(&tomb("a", "2026-09-19T00:00:00.002Z"))?;
        let receipt = Receipt {
            op_id: first[0].op_id.clone(),
            status: "applied".into(),
            stored_rev: 1,
            head_rev: 1,
        };
        s.acknowledge(&first, &[receipt], false)?;
        assert_eq!(s.all_dirty()?.len(), 1);
        let remaining = s.outgoing()?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].parent_op_id.as_deref(),
            Some(first[0].op_id.as_str())
        );
        drop(s);
        let reopened = LocalStore::open(&path)?;
        assert_eq!(reopened.outgoing()?[0].op_id, remaining[0].op_id);
        Ok(())
    }

    #[test]
    fn pending_and_undecodable_heads_do_not_advance_editing_base() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let s = LocalStore::open(&dir.path().join("a.db"))?;
        let keys = SessionKeys::from_urk([7; 32])?;
        s.begin_sync_epoch("e")?;
        s.apply_page(
            &keys,
            &page(1, tomb("a", "2026-09-19T00:00:00.001Z")),
            false,
        )?;
        s.put(&tomb("a", "2026-09-19T00:00:00.003Z"))?;
        let outgoing = s.outgoing()?;
        s.apply_page(
            &keys,
            &page(2, tomb("a", "2026-09-19T00:00:00.002Z")),
            false,
        )?;
        let base: i64 =
            s.connection
                .query_row("SELECT rev FROM sync_base WHERE id='a'", [], |r| r.get(0))?;
        assert_eq!(base, 1);
        s.acknowledge(
            &outgoing,
            &[Receipt {
                op_id: outgoing[0].op_id.clone(),
                status: "conflict_saved".into(),
                stored_rev: 3,
                head_rev: 2,
            }],
            false,
        )?;
        // Re-entering with no pending operation must finish interrupted materialization.
        s.materialize_received(&keys)?;
        assert_eq!(
            s.updated_at_of("a")?.as_deref(),
            Some("2026-09-19T00:00:00.002Z")
        );
        let mut broken = tomb("a", "2026-09-19T00:00:00.004Z");
        broken.deleted = false;
        broken.ciphertext = "broken".into();
        broken.nonce = "broken".into();
        s.apply_page(&keys, &page(4, broken), false)?;
        let base: i64 =
            s.connection
                .query_row("SELECT rev FROM sync_base WHERE id='a'", [], |r| r.get(0))?;
        assert_eq!(base, 2);
        assert_eq!(s.sync_counts()?.2, 1);
        Ok(())
    }

    #[test]
    fn bad_page_rolls_back_versions_and_cursor() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let s = LocalStore::open(&dir.path().join("a.db"))?;
        let keys = SessionKeys::from_urk([7; 32])?;
        s.begin_sync_epoch("e")?;
        let mut p = page(2, tomb("a", "2026-09-19T00:00:00.002Z"));
        p.changes.push(p.changes[0].clone());
        assert!(s.apply_page(&keys, &p, false).is_err());
        assert_eq!(s.meta_get("sync_v2_cursor")?, None);
        assert!(s.all(true)?.is_empty());
        assert!(s.sync_history(None)?.is_empty());
        Ok(())
    }

    #[test]
    fn index_update_is_local_and_reset_keeps_pending_history() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let s = LocalStore::open(&dir.path().join("a.db"))?;
        let mut b = tomb("a", "2026-09-19T00:00:00.001Z");
        b.deleted = false;
        b.ciphertext = "source".into();
        s.put(&b)?;
        let op = s.outgoing()?[0].op_id.clone();
        assert!(s.set_artifact("a", b"locator", "source")?);
        assert!(!s.set_artifact("a", b"locator", "stale")?);
        assert_eq!(s.outgoing()?.len(), 1);
        s.begin_sync_epoch("old")?;
        s.reset_sync_snapshot()?;
        s.begin_sync_epoch("new")?;
        let pending = s.outgoing()?;
        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0].op_id, op);
        assert!(s.sync_history(None)?.len() >= 2);
        Ok(())
    }

    #[test]
    fn legacy_parent_is_reissued_before_first_v2_sync() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let s = LocalStore::open(&dir.path().join("a.db"))?;
        s.put(&tomb("a", "2026-09-19T00:00:00.001Z"))?;
        let first = s.outgoing()?;
        s.put(&tomb("a", "2026-09-19T00:00:00.002Z"))?;
        s.acknowledge(
            &first,
            &[Receipt {
                op_id: first[0].op_id.clone(),
                status: "applied".into(),
                stored_rev: 0,
                head_rev: 0,
            }],
            true,
        )?;
        let before = s.outgoing()?;
        assert!(before[0].parent_op_id.is_some());
        s.begin_sync_epoch("new")?;
        let after = s.outgoing()?;
        assert_eq!(after.len(), 1);
        assert!(after[0].parent_op_id.is_none());
        assert!(after[0].base_rev.is_none());
        assert_ne!(before[0].op_id, after[0].op_id);
        assert!(s.sync_history(None)?.len() >= 3);
        Ok(())
    }
}

//! transport::local — local authoritative working store (SQLite)
//!
//! local-first: search / dedup / merge are all local. This store holds ciphertext + local plaintext index columns
//! (kind/tags/title/project/computer + plaintext embedding BLOB),
//! those plaintext columns serve local search only and are **never uploaded** (StoredMemory serde skip).
//!
//! Supported TEXT-ID schemas retain their rows during upgrades. Historical
//! INTEGER-ID demos use a different ciphertext format and require explicit export.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use super::MemoryTransport;
use crate::memory::model::StoredMemory;

mod conflicts;
mod grants;
mod retrieval;
mod resident;
pub use resident::MemorySourceChanged;
mod related;
mod sync;
pub use grants::AccessGrant;
pub use retrieval::IndexSourceChanged;

/// Query-log row (query-log command output). candidates=search candidates; adopted=used on a write (weak signal);
/// good/bad=model self-grade (main post-train signal: useful / misleading).
#[derive(serde::Serialize)]
pub struct QueryLogRow {
    pub id: i64,
    pub ts: String,
    pub query: String,
    pub project: String,
    pub scope: String,
    pub candidates: Vec<String>,
    pub adopted: Vec<String>,
    pub good: Vec<String>,
    pub bad: Vec<String>,
}

/// Query-log stats.
#[derive(serde::Serialize)]
pub struct QueryLogStats {
    pub total: i64,
    /// Queries with at least one adopted id
    pub with_adopted: i64,
    /// Queries with an empty candidate set (search negatives)
    pub empty_candidates: i64,
    /// Model self-grade "useful" total (post-train chosen)
    pub good_total: i64,
    /// Model self-grade "misleading" total (post-train rejected)
    pub bad_total: i64,
    /// Top adopted entries (id, count)
    pub top: Vec<(String, i64)>,
}

pub struct LocalStore {
    connection: Connection,
}

fn map_audit(row: &rusqlite::Row<'_>) -> rusqlite::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "entry_id": row.get::<_, String>(0)?,
        "action": row.get::<_, String>(1)?,
        "title": row.get::<_, String>(2)?,
        "content_head": row.get::<_, String>(3)?,
        "actor": row.get::<_, String>(4)?,
        "ts": row.get::<_, String>(5)?,
    }))
}

impl LocalStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create data dir: {}", parent.display()))?;
            respire_core_sdk::set_index_root(&std::fs::canonicalize(parent)?)?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open local memory db: {}", path.display()))?;
        connection.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 30000;
            ",
        )?;
        migrate(&connection)?;
        connection.execute_batch(include_str!("local/sync_schema.sql"))?;
        connection.execute_batch(include_str!("local/resident_schema.sql"))?;
        Ok(Self { connection })
    }

    /// Connect to a library already initialized by its runtime owner, without recovery writes.
    pub fn open_existing(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            respire_core_sdk::set_index_root(&std::fs::canonicalize(parent)?)?;
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| {
            format!("failed to open initialized local memory db: {}", path.display())
        })?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 30000;")?;
        connection
            .prepare("SELECT seq, op_id, state FROM sync_outbox LIMIT 0")
            .context("runtime library schema is not initialized")?;
        Ok(Self { connection })
    }

    /// Benchmark an initialized library without migrations or database writes.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            respire_core_sdk::set_index_root(&std::fs::canonicalize(parent)?)?;
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ).with_context(|| format!("failed to open read-only memory db: {}", path.display()))?;
        connection.busy_timeout(std::time::Duration::from_secs(30))?;
        Ok(Self { connection })
    }

    /// Write (dirty semantics same as put, mark dirty=1).
    pub fn put_inner(&self, memory: &StoredMemory, dirty: bool) -> Result<bool> {
        self.put_inner_policy(memory, dirty, false)
    }

    fn put_inner_policy(
        &self,
        memory: &StoredMemory,
        dirty: bool,
        authoritative: bool,
    ) -> Result<bool> {
        let immediate = self.connection.is_autocommit().then(||
            rusqlite::Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)).transpose()?;
        self.connection
            .execute_batch("SAVEPOINT memory_with_chunks")?;
        let result = self.put_memory_and_chunks(memory, dirty, authoritative);
        if result.is_err() {
            self.connection
                .execute_batch("ROLLBACK TO memory_with_chunks")?;
        }
        self.connection
            .execute_batch("RELEASE memory_with_chunks")?;
        if result.is_ok() { if let Some(immediate) = immediate { immediate.commit()?; } }
        result
    }

    fn put_memory_and_chunks(
        &self,
        memory: &StoredMemory,
        dirty: bool,
        authoritative: bool,
    ) -> Result<bool> {
        // last-write-wins: same id and existing updated_at is newer → drop this write;
        // a tie (same updated_at) and local dirty=1 → also refuse — unpushed local edits (attach/delete) must not be overwritten by a sync loop
        // (hit 2026-09-08: after batch attach, sync reconcile pulled a same-stamp remote and wiped the unpushed attach).
        let existing: Option<(String, i64)> = self
            .connection
            .query_row(
                "SELECT updated_at, dirty FROM memories WHERE id = ?1",
                params![memory.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((old, was_dirty)) = existing {
            let order = super::compare_timestamps(&old, &memory.updated_at)?;
            if !authoritative && (order.is_gt() || (order.is_eq() && was_dirty == 1)) {
                return Ok(false); // local already has a newer / unpushed version
            }
        }
        // Preserve legacy derived bytes only for an unchanged encrypted source.
        // New writers never provide or persist raw Core features.
        let emb_blob = self.connection.query_row(
            "SELECT embedding FROM memories WHERE id=?1 AND ciphertext=?2",
            params![memory.id, memory.ciphertext], |row| row.get::<_, Option<Vec<u8>>>(0),
        ).optional()?.flatten();
        self.connection.execute(
            "INSERT INTO memories
                (id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, dirty, parent_id, content_head, recall_count, importance,
                 device, modified_by)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
             ON CONFLICT(id) DO UPDATE SET
                user=excluded.user, ciphertext=excluded.ciphertext, nonce=excluded.nonce,
                embedding_enc=excluded.embedding_enc, updated_at=excluded.updated_at,
                deleted=excluded.deleted, kind=excluded.kind, tags=excluded.tags,
                title=excluded.title, project=excluded.project, computer=excluded.computer,
                embedding=excluded.embedding, created_at=excluded.created_at,
                dirty=excluded.dirty, parent_id=excluded.parent_id, content_head=excluded.content_head,
                importance=excluded.importance, device=excluded.device, modified_by=excluded.modified_by,
                recall_count=COALESCE((SELECT recall_count FROM memories WHERE id=excluded.id), excluded.recall_count)",
            params![
                memory.id,
                memory.user,
                memory.ciphertext,
                memory.nonce,
                memory.embedding_enc,
                memory.updated_at,
                memory.deleted as i64,
                memory.local_kind,
                memory.local_tags,
                memory.local_title,
                memory.local_project,
                memory.local_computer,
                emb_blob,
                memory.local_created_at,
                dirty as i64,
                memory.local_parent_id,
                memory.local_content_head,
                memory.local_recall_count,
                memory.local_importance,
                memory.local_device,
                memory.local_modified_by,
            ],
        )?;
        self.store_artifact(memory, &self.retrieval_model()?)?;
        Ok(true)
    }

    /// Import already-sealed new rows: the whole batch commits or rolls back, so a partial backup cannot remain.
    pub fn import_batch(&self, memories: &[StoredMemory]) -> Result<()> {
        let transaction = rusqlite::Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        for memory in memories {
            if !self.put_inner(memory, true)? {
                anyhow::bail!("import conflict: {}", memory.id);
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Keep a compound local edit atomic, including any reads used to plan it.
    pub fn write_transaction<T>(&self, edit: impl FnOnce() -> Result<T>) -> Result<T> {
        let transaction = rusqlite::Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        let result = edit()?;
        transaction.commit()?;
        Ok(result)
    }

    /// Pull-only write (sync pull step): write content but do not mark dirty — dirty is reserved for real local edits.
    pub fn put_synced(&self, memory: &StoredMemory) -> Result<bool> {
        self.put_inner(memory, false)
    }

    /// For LWW: local updated_at of one id (None if missing).
    pub fn updated_at_of(&self, id: &str) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT updated_at FROM memories WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Read the version from the live store so a batch does not reuse an old snapshot and mint the same stamp twice.
    pub fn edit_stamp(&self, id: &str) -> Result<String> {
        let previous: Option<String> = self
            .connection
            .query_row(
                "SELECT updated_at FROM memories WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        super::timestamp_after(previous.as_deref())
    }

    fn row_to_memory(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMemory> {
        let local_embedding = None;
        Ok(StoredMemory {
            id: row.get(0)?,
            user: row.get(1)?,
            ciphertext: row.get(2)?,
            nonce: row.get(3)?,
            embedding_enc: row.get(4)?,
            updated_at: row.get(5)?,
            deleted: row.get::<_, i64>(6)? != 0,
            local_kind: row.get(7)?,
            local_tags: row.get(8)?,
            local_title: row.get(9)?,
            local_project: row.get(10)?,
            local_computer: row.get(11)?,
            local_embedding,
            local_parent_id: row.get(14)?,
            local_created_at: row.get(13)?,
            local_content_head: row.get(15)?,
            local_recall_count: row.get(16)?,
            local_importance: row.get(17).unwrap_or_else(|_| "normal".to_owned()),
            local_device: row.get(18).unwrap_or_default(),
            local_modified_by: row.get(19).unwrap_or_default(),
            local_chunks: Vec::new(),
            local_artifact: Vec::new(),
        })
    }

    /// Dirty rows (local new/edit/delete, pending cloud push). Includes tombstones.
    pub fn all_dirty(&self) -> Result<Vec<StoredMemory>> {
        let mut statement = self.connection.prepare(
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by
             FROM memories WHERE dirty = 1",
        )?;
        let rows = statement.query_map([], Self::row_to_memory)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Live rows pending a vector: embedding column empty (not yet embedded on this machine).
    /// Called after cross-device sync — remote only syncs ciphertext; this machine recomputes vectors with its own model (frozen 2026-09-14).
    pub fn missing_embedding(&self) -> Result<Vec<StoredMemory>> {
        let mut statement = self.connection.prepare(
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by
             FROM memories WHERE deleted = 0 AND NOT EXISTS (SELECT 1 FROM core_artifacts a WHERE a.memory_id=memories.id AND a.source=memories.ciphertext AND a.model=?1)",
        )?;
        let rows = statement.query_map([respire_core_sdk::generation_key(&self.retrieval_model()?)?], Self::row_to_memory)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Clear dirty (called after a successful push).
    pub fn clear_dirty(&self, id: &str) -> Result<()> {
        self.connection
            .execute("UPDATE memories SET dirty = 0 WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Causal tree: direct children of a node (tombstones? live only).
    pub fn children(&self, parent_id: &str) -> Result<Vec<StoredMemory>> {
        if parent_id.is_empty() {
            return self.roots();
        }
        let mut statement = self.connection.prepare(
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by
             FROM memories WHERE parent_id = ?1 AND deleted = 0 ORDER BY recall_count DESC, updated_at",
        )?;
        let rows = statement.query_map(params![parent_id], Self::row_to_memory)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Causal tree: root set (entries with no cause, i.e. event sources).
    pub fn roots(&self) -> Result<Vec<StoredMemory>> {
        let mut statement = self.connection.prepare(
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by
             FROM memories WHERE parent_id = '' AND deleted = 0 ORDER BY recall_count DESC, updated_at",
        )?;
        let rows = statement.query_map([], Self::row_to_memory)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Causal tree: reparent (new parent) — update parent_id, bump updated_at and mark dirty (syncs),
    /// used by promote / demote and --parent reattach.
    /// Cycle check is the caller's: the new parent must not be a descendant (this store does not recurse; the command layer does).
    pub fn set_parent(&self, id: &str, new_parent_id: &str) -> Result<bool> {
        let now = self.edit_stamp(id)?;
        let n = self.connection.execute(
            "UPDATE memories SET parent_id = ?2, updated_at = ?3, dirty = 1 WHERE id = ?1 AND deleted = 0",
            params![id, new_parent_id, now],
        )?;
        Ok(n > 0)
    }

    /// Causal tree: walk the cause chain (parent→grandparent→…), return root-to-parent order (excluding self).
    pub fn ancestor_chain(&self, id: &str) -> Result<Vec<String>> {
        let mut chain = Vec::new();
        let mut cur = id.to_owned();
        for _ in 0..64 {
            let pid: Option<String> = self
                .connection
                .query_row(
                    "SELECT parent_id FROM memories WHERE id = ?1",
                    params![cur],
                    |row| row.get(0),
                )
                .ok();
            match pid {
                Some(p) if !p.is_empty() => {
                    chain.push(p.clone());
                    cur = p;
                }
                _ => break,
            }
        }
        chain.reverse(); // root first
        Ok(chain)
    }

    /// Bump hit count (after recall returns, +1 on hit entries; local heat only, not dirty, not synced).
    pub fn bump_recall_count(&self, id: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "UPDATE memories SET recall_count = recall_count + 1 WHERE id = ?1",
            params![id],
        )? > 0)
    }

    /// Query log: each recall writes one candidate row (including empty — empty is a search negative, DPO material).
    /// Note: this records the candidate set, not hits — a hit is a model mark --good, see mark_verdict.
    /// Local-only table, not dirty, not synced.
    pub fn log_query(
        &self,
        query: &str,
        project: &str,
        scope: &str,
        candidates: &[String],
        candidate_scores: &[f32],
    ) -> Result<()> {
        let now = chrono::Utc::now();
        self.connection.execute(
            "INSERT INTO query_log (ts_unix, ts, query, project, scope, candidates, candidate_scores, adopted)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'[]')",
            params![
                now.timestamp(),
                now.to_rfc3339(),
                query,
                project,
                scope,
                serde_json::to_string(candidates)?,
                serde_json::to_string(candidate_scores)?
            ],
        )?;
        Ok(())
    }

    /// Recall hit-heat writeback: hit entries recall_count + 1 (source of the heat-axis hit_score).
    pub fn bump_recall(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        for id in ids {
            self.connection.execute(
                "UPDATE memories SET recall_count = recall_count + 1 WHERE id = ?1",
                params![id],
            )?;
        }
        Ok(())
    }

    /// For the passport: distinct computer count in this library (live rows).
    pub fn devices_count(&self) -> Result<usize> {
        Ok(self.connection.query_row(
            "SELECT COUNT(DISTINCT computer) FROM memories WHERE deleted = 0",
            [],
            |r| r.get::<_, i64>(0),
        )? as usize)
    }

    /// Entry-change audit query: action stream for this id (or whole library --limit) (trigger-recorded, see entry_audit).
    pub fn entry_audit(
        &self,
        entry_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let rows = if let Some(eid) = entry_id {
            let mut stmt = self.connection.prepare(
                "SELECT entry_id, action, title_head, content_head, actor, ts
                 FROM entry_audit WHERE entry_id = ?1 ORDER BY seq DESC LIMIT ?2",
            )?;
            let v: Vec<serde_json::Value> = stmt
                .query_map(rusqlite::params![eid, limit as i64], map_audit)?
                .flatten()
                .collect();
            v
        } else {
            let mut stmt = self.connection.prepare(
                "SELECT entry_id, action, title_head, content_head, actor, ts
                 FROM entry_audit ORDER BY seq DESC LIMIT ?1",
            )?;
            let v: Vec<serde_json::Value> = stmt
                .query_map(rusqlite::params![limit as i64], map_audit)?
                .flatten()
                .collect();
            v
        };
        Ok(rows)
    }

    /// Model self-grade report (main post-train signal): useful recall hits --good, misleading --bad.
    /// Look back 10 minutes (at most 20 rows) for candidate logs containing this id (8-char prefix ok), write good_ids/bad_ids.
    /// Returns ids that matched no candidate (caller warns).
    pub fn mark_verdict(&self, ids: &[String], good: bool) -> Result<Vec<String>> {
        let cutoff = chrono::Utc::now().timestamp() - 600;
        let rows: Vec<(i64, String, String, String)> = {
            let mut stmt = self.connection.prepare(
                "SELECT id, candidates, good_ids, bad_ids FROM query_log WHERE ts_unix >= ?1 ORDER BY id DESC LIMIT 20",
            )?;
            let it = stmt.query_map(params![cutoff], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            it.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut unmatched: Vec<String> = ids.to_vec();
        for (row_id, cands_json, good_json, bad_json) in rows {
            if unmatched.is_empty() {
                break;
            }
            let cands: Vec<String> = serde_json::from_str(&cands_json).unwrap_or_default();
            let mut good_ids: Vec<String> = serde_json::from_str(&good_json).unwrap_or_default();
            let mut bad_ids: Vec<String> = serde_json::from_str(&bad_json).unwrap_or_default();
            let mut changed = false;
            unmatched.retain(|short| {
                let Some(full) = cands
                    .iter()
                    .find(|c| *c == short || c.starts_with(short.as_str()))
                else {
                    return true; // this row has no such candidate; id stays unmatched
                };
                // Re-grade: latest self-grade wins — write this side and remove from the other (bad then good = re-grade good)
                let (tgt, other) = if good {
                    (&mut good_ids, &mut bad_ids)
                } else {
                    (&mut bad_ids, &mut good_ids)
                };
                if !tgt.contains(full) {
                    tgt.push(full.clone());
                    changed = true;
                }
                if let Some(pos) = other.iter().position(|x| x == full) {
                    other.remove(pos);
                    changed = true;
                }
                false // matched; drop from unmatched
            });
            if changed {
                self.connection.execute(
                    "UPDATE query_log SET good_ids = ?2, bad_ids = ?3 WHERE id = ?1",
                    params![
                        row_id,
                        serde_json::to_string(&good_ids)?,
                        serde_json::to_string(&bad_ids)?
                    ],
                )?;
            }
        }
        Ok(unmatched)
    }

    /// Adoption attribution: called after a successful update/attach/demote/merge/attach —
    /// if a query in the last 10 minutes (at most 20 rows back) hit this id, record the id in that query's adopted.
    /// Returns how many query rows were marked.
    pub fn mark_adopted(&self, id: &str) -> Result<usize> {
        let cutoff = chrono::Utc::now().timestamp() - 600;
        let rows: Vec<(i64, String)> = {
            let mut stmt = self
                .connection
                .prepare("SELECT id, candidates FROM query_log WHERE ts_unix >= ?1 ORDER BY id DESC LIMIT 20")?;
            let it = stmt.query_map(params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?;
            it.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut marked = 0;
        for (row_id, cands_json) in rows {
            let ids: Vec<String> = serde_json::from_str(&cands_json).unwrap_or_default();
            if !ids.iter().any(|x| x == id) {
                continue;
            }
            let adopted: Vec<String> = {
                let cur: String = self.connection.query_row(
                    "SELECT adopted FROM query_log WHERE id = ?1",
                    params![row_id],
                    |r| r.get(0),
                )?;
                serde_json::from_str(&cur).unwrap_or_default()
            };
            if adopted.iter().any(|x| x == id) {
                continue;
            }
            let mut next = adopted;
            next.push(id.to_owned());
            self.connection.execute(
                "UPDATE query_log SET adopted = ?2 WHERE id = ?1",
                params![row_id, serde_json::to_string(&next)?],
            )?;
            marked += 1;
        }
        Ok(marked)
    }

    /// List recent query logs (newest first).
    pub fn query_log_rows(&self, limit: usize) -> Result<Vec<QueryLogRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT id, ts, query, project, scope, candidates, adopted, good_ids, bad_ids FROM query_log ORDER BY id DESC LIMIT ?1",
        )?;
        let it = stmt.query_map(params![limit as i64], |r| {
            Ok(QueryLogRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                query: r.get(2)?,
                project: r.get(3)?,
                scope: r.get(4)?,
                candidates: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                adopted: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
                good: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default(),
                bad: serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default(),
            })
        })?;
        Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Query-log stats: total queries, queries with adopted, empty-candidate count, self-grade good/bad totals, top adopted entries.
    pub fn query_log_stats(&self) -> Result<QueryLogStats> {
        let total: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM query_log", [], |r| r.get(0))?;
        let with_adopted: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM query_log WHERE adopted != '[]'",
            [],
            |r| r.get(0),
        )?;
        let empty_candidates: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM query_log WHERE candidates = '[]'",
            [],
            |r| r.get(0),
        )?;
        // Self-grade counts: expand JSON arrays (old SQLite without json1 falls back to 0)
        let count_json = |col: &str| -> i64 {
            self.connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM query_log, json_each(query_log.{col})"),
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0)
        };
        let good_total = count_json("good_ids");
        let bad_total = count_json("bad_ids");
        // Top adopted entries: expand JSON arrays and count
        let mut top: Vec<(String, i64)> = Vec::new();
        let ok = self
            .connection
            .prepare("SELECT je.value, COUNT(*) c FROM query_log, json_each(query_log.good_ids) je GROUP BY je.value ORDER BY c DESC LIMIT 5")
            .and_then(|mut s| {
                let it = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
                top = it.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(())
            });
        if ok.is_err() {
            top.clear(); // old SQLite without json1 falls back to empty
        }
        Ok(QueryLogStats {
            total,
            with_adopted,
            empty_candidates,
            good_total,
            bad_total,
            top,
        })
    }

    /// meta read/write (sync cursor etc.).
    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok())
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO meta (key, value) VALUES (?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Persist a Core-owned index locator only if the encrypted source is current.
    /// Index work must never create a content version or an outgoing sync operation.
    pub fn set_artifact(
        &self,
        id: &str,
        artifact: &[u8],
        source_ciphertext: &str,
    ) -> Result<bool> {
        let n = self.connection.execute(
            "INSERT OR REPLACE INTO core_artifacts(memory_id,model,source,artifact)
             SELECT id,?2,ciphertext,?4 FROM memories WHERE id=?1 AND ciphertext=?3 AND deleted=0",
            params![id, respire_core_sdk::generation_key(&self.retrieval_model()?)?, source_ciphertext, artifact],
        )?;
        Ok(n > 0)
    }

    pub fn chunked_ids(&self) -> Result<std::collections::HashSet<String>> {
        let mut stmt = self
            .connection
            .prepare("SELECT DISTINCT memory_id FROM memory_chunks")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<std::collections::HashSet<_>>>()?)
    }
}

/// Validate and upgrade an existing migration staging database before publication.
/// This does not create a database or configure the private Core index root.
pub fn validate_migration_snapshot(path: &Path) -> Result<()> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("failed to open existing migration staging database")?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 30000;")?;
    migrate(&connection)?;
    connection
        .execute_batch(include_str!("local/sync_schema.sql"))
        .context("migration staging sync schema is incompatible")?;
    Ok(())
}

/// Commit schema upgrades together; any unsupported format or SQL failure leaves
/// the original tables and rows intact.
fn migrate(connection: &Connection) -> Result<()> {
    let transaction = connection.unchecked_transaction()?;
    migrate_schema(&transaction)?;
    transaction.execute_batch("CREATE TABLE IF NOT EXISTS recall_pairs(a TEXT NOT NULL,b TEXT NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(a,b),CHECK(a<b)); CREATE INDEX IF NOT EXISTS recall_pairs_b ON recall_pairs(b);")?;
    transaction.commit()?;
    Ok(())
}

fn migrate_schema(connection: &Connection) -> Result<()> {
    let has_old = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='memories'")?
        .exists([])?;
    if has_old {
        let columns: Vec<(String, String, i64)> = connection
            .prepare("PRAGMA table_info(memories)")?
            .query_map([], |row| Ok((row.get(1)?, row.get(2)?, row.get(5)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        anyhow::ensure!(
            !columns.iter().any(|(name, _, _)| name == "tag_hashes")
                && columns.iter().filter(|(_, _, primary)| *primary > 0).count() == 1
                && columns.iter().any(|(name, kind, primary)| {
                    name == "id" && kind.trim().eq_ignore_ascii_case("TEXT") && *primary == 1
                }),
            "unsupported legacy memory schema: historical INTEGER-ID/tag_hashes demos use a different key derivation and plaintext format; no rows were removed. Keep the original database and export with its original version before importing into rsrs"
        );
        for required in ["user", "ciphertext", "nonce", "created_at", "updated_at"] {
            anyhow::ensure!(
                columns.iter().any(|(name, _, _)| name == required),
                "unsupported memory schema: missing {required}; encrypted fields cannot be reconstructed. No rows were removed"
            );
        }
        // These are derived indexes or local state, not invented key material.
        // The original ciphertext, nonce, identity and timestamps stay untouched.
        for (name, declaration) in [
            ("embedding_enc", "TEXT NOT NULL DEFAULT ''"),
            ("deleted", "INTEGER NOT NULL DEFAULT 0"),
            ("kind", "TEXT NOT NULL DEFAULT 'context'"),
            ("tags", "TEXT NOT NULL DEFAULT ''"),
            ("title", "TEXT NOT NULL DEFAULT ''"),
            ("project", "TEXT NOT NULL DEFAULT ''"),
            ("computer", "TEXT NOT NULL DEFAULT ''"),
            ("embedding", "BLOB"),
        ] {
            if !columns.iter().any(|(existing, _, _)| existing == name) {
                connection.execute_batch(&format!(
                    "ALTER TABLE memories ADD COLUMN {name} {declaration}"
                ))?;
            }
        }
    }
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS memories (
            id TEXT PRIMARY KEY,
            user TEXT NOT NULL DEFAULT '',
            ciphertext TEXT NOT NULL DEFAULT '',
            nonce TEXT NOT NULL DEFAULT '',
            embedding_enc TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT '',
            deleted INTEGER NOT NULL DEFAULT 0,
            kind TEXT NOT NULL DEFAULT 'context',
            tags TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            project TEXT NOT NULL DEFAULT '',
            computer TEXT NOT NULL DEFAULT '',
            embedding BLOB,
            created_at TEXT NOT NULL DEFAULT '',
            dirty INTEGER NOT NULL DEFAULT 1,
            parent_id TEXT NOT NULL DEFAULT '',
            content_head TEXT NOT NULL DEFAULT '',
            recall_count INTEGER NOT NULL DEFAULT 0,
            importance TEXT NOT NULL DEFAULT 'normal',
            device TEXT NOT NULL DEFAULT '',
            modified_by TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(updated_at);
        CREATE TABLE IF NOT EXISTS memory_chunks (
            memory_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            embedding BLOB NOT NULL,
            PRIMARY KEY (memory_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_chunks_memory ON memory_chunks(memory_id);
        CREATE TABLE IF NOT EXISTS retrieval_generations (
            memory_id TEXT NOT NULL, model TEXT NOT NULL, source TEXT NOT NULL,
            embedding BLOB NOT NULL, chunks BLOB NOT NULL,
            PRIMARY KEY(memory_id, model)
        );
        CREATE TRIGGER IF NOT EXISTS clear_deleted_retrieval
        AFTER UPDATE OF deleted ON memories WHEN NEW.deleted = 1
        BEGIN
            DELETE FROM memory_chunks WHERE memory_id = NEW.id;
            DELETE FROM retrieval_generations WHERE memory_id = NEW.id;
        END;
        CREATE TRIGGER IF NOT EXISTS clear_removed_retrieval
        AFTER DELETE ON memories
        BEGIN
            DELETE FROM memory_chunks WHERE memory_id = OLD.id;
            DELETE FROM retrieval_generations WHERE memory_id = OLD.id;
        END;
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        ",
    )?;
    // v2 → v3 → v4: add columns (stock defaults, later filled by sync/backfill)
    let cols: Vec<String> = connection
        .prepare("PRAGMA table_info(memories)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !cols.iter().any(|c| c == "dirty") {
        connection.execute_batch(
            "
            ALTER TABLE memories ADD COLUMN dirty INTEGER NOT NULL DEFAULT 1;
            ",
        )?;
    }
    if !cols.iter().any(|c| c == "parent_id") {
        connection.execute_batch(
            "
            ALTER TABLE memories ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
            ",
        )?;
    }
    if !cols.iter().any(|c| c == "content_head") {
        connection.execute_batch(
            "
            ALTER TABLE memories ADD COLUMN content_head TEXT NOT NULL DEFAULT '';
            ",
        )?;
    }
    if !cols.iter().any(|c| c == "recall_count") {
        connection.execute_batch(
            "
            ALTER TABLE memories ADD COLUMN recall_count INTEGER NOT NULL DEFAULT 0;
            ",
        )?;
    }
    if !cols.iter().any(|c| c == "importance") {
        connection.execute_batch(
            "
            ALTER TABLE memories ADD COLUMN importance TEXT NOT NULL DEFAULT 'normal';
            ",
        )?;
    }
    if !cols.iter().any(|c| c == "device") {
        connection.execute_batch(
            "
            ALTER TABLE memories ADD COLUMN device TEXT NOT NULL DEFAULT '';
            ",
        )?;
    }
    if !cols.iter().any(|c| c == "modified_by") {
        connection.execute_batch(
            "
            ALTER TABLE memories ADD COLUMN modified_by TEXT NOT NULL DEFAULT '';
            ",
        )?;
    }
    // parent index: create after the column exists (new DBs already have it; old DBs add the column then reach here)
    connection.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_memories_parent ON memories(parent_id);
        CREATE TABLE IF NOT EXISTS access_grants (
            id TEXT PRIMARY KEY, label TEXT NOT NULL, root_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE TRIGGER IF NOT EXISTS revoke_deleted_root
        AFTER UPDATE OF deleted ON memories WHEN NEW.deleted = 1
        BEGIN UPDATE access_grants SET revoked = 1 WHERE root_id = NEW.id; END;
        CREATE TRIGGER IF NOT EXISTS revoke_removed_root
        AFTER DELETE ON memories
        BEGIN UPDATE access_grants SET revoked = 1 WHERE root_id = OLD.id; END;
        CREATE TABLE IF NOT EXISTS query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_unix INTEGER NOT NULL,
            ts TEXT NOT NULL,
            query TEXT NOT NULL,
            project TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT '',
            candidates TEXT NOT NULL DEFAULT '[]',
            candidate_scores TEXT NOT NULL DEFAULT '[]',
            adopted TEXT NOT NULL DEFAULT '[]',
            good_ids TEXT NOT NULL DEFAULT '[]',
            bad_ids TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts_unix);
        CREATE TABLE IF NOT EXISTS entry_audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id TEXT NOT NULL,
            action TEXT NOT NULL,
            title_head TEXT NOT NULL DEFAULT '',
            content_head TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_entry_audit_id ON entry_audit(entry_id);
        CREATE TRIGGER IF NOT EXISTS audit_mem_insert AFTER INSERT ON memories
        BEGIN
            INSERT INTO entry_audit(entry_id,action,title_head,content_head,actor,ts)
            VALUES (NEW.id,'create',NEW.title,substr(NEW.content_head,1,200),NEW.computer,NEW.updated_at);
        END;
        CREATE TRIGGER IF NOT EXISTS audit_mem_update AFTER UPDATE OF title,content_head,parent_id ON memories
        WHEN OLD.title != NEW.title OR OLD.content_head != NEW.content_head OR OLD.parent_id != NEW.parent_id
        BEGIN
            INSERT INTO entry_audit(entry_id,action,title_head,content_head,actor,ts)
            VALUES (NEW.id,'update',NEW.title,substr(NEW.content_head,1,200),NEW.computer,NEW.updated_at);
        END;
        CREATE TRIGGER IF NOT EXISTS audit_mem_delete AFTER UPDATE OF deleted ON memories
        WHEN OLD.deleted = 0 AND NEW.deleted = 1
        BEGIN
            INSERT INTO entry_audit(entry_id,action,title_head,content_head,actor,ts)
            VALUES (NEW.id,'delete',OLD.title,substr(OLD.content_head,1,200),NEW.computer,NEW.updated_at);
        END;
        CREATE TRIGGER IF NOT EXISTS audit_mem_restore AFTER UPDATE OF deleted ON memories
        WHEN OLD.deleted = 1 AND NEW.deleted = 0
        BEGIN
            INSERT INTO entry_audit(entry_id,action,title_head,content_head,actor,ts)
            VALUES (NEW.id,'restore',NEW.title,substr(NEW.content_head,1,200),NEW.computer,NEW.updated_at);
        END;
        CREATE TRIGGER IF NOT EXISTS audit_mem_purge AFTER DELETE ON memories
        BEGIN
            INSERT INTO entry_audit(entry_id,action,title_head,content_head,actor,ts)
            VALUES (OLD.id,'purge',OLD.title,substr(OLD.content_head,1,200),'',OLD.updated_at);
        END;
        ",
    )?;
    // query_log v1→v2: hit_ids/hit_scores renamed candidates/candidate_scores (candidates are not hits —
    // a hit is a model self-grade useful, in good_ids/bad_ids); old DBs add columns, new DBs already match and skip.
    let mut qcols: Vec<String> = connection
        .prepare("PRAGMA table_info(query_log)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if qcols.iter().any(|c| c == "hit_ids") {
        connection.execute_batch(
            "
            ALTER TABLE query_log RENAME COLUMN hit_ids TO candidates;
            ALTER TABLE query_log RENAME COLUMN hit_scores TO candidate_scores;
            ",
        )?;
        qcols = connection
            .prepare("PRAGMA table_info(query_log)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    }
    if !qcols.is_empty() && !qcols.iter().any(|c| c == "good_ids") {
        connection.execute_batch(
            "
            ALTER TABLE query_log ADD COLUMN good_ids TEXT NOT NULL DEFAULT '[]';
            ALTER TABLE query_log ADD COLUMN bad_ids TEXT NOT NULL DEFAULT '[]';
            ",
        )?;
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS core_artifacts (
            memory_id TEXT NOT NULL, model TEXT NOT NULL, source TEXT NOT NULL,
            artifact BLOB NOT NULL, PRIMARY KEY(memory_id,model)
        );",
    )?;
    Ok(())
}

/// purge helpers
impl LocalStore {
    /// Purge entry content: tombstone first, then clear ciphertext/body/vectors.
    pub fn purge_entry(&self, id: &str) -> Result<bool> {
        let id = id.trim_start_matches('#');
        let stamp = chrono::Utc::now().to_rfc3339();
        self.forget(id)?;
        self.connection
            .execute("DELETE FROM core_artifacts WHERE memory_id=?1", params![id])?;
        let n = self.connection.execute(
            "UPDATE memories SET ciphertext='', nonce='', embedding_enc='', embedding=NULL, title='', content_head='', tags='', project='', computer='', kind='', recall_count=0, dirty=1, updated_at=?2 WHERE id=?1",
            params![id, stamp],
        )?;
        Ok(n > 0)
    }

    /// Clear local content fields (called on an empty tombstone — remote already purged, local syncs the clear).
    pub fn purge_content(&self, id: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM core_artifacts WHERE memory_id=?1", params![id])?;
        self.connection.execute(
            "UPDATE memories SET ciphertext='', nonce='', embedding_enc='', embedding=NULL, title='', content_head='', tags='', project='', computer='' WHERE id=?1",
            params![id],
        )?;
        Ok(())
    }

    /// Clear tombstone content older than purge_days (auto-clean old tombstones).
    /// purge_days=0 → clear now; returns rows cleared.
    pub fn auto_purge_old(&self, days: i64) -> Result<usize> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339();
        let ids: Vec<String> = {
            let mut stmt = self.connection.prepare(
                "SELECT id FROM memories WHERE deleted=1 AND ciphertext<>'' AND updated_at < ?1",
            )?;
            let rows = stmt.query_map(params![cutoff], |row| row.get::<_, String>(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };
        for id in &ids {
            self.purge_content(id)?;
        }
        Ok(ids.len())
    }
}

impl MemoryTransport for LocalStore {
    fn put(&self, memory: &StoredMemory) -> Result<bool> {
        self.put_inner(memory, true)
    }

    fn all(&self, include_deleted: bool) -> Result<Vec<StoredMemory>> {
        let sql = if include_deleted {
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by
             FROM memories"
        } else {
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by
             FROM memories WHERE deleted = 0"
        };
        let mut statement = self.connection.prepare(sql)?;
        let rows = statement.query_map([], Self::row_to_memory)?;
        let mut out = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        self.attach_retrieval_index(&mut out)?;
        Ok(out)
    }

    fn max_updated_at(&self) -> Result<Option<String>> {
        let value: Option<String> = self
            .connection
            .query_row("SELECT MAX(updated_at) FROM memories", [], |row| row.get(0))
            .ok();
        Ok(value.filter(|s| !s.is_empty()))
    }

    fn forget(&self, id: &str) -> Result<bool> {
        // list/show print 🆔 with a # prefix; paste as-is — this entry strips #
        let id = id.trim_start_matches('#');
        let stamp = self.edit_stamp(id)?;
        // Prefix match: exact id first, else unique prefix (ambiguous → leave and report)
        let n = self.connection.execute(
            "UPDATE memories SET deleted = 1, updated_at = ?2, dirty = 1 WHERE id = ?1 AND deleted = 0",
            params![id, stamp],
        )?;
        if n > 0 {
            return Ok(true);
        }
        let mut hits: Vec<String> = Vec::new();
        {
            let mut stmt = self
                .connection
                .prepare("SELECT id FROM memories WHERE deleted = 0 AND id LIKE ?1 || '%'")?;
            let rows = stmt.query_map(params![id], |row| row.get::<_, String>(0))?;
            for r in rows {
                hits.push(r?);
            }
        }
        if hits.len() == 1 {
            let stamp = self.edit_stamp(&hits[0])?;
            let n = self.connection.execute(
                "UPDATE memories SET deleted = 1, updated_at = ?2, dirty = 1 WHERE id = ?1",
                params![hits[0], stamp],
            )?;
            return Ok(n > 0);
        }
        if hits.len() > 1 {
            eprintln!(
                "warning: prefix {} matches {} entries; use a longer id",
                id,
                hits.len()
            );
            return Ok(false);
        }
        Ok(false)
    }

    fn count(&self) -> Result<i64> {
        Ok(self.connection.query_row(
            "SELECT COUNT(*) FROM memories WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn sample(id: &str) -> StoredMemory {
        StoredMemory {
            id: id.to_owned(),
            user: "alice".to_owned(),
            ciphertext: "aabbcc".to_owned(),
            nonce: "112233".to_owned(),
            embedding_enc: String::new(),
            updated_at: "2026-09-02T00:00:00.000Z".to_owned(),
            deleted: false,
            local_kind: "context".to_owned(),
            local_tags: "rust,加密".to_owned(),
            local_title: "标题".to_owned(),
            local_project: "respire".to_owned(),
            local_computer: "pc1".to_owned(),
            local_embedding: Some(
                [0.1f32, 0.2, 0.3]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect(),
            ),
            local_parent_id: String::new(),
            local_created_at: "2026-09-02T00:00:00.000Z".to_owned(),
            local_content_head: "旧备份库关系边 演示内容".to_owned(),
            local_recall_count: 0,
            local_importance: "normal".to_owned(),
            local_device: "test-dev".to_owned(),
            local_chunks: Vec::new(),
            local_artifact: Vec::new(),
            local_modified_by: "test-dev".to_owned(),
        }
    }

    #[test]
    fn put_all_forget_lww() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;

        // put a new row
        assert!(MemoryTransport::put(&store, &sample("id-1"))?);
        assert_eq!(MemoryTransport::count(&store)?, 1);

        // LWW: an older version does not overwrite
        let mut stale = sample("id-1");
        stale.updated_at = "2026-01-01T00:00:00.000Z".to_owned();
        stale.local_title = "旧标题".to_owned();
        assert!(!MemoryTransport::put(&store, &stale)?);
        let all = MemoryTransport::all(&store, false)?;
        assert_eq!(all[0].local_title, "标题");

        // a newer version overwrites
        let mut fresh = sample("id-1");
        fresh.updated_at = "2026-09-03T00:00:00.000Z".to_owned();
        fresh.local_title = "新标题".to_owned();
        assert!(MemoryTransport::put(&store, &fresh)?);
        let all = MemoryTransport::all(&store, false)?;
        assert_eq!(all[0].local_title, "新标题");

        // tombstone: after forget, count=0, but all(true) still sees it
        assert!(MemoryTransport::forget(&store, "id-1")?);
        assert_eq!(MemoryTransport::count(&store)?, 0);
        assert!(MemoryTransport::all(&store, false)?.is_empty());
        assert_eq!(MemoryTransport::all(&store, true)?.len(), 1);

        // Legacy feature bytes are not returned through the public storage layer.
        let all = MemoryTransport::all(&store, true)?;
        assert!(all[0].local_embedding.is_none());
        Ok(())
    }

    #[test]
    fn max_updated_at_cursor() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        assert_eq!(MemoryTransport::max_updated_at(&store)?, None);
        let mut a = sample("a");
        a.updated_at = "2026-09-02T01:00:00.000Z".to_owned();
        MemoryTransport::put(&store, &a)?;
        let mut b = sample("b");
        b.updated_at = "2026-09-02T02:00:00.000Z".to_owned();
        MemoryTransport::put(&store, &b)?;
        assert_eq!(
            MemoryTransport::max_updated_at(&store)?.as_deref(),
            Some("2026-09-02T02:00:00.000Z")
        );
        Ok(())
    }

    #[test]
    fn v1_schema_is_preserved_and_requires_legacy_export() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("old.db");
        // The historical demo has a different KDF and encrypts content directly.
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "CREATE TABLE memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'context',
                tags TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                tag_hashes TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO memories(ciphertext,nonce,kind,tags,title,created_at,updated_at)
            VALUES ('original-ciphertext','original-nonce','context','legacy','original-title','created','updated');",
        )?;
        drop(conn);
        let error = LocalStore::open(&path)
            .err()
            .ok_or_else(|| anyhow::anyhow!("legacy demo was unexpectedly opened"))?;
        assert!(error
            .to_string()
            .contains("unsupported legacy memory schema"));
        let preserved = Connection::open(&path)?;
        let original: (i64, String, String, String) = preserved.query_row(
            "SELECT id,ciphertext,nonce,title FROM memories",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(
            original,
            (
                1,
                "original-ciphertext".to_owned(),
                "original-nonce".to_owned(),
                "original-title".to_owned()
            )
        );
        assert_eq!(
            preserved.query_row("SELECT COUNT(*) FROM memories", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        assert!(preserved
            .prepare("SELECT tag_hashes FROM memories")?
            .exists([])?);
        Ok(())
    }

    #[test]
    fn text_schema_adds_missing_indexes_without_changing_encrypted_rows() -> anyhow::Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE memories (
                id TEXT PRIMARY KEY, user TEXT NOT NULL, ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                title TEXT NOT NULL
            );
            INSERT INTO memories VALUES ('kept-id','kept-user','original-ciphertext','original-nonce','created','updated','kept-title');",
        )?;
        migrate(&connection)?;
        migrate(&connection)?;
        let kept: (String, String, String, String, String, String, String) = connection.query_row(
            "SELECT id,user,ciphertext,nonce,created_at,updated_at,title FROM memories",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?;
        assert_eq!(
            kept,
            (
                "kept-id".to_owned(),
                "kept-user".to_owned(),
                "original-ciphertext".to_owned(),
                "original-nonce".to_owned(),
                "created".to_owned(),
                "updated".to_owned(),
                "kept-title".to_owned()
            )
        );
        let derived: (String, Option<Vec<u8>>, i64) = connection.query_row(
            "SELECT embedding_enc,embedding,dirty FROM memories",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(derived, (String::new(), None, 1));
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM memories", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        Ok(())
    }

    #[test]
    fn schema_upgrade_rolls_back_if_existing_query_log_is_unsupported() -> anyhow::Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE memories (
                id TEXT PRIMARY KEY, user TEXT NOT NULL, ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            INSERT INTO memories VALUES ('kept-id','kept-user','original-ciphertext','original-nonce','created','updated');
            CREATE TABLE query_log (id INTEGER PRIMARY KEY, ts_unix INTEGER, hit_ids TEXT);",
        )?;
        assert!(migrate(&connection).is_err());
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(memories)")?
            .query_map([], |row| row.get(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert!(!columns.iter().any(|column| column == "embedding_enc"));
        let original: (String, String) =
            connection.query_row("SELECT ciphertext,nonce FROM memories", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        assert_eq!(
            original,
            (
                "original-ciphertext".to_owned(),
                "original-nonce".to_owned()
            )
        );
        assert!(connection.prepare("SELECT hit_ids FROM query_log").is_ok());
        Ok(())
    }

    #[test]
    fn causal_tree_children_parent_chain() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        // root A + child B + grandchild C (causal: A cause → B effect-and-cause → C effect)
        let mut a = sample("a");
        a.local_parent_id = String::new();
        MemoryTransport::put(&store, &a)?;
        let mut b = sample("b");
        b.local_parent_id = "a".to_owned();
        MemoryTransport::put(&store, &b)?;
        let mut c = sample("c");
        c.local_parent_id = "b".to_owned();
        MemoryTransport::put(&store, &c)?;
        // root/child/grandchild queries
        let roots = store.roots()?;
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "a");
        let kids_b = store.children("b")?;
        assert_eq!(kids_b.len(), 1);
        assert_eq!(kids_b[0].id, "c");
        // cause-chain walk (root first)
        let chain = store.ancestor_chain("c")?;
        assert_eq!(chain, vec!["a".to_owned(), "b".to_owned()]);
        // set_parent (demote/promote bottom): rehang B under root A (already under A) → same parent, no change;
        // hanging B under C should be allowed here (cycle check is command-layer); this only checks set_parent takes
        assert!(store.set_parent("b", "a")?);
        let chain_b = store.ancestor_chain("b")?;
        assert_eq!(chain_b, vec!["a".to_owned()]);
        // cycle evidence: ancestor_chain can be used by the command layer to refuse a descendant attach
        let chain_self = store.ancestor_chain("a")?;
        assert!(chain_self.is_empty());
        Ok(())
    }

    #[test]
    fn grant_create_list_snapshot_revoke() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        let root = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let mut m = sample(root);
        m.id = root.to_owned();
        MemoryTransport::put(&store, &m)?;
        let mut child = sample("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff");
        child.local_parent_id = root.to_owned();
        MemoryTransport::put(&store, &child)?;
        assert!(store.create_grant(root, "").is_err());
        assert!(store.create_grant("not-a-uuid", "lab").is_err());
        let (grant, token) = store.create_grant(root, "lab")?;
        assert_eq!(grant.label, "lab");
        assert_eq!(store.list_grants()?.len(), 1);
        let snap = store
            .grant_snapshot(&token)?
            .ok_or_else(|| anyhow::anyhow!("snapshot"))?;
        assert_eq!(snap.len(), 2);
        assert!(store.revoke_grant(&grant.id[..8])?);
        assert!(store.grant_snapshot(&token)?.is_none());
        assert!(!store.revoke_grant(&grant.id)?);
        Ok(())
    }
}

#[cfg(test)]
mod lww_tie_tests {
    use super::tests::sample;
    use super::*;

    /// A tie must not overwrite a local dirty row: after attach unpushed (dirty=1), a same-stamp pull must not wipe the attach.
    #[test]
    fn put_synced_tie_keeps_local_dirty() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        let mut m = sample("11111111-2222-3333-4444-555555555555");
        m.local_title = "旧".into();
        store.put(&m)?;

        // Local reparent (set_parent bumps updated_at and marks dirty)
        store.set_parent(&m.id, "p1")?;
        let local = store.all(false)?.remove(0);
        assert_eq!(local.local_parent_id, "p1");

        // Cloud pull of same id same updated_at with the old parent (reconcile tie)
        let mut remote = local.clone();
        remote.local_parent_id = String::new();
        let took = store.put_synced(&remote)?;
        assert!(!took, "tie + local dirty → pull must be refused");
        assert_eq!(store.all(false)?[0].local_parent_id, "p1");
        Ok(())
    }
}

use super::LocalStore;
use crate::{StoredMemory, transport::MemoryTransport};
use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

#[cfg(test)]
#[path = "resident_tests.rs"]
mod tests;

#[derive(Debug)]
pub struct MemorySourceChanged;
impl std::fmt::Display for MemorySourceChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("memory changed during preparation; retry from the latest version")
    }
}
impl std::error::Error for MemorySourceChanged {}

impl LocalStore {
    /// Acquire SQLite's writer only for source validation and durable commit.
    pub fn put_checked(&self, memory: &StoredMemory, expected_source: Option<&str>) -> Result<bool> {
        let tx = rusqlite::Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        let written = self.put_checked_inner(memory, expected_source)?;
        tx.commit()?;
        Ok(written)
    }

    fn put_checked_inner(&self, memory: &StoredMemory, expected_source: Option<&str>) -> Result<bool> {
        let current = self.connection.query_row("SELECT ciphertext,deleted FROM memories WHERE id=?1",
            [&memory.id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))).optional()?;
        let matches = match (expected_source, current.as_ref()) {
            (Some(expected), Some((current, false))) => expected == current,
            (None, None | Some((_, true))) => true,
            _ => false,
        };
        if !matches { return Err(MemorySourceChanged.into()); }
        self.put_inner(memory, true)
    }
    pub fn put_diary_checked(&self, memory: &StoredMemory, expected_source: &str,
        duplicates: &[&StoredMemory]) -> Result<bool> {
        let tx = rusqlite::Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        for duplicate in duplicates {
            let unchanged: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM memories WHERE id=?1 AND ciphertext=?2 AND deleted=0)",
                params![duplicate.id, duplicate.ciphertext], |row| row.get(0))?;
            if !unchanged { return Err(MemorySourceChanged.into()); }
        }
        let written = self.put_checked_inner(memory, Some(expected_source))?;
        if written { for duplicate in duplicates { self.forget(&duplicate.id)?; } }
        tx.commit()?;
        Ok(written)
    }

    pub fn library_identity(&self) -> Result<&str> {
        self.connection.path().context("resident retrieval requires a persistent library")
    }

    pub fn retrieval_revision(&self) -> Result<i64> {
        Ok(self.connection.query_row("SELECT revision FROM retrieval_revision WHERE singleton=1", [], |row| row.get(0))?)
    }

    /// The revision, source rows and artifacts come from one WAL read snapshot.
    pub fn retrieval_delta(&self, since: Option<i64>) -> Result<(i64, Vec<StoredMemory>, Vec<String>)> {
        let tx = self.connection.unchecked_transaction()?;
        let revision = self.retrieval_revision()?;
        let Some(since) = since else {
            let all = self.all(false)?;
            tx.commit()?;
            return Ok((revision, all, Vec::new()));
        };
        let ids = self.connection.prepare("SELECT memory_id FROM retrieval_changes WHERE revision>?1")?
            .query_map([since], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let generation = respire_core_sdk::generation_key(&self.retrieval_model()?)?;
        let mut changed = Vec::new();
        let mut removed = Vec::new();
        for id in ids {
            let memory = self.connection.query_row(
                "SELECT id,user,ciphertext,nonce,embedding_enc,updated_at,deleted,
                 kind,tags,title,project,computer,embedding,created_at,parent_id,content_head,recall_count,importance,device,modified_by
                 FROM memories WHERE id=?1 AND deleted=0", [&id], Self::row_to_memory).optional()?;
            if let Some(mut memory) = memory {
                memory.local_artifact = self.connection.query_row(
                    "SELECT artifact FROM core_artifacts WHERE memory_id=?1 AND model=?2 AND source=?3",
                    params![memory.id,generation,memory.ciphertext], |row| row.get(0)).optional()?.unwrap_or_default();
                changed.push(memory);
            } else { removed.push(id); }
        }
        tx.commit()?;
        Ok((revision, changed, removed))
    }
}

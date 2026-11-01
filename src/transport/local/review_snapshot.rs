//! One local read view for review candidates, their sources and the commit CAS.

use anyhow::Result;

use super::{LocalStore, MemoryTransport};

#[derive(Debug, Clone)]
pub struct ReviewSnapshot {
    pub memory_revision: String,
    pub memories: Vec<crate::StoredMemory>,
    pub unavailable_ids: Vec<String>,
}

impl LocalStore {
    /// Includes tombstones so Core can distinguish a deleted source from a live one.
    pub fn review_snapshot(&self) -> Result<ReviewSnapshot> {
        let transaction = self.connection.unchecked_transaction()?;
        let memory_revision = self.memory_revision()?;
        let memories = self.all(true)?;
        let unavailable_ids = {
            let mut statement = self.connection.prepare(
                "SELECT h.id FROM sync_remote_heads h LEFT JOIN sync_base b ON b.id=h.id
                 WHERE h.decode_error<>'' OR (
                   (b.rev IS NULL OR b.rev<h.rev) AND
                   CASE WHEN h.wire='' OR NOT json_valid(h.wire) THEN 1 ELSE NOT EXISTS(
                     SELECT 1 FROM memories m WHERE m.id=h.id
                       AND m.user IS json_extract(h.wire,'$.user')
                       AND m.ciphertext IS json_extract(h.wire,'$.ciphertext')
                       AND m.nonce IS json_extract(h.wire,'$.nonce')
                       AND m.updated_at IS json_extract(h.wire,'$.updated_at')
                       AND m.deleted IS json_extract(h.wire,'$.deleted')
                   ) END
                 ) ORDER BY h.id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        transaction.commit()?;
        Ok(ReviewSnapshot { memory_revision, memories, unavailable_ids })
    }
}

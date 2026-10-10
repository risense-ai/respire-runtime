use std::collections::HashSet;

use anyhow::{anyhow, bail, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::LocalStore;
use crate::memory::{crypto::random_hex, model::StoredMemory};
use crate::transport::MemoryTransport;

#[derive(Serialize)]
pub struct AccessGrant {
    pub id: String,
    pub label: String,
    pub root_id: String,
    pub created_at: String,
    pub revoked: bool,
}

fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

impl LocalStore {
    /// Token is returned only at creation; the grant binds a full root id, independent of default scope.
    pub fn create_grant(&self, root: &str, label: &str) -> Result<(AccessGrant, String)> {
        uuid::Uuid::parse_str(root)?;
        if label.trim().is_empty() || label.len() > 128 {
            bail!("grant label must be 1–128 bytes of non-empty text");
        }
        let transaction = rusqlite::Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        let exists = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM memories WHERE id = ?1 AND deleted = 0)",
            params![root], |row| row.get::<_, bool>(0),
        )?;
        if !exists { bail!("grant root does not exist or is deleted"); }
        let grant = AccessGrant {
            id: uuid::Uuid::new_v4().to_string(), label: label.to_owned(),
            root_id: root.to_owned(), created_at: chrono::Utc::now().to_rfc3339(),
            revoked: false,
        };
        let token = random_hex(32);
        self.connection.execute(
            "INSERT INTO access_grants(id,label,root_id,token_hash,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![grant.id, grant.label, grant.root_id, token_hash(&token), grant.created_at],
        )?;
        transaction.commit()?;
        Ok((grant, token))
    }

    pub fn list_grants(&self) -> Result<Vec<AccessGrant>> {
        let mut statement = self.connection.prepare(
            "SELECT id,label,root_id,created_at,revoked FROM access_grants ORDER BY created_at,id",
        )?;
        let grants = statement.query_map([], |row| Ok(AccessGrant {
            id: row.get(0)?, label: row.get(1)?, root_id: row.get(2)?,
            created_at: row.get(3)?, revoked: row.get(4)?,
        }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(grants)
    }

    pub fn revoke_grant(&self, id: &str) -> Result<bool> {
        // Full UUID or prefix (same short-id convention as attach/demote; fixed 2026-09-21 —
        // previously only a full UUID was accepted, so an 8-char short id raised `invalid length: found 8` with no guidance).
        let full = if uuid::Uuid::parse_str(id).is_ok() {
            id.to_owned()
        } else {
            let like = format!("{id}%");
            let mut statement = self.connection.prepare(
                "SELECT id FROM access_grants WHERE id LIKE ?1 AND revoked = 0",
            )?;
            let hits = statement
                .query_map(params![like], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            match hits.len() {
                0 => bail!("no such grant (or already revoked): {id} — run rsrs grant list"),
                1 => hits
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("grant prefix unique match missing id"))?,
                n => bail!("prefix {id} matches {n} grants; use a longer prefix"),
            }
        };
        Ok(self.connection.execute(
            "UPDATE access_grants SET revoked = 1 WHERE id = ?1 AND revoked = 0", params![full],
        )? != 0)
    }

    /// Auth and tree reads share one SQLite snapshot; missing root is refused, never expanded to the whole library.
    pub fn grant_snapshot(&self, token: &str) -> Result<Option<Vec<StoredMemory>>> {
        let transaction = self.connection.unchecked_transaction()?;
        let root: Option<String> = self.connection.query_row(
            "SELECT root_id FROM access_grants WHERE token_hash = ?1 AND revoked = 0",
            params![token_hash(token)], |row| row.get(0),
        ).optional()?;
        let Some(root) = root else { return Ok(None); };
        let mut all = self.all(false)?;
        if !all.iter().any(|entry| entry.id == root) { return Ok(None); }
        let mut members = HashSet::from([root]);
        loop {
            let before = members.len();
            for entry in &all {
                if members.contains(&entry.local_parent_id) { members.insert(entry.id.clone()); }
            }
            if members.len() == before { break; }
        }
        all.retain(|entry| members.contains(&entry.id));
        transaction.commit()?;
        Ok(Some(all))
    }
}

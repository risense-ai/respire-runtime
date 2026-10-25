//! Versioned canonical hash chain of accepted source mutations, not encryption
//! or an external trust anchor. SQLite triggers share the source transaction.
use super::LocalStore;
use anyhow::Result;
use rusqlite::{functions::FunctionFlags, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
fn hash(domain: &[u8], payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(payload);
    format!("{:x}", digest.finalize())
}
fn event_hash(
    library: &str,
    seq: i64,
    ts: &str,
    action: &str,
    id: &str,
    previous_id: &str,
    before: Option<&str>,
    after: Option<&str>,
    prev: &str,
) -> Result<String> {
    Ok(hash(
        b"rsrs:witness:event:v1\0",
        &serde_json::to_vec(&(
            1,
            library,
            seq,
            ts,
            action,
            id,
            previous_id,
            before,
            after,
            prev,
        ))?,
    ))
}

pub fn register_witness_functions(connection: &Connection) -> Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8
        | FunctionFlags::SQLITE_DETERMINISTIC
        | FunctionFlags::SQLITE_INNOCUOUS;
    connection.create_scalar_function("rsrs_witness_source_v1", 18, flags, |context| {
        let fields = (0..18)
            .map(|index| context.get::<Option<String>>(index))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let encoded = serde_json::to_vec(&fields)
            .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
        Ok(hash(b"rsrs:witness:source:v1\0", &encoded))
    })?;
    connection.create_scalar_function("rsrs_witness_event_v1", 9, flags, |context| {
        event_hash(
            &context.get::<String>(0)?,
            context.get(1)?,
            &context.get::<String>(2)?,
            &context.get::<String>(3)?,
            &context.get::<String>(4)?,
            &context.get::<String>(5)?,
            context.get::<Option<String>>(6)?.as_deref(),
            context.get::<Option<String>>(7)?.as_deref(),
            &context.get::<String>(8)?,
        )
        .map_err(|error| rusqlite::Error::UserFunctionError(error.into_boxed_dyn_error()))
    })?;
    Ok(())
}

pub(super) fn install(connection: &Connection) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO meta(key,value) VALUES('witness_library_id_v1',?1)",
        [uuid::Uuid::new_v4().simple().to_string()],
    )?;
    connection.execute_batch(include_str!("witness_schema.sql"))?;
    Ok(())
}

#[derive(Debug, serde::Serialize)]
pub struct WitnessReport {
    pub count: u64,
    pub intact: bool,
    pub broken_at: Option<i64>,
    pub head: String,
    pub reason: Option<String>,
}
impl LocalStore {
    /// Pure local verification. A rewritten whole chain, removed tail or database
    /// rollback is not detectable without an independently retained checkpoint.
    pub fn witness_verify(&self) -> Result<WitnessReport> {
        let transaction = self
            .connection
            .is_autocommit()
            .then(|| self.connection.unchecked_transaction())
            .transpose()?;
        let library: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key='witness_library_id_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let library =
            library.ok_or_else(|| anyhow::anyhow!("witness schema is not initialized"))?;
        let mut statement=self.connection.prepare("SELECT schema_version,library_id,seq,ts,action,entry_id,previous_entry_id,before_digest,after_digest,prev,hash FROM witness_log ORDER BY seq")?;
        let mut rows = statement.query([])?;
        let mut report = WitnessReport {
            count: 0,
            intact: true,
            broken_at: None,
            head: ZERO.to_owned(),
            reason: None,
        };
        while let Some(row) = rows.next()? {
            let version: i64 = row.get(0)?;
            let row_library: String = row.get(1)?;
            let seq: i64 = row.get(2)?;
            let ts: String = row.get(3)?;
            let action: String = row.get(4)?;
            let id: String = row.get(5)?;
            let previous_id: String = row.get(6)?;
            let before: Option<String> = row.get(7)?;
            let after: Option<String> = row.get(8)?;
            let prev: String = row.get(9)?;
            let stored: String = row.get(10)?;
            let expected = event_hash(
                &row_library,
                seq,
                &ts,
                &action,
                &id,
                &previous_id,
                before.as_deref(),
                after.as_deref(),
                &prev,
            )?;
            let failure = if version != 1 || row_library != library {
                Some("schema or library identity mismatch")
            } else if seq != report.count as i64 + 1 {
                Some("sequence gap or reordering")
            } else if prev != report.head {
                Some("previous hash mismatch")
            } else if stored != expected {
                Some("event digest mismatch")
            } else {
                None
            };
            if let Some(reason) = failure {
                report.intact = false;
                report.broken_at = Some(if seq != report.count as i64 + 1 {
                    report.count as i64 + 1
                } else {
                    seq
                });
                report.reason = Some(reason.into());
                break;
            }
            report.count += 1;
            report.head = stored;
        }
        drop(rows);
        drop(statement);
        if let Some(transaction) = transaction {
            transaction.commit()?;
        }
        Ok(report)
    }
}

/// Inspect a snapshot without migrating it or reconfiguring Core index roots.
pub fn witness_checkpoint_file(path: &std::path::Path) -> Result<Option<WitnessReport>> {
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    let store = LocalStore { connection };
    let transaction = store.connection.unchecked_transaction()?;
    let present: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='witness_log')",
        [],
        |row| row.get(0),
    )?;
    let report = if present {
        Some(store.witness_verify()?)
    } else {
        None
    };
    transaction.commit()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MemoryTransport;
    fn fixture() -> Result<(tempfile::TempDir, LocalStore)> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("rsrs.db"))?;
        Ok((dir, store))
    }
    fn sample(id: &str) -> crate::memory::model::StoredMemory {
        super::super::tests::sample(id)
    }
    #[test]
    fn accepted_mutations_are_chained_and_lww_rejection_has_no_event() -> Result<()> {
        let (_dir, store) = fixture()?;
        let mut item = sample("source");
        assert!(store.put(&item)?);
        assert_eq!(store.witness_verify()?.count, 1);
        assert!(!store.put(&item)?);
        assert_eq!(store.witness_verify()?.count, 1);
        item.updated_at = "2026-09-03T00:00:00Z".into();
        item.local_parent_id = "parent".into();
        assert!(store.put_synced(&item)?);
        assert!(store.forget("sour")?);
        store.purge_content("source")?;
        store
            .connection
            .execute("DELETE FROM memories WHERE id='source'", [])?;
        let report = store.witness_verify()?;
        assert!(report.intact);
        assert_eq!(report.count, 5);
        let actions = store
            .connection
            .prepare("SELECT action FROM witness_log ORDER BY seq")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(actions, ["create", "attach", "tombstone", "purge", "prune"]);
        Ok(())
    }
    #[test]
    fn transaction_failure_rolls_back_both_source_and_witness() -> Result<()> {
        let (_dir, store) = fixture()?;
        let failure = store.write_transaction(|| -> Result<()> {
            store.put(&sample("rollback"))?;
            anyhow::bail!("synthetic transaction abort")
        });
        assert!(failure.is_err());
        assert_eq!(store.count()?, 0);
        assert_eq!(store.witness_verify()?.count, 0);
        // Failure after trigger execution is rolled back with its SQL statement.
        store.connection.execute_batch("CREATE TRIGGER synthetic_abort AFTER INSERT ON memories BEGIN SELECT RAISE(ABORT,'synthetic rejection'); END;")?;
        assert!(store.put(&sample("rejected")).is_err());
        assert_eq!(store.witness_verify()?.count, 0);
        assert_eq!(store.count()?, 0);
        Ok(())
    }
    #[test]
    fn tamper_middle_delete_and_reordering_identify_the_break() -> Result<()> {
        for mutation in [
            "UPDATE witness_log SET after_digest='tampered' WHERE seq=2",
            "DELETE FROM witness_log WHERE seq=2",
            "UPDATE witness_log SET seq=20 WHERE seq=2",
        ] {
            let (_dir, store) = fixture()?;
            for id in ["one", "two", "three"] {
                assert!(store.put(&sample(id))?);
            }
            store.connection.execute_batch(mutation)?;
            let report = store.witness_verify()?;
            assert!(!report.intact);
            assert_eq!(report.broken_at, Some(2), "{mutation}");
        }
        Ok(())
    }
    #[test]
    fn metadata_binding_and_no_plaintext_body_in_ledger() -> Result<()> {
        let (_dir, store) = fixture()?;
        let mut item = sample("opaque-id");
        item.ciphertext = "synthetic-sealed-ciphertext-marker".into();
        item.nonce = "synthetic-nonce-marker".into();
        item.local_title = "synthetic private title".into();
        item.local_content_head = "synthetic private body".into();
        assert!(store.put(&item)?);
        let record:String=store.connection.query_row("SELECT group_concat(schema_version||library_id||seq||ts||action||entry_id||previous_entry_id||coalesce(before_digest,'')||coalesce(after_digest,'')||prev||hash) FROM witness_log",[],|row|row.get(0))?;
        for text in [
            &item.local_title,
            &item.local_content_head,
            &item.ciphertext,
            &item.nonce,
        ] {
            assert!(!record.contains(text));
        }
        store.connection.execute(
            "UPDATE meta SET value='different-library' WHERE key='witness_library_id_v1'",
            [],
        )?;
        assert!(!store.witness_verify()?.intact);
        Ok(())
    }
    #[test]
    fn independent_connections_serialize_sequence_and_verify_readonly() -> Result<()> {
        let (dir, store) = fixture()?;
        let path = dir.path().join("rsrs.db");
        drop(store);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let mut threads = Vec::new();
        for index in 0..4 {
            let store = LocalStore::open(&path)?;
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || -> Result<()> {
                barrier.wait();
                for offset in 0..10 {
                    store.put(&sample(&format!("{index}-{offset}")))?;
                }
                Ok(())
            }));
        }
        for thread in threads {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("witness writer panicked"))??;
        }
        let readonly = LocalStore::open_read_only(&path)?;
        let report = readonly.witness_verify()?;
        assert!(report.intact);
        assert_eq!(report.count, 40);
        Ok(())
    }
    #[test]
    fn read_counters_and_dirty_acknowledgments_do_not_append_events() -> Result<()> {
        let (_dir, store) = fixture()?;
        store.put(&sample("one"))?;
        store.connection.execute_batch("UPDATE memories SET recall_count=recall_count+1,dirty=0; UPDATE memories SET ciphertext=ciphertext;")?;
        assert_eq!(store.witness_verify()?.count, 1);
        Ok(())
    }
}

//! O(1), read-only snapshot token lookup. No Core index, keys, model, or row scan.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

/// Probe only an already-initialized database; never create or migrate a library.
/// Do not use SQLite immutable mode: a live runtime's committed WAL must be visible.
pub fn read_memory_revision(path: &Path) -> Result<String> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("memory revision unavailable: open the library normally to initialize it")?;
    connection.busy_timeout(Duration::from_secs(1))?;
    read_revision(&connection)
}

fn read_revision(connection: &Connection) -> Result<String> {
    let revision: String = connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'memory_revision_v1'",
            [],
            |row| row.get(0),
        )
        .context("memory revision unavailable: open the library normally to upgrade its schema")?;
    anyhow::ensure!(
        revision.len() == 32
            && revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "memory revision unavailable: invalid snapshot token"
    );
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::super::{migrate, LocalStore};
    use super::*;
    use crate::transport::MemoryTransport;

    fn initialized(connection: Connection) -> Result<LocalStore> {
        migrate(&connection)?;
        connection.execute_batch(include_str!("sync_schema.sql"))?;
        Ok(LocalStore { connection })
    }

    #[test]
    fn revision_legacy_initialization_is_atomic_and_idempotent() -> Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE memories (
                id TEXT PRIMARY KEY, user TEXT, ciphertext TEXT, nonce TEXT,
                created_at TEXT, updated_at TEXT
            );
            INSERT INTO memories VALUES ('old','owner','sealed','nonce','created','updated');",
        )?;
        migrate(&connection)?;
        let revision = read_revision(&connection)?;
        let changes = connection.total_changes();
        migrate(&connection)?;
        assert_eq!(read_revision(&connection)?, revision);
        assert_eq!(connection.total_changes(), changes);
        let preserved: (String, String, String, String) = connection.query_row(
            "SELECT ciphertext,nonce,created_at,updated_at FROM memories WHERE id='old'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        assert_eq!(
            preserved,
            (
                "sealed".into(),
                "nonce".into(),
                "created".into(),
                "updated".into()
            )
        );
        // Unsupported legacy data must not gain a misleading initialized token.
        let unsupported = Connection::open_in_memory()?;
        unsupported.execute_batch("CREATE TABLE memories (id INTEGER PRIMARY KEY);")?;
        assert!(migrate(&unsupported).is_err());
        assert_eq!(unsupported.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('meta','memory_revision_insert')",
            [], |r| r.get::<_, i64>(0),
        )?, 0);
        Ok(())
    }

    #[test]
    fn revision_tracks_each_memory_field_and_null_transitions() -> Result<()> {
        let store = initialized(Connection::open_in_memory()?)?;
        let conn = &store.connection;
        let mut before = read_revision(conn)?;
        conn.execute("INSERT INTO memories(id,dirty) VALUES ('a',0)", [])?;
        assert_ne!(read_revision(conn)?, before);
        // Dirty, recall_count, embedding and embedding_enc deliberately excluded.
        for column in [
            "user",
            "ciphertext",
            "nonce",
            "created_at",
            "updated_at",
            "kind",
            "tags",
            "title",
            "project",
            "computer",
            "parent_id",
            "content_head",
            "importance",
            "device",
            "modified_by",
        ] {
            before = read_revision(conn)?;
            conn.execute(
                &format!("UPDATE memories SET {column}='changed' WHERE id='a'"),
                [],
            )?;
            assert_ne!(read_revision(conn)?, before, "missing column {column}");
        }
        before = read_revision(conn)?;
        conn.execute("UPDATE memories SET id='renamed' WHERE id='a'", [])?;
        assert_ne!(read_revision(conn)?, before);
        // Nullable columns are permitted in supported historical TEXT-ID schemas.
        let legacy = Connection::open_in_memory()?;
        legacy.execute_batch("CREATE TABLE memories (id TEXT PRIMARY KEY,user TEXT,ciphertext TEXT,nonce TEXT,created_at TEXT,updated_at TEXT);
            INSERT INTO memories VALUES ('a',NULL,NULL,NULL,NULL,NULL);")?;
        migrate(&legacy)?;
        before = read_revision(&legacy)?;
        legacy.execute("UPDATE memories SET ciphertext='sealed' WHERE id='a'", [])?;
        assert_ne!(read_revision(&legacy)?, before);
        before = read_revision(&legacy)?;
        legacy.execute("UPDATE memories SET ciphertext=NULL WHERE id='a'", [])?;
        assert_ne!(read_revision(&legacy)?, before);
        Ok(())
    }

    #[test]
    fn revision_tracks_tombstone_restore_purge_and_clear() -> Result<()> {
        let store = initialized(Connection::open_in_memory()?)?;
        let conn = &store.connection;
        conn.execute_batch("INSERT INTO memories(id,dirty) VALUES ('a',0),('b',0);")?;
        for sql in [
            "UPDATE memories SET deleted=1 WHERE id='a'",
            "UPDATE memories SET deleted=0 WHERE id='a'",
            "DELETE FROM memories WHERE id='a'",
            "DELETE FROM memories",
        ] {
            let before = read_revision(conn)?;
            conn.execute_batch(sql)?;
            assert_ne!(read_revision(conn)?, before, "missed {sql}");
        }
        let before = read_revision(conn)?;
        conn.execute_batch("DELETE FROM memories")?;
        assert_eq!(
            read_revision(conn)?,
            before,
            "clearing an empty store is a no-op"
        );
        Ok(())
    }

    #[test]
    fn revision_catches_same_count_historical_sync_without_changing_outbox() -> Result<()> {
        let store = initialized(Connection::open_in_memory()?)?;
        let mut historical = super::super::tests::sample("historical");
        let mut newest = super::super::tests::sample("newest");
        newest.updated_at = "2026-10-04T00:00:00.000Z".into();
        store.put_inner(&historical, false)?;
        store.put_inner(&newest, false)?;
        let count = store.count()?;
        let max = store.max_updated_at()?;
        let before = read_revision(&store.connection)?;
        historical.ciphertext = "new encrypted content".into();
        historical.updated_at = "2026-09-03T00:00:00.000Z".into();
        assert!(store.put_inner(&historical, false)?);
        assert_ne!(read_revision(&store.connection)?, before);
        assert_eq!(store.count()?, count);
        assert_eq!(store.max_updated_at()?, max);
        // Authoritative revision-log sync can replace a row with an older timestamp.
        let before = read_revision(&store.connection)?;
        historical.updated_at = "2026-01-01T00:00:00.000Z".into();
        assert!(store.put_inner_policy(&historical, false, true)?);
        assert_ne!(read_revision(&store.connection)?, before);
        assert_eq!(store.count()?, count);
        assert_eq!(store.max_updated_at()?, max);
        assert!(store.outgoing()?.is_empty());
        Ok(())
    }

    #[test]
    fn revision_reads_noops_and_bookkeeping_do_not_invalidate() -> Result<()> {
        let store = initialized(Connection::open_in_memory()?)?;
        let memory = super::super::tests::sample("a");
        store.put_inner(&memory, false)?;
        let before = read_revision(&store.connection)?;
        let changes = store.connection.total_changes();
        for _ in 0..3 {
            assert_eq!(read_revision(&store.connection)?, before);
            let _ = store.all(true)?;
            let _ = store.count()?;
            let _ = store.max_updated_at()?;
        }
        assert_eq!(store.connection.total_changes(), changes);
        assert!(store.put_inner(&memory, false)?);
        store.clear_dirty("a")?;
        store.bump_recall(&["a".into()])?;
        store.connection.execute_batch(
            "UPDATE memories SET title=title,ciphertext=ciphertext;
            UPDATE memories SET embedding=x'0102',embedding_enc='derived';
            INSERT INTO meta(key,value) VALUES ('sync_v2_cursor','123');",
        )?;
        assert_eq!(read_revision(&store.connection)?, before);
        // A real local save still creates exactly the same outgoing version.
        let mut updated = memory;
        updated.ciphertext = "edited ciphertext".into();
        updated.updated_at = "2026-10-04T00:00:00.000Z".into();
        store.put(&updated)?;
        assert_ne!(read_revision(&store.connection)?, before);
        let outgoing = store.outgoing()?;
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].blob.ciphertext, updated.ciphertext);
        assert_eq!(outgoing[0].blob.nonce, updated.nonce);
        assert_eq!(outgoing[0].blob.updated_at, updated.updated_at);
        Ok(())
    }

    #[test]
    fn revision_rolls_back_with_failed_mutation_and_import() -> Result<()> {
        let store = initialized(Connection::open_in_memory()?)?;
        let mut existing = super::super::tests::sample("existing");
        existing.updated_at = "2026-10-04T00:00:00.000Z".into();
        store.put(&existing)?;
        let before = read_revision(&store.connection)?;
        let count = store.count()?;
        assert!(store
            .import_batch(&[
                super::super::tests::sample("inserted-before-conflict"),
                super::super::tests::sample("existing"),
            ])
            .is_err());
        assert_eq!(read_revision(&store.connection)?, before);
        assert_eq!(store.count()?, count);
        store.import_batch(&[super::super::tests::sample("successful-import")])?;
        assert_ne!(read_revision(&store.connection)?, before);
        let before = read_revision(&store.connection)?;
        store
            .connection
            .execute_batch("BEGIN; UPDATE memories SET title='rolled back'; ROLLBACK;")?;
        assert_eq!(read_revision(&store.connection)?, before);
        Ok(())
    }

    #[test]
    fn revision_read_only_probe_observes_committed_wal_without_initialization() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("onememory.db");
        assert!(read_memory_revision(&path).is_err());
        assert!(!path.exists());
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        assert!(read_memory_revision(&path).is_err());
        let store = initialized(conn)?;
        let before = read_memory_revision(&path)?;
        let changes = store.connection.total_changes();
        for _ in 0..3 {
            assert_eq!(read_memory_revision(&path)?, before);
        }
        assert_eq!(store.connection.total_changes(), changes);
        store
            .connection
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO memories(id,dirty) VALUES ('a',0);")?;
        assert_eq!(
            read_memory_revision(&path)?,
            before,
            "uncommitted writes are invisible"
        );
        store.connection.execute_batch("COMMIT;")?;
        assert_ne!(read_memory_revision(&path)?, before);
        drop(store);
        let previous = read_memory_revision(&path)?;
        std::fs::remove_file(&path)?;
        let _replacement = initialized(Connection::open(&path)?)?;
        assert_ne!(
            read_memory_revision(&path)?,
            previous,
            "replacement DB needs a fresh identity"
        );
        Ok(())
    }
}

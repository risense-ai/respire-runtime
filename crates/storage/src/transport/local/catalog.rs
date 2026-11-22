//! Catalog counts and materialization deliberately share the same row decoder.

use anyhow::Result;
use rusqlite::types::{FromSql, FromSqlResult, ValueRef};
use rusqlite::{Row, Statement};

use super::LocalStore;
use crate::memory::model::StoredMemory;

struct CheckedText;

impl FromSql for CheckedText {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        // Use exactly the SQLite conversion underlying FromSql for String.
        value.as_str().map(|_| Self)
    }
}

struct MemoryColumns<Text> {
    id: Text,
    user: Text,
    ciphertext: Text,
    nonce: Text,
    embedding_enc: Text,
    updated_at: Text,
    deleted: bool,
    kind: Text,
    tags: Text,
    title: Text,
    project: Text,
    computer: Text,
    parent_id: Text,
    created_at: Text,
    content_head: Text,
    recall_count: i64,
    importance: Option<Text>,
    device: Option<Text>,
    modified_by: Option<Text>,
    metadata: respire_protocol::MemoryMeta,
}

impl<Text: FromSql> MemoryColumns<Text> {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            user: row.get(1)?,
            ciphertext: row.get(2)?,
            nonce: row.get(3)?,
            embedding_enc: row.get(4)?,
            updated_at: row.get(5)?,
            deleted: row.get::<_, i64>(6)? != 0,
            kind: row.get(7)?,
            tags: row.get(8)?,
            title: row.get(9)?,
            project: row.get(10)?,
            computer: row.get(11)?,
            parent_id: row.get(14)?,
            created_at: row.get(13)?,
            content_head: row.get(15)?,
            recall_count: row.get(16)?,
            importance: row.get(17).ok(),
            device: row.get(18).ok(),
            modified_by: row.get(19).ok(),
            metadata: respire_protocol::MemoryMeta {
                memory_contract: row.get(20)?,
                summary: row.get(21)?,
                source_refs: json_column(row, 22)?,
                valid_until: row.get(23)?,
                review_at: row.get(24)?,
                artifact: json_column(row, 25)?,
                verification: json_column(row, 26)?,
            },
        })
    }
}

impl From<MemoryColumns<String>> for StoredMemory {
    fn from(row: MemoryColumns<String>) -> Self {
        Self {
            id: row.id,
            user: row.user,
            ciphertext: row.ciphertext,
            nonce: row.nonce,
            embedding_enc: row.embedding_enc,
            updated_at: row.updated_at,
            deleted: row.deleted,
            local_kind: row.kind,
            local_tags: row.tags,
            local_title: row.title,
            local_project: row.project,
            local_computer: row.computer,
            local_embedding: None,
            local_parent_id: row.parent_id,
            local_created_at: row.created_at,
            local_content_head: row.content_head,
            local_recall_count: row.recall_count,
            local_importance: row.importance.unwrap_or_else(|| "normal".to_owned()),
            local_device: row.device.unwrap_or_default(),
            local_modified_by: row.modified_by.unwrap_or_default(),
            local_chunks: Vec::new(),
            local_artifact: Vec::new(),
            local_meta: row.metadata,
        }
    }
}

fn json_column<T: serde::de::DeserializeOwned>(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<T> {
    let text: String = row.get(column)?;
    serde_json::from_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

impl LocalStore {
    pub(super) fn row_to_memory(row: &Row<'_>) -> rusqlite::Result<StoredMemory> {
        MemoryColumns::<String>::read(row).map(Into::into)
    }

    /// Validate what a full catalog read would accept, without collecting
    /// ciphertext, materialized memories, or opaque retrieval bytes.
    pub fn catalog_counts(&self) -> Result<(usize, usize)> {
        let mut statement = self.catalog_statement(true)?;
        let rows = statement.query_map([], |row| {
            Ok(!MemoryColumns::<CheckedText>::read(row)?.deleted)
        })?;
        let mut total = 0;
        let mut alive = 0;
        for row in rows {
            alive += usize::from(row?);
            total += 1;
        }
        // Catalog decoding has always taken precedence over locator errors.
        self.visit_retrieval_index(|_, _, _| {})?;
        Ok((total, alive))
    }

    pub(super) fn catalog_statement(
        &self,
        include_deleted: bool,
    ) -> rusqlite::Result<Statement<'_>> {
        let sql = if include_deleted {
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by,
                 memory_contract, summary, source_refs, valid_until, review_at, COALESCE(artifact,'null'), COALESCE(verification,'null')
             FROM memories"
        } else {
            "SELECT id, user, ciphertext, nonce, embedding_enc, updated_at, deleted,
                 kind, tags, title, project, computer, embedding, created_at, parent_id, content_head, recall_count, importance, device, modified_by,
                 memory_contract, summary, source_refs, valid_until, review_at, COALESCE(artifact,'null'), COALESCE(verification,'null')
             FROM memories WHERE deleted = 0"
        };
        self.connection.prepare(sql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MemoryTransport;
    use rusqlite::params;

    fn count_full(store: &LocalStore) -> Result<(usize, usize)> {
        let rows = store.all(true)?;
        Ok((rows.len(), rows.iter().filter(|row| !row.deleted).count()))
    }

    fn same_catalog_error(store: &LocalStore, expected: impl FnOnce(&rusqlite::Error) -> bool) {
        let Err(old) = count_full(store) else {
            panic!("full catalog unexpectedly accepted the fixture");
        };
        let Err(new) = store.catalog_counts() else {
            panic!("streaming catalog unexpectedly accepted the fixture");
        };
        let Some(old_sql) = old.downcast_ref::<rusqlite::Error>() else {
            panic!("full catalog returned a non-SQLite error: {old:#}");
        };
        let Some(new_sql) = new.downcast_ref::<rusqlite::Error>() else {
            panic!("streaming catalog returned a non-SQLite error: {new:#}");
        };
        assert!(expected(old_sql), "unexpected baseline error: {old:#}");
        assert_eq!(format!("{old:#}"), format!("{new:#}"));
        assert_eq!(format!("{old_sql:?}"), format!("{new_sql:?}"));
    }

    #[test]
    fn checked_text_matches_string_type_and_utf8_errors() -> Result<()> {
        let connection = rusqlite::Connection::open_in_memory()?;
        let mut statement = connection.prepare(
            "SELECT '' AS empty, 'sample' AS valid, CAST(x'ff' AS TEXT) AS malformed,
             x'ff' AS blob, 9 AS number, NULL AS missing",
        )?;
        let mut rows = statement.query([])?;
        let Some(row) = rows.next()? else {
            panic!("projection fixture returned no row");
        };
        for column in 0..6 {
            let string = row.get::<_, String>(column).map(|_| ());
            let checked = row.get::<_, CheckedText>(column).map(|_| ());
            assert_eq!(format!("{string:?}"), format!("{checked:?}"));
        }
        Ok(())
    }

    #[test]
    fn counts_keep_tombstones_and_library_scope_without_requiring_artifacts() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let store = LocalStore::open(&temporary.path().join("first/db.sqlite"))?;
        let other = LocalStore::open(&temporary.path().join("second/db.sqlite"))?;
        assert_eq!(store.catalog_counts()?, count_full(&store)?);
        assert_eq!(store.catalog_counts()?, (0, 0));
        store.connection.execute_batch(
            "INSERT INTO memories(id,user,updated_at,deleted) VALUES
             ('live','first-account','2026-11-21T11:00:00Z',0),
             ('deleted','first-account','2026-11-22T11:00:00Z',1),
             ('empty-date','first-account','',0);",
        )?;
        other.connection.execute(
            "INSERT INTO memories(id,user,updated_at,deleted) VALUES ('alone','second-account','',0)",
            [],
        )?;
        assert_eq!(store.catalog_counts()?, count_full(&store)?);
        assert_eq!(other.catalog_counts()?, count_full(&other)?);
        assert_eq!(store.catalog_counts()?, (3, 2));
        assert_eq!(other.catalog_counts()?, (1, 1));
        assert_eq!(
            store.max_updated_at()?.as_deref(),
            Some("2026-11-22T11:00:00Z")
        );
        assert_eq!(other.max_updated_at()?, None);
        Ok(())
    }

    #[test]
    fn counts_preserve_row_and_metadata_errors_before_current_artifacts() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let store = LocalStore::open(&temporary.path().join("db.sqlite"))?;
        let generation = store.active_generation_key()?;
        store.meta_set("memory_metadata_v1_enabled", "1")?;
        store.connection.execute_batch(
            "INSERT INTO memories(id,ciphertext) VALUES ('live','sealed-fixture'),('tombstone','deleted-fixture');
             UPDATE memories SET deleted=1 WHERE id='tombstone';",
        )?;
        store.connection.execute(
            "INSERT INTO core_artifacts(memory_id,model,source,artifact)
             VALUES ('live',?1,'sealed-fixture','invalid SQL type')",
            [&generation],
        )?;
        store.connection.execute(
            "UPDATE memories SET recall_count=x'ffff6f' WHERE id='tombstone'",
            [],
        )?;
        same_catalog_error(
            &store,
            |error| matches!(error, rusqlite::Error::InvalidColumnType(16, name, rusqlite::types::Type::Blob) if name == "recall_count"),
        );
        store.connection.execute(
            "UPDATE memories SET recall_count=0,summary=CAST(x'ff' AS TEXT) WHERE id='tombstone'",
            [],
        )?;
        same_catalog_error(&store, |error| {
            matches!(
                error,
                rusqlite::Error::FromSqlConversionFailure(21, rusqlite::types::Type::Text, _)
            )
        });
        store.connection.execute(
            "UPDATE memories SET summary=NULL,source_refs='{\"wrong\":\"typed JSON\"}' WHERE id='tombstone'",
            [],
        )?;
        same_catalog_error(&store, |error| {
            matches!(
                error,
                rusqlite::Error::FromSqlConversionFailure(22, rusqlite::types::Type::Text, _)
            )
        });
        store.connection.execute(
            "UPDATE memories SET source_refs='[]' WHERE id='tombstone'",
            [],
        )?;
        same_catalog_error(
            &store,
            |error| matches!(error, rusqlite::Error::InvalidColumnType(2, name, rusqlite::types::Type::Text) if name == "artifact"),
        );
        Ok(())
    }

    #[test]
    fn opaque_artifacts_are_checked_only_at_the_active_source_join() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let store = LocalStore::open(&temporary.path().join("db.sqlite"))?;
        let generation = store.active_generation_key()?;
        store.connection.execute_batch(
            "INSERT INTO memories(id,ciphertext,deleted) VALUES
             ('live','sealed-fixture',0),('deleted','deleted-fixture',1),('changed','current-fixture',0);",
        )?;
        store.connection.execute(
            "INSERT INTO core_artifacts(memory_id,model,source,artifact) VALUES
             ('live',?1,'sealed-fixture',x'ff0001'),
             ('deleted',?1,'deleted-fixture','bad deleted locator type'),
             ('changed',?1,'old-fixture','bad stale locator type'),
             ('live','inactive-generation','sealed-fixture','bad inactive locator type'),
             ('missing',?1,'unmatched-fixture','bad absent locator type')",
            params![generation],
        )?;
        assert_eq!(store.catalog_counts()?, count_full(&store)?);
        assert_eq!(store.catalog_counts()?, (3, 2));
        let rows = store.all(true)?;
        let live = rows.iter().find(|row| row.id == "live");
        assert_eq!(
            live.map(|row| row.local_artifact.as_slice()),
            Some([255, 0, 1].as_slice())
        );
        assert!(rows
            .iter()
            .filter(|row| row.id != "live")
            .all(|row| row.local_artifact.is_empty()));

        store.connection.execute(
            "UPDATE core_artifacts SET source='current-fixture' WHERE memory_id='changed'",
            [],
        )?;
        same_catalog_error(
            &store,
            |error| matches!(error, rusqlite::Error::InvalidColumnType(2, name, rusqlite::types::Type::Text) if name == "artifact"),
        );
        Ok(())
    }
}

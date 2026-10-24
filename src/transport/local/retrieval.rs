//! Resumable, source-checked local retrieval index generations.

use super::LocalStore;
use crate::transport::MemoryTransport;
use anyhow::Result;
use rusqlite::{params, OptionalExtension};

fn generation_key(model: &str) -> Result<String> { respire_core_sdk::generation_key(model) }

#[derive(Debug)]
pub struct IndexSourceChanged {
    pub pending: i64,
}

impl std::fmt::Display for IndexSourceChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "index source changed during rebuild; rerun to resume ({} pending)", self.pending)
    }
}

impl std::error::Error for IndexSourceChanged {}

impl LocalStore {
    // Only production caller: LocalStore::all. Its SELECT reads the memories
    // primary key, so out has unique IDs. On any error all discards the entire
    // output Vec; this helper does not promise rollback for an arbitrary slice.
    pub(super) fn attach_retrieval_index(
        &self,
        out: &mut [crate::memory::model::StoredMemory],
    ) -> Result<()> {
        let model = self.retrieval_model()?;
        let mut stmt = self.connection.prepare(
            "SELECT a.memory_id,a.source,a.artifact FROM core_artifacts a
             JOIN memories m ON m.id=a.memory_id AND m.ciphertext=a.source
             WHERE a.model=?1 AND m.deleted=0",
        )?;
        // Keep only the small ID lookup. Collecting every source ciphertext and
        // artifact first duplicates the entire encrypted catalog at peak.
        let positions: std::collections::HashMap<String, usize> = out.iter()
            .enumerate().map(|(index, memory)| (memory.id.clone(), index)).collect();
        debug_assert_eq!(positions.len(), out.len(), "catalog IDs must be unique");
        let mut rows = stmt.query(params![generation_key(&model)?])?;
        while let Some(row) = rows.next()? {
            let id = row.get_ref(0)?.as_str()?;
            let source = row.get_ref(1)?.as_str()?;
            // Preserve the previous collect's decoding errors even if this row
            // is absent from, or no longer matches, the supplied snapshot.
            let artifact: Vec<u8> = row.get(2)?;
            if let Some(&index) = positions.get(id) {
                let memory = &mut out[index];
                // The SQL join checks the database source; this check also
                // protects a supplied snapshot from a newer database source.
                if memory.ciphertext == source {
                    memory.local_artifact = artifact;
                }
            }
        }
        Ok(())
    }

    pub(super) fn store_artifact(&self, memory: &crate::StoredMemory, model: &str) -> Result<()> {
        let generation = generation_key(model)?;
        // The source guard also protects a newer artifact from an older prepared snapshot.
        self.connection.execute_batch("SAVEPOINT core_artifact_publish")?;
        let result = (|| -> Result<()> {
            self.connection.execute(
                "DELETE FROM core_artifacts WHERE memory_id=?1 AND (source<>?2 OR ?3=1)
                 AND EXISTS(SELECT 1 FROM memories m WHERE m.id=?1 AND m.ciphertext=?2 AND m.deleted=?3)",
                params![memory.id, memory.ciphertext, memory.deleted as i64],
            )?;
            if !memory.deleted && !memory.local_artifact.is_empty() {
                self.connection.execute(
                    "INSERT OR REPLACE INTO core_artifacts(memory_id,model,source,artifact)
                     SELECT id,?2,ciphertext,?4 FROM memories WHERE id=?1 AND ciphertext=?3 AND deleted=0",
                    params![memory.id, generation, memory.ciphertext, memory.local_artifact],
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.connection.execute_batch("ROLLBACK TO core_artifact_publish")?;
        }
        self.connection.execute_batch("RELEASE core_artifact_publish")?;
        result
    }

    /// Check the actual candidate snapshot before semantic retrieval, without a separate database read.
    pub fn candidates_index_ready(&self, candidates: &[crate::StoredMemory]) -> Result<bool> {
        let mut artifacts = Vec::new();
        for memory in candidates.iter().filter(|memory| !memory.deleted) {
            if memory.local_artifact.is_empty() {
                return Ok(false);
            }
            artifacts.push(memory.local_artifact.clone());
        }
        if artifacts.is_empty() {
            return Ok(true);
        }
        respire_core_sdk::index_ready(&artifacts)
    }

    pub fn index_missing(&self, model: &str) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM memories m WHERE m.deleted=0 AND NOT EXISTS
             (SELECT 1 FROM core_artifacts r WHERE r.memory_id=m.id AND r.model=?1 AND r.source=m.ciphertext))",
            params![generation_key(model)?], |row| row.get(0))?)
    }

    pub fn index_pending(&self, model: &str) -> Result<bool> {
        let missing: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM memories m WHERE m.deleted=0 AND NOT EXISTS
             (SELECT 1 FROM core_artifacts r WHERE r.memory_id=m.id AND r.model=?1 AND r.source=m.ciphertext))",
            params![generation_key(&model)?], |row| row.get(0))?;
        if missing { return Ok(true); }
        let mut statement = self.connection.prepare("SELECT a.artifact FROM core_artifacts a JOIN memories m ON m.id=a.memory_id AND m.ciphertext=a.source WHERE a.model=?1 AND m.deleted=0")?;
        let artifacts = statement.query_map([generation_key(model)?], |row| row.get::<_, Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(!respire_core_sdk::index_ready(&artifacts)?)
    }

    /// Model generations are local derived data. Checkpoint each row, then activate atomically.
    /// A source-ciphertext check prevents a concurrent edit from publishing stale index locators.
    pub fn rebuild_index<E: crate::memory::search::Embedder>(
        &self,
        keys: &crate::memory::SessionKeys,
        embedder: &E,
        model: &str,
    ) -> Result<usize> {
        let started = std::time::Instant::now();
        self.rebuild_index_with_progress(keys, embedder, model, |done, total| {
            anyhow::ensure!(
                started.elapsed() < std::time::Duration::from_secs(15),
                "local index rebuild exceeded the foreground budget ({done}/{total} checked); run `rsrs reembed` to resume with progress; saved memories and keys are unchanged"
            );
            Ok(())
        })
    }

    pub fn rebuild_index_with_progress<E: crate::memory::search::Embedder>(
        &self,
        keys: &crate::memory::SessionKeys,
        embedder: &E,
        model: &str,
        mut progress: impl FnMut(usize, usize) -> Result<()>,
    ) -> Result<usize> {
        anyhow::ensure!(model == "m3", "unknown index model");
        progress(0, 0)?;
        let missing = self.index_missing(model)?;
        if !missing && self.meta_get("retrieval_model")?.as_deref() == Some(model)
            && !self.index_pending(model)?
        {
            progress(0, 0)?;
            return Ok(0);
        }
        progress(0, 0)?;
        let candidates = if missing {
            // Ordinary background work reads only current missing sources, with recent local writes first.
            let mut statement = self.connection.prepare(
                "SELECT id,user,ciphertext,nonce,embedding_enc,updated_at,deleted,
                 kind,tags,title,project,computer,embedding,created_at,parent_id,content_head,recall_count,importance,device,modified_by
                 FROM memories m WHERE deleted=0 AND NOT EXISTS
                 (SELECT 1 FROM core_artifacts r WHERE r.memory_id=m.id AND r.model=?1 AND r.source=m.ciphertext)
                 ORDER BY dirty DESC,updated_at DESC")?;
            let rows = statement.query_map([generation_key(model)?], Self::row_to_memory)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        } else {
            // An explicit repair still validates existing artifacts when none are missing.
            self.all(false)?
        };
        progress(0, candidates.len())?;
        let mut completed = 0;
        for (index, stored) in candidates.iter().enumerate() {
            progress(index, candidates.len())?;
            let artifact = self.connection.query_row(
                "SELECT artifact FROM core_artifacts WHERE memory_id=?1 AND model=?2 AND source=?3",
                params![stored.id, generation_key(model)?, stored.ciphertext], |r| r.get::<_, Vec<u8>>(0)).optional()?;
            if let Some(artifact) = artifact {
                if respire_core_sdk::index_ready(&[artifact])? { continue; }
            }
            let t_open = std::time::Instant::now();
            let entry = crate::memory::MemoryEngine::open(keys, stored)?;
            let open_ms = t_open.elapsed().as_millis();
            let t_prep = std::time::Instant::now();
            let prepared = embedder.prepare(&entry)?;
            let prep_ms = t_prep.elapsed().as_millis();
            if std::env::var("RSRS_REBUILD_TRACE").as_deref() == Ok("1") {
                eprintln!("[rebuild] {}/{} chars={} art={}B open={}ms prepare={}ms", index + 1, candidates.len(), entry.content.chars().count(), prepared.artifact.len(), open_ms, prep_ms);
            }
            progress(index, candidates.len())?;
            let mut derived = stored.clone();
            derived.local_artifact = prepared.artifact;
            self.store_artifact(&derived, model)?;
            completed += 1;
        }
        progress(candidates.len(), candidates.len())?;
        let tx = rusqlite::Transaction::new_unchecked(&self.connection, rusqlite::TransactionBehavior::Immediate)?;
        let missing: i64 = tx.query_row(
            "SELECT COUNT(*) FROM memories m WHERE deleted=0 AND NOT EXISTS
             (SELECT 1 FROM core_artifacts r WHERE r.memory_id=m.id AND r.model=?1 AND r.source=m.ciphertext)",
            params![generation_key(&model)?], |r| r.get(0))?;
        if missing != 0 {
            return Err(IndexSourceChanged { pending: missing }.into());
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('retrieval_model',?1)",
            params![model],
        )?;
        tx.commit()?;
        Ok(completed)
    }

    pub fn retrieval_model(&self) -> Result<String> {
        Ok("m3".to_owned())
    }
}

#[cfg(test)]
mod copy_tests {
    use super::*;

    #[test]
    fn attachments_preserve_source_deleted_model_and_subset_guards() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("attach.db"))?;
        let mut one = super::super::tests::sample("one");
        one.local_artifact = vec![1, 2, 3];
        let mut two = super::super::tests::sample("two");
        two.local_artifact = vec![4, 5, 6];
        store.put(&one)?;
        store.put(&two)?;
        // IDs, not ciphertext/artifact identity, distinguish rows.
        let mut duplicate = one.clone();
        duplicate.id = "duplicate".into();
        store.put(&duplicate)?;
        let mut missing = one.clone();
        missing.id = "missing".into();
        missing.local_artifact.clear();
        store.put(&missing)?;
        let all = store.all(false)?;
        assert_eq!(all.iter().map(|memory| &memory.id).collect::<std::collections::HashSet<_>>().len(), all.len());
        let mut actual = all.clone();
        let mut expected = all.clone();
        for memory in actual.iter_mut().chain(expected.iter_mut()) { memory.local_artifact.clear(); }
        let mut statement = store.connection.prepare("SELECT a.memory_id,a.source,a.artifact FROM core_artifacts a JOIN memories m ON m.id=a.memory_id AND m.ciphertext=a.source WHERE a.model=?1 AND m.deleted=0")?;
        let artifacts = statement.query_map([generation_key("m3")?], |row| {
            Ok(((row.get::<_, String>(0)?, row.get::<_, String>(1)?), row.get::<_, Vec<u8>>(2)?))
        })?.collect::<rusqlite::Result<std::collections::HashMap<_, _>>>()?;
        for memory in &mut expected {
            if let Some(artifact) = artifacts.get(&(memory.id.clone(), memory.ciphertext.clone())) {
                memory.local_artifact = artifact.clone();
            }
        }
        store.attach_retrieval_index(&mut actual)?;
        // Debug covers local-only fields skipped by wire serde, plus ordering.
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        drop(statement);
        assert_eq!(all.len(), 4);
        assert_eq!(all.iter().find(|m| m.id == "duplicate").ok_or_else(|| anyhow::anyhow!("duplicate fixture missing"))?.local_artifact, one.local_artifact);
        assert!(all.iter().find(|m| m.id == "missing").ok_or_else(|| anyhow::anyhow!("missing fixture absent"))?.local_artifact.is_empty());
        let mut stale = one.clone();
        stale.ciphertext = "older source".into();
        stale.local_artifact.clear();
        store.attach_retrieval_index(std::slice::from_mut(&mut stale))?;
        assert!(stale.local_artifact.is_empty());
        let mut subset = vec![two.clone()];
        subset[0].local_artifact.clear();
        store.attach_retrieval_index(&mut subset)?;
        assert_eq!(subset[0].local_artifact, two.local_artifact);
        store.connection.execute("UPDATE core_artifacts SET model='other-generation' WHERE memory_id='one'", [])?;
        store.connection.execute("UPDATE memories SET deleted=1 WHERE id='two'", [])?;
        let all = store.all(true)?;
        assert_eq!(all.len(), 4);
        assert!(all.iter().filter(|m| m.id != "duplicate").all(|m| m.local_artifact.is_empty()));
        store.attach_retrieval_index(&mut [])?;
        store.connection.execute("UPDATE core_artifacts SET artifact='not-a-blob' WHERE memory_id='duplicate'", [])?;
        assert!(store.attach_retrieval_index(std::slice::from_mut(&mut stale)).is_err());
        assert!(store.all(false).is_err());
        store.connection.execute("DROP TABLE core_artifacts", [])?;
        assert!(store.attach_retrieval_index(&mut subset).is_err());
        Ok(())
    }
}

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
        let rows = stmt.query_map(params![generation_key(&model)?], |row| {
            Ok(((row.get::<_, String>(0)?, row.get::<_, String>(1)?), row.get::<_, Vec<u8>>(2)?))
        })?;
        let artifacts = rows.collect::<rusqlite::Result<std::collections::HashMap<_, _>>>()?;
        for memory in out.iter_mut() {
            if let Some(artifact) = artifacts.get(&(memory.id.clone(), memory.ciphertext.clone())) {
                memory.local_artifact = artifact.clone();
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
        if self.meta_get("retrieval_model")?.as_deref() == Some(model)
            && !self.index_pending(model)?
        {
            progress(0, 0)?;
            return Ok(0);
        }
        progress(0, 0)?;
        let candidates = self.all(false)?;
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
            let entry = crate::memory::MemoryEngine::open(keys, stored)?;
            let prepared = embedder.prepare(&entry)?;
            progress(index, candidates.len())?;
            let mut derived = stored.clone();
            derived.local_artifact = prepared.artifact;
            self.store_artifact(&derived, model)?;
            completed += 1;
        }
        progress(candidates.len(), candidates.len())?;
        let tx = self.connection.unchecked_transaction()?;
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

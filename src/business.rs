//! Business requests and opaque compatibility payloads. No inference code lives here.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use respire_protocol::{MemoryEntry, MemoryQuery, StoredMemory};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::cell::RefCell;

thread_local! {
    static CORE: RefCell<Option<crate::Core>> = const { RefCell::new(None) };
    static INDEX_ROOT: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) };
}

/// Select the local profile that owns derived Core index state on this thread.
pub fn set_index_root(root: &std::path::Path) -> Result<()> {
    anyhow::ensure!(root.is_absolute(), "Core index root must be absolute");
    std::fs::create_dir_all(root)?;
    let root = std::fs::canonicalize(root)?;
    INDEX_ROOT.with(|slot| *slot.borrow_mut() = Some(root));
    Ok(())
}

pub fn execute<T: DeserializeOwned>(operation: &str, mut payload: Value) -> Result<T> {
    execute_inner(operation, &mut payload, None)
}

pub fn execute_with_transport<T: DeserializeOwned>(operation: &str, mut payload: Value,
    transport: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<T> {
    execute_inner(operation, &mut payload, Some(transport))
}

fn execute_inner<T: DeserializeOwned>(operation: &str, payload: &mut Value,
    transport: Option<&mut dyn FnMut(&Value) -> Result<Value>>) -> Result<T> {
    if matches!(operation, "prepare" | "query" | "query_business" | "related_business" | "remember_candidates" | "candidate_report" | "analyze_duplicates" | "tree_cure" | "deepen_plan" | "tree_float" | "index_status") { INDEX_ROOT.with(|slot| {
        if let (Some(root), Some(fields)) = (slot.borrow().as_ref(), payload.as_object_mut()) {
            fields.insert("index_root".to_owned(), json!(root));
        }
    }); }
    CORE.with(|cell| {
        let mut slot = cell.try_borrow_mut().context("recursive Core call")?;
        if slot.is_none() {
            *slot = Some(crate::Core::new()?);
        }
        let core = slot.as_mut().context("Core not initialized")?;
        let payload = payload.take();
        let result = match transport {
            Some(transport) => core.call_with_transport(operation, payload, transport)?,
            None => core.call(operation, payload)?,
        };
        serde_json::from_value(result).context("invalid Core business response")
    })
}

/// Reject an older binary SDK before writing fields it cannot round-trip.
pub fn require_associations() -> Result<()> {
    let capabilities: Value = execute("capabilities",json!({}))?;
    anyhow::ensure!(capabilities["operations"].as_array().is_some_and(|ops|
        ops.iter().any(|op| op.as_str() == Some("related_business"))),
        "Core SDK does not support associations; install a matching SDK");
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prepared {
    /// Local-only Core index locator; no intermediate features cross this API.
    #[serde(default, with = "bytes")]
    pub artifact: Vec<u8>,
}

mod bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error> {
        STANDARD.decode(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub deleted: bool,
    pub updated_at: String,
    pub kind: String,
    pub tags: String,
    pub title: String,
    pub project: String,
    pub computer: String,
    pub parent_id: String,
    pub created_at: String,
    pub content_head: String,
    pub recall_count: i64,
    pub importance: String,
    pub entry: Option<MemoryEntry>,
    pub features: Option<Prepared>,
}

impl Snapshot {
    pub fn new(memory: &StoredMemory, entry: Option<MemoryEntry>) -> Self {
        Self {
            id: memory.id.clone(), deleted: memory.deleted, updated_at: memory.updated_at.clone(),
            kind: memory.local_kind.clone(), tags: memory.local_tags.clone(), title: memory.local_title.clone(),
            project: memory.local_project.clone(), computer: memory.local_computer.clone(), parent_id: memory.local_parent_id.clone(),
            created_at: memory.local_created_at.clone(), content_head: memory.local_content_head.clone(),
            recall_count: memory.local_recall_count, importance: memory.local_importance.clone(), entry,
            features: (!memory.local_artifact.is_empty()).then(|| Prepared { artifact: memory.local_artifact.clone() }),
        }
    }
}

pub fn metadata_snapshots(memories: &[StoredMemory]) -> Vec<Snapshot> {
    memories.iter().map(|memory| Snapshot::new(memory, None)).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecalledWithContext {
    pub score: f32,
    pub entry: MemoryEntry,
    pub ancestors: Vec<MemoryEntry>,
}

pub fn query<E: search::Embedder, T: DeserializeOwned>(provider: &E, snapshots: &[Snapshot], query: &MemoryQuery, mode: &str) -> Result<T> {
    execute("query", json!({"model":provider.model_name(), "snapshots":snapshots, "query":query, "mode":mode}))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RememberCandidates {
    pub merge: Vec<(f32, MemoryEntry)>,
    pub parent: Vec<(f32, MemoryEntry)>,
}

pub fn remember_candidates<E: search::Embedder>(provider: &E, snapshots: &[Snapshot], query: &MemoryQuery) -> Result<RememberCandidates> {
    execute("remember_candidates", json!({"model":provider.model_name(), "snapshots":snapshots, "query":query}))
}

pub fn generation_key(model: &str) -> Result<String> {
    execute("index_generation", json!({"model":model}))
}

pub fn index_ready(artifacts: &[Vec<u8>]) -> Result<bool> {
    execute("index_status", json!({"artifacts":artifacts.iter().map(|artifact| STANDARD.encode(artifact)).collect::<Vec<_>>()}))
}

pub mod search {
    use super::*;
    /// Selects a private inference provider; never exposes vector operations.
    pub trait Embedder: Send + Sync {
        fn model_name(&self) -> &str;
        fn dims(&self) -> usize;
        fn prepare(&self, entry: &MemoryEntry) -> Result<Prepared> {
            execute("prepare", json!({"model":self.model_name(), "entry":entry}))
        }
    }
    impl<T: Embedder + ?Sized> Embedder for Box<T> {
        fn model_name(&self) -> &str { (**self).model_name() }
        fn dims(&self) -> usize { (**self).dims() }
        fn prepare(&self, entry: &MemoryEntry) -> Result<Prepared> { (**self).prepare(entry) }
    }
    /// Explicit existing-test provider; the Core also requires RSRS_CORE_TEST_MODE=1.
    #[derive(Clone)]
    pub struct HashingEmbedder { name: String, dims: usize }
    impl HashingEmbedder { pub fn new(dims: usize) -> Self { Self { name:format!("test-hash:{dims}"), dims } } }
    impl Default for HashingEmbedder { fn default() -> Self { Self::new(256) } }
    impl Embedder for HashingEmbedder {
        fn model_name(&self) -> &str { &self.name }
        fn dims(&self) -> usize { self.dims }
    }
}

pub mod bge {
    use super::*;
    use std::path::{Path, PathBuf};
    #[derive(Clone)]
    pub struct BgeEmbedder { model: String, dims: usize }
    impl BgeEmbedder {
        pub fn load() -> Result<Self> { Self::load_model("m3") }
        pub fn load_model(model: &str) -> Result<Self> {
            let value: Value = execute("model_status", json!({"model":model}))?;
            let dims = value["dimensions"].as_u64().context("missing model dimensions")? as usize;
            Ok(Self { model:model.to_owned(), dims })
        }
        pub fn model_name(&self) -> &str { &self.model }
        pub fn probe(&self, text: &str) -> Result<Value> { execute("model_probe", json!({"model":self.model,"text":text})) }
    }
    impl search::Embedder for BgeEmbedder {
        fn model_name(&self) -> &str { &self.model }
        fn dims(&self) -> usize { self.dims }
    }
    // Installation paths are public infrastructure and use the Respire profile.
    pub fn default_user_model_dir() -> PathBuf {
        crate::env::var("RSRS_DATA_DIR").ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| expand_home(value.trim()).join("models/bge-m3"))
            .unwrap_or_else(|| expand_home("~/.rsrs/models/bge-m3"))
    }
    pub fn m3_model_dir() -> PathBuf { crate::env::var("RSRS_M3_DIR").ok().filter(|s| !s.trim().is_empty()).map(|s| expand_home(s.trim())).unwrap_or_else(default_user_model_dir) }
    pub fn model_files_present(dir: &Path) -> bool { dir.join("tokenizer.json").is_file() && dir.join("onnx/model_quantized.onnx").is_file() }
    pub fn expand_home(value: &str) -> PathBuf {
        match value.strip_prefix("~/") {
            Some(rest) => dirs::home_dir().or_else(|| crate::env::var_os("HOME").map(PathBuf::from)).or_else(|| crate::env::var_os("USERPROFILE").map(PathBuf::from)).map(|base| base.join(rest)).unwrap_or_else(|| PathBuf::from(value)),
            None => PathBuf::from(value),
        }
    }
}

pub mod onnx {
    use super::*;
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all="lowercase")]
    pub enum Engine { Npu, Gpu, #[default] Cpu }
    impl Engine {
        pub fn parse(value: &str) -> Result<Self> {
            match value { "cpu" => Ok(Self::Cpu), "gpu" => Ok(Self::Gpu), "npu" => Ok(Self::Npu), _ => bail!("engine must be npu, gpu, or cpu; automatic mode is no longer supported") }
        }
    }
    pub fn configured_engine() -> Result<Engine> { execute("engine_control", json!({"action":"get"})) }
    pub fn inference_status() -> Result<Value> { execute("engine_control", json!({"action":"inference_status"})) }
    pub fn save_engine(engine: Engine) -> Result<()> { execute("engine_control", json!({"action":"set","engine":engine})) }
    pub fn reset_sessions() -> Result<()> { execute("engine_control", json!({"action":"reset"})) }
    pub fn reset_cpu_config() -> Result<()> { execute("engine_control", json!({"action":"reset_cpu"})) }
    pub fn accelerator_catalog_path() -> Result<Option<std::path::PathBuf>> { execute("engine_control", json!({"action":"accelerator_catalog"})) }
    pub fn install_accelerators() -> Result<Vec<String>> { bail!("accelerator installation is host-managed; run rsrs model install-engines from the host CLI") }
}

pub mod defrag {
    use super::*;
    pub use super::reports::{Cluster, Member, Report};
    pub fn analyze(memories: &[StoredMemory], min: f32) -> Result<Report> { execute("analyze_duplicates", json!({"snapshots":metadata_snapshots(memories), "min":min})) }
}

pub mod reports;

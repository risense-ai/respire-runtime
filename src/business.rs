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
    crate::resident::apply_scope(operation, payload);
    if crate::worker::enabled() {
        if matches!(operation, "query" | "query_business" | "related_business" | "remember_candidates" | "candidate_report" | "analyze_duplicates" | "tree_cure" | "deepen_plan" | "tree_float") {
            crate::host::request_settings(payload)?;
        }
        return serde_json::from_value(crate::worker::execute(operation, payload, transport)?)
            .context("invalid isolated Core business response");
    }
    if let Err(error) = crate::host::resolve_artifacts(payload) {
        if operation == "index_status" && error.chain().any(|cause|
            cause.downcast_ref::<crate::host::CorruptArtifact>().is_some() || cause.downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)) {
            return serde_json::from_value(json!(false)).map_err(Into::into);
        }
        return Err(error);
    }
    if matches!(operation, "query" | "query_business" | "related_business" | "remember_candidates" | "candidate_report" | "analyze_duplicates" | "tree_cure" | "deepen_plan" | "tree_float") {
        crate::host::request_settings(payload)?;
    }
    CORE.with(|cell| {
        let mut slot = cell.try_borrow_mut().context("recursive Core call")?;
        if slot.is_none() {
            *slot = Some(crate::Core::new()?);
        }
        let core = slot.as_mut().context("Core not initialized")?;
        if payload["model"].as_str() == Some("m3")
            && matches!(operation, "prepare" | "query" | "query_business" | "remember_candidates" | "candidate_report" | "taxonomy_classify" | "model_probe" | "model_status")
            && payload["lexical_only"].as_bool() != Some(true) {
            crate::host::initialize_model(core)?;
        }
        let payload = payload.take();
        let mut result = match transport {
            Some(transport) => core.call_with_transport(operation, payload, transport)?,
            None => core.call(operation, payload)?,
        };
        if operation == "prepare" { crate::host::persist_prepared(&mut result)?; }
        serde_json::from_value(result).context("invalid Core business response")
    })
}

pub(crate) fn index_root() -> Result<std::path::PathBuf> {
    INDEX_ROOT.with(|slot| slot.borrow().clone().context("missing selected profile index root"))
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
    /// Host-owned local index locator. Its contents remain opaque to the host.
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
            if crate::indexing_deferred() || crate::resident::resident_lexical_only() {
                anyhow::ensure!(model == "m3", "only BGE-M3 is supported");
                return Ok(Self { model:model.to_owned(), dims:1024 });
            }
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
    pub fn resolve_model_dir() -> Result<PathBuf> {
        let explicit = crate::env::var("RSRS_M3_DIR").ok().filter(|value| !value.trim().is_empty());
        let user = m3_model_dir();
        if explicit.is_some() {
            anyhow::ensure!(model_files_present(&user), "BGE-M3 quantized files missing in {}; need tokenizer.json and onnx/model_quantized.onnx; run rsrs model install-m3", user.display());
            return Ok(user);
        }
        let mut candidates = vec![user.clone()];
        if crate::env::var_os("RSRS_DATA_DIR").is_none() {
            if let Some(home) = dirs::home_dir() {
                candidates.extend([home.join(".respire/models/bge-m3"), home.join(".onememory/models/bge-m3")]);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() { candidates.insert(0, parent.join("models/bge-m3")); }
        }
        candidates.push(PathBuf::from("/usr/lib/respire/models/bge-m3"));
        for directory in candidates { if model_files_present(&directory) { return Ok(directory); } }
        bail!("BGE-M3 quantized files missing; need tokenizer.json and onnx/model_quantized.onnx; run rsrs model install-m3 or set RSRS_M3_DIR (expected {})", user.display())
    }
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
    fn settings_dir() -> std::path::PathBuf {
        crate::env::var_os("RSRS_DATA_DIR").map(std::path::PathBuf::from)
            .unwrap_or_else(|| bge::expand_home("~/.rsrs"))
    }
    pub(crate) fn host_cache_dir() -> std::path::PathBuf { settings_dir().join("engines/openvino-cache") }
    pub fn configured_engine() -> Result<Engine> {
        let mut path = settings_dir().join("inference.json");
        if !path.exists() && crate::env::var_os("RSRS_DATA_DIR").is_none() {
            if let Some(home) = dirs::home_dir() {
                for legacy in [".respire", ".onememory"] {
                    let candidate = home.join(legacy).join("inference.json");
                    if candidate.exists() { path = candidate; break; }
                }
            }
        }
        let value = if path.exists() { serde_json::from_slice::<Value>(&std::fs::read(path)?)? }
            else { json!({"engine":"cpu"}) };
        if value["force_cpu"].as_bool() == Some(true) { return Ok(Engine::Cpu); }
        if let Ok(value) = crate::env::var("RSRS_ENGINE") { return Engine::parse(&value); }
        match value["engine"].as_str().context("inference.json missing engine")? {
            "auto" => Ok(Engine::Cpu), value => Engine::parse(value),
        }
    }
    pub fn inference_status() -> Result<Value> {
        if crate::worker::enabled() { return crate::worker::status(); }
        let mut status: Value = execute("engine_control", json!({"action":"inference_status"}))?;
        let diagnostics = crate::host::provider_diagnostics()?;
        if !diagnostics.is_empty() { status["provider_registration_errors"] = json!(diagnostics); }
        Ok(status)
    }
    fn write_engine(engine: Engine, force_cpu: bool) -> Result<()> {
        let directory = settings_dir();
        std::fs::create_dir_all(&directory)?;
        std::fs::write(directory.join("inference.json"), serde_json::to_vec_pretty(&json!({"engine":engine,"force_cpu":force_cpu}))?)?;
        Ok(())
    }
    pub fn save_engine(engine: Engine) -> Result<()> {
        reset_sessions()?;
        write_engine(engine, false)
    }
    pub fn reset_sessions() -> Result<()> {
        execute::<()>("engine_control", json!({"action":"reset"}))?;
        crate::host::reset_model_cache()
    }
    pub fn reset_cpu_config() -> Result<()> { write_engine(Engine::Cpu, true) }
    pub fn accelerator_catalog_path() -> Result<Option<std::path::PathBuf>> {
        #[cfg(windows)] {
            let directory = settings_dir().join("engines/winml-2.4.89");
            let dll = directory.join("Microsoft.Windows.AI.MachineLearning.dll");
            if !dll.exists() {
                std::fs::create_dir_all(&directory)?;
                std::fs::write(&dll, crate::host_winml::DLL)?;
                std::fs::write(directory.join("license.txt"), crate::host_winml::LICENSE)?;
            }
            Ok(Some(dll))
        }
        #[cfg(not(windows))] { Ok(None) }
    }
    #[cfg(windows)]
    pub(crate) fn host_providers() -> Result<Vec<crate::host_winml::Provider>> {
        let dll = accelerator_catalog_path()?.context("Windows ML catalog path missing")?;
        let mut providers = crate::host_winml::Catalog::open(&dll)?.providers()?;
        let manifest = settings_dir().join("engines/providers.json");
        if manifest.exists() {
            let saved: std::collections::BTreeMap<String, std::path::PathBuf> = serde_json::from_slice(&std::fs::read(manifest)?)?;
            for (name, path) in saved { providers.push(crate::host_winml::Provider { name, ready:path.is_file(), path:Some(path) }); }
        }
        Ok(providers)
    }
    pub fn install_accelerators() -> Result<Vec<String>> { bail!("accelerator installation is host-managed; run rsrs model install-engines from the host CLI") }
}

pub mod defrag {
    use super::*;
    pub use super::reports::{Cluster, Member, Report};
    pub fn analyze(memories: &[StoredMemory], min: f32) -> Result<Report> { execute("analyze_duplicates", json!({"snapshots":metadata_snapshots(memories), "min":min})) }
}

pub mod reports;

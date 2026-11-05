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
    let selection = crate::profiles::current()?;
    if let Some(selection) = selection.as_ref().filter(|s| s.backend_profile.backend == "host_transport") {
        let mut transport = |request: &Value| crate::profiles::transport(request, selection);
        execute_inner(operation, &mut payload, Some(&mut transport))
    } else { execute_inner(operation, &mut payload, None) }
}

pub fn execute_with_transport<T: DeserializeOwned>(operation: &str, mut payload: Value,
    transport: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<T> {
    let selection = crate::profiles::current()?;
    let mut combined = |request: &Value| {
        if request["operation"] == "embedding" && crate::profiles::transport_available()? {
            crate::profiles::transport(request, selection.as_ref().context("embedding selection missing")?)
        } else { transport(request) }
    };
    execute_inner(operation, &mut payload, Some(&mut combined))
}

// The parent still submits one request with one worker deadline. Bound only
// the expanded artifact payload sent through the unchanged native ABI.
const INDEX_STATUS_BATCH_COUNT: usize = 128;
const INDEX_STATUS_BATCH_BYTES: usize = 4 * 1024 * 1024;

fn unavailable_index(error: &anyhow::Error) -> bool {
    error.chain().any(|cause|
        cause.downcast_ref::<crate::host::CorruptArtifact>().is_some()
            || cause.downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound))
}

fn check_index_batches(
    artifacts: Vec<String>,
    mut resolve: impl FnMut(&str) -> Result<String>,
    mut check: impl FnMut(Vec<String>) -> Result<bool>,
) -> Result<bool> {
    if artifacts.is_empty() { return check(Vec::new()); }
    let mut batch = Vec::new();
    let mut bytes = 0usize;
    let mut verdict = Ok(true);
    for artifact in artifacts {
        let resolved = match resolve(&artifact) {
            Ok(resolved) => resolved,
            Err(error) if unavailable_index(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        // The old request resolves every locator before native validation.
        // Keep resolving after a native failure so later host errors retain
        // precedence, but never replay the failed native validation.
        if !matches!(verdict, Ok(true)) { continue; }
        if !batch.is_empty() && (batch.len() == INDEX_STATUS_BATCH_COUNT
            || resolved.len() > INDEX_STATUS_BATCH_BYTES.saturating_sub(bytes)) {
            verdict = check(std::mem::take(&mut batch));
            bytes = 0;
            if !matches!(verdict, Ok(true)) { continue; }
        }
        bytes += resolved.len();
        batch.push(resolved);
    }
    if matches!(verdict, Ok(true)) && !batch.is_empty() { verdict = check(batch); }
    verdict
}

fn execute_index_batches(payload: &mut Value,
    mut transport: Option<&mut dyn FnMut(&Value) -> Result<Value>>) -> Result<bool> {
    let artifacts = serde_json::from_value(payload["artifacts"].take())?;
    CORE.with(|cell| {
        let mut slot = cell.try_borrow_mut().context("recursive Core call")?;
        check_index_batches(artifacts, crate::host::resolve, |batch| {
            if slot.is_none() { *slot = Some(crate::Core::new()?); }
            let core = slot.as_mut().context("Core not initialized")?;
            let payload = json!({"artifacts": batch});
            let result = match transport.as_mut() {
                Some(transport) => core.call_with_transport("index_status", payload, *transport)?,
                None => core.call("index_status", payload)?,
            };
            serde_json::from_value(result).context("invalid Core business response")
        })
    })
}

fn execute_inner<T: DeserializeOwned>(operation: &str, payload: &mut Value,
    transport: Option<&mut dyn FnMut(&Value) -> Result<Value>>) -> Result<T> {
    let selected = crate::profiles::current()?;
    if let Some(selection) = selected.as_ref() {
        if !matches!(operation,"memory_evidence_evaluate" | "memory_metadata_validate" | "classify_business") && payload.get("config").is_none() && payload["model"].as_str() == Some(&selection.model) {
            payload["config"] = selection.config()?;
        }
    }
    if selected.is_none() && payload["model"].as_str() == Some("m3") && payload.get("config").is_none()
        && !matches!(operation,"memory_evidence_evaluate" | "memory_metadata_validate" | "classify_business") {
        payload["config"] = crate::legacy_effective_model_config()?;
    }
    let reset = operation == "engine_control" && payload["action"] == "reset";
    let _gate = crate::model_selection::gate(operation == "host_load_selection" || reset)?;
    crate::resident::apply_scope(operation, payload);
    if crate::worker::enabled() {
        if matches!(operation, "query" | "query_business" | "related_business" | "remember_candidates" | "candidate_report" | "analyze_duplicates" | "tree_cure" | "deepen_plan" | "tree_float") {
            crate::host::request_settings(payload)?;
        }
        return serde_json::from_value(crate::worker::execute(operation, payload, transport)?)
            .context("invalid isolated Core business response");
    }
    if operation == "host_load_selection" {
        let engine = onnx::Engine::parse(payload["engine"].as_str().context("missing engine")?)?;
        let variant = onnx::parse_variant(payload["variant"].as_str().context("missing variant")?)?;
        return serde_json::from_value(crate::model_selection::load(engine, variant)?).map_err(Into::into);
    }
    if operation == "index_status" && payload.as_object().is_some_and(|fields|
        fields.len() == 1 && fields.get("artifacts").and_then(Value::as_array)
            .is_some_and(|artifacts| artifacts.iter().all(Value::is_string))) {
        return serde_json::from_value(json!(execute_index_batches(payload, transport)?))
            .context("invalid Core business response");
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
        if operation == "index_generation" && payload.get("config").is_some() {
            let capabilities = core.capabilities()?;
            anyhow::ensure!(capabilities["embedding_profile_contract"].as_u64() == Some(1), "paired Core SDK with embedding profile contract 1 is required");
        }
        if payload["model"].as_str().is_some_and(|model| model == "m3" || selected.as_ref().is_some_and(|s| s.model == model))
            && matches!(operation, "prepare" | "query" | "query_business" | "remember_candidates" | "candidate_report" | "taxonomy_classify" | "model_probe" | "model_status")
            && payload["lexical_only"].as_bool() != Some(true) {
            crate::host::initialize_model(core)?;
        }
        let payload = payload.take();
        let mut result = match transport {
            Some(transport) => core.call_with_transport(operation, payload, transport)?,
            None => core.call(operation, payload)?,
        };
        if reset { crate::host::reset_model_cache()?; }
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

#[cfg(test)]
mod index_batch_tests {
    use super::*;

    #[test]
    fn empty_count_and_byte_boundaries_preserve_order() -> Result<()> {
        let mut batches = Vec::new();
        assert!(check_index_batches(Vec::new(), |value| Ok(value.to_owned()), |batch| {
            batches.push(batch); Ok(true)
        })?);
        assert_eq!(batches, vec![Vec::<String>::new()]);
        batches.clear();
        let input: Vec<_> = (0..257).map(|index| index.to_string()).collect();
        assert!(check_index_batches(input.clone(), |value| Ok(value.to_owned()), |batch| {
            batches.push(batch); Ok(true)
        })?);
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [128, 128, 1]);
        assert_eq!(batches.into_iter().flatten().collect::<Vec<_>>(), input);
        let sizes = [INDEX_STATUS_BATCH_BYTES / 2, INDEX_STATUS_BATCH_BYTES / 2,
            1, INDEX_STATUS_BATCH_BYTES + 1, 1];
        let mut actual = Vec::new();
        assert!(check_index_batches((0..sizes.len()).map(|i| i.to_string()).collect(),
            |value| Ok("a".repeat(sizes[value.parse::<usize>()?])),
            |batch| { actual.push(batch.iter().map(String::len).sum::<usize>()); Ok(true) })?);
        assert_eq!(actual, [INDEX_STATUS_BATCH_BYTES, 1, INDEX_STATUS_BATCH_BYTES + 1, 1]);
        Ok(())
    }

    #[test]
    fn first_middle_and_last_native_failures_are_not_replayed() -> Result<()> {
        for failed_batch in 0..3 {
            let mut calls = 0;
            let mut resolved = 0;
            let error = check_index_batches((0..257).map(|i| i.to_string()).collect(),
                |value| { resolved += 1; Ok(value.to_owned()) },
                |_| {
                    let batch = calls; calls += 1;
                    if batch == failed_batch { bail!("native fixture failure {batch}"); }
                    Ok(true)
                }).err().context("native failure disappeared")?;
            assert_eq!(error.to_string(), format!("native fixture failure {failed_batch}"));
            assert_eq!(calls, failed_batch + 1);
            assert_eq!(resolved, 257);
        }
        Ok(())
    }

    #[test]
    fn later_host_errors_keep_priority_over_native_failures() -> Result<()> {
        for kind in [std::io::ErrorKind::NotFound, std::io::ErrorKind::PermissionDenied] {
            let result = check_index_batches((0..257).map(|i| i.to_string()).collect(),
                |value| {
                    if value == "256" { return Err(std::io::Error::from(kind).into()); }
                    Ok(value.to_owned())
                }, |_| bail!("earlier native failure"));
            if kind == std::io::ErrorKind::NotFound {
                assert!(!result?);
            } else {
                let error = result.err().context("host error disappeared")?;
                assert_eq!(error.downcast_ref::<std::io::Error>().context("IO type lost")?.kind(), kind);
            }
        }
        assert!(!check_index_batches(vec!["corrupt".into()],
            |_| Err(crate::host::CorruptArtifact.into()), |_| Ok(true))?);
        Ok(())
    }

    #[test]
    fn first_middle_and_last_host_failures_never_accept_partial_results() -> Result<()> {
        for failed_row in [0, 128, 256] {
            let error = check_index_batches((0..257).map(|i| i.to_string()).collect(),
                |value| {
                    if value == failed_row.to_string() { bail!("host fixture failure {failed_row}"); }
                    Ok(value.to_owned())
                }, |_| Ok(true)).err().context("host failure disappeared")?;
            assert_eq!(error.to_string(), format!("host fixture failure {failed_row}"));
        }
        Ok(())
    }
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
    pub struct BgeEmbedder { model: String, dims: usize, generation: String }
    impl BgeEmbedder {
        pub fn load() -> Result<Self> { Self::load_model(&crate::profiles::current()?.map(|s| s.model).unwrap_or_else(|| "m3".to_owned())) }
        pub fn load_model(model: &str) -> Result<Self> {
            let selected = crate::profiles::current()?;
            let model = if model == "m3" { selected.as_ref().map(|s|s.model.as_str()).unwrap_or(model) } else { model };
            anyhow::ensure!(selected.as_ref().is_none_or(|selection| selection.model == model),"requested model does not match the selected profile");
            if crate::indexing_deferred() || crate::resident::resident_lexical_only() {
                let dims = crate::profiles::current()?.map(|s| s.profile.embedding["dimensions"].as_u64().unwrap_or(1024) as usize).unwrap_or(1024);
                return Ok(Self { model:model.to_owned(), dims, generation:crate::generation_key(model)? });
            }
            let value: Value = execute("model_status", json!({"model":model}))?;
            let dims = value["dimensions"].as_u64().context("missing model dimensions")? as usize;
            Ok(Self { model:model.to_owned(), dims, generation:crate::generation_key(model)? })
        }
        pub fn model_name(&self) -> &str { &self.model }
        pub fn generation_key(&self) -> &str { &self.generation }
        pub fn probe(&self, text: &str) -> Result<Value> { execute("model_probe", json!({"model":self.model,"text":text})) }
    }
    impl search::Embedder for BgeEmbedder {
        fn model_name(&self) -> &str { &self.model }
        fn dims(&self) -> usize { self.dims }
    }
    pub use crate::cpu_model::{CPU_ORT_REVISION, CPU_ORT_NAME, CPU_ORT_SHA256, CPU_ORT_SIZE, CPU_ORT_URL, cpu_owned_mode, cpu_ort_cache_path, cpu_ort_path, cpu_ort_present, invalidate_cpu_ort_validation};
    // Installation paths are public infrastructure and use the Respire profile.
    fn model_dir_setting(name: &str) -> Result<Option<PathBuf>> {
        match crate::env::var(name) {
            Ok(value) => {
                anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty or whitespace");
                Ok(Some(expand_home(value.trim())))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must contain valid Unicode"),
        }
    }

    pub fn default_user_model_dir() -> Result<PathBuf> {
        let root = model_dir_setting("RSRS_DATA_DIR")?;
        // CPU cache callers must reject an invalid model override too.
        model_dir_setting("RSRS_M3_DIR")?;
        Ok(root.map(|root| root.join("models/bge-m3"))
            .unwrap_or_else(|| expand_home("~/.rsrs/models/bge-m3")))
    }

    pub fn m3_model_dir() -> Result<PathBuf> {
        // Validate the isolation root even when a model override is present.
        let default = default_user_model_dir()?;
        Ok(model_dir_setting("RSRS_M3_DIR")?.unwrap_or(default))
    }

    pub fn model_files_present(dir: &Path) -> bool {
        dir.join("tokenizer.json").is_file() && dir.join("onnx/model_quantized.onnx").is_file()
    }

    pub fn resolve_model_dir() -> Result<PathBuf> {
        let directory = discovered_model_dir()?;
        anyhow::ensure!(model_files_present(&directory), "BGE-M3 quantized files missing in {}; need tokenizer.json and onnx/model_quantized.onnx; run rsrs model install-m3 or set RSRS_M3_DIR",directory.display());
        Ok(directory)
    }

    /// Find a model without requiring baseline files, so inventories can report missing assets.
    pub fn discovered_model_dir() -> Result<PathBuf> {
        let user = m3_model_dir()?;
        if crate::env::var_os("RSRS_M3_DIR").is_some() {
            return Ok(user);
        }
        let isolated = crate::env::var_os("RSRS_DATA_DIR").is_some();
        let mut legacy = Vec::new();
        if !isolated {
            if let Some(home) = dirs::home_dir() {
                legacy.extend([
                    home.join(".respire/models/bge-m3"),
                    home.join(".onememory/models/bge-m3"),
                ]);
            }
        }
        let packaged = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|parent| parent.join("models/bge-m3")));
        Ok(model_directory_candidates(user.clone(), legacy, packaged, isolated)
            .into_iter()
            .find(|directory| model_files_present(directory))
            .unwrap_or(user))
    }

    pub(crate) fn model_directory_candidates(
        user: PathBuf,
        legacy: Vec<PathBuf>,
        packaged: Option<PathBuf>,
        isolated: bool,
    ) -> Vec<PathBuf> {
        let mut candidates = vec![user];
        if !isolated {
            candidates.extend(legacy);
            candidates.extend(packaged);
            candidates.push(PathBuf::from("/usr/lib/respire/models/bge-m3"));
        }
        candidates
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ModelVariant { pub name: &'static str, pub sha256: &'static str, pub size: u64 }
    /// Pinned Xenova/bge-m3@4de13258 single-file onnx variants. fp32 (external
    /// .onnx_data), bnb4 and sentence_transformers files cannot load from memory
    /// or conflict with CLS pooling, so they are not offered.
    pub const MODEL_VARIANTS: &[ModelVariant] = &[
        ModelVariant { name: "quantized", sha256: "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d", size: 569694530 },
        ModelVariant { name: "fp16", sha256: "4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9", size: 1133992936 },
        ModelVariant { name: "int8", sha256: "a206e10e995aa2a833924bcd725ba5dd6c3425cd34bac3cf2b5677cd2a1c51d6", size: 568456694 },
        ModelVariant { name: "uint8", sha256: "3222211565d0d5da2fe89e0c40856ed879e5c5dd3369fbbe685213469498e811", size: 568456765 },
        ModelVariant { name: "q4", sha256: "4f6d9786712f8dbf00efbb08ffd819395ef05d860249e852b4efc16022f753a6", size: 1248237611 },
        ModelVariant { name: "q4f16", sha256: "8305fdfa48b5702ecb4a6d84c1a52a4d1cb27d69880ff7f69d1a93d795864f25", size: 699932840 },
    ];
    pub fn parse_variant(value: &str) -> Result<ModelVariant> {
        let wanted = value.trim().to_ascii_lowercase();
        MODEL_VARIANTS.iter().copied().find(|variant| variant.name == wanted).ok_or_else(|| {
            anyhow::anyhow!("model variant must be one of: {}",
                MODEL_VARIANTS.iter().map(|variant| variant.name).collect::<Vec<_>>().join(", "))
        })
    }
    pub fn variant_file_name(variant: &str) -> String { format!("onnx/model_{variant}.onnx") }
    /// CPU keeps the quantized graph; accelerators default to fp16.
    pub fn default_variant(engine: Engine) -> &'static str {
        match engine { Engine::Cpu => "quantized", _ => "fp16" }
    }
    fn settings_dir() -> std::path::PathBuf {
        crate::env::var_os("RSRS_DATA_DIR").map(std::path::PathBuf::from)
            .unwrap_or_else(|| bge::expand_home("~/.rsrs"))
    }
    pub(crate) fn host_cache_dir() -> std::path::PathBuf { settings_dir().join("engines/openvino-cache") }
    fn read_inference_json() -> Result<(std::path::PathBuf, Value)> {
        let mut path = settings_dir().join("inference.json");
        if !path.exists() && crate::env::var_os("RSRS_DATA_DIR").is_none() {
            if let Some(home) = dirs::home_dir() {
                for legacy in [".respire", ".onememory"] {
                    let candidate = home.join(legacy).join("inference.json");
                    if candidate.exists() { path = candidate; break; }
                }
            }
        }
        let value = if path.exists() { serde_json::from_slice::<Value>(&std::fs::read(&path)?)? }
            else { json!({"engine":"cpu"}) };
        anyhow::ensure!(value.is_object(), "inference.json must contain an object");
        Ok((path, value))
    }
    fn stored_variant(value: &Value) -> Result<Option<ModelVariant>> {
        value.get("model").map(|model| {
            parse_variant(model.as_str().context("inference.json model must be a string")?)
        }).transpose()
    }
    pub fn configured_engine() -> Result<Engine> {
        if let Some((engine, _)) = crate::model_selection::selection() { return Ok(engine); }
        let (_, value) = read_inference_json()?;
        if value["force_cpu"].as_bool() == Some(true) { return Ok(Engine::Cpu); }
        if let Ok(value) = crate::env::var("RSRS_ENGINE") { return Engine::parse(&value); }
        match value["engine"].as_str().context("inference.json missing engine")? {
            "auto" => Ok(Engine::Cpu), value => Engine::parse(value),
        }
    }
    /// Selected onnx variant; falls back to the engine default when unset.
    pub fn configured_variant(engine: Engine) -> Result<ModelVariant> {
        if let Some((_, variant)) = crate::model_selection::selection() { return Ok(variant); }
        if let Ok(value) = crate::env::var("RSRS_MODEL_VARIANT") { return parse_variant(&value); }
        let (_, value) = read_inference_json()?;
        stored_variant(&value)?.map_or_else(|| parse_variant(default_variant(engine)), Ok)
    }
    /// Whether the operator picked a variant (setting or env), not the engine default.
    pub fn explicit_model_selection() -> Result<bool> {
        if crate::model_selection::selection().is_some() { return Ok(true); }
        if crate::env::var("RSRS_MODEL_VARIANT").is_ok() { return Ok(true); }
        let (_, value) = read_inference_json()?;
        Ok(stored_variant(&value)?.is_some())
    }
    pub fn inference_status() -> Result<Value> {
        if crate::worker::enabled() { return crate::worker::status(); }
        let mut status: Value = execute("engine_control", json!({"action":"inference_status"}))?;
        let diagnostics = crate::host::provider_diagnostics()?;
        if !diagnostics.is_empty() { status["provider_registration_errors"] = json!(diagnostics); }
        Ok(status)
    }
    pub(crate) fn engine_settings(engine: Engine, force_cpu: bool, model: Option<&str>) -> Result<(std::path::PathBuf, Value)> {
        let directory = settings_dir();
        let (_, existing) = read_inference_json()?;
        let selected = match model {
            Some(model) => Some(parse_variant(model)?),
            None => stored_variant(&existing)?,
        };
        let mut value = existing;
        value["engine"] = json!(engine);
        value["force_cpu"] = json!(force_cpu);
        if let Some(model) = selected { value["model"] = json!(model.name); }
        Ok((directory.join("inference.json"), value))
    }
    fn commit_engine_settings(path: &std::path::Path, value: &Value, reset: impl FnOnce() -> Result<()>) -> Result<()> {
        use std::io::Write;
        reset()?;
        let parent = path.parent().context("inference settings have no parent directory")?;
        std::fs::create_dir_all(parent)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(&serde_json::to_vec_pretty(value)?)?;
        temp.as_file().sync_all()?;
        temp.persist(path).map_err(|error| error.error)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn inference_config_lock() -> Result<std::fs::File> {
        let directory = settings_dir();
        std::fs::create_dir_all(&directory)?;
        let path = directory.join("inference.json.lock");
        let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        lock.lock()?;
        Ok(lock)
    }
    /// Thread-local draft for host preparation; does not change settings or sessions.
    pub fn with_selection<T>(engine: Engine, variant: &str, action: impl FnOnce() -> Result<T>) -> Result<T> {
        crate::model_selection::scoped(engine, parse_variant(variant)?, action)
    }
    /// Verify installed pinned files and the selected host path without loading or downloading.
    pub fn validate_selection(engine: Engine, variant: &str) -> Result<()> {
        let variant = parse_variant(variant)?;
        crate::model_selection::check_overrides(engine, variant)?;
        crate::model_selection::scoped(engine, variant, || crate::model_selection::validate(engine, variant))
    }
    /// Validate, load, infer and persist without ever downloading assets.
    pub fn load_selection(engine: Engine, variant: &str) -> Result<Value> {
        anyhow::ensure!(crate::profiles::current()?.is_none(),"library has an active model profile; use model switch to change it");
        let _gate = crate::model_selection::gate(true)?;
        let variant = parse_variant(variant)?;
        crate::model_selection::check_overrides(engine, variant)?;
        execute("host_load_selection", json!({"engine":engine,"variant":variant.name}))
    }
    pub fn save_engine(engine: Engine) -> Result<()> { save_engine_with_variant(engine, None) }
    pub fn save_engine_with_variant(engine: Engine, model: Option<&str>) -> Result<()> {
        save_engine_with_variant_revision(engine, model, None)?;
        Ok(())
    }
    pub fn save_engine_with_variant_revision(engine: Engine, model: Option<&str>, expected_revision: Option<&str>) -> Result<String> {
        anyhow::ensure!(crate::profiles::current()?.is_none(),"library has an active model profile; use model switch to change it");
        let _gate = crate::model_selection::gate(true)?;
        let _config_lock = inference_config_lock()?;
        let revision_path = settings_dir().join("inference.json");
        if let Some(expected) = expected_revision { ensure_engine_revision(&revision_path, expected)?; }
        let (path, value) = engine_settings(engine, false, model)?;
        commit_engine_settings(&path, &value, reset_sessions_locked)?;
        Ok(bytes_revision(&serde_json::to_vec_pretty(&value)?))
    }
    /// Persist an explicit model variant selection without touching the engine.
    pub fn save_model_variant(model: &str) -> Result<()> {
        anyhow::ensure!(crate::profiles::current()?.is_none(),"library has an active model profile; use model switch to change it");
        let _gate = crate::model_selection::gate(true)?;
        let _config_lock = inference_config_lock()?;
        let (path, mut value) = read_inference_json()?;
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        value["model"] = json!(parse_variant(model)?.name);
        if value.get("engine").is_none() { value["engine"] = json!("cpu"); }
        commit_engine_settings(&path, &value, || Ok(()))
    }
    pub fn reset_sessions() -> Result<()> {
        let _gate = crate::model_selection::gate(true)?;
        let _config_lock = inference_config_lock()?;
        reset_sessions_locked()
    }
    // The caller holds the model gate and inference configuration lock through reset.
    pub(crate) fn reset_sessions_locked() -> Result<()> {
        execute::<()>("engine_control", json!({"action":"reset"}))?;
        crate::host::reset_model_cache()
    }
    pub fn reset_cpu_config() -> Result<()> {
        let _gate = crate::model_selection::gate(true)?;
        let _config_lock = inference_config_lock()?;
        let (path, value) = engine_settings(Engine::Cpu, true, None)?;
        commit_engine_settings(&path, &value, || Ok(()))
    }
    fn bytes_revision(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
    }
    fn ensure_engine_revision(path: &std::path::Path, expected: &str) -> Result<()> {
        anyhow::ensure!(expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase()),
            "engine revision must be a lowercase SHA-256 digest");
        let actual = if path.exists() { std::fs::read(path)? } else { Vec::new() };
        anyhow::ensure!(bytes_revision(&actual) == expected,
            "engine revision conflict: inference settings changed since this operation started");
        Ok(())
    }
    #[cfg(windows)]
    pub fn accelerator_catalog_metadata() -> (std::path::PathBuf, u64, String) {
        use sha2::{Digest, Sha256};
        // Embedded bytes come from the pinned, SHA-256-verified official NuGet payload.
        let expected = crate::host_winml::DLL;
        (
            settings_dir().join("engines/winml-2.4.89/Microsoft.Windows.AI.MachineLearning.dll"),
            expected.len() as u64,
            format!("{:x}", Sha256::digest(expected)),
        )
    }
    pub fn accelerator_catalog_path() -> Result<Option<std::path::PathBuf>> {
        #[cfg(windows)] {
            let (dll, size, sha256) = accelerator_catalog_metadata();
            crate::model_selection::verify(&dll, size, &sha256)
                .context("assets_missing: Windows ML catalog is missing or invalid; install or repair it with the host CLI")?;
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
    #[cfg(test)]
    mod variant_settings_tests {
        use super::*;
        #[test]
        fn failed_session_reset_does_not_persist_a_partial_selection() -> Result<()> {
            let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
            let directory = std::env::temp_dir().join(format!("respire-engine-commit-{}-{nonce}",std::process::id()));
            std::fs::create_dir(&directory)?;
            let path = directory.join("inference.json");
            let previous = br#"{"engine":"cpu","model":"quantized"}"#;
            std::fs::write(&path, previous)?;
            let selected = json!({"engine":"gpu","model":"fp16","force_cpu":false});
            assert!(commit_engine_settings(&path, &selected, || anyhow::bail!("native reset failed")).is_err());
            assert_eq!(std::fs::read(&path)?, previous);
            commit_engine_settings(&path, &selected, || Ok(()))?;
            assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(&path)?)?, selected);
            std::fs::remove_dir_all(directory)?;
            Ok(())
        }
        #[test]
        fn missing_legacy_selection_is_distinct_from_malformed_selection() -> Result<()> {
            assert_eq!(stored_variant(&json!({"engine":"gpu"}))?, None);
            assert_eq!(stored_variant(&json!({"model":" FP16 "}))?.map(|v| v.name), Some("fp16"));
            for value in [json!(null), json!(1), json!(false), json!([]), json!({})] {
                assert!(stored_variant(&json!({"model":value})).is_err());
            }
            assert!(stored_variant(&json!({"model":"unknown"})).is_err());
            Ok(())
        }
        #[test]
        fn engine_revision_fence_rejects_changed_settings() -> Result<()> {
            let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!("respire-engine-revision-{}-{nonce}",std::process::id()));
            let previous = br#"{"engine":"cpu","model":"quantized"}"#;
            std::fs::write(&path, previous)?;
            ensure_engine_revision(&path, &bytes_revision(previous))?;
            assert!(ensure_engine_revision(&path, &bytes_revision(b"changed")).is_err());
            std::fs::remove_file(&path)?;
            Ok(())
        }
    }
    pub fn install_accelerators() -> Result<Vec<String>> { bail!("accelerator installation is host-managed; run rsrs model install-engines from the host CLI") }
}

pub mod defrag {
    use super::*;
    pub use super::reports::{Cluster, Member, Report};
    pub fn analyze(memories: &[StoredMemory], min: f32) -> Result<Report> { execute("analyze_duplicates", json!({"snapshots":metadata_snapshots(memories), "min":min})) }
}

pub mod reports;

//! Host-owned immutable model selections. Core receives only the execution config.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cell::RefCell, path::PathBuf, sync::RwLock};
use crate::onnx::Engine;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    #[serde(default)] pub download: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProfile {
    pub id: String,
    pub embedding: Value,
    #[serde(default)] pub onnx: Value,
    #[serde(default)] pub weights: Option<Resource>,
    #[serde(default)] pub tokenizer: Option<Resource>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProfile {
    pub provider: String,
    #[serde(default)] pub device_id: Option<String>,
    #[serde(default)] pub provider_options: std::collections::BTreeMap<String,String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendProfile {
    pub id: String,
    pub backend: String,
    #[serde(default)] pub native: Option<NativeProfile>,
    #[serde(default)] pub provider: Option<String>,
    #[serde(default)] pub protocol: Option<String>,
    #[serde(default)] pub endpoint: Option<String>,
    #[serde(default)] pub keyring_service: Option<String>,
    #[serde(default)] pub keyring_account: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub model: String,
    pub backend: String,
    pub engine: Engine,
    #[serde(default)] pub variant: Option<String>,
    pub profile: ModelProfile,
    pub backend_profile: BackendProfile,
    #[serde(default)] pub generation: String,
}

pub const ACTIVE_SELECTION_KEY: &str = "embedding.active.selection.v1";

thread_local! { static ACTIVE: RefCell<Option<Selection>> = const { RefCell::new(None) }; }
type Transport = fn(&Value, &Selection) -> Result<Value>;
static TRANSPORT: RwLock<Option<Transport>> = RwLock::new(None);
thread_local! { static DRAFT: RefCell<Option<Selection>> = const { RefCell::new(None) }; }

pub fn set_transport(callback: Transport) -> Result<()> {
    *TRANSPORT.write().map_err(|_| anyhow::anyhow!("embedding transport lock poisoned"))? = Some(callback);
    Ok(())
}

pub(crate) fn transport_available() -> Result<bool> { Ok(TRANSPORT.read().map_err(|_|anyhow::anyhow!("embedding transport lock poisoned"))?.is_some()) }
pub(crate) fn transport(request: &Value, selection: &Selection) -> Result<Value> {
    let callback = *TRANSPORT.read().map_err(|_| anyhow::anyhow!("embedding transport lock poisoned"))?;
    callback.context("host embedding transport is not configured")?(request, selection)
}
pub fn set_active(selection: Option<Selection>) {
    ACTIVE.with_borrow_mut(|slot| *slot = selection);
}
pub fn current() -> Result<Option<Selection>> {
    if let Some(selection) = DRAFT.with_borrow(Clone::clone) { return Ok(Some(selection)); }
    Ok(ACTIVE.with_borrow(Clone::clone))
}
pub fn scoped<T>(selection: Selection, action: impl FnOnce() -> Result<T>) -> Result<T> {
    struct Restore(Option<Selection>);
    impl Drop for Restore { fn drop(&mut self) { DRAFT.with_borrow_mut(|slot| *slot = self.0.take()); } }
    let _restore = Restore(DRAFT.with_borrow_mut(|slot| slot.replace(selection)));
    action()
}
impl Selection {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.model.trim().is_empty() && self.model == self.profile.id, "selection model/profile mismatch");
        anyhow::ensure!(self.backend == self.backend_profile.id, "selection backend/profile mismatch");
        anyhow::ensure!(matches!(self.backend_profile.backend.as_str(), "onnx" | "host_transport" | "mlx"), "unsupported embedding backend");
        if let Some(native) = &self.backend_profile.native {
            anyhow::ensure!(!native.provider.is_empty(),"native provider name is empty");
            anyhow::ensure!(self.backend_profile.backend == "onnx","native options require ONNX backend");
            if native.provider == "CPUExecutionProvider" { anyhow::ensure!(self.engine == Engine::Cpu,"CPU provider requires engine cpu"); }
        }
        let embedding = &self.profile.embedding;
        let allowed = ["model_id","revision","dimensions","max_tokens","pooling","normalize","query_prefix","document_prefix","pad_token_id","pad_to_max_tokens"];
        anyhow::ensure!(embedding.as_object().is_some_and(|fields| fields.keys().all(|key|allowed.contains(&key.as_str()))),"unknown embedding configuration field");
        anyhow::ensure!(embedding["model_id"].as_str().is_some_and(|v| !v.is_empty()) && embedding["revision"].as_str().is_some_and(|v| !v.is_empty()), "embedding model_id and immutable revision are required");
        anyhow::ensure!(embedding["dimensions"].as_u64().is_some_and(|v| v > 0 && v <= 65536) && embedding["max_tokens"].as_u64().is_some_and(|v| v >= 4 && v <= 131072), "invalid embedding dimensions/window");
        anyhow::ensure!(matches!(embedding["pooling"].as_str(), Some("cls" | "mean" | "sentence_embedding")) && embedding["normalize"].is_boolean(), "invalid pooling/normalization");
        for field in ["query_prefix", "document_prefix"] { anyhow::ensure!(embedding[field].is_string(), "embedding {field} must be a string"); }
        if matches!(self.backend_profile.backend.as_str(), "onnx" | "mlx") {
            for resource in [&self.profile.weights, &self.profile.tokenizer] {
                let resource = resource.as_ref().context("local embedding weights and tokenizer are required")?;
                anyhow::ensure!(resource.size > 0 && resource.sha256.len() == 64 && resource.sha256.bytes().all(|b| b.is_ascii_hexdigit()), "resource requires exact size and SHA-256");
            }
            if self.backend_profile.backend == "onnx" {
                for name in ["input_ids"] { anyhow::ensure!(self.profile.onnx[name].as_str().is_some_and(|v| !v.is_empty()), "missing ONNX tensor name {name}"); }
            } else {
                anyhow::ensure!(matches!(self.engine, Engine::Cpu | Engine::Gpu), "MLX backend accepts cpu or gpu");
                anyhow::ensure!(!self.profile.onnx.is_object() || self.profile.onnx.as_object().is_some_and(|fields| fields.is_empty()), "MLX profiles must not declare ONNX tensor names");
            }
        } else {
            anyhow::ensure!(self.engine == Engine::Cpu, "host_transport does not accept a local accelerator engine");
            anyhow::ensure!(self.backend_profile.protocol.as_deref() == Some("openai_embeddings") && self.backend_profile.provider.as_deref().is_some_and(|v| !v.is_empty()), "host transport requires provider and openai_embeddings protocol");
        }
        Ok(())
    }
    pub fn config(&self) -> Result<Value> {
        self.validate()?;
        let asset_id = if matches!(self.backend_profile.backend.as_str(), "onnx" | "mlx") {
            format!("{}:{}", self.profile.weights.as_ref().context("weights missing")?.sha256, self.profile.tokenizer.as_ref().context("tokenizer missing")?.sha256)
        } else { format!("{}:{}", self.profile.embedding["model_id"].as_str().context("model_id missing")?, self.profile.embedding["revision"].as_str().context("revision missing")?) };
        use sha2::{Digest,Sha256};
        let native_id = self.backend_profile.native.as_ref().map(|native| serde_json::to_vec(native).map(|bytes| format!("{:x}",Sha256::digest(bytes)))).transpose()?;
        let mut config = json!({"model":self.model,"backend":self.backend_profile.backend,"engine":self.engine,
            "asset_id":asset_id,"session_options_id":format!("profile-v1:{:?}:{:?}",self.engine,native_id),
            "embedding":self.profile.embedding,
            "execution_timeout_secs":120});
        if !self.profile.onnx.is_null() && !self.profile.onnx.as_object().is_some_and(|fields| fields.is_empty()) { config["onnx"] = self.profile.onnx.clone(); }
        if matches!(self.backend_profile.backend.as_str(), "onnx" | "mlx") {
            config["model_sha256"] = json!(self.profile.weights.as_ref().context("weights missing")?.sha256.to_ascii_lowercase());
            config["tokenizer_sha256"] = json!(self.profile.tokenizer.as_ref().context("tokenizer missing")?.sha256.to_ascii_lowercase());
        }
        if self.backend_profile.backend == "host_transport" {
            config["provider"] = json!(self.backend_profile.provider);
            config["protocol"] = json!(self.backend_profile.protocol);
        }
        if self.backend_profile.native.is_some() { config["host_execution_provider"] = json!(true); }
        if self.backend_profile.backend == "host_transport" {
            config["execution_identity"] = json!(format!("{:x}",Sha256::digest(serde_json::to_vec(&json!({"provider":self.backend_profile.provider,"protocol":self.backend_profile.protocol,"endpoint":self.backend_profile.endpoint}))?)));
        } else if let Some(identity) = native_id { config["execution_identity"] = json!(identity); }
        Ok(config)
    }
    pub fn verify(&self) -> Result<()> {
        self.validate()?;
        if matches!(self.backend_profile.backend.as_str(), "onnx" | "mlx") {
            for resource in [&self.profile.weights, &self.profile.tokenizer] {
                let resource = resource.as_ref().context("resource missing")?;
                crate::model_selection::verify(&resource.path, resource.size, &resource.sha256)?;
            }
        }
        Ok(())
    }
}
pub fn generation_key_for_profile(selection: &Selection) -> Result<String> {
    crate::execute("index_generation", json!({"model":selection.model,"config":selection.config()?}))
}

pub fn verify_resource(resource: &Resource) -> Result<()> { crate::model_selection::verify(&resource.path,resource.size,&resource.sha256) }
pub fn load(selection: &Selection) -> Result<Value> {
    selection.verify()?;
    exclusive(|| scoped(selection.clone(), || {
        crate::onnx::reset_sessions()?;
        crate::bge::BgeEmbedder::load_model(&selection.model)?.probe("Respire model load verification \u{672c}\u{5730}\u{63a8}\u{7406}\u{9a8c}\u{8bc1}")
    }))
}
static LOADED_CONFIG: std::sync::Mutex<Option<Value>> = std::sync::Mutex::new(None);
pub(crate) fn reset_cache() -> Result<()> {
    *LOADED_CONFIG.lock().map_err(|_| anyhow::anyhow!("profile model cache poisoned"))? = None;
    Ok(())
}
pub fn exclusive<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    let _gate = crate::model_selection::gate(true)?;
    action()
}
pub(crate) fn initialize(core: &mut crate::Core, selection: &Selection) -> Result<()> {
    selection.validate()?;
    let capabilities = core.capabilities()?;
    anyhow::ensure!(capabilities["embedding_profile_contract"].as_u64() == Some(1) && capabilities["embedding_transport_contract"].as_u64() == Some(1), "paired Core SDK with embedding profile/transport contract 1 is required");
    if selection.backend_profile.backend == "mlx" {
        anyhow::ensure!(capabilities["mlx_backend_contract"].as_u64() == Some(1), "the paired Core SDK was built without the Apple MLX backend; install a Core SDK built with the mlx feature");
    }
    let mut config = selection.config()?;
    let mut loaded = LOADED_CONFIG.lock().map_err(|_| anyhow::anyhow!("profile model cache poisoned"))?;
    if loaded.as_ref() == Some(&config) {
        let mut reuse = config.clone();
        reuse["reuse_current"] = json!(true);
        core.load_model(reuse, &[], &[])?;
        return Ok(());
    }
    *loaded = None;
    config["reuse_current"] = json!(false);
    let identity = selection.config()?;
    #[cfg(windows)]
    if selection.backend_profile.backend == "onnx" {
        crate::host::register_selected_catalog(selection.engine, || core.register_providers())?;
    }
    if selection.backend_profile.backend == "host_transport" { core.load_model(config, &[], &[])?; }
    else {
        selection.verify()?;
        let weights = std::fs::read(&selection.profile.weights.as_ref().context("weights missing")?.path)?;
        let tokenizer = std::fs::read(&selection.profile.tokenizer.as_ref().context("tokenizer missing")?.path)?;
        // Recheck the exact bytes passed to Core, including concurrent file replacement.
        use sha2::{Digest, Sha256};
        for (bytes, resource) in [(&weights, &selection.profile.weights), (&tokenizer, &selection.profile.tokenizer)] {
            let resource = resource.as_ref().context("resource missing")?;
            anyhow::ensure!(bytes.len() as u64 == resource.size && format!("{:x}",Sha256::digest(bytes)).eq_ignore_ascii_case(&resource.sha256), "model resource changed while loading");
        }
        core.load_model(config, &weights, &tokenizer)?;
    }
    *loaded = Some(identity);
    Ok(())
}

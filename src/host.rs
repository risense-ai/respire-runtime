//! Public host plumbing. Files remain opaque; all interpretation stays in Core.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Write, path::PathBuf, sync::Mutex};

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug)]
pub(crate) struct CorruptArtifact;
impl std::fmt::Display for CorruptArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("local index is corrupt; rebuild the local index")
    }
}
impl std::error::Error for CorruptArtifact {}

pub(crate) fn resolve(encoded: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(encoded)
        .context("invalid index artifact encoding")?;
    let Some(identity) = bytes.strip_prefix(b"rsi1:") else {
        return Ok(encoded.to_owned());
    };
    anyhow::ensure!(
        identity.len() == 64 && identity.iter().all(u8::is_ascii_hexdigit),
        "invalid local index locator"
    );
    let identity = std::str::from_utf8(identity)?;
    let bytes = std::fs::read(
        crate::business::index_root()?
            .join("core-index")
            .join(identity),
    )
    .context("local index is unavailable; rebuild the local index")?;
    if digest(&bytes) != identity {
        return Err(CorruptArtifact.into());
    }
    Ok(STANDARD.encode(bytes))
}

pub(crate) fn resolve_artifacts(value: &mut Value) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if name == "artifact" {
                    if let Some(encoded) = value.as_str() {
                        *value = json!(resolve(encoded)?);
                    }
                } else if name == "artifacts" {
                    if let Some(artifacts) = value.as_array_mut() {
                        for artifact in artifacts {
                            if let Some(encoded) = artifact.as_str() {
                                *artifact = json!(resolve(encoded)?);
                            }
                        }
                    }
                } else {
                    resolve_artifacts(value)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                resolve_artifacts(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn persist_prepared(value: &mut Value) -> Result<()> {
    let encoded = value["artifact"]
        .as_str()
        .context("Core preparation missing opaque artifact")?;
    let bytes = STANDARD.decode(encoded)?;
    let identity = digest(&bytes);
    let directory = crate::business::index_root()?.join("core-index");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(&identity);
    let ready = match std::fs::read(&path) {
        Ok(existing) => digest(&existing) == identity,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !ready {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temporary = directory.join(format!(
            ".{identity}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        drop(file);
        if let Err(error) = std::fs::rename(&temporary, &path) {
            let _ = std::fs::remove_file(&temporary);
            match std::fs::read(&path) {
                Ok(existing) if digest(&existing) == identity => {}
                _ => return Err(error.into()),
            }
        }
    }
    value["artifact"] = json!(STANDARD.encode(format!("rsi1:{identity}")));
    Ok(())
}

fn explicit_setting<T: std::str::FromStr + serde::Serialize>(
    settings: &mut serde_json::Map<String, Value>,
    key: &str,
    name: &str,
) -> Result<()> {
    match crate::env::var(name) {
        Ok(value) => {
            let value: T = value
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid {name}"))?;
            settings.insert(key.to_owned(), serde_json::to_value(value)?);
            Ok(())
        }
        Err(std::env::VarError::NotPresent) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn request_settings(payload: &mut Value) -> Result<()> {
    if let Some(fields) = payload.as_object_mut() {
        if !fields.contains_key("query_settings") {
            let mut settings = serde_json::Map::new();
            match crate::env::var("RSRS_ROUTE") {
                Ok(value) => { settings.insert("route_on".to_owned(), json!(value != "0")); }
                Err(std::env::VarError::NotPresent) => {}
                Err(error) => return Err(error.into()),
            }
            match crate::env::var("RSRS_ABLATE") {
                Ok(value) => { settings.insert("ablate".to_owned(), json!(value)); }
                Err(std::env::VarError::NotPresent) => {}
                Err(error) => return Err(error.into()),
            }
            explicit_setting::<f32>(&mut settings, "recall_min_score", "RSRS_RECALL_MIN_SCORE")?;
            explicit_setting::<f32>(&mut settings, "mmr_lambda", "RSRS_MMR_LAMBDA")?;
            explicit_setting::<usize>(&mut settings, "ancestor_budget", "RSRS_ANCESTOR_BUDGET")?;
            explicit_setting::<usize>(
                &mut settings,
                "ancestor_root_floor",
                "RSRS_ANCESTOR_ROOT_FLOOR",
            )?;
            fields.insert("query_settings".to_owned(), Value::Object(settings));
        }
        if !fields.contains_key("related_settings") {
            let mut settings = serde_json::Map::new();
            match crate::env::var("RSRS_RELATED") {
                Ok(value) => {
                    settings.insert("enabled".to_owned(), json!(value != "0"));
                }
                Err(std::env::VarError::NotPresent) => {}
                Err(error) => return Err(error.into()),
            }
            explicit_setting::<usize>(&mut settings, "max", "RSRS_RELATED_MAX")?;
            explicit_setting::<u64>(&mut settings, "pair_min", "RSRS_RELATED_PAIR_MIN")?;
            explicit_setting::<f32>(&mut settings, "min_cos", "RSRS_RELATED_MIN_COS")?;
            explicit_setting::<usize>(&mut settings, "knn_seeds", "RSRS_RELATED_KNN_SEEDS")?;
            explicit_setting::<usize>(&mut settings, "knn_per", "RSRS_RELATED_KNN_PER")?;
            fields.insert("related_settings".to_owned(), Value::Object(settings));
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
struct ModelStamp {
    directory: PathBuf,
    engine: crate::onnx::Engine,
    model: (u64, std::time::SystemTime),
    tokenizer: (u64, std::time::SystemTime),
    session_options_id: String,
}
struct LoadedModel {
    stamp: ModelStamp,
    asset_id: String,
}
static LOADED: Mutex<Option<LoadedModel>> = Mutex::new(None);
static PROVIDER_DIAGNOSTICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub(crate) fn provider_diagnostics() -> Result<Vec<String>> {
    Ok(PROVIDER_DIAGNOSTICS
        .lock()
        .map_err(|_| anyhow::anyhow!("host provider diagnostics poisoned"))?
        .clone())
}

fn model_cache() -> Result<std::sync::MutexGuard<'static, Option<LoadedModel>>> {
    // Match the resident Core queue's existing wait budget. A stuck native load
    // must not make host callers wait forever or start another model session.
    let started = std::time::Instant::now();
    loop {
        match LOADED.try_lock() {
            Ok(cache) => return Ok(cache),
            Err(std::sync::TryLockError::Poisoned(_)) => anyhow::bail!("host model cache poisoned"),
            Err(std::sync::TryLockError::WouldBlock) => {
                anyhow::ensure!(started.elapsed() < std::time::Duration::from_secs(120),
                    "model initialization wait timed out; no second session started; inspect the runtime model task or run rsrs restart from the host");
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
}

pub(crate) fn reset_model_cache() -> Result<()> {
    *model_cache()? = None;
    Ok(())
}

fn model_file_metadata(path: &std::path::Path, custom_cpu_file: bool) -> Result<(u64, std::time::SystemTime)> {
    let recovery = if custom_cpu_file {
        "correct or unset RSRS_CPU_OWNED_ORT_FILE; installing the default model does not repair this custom path"
    } else {
        "run rsrs model install-m3 in this profile before direct inference"
    };
    let metadata = std::fs::metadata(path).with_context(|| format!(
        "model file unavailable at {}; {recovery}", path.display()))?;
    Ok((metadata.len(), metadata.modified()?))
}

pub(crate) fn initialize_model(core: &mut crate::Core) -> Result<()> {
    let directory = crate::bge::resolve_model_dir()?;
    let engine = crate::onnx::configured_engine()?;
    let cpu_owned_experiment = crate::bge::cpu_owned_mode(engine)?;
    anyhow::ensure!(!cpu_owned_experiment || cfg!(feature = "cpu-owned-ort-experiment"), "CPU owned ORT experiment requires an experimental SDK build");
    anyhow::ensure!(!cpu_owned_experiment || engine == crate::onnx::Engine::Cpu, "CPU owned ORT experiment requires CPU; GPU/NPU remain legacy");
    anyhow::ensure!(!cpu_owned_experiment || crate::env::var_os("RSRS_ORT_PROFILE").is_none(),
        "CPU owned ORT experiment does not support host profiling callbacks; disable the experiment for legacy profiling");
    let model_path = if cpu_owned_experiment {
        crate::env::var_os("RSRS_CPU_OWNED_ORT_FILE").map(std::path::PathBuf::from)
            .unwrap_or_else(|| crate::bge::cpu_ort_path(&directory))
    } else { directory.join("onnx/model_quantized.onnx") };
    let tokenizer_path = directory.join("tokenizer.json");
    let metadata = |path: &std::path::Path| -> Result<_> {
        let custom_cpu_file = cpu_owned_experiment && path == model_path.as_path()
            && crate::env::var_os("RSRS_CPU_OWNED_ORT_FILE").is_some();
        model_file_metadata(path, custom_cpu_file)
    };
    let legacy_options_id = digest(
        format!(
            "{:?}:{:?}",
            crate::env::var_os("RSRS_ORT_PROFILE"),
            if cfg!(windows) && engine != crate::onnx::Engine::Cpu {
                Some(crate::onnx::host_cache_dir())
            } else {
                None
            }
        )
        .as_bytes(),
    );
    let session_options_id = if cpu_owned_experiment {
        digest(format!("cpu-owned-ort-v1:{legacy_options_id}:{}", model_path.display()).as_bytes())
    } else { legacy_options_id };
    #[cfg(test)]
    let session_options_id = if crate::ffi::test_option_failure_armed() {
        format!("test-failing-options:{session_options_id}")
    } else { session_options_id };
    let stamp = ModelStamp {
        directory,
        engine,
        model: metadata(&model_path)?,
        tokenizer: metadata(&tokenizer_path)?,
        session_options_id: session_options_id.clone(),
    };
    let mut loaded = model_cache()?;
    if let Some(existing) = loaded.as_ref().filter(|existing| existing.stamp == stamp) {
        let mut request = json!({"model":"m3", "asset_id":existing.asset_id,"engine":engine,
            "execution_timeout_secs":120,"session_options_id":session_options_id,"reuse_current":true});
        if cpu_owned_experiment { request["cpu_owned_ort_experiment"] = json!(true); }
        let reused = core.load_model(request, &[], &[]);
        if reused.is_ok() { return Ok(()); }
        // A reset or failed replacement may have retired the canonical group.
        // Cached reuse is initialization, not a replay of a business operation.
        *loaded = None;
    }
    #[cfg(model_input_stream_contract)]
    if cpu_owned_experiment {
        const MODEL_HASH: &str = "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff";
        const MODEL_BYTES: usize = 569654128;
        let tokenizer = std::fs::read(&tokenizer_path).context("read host BGE-M3 tokenizer")?;
        let tokenizer_hash = digest(&tokenizer);
        anyhow::ensure!(tokenizer_hash == "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790", "BGE-M3 tokenizer checksum mismatch; reinstall the model");
        let mut file = std::fs::File::open(&model_path).context("open host BGE-M3 model")?;
        anyhow::ensure!(file.metadata()?.len() == MODEL_BYTES as u64, "BGE-M3 model length mismatch");
        let mut input = core.begin_model_input(MODEL_BYTES)?;
        let model_hash = stream_model(&mut file, MODEL_BYTES, |bytes| input.append(bytes))?;
        anyhow::ensure!(model_hash == MODEL_HASH, "BGE-M3 model checksum mismatch; reinstall the model");
        drop(file);
        let asset_id = format!("{MODEL_HASH}:{tokenizer_hash}");
        let request = json!({"model":"m3", "asset_id":asset_id,"engine":engine,
            "execution_timeout_secs":120,"session_options_id":session_options_id,"reuse_current":false,"cpu_owned_ort_experiment":true});
        *loaded = None;
        *PROVIDER_DIAGNOSTICS.lock().map_err(|_| anyhow::anyhow!("host provider diagnostics poisoned"))? = Vec::new();
        input.commit(request, &tokenizer)?;
        *loaded = Some(LoadedModel { stamp, asset_id });
        return Ok(());
    }
    let model = std::fs::read(&model_path).context("read host BGE-M3 model (CPU upgrades are prepared by the runtime model task; run rsrs model install-m3 if unavailable)")?;
    let tokenizer = std::fs::read(&tokenizer_path).context("read host BGE-M3 tokenizer")?;
    let model_hash = digest(&model);
    let tokenizer_hash = digest(&tokenizer);
    anyhow::ensure!(
        model_hash == if cpu_owned_experiment {
            "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff"
        } else { "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d" },
        "BGE-M3 quantized model checksum mismatch; reinstall the model"
    );
    anyhow::ensure!(
        tokenizer_hash == "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
        "BGE-M3 tokenizer checksum mismatch; reinstall the model"
    );
    let asset_id = format!("{model_hash}:{tokenizer_hash}");
    let registration_errors: Vec<String> = {
        #[cfg(windows)]
        {
            if engine != crate::onnx::Engine::Cpu {
                core.register_providers()?
            } else {
                Vec::new()
            }
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    };
    *PROVIDER_DIAGNOSTICS
        .lock()
        .map_err(|_| anyhow::anyhow!("host provider diagnostics poisoned"))? =
        registration_errors.clone();
    // Core retires the old group before constructing a replacement. Its failure
    // leaves no usable canonical group; never preserve an apparently live stamp.
    *loaded = None;
    let mut request = json!({"model":"m3", "asset_id":asset_id,"engine":engine,
        "execution_timeout_secs":120,"session_options_id":session_options_id,"reuse_current":false});
    if cpu_owned_experiment { request["cpu_owned_ort_experiment"] = json!(true); }
    let loaded_model = core.load_model(request, &model, &tokenizer);
    if registration_errors.is_empty() {
        loaded_model?;
    } else {
        loaded_model.with_context(|| {
            format!(
                "optional provider registration failures: {}",
                registration_errors.join("; ")
            )
        })?;
    }
    *loaded = Some(LoadedModel { stamp, asset_id });
    Ok(())
}

#[cfg(model_input_stream_contract)]
fn stream_model(reader: &mut impl std::io::Read, expected: usize, mut append: impl FnMut(&[u8]) -> Result<()>) -> Result<String> {
    let mut chunk = vec![0u8; 1 << 20];
    let mut hasher = Sha256::new();
    let mut received = 0usize;
    loop {
        let count = match reader.read(&mut chunk) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.context("stream host BGE-M3 model")?,
        };
        if count == 0 { break; }
        received = received.checked_add(count).context("model length overflow")?;
        anyhow::ensure!(received <= expected, "BGE-M3 model grew during read");
        hasher.update(&chunk[..count]);
        append(&chunk[..count])?;
    }
    anyhow::ensure!(received == expected, "short BGE-M3 model read");
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(all(test, model_input_stream_contract))]
mod stream_tests {
    use super::*;
    #[test]
    fn bounded_stream_short_long_failure_and_digest() -> Result<()> {
        let source = b"synthetic model bytes";
        let mut received = Vec::new();
        let hash = stream_model(&mut &source[..], source.len(), |bytes| { received.extend_from_slice(bytes); Ok(()) })?;
        assert_eq!(received, source);
        assert_eq!(hash, digest(source));
        assert!(stream_model(&mut &source[..], source.len()+1, |_| Ok(())).is_err());
        assert!(stream_model(&mut &source[..], source.len()-1, |_| Ok(())).is_err());
        assert!(stream_model(&mut &source[..], source.len(), |_| anyhow::bail!("injected append failure")).is_err());
        struct Broken;
        impl std::io::Read for Broken { fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> { Err(std::io::Error::other("injected read failure")) } }
        assert!(stream_model(&mut Broken, source.len(), |_| Ok(())).is_err());
        Ok(())
    }
}

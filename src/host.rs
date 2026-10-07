//! Public host plumbing. Files remain opaque; all interpretation stays in Core.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Write, path::PathBuf, sync::Mutex};

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

fn resolve(encoded: &str) -> Result<String> {
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

pub(crate) fn initialize_model(core: &mut crate::Core) -> Result<()> {
    let directory = crate::bge::resolve_model_dir()?;
    let engine = crate::onnx::configured_engine()?;
    let model_path = directory.join("onnx/model_quantized.onnx");
    let tokenizer_path = directory.join("tokenizer.json");
    let metadata = |path: &std::path::Path| -> Result<_> {
        let metadata = std::fs::metadata(path)?;
        Ok((metadata.len(), metadata.modified()?))
    };
    let session_options_id = digest(
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
    let stamp = ModelStamp {
        directory,
        engine,
        model: metadata(&model_path)?,
        tokenizer: metadata(&tokenizer_path)?,
        session_options_id: session_options_id.clone(),
    };
    let mut loaded = model_cache()?;
    if let Some(existing) = loaded.as_ref().filter(|existing| existing.stamp == stamp) {
        core.load_model(json!({"model":"m3", "asset_id":existing.asset_id,"engine":engine,
            "execution_timeout_secs":120,"session_options_id":session_options_id,"reuse_current":true}), &[], &[])?;
        return Ok(());
    }
    let model = std::fs::read(&model_path).context("read host BGE-M3 model")?;
    let tokenizer = std::fs::read(&tokenizer_path).context("read host BGE-M3 tokenizer")?;
    let model_hash = digest(&model);
    let tokenizer_hash = digest(&tokenizer);
    anyhow::ensure!(
        model_hash == "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
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
    let loaded_model = core.load_model(json!({"model":"m3", "asset_id":asset_id,"engine":engine,
        "execution_timeout_secs":120,"session_options_id":session_options_id,"reuse_current":false}), &model, &tokenizer);
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

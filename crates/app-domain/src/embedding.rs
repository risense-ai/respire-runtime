//! Host model registry, resource preparation and remote embedding transport.
use crate::core_sdk::onnx::{Engine, MODEL_VARIANTS};
use crate::core_sdk::profiles::{BackendProfile, ModelProfile, Resource, Selection};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Default, Serialize, Deserialize)]
pub struct Registry {
    pub models: BTreeMap<String, ModelProfile>,
    pub backends: BTreeMap<String, BackendProfile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configure {
    pub model_profile: Option<ModelProfile>,
    pub backend_profile: Option<BackendProfile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub model: String,
    pub backend: String,
    #[serde(default)]
    pub engine: Engine,
    #[serde(default)]
    pub variant: Option<String>,
}
fn registry_path() -> PathBuf {
    crate::service::main_data_dir().join("embedding-profiles-v1.json")
}

pub fn saved_selection() -> Result<Option<Selection>> {
    use rusqlite::OptionalExtension;
    let path = crate::service::database_path(&crate::service::data_dir())?;
    if !path.is_file() {
        return Ok(None);
    }
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let saved: Option<String> = connection
        .query_row(
            "SELECT value FROM meta WHERE key=?1",
            [crate::core_sdk::profiles::ACTIVE_SELECTION_KEY],
            |row| row.get(0),
        )
        .optional()?;
    saved
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .transpose()
}
fn resource(
    root: &std::path::Path,
    file: &str,
    size: u64,
    hash: &str,
    repo: &str,
    revision: &str,
) -> Resource {
    Resource {
        path: root.join(file),
        size,
        sha256: hash.to_owned(),
        download: Some(format!(
            "https://huggingface.co/{repo}/resolve/{revision}/{file}"
        )),
    }
}
pub fn registry() -> Result<Registry> {
    let mut registry = Registry::default();
    let root = crate::service::main_data_dir().join("models");
    let m3_revision = "4de13258303883538bd53b696b452bf8099f0858";
    let small_revision = "75c43b069aac4d136ba6bc1122f995fedcfd2781";
    for (id, repo, revision, dims, directory, size, hash, tokenizer_size, tokenizer_hash, prefix) in [
        ("m3", "Xenova/bge-m3", m3_revision, 1024, crate::core_sdk::bge::m3_model_dir()?, 569694530, "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d", 17082821, "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790", ""),
        ("bge-small-zh-v1.5", "Xenova/bge-small-zh-v1.5", small_revision, 512, root.join("bge-small-zh-v1.5"), 24010842, "15b717c382bcb518ba457b93ea6850ede7f4f1cd8937454aa06972366cd19bcc", 439125, "48cea5d44424912a6fd1ea647bf4fe50b55ab8b1e5879c3275f80e339e8fae26", "\u{4e3a}\u{8fd9}\u{4e2a}\u{53e5}\u{5b50}\u{751f}\u{6210}\u{8868}\u{793a}\u{4ee5}\u{7528}\u{4e8e}\u{68c0}\u{7d22}\u{76f8}\u{5173}\u{6587}\u{7ae0}\u{ff1a}"),
    ] {
        registry.models.insert(id.to_owned(), ModelProfile { id:id.to_owned(),
            embedding:json!({"model_id":repo,"revision":revision,"dimensions":dims,"max_tokens":512,"pooling":"cls","normalize":true,"query_prefix":prefix,"document_prefix":"","pad_token_id":0,"pad_to_max_tokens":false}),
            onnx:json!({"input_ids":"input_ids","attention_mask":"attention_mask","token_type_ids":"token_type_ids","output":"last_hidden_state"}),
            weights:Some(resource(&directory,"onnx/model_quantized.onnx",size,hash,repo,revision)),
            tokenizer:Some(resource(&directory,"tokenizer.json",tokenizer_size,tokenizer_hash,repo,revision)),
        });
    }
    let mlx_revision = "a37eddded9a6a1273a87fb8b0da0d1cdbd98aeec";
    let mlx_root = root.join("bge-m3-mlx");
    registry.models.insert("m3-mlx".to_owned(), ModelProfile {
        id: "m3-mlx".to_owned(),
        embedding: json!({"model_id":"mlx-community/bge-m3-mlx-fp16","revision":mlx_revision,"dimensions":1024,"max_tokens":512,"pooling":"cls","normalize":true,"query_prefix":"","document_prefix":"","pad_token_id":0,"pad_to_max_tokens":false}),
        onnx: Value::Null,
        weights: Some(resource(&mlx_root,"model.safetensors",1_135_554_209,"e8028acb2e77e0010d35ef75832d823edb5851c95682deef2bde86a45bd4441d","mlx-community/bge-m3-mlx-fp16",mlx_revision)),
        tokenizer: Some(resource(&mlx_root,"tokenizer.json",17_098_085,"5df1f55d60c9705a501ab9a75550728625740741fe4be308dac4806c16b7d51d","mlx-community/bge-m3-mlx-fp16",mlx_revision)),
    });
    // Built-in profile pins only; the runtime never downloads or installs these assets.
    // The Granite ONNX graphs expose input_ids/attention_mask only, so token_type_ids
    // is deliberately absent from the onnx tensor map.
    let granite_onnx = json!({"input_ids":"input_ids","attention_mask":"attention_mask","output":"last_hidden_state"});
    for (id, repo, revision, dims, directory, weights_file, weights_size, weights_hash, tokenizer_size, tokenizer_hash, pad_token_id) in [
        ("granite-97m-r2", "ibm-granite/granite-embedding-97m-multilingual-r2", "835ad14087e140460703cf0fae09f97d469d65c2", 384, root.join("granite-97m-r2"), "onnx/model.onnx", 390004608u64, "68e592b160673d30250824c1116bc6ab33f70efb22b97c9e1d7ce1e69c1c9d70", 25301672u64, "4f2842d568e2724370aec203652a42ac783c7937f8347a1a2cc7506d71f1582f", 179935),
        ("granite-311m-r2", "ibm-granite/granite-embedding-311m-multilingual-r2", "44399559930365213510b1ee2eb15ded83374f0e", 768, root.join("granite-311m-r2"), "onnx/model_quint8_avx2.onnx", 313421909u64, "f1fdd44e7e1ac51f12ab7957c7bd092e064d596c288513bf9d326842f669edee", 33384821u64, "0087c868b33bad550a78a08d19798cfd7f713cde4f020803b8f51f405503e15f", 0),
    ] {
        registry.models.insert(id.to_owned(), ModelProfile {
            id: id.to_owned(),
            embedding: json!({"model_id":repo,"revision":revision,"dimensions":dims,"max_tokens":32768,"pooling":"cls","normalize":true,"query_prefix":"","document_prefix":"","pad_token_id":pad_token_id,"pad_to_max_tokens":false}),
            onnx: granite_onnx.clone(),
            weights: Some(resource(&directory, weights_file, weights_size, weights_hash, repo, revision)),
            tokenizer: Some(resource(&directory, "tokenizer.json", tokenizer_size, tokenizer_hash, repo, revision)),
        });
    }
    registry.backends.insert(
        "onnx".to_owned(),
        BackendProfile {
            id: "onnx".to_owned(),
            backend: "onnx".to_owned(),
            native: None,
            provider: None,
            protocol: None,
            endpoint: None,
            keyring_service: None,
            keyring_account: None,
        },
    );
    registry.backends.insert(
        "mlx".to_owned(),
        BackendProfile {
            id: "mlx".to_owned(),
            backend: "mlx".to_owned(),
            native: None,
            provider: None,
            protocol: None,
            endpoint: None,
            keyring_service: None,
            keyring_account: None,
        },
    );
    match std::fs::read(registry_path()) {
        Ok(bytes) => {
            let saved: Registry = serde_json::from_slice(&bytes)?;
            registry.models.extend(saved.models);
            registry.backends.extend(saved.backends);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(registry)
}
static REGISTRY_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn configure(configure: Configure) -> Result<Value> {
    let _write = REGISTRY_WRITE
        .lock()
        .map_err(|_| anyhow::anyhow!("profile registry lock poisoned"))?;
    anyhow::ensure!(
        configure.model_profile.is_some() || configure.backend_profile.is_some(),
        "configuration must include a model_profile or backend_profile"
    );
    let mut registry = registry()?;
    if let Some(model) = configure.model_profile {
        anyhow::ensure!(!model.id.trim().is_empty(), "model profile ID is empty");
        registry.models.insert(model.id.clone(), model);
    }
    if let Some(backend) = configure.backend_profile {
        anyhow::ensure!(!backend.id.trim().is_empty(), "backend profile ID is empty");
        if backend.backend == "host_transport" {
            validate_url(
                backend
                    .endpoint
                    .as_deref()
                    .context("embedding endpoint required")?,
            )?;
            anyhow::ensure!(
                backend.protocol.as_deref() == Some("openai_embeddings"),
                "unsupported embedding protocol"
            );
        } else {
            anyhow::ensure!(
                matches!(backend.backend.as_str(), "onnx" | "mlx"),
                "unsupported embedding backend"
            );
        }
        registry.backends.insert(backend.id.clone(), backend);
    }
    let path = registry_path();
    let parent = path.parent().context("registry parent missing")?;
    std::fs::create_dir_all(parent)?;
    let staged = parent.join(format!("embedding-profiles-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)?;
        file.write_all(&serde_json::to_vec_pretty(&registry)?)?;
        file.sync_all()?;
        std::fs::rename(&staged, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result?;
    Ok(json!({"saved":true,"activated":false,"registry":registry}))
}
pub fn select(choice: Choice) -> Result<Selection> {
    let registry = registry()?;
    let mut profile = registry
        .models
        .get(&choice.model)
        .context("unknown model profile")?
        .clone();
    if let Some(variant) = choice.variant.as_deref() {
        if choice.model == "m3" {
            let variant = MODEL_VARIANTS
                .iter()
                .find(|v| v.name == variant)
                .context("unknown M3 variant")?;
            let original = profile.weights.as_ref().context("M3 weights missing")?;
            let directory = original
                .path
                .parent()
                .and_then(|p| p.parent())
                .context("M3 model root missing")?;
            profile.weights = Some(resource(
                directory,
                &format!("onnx/model_{}.onnx", variant.name),
                variant.size,
                variant.sha256,
                "Xenova/bge-m3",
                "4de13258303883538bd53b696b452bf8099f0858",
            ));
        } else if choice.model == "m3-mlx" {
            anyhow::ensure!(
                variant == "fp16",
                "m3-mlx supports only the fp16 MLX conversion"
            );
        } else {
            anyhow::ensure!(variant == "quantized", "custom models select resource paths in their profile; preset small supports quantized");
        }
    }
    let selection = Selection {
        model: choice.model,
        backend: choice.backend.clone(),
        engine: choice.engine,
        variant: choice.variant,
        profile,
        backend_profile: registry
            .backends
            .get(&choice.backend)
            .context("unknown backend profile")?
            .clone(),
        generation: String::new(),
    };
    selection.validate()?;
    Ok(selection)
}
fn validate_url(url: &str) -> Result<()> {
    let (scheme, remainder) = url
        .split_once("://")
        .context("absolute embedding URL required")?;
    let authority = remainder.split('/').next().unwrap_or("");
    anyhow::ensure!(
        !authority.is_empty()
            && !url.chars().any(char::is_whitespace)
            && !url.contains(['@', '?', '#', '\\']),
        "embedding URL cannot contain credentials, query or fragment"
    );
    let loopback = ["localhost", "127.0.0.1", "[::1]"].iter().any(|host| {
        authority == *host
            || authority
                .strip_prefix(host)
                .is_some_and(|v| v.starts_with(':') && v[1..].bytes().all(|b| b.is_ascii_digit()))
    });
    anyhow::ensure!(
        scheme == "https" || (scheme == "http" && loopback),
        "embedding URL requires HTTPS (HTTP is allowed only for loopback fixtures)"
    );
    Ok(())
}
pub fn install_transport() -> Result<()> {
    crate::core_sdk::profiles::set_transport(embedding_request)
}
fn embedding_request(request: &Value, selection: &Selection) -> Result<Value> {
    let backend = &selection.backend_profile;
    anyhow::ensure!(
        request["operation"] == "embedding"
            && request["protocol"] == "openai_embeddings"
            && request["provider"].as_str() == backend.provider.as_deref()
            && backend.protocol.as_deref() == Some("openai_embeddings"),
        "embedding callback/provider mismatch"
    );
    let endpoint = backend
        .endpoint
        .as_deref()
        .context("embedding endpoint is missing")?;
    validate_url(endpoint)?;
    let model = request["model"]
        .as_str()
        .context("embedding callback model is missing")?;
    let input = request["input"]
        .as_array()
        .context("embedding callback input is missing")?;
    anyhow::ensure!(
        Some(model) == selection.profile.embedding["model_id"].as_str()
            && !input.is_empty()
            && input.iter().all(Value::is_string),
        "invalid embedding callback input"
    );
    let body = json!({"model":model,"input":input});
    let timeout = request["timeout"]
        .as_u64()
        .filter(|seconds| *seconds > 0)
        .context("embedding callback timeout missing")?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(timeout))
        .redirects(0)
        .build();
    let mut call = agent.post(endpoint);
    match (&backend.keyring_service, &backend.keyring_account) {
        (Some(service), Some(account)) => {
            let secret = keyring::Entry::new(service, account)?
                .get_password()
                .map_err(|_| anyhow::anyhow!("embedding credential unavailable in OS keyring"))?;
            call = call.set("Authorization", &format!("Bearer {secret}"));
        }
        (None, None) => (),
        _ => anyhow::bail!("embedding keyring service and account must be configured together"),
    }
    let response = call.send_json(body.clone()).map_err(|error| match error {
        ureq::Error::Status(status, _) => {
            anyhow::anyhow!("embedding provider HTTP status {status}")
        }
        _ => anyhow::anyhow!("embedding provider transport failed"),
    })?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        "embedding provider response is too large"
    );
    serde_json::from_slice(&bytes).context("invalid embedding provider JSON")
}

/// Resource downloads are staged and resumable; the active library is never changed.
pub fn prepare(
    selection: &Selection,
    mut progress: impl FnMut(&str, u64, Option<u64>) -> Result<()>,
) -> Result<()> {
    selection.validate()?;
    if selection.backend_profile.backend == "host_transport" {
        return Ok(());
    }
    for resource in [&selection.profile.weights, &selection.profile.tokenizer] {
        let resource = resource.as_ref().context("resource missing")?;
        if resource.path.is_file() {
            // Existing corrupt files are errors, never silently replaced by a download.
            crate::core_sdk::profiles::verify_resource(resource)?;
            continue;
        }
        let url = resource
            .download
            .as_deref()
            .context("resource missing and no download URL configured")?;
        validate_url(url)?;
        let parent = resource.path.parent().context("resource parent missing")?;
        std::fs::create_dir_all(parent)?;
        let partial = resource
            .path
            .with_extension(format!("{}.part", resource.sha256));
        let offset = std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0);
        anyhow::ensure!(
            offset <= resource.size,
            "partial resource exceeds expected size"
        );
        if offset == resource.size {
            let mut staged = resource.clone();
            staged.path = partial.clone();
            crate::core_sdk::profiles::verify_resource(&staged)?;
            progress(
                &resource.path.to_string_lossy(),
                offset,
                Some(resource.size),
            )?;
            std::fs::rename(&partial, &resource.path)?;
            continue;
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(std::time::Duration::from_secs(30))
            .build();
        let mut call = agent.get(url);
        if offset > 0 {
            call = call.set("Range", &format!("bytes={offset}-"));
        }
        let response = call
            .call()
            .map_err(|_| anyhow::anyhow!("model resource download failed"))?;
        let resume = offset > 0 && response.status() == 206;
        if resume {
            anyhow::ensure!(
                response
                    .header("Content-Range")
                    .is_some_and(|v| v.starts_with(&format!("bytes {offset}-"))),
                "invalid download Range response"
            );
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(resume)
            .truncate(!resume)
            .open(&partial)?;
        let mut done = if resume { offset } else { 0 };
        let mut reader = response.into_reader();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            progress(&resource.path.to_string_lossy(), done, Some(resource.size))?;
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            done += count as u64;
            anyhow::ensure!(
                done <= resource.size,
                "resource download exceeds pinned size"
            );
            file.write_all(&buffer[..count])?;
        }
        file.sync_all()?;
        drop(file);
        let mut staged = resource.clone();
        staged.path = partial.clone();
        crate::core_sdk::profiles::verify_resource(&staged)?;
        progress(&resource.path.to_string_lossy(), done, Some(resource.size))?;
        std::fs::rename(&partial, &resource.path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granite_builtin_profiles_are_registered_and_valid() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let registry = registry()?;
        for id in ["granite-97m-r2", "granite-311m-r2"] {
            let profile = registry
                .models
                .get(id)
                .with_context(|| format!("missing built-in profile {id}"))?;
            assert_eq!(profile.id, id);
            // The Granite graphs have no token_type_ids input.
            assert!(profile.onnx.get("token_type_ids").is_none());
            let selection = Selection {
                model: id.to_owned(),
                backend: "onnx".to_owned(),
                engine: crate::core_sdk::onnx::Engine::Cpu,
                variant: None,
                profile: profile.clone(),
                backend_profile: registry
                    .backends
                    .get("onnx")
                    .context("missing built-in onnx backend")?
                    .clone(),
                generation: String::new(),
            };
            selection.validate()?;
        }
        let nine = &registry.models["granite-97m-r2"];
        assert_eq!(nine.embedding["dimensions"], 384);
        assert_eq!(nine.embedding["pad_token_id"], 179935);
        let large = &registry.models["granite-311m-r2"];
        assert_eq!(large.embedding["dimensions"], 768);
        assert_eq!(large.embedding["pad_token_id"], 0);
        Ok(())
    }
}

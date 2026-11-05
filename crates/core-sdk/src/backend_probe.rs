//! Fresh native diagnostics, isolated from business model/worker caches.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::{Path, PathBuf}};

#[allow(unsafe_code)]
mod native;

fn file_hash(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path).context("read probe module/resource")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn address(value: &Value, nullable: bool) -> Result<usize> {
    let text = value.as_str().and_then(|value| value.strip_prefix("0x")).context("invalid borrowed native address encoding")?;
    let address = usize::from_str_radix(text, 16).context("invalid borrowed native address")?;
    anyhow::ensure!(nullable || address != 0, "null borrowed native address");
    Ok(address)
}

fn sdk_pin() -> Result<Value> {
    let platform = if cfg!(windows) { "pc-windows-msvc" } else if cfg!(target_os = "macos") { "apple-darwin" }
        else if cfg!(all(target_os = "linux", target_env = "musl")) { "unknown-linux-musl" }
        else if cfg!(target_os = "linux") { "unknown-linux-gnu" } else { anyhow::bail!("unsupported probe SDK target") };
    let target = format!("{}-{platform}", std::env::consts::ARCH);
    let pins: Value = serde_json::from_str(include_str!("../core-sdk.lock.json"))?;
    let pin = &pins["targets"][&target];
    anyhow::ensure!(pin["manifest_sha256"].as_str().is_some_and(|hash| hash.len() == 64), "compiled SDK target has no trusted manifest pin");
    Ok(json!({"target":target,"sdk_version":pin["sdk_version"],"manifest_sha256":pin["manifest_sha256"]}))
}

struct Resources {
    executable: PathBuf,
    pinned: BTreeMap<PathBuf, (String, String)>,
    #[cfg(windows)]
    libraries: BTreeMap<PathBuf, native::LoadedLibrary>,
    #[cfg(windows)]
    providers: Vec<crate::host_winml::Provider>,
    dynamic_ort: bool,
}

impl Resources {
    fn load(engine: crate::onnx::Engine) -> Result<Self> {
        let executable = std::fs::canonicalize(std::env::current_exe()?)?;
        let root = executable.parent().context("probe executable has no directory")?;
        let mut result = Self { executable: executable.clone(), pinned: BTreeMap::new(), dynamic_ort: false,
            #[cfg(windows)] libraries: BTreeMap::new(), #[cfg(windows)] providers: Vec::new() };
        for &(name, expected) in crate::RUNTIME_FILES {
            anyhow::ensure!(!name.is_empty() && !name.contains(['/', '\\']) && name != "." && name != "..", "invalid pinned runtime resource name");
            let lower = name.to_ascii_lowercase();
            // Archives/import libraries are link inputs, not deployed runtime resources.
            if lower.ends_with(".a") || lower.ends_with(".lib") { continue; }
            let path = std::fs::canonicalize(root.join(name)).context("pinned runtime resource missing beside executable")?;
            anyhow::ensure!(path.parent() == Some(root), "pinned runtime resource resolves outside executable directory");
            anyhow::ensure!(file_hash(&path)? == expected, "runtime resource checksum differs from compiled SDK pin");
            result.dynamic_ort |= lower == "onnxruntime.dll" || lower.starts_with("libonnxruntime.so") || lower == "libonnxruntime.dylib";
            result.pinned.insert(path, (name.to_owned(), expected.to_owned()));
        }
        #[cfg(windows)]
        {
            for path in result.pinned.keys().filter(|path| path.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))) {
                result.libraries.insert(path.clone(), native::load_library(path)?);
            }
            if engine == crate::onnx::Engine::Npu {
                // Catalog paths/ready flags are not trusted provider checksums.
                for mut provider in crate::onnx::host_providers()? {
                    if !provider.ready { continue; }
                    let Some(path) = provider.path.as_ref() else { continue; };
                    let path = std::fs::canonicalize(path).context("resolve catalog provider library")?;
                    if result.pinned.contains_key(&path) {
                        provider.path = Some(path);
                        result.providers.push(provider);
                    }
                }
                anyhow::ensure!(!result.providers.is_empty(), "NPU unavailable: no catalog provider library has a trusted compiled SDK pin");
            }
        }
        #[cfg(not(windows))]
        anyhow::ensure!(engine == crate::onnx::Engine::Cpu, "accelerator module identity verification is unsupported on this host; CPU probe remains available");
        Ok(result)
    }

    fn module(&self, path: &Path) -> Result<Value> {
        let path = std::fs::canonicalize(path)?;
        let hash = file_hash(&path)?;
        if let Some((id, expected)) = self.pinned.get(&path) {
            anyhow::ensure!(&hash == expected, "loaded module differs from its compiled pin");
            Ok(json!({"id":id,"sha256":hash,"symbols":{}}))
        } else {
            // Static SDK code must map into this executable, not an adjacent .a/.lib file.
            anyhow::ensure!(!self.dynamic_ort && path == self.executable, "runtime function resolved to an unpinned loaded module");
            Ok(json!({"id":"linked-sdk-executable","sha256":hash,"symbols":{}}))
        }
    }

    fn verify(&self, observation: &Value, provider: &str) -> Result<Value> {
        anyhow::ensure!(observation["fresh_session"] == true && observation["inference_completed"] == true, "Core did not prove fresh load and inference");
        anyhow::ensure!(observation["runtime"]["kind"] == "onnxruntime", "unsupported native module observation");
        let mut modules = BTreeMap::<PathBuf, Value>::new();
        for name in ["CreateSessionFromArray", "Run"] {
            let raw = &observation["runtime"]["symbols"][name];
            let path = std::fs::canonicalize(native::module_path(address(raw, false)?)?)?;
            if !modules.contains_key(&path) { modules.insert(path.clone(), self.module(&path)?); }
            modules.get_mut(&path).context("loaded module identity missing")?["symbols"][name] = raw.clone();
        }
        #[cfg(windows)]
        if provider == "DmlExecutionProvider" {
            let (path, library) = self.libraries.iter().find(|(path, _)| path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.eq_ignore_ascii_case("DirectML.dll")))
                .context("DirectML unavailable: no trusted DirectML runtime pin")?;
            anyhow::ensure!(std::fs::canonicalize(native::symbol_path(library, b"DMLCreateDevice\0")?)? == *path, "DirectML export resolved outside its pinned module");
            if !modules.contains_key(path) { modules.insert(path.clone(), self.module(path)?); }
        }
        #[cfg(windows)]
        if provider != "CPUExecutionProvider" && provider != "DmlExecutionProvider" {
            let selected = self.providers.iter().find(|candidate| candidate.name == provider).context("selected provider has no trusted catalog pin")?;
            let path = std::fs::canonicalize(selected.path.as_ref().context("selected provider library missing")?)?;
            let library = self.libraries.get(&path).context("selected provider was not loaded from its trusted pin")?;
            anyhow::ensure!(std::fs::canonicalize(native::symbol_path(library, b"CreateEpFactories\0")?)? == path, "provider factory export resolved outside its pinned module");
            modules.entry(path.clone()).or_insert(self.module(&path)?);
        }
        // Re-read every pinned data dependency too; file presence alone is not resource verification.
        for (path, (_, expected)) in &self.pinned { anyhow::ensure!(file_hash(path)? == *expected, "pinned runtime resource changed during probe"); }
        Ok(json!({"verified":true,"resources_verified":true,"provider":provider,
            "runtime_api_version":observation["runtime"]["api_version"],"modules":modules.into_values().collect::<Vec<_>>()}))
    }
}

pub(crate) fn sanitized(observation: &Value, pin: &Value) -> Result<Value> {
    anyhow::ensure!(observation["ready"] == true && observation["status"] == "loaded", "Core did not return loaded readiness");
    anyhow::ensure!(observation["fresh_session"] == true && observation["inference_completed"] == true
        && observation["host_identity"]["verified"] == true && observation["host_identity"]["resources_verified"] == true,
        "Core readiness is missing fresh native execution or verified module evidence");
    let modules = observation["host_identity"]["modules"].as_array().context("probe module identities missing")?
        .iter().map(|module| json!({"id":module["id"],"sha256":module["sha256"]})).collect::<Vec<_>>();
    Ok(json!({"contract":1,"status":"loaded","ready":true,"backend":observation["backend"],"engine":observation["engine"],
        "selected":observation["selected"],"provider":observation["host_identity"]["provider"],"fresh_session":true,
        "inference_completed":true,"model":observation["model"],"index_identity":observation["index_identity"],
        "dimensions":observation["dimensions"],"node_assignment":observation["node_assignment"],"cpu_node_fallback":observation["cpu_node_fallback"],
        "runtime":{"kind":observation["runtime"]["kind"],"api_version":observation["runtime"]["api_version"],
            "build_info_sha256":crate::host::digest(observation["runtime"]["build_info"].as_str().context("runtime build identity missing")?.as_bytes())},
        "sdk_pin":pin,"modules":modules,"module_identity_source":"host_verified"}))
}

pub(crate) fn require_contract(capabilities: &Value) -> Result<()> {
    anyhow::ensure!(capabilities["backend_load_probe_contract"].as_u64() == Some(1)
        && capabilities["operations"].as_array().is_some_and(|operations| operations.iter().any(|operation| operation == "backend_load_probe")),
        "paired Core SDK does not support backend_load_probe contract 1; no status/capabilities fallback is permitted");
    Ok(())
}

/// Probe the current host selection without initializing business workers or model caches.
/// Use onnx::with_selection(engine, variant, backend_load_probe) for an explicit legacy selection.
pub fn backend_load_probe() -> Result<Value> {
    let snapshot_gate = crate::model_selection::probe_gate()?;
    let mut core = crate::Core::new()?;
    let capabilities = core.capabilities()?;
    require_contract(&capabilities)?;
    let pin = sdk_pin()?;
    let assets = crate::host::probe_assets()?;
    let engine = crate::onnx::Engine::parse(assets.config["engine"].as_str().context("probe engine missing")?)?;
    if let Some(native) = &assets.native {
        anyhow::ensure!((engine == crate::onnx::Engine::Cpu && native.provider == "CPUExecutionProvider")
            || (cfg!(windows) && (engine == crate::onnx::Engine::Npu
                || (engine == crate::onnx::Engine::Gpu && native.provider == "DmlExecutionProvider"))),
            "custom provider module identity verification is unsupported for this selection");
    }
    let mut options = crate::ffi::ProbeOptions::new(assets.native.clone());
    // Buffers/config are now an immutable snapshot. Never hold a host model gate across native work.
    drop(snapshot_gate);
    let mut resources: Option<Resources> = None;
    let mut api_identity = None;
    let mut environment_identity = None;
    let mut runtime_version = None;
    let mut configured_provider = assets.native.map(|native| native.provider);
    let mut verified = false;
    let mut transport = |request: &Value| -> Result<Value> {
        anyhow::ensure!(request["operation"] == "backend_load_probe", "unexpected native probe callback");
        match request["phase"].as_str().context("probe callback phase missing")? {
            "load" => {
                anyhow::ensure!(resources.is_none() && request["backend"] == "onnx" && request["engine"] == json!(engine), "probe load selection/order mismatch");
                resources = Some(Resources::load(engine)?);
                Ok(json!({"ok":true}))
            }
            "register" => {
                let resources = resources.as_ref().context("probe register preceded resource load")?;
                anyhow::ensure!(api_identity.is_none(), "duplicate probe registration");
                let api = address(&request["api_address"], false)?;
                let environment = address(&request["environment_address"], false)?;
                #[cfg(windows)]
                if engine == crate::onnx::Engine::Npu { crate::ffi::probe_register(environment, api, resources.providers.clone())?; }
                #[cfg(not(windows))]
                let _ = (resources, environment);
                api_identity = Some(crate::host::digest(&api.to_ne_bytes()));
                environment_identity = Some(crate::host::digest(&environment.to_ne_bytes()));
                Ok(json!({"ok":true}))
            }
            "configure" => {
                let api = address(&request["api_address"], false)?;
                let environment = address(&request["environment_address"], false)?;
                anyhow::ensure!(api_identity.as_deref() == Some(crate::host::digest(&api.to_ne_bytes()).as_str())
                    && environment_identity.as_deref() == Some(crate::host::digest(&environment.to_ne_bytes()).as_str()),
                    "probe configuration handles differ from registration");
                let provider = options.configure(address(&request["options_address"], false)?, api,
                    environment, address(&request["device_address"], true)?)?;
                if let Some(provider) = provider { configured_provider = Some(provider); }
                Ok(json!({"ok":true}))
            }
            "verify" => {
                let observation = &request["observation"];
                let api = address(&observation["runtime"]["api_address"], false)?;
                anyhow::ensure!(!verified && api_identity.as_deref() == Some(crate::host::digest(&api.to_ne_bytes()).as_str()), "probe verification API/order mismatch");
                anyhow::ensure!(observation["backend"] == "onnx" && observation["engine"] == json!(engine), "probe observation selection mismatch");
                let selected = observation["selected"].as_str().context("selected probe provider missing")?;
                let provider = configured_provider.as_deref().or(match selected { "CPU" => Some("CPUExecutionProvider"), "Gpu: DmlExecutionProvider" => Some("DmlExecutionProvider"), _ => selected.strip_prefix("Npu: ") })
                    .context("selected native provider has no verifiable identity")?;
                if selected != "Host" {
                    let expected = match selected { "CPU" => "CPUExecutionProvider", "Gpu: DmlExecutionProvider" => "DmlExecutionProvider", value => value.strip_prefix("Npu: ").context("unsupported selected provider")? };
                    anyhow::ensure!(provider == expected, "configured provider differs from Core selection");
                }
                let evidence = resources.as_ref().context("probe verification preceded resource load")?.verify(observation, provider)?;
                let version = observation["runtime"]["api_version"].as_u64().and_then(|version| u32::try_from(version).ok()).context("invalid observed ORT API version")?;
                runtime_version = Some(native::runtime_version(api, version,
                    address(&observation["runtime"]["symbols"]["CreateSessionFromArray"], false)?,
                    address(&observation["runtime"]["symbols"]["Run"], false)?)?);
                verified = true;
                Ok(evidence)
            }
            _ => anyhow::bail!("unsupported native probe callback phase"),
        }
    };
    let payload = json!({"config":assets.config,"model_base64":STANDARD.encode(&assets.model),
        "tokenizer_base64":STANDARD.encode(&assets.tokenizer),"text":"Respire selected backend load verification"});
    drop(assets.model);
    drop(assets.tokenizer);
    let observation = core.call_with_transport("backend_load_probe", payload, &mut transport)?;
    anyhow::ensure!(verified, "Core returned readiness without synchronous module verification");
    let mut summary = sanitized(&observation, &pin)?;
    summary["runtime"]["version"] = json!(runtime_version.context("loaded runtime version was not verified")?);
    Ok(summary)
}

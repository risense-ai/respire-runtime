//! Read-only model inventory, integrity verification and backend readiness.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use respire_app::memory::bge::model_files_present;
use respire_protocol::{
    AssetRequirement, AssetState, AssetsStatus, BackendLoadState, BackendLoadStatus,
};

/// HuggingFace repo (where the ONNX actually lives, not the BAAI source repo).
pub const MODEL_REPO: &str = "Xenova/bge-m3";
/// Verified revision (this commit's tokenizer/onnx hashes match the local read-only model).
pub const MODEL_REVISION: &str = "4de13258303883538bd53b696b452bf8099f0858";
const TOKENIZER_SHA256: &str = "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790";

pub fn model_directory() -> Result<PathBuf> {
    respire_app::memory::bge::m3_model_dir()
}

fn file_url(origin: &str, relative: &str) -> String {
    format!("{origin}/{MODEL_REPO}/resolve/{MODEL_REVISION}/{relative}")
}

/// Cheap runtime inventory for settings UIs. Presence/size is not a checksum or
/// provider compatibility claim; inference and the installer still verify hashes.
pub fn variant_inventory() -> Result<serde_json::Value> {
    let directory = respire_app::memory::bge::discovered_model_dir()?;
    let baseline = model_files_present(&directory);
    respire_app::memory::onnx::MODEL_VARIANTS
        .iter()
        .map(|variant| {
            let state = if baseline {
                variant_file_state(
                    &directory.join(respire_app::memory::onnx::variant_file_name(variant.name)),
                    variant.size,
                )?
            } else {
                "baseline_missing"
            };
            Ok(serde_json::json!({"name":variant.name,"size":variant.size,"state":state}))
        })
        .collect::<Result<Vec<_>>>()
        .map(serde_json::Value::from)
}

#[derive(Clone)]
struct RequiredAsset<'a> {
    name: &'a str,
    version: &'a str,
    path: PathBuf,
    size: u64,
    sha256: String,
    suggested_source: &'a str,
    incompatible_reason: Option<String>,
}

const PROBE_INPUT_LIMIT: usize = 256 * 1024;
const PROBE_OUTPUT_LIMIT: usize = 64 * 1024;
const PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(150);
static PROBE_HELPER_HOST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[derive(Clone, Copy)]
pub enum BackendProbeHost {
    Serving = 1,
    PrivateControl = 2,
}

/// Only the standalone runtime installs the early private helper entry.
pub fn enable_backend_probe_host(host: BackendProbeHost) {
    PROBE_HELPER_HOST.store(host as usize, std::sync::atomic::Ordering::Release);
}

fn probe_needs_serving_admission(host: usize) -> Result<bool> {
    match host {
        1 => Ok(true),
        2 => Ok(false),
        _ => anyhow::bail!("this host image has not installed the private backend probe entry"),
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeSelection {
    profile: Option<respire_app::core_sdk::profiles::Selection>,
    engine: String,
    variant: String,
    directory: PathBuf,
    cpu_owned: bool,
    cpu_file: Option<PathBuf>,
    settings: std::collections::BTreeMap<String, String>,
}

impl ProbeSelection {
    fn capture() -> Result<Self> {
        // Read the authoritative persisted choice, not a stale worker-thread TLS copy.
        Self::capture_choice(respire_app::embedding::saved_selection()?)
    }

    fn capture_choice(profile: Option<respire_app::core_sdk::profiles::Selection>) -> Result<Self> {
        use respire_app::memory::{bge, onnx};
        let mut settings = std::collections::BTreeMap::new();
        for name in ["RSRS_DATA_DIR", "RSRS_ORT_PROFILE", "RSRS_INTRA_THREADS"] {
            if let Some(value) = respire_app::env::var_os(name) {
                settings.insert(name.to_owned(), value.into_string().map_err(|_| anyhow!("non-Unicode probe setting {name}"))?);
            }
        }
        if let Some(selection) = &profile {
            selection.validate()?;
            return Ok(Self { engine: serde_json::to_value(selection.engine)?.as_str().context("invalid profile engine")?.to_owned(),
                variant: selection.variant.clone().unwrap_or_default(), profile, directory: PathBuf::new(),
                cpu_owned: false, cpu_file: None, settings });
        }
        let engine = onnx::configured_engine()?;
        let variant = onnx::configured_variant(engine)?;
        let directory = std::path::absolute(bge::discovered_model_dir()?)?;
        let cpu_owned = bge::cpu_owned_mode(engine)?;
        let cpu_file = if cpu_owned { Some(std::path::absolute(match respire_app::env::var_os("RSRS_CPU_OWNED_ORT_FILE") {
            Some(path) => PathBuf::from(path), None => bge::cpu_ort_path(&directory)?,
        })?) } else { None };
        Ok(Self { profile, engine: serde_json::to_value(engine)?.as_str().context("invalid legacy engine")?.to_owned(),
            variant: variant.name.to_owned(), directory, cpu_owned, cpu_file, settings })
    }

    fn identity(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }

    fn probe(&self) -> Result<serde_json::Value> {
        if let Some(selection) = &self.profile {
            return respire_app::core_sdk::profiles::scoped(selection.clone(), respire_app::core_sdk::backend_load_probe);
        }
        respire_app::memory::onnx::with_selection(
            respire_app::memory::onnx::Engine::parse(&self.engine)?, &self.variant,
            respire_app::core_sdk::backend_load_probe,
        )
    }
}

fn read_probe_frame(mut input: impl Read) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(length <= PROBE_INPUT_LIMIT, "probe request exceeds input limit");
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

// Only the runtime's early private entry calls this. No account, store, hooks or listener is opened.
pub fn run_backend_probe_helper() -> Result<()> {
    let bytes = read_probe_frame(std::io::stdin().lock())?;
    // The request pipe remains open as the parent's lifetime lease on Unix.
    respire_spawn::watch_probe_parent()?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request { nonce: String, selection: ProbeSelection }
    let request: Request = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(request.nonce.len() == 36, "invalid private probe nonce");
    let identity = request.selection.identity()?;
    let result = request.selection.probe().map_err(|error| format!("{error:#}"));
    let output = serde_json::to_vec(&serde_json::json!({"nonce":request.nonce,"selection_identity":identity,
        "pid":std::process::id(),"result":result}))?;
    anyhow::ensure!(output.len() <= PROBE_OUTPUT_LIMIT, "probe response exceeds output limit");
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}

struct OwnedProbe(respire_spawn::ProbeChild);

impl OwnedProbe {
    fn retire(&mut self) -> Result<()> {
        if self.0.try_wait()?.is_some() { return Ok(()); }
        // The child retains its OS identity; no PID lookup or process-name kill is used.
        if let Err(error) = self.0.kill() {
            if self.0.try_wait()?.is_none() { return Err(error.into()); }
        }
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if self.0.try_wait()?.is_some() { return Ok(()); }
            anyhow::ensure!(std::time::Instant::now() < until, "probe termination was not confirmed");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

impl Drop for OwnedProbe {
    fn drop(&mut self) {
        if let Err(error) = self.retire() {
            // Never publish a drained receipt while an owned native child is unaccounted for.
            // Exit closes the job/lease pipe; Linux also has a kernel parent-death signal.
            eprintln!("fatal probe cleanup failure: {error:#}");
            std::process::exit(2);
        }
    }
}

fn probe_cancelled() -> bool {
    crate::rpc_worker::STOPPING.load(std::sync::atomic::Ordering::Acquire)
        || crate::rpc_serve::control_state() != "running"
}

fn managed_backend_probe(selection: &ProbeSelection) -> Result<serde_json::Value> {
    use std::{process::{Command, Stdio}, sync::mpsc, time::Instant};
    let serving = probe_needs_serving_admission(
        PROBE_HELPER_HOST.load(std::sync::atomic::Ordering::Acquire))?;
    anyhow::ensure!(!probe_cancelled(), "runtime is draining; probe was not started");
    let nonce = uuid::Uuid::new_v4().to_string();
    // Authenticated private verification runs while the serving host is Paused.
    // Serving probes retain drain accounting until owned-child cleanup finishes.
    let _admission = if serving {
        Some(crate::rpc_serve::begin_admission(nonce.clone(), "backend_load_probe")
            .context("runtime drain rejected the backend probe")?)
    } else {
        None
    };
    let request = serde_json::to_vec(&serde_json::json!({"nonce":nonce,"selection":selection}))?;
    anyhow::ensure!(request.len() <= PROBE_INPUT_LIMIT, "probe request exceeds input limit");
    let mut command = Command::new(std::fs::canonicalize(std::env::current_exe()?)?);
    command.env_clear();
    for name in ["SystemRoot", "SystemDrive", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"] {
        if let Some(value) = std::env::var_os(name) { command.env(name, value); }
    }
    for (name, value) in &selection.settings { command.env(name, value); }
    if selection.profile.is_none() {
        command.env("RSRS_M3_DIR", &selection.directory)
            .env("RSRS_CPU_OWNED_ORT_EXPERIMENT", if selection.cpu_owned { "1" } else { "0" });
        if let Some(path) = &selection.cpu_file { command.env("RSRS_CPU_OWNED_ORT_FILE", path); }
    }
    command.arg("--backend-load-probe-internal")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let deadline = Instant::now() + PROBE_DEADLINE;
    // Declared before child: its writer stays alive until owned-child cleanup finishes.
    let (_lease, lease_end) = mpsc::channel::<()>();
    let mut child = OwnedProbe(respire_spawn::spawn_probe_helper(&mut command)?);
    let pid = child.0.id();
    let mut input = child.0.take_stdin().context("probe stdin missing")?;
    let output = child.0.take_stdout().context("probe stdout missing")?;
    let (send, receive) = mpsc::channel();
    let input_send = send.clone();
    std::thread::Builder::new().name("backend-probe-input".into()).spawn(move || {
        let result = input.write_all(&(request.len() as u32).to_be_bytes()).and_then(|_| input.write_all(&request));
        if let Err(error) = result { let _ = input_send.send(Err(anyhow!(error))); }
        // Keep the sole parent writer alive without holding any application lock.
        let _ = lease_end.recv();
        drop(input);
    })?;
    std::thread::Builder::new().name("backend-probe-output".into()).spawn(move || {
        let result = (|| -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            output.take(PROBE_OUTPUT_LIMIT as u64 + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= PROBE_OUTPUT_LIMIT, "probe response exceeds output limit");
            Ok(bytes)
        })();
        let _ = send.send(result);
    })?;
    let bytes = loop {
        anyhow::ensure!(!probe_cancelled(), "runtime drain cancelled native probe");
        anyhow::ensure!(Instant::now() < deadline, "native probe exceeded its hard deadline");
        match receive.recv_timeout(std::time::Duration::from_millis(20)) {
            Ok(result) => break result?,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(error) => return Err(error.into()),
        }
    };
    // EOF is not proof of exit: a provider may close stdout and then hang in teardown.
    loop {
        if let Some(status) = child.0.try_wait()? { anyhow::ensure!(status.success(), "native probe helper failed"); break; }
        anyhow::ensure!(!probe_cancelled() && Instant::now() < deadline, "native probe cancelled before confirmed exit");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let response: serde_json::Value = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(response["nonce"] == nonce && response["pid"].as_u64() == Some(u64::from(pid))
        && response["selection_identity"] == selection.identity()?, "probe helper receipt identity mismatch");
    let result: std::result::Result<serde_json::Value, String> = serde_json::from_value(response["result"].clone())?;
    result.map_err(|error| anyhow!("native probe: {error}"))
}

fn installation_plan_for(selection: &ProbeSelection) -> Result<AssetsStatus> {
    use respire_app::memory::{bge, onnx};
    let mut assets = Vec::new();
    if let Some(profile) = &selection.profile {
        profile.validate()?;
        let backend = profile.backend_profile.backend.as_str();
        if matches!(backend, "onnx" | "mlx") {
            for (name, resource) in [
                ("profile-tokenizer", &profile.profile.tokenizer),
                ("profile-weights", &profile.profile.weights),
            ] {
                let resource = resource
                    .as_ref()
                    .context("selected profile resource missing")?;
                let unsupported = (backend == "mlx" && !cfg!(target_os = "macos"))
                    || (backend == "onnx"
                        && profile.engine != onnx::Engine::Cpu
                        && !cfg!(any(windows, target_os = "macos")));
                let reason = if unsupported {
                    Some("selected backend is unsupported on this platform")
                } else if resource.download.is_none() {
                    Some("selected profile has no pinned download source; Runtime-specific preparation is required")
                } else {
                    None
                };
                assets.push(planned_asset(
                    name,
                    profile.profile.embedding["revision"]
                        .as_str()
                        .context("profile revision missing")?,
                    std::path::absolute(&resource.path)?,
                    resource.size,
                    &resource.sha256,
                    resource.download.as_deref().unwrap_or(""),
                    reason,
                )?);
            }
        } else {
            assets.push(unprepared_asset(
                "profile-backend",
                "selected backend has no local file preparation contract",
            ));
        }
        let unsupported_provider = profile
            .backend_profile
            .native
            .as_ref()
            .is_some_and(|native| {
                !((profile.engine == onnx::Engine::Cpu
                    && native.provider == "CPUExecutionProvider")
                    || (cfg!(windows)
                        && profile.engine == onnx::Engine::Gpu
                        && native.provider == "DmlExecutionProvider"))
            });
        if profile.engine == onnx::Engine::Npu || unsupported_provider {
            assets.push(unprepared_asset("native-provider", "native catalog/provider preparation requires the Runtime platform interface; file pins alone cannot attest provider readiness"));
        }
    } else {
        let engine = onnx::Engine::parse(&selection.engine)?;
        let variant = onnx::parse_variant(&selection.variant)?;
        let baseline = onnx::parse_variant("quantized")?;
        // Match the existing installer target, including strict environment validation.
        // Loading may discover a legacy/system directory; installation must not overwrite it.
        let directory = std::path::absolute(model_directory()?)?;
        let unsupported = engine != onnx::Engine::Cpu && !cfg!(any(windows, target_os = "macos"));
        let reason = unsupported.then_some("selected engine is unsupported on this platform");
        for (name, file, size, hash) in [
            (
                "bge-m3-tokenizer",
                "tokenizer.json".to_owned(),
                17_082_821,
                TOKENIZER_SHA256,
            ),
            (
                "bge-m3-baseline",
                onnx::variant_file_name(baseline.name),
                baseline.size,
                baseline.sha256,
            ),
        ] {
            assets.push(planned_asset(
                name,
                MODEL_REVISION,
                directory.join(&file),
                size,
                hash,
                &file_url("https://huggingface.co", &file),
                reason,
            )?);
        }
        if variant.name != baseline.name {
            let file = onnx::variant_file_name(variant.name);
            assets.push(planned_asset(
                "bge-m3-model",
                MODEL_REVISION,
                directory.join(&file),
                variant.size,
                variant.sha256,
                &file_url("https://huggingface.co", &file),
                reason,
            )?);
        }
        if selection.cpu_owned {
            anyhow::ensure!(
                respire_app::env::var_os("RSRS_CPU_OWNED_ORT_FILE").is_none(),
                "unset RSRS_CPU_OWNED_ORT_FILE before preparing pinned weights"
            );
            assets.push(planned_asset(
                "bge-m3-cpu-ort",
                bge::CPU_ORT_REVISION,
                std::path::absolute(bge::cpu_ort_cache_path()?)?,
                bge::CPU_ORT_SIZE,
                bge::CPU_ORT_SHA256,
                bge::CPU_ORT_URL,
                None,
            )?);
        }
        if engine == onnx::Engine::Npu {
            assets.push(unprepared_asset("native-provider", "NPU catalog/provider preparation requires the Runtime platform interface; do not copy or release the SDK catalog DLL in the client"));
        }
    }
    Ok(AssetsStatus::installation_plan(assets))
}

/// File discovery changes after installation; bind configured paths, not that side effect.
fn preparation_selection(mut selection: ProbeSelection) -> Result<ProbeSelection> {
    if selection.profile.is_none() {
        selection.directory = std::path::absolute(model_directory()?)?;
        if selection.cpu_owned && respire_app::env::var_os("RSRS_CPU_OWNED_ORT_FILE").is_none() {
            selection.cpu_file = Some(std::path::absolute(respire_app::memory::bge::cpu_ort_cache_path()?)?);
        }
    }
    Ok(selection)
}

fn preparation_snapshot(
    intent: &respire_protocol::ModelInstallIntent,
) -> Result<(respire_protocol::ModelPreparation, ProbeSelection)> {
    use respire_app::memory::onnx;
    if let Some(model) = &intent.model { onnx::parse_variant(model)?; }
    let authoritative = preparation_selection(ProbeSelection::capture()?)?;
    let target = if let Some(engine) = &intent.for_engine {
        anyhow::ensure!(matches!(engine.as_str(), "cpu" | "gpu" | "npu"), "invalid install engine");
        let engine = onnx::Engine::parse(engine)?;
        onnx::with_selection(engine, intent.model.as_deref().unwrap_or(onnx::default_variant(engine)), || {
            preparation_selection(ProbeSelection::capture_choice(None)?)
        })?
    } else {
        authoritative.clone()
    };
    let mut plan = installation_plan_for(&target)?;
    if let Some(model) = &intent.model {
        // --model adds a legacy variant; without --for-engine it does not select it.
        let variant = onnx::parse_variant(model)?;
        let legacy = if intent.for_engine.is_some() { target.clone() }
            else { preparation_selection(ProbeSelection::capture_choice(None)?)? };
        let mut extra = installation_plan_for(&legacy)?.assets;
        let file = onnx::variant_file_name(variant.name);
        let engine = onnx::Engine::parse(&legacy.engine)?;
        let reason = (engine != onnx::Engine::Cpu && !cfg!(any(windows, target_os = "macos")))
            .then_some("selected engine is unsupported on this platform");
        extra.push(planned_asset("bge-m3-model", MODEL_REVISION, legacy.directory.join(&file),
            variant.size, variant.sha256, &file_url("https://huggingface.co", &file), reason)?);
        for asset in extra {
            if let Some(existing) = plan.assets.iter().find(|existing| existing.path == asset.path) {
                anyhow::ensure!(existing.sha256 == asset.sha256 && existing.expected_size == asset.expected_size,
                    "install intent has conflicting pins for one destination");
            } else { plan.assets.push(asset); }
        }
        plan.missing = plan.assets.clone();
    }
    let selection_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(
        &(respire_protocol::HOST_MODEL_SCHEMA_V, intent, &authoritative, &target, &plan))?));
    Ok((respire_protocol::ModelPreparation { selection_sha256, assets: plan }, target))
}

/// The dispatcher supplies an authenticated Paused grant; this never changes selection.
pub fn model_preparation_plan(intent: &respire_protocol::ModelInstallIntent) -> Result<respire_protocol::ModelPreparation> {
    let epoch = crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire);
    let (plan, _) = preparation_snapshot(intent)?;
    anyhow::ensure!(crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire) == epoch
        && preparation_snapshot(intent)?.0 == plan, "model preparation scope changed while planning");
    Ok(plan)
}

/// Caller installs the control-parent watch and budgets the existing 150s native probe.
pub fn model_preparation_verify(
    intent: &respire_protocol::ModelInstallIntent,
    selection_sha256: &str,
) -> Result<respire_protocol::ModelPreparation> {
    anyhow::ensure!(selection_sha256.len() == 64
        && selection_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid model preparation selection digest");
    let epoch = crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire);
    let (preparation, target) = preparation_snapshot(intent)?;
    anyhow::ensure!(preparation.selection_sha256 == selection_sha256, "model preparation selection changed");
    let unchanged = || -> Result<()> {
        anyhow::ensure!(!probe_cancelled()
            && crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire) == epoch
            && preparation_snapshot(intent)?.0 == preparation, "model preparation selection changed");
        Ok(())
    };
    let mut reports = Vec::new();
    for asset in &preparation.assets.assets {
        if asset.state == AssetState::Incompatible { reports.push(asset.clone()); continue; }
        reports.push(required_asset_status(&RequiredAsset {
            name: &asset.name, version: asset.version.as_deref().context("plan revision missing")?,
            path: PathBuf::from(asset.path.as_deref().context("plan destination missing")?),
            size: asset.expected_size.context("plan size missing")?,
            sha256: asset.sha256.clone().context("plan SHA-256 missing")?,
            suggested_source: &asset.suggested_source, incompatible_reason: None,
        })?);
    }
    let missing: Vec<_> = reports.iter().filter(|asset| asset.state != AssetState::Complete).cloned().collect();
    unchanged()?;
    respire_app::memory::bge::invalidate_cpu_ort_validation()?;
    let assets = with_backend_load(AssetsStatus { complete: missing.is_empty(), missing,
        assets: reports, backend_load: None }, || {
        unchanged()?;
        let evidence = managed_backend_probe(&target)?;
        unchanged()?;
        Ok(evidence)
    });
    // Selection races are scope errors, not a readiness result for a different target.
    unchanged()?;
    Ok(respire_protocol::ModelPreparation { selection_sha256: selection_sha256.to_owned(), assets })
}

fn planned_asset(
    name: &str,
    version: &str,
    path: PathBuf,
    size: u64,
    hash: &str,
    source: &str,
    incompatible: Option<&str>,
) -> Result<AssetRequirement> {
    anyhow::ensure!(
        path.is_absolute() && path.to_str().is_some(),
        "model asset path must be absolute Unicode"
    );
    anyhow::ensure!(
        size > 0 && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "model asset requires a fixed SHA-256 and size"
    );
    // Unsupported profile sources must not be advertised as executable Missing files.
    let incompatible = incompatible.or_else(|| {
        (!planned_source_supported(name, version, &path, source)).then_some(
            "source is unsupported by client preparation: require an official immutable Hugging Face URL or pinned CPU release; use the Runtime-specific preparation interface",
        )
    });
    Ok(AssetRequirement {
        name: name.to_owned(),
        version: Some(version.to_owned()),
        path: Some(
            path.to_str()
                .context("model path is not Unicode")?
                .to_owned(),
        ),
        expected_size: Some(size),
        sha256: Some(hash.to_owned()),
        suggested_source: source.to_owned(),
        state: if incompatible.is_some() {
            AssetState::Incompatible
        } else {
            AssetState::Missing
        },
        actual_size: None,
        actual_sha256: None,
        reason: incompatible.map(str::to_owned),
    })
}

fn planned_source_supported(name: &str, version: &str, target: &Path, source: &str) -> bool {
    // Match the client's restricted source contract, not a general URL allowlist.
    let Some(filename) = target.file_name().and_then(|file| file.to_str()) else {
        return false;
    };
    if filename.starts_with('.')
        || !filename
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return false;
    }
    let cpu = name == "bge-m3-cpu-ort";
    let prefix = if cpu {
        "https://github.com/risense-ai/respire-cli/releases/download/"
    } else {
        "https://huggingface.co/"
    };
    let Some(relative) = source.strip_prefix(prefix) else {
        return false;
    };
    let path: Vec<_> = relative.split('/').collect();
    if !path.iter().all(|part| {
        !part.is_empty()
            && *part != "."
            && *part != ".."
            && part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    }) {
        return false;
    }
    if cpu {
        !version.is_empty() && path.len() == 2 && path[1] == filename
    } else {
        path.len() >= 5
            && path[2] == "resolve"
            && path[3] == version
            && path.last().copied() == Some(filename)
            && version.len() == 40
            && version.bytes().all(|c| c.is_ascii_hexdigit())
    }
}

fn unprepared_asset(name: &str, reason: &str) -> AssetRequirement {
    AssetRequirement {
        name: name.to_owned(),
        version: None,
        path: None,
        expected_size: None,
        sha256: None,
        suggested_source: String::new(),
        state: AssetState::Incompatible,
        actual_size: None,
        actual_sha256: None,
        reason: Some(reason.to_owned()),
    }
}

pub fn assets_status() -> Result<AssetsStatus> {
    let epoch = crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire);
    let selection = ProbeSelection::capture()?;
    let identity = selection.identity()?;
    let status = file_assets_status_for(&selection)?;
    Ok(with_backend_load(status, || {
        anyhow::ensure!(!probe_cancelled()
            && crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire) == epoch
            && ProbeSelection::capture()?.identity()? == identity,
            "selected assets changed before native probing");
        let evidence = managed_backend_probe(&selection)?;
        anyhow::ensure!(!probe_cancelled()
            && crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire) == epoch
            && ProbeSelection::capture()?.identity()? == identity,
            "selected assets changed during native probing; readiness discarded");
        Ok(evidence)
    }))
}

fn with_backend_load(
    mut status: AssetsStatus,
    probe: impl FnOnce() -> Result<serde_json::Value>,
) -> AssetsStatus {
    if !status.complete {
        let provider_unverified = status.assets.iter().any(|asset| asset.name == "windows-npu-provider" && asset.state != AssetState::Complete);
        status.backend_load = Some(BackendLoadStatus {
            state: if provider_unverified { BackendLoadState::Failed } else { BackendLoadState::NotRun },
            reason: Some(if provider_unverified { "npu_provider_unverified" } else { "assets_incomplete" }.to_owned()),
            evidence: None,
        });
        return status;
    }
    match probe().and_then(|value| {
        anyhow::ensure!(
            value["contract"] == 1
                && value["status"] == "loaded"
                && value["ready"] == true
                && value["fresh_session"] == true
                && value["inference_completed"] == true,
            "native backend did not prove fresh loading and inference"
        );
        serde_json::from_value(value).context("invalid native backend load evidence")
    }) {
        Ok(evidence) => {
            status.backend_load = Some(BackendLoadStatus {
                state: BackendLoadState::Loaded,
                reason: None,
                evidence: Some(evidence),
            });
        }
        Err(error) => {
            eprintln!("backend load verification failed: {error:#}");
            status.complete = false;
            status.backend_load = Some(BackendLoadStatus {
                state: BackendLoadState::Failed,
                reason: Some("backend_load_failed".to_owned()),
                evidence: None,
            });
        }
    }
    status
}

fn file_assets_status() -> Result<AssetsStatus> {
    // Pre-initialization checks stay file-only and must not open the account database.
    file_assets_status_for(&ProbeSelection::capture_choice(respire_app::core_sdk::profiles::current()?)?)
}

fn file_assets_status_for(selection: &ProbeSelection) -> Result<AssetsStatus> {
    if let Some(profile) = &selection.profile {
        profile.validate()?;
        anyhow::ensure!(matches!(profile.backend_profile.backend.as_str(), "onnx" | "mlx"),
            "asset load diagnostics require a native backend");
        let mut assets = Vec::new();
        for (name, resource) in [("profile-weights", &profile.profile.weights), ("profile-tokenizer", &profile.profile.tokenizer)] {
            let resource = resource.as_ref().context("selected profile resource missing")?;
            assets.push(RequiredAsset { name, version: "profile-v1", path: resource.path.clone(), size: resource.size,
                sha256: resource.sha256.clone(), suggested_source: "selected model profile", incompatible_reason: None });
        }
        return required_assets_status(&assets);
    }
    let engine = respire_app::memory::onnx::Engine::parse(&selection.engine)?;
    let variant = respire_app::memory::onnx::parse_variant(&selection.variant)?;
    let directory = &selection.directory;
    let accelerator_supported = engine == respire_app::memory::onnx::Engine::Cpu
        || cfg!(windows)
        || cfg!(target_os = "macos");
    let incompatible_reason = (!accelerator_supported)
        .then(|| "the selected inference engine is unsupported on this OS".to_owned());
    let mut assets = vec![
        RequiredAsset {
            name: "bge-m3-tokenizer",
            version: MODEL_REVISION,
            path: directory.join("tokenizer.json"),
            size: 17_082_821,
            sha256: TOKENIZER_SHA256.to_owned(),
            suggested_source: "https://huggingface.co/Xenova/bge-m3",
            incompatible_reason: incompatible_reason.clone(),
        },
        RequiredAsset {
            name: "bge-m3-model",
            version: variant.name,
            path: directory.join(respire_app::memory::onnx::variant_file_name(variant.name)),
            size: variant.size,
            sha256: variant.sha256.to_owned(),
            suggested_source: "https://huggingface.co/Xenova/bge-m3",
            incompatible_reason,
        },
    ];
    if selection.cpu_owned {
        // The owned loader consumes the ORT container, not a second legacy ONNX model.
        assets[1] = RequiredAsset {
            name: "bge-m3-cpu-ort",
            version: respire_app::memory::bge::CPU_ORT_REVISION,
            path: selection.cpu_file.clone().context("CPU-owned snapshot lacks its container")?,
            size: respire_app::memory::bge::CPU_ORT_SIZE,
            sha256: respire_app::memory::bge::CPU_ORT_SHA256.to_owned(),
            suggested_source: respire_app::memory::bge::CPU_ORT_URL,
            incompatible_reason: None,
        };
    }
    #[cfg(windows)]
    if engine == respire_app::memory::onnx::Engine::Npu {
        let (path, size, sha256) = respire_app::memory::onnx::accelerator_catalog_metadata();
        assets.push(RequiredAsset {
            name: "windows-ml-catalog",
            version: "2.4.89",
            path,
            size,
            sha256,
            suggested_source: "https://www.nuget.org/packages/Microsoft.Windows.AI.MachineLearning/2.4.89",
            incompatible_reason: None,
        });
        let mut status = required_assets_status(&assets)?;
        // The catalog pin does not attest hardware-specific provider payloads.
        let provider = AssetRequirement {
            name: "windows-npu-provider".to_owned(),
            version: None,
            sha256: None,
            suggested_source: "host CLI accelerator installer (official hardware provider payload)".to_owned(),
            state: AssetState::Incompatible,
            path: None,
            expected_size: None,
            actual_size: None,
            actual_sha256: None,
            reason: Some("NPU provider payload integrity and compatibility are unverified: no pinned provider metadata is available; catalog verification alone does not establish readiness".to_owned()),
        };
        status.complete = false;
        // This is a provider attestation failure, not a downloadable file with a path.
        status.assets.push(provider);
        return Ok(status);
    }
    required_assets_status(&assets)
}

fn required_assets_status(assets: &[RequiredAsset<'_>]) -> Result<AssetsStatus> {
    let mut reports = Vec::with_capacity(assets.len());
    for asset in assets {
        reports.push(required_asset_status(asset)?);
    }
    let missing: Vec<_> = reports
        .iter()
        .filter(|asset| asset.state != AssetState::Complete)
        .cloned()
        .collect();
    Ok(AssetsStatus {
        complete: missing.is_empty(),
        missing,
        assets: reports,
        backend_load: None,
    })
}

fn required_asset_status(asset: &RequiredAsset<'_>) -> Result<AssetRequirement> {
    let mut requirement = AssetRequirement {
        name: asset.name.to_owned(),
        version: Some(asset.version.to_owned()),
        sha256: Some(asset.sha256.to_owned()),
        suggested_source: asset.suggested_source.to_owned(),
        state: AssetState::Missing,
        path: Some(asset.path.display().to_string()),
        expected_size: Some(asset.size),
        actual_size: None,
        actual_sha256: None,
        reason: None,
    };
    match std::fs::symlink_metadata(&asset.path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            requirement.state = AssetState::Corrupt;
            requirement.reason = Some("asset must be a regular file, not a symlink".to_owned());
        }
        Ok(metadata) if !metadata.is_file() => {
            requirement.state = AssetState::Corrupt;
            requirement.reason = Some("asset path is not a regular file".to_owned());
        }
        Ok(metadata) => {
            requirement.actual_size = Some(metadata.len());
            if metadata.len() < asset.size {
                requirement.state = AssetState::Incomplete;
                requirement.reason = Some(format!(
                    "expected {} bytes, found {}",
                    asset.size,
                    metadata.len()
                ));
            } else if metadata.len() > asset.size {
                requirement.state = AssetState::Corrupt;
                requirement.reason = Some(format!(
                    "expected {} bytes, found {}",
                    asset.size,
                    metadata.len()
                ));
            } else {
                requirement.actual_sha256 = Some(hash_asset(&asset.path)?.to_lowercase());
                let valid = requirement
                    .actual_sha256
                    .as_deref()
                    .is_some_and(|digest| digest.eq_ignore_ascii_case(&asset.sha256));
                requirement.state = if valid {
                    AssetState::Complete
                } else {
                    AssetState::Corrupt
                };
                if !valid {
                    requirement.reason = Some("size matches but SHA-256 differs".to_owned());
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            requirement.state = AssetState::Corrupt;
            requirement.reason = Some(format!("cannot inspect asset: {error}"));
        }
    }
    if let Some(reason) = &asset.incompatible_reason {
        requirement.state = AssetState::Incompatible;
        requirement.reason = Some(reason.clone());
    }
    Ok(requirement)
}

fn hash_asset(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn variant_file_state(path: &Path, expected_size: u64) -> Result<&'static str> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() == expected_size => Ok("present"),
        Ok(_) => Ok("invalid_size"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("missing"),
        Err(error) => Err(error).context("read installed model state"),
    }
}

/// Runtime readiness failures never authorize asset installation.
#[derive(Debug)]
pub(crate) struct AssetsUnavailable;

impl std::fmt::Display for AssetsUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("assets_missing: required model assets are unavailable; install or repair them with the CLI and retry")
    }
}

impl std::error::Error for AssetsUnavailable {}

/// Verify the selected profile without staging, downloading or changing selection.
pub fn verify_selection_assets(
    selection: &respire_app::core_sdk::profiles::Selection,
) -> Result<()> {
    selection.validate()?;
    selection.verify().context(AssetsUnavailable)
}

/// Reuse the pinned file inventory reported by assets.status, including CPU ORT.
pub fn verify_m3_assets() -> Result<()> {
    // Initialization verifies files only; requiring a loaded backend here creates a cold-start cycle.
    let status = file_assets_status()?;
    if !status.complete {
        return Err(anyhow::Error::new(AssetsUnavailable).context(serde_json::to_string(&status)?));
    }
    Ok(())
}

pub fn cpu_model_preparation_needed() -> Result<bool> {
    let directory = respire_app::memory::bge::discovered_model_dir()?;
    if !respire_app::memory::bge::cpu_owned_mode(respire_app::memory::onnx::configured_engine()?)? {
        return Ok(false);
    }
    Ok(!model_files_present(&directory)
        || !respire_app::memory::bge::cpu_ort_present(&directory)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn backend_probe_host_keeps_serving_and_private_admission_separate() -> Result<()> {
        assert!(probe_needs_serving_admission(BackendProbeHost::Serving as usize)?);
        assert!(!probe_needs_serving_admission(BackendProbeHost::PrivateControl as usize)?);
        assert!(probe_needs_serving_admission(0).is_err());
        assert!(probe_needs_serving_admission(usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn backend_load_is_not_attempted_for_incomplete_files() {
        assert!(read_probe_frame(std::io::Cursor::new(((PROBE_INPUT_LIMIT + 1) as u32).to_be_bytes())).is_err());
        assert!(read_probe_frame(std::io::Cursor::new([0u8, 0, 0, 2, b'{'])).is_err());
        let mut lease = std::io::Cursor::new([0u8, 0, 0, 2, b'{', b'}', b'x']);
        assert!(read_probe_frame(&mut lease).is_ok());
        assert_eq!(lease.position(), 6, "lifetime watcher owns everything after the one request frame");
        assert!(read_probe_frame(std::io::Cursor::new([0u8, 0, 0, 2, b'{', b'}'])).is_ok());
        let status = with_backend_load(AssetsStatus::default(), || {
            panic!("incomplete files must not enter native backend loading")
        });
        assert!(!status.complete);
        assert!(status.backend_load.is_some_and(|backend| {
            backend.state == BackendLoadState::NotRun && backend.evidence.is_none()
        }));
    }

    #[test]
    fn verified_files_do_not_hide_backend_failure_or_malformed_evidence() -> Result<()> {
        let mut unverified = required_assets_status(&[])?;
        unverified.complete = false;
        unverified.assets.push(AssetRequirement {
            name: "windows-npu-provider".into(), version: None, sha256: None,
            suggested_source: "fixture".into(), state: AssetState::Incompatible, path: None,
            expected_size: None, actual_size: None, actual_sha256: None, reason: Some("unverified".into()),
        });
        let unverified = with_backend_load(unverified, || anyhow::bail!("must not probe an unverified provider"));
        assert!(!unverified.complete && unverified.missing.is_empty());
        assert!(unverified.backend_load.is_some_and(|backend| backend.state == BackendLoadState::Failed
            && backend.reason.as_deref() == Some("npu_provider_unverified")));
        #[cfg(windows)]
        {
            use std::process::{Command, Stdio};
            let shell = PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot missing")?)
                .join("System32/WindowsPowerShell/v1.0/powershell.exe");
            let mut command = Command::new(shell);
            command.args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60"])
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            let mut child = OwnedProbe(respire_spawn::spawn_probe_helper(&mut command)?);
            assert!(child.0.try_wait()?.is_none());
            let started = std::time::Instant::now();
            child.retire()?;
            assert!(child.0.try_wait()?.is_some());
            assert!(started.elapsed() < std::time::Duration::from_secs(6));
            child.retire()?;
        }
        #[cfg(unix)]
        {
            let mut command = std::process::Command::new("/bin/sleep");
            command.arg("60").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            let mut child = OwnedProbe(respire_spawn::spawn_probe_helper(&mut command)?);
            assert!(child.0.try_wait()?.is_none());
            let started = std::time::Instant::now();
            child.retire()?;
            assert!(child.0.try_wait()?.is_some());
            assert!(started.elapsed() < std::time::Duration::from_secs(6));
            child.retire()?;
        }
        for malformed in [false, true] {
            let status = with_backend_load(required_assets_status(&[])?, || {
                if malformed {
                    Ok(serde_json::json!({"ready": true}))
                } else {
                    anyhow::bail!("selected native backend failed to load")
                }
            });
            assert!(!status.complete);
            assert!(status.missing.is_empty());
            assert!(status.backend_load.is_some_and(|backend| {
                backend.state == BackendLoadState::Failed
                    && backend.reason.is_some()
                    && backend.evidence.is_none()
            }));
        }
        Ok(())
    }

    #[test]
    fn picker_inventory_reports_presence_without_claiming_checksum_validation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("weights");
        assert_eq!(variant_file_state(&path, 3)?, "missing");
        std::fs::write(&path, b"abc")?;
        assert_eq!(variant_file_state(&path, 4)?, "invalid_size");
        assert_eq!(variant_file_state(&path, 3)?, "present");
        assert_eq!(variant_file_state(dir.path(), 3)?, "invalid_size");
        Ok(())
    }

    #[test]
    fn asset_status_reports_real_file_and_compatibility_states() -> Result<()> {
        let profile_dir = tempfile::tempdir()?;
        let weights = profile_dir.path().join("profile-weights");
        let tokenizer = profile_dir.path().join("profile-tokenizer");
        std::fs::write(&weights, b"abc")?;
        std::fs::write(&tokenizer, b"abc")?;
        let digest = format!("{:x}", Sha256::digest(b"abc"));
        let resource = |path: &Path| serde_json::json!({"path":path,"size":3,"sha256":digest});
        let selection = serde_json::from_value(serde_json::json!({
            "model":"fixture-profile","backend":"fixture-cpu","engine":"cpu",
            "profile":{"id":"fixture-profile","embedding":{"model_id":"fixture","revision":"pinned",
                "dimensions":1,"max_tokens":4,"pooling":"cls","normalize":true,"query_prefix":"","document_prefix":""},
                "onnx":{"input_ids":"input_ids"},"weights":resource(&weights),"tokenizer":resource(&tokenizer)},
            "backend_profile":{"id":"fixture-cpu","backend":"onnx"}
        }))?;
        let snapshot = ProbeSelection::capture_choice(Some(selection))?;
        let profile_status = file_assets_status_for(&snapshot)?;
        assert!(profile_status.complete);
        assert_eq!(profile_status.assets.len(), 2);
        assert_eq!(profile_status.assets[0].path.as_deref(), weights.to_str());
        assert!(profile_status.assets.iter().all(|asset| asset.name.starts_with("profile-")));
        let identity = snapshot.identity()?;
        let mut changed = snapshot.clone();
        changed.profile.as_mut().context("fixture profile missing")?.generation = "changed".into();
        assert_ne!(identity, changed.identity()?);
        changed = snapshot.clone();
        changed.profile.as_mut().context("fixture profile missing")?.profile.weights.as_mut()
            .context("fixture weights missing")?.path = profile_dir.path().join("different-model");
        assert_ne!(identity, changed.identity()?);
        assert!(!file_assets_status_for(&changed)?.complete);
        std::fs::write(&weights, b"bad")?;
        assert!(!file_assets_status_for(&snapshot)?.complete);
        let complete = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let corrupt = "3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282";
        let specs = [
            ("missing", None, complete, 3, false),
            ("incomplete", Some(b"ab".as_slice()), complete, 3, false),
            ("short-digest", Some(b"abc".as_slice()), corrupt, 3, false),
            ("overlong", Some(b"abcd".as_slice()), complete, 3, false),
            ("complete", Some(b"abc".as_slice()), complete, 3, false),
            ("incompatible", Some(b"abc".as_slice()), complete, 3, true),
        ];
        let directory = tempfile::tempdir()?;
        let mut expected = Vec::new();
        for (name, bytes, sha256, size, incompatible) in specs {
            let path = directory.path().join(name);
            if let Some(bytes) = bytes {
                std::fs::write(&path, bytes)?;
            }
            expected.push(RequiredAsset {
                name: "test-asset",
                version: "test-version",
                path,
                size,
                sha256: sha256.to_owned(),
                suggested_source: "fixture",
                incompatible_reason: incompatible.then(|| "unsupported on this host".to_owned()),
            });
        }
        let status = required_assets_status(&expected)?;
        assert!(!status.complete);
        assert_eq!(status.assets.len(), 6);
        assert_eq!(status.missing.len(), 5);
        for (name, expected_state) in [
            ("missing", AssetState::Missing),
            ("incomplete", AssetState::Incomplete),
            ("short-digest", AssetState::Corrupt),
            ("overlong", AssetState::Corrupt),
            ("complete", AssetState::Complete),
            ("incompatible", AssetState::Incompatible),
        ] {
            let asset = status
                .assets
                .iter()
                .find(|asset| asset.path == Some(directory.path().join(name).display().to_string()))
                .ok_or_else(|| anyhow!("missing report for {name}"))?;
            assert_eq!(asset.state, expected_state, "{name}");
        }
        let complete_report = status.assets.last().context("status reports are present")?;
        assert_eq!(complete_report.actual_size, Some(3));
        assert_eq!(complete_report.actual_sha256.as_deref(), Some(complete));
        Ok(())
    }

    #[test]
    fn missing_explicit_cpu_variant_does_not_load_the_owned_quantized_container() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.0 {
                    if let Some(value) = value {
                        std::env::set_var(key, value);
                    } else {
                        std::env::remove_var(key);
                    }
                }
            }
        }
        let keys = [
            "RSRS_M3_DIR",
            "RSRS_DATA_DIR",
            "RSRS_ENGINE",
            "RSRS_MODEL_VARIANT",
            "RSRS_CPU_OWNED_ORT_EXPERIMENT",
        ];
        let _restore = Restore(
            keys.into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
        );
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join("onnx"))?;
        std::fs::write(
            dir.path().join("onnx/model_quantized.onnx"),
            b"baseline presence only",
        )?;
        std::fs::write(dir.path().join("tokenizer.json"), b"{}")?;
        std::env::set_var("RSRS_M3_DIR", dir.path());
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::set_var("RSRS_ENGINE", "cpu");
        std::env::set_var("RSRS_MODEL_VARIANT", "fp16");
        std::env::remove_var("RSRS_CPU_OWNED_ORT_EXPERIMENT");
        let error = respire_app::memory::bge::BgeEmbedder::load()
            .err()
            .ok_or_else(|| anyhow!("missing explicit fp16 must fail"))?;
        let message = format!("{error:#}");
        assert!(message.contains("model_fp16.onnx"), "{message}");
        assert!(message.contains("--model fp16"), "{message}");
        assert!(!message.contains("model_quantized.cpu-v1.ort"), "{message}");
        Ok(())
    }

}

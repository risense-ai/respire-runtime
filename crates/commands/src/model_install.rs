//! Explicitly install the local BGE-M3 model files.
//!
//! Does not touch the session or create a memory store. A failed download leaves
//! partial files outside the loader's paths. A model that already
//! verifies is not overwritten. Hugging Face mirrors only replace the host;
//! CPU release proxies have their own source list and retain the pinned bytes.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::model_progress;
use respire_app::memory::bge::{expand_home, model_files_present};
use respire_protocol::{
    AssetRequirement, AssetState, AssetsStatus, BackendLoadState, BackendLoadStatus,
};

pub fn install_engines() -> Result<Vec<String>> {
    #[cfg(windows)]
    {
        let dll = respire_app::memory::onnx::accelerator_catalog_path()?
            .context("Windows ML catalog path missing")?;
        let paths = respire_spawn::install_accelerators(&dll)?;
        let directory = dll
            .parent()
            .and_then(Path::parent)
            .context("Windows ML engine directory missing")?;
        let target = directory.join("providers.json");
        let staged = directory.join(format!(".providers-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&staged, serde_json::to_vec_pretty(&paths)?)?;
        if let Err(error) = respire_spawn::replace_provider_manifest(&staged, &target) {
            let _ = std::fs::remove_file(&staged);
            return Err(error.into());
        }
        Ok(paths.into_keys().collect())
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

/// HuggingFace repo (where the ONNX actually lives, not the BAAI source repo).
pub const MODEL_REPO: &str = "Xenova/bge-m3";
/// Verified revision (this commit's tokenizer/onnx hashes match the local read-only model).
pub const MODEL_REVISION: &str = "4de13258303883538bd53b696b452bf8099f0858";
const ONNX_SHA256: &str = "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d";
const TOKENIZER_SHA256: &str = "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790";

/// Preserve the upstream model card/license separately from the Core SDK license.
fn write_model_notices(dest: &Path, model: &str, repo: &str, revision: &str) -> Result<()> {
    let source = serde_json::json!({"repository":repo,"revision":revision});
    std::fs::write(
        dest.join("MODEL-SOURCE.json"),
        serde_json::to_vec_pretty(&source)?,
    )?;
    std::fs::write(
        dest.join("MODEL-CARD.md"),
        include_str!("../../../docs/model-notices/bge-m3-MODEL-CARD.md"),
    )?;
    std::fs::write(
        dest.join("LICENSE.txt"),
        include_str!("../../../docs/model-notices/FlagEmbedding-LICENSE.txt"),
    )?;
    std::fs::write(
        dest.join("NOTICE-SOURCES.json"),
        include_str!("../../../docs/model-notices/sources.json"),
    )?;
    let _ = model;
    Ok(())
}

pub struct InstallReport {
    pub dir: PathBuf,
    pub skipped: bool,
}

/// Download sources all serve the same pinned BGE-M3 files.
pub const MIRRORS: &[&str] = &[
    "auto",
    "https://hf-mirror.com",
    "https://hf-mirror.net",
    "https://huggingface.co",
];

pub fn mirror_from_env() -> Option<String> {
    respire_app::env::var("RSRS_MIRROR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            respire_app::service::read_agent_config()["model_mirror"]
                .as_str()
                .map(str::to_owned)
        })
}

pub fn install_target_dir(explicit: Option<&str>) -> Result<PathBuf> {
    let default = respire_app::memory::bge::m3_model_dir()?;
    Ok(explicit
        .filter(|s| !s.trim().is_empty())
        .map(|s| expand_home(s.trim()))
        .unwrap_or(default))
}

pub fn install_m3(mirror: Option<&str>) -> Result<InstallReport> {
    let _operation = model_progress::Operation::begin_download()?;
    install_m3_inner(mirror)
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
static PROBE_HELPER_HOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Only the standalone runtime installs the early private helper entry.
pub fn enable_backend_probe_host() {
    PROBE_HELPER_HOST.store(true, std::sync::atomic::Ordering::Release);
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
    anyhow::ensure!(PROBE_HELPER_HOST.load(std::sync::atomic::Ordering::Acquire),
        "this host image has not installed the private backend probe entry");
    anyhow::ensure!(!probe_cancelled(), "runtime is draining; probe was not started");
    let nonce = uuid::Uuid::new_v4().to_string();
    // Existing drain accounting waits for this guard. Child cleanup runs before it is dropped.
    let _admission = crate::rpc_serve::begin_admission(nonce.clone(), "backend_load_probe")
        .context("runtime drain rejected the backend probe")?;
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

/// Describe preparation without downloading, probing, changing selection or releasing native code.
/// The caller binds this snapshot to the existing authenticated operation scope.
pub fn model_install_plan() -> Result<AssetsStatus> {
    let epoch = crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire);
    let selection = ProbeSelection::capture()?;
    let identity = selection.identity()?;
    let plan = installation_plan_for(&selection)?;
    anyhow::ensure!(
        crate::rpc_worker::GENERATION.load(std::sync::atomic::Ordering::Acquire) == epoch
            && ProbeSelection::capture()?.identity()? == identity,
        "selected model changed while planning installation"
    );
    Ok(plan)
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
        let directory = std::path::absolute(install_target_dir(None)?)?;
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
        selection.directory = std::path::absolute(install_target_dir(None)?)?;
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
    if let Some(mirror) = &intent.mirror { model_origins(Some(mirror))?; }
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
    enable_backend_probe_host();
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

/// Verify prepared files and fresh native loading for the current authoritative selection.
/// The authenticated paused dispatcher must install `watch_control_parent` after reading
/// both frames, and allow the 150s native probe plus file validation and child cleanup.
pub fn model_install_verify() -> Result<AssetsStatus> {
    // Private control dispatch bypasses normal startup's probe-host initialization.
    enable_backend_probe_host();
    respire_app::memory::bge::invalidate_cpu_ort_validation()?;
    assets_status()
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

/// Fetch one extra onnx variant (e.g. fp16 for GPU/NPU) into the model dir.
/// Skips when the pinned file already verifies. Never removes other variants.
pub fn install_variant(variant_name: &str, mirror: Option<&str>) -> Result<()> {
    use respire_app::memory::onnx::parse_variant;
    let _operation = model_progress::Operation::begin_download()?;
    let variant = parse_variant(variant_name)?;
    let dest = install_target_dir(None)?;
    let origins = model_origins(mirror)?;
    install_variant_into(variant, &dest, &origins)
}

fn install_variant_into(
    variant: respire_app::memory::onnx::ModelVariant,
    dest: &Path,
    origins: &[String],
) -> Result<()> {
    let file = respire_app::memory::onnx::variant_file_name(variant.name);
    std::fs::create_dir_all(&dest)?;
    let tmp = variant_staging_dir(&dest);
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let dest_path = dest.join(&file);
    let tmp_path = tmp.join(&file);
    if !variant_file_valid(&dest_path, variant)? {
        // A verified leftover from an earlier attempt is published without
        // re-downloading; only an unverified destination downloads.
        if !variant_file_valid(&tmp_path, variant)? {
            let sources = origins
                .iter()
                .map(|origin| file_url(origin, &file))
                .collect::<Vec<_>>();
            download_with_fallback(
                &sources,
                &tmp_path,
                variant.sha256,
                true,
                DownloadTimeouts::default(),
            )?;
        }
        std::fs::create_dir_all(dest.join("onnx"))?;
        anyhow::ensure!(
            variant_file_valid(&tmp_path, variant)?,
            "downloaded variant size or checksum mismatch"
        );
        replace_file(&tmp_path, &dest_path)?;
    }
    anyhow::ensure!(
        variant_file_valid(&dest_path, variant)?,
        "BGE-M3 {} install is incomplete",
        variant.name
    );
    Ok(())
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

/// Kept for the existing RPC caller; a mirror never permits Runtime downloads.
pub fn prepare_m3_from_mirror(_mirror: &str) -> Result<()> {
    verify_m3_assets()
}

/// The background operation is already reserved; only verify installed assets.
pub fn prepare_m3_for_index() -> Result<()> {
    verify_m3_assets()
}

fn install_m3_inner(mirror: Option<&str>) -> Result<InstallReport> {
    let dest = install_target_dir(None)?;
    let origins = model_origins(mirror)?;
    let files = [
        ("tokenizer.json", TOKENIZER_SHA256),
        ("onnx/model_quantized.onnx", ONNX_SHA256),
    ];
    std::fs::create_dir_all(&dest)?;
    // A pinned revision allows cancellation, restart and mirror changes to reuse
    // partial bytes without exposing an incomplete file to the model loader.
    let tmp = dest.join(format!(".download-{MODEL_REVISION}"));
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let mut skipped = true;
    for (name, sha) in files {
        if file_valid(&dest.join(name), sha)? {
            continue;
        }
        if file_valid(&tmp.join(name), sha)? {
            skipped = false;
            continue;
        }
        let sources = origins
            .iter()
            .map(|origin| file_url(origin, name))
            .collect::<Vec<_>>();
        download_with_fallback(
            &sources,
            &tmp.join(name),
            sha,
            name.ends_with(".onnx"),
            DownloadTimeouts::default(),
        )?;
        skipped = false;
    }
    // Publish only after every required replacement has passed the pinned checksum.
    std::fs::create_dir_all(dest.join("onnx"))?;
    for (name, _) in files {
        if tmp.join(name).is_file() {
            replace_file(&tmp.join(name), &dest.join(name))?;
        }
    }
    std::fs::remove_dir_all(&tmp)?;
    anyhow::ensure!(
        model_files_present(&dest) && m3_model_valid(&dest.join("onnx/model_quantized.onnx"))?,
        "BGE-M3 quantized install is incomplete"
    );
    write_model_notices(&dest, "m3", MODEL_REPO, MODEL_REVISION)?;
    let cpu_ready = prepare_cpu_ort(&dest)?;
    Ok(InstallReport {
        dir: dest,
        skipped: skipped && cpu_ready,
    })
}

/// Runs outside the Core worker on the existing cancellable model-operation thread.
/// Keep ONNX for GPU/NPU. A CPU container upgrade does not change stored vectors or index schema.
fn prepare_cpu_ort(directory: &Path) -> Result<bool> {
    use respire_app::memory::bge;
    if !bge::cpu_owned_mode(respire_app::memory::onnx::configured_engine()?)? {
        return Ok(true);
    }
    if file_valid(&bge::cpu_ort_path(directory)?, bge::CPU_ORT_SHA256)? {
        return Ok(true);
    }
    // Legacy packaged/system model directories may be read-only. Upgrade into the user cache.
    let dest = bge::cpu_ort_cache_path()?;
    if file_valid(&dest, bge::CPU_ORT_SHA256)? {
        return Ok(true);
    }
    let parent = dest.parent().context("CPU model cache directory missing")?;
    std::fs::create_dir_all(parent)?;
    let partial = parent.join(format!(".download-{}.ort", bge::CPU_ORT_REVISION));
    let sources = cpu_ort_sources()?;
    let downloaded_from = if !file_valid(&partial, bge::CPU_ORT_SHA256)? {
        Some(download_with_fallback(
            &sources,
            &partial,
            bge::CPU_ORT_SHA256,
            true,
            DownloadTimeouts::default(),
        )?)
    } else {
        None
    };
    anyhow::ensure!(
        partial.metadata()?.len() == bge::CPU_ORT_SIZE,
        "CPU model size mismatch"
    );
    remove_download_parts(&partial)?;
    replace_file(&partial, &dest)?;
    bge::invalidate_cpu_ort_validation()?;
    std::fs::write(
        parent.join("CPU-MODEL-SOURCE.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "container_version":bge::CPU_ORT_REVISION,"source_repository":MODEL_REPO,
            "source_revision":MODEL_REVISION,"source_onnx_sha256":ONNX_SHA256,
            "cpu_ort_sha256":bge::CPU_ORT_SHA256,"url":bge::CPU_ORT_URL,
            "downloaded_from":downloaded_from,
            "ort_version":"1.28.0","graph_optimization":99,"weights_changed":false
        }))?,
    )?;
    Ok(false)
}

pub fn cpu_model_preparation_needed() -> Result<bool> {
    let directory = respire_app::memory::bge::discovered_model_dir()?;
    if !respire_app::memory::bge::cpu_owned_mode(respire_app::memory::onnx::configured_engine()?)? {
        return Ok(false);
    }
    Ok(!model_files_present(&directory)
        || !respire_app::memory::bge::cpu_ort_present(&directory)?)
}

pub struct UninstallReport {
    pub dir: PathBuf,
    pub removed: bool,
}

fn refuse_system_model_dir(path: &Path) -> Result<()> {
    let text = path.to_string_lossy().replace('\\', "/");
    if text.contains("/usr/lib/respire/models") {
        anyhow::bail!(
            "refusing to delete the system model dir: {}",
            path.display()
        );
    }
    Ok(())
}

fn remove_model_dir(path: &Path) -> Result<bool> {
    refuse_system_model_dir(path)?;
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(path)
        .map_err(|e| anyhow!("failed to delete {}: {e}", path.display()))?;
    Ok(true)
}

/// Delete the BGE-M3 files at the install target and drop the in-process session.
pub fn uninstall_m3() -> Result<UninstallReport> {
    respire_app::memory::onnx::reset_sessions()?;
    let dest = install_target_dir(None)?;
    let removed = remove_model_dir(&dest)?;
    Ok(UninstallReport { dir: dest, removed })
}

#[cfg(test)]
struct TmpGuard(PathBuf);

#[cfg(test)]
impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn validate_mirror(value: &str) -> Result<()> {
    if value == "auto" {
        return Ok(());
    }
    origin_from_mirror(value).map(|_| ())
}

fn origin_from_mirror(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("--mirror must not be empty");
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let Some((scheme, rest)) = with_scheme.split_once("://") else {
        anyhow::bail!("--mirror is invalid: {raw}");
    };
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("--mirror only supports http/https");
    }
    let hostport = match rest.split('/').next() {
        Some(h) if !h.is_empty() => h.trim(),
        _ => anyhow::bail!("--mirror is missing a host"),
    };
    anyhow::ensure!(
        !hostport.contains(['@', '?', '#']) && !hostport.chars().any(char::is_whitespace),
        "mirror must be a host without credentials, query or fragment"
    );
    Ok(format!("{scheme}://{hostport}"))
}

fn model_origins(mirror: Option<&str>) -> Result<Vec<String>> {
    let setting = mirror
        .map(str::to_owned)
        .or_else(mirror_from_env)
        .unwrap_or_else(|| "auto".to_owned());
    if setting.trim() == "auto" {
        Ok(MIRRORS[1..]
            .iter()
            .map(|origin| (*origin).to_owned())
            .collect())
    } else {
        Ok(vec![origin_from_mirror(&setting)?])
    }
}

fn cpu_ort_sources() -> Result<Vec<String>> {
    let setting = respire_app::env::var("RSRS_CPU_ORT_MIRROR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            respire_app::service::read_agent_config()["model_cpu_ort_mirror"]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "auto".to_owned());
    cpu_ort_sources_from_setting(&setting)
}

fn cpu_ort_sources_from_setting(setting: &str) -> Result<Vec<String>> {
    use respire_app::memory::bge::CPU_ORT_URL;
    // Release containers and Hugging Face ONNX files use different URL layouts.
    // Never turn a Hugging Face model into a substitute for the pinned CPU ORT.
    match setting.trim() {
        "auto" => Ok(vec![
            format!("https://gh-proxy.org/{CPU_ORT_URL}"),
            CPU_ORT_URL.to_owned(),
        ]),
        "github" | "https://github.com" | "https://github.com/" => Ok(vec![CPU_ORT_URL.to_owned()]),
        value => {
            anyhow::ensure!(
                !value.is_empty() && !value.chars().any(char::is_whitespace),
                "CPU ORT mirror must be a nonempty origin without whitespace"
            );
            let supplied = if value.contains("://") {
                value.to_owned()
            } else {
                format!("https://{value}")
            };
            let origin = url::Url::parse(&supplied).context("invalid CPU ORT mirror origin")?;
            anyhow::ensure!(
                matches!(origin.scheme(), "http" | "https") && origin.host_str().is_some(),
                "CPU ORT mirror must be an http/https origin"
            );
            anyhow::ensure!(
                origin.username().is_empty()
                    && origin.password().is_none()
                    && origin.query().is_none()
                    && origin.fragment().is_none()
                    && origin.path() == "/",
                "CPU ORT mirror must be an origin without credentials, path, query or fragment"
            );
            // Only the public release URL goes to the proxy. No account headers.
            Ok(vec![format!(
                "{}/{CPU_ORT_URL}",
                origin.as_str().trim_end_matches('/')
            )])
        }
    }
}

fn file_url(origin: &str, rel: &str) -> String {
    format!(
        "{}/{}/resolve/{}/{}",
        origin.trim_end_matches('/'),
        MODEL_REPO,
        MODEL_REVISION,
        rel
    )
}

fn replace_file(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        std::fs::remove_file(to)
            .with_context(|| format!("cannot replace invalid file {}", to.display()))?;
    }
    std::fs::rename(from, to).with_context(|| format!("failed to place {}", to.display()))
}

fn m3_model_valid(path: &Path) -> Result<bool> {
    file_valid(path, ONNX_SHA256)
}

fn variant_staging_dir(dest: &Path) -> PathBuf {
    dest.join(format!(".variants-{MODEL_REVISION}"))
}

fn variant_file_valid(
    path: &Path,
    variant: respire_app::memory::onnx::ModelVariant,
) -> Result<bool> {
    if !path.is_file() || path.metadata()?.len() != variant.size {
        return Ok(false);
    }
    file_valid(path, variant.sha256)
}

fn pinned_size(expected: &str) -> Option<u64> {
    // tokenizer.json at the same fixed upstream revision (LFS size/hash verified).
    if expected == TOKENIZER_SHA256 {
        return Some(17_082_821);
    }
    if expected == respire_app::memory::bge::CPU_ORT_SHA256 {
        Some(respire_app::memory::bge::CPU_ORT_SIZE)
    } else {
        respire_app::memory::onnx::MODEL_VARIANTS
            .iter()
            .find(|variant| variant.sha256.eq_ignore_ascii_case(expected))
            .map(|variant| variant.size)
    }
}

fn file_valid(path: &Path, expected: &str) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    if let Some(size) = pinned_size(expected) {
        if path.metadata()?.len() != size {
            return Ok(false);
        }
    }
    let actual = sha256_file(path)?;
    Ok(actual.eq_ignore_ascii_case(expected))
}

fn sha256_file(path: &Path) -> Result<String> {
    let item = path.file_name().unwrap_or_default().to_string_lossy();
    let total = path.metadata()?.len();
    let mut checked = 0;
    model_progress::update("verify", &item, 0, Some(total))?;
    let mut file =
        File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        checked += n as u64;
        model_progress::update("verify", &item, checked, Some(total))?;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Bound stalled network operations, not the lifetime of a progressing download.
#[derive(Clone, Copy)]
struct DownloadTimeouts {
    connect: std::time::Duration,
    read: std::time::Duration,
    write: std::time::Duration,
}

impl Default for DownloadTimeouts {
    fn default() -> Self {
        use std::time::Duration;
        Self {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(30),
            write: Duration::from_secs(10),
        }
    }
}

/// Every source must provide the same pinned artifact. Network/checksum errors
/// advance to the next source; cancellation and local filesystem failures do not.
/// A single explicit source therefore never silently falls back to another host.
fn download_with_fallback(
    sources: &[String],
    dest: &Path,
    expected: &str,
    parallel: bool,
    timeouts: DownloadTimeouts,
) -> Result<String> {
    let mut failures = Vec::new();
    for url in sources {
        model_progress::check()?;
        let result = if parallel && !dest.exists() {
            download_parallel_with_timeouts(url, dest, expected, 16 * 1024 * 1024, timeouts)
                .and_then(|used| {
                    if used {
                        Ok(())
                    } else {
                        download_verified_with_timeouts(url, dest, expected, timeouts)
                    }
                })
        } else {
            download_verified_with_timeouts(url, dest, expected, timeouts)
        };
        match result {
            Ok(()) => {
                // A no-Range fallback may have finished a prior segmented transfer.
                remove_download_parts(dest)?;
                return Ok(url.clone());
            }
            Err(error) => {
                model_progress::check()?;
                if error.downcast_ref::<std::io::Error>().is_some() {
                    return Err(error);
                }
                failures.push(format!("{url}: {error:#}"));
            }
        }
    }
    anyhow::bail!("BGE-M3 download failed: {}", failures.join("; "))
}

#[cfg(test)]
fn download_verified(url: &str, dest: &Path, expected: &str) -> Result<()> {
    download_verified_with_timeouts(url, dest, expected, DownloadTimeouts::default())
}

fn download_verified_with_timeouts(
    url: &str,
    dest: &Path,
    expected: &str,
    timeouts: DownloadTimeouts,
) -> Result<()> {
    download_verified_bounded(url, dest, expected, timeouts, pinned_size(expected))
}

fn download_verified_bounded(
    url: &str,
    dest: &Path,
    expected: &str,
    timeouts: DownloadTimeouts,
    expected_size: Option<u64>,
) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if dest.is_file()
        && expected_size
            .is_some_and(|size| dest.metadata().map(|m| m.len() > size).unwrap_or(false))
    {
        std::fs::remove_file(dest)?;
    }
    let offset = if dest.is_file() {
        dest.metadata()?.len()
    } else {
        0
    };
    let resp = match download_response(url, dest, offset, timeouts) {
        Ok(response) => response,
        Err(error)
            if offset > 0
                && error
                    .downcast_ref::<ureq::Error>()
                    .is_some_and(|error| matches!(error, ureq::Error::Status(416, _))) =>
        {
            std::fs::remove_file(dest)?;
            download_response(url, dest, 0, timeouts)?
        }
        Err(error) => return Err(error),
    };
    let resumed = resp.status() == 206;
    let total = if resumed {
        let range = resp
            .header("Content-Range")
            .ok_or_else(|| anyhow!("partial response has no Content-Range"))?;
        let (start, total) = parse_content_range(range)?;
        anyhow::ensure!(
            start == offset,
            "partial response starts at {start}, expected {offset}"
        );
        Some(total)
    } else {
        anyhow::ensure!(
            resp.status() == 200,
            "unexpected download status {}",
            resp.status()
        );
        resp.header("Content-Length")
            .and_then(|v| v.parse::<u64>().ok())
    };
    if let (Some(pinned), Some(reported)) = (expected_size, total) {
        anyhow::ensure!(
            pinned == reported,
            "model size mismatch: response {reported}, expected {pinned}"
        );
    }
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    let mut reader = resp.into_reader();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(resumed)
        .truncate(!resumed)
        .open(dest)
        .with_context(|| format!("failed to write {}", dest.display()))?;
    let mut buf = [0u8; 64 * 1024];
    let mut written: u64 = if resumed { offset } else { 0 };
    loop {
        model_progress::update("download", &item, written, total)?;
        let n = read_download(&mut reader, &mut buf, url)?;
        if n == 0 {
            break;
        }
        if let Some(limit) = expected_size {
            anyhow::ensure!(
                written <= limit && n as u64 <= limit - written,
                "model response exceeds pinned size {limit}"
            );
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("failed to write {}", dest.display()))?;
        written += n as u64;
    }
    file.flush()
        .with_context(|| format!("failed to write {}", dest.display()))?;
    drop(file);
    if let Some(total) = total {
        anyhow::ensure!(
            written == total,
            "download incomplete: {written}/{total} bytes; partial file retained"
        );
    }
    if let Some(expected) = expected_size {
        anyhow::ensure!(
            written == expected,
            "model size mismatch: {written}/{expected}"
        );
    }
    model_progress::update("verify", &item, written, Some(written))?;
    let actual = sha256_file(dest)?;
    if !actual.eq_ignore_ascii_case(expected) {
        // A saved prefix can be corrupt. Retry this source once from byte zero;
        // the fresh request cannot enter this branch with a nonzero offset.
        if resumed && offset > 0 {
            std::fs::remove_file(dest)?;
            return download_verified_bounded(url, dest, expected, timeouts, expected_size);
        }
        // Unknown-length EOF may be a truncated response. Preserve resumable bytes.
        if total.is_some() {
            std::fs::remove_file(dest)?;
        }
        anyhow::bail!(
            "checksum failed: {} SHA256={actual} (expected {expected})",
            dest.display()
        );
    }
    Ok(())
}

fn parse_content_range(value: &str) -> Result<(u64, u64)> {
    let value = value
        .strip_prefix("bytes ")
        .ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (range, total) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let start = start.parse::<u64>()?;
    let end = end.parse::<u64>()?;
    let total = total.parse::<u64>()?;
    anyhow::ensure!(start <= end && end < total, "invalid Content-Range bounds");
    Ok((start, total))
}

fn download_parts_path(dest: &Path) -> PathBuf {
    // Preserve the existing partial-directory name across installer upgrades.
    dest.with_extension("onnx.parts")
}

fn remove_download_parts(dest: &Path) -> Result<()> {
    match std::fs::remove_dir_all(download_parts_path(dest)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to remove completed model segments"),
    }
}

/// Four persistent ranges. Only the coordinator updates task state; workers
/// receive cancellation through a shared flag and retain their partial files.
#[cfg(test)]
fn download_parallel(url: &str, dest: &Path, expected: &str, minimum: u64) -> Result<bool> {
    download_parallel_with_timeouts(url, dest, expected, minimum, DownloadTimeouts::default())
}

fn download_parallel_with_timeouts(
    url: &str,
    dest: &Path,
    expected: &str,
    minimum: u64,
    timeouts: DownloadTimeouts,
) -> Result<bool> {
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    };
    use std::time::Duration;
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, 0, None)?;
    let response = download_agent(timeouts)
        .get(url)
        .set("Accept-Encoding", "identity")
        .set("Range", "bytes=0-0")
        .call()
        .with_context(|| format!("download probe failed ({url})"))?;
    model_progress::check()?;
    if response.status() == 200 {
        return Ok(false);
    }
    anyhow::ensure!(response.status() == 206, "unexpected range probe status");
    let range = response
        .header("Content-Range")
        .ok_or_else(|| anyhow!("range probe has no Content-Range"))?;
    let (start, total) = parse_content_range(range)?;
    anyhow::ensure!(start == 0, "range probe starts at {start}");
    if let Some(pinned) = pinned_size(expected) {
        anyhow::ensure!(
            total == pinned,
            "model size mismatch: response {total}, expected {pinned}"
        );
    }
    drop(response);
    if total < minimum || total < 4 {
        return Ok(false);
    }
    let parts = download_parts_path(dest);
    std::fs::create_dir_all(&parts)?;
    for index in 0..4 {
        let path = parts.join(index.to_string());
        let length = total * (index + 1) / 4 - total * index / 4;
        if path.is_file() && path.metadata()?.len() > length {
            // Stale or corrupt segment lengths cannot be safely resumed.
            std::fs::remove_dir_all(&parts)?;
            std::fs::create_dir_all(&parts)?;
            break;
        }
    }
    let counts: [AtomicU64; 4] = std::array::from_fn(|_| AtomicU64::new(0));
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::channel();
    let result = std::thread::scope(|scope| -> Result<()> {
        for (index, count) in counts.iter().enumerate() {
            let begin = total * index as u64 / 4;
            let end = total * (index + 1) as u64 / 4;
            let path = parts.join(index.to_string());
            let sender = sender.clone();
            let stop = &stop;
            scope.spawn(move || {
                let result = download_part(url, &path, begin, end, total, count, stop, timeouts);
                let failed = result.is_err();
                let _ = sender.send(result);
                if failed {
                    stop.store(true, Ordering::Relaxed);
                }
            });
        }
        drop(sender);
        let mut finished = 0;
        let mut failure = None;
        while finished < 4 {
            let done = counts
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .sum();
            if let Err(error) = model_progress::update("download", &item, done, Some(total)) {
                stop.store(true, Ordering::Relaxed);
                if failure.is_none() {
                    failure = Some(error);
                }
            }
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(result) => {
                    finished += 1;
                    if let Err(error) = result {
                        // A concurrent network failure must not hide a disk failure
                        // reported by another worker and turn it into a failover.
                        if failure.is_none() || error.downcast_ref::<std::io::Error>().is_some() {
                            failure = Some(error);
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("download workers disconnected")
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    });
    result?;
    let mut merged = File::create(dest)?;
    for index in 0..4 {
        model_progress::check()?;
        std::io::copy(&mut File::open(parts.join(index.to_string()))?, &mut merged)?;
    }
    merged.flush()?;
    drop(merged);
    if !file_valid(dest, expected)? {
        std::fs::remove_file(dest)?;
        std::fs::remove_dir_all(&parts)?;
        // A corrupt saved prefix must not exhaust the final healthy source.
        // Discard every segment and retry that source once from byte zero.
        download_verified_with_timeouts(url, dest, expected, timeouts)?;
        return Ok(true);
    }
    std::fs::remove_dir_all(parts)?;
    Ok(true)
}

fn download_part(
    url: &str,
    path: &Path,
    begin: u64,
    end: u64,
    total: u64,
    count: &std::sync::atomic::AtomicU64,
    stop: &std::sync::atomic::AtomicBool,
    timeouts: DownloadTimeouts,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    let length = end - begin;
    let mut offset = if path.is_file() {
        path.metadata()?.len()
    } else {
        0
    };
    anyhow::ensure!(offset <= length, "saved download segment is too long");
    count.store(offset, Ordering::Relaxed);
    if offset == length {
        return Ok(());
    }
    anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
    let start = begin + offset;
    let response = download_agent(timeouts)
        .get(url)
        .set("Accept-Encoding", "identity")
        .set("Range", &format!("bytes={start}-{}", end - 1))
        .call()
        .with_context(|| format!("segment download failed ({url})"))?;
    anyhow::ensure!(
        response.status() == 206,
        "source did not honor the segment range"
    );
    let expected_range = format!("bytes {start}-{}/{total}", end - 1);
    anyhow::ensure!(
        response.header("Content-Range") == Some(expected_range.as_str()),
        "source returned an incorrect segment range"
    );
    let mut reader = response.into_reader();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    while offset < length {
        anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
        let limit = buffer.len().min((length - offset) as usize);
        let received = reader
            .read(&mut buffer[..limit])
            .map_err(|error| anyhow!("segment interrupted ({url}): {error}"))?;
        anyhow::ensure!(
            received > 0,
            "segment download incomplete; partial bytes retained"
        );
        file.write_all(&buffer[..received])?;
        offset += received as u64;
        count.store(offset, Ordering::Relaxed);
    }
    file.flush()?;
    Ok(())
}

fn download_agent(timeouts: DownloadTimeouts) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeouts.connect)
        .timeout_read(timeouts.read)
        .timeout_write(timeouts.write)
        .build()
}

fn download_response(
    url: &str,
    dest: &Path,
    offset: u64,
    timeouts: DownloadTimeouts,
) -> Result<ureq::Response> {
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, offset, None)?;
    // Headers and body reads share the same bounded idle wait. No total deadline
    // cuts off a large model while bytes are still arriving.
    let request = download_agent(timeouts)
        .get(url)
        .set("Accept-Encoding", "identity");
    let request = if offset > 0 {
        request.set("Range", &format!("bytes={offset}-"))
    } else {
        request
    };
    let response = request.call();
    model_progress::check()?;
    response.with_context(|| format!("download failed ({url})"))
}

fn read_download(reader: &mut impl Read, buf: &mut [u8], url: &str) -> Result<usize> {
    let result = reader.read(buf);
    model_progress::check()?;
    result.map_err(|error| anyhow!("download interrupted ({url}): {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

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

    #[test]
    fn verified_variant_survives_base_cleanup_and_publishes_without_network() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let variant = respire_app::memory::onnx::ModelVariant {
            name: "fp16",
            size: 3,
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        };
        let staging = variant_staging_dir(dir.path());
        std::fs::create_dir_all(staging.join("onnx"))?;
        std::fs::write(staging.join("onnx/model_fp16.onnx"), b"abc")?;
        let base_staging = dir.path().join(format!(".download-{MODEL_REVISION}"));
        std::fs::create_dir_all(&base_staging)?;
        std::fs::remove_dir_all(base_staging)?;
        install_variant_into(variant, dir.path(), &[])?;
        install_variant_into(variant, dir.path(), &[])?;
        assert_eq!(
            std::fs::read(dir.path().join("onnx/model_fp16.onnx"))?,
            b"abc"
        );
        assert!(!staging.join("onnx/model_fp16.onnx").exists());
        Ok(())
    }

    #[test]
    fn bounded_download_rejects_headers_stream_overflow_and_short_eof() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        for (headers, body, valid) in [
            ("Content-Length: 4\r\n", "abcd", false),
            (
                "Transfer-Encoding: chunked\r\n",
                "4\r\nabcd\r\n0\r\n\r\n",
                false,
            ),
            ("", "ab", false),
            ("Content-Length: 3\r\n", "abc", true),
        ] {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join("model");
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let url = format!("http://{}/model", listener.local_addr()?);
            let response = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{headers}\r\n{body}");
            let worker = std::thread::spawn(move || -> Result<()> {
                let (mut socket, _) = listener.accept()?;
                socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    anyhow::ensure!(socket.read(&mut byte)? == 1, "request ended early");
                    request.push(byte[0]);
                }
                socket.write_all(response.as_bytes())?;
                Ok(())
            });
            let result =
                download_verified_bounded(&url, &target, expected, fast_timeouts(), Some(3));
            worker.join().map_err(|_| anyhow!("server panicked"))??;
            assert_eq!(result.is_ok(), valid, "unexpected result: {result:?}");
            if target.exists() {
                assert!(target.metadata()?.len() <= 3);
            }
        }
        Ok(())
    }

    #[test]
    fn parse_source_and_mirror() -> Result<()> {
        assert_eq!(
            origin_from_mirror("hf-mirror.com")?,
            "https://hf-mirror.com"
        );
        assert_eq!(
            origin_from_mirror("http://127.0.0.1:8080/x")?,
            "http://127.0.0.1:8080"
        );
        assert!(origin_from_mirror("").is_err());
        Ok(())
    }

    #[test]
    fn cpu_source_policy_preserves_exact_release_and_explicit_sources() -> Result<()> {
        let official = respire_app::memory::bge::CPU_ORT_URL;
        assert_eq!(
            cpu_ort_sources_from_setting("auto")?,
            vec![
                format!("https://gh-proxy.org/{official}"),
                official.to_owned()
            ]
        );
        assert_eq!(
            cpu_ort_sources_from_setting(" github ")?,
            vec![official.to_owned()]
        );
        assert_eq!(
            cpu_ort_sources_from_setting("https://github.com/")?,
            vec![official.to_owned()]
        );
        assert_eq!(
            cpu_ort_sources_from_setting("mirror.example")?,
            vec![format!("https://mirror.example/{official}")]
        );
        assert_eq!(
            cpu_ort_sources_from_setting("http://127.0.0.1:8080/")?,
            vec![format!("http://127.0.0.1:8080/{official}")]
        );
        for value in [
            "",
            "https://user:secret@mirror.example",
            "file:///tmp/model",
            "https://mirror.example/path",
            "https://mirror.example/?token=secret",
            "https://mirror.example/#fragment",
        ] {
            assert!(
                cpu_ort_sources_from_setting(value).is_err(),
                "accepted unsafe mirror {value}"
            );
        }
        assert_eq!(
            model_origins(Some("auto"))?,
            MIRRORS[1..]
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            model_origins(Some("hf-mirror.com"))?,
            vec!["https://hf-mirror.com"]
        );
        assert_eq!(respire_app::memory::bge::CPU_ORT_SIZE, 569654128);
        assert_eq!(
            respire_app::memory::bge::CPU_ORT_SHA256,
            "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff"
        );
        Ok(())
    }

    fn fast_timeouts() -> DownloadTimeouts {
        use std::time::Duration;
        DownloadTimeouts {
            connect: Duration::from_millis(500),
            read: Duration::from_millis(200),
            write: Duration::from_millis(500),
        }
    }

    /// Hold the connection open until the test releases it, so advancing to the
    /// next source proves the client timeout fired rather than the server's EOF.
    fn stalled_source(
        body: Option<(&[u8], usize)>,
    ) -> Result<(
        String,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<Result<()>>,
    )> {
        use std::time::Duration;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/model", listener.local_addr()?);
        let body = body.map(|(prefix, total)| (prefix.to_vec(), total));
        let (release, wait) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || -> Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                anyhow::ensure!(
                    socket.read(&mut byte)? == 1,
                    "request closed before headers"
                );
                request.push(byte[0]);
            }
            if let Some((prefix, total)) = body {
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
                )?;
                socket.write_all(&prefix)?;
                socket.flush()?;
            }
            wait.recv_timeout(Duration::from_secs(10))?;
            Ok(())
        });
        Ok((url, release, server))
    }

    fn responding_source(
        body: &[u8],
        offset: usize,
    ) -> Result<(String, std::thread::JoinHandle<Result<()>>)> {
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let body = body.to_vec();
        let worker = std::thread::spawn(move || -> Result<()> {
            let request = server
                .recv_timeout(std::time::Duration::from_secs(5))?
                .ok_or_else(|| anyhow!("fallback source not requested"))?;
            let range = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("Range"));
            let response = if offset > 0 {
                assert_eq!(
                    range.map(|header| header.value.as_str()),
                    Some(format!("bytes={offset}-").as_str())
                );
                tiny_http::Response::from_data(body[offset..].to_vec())
                    .with_status_code(206)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            "Content-Range",
                            format!("bytes {offset}-{}/{}", body.len() - 1, body.len()),
                        )
                        .map_err(|_| anyhow!("invalid test header"))?,
                    )
            } else {
                assert!(range.is_none());
                tiny_http::Response::from_data(body)
            };
            request.respond(response)?;
            Ok(())
        });
        Ok((url, worker))
    }

    #[test]
    fn stalled_headers_and_body_fail_over_and_resume_without_waiting_for_eof() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body = b"pinned artifact from healthy fallback";
        let expected = hex::encode(Sha256::digest(body));
        for offset in [0, 7] {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join("model.ort");
            let prefix = if offset == 0 {
                None
            } else {
                Some((&body[..offset], body.len()))
            };
            let (first, release, stalled) = stalled_source(prefix)?;
            let (second, healthy) = responding_source(body, offset)?;
            let started = std::time::Instant::now();
            let result = download_with_fallback(
                &[first, second.clone()],
                &target,
                &expected,
                false,
                fast_timeouts(),
            );
            let elapsed = started.elapsed();
            release.send(())?;
            stalled
                .join()
                .map_err(|_| anyhow!("stalled source panicked"))??;
            healthy
                .join()
                .map_err(|_| anyhow!("healthy source panicked"))??;
            assert_eq!(result?, second);
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "fallback was not bounded: {elapsed:?}"
            );
            assert_eq!(std::fs::read(target)?, body);
        }
        Ok(())
    }

    #[test]
    fn stalled_range_probe_fails_over_without_publishing_unverified_bytes() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let parts = download_parts_path(&target);
        std::fs::create_dir_all(&parts)?;
        std::fs::write(
            parts.join("0"),
            b"saved segment from an interrupted range source",
        )?;
        let body = b"healthy model";
        let expected = hex::encode(Sha256::digest(body));
        let (first, release, stalled) = stalled_source(None)?;
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let second = format!("http://{}/model", server.server_addr());
        let healthy = std::thread::spawn(move || -> Result<()> {
            let probe = server
                .recv_timeout(std::time::Duration::from_secs(5))?
                .ok_or_else(|| anyhow!("probe missing"))?;
            assert!(probe
                .headers()
                .iter()
                .any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=0-0"));
            probe.respond(tiny_http::Response::from_data(body.to_vec()))?;
            let request = server
                .recv_timeout(std::time::Duration::from_secs(5))?
                .ok_or_else(|| anyhow!("full request missing"))?;
            request.respond(tiny_http::Response::from_data(body.to_vec()))?;
            Ok(())
        });
        let result = download_with_fallback(
            &[first, second.clone()],
            &target,
            &expected,
            true,
            fast_timeouts(),
        );
        release.send(())?;
        stalled
            .join()
            .map_err(|_| anyhow!("stalled source panicked"))??;
        healthy
            .join()
            .map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(result?, second);
        assert_eq!(std::fs::read(target)?, body);
        assert!(
            !parts.exists(),
            "no-Range fallback left unused CPU segments behind"
        );
        Ok(())
    }

    #[test]
    fn progressing_transfer_outlives_the_per_read_timeout() -> Result<()> {
        use std::time::Duration;
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let body = b"abcdefgh";
        let expected = hex::encode(Sha256::digest(body));
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/model", listener.local_addr()?);
        let worker = std::thread::spawn(move || -> Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_nodelay(true)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                anyhow::ensure!(
                    socket.read(&mut byte)? == 1,
                    "request closed before headers"
                );
                request.push(byte[0]);
            }
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            for byte in body {
                socket.write_all(&[*byte])?;
                socket.flush()?;
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        });
        let timeouts = DownloadTimeouts {
            read: Duration::from_millis(500),
            ..fast_timeouts()
        };
        let started = std::time::Instant::now();
        download_with_fallback(&[url], &target, &expected, false, timeouts)?;
        assert!(started.elapsed() > timeouts.read);
        worker
            .join()
            .map_err(|_| anyhow!("progressing source panicked"))??;
        assert_eq!(std::fs::read(target)?, body);
        Ok(())
    }

    #[test]
    fn corrupt_source_is_rejected_before_clean_fallback() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let expected = hex::encode(Sha256::digest(b"trusted model"));
        let (first, corrupt) = responding_source(b"corrupt model", 0)?;
        let (second, healthy) = responding_source(b"trusted model", 0)?;
        assert_eq!(
            download_with_fallback(
                &[first, second.clone()],
                &target,
                &expected,
                false,
                fast_timeouts()
            )?,
            second
        );
        corrupt
            .join()
            .map_err(|_| anyhow!("corrupt source panicked"))??;
        healthy
            .join()
            .map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(std::fs::read(target)?, b"trusted model");
        Ok(())
    }

    #[test]
    fn failed_source_releases_operation_slot_and_can_retry() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let body = b"verified retry";
        let expected = hex::encode(Sha256::digest(body));
        let (first, release, stalled) = stalled_source(None)?;
        let failed = {
            let _operation = model_progress::Operation::begin_download()?;
            let result =
                download_with_fallback(&[first], &target, &expected, false, fast_timeouts());
            assert_eq!(model_progress::status()?["active"], true);
            result
        };
        release.send(())?;
        stalled
            .join()
            .map_err(|_| anyhow!("stalled source panicked"))??;
        assert!(failed.is_err());
        assert!(!target.exists());
        assert_eq!(model_progress::status()?["active"], false);
        let (second, healthy) = responding_source(body, 0)?;
        {
            let _operation = model_progress::Operation::begin_download()?;
            download_with_fallback(&[second], &target, &expected, false, fast_timeouts())?;
        }
        healthy
            .join()
            .map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(model_progress::status()?["active"], false);
        assert_eq!(std::fs::read(target)?, body);
        Ok(())
    }

    #[test]
    fn local_disk_failure_is_not_retried_as_a_mirror_outage() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let parent = dir.path().join("not-a-directory");
        std::fs::write(&parent, b"keep")?;
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let error = download_with_fallback(
            &[url.clone(), url],
            &parent.join("model.ort"),
            "unused",
            false,
            fast_timeouts(),
        )
        .unwrap_err();
        assert!(
            error.downcast_ref::<std::io::Error>().is_some(),
            "disk failure identity lost: {error:#}"
        );
        assert!(server
            .recv_timeout(std::time::Duration::from_millis(10))?
            .is_none());
        assert_eq!(std::fs::read(parent)?, b"keep");
        Ok(())
    }

    #[test]
    fn partial_download_resumes_across_sources_and_ignoring_range_restarts_safely() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body = b"pinned model contents";
        let expected = hex::encode(Sha256::digest(body));
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial.bin");
        for supports_range in [true, false] {
            std::fs::write(&target, &body[..7])?;
            let server =
                tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
            let url = format!("http://{}/model", server.server_addr());
            let worker = std::thread::spawn(move || -> Result<()> {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(10))?
                    .ok_or_else(|| anyhow!("download not requested"))?;
                assert!(request.headers().iter().any(
                    |header| header.field.equiv("Range") && header.value.as_str() == "bytes=7-"
                ));
                let response = if supports_range {
                    tiny_http::Response::from_data(body[7..].to_vec())
                        .with_status_code(206)
                        .with_header(
                            tiny_http::Header::from_bytes(
                                "Content-Range",
                                format!("bytes 7-{}/{}", body.len() - 1, body.len()),
                            )
                            .map_err(|_| anyhow!("invalid test header"))?,
                        )
                } else {
                    tiny_http::Response::from_data(body.to_vec())
                };
                request.respond(response)?;
                Ok(())
            });
            download_verified(&url, &target, &expected)?;
            worker.join().map_err(|_| anyhow!("server panicked"))??;
            assert_eq!(std::fs::read(&target)?, body);
        }
        assert!(parse_content_range("bytes 8-9/9").is_err());
        assert!(parse_content_range("bytes 8-7/10").is_err());
        Ok(())
    }

    #[test]
    fn four_parallel_ranges_resume_saved_segments_and_verify_the_merged_file() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body: Vec<u8> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
        let expected = hex::encode(Sha256::digest(&body));
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model_quantized.onnx");
        let parts = target.with_extension("onnx.parts");
        std::fs::create_dir(&parts)?;
        for index in 0..4 {
            let begin = body.len() * index / 4;
            std::fs::write(parts.join(index.to_string()), &body[begin..begin + 3])?;
        }
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let source = body.clone();
        let worker = std::thread::spawn(move || -> Result<()> {
            let header = |value: String| {
                tiny_http::Header::from_bytes("Content-Range", value)
                    .map_err(|_| anyhow!("invalid test header"))
            };
            let probe = server
                .recv_timeout(std::time::Duration::from_secs(10))?
                .ok_or_else(|| anyhow!("probe missing"))?;
            probe.respond(
                tiny_http::Response::from_data(vec![source[0]])
                    .with_status_code(206)
                    .with_header(header(format!("bytes 0-0/{}", source.len()))?),
            )?;
            // Hold all four responses until all requests arrive. A sequential
            // implementation times out here instead of passing this test.
            let mut requests = Vec::new();
            for _ in 0..4 {
                requests.push(
                    server
                        .recv_timeout(std::time::Duration::from_secs(10))?
                        .ok_or_else(|| anyhow!("four concurrent requests did not arrive"))?,
                );
            }
            for request in requests {
                let range = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Range"))
                    .ok_or_else(|| anyhow!("segment Range missing"))?
                    .value
                    .as_str();
                let (start, end) = range
                    .strip_prefix("bytes=")
                    .and_then(|value| value.split_once('-'))
                    .ok_or_else(|| anyhow!("bad range"))?;
                let start = start.parse::<usize>()?;
                let end = end.parse::<usize>()?;
                assert_eq!(start % (source.len() / 4), 3);
                request.respond(
                    tiny_http::Response::from_data(source[start..=end].to_vec())
                        .with_status_code(206)
                        .with_header(header(format!("bytes {start}-{end}/{}", source.len()))?),
                )?;
            }
            Ok(())
        });
        assert!(download_parallel(&url, &target, &expected, 0)?);
        worker.join().map_err(|_| anyhow!("source panicked"))??;
        assert_eq!(std::fs::read(target)?, body);
        assert!(!parts.exists());
        Ok(())
    }

    #[test]
    fn corrupt_or_overlong_parallel_segments_restart_cleanly_on_the_same_source() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body: Vec<u8> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
        let expected = hex::encode(Sha256::digest(&body));
        for overlong in [false, true] {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join("model.ort");
            let parts = download_parts_path(&target);
            std::fs::create_dir(&parts)?;
            for index in 0..4 {
                let bad_length = if overlong { body.len() / 4 + 1 } else { 3 };
                std::fs::write(parts.join(index.to_string()), vec![255; bad_length])?;
            }
            let server =
                tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
            let url = format!("http://{}/model", server.server_addr());
            let source = body.clone();
            let worker = std::thread::spawn(move || -> Result<()> {
                let header = |value: String| {
                    tiny_http::Header::from_bytes("Content-Range", value)
                        .map_err(|_| anyhow!("invalid test header"))
                };
                let next = || {
                    server
                        .recv_timeout(std::time::Duration::from_secs(5))?
                        .ok_or_else(|| anyhow!("download request missing"))
                };
                next()?.respond(
                    tiny_http::Response::from_data(vec![source[0]])
                        .with_status_code(206)
                        .with_header(header(format!("bytes 0-0/{}", source.len()))?),
                )?;
                for _ in 0..4 {
                    let request = next()?;
                    let range = request
                        .headers()
                        .iter()
                        .find(|header| header.field.equiv("Range"))
                        .ok_or_else(|| anyhow!("segment Range missing"))?
                        .value
                        .as_str();
                    let (start, end) = range
                        .strip_prefix("bytes=")
                        .and_then(|value| value.split_once('-'))
                        .ok_or_else(|| anyhow!("bad range"))?;
                    let start = start.parse::<usize>()?;
                    let end = end.parse::<usize>()?;
                    assert_eq!(start % (source.len() / 4), if overlong { 0 } else { 3 });
                    request.respond(
                        tiny_http::Response::from_data(source[start..=end].to_vec())
                            .with_status_code(206)
                            .with_header(header(format!("bytes {start}-{end}/{}", source.len()))?),
                    )?;
                }
                if !overlong {
                    let fresh = next()?;
                    assert!(!fresh
                        .headers()
                        .iter()
                        .any(|header| header.field.equiv("Range")));
                    fresh.respond(tiny_http::Response::from_data(source))?;
                }
                Ok(())
            });
            assert!(download_parallel_with_timeouts(
                &url,
                &target,
                &expected,
                0,
                fast_timeouts()
            )?);
            worker
                .join()
                .map_err(|_| anyhow!("range source panicked"))??;
            assert_eq!(std::fs::read(target)?, body);
            assert!(!parts.exists());
        }
        Ok(())
    }

    #[test]
    fn install_target_and_file_helpers() -> Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let explicit = install_target_dir(Some("D:/models/bge"))?;
        assert!(explicit.ends_with("bge") || explicit.to_string_lossy().contains("models"));
        let saved = std::env::var("RSRS_M3_DIR").ok();
        std::env::set_var("RSRS_M3_DIR", "/tmp/om-model-test");
        let from_env = install_target_dir(None)?;
        assert!(from_env.to_string_lossy().contains("om-model-test"));
        match saved {
            Some(v) => std::env::set_var("RSRS_M3_DIR", v),
            None => std::env::remove_var("RSRS_M3_DIR"),
        }
        let url = file_url("https://huggingface.co", "tokenizer.json");
        assert!(url.contains("tokenizer.json"));
        let dir = tempfile::tempdir()?;
        let p = dir.path().join("a.bin");
        assert!(!file_valid(&p, "deadbeef")?);
        std::fs::write(&p, b"abc")?;
        let hash = sha256_file(&p)?;
        assert_eq!(hash.len(), 64);
        assert!(file_valid(&p, &hash)?);
        let dest = dir.path().join("b.bin");
        replace_file(&p, &dest)?;
        assert!(dest.is_file());
        let tmp = dir.path().join("tmp-guard");
        std::fs::create_dir_all(&tmp)?;
        drop(TmpGuard(tmp.clone()));
        assert!(!tmp.exists());
        Ok(())
    }

    #[test]
    fn cancelling_a_download_releases_the_slot_and_restart_uses_the_new_source() -> Result<()> {
        use std::sync::mpsc;
        use std::time::Duration;
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let verified = dir.path().join("verified.bin");
        std::fs::write(&verified, b"keep verified file")?;
        let temporary = dir.path().join("partial");
        std::fs::create_dir(&temporary)?;
        let first = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let first_url = file_url(&format!("http://{}", first.server_addr()), "tokenizer.json");
        let (started, waiting) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let server = std::thread::spawn(move || -> Result<()> {
            let request = first
                .recv_timeout(Duration::from_secs(10))?
                .ok_or_else(|| anyhow!("first source was not used"))?;
            started.send(())?;
            resume.recv_timeout(Duration::from_secs(10))?;
            request.respond(tiny_http::Response::from_string("cancelled body"))?;
            Ok(())
        });
        let download_dir = temporary.clone();
        let download = std::thread::spawn(move || -> Result<()> {
            let _operation = model_progress::Operation::begin("connect")?;
            download_verified(
                &first_url,
                &download_dir.join("tokenizer.json"),
                "unused-on-cancel",
            )
        });
        waiting.recv_timeout(Duration::from_secs(10))?;
        let status = model_progress::status()?;
        let id = status["id"]
            .as_str()
            .ok_or_else(|| anyhow!("task id missing"))?;
        assert_eq!(model_progress::control("stale-task", true)?["stale"], true);
        assert_eq!(model_progress::status()?["cancelled"], false);
        assert_eq!(model_progress::control(id, true)?["cancelled"], true);
        release.send(())?;
        server
            .join()
            .map_err(|_| anyhow!("download server panicked"))??;
        let error = download
            .join()
            .map_err(|_| anyhow!("download worker panicked"))?
            .err()
            .ok_or_else(|| anyhow!("cancelled download succeeded"))?;
        assert!(matches!(
            error.downcast_ref::<model_progress::OperationStopped>(),
            Some(model_progress::OperationStopped::Cancelled)
        ));
        assert_eq!(model_progress::status()?["active"], false);
        assert!(temporary.exists());
        assert_eq!(std::fs::read(&verified)?, b"keep verified file");
        let second = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let second_url = file_url(
            &format!("http://{}", second.server_addr()),
            "tokenizer.json",
        );
        let server = std::thread::spawn(move || -> Result<()> {
            let request = second
                .recv_timeout(Duration::from_secs(10))?
                .ok_or_else(|| anyhow!("replacement source was not used"))?;
            assert!(request.url().contains(MODEL_REVISION));
            request.respond(tiny_http::Response::from_string("replacement body"))?;
            Ok(())
        });
        let _operation = model_progress::Operation::begin("connect")?;
        let expected = hex::encode(Sha256::digest(b"replacement body"));
        let target = dir.path().join("tokenizer.json");
        download_verified(&second_url, &target, &expected)?;
        server
            .join()
            .map_err(|_| anyhow!("replacement server panicked"))??;
        assert_eq!(std::fs::read(target)?, b"replacement body");
        assert_eq!(std::fs::read(verified)?, b"keep verified file");
        Ok(())
    }

    #[test]
    fn unknown_length_partial_is_retained_and_resumed_after_checksum_failure() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial");
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let handler =
            std::thread::spawn(move || -> Result<()> {
                let request = server.recv()?;
                request.respond(tiny_http::Response::new(
                    tiny_http::StatusCode(200),
                    vec![],
                    std::io::Cursor::new(b"abc"),
                    None,
                    None,
                ))?;
                let request = server.recv()?;
                assert!(request.headers().iter().any(
                    |header| header.field.equiv("Range") && header.value.as_str() == "bytes=3-"
                ));
                let range = tiny_http::Header::from_bytes("Content-Range", "bytes 3-5/6")
                    .map_err(|_| anyhow!("range header"))?;
                request.respond(
                    tiny_http::Response::from_string("def")
                        .with_status_code(206)
                        .with_header(range),
                )?;
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(10))?
                    .ok_or_else(|| anyhow!("corrupt-prefix resume request missing"))?;
                assert!(request.headers().iter().any(
                    |header| header.field.equiv("Range") && header.value.as_str() == "bytes=3-"
                ));
                let range = tiny_http::Header::from_bytes("Content-Range", "bytes 3-5/6")
                    .map_err(|_| anyhow!("range header"))?;
                request.respond(
                    tiny_http::Response::from_string("def")
                        .with_status_code(206)
                        .with_header(range),
                )?;
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(10))?
                    .ok_or_else(|| anyhow!("fresh request after corrupt prefix missing"))?;
                assert!(!request
                    .headers()
                    .iter()
                    .any(|header| header.field.equiv("Range")));
                request.respond(tiny_http::Response::from_string("abcdef"))?;
                Ok(())
            });
        let expected = hex::encode(Sha256::digest(b"abcdef"));
        assert!(download_verified(&url, &target, &expected).is_err());
        assert_eq!(std::fs::read(&target)?, b"abc");
        download_verified(&url, &target, &expected)?;
        assert_eq!(std::fs::read(&target)?, b"abcdef");
        std::fs::write(&target, b"bad")?;
        download_verified(&url, &target, &expected)?;
        handler
            .join()
            .map_err(|_| anyhow!("test server panicked"))??;
        assert_eq!(std::fs::read(target)?, b"abcdef");
        Ok(())
    }

    #[test]
    fn uninstall_m3_delete_files() -> Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir()?;
        let bge = root.path().join("bge-m3");
        std::fs::create_dir_all(bge.join("onnx"))?;
        std::fs::write(bge.join("tokenizer.json"), b"{}")?;
        std::fs::write(bge.join("onnx").join("model_quantized.onnx"), b"onnx")?;
        let saved_bge = std::env::var("RSRS_M3_DIR").ok();
        std::env::set_var("RSRS_M3_DIR", &bge);

        let gone_bge = uninstall_m3()?;
        assert!(gone_bge.removed);
        assert!(!bge.exists());
        let again_bge = uninstall_m3()?;
        assert!(!again_bge.removed);

        match saved_bge {
            Some(v) => std::env::set_var("RSRS_M3_DIR", v),
            None => std::env::remove_var("RSRS_M3_DIR"),
        }
        Ok(())
    }
}

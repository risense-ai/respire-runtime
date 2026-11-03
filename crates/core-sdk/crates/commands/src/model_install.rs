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

use respire_app::memory::bge::{expand_home, model_files_present};
use crate::model_progress;

pub fn install_engines() -> Result<Vec<String>> {
    #[cfg(windows)]
    {
        let dll = respire_app::memory::onnx::accelerator_catalog_path()?.context("Windows ML catalog path missing")?;
        let paths = respire_spawn::install_accelerators(&dll)?;
        let directory = dll.parent().and_then(Path::parent).context("Windows ML engine directory missing")?;
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
    { Ok(Vec::new()) }
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
    std::fs::write(dest.join("MODEL-SOURCE.json"), serde_json::to_vec_pretty(&source)?)?;
    std::fs::write(dest.join("MODEL-CARD.md"), include_str!("../../../docs/model-notices/bge-m3-MODEL-CARD.md"))?;
    std::fs::write(dest.join("LICENSE.txt"), include_str!("../../../docs/model-notices/FlagEmbedding-LICENSE.txt"))?;
    std::fs::write(dest.join("NOTICE-SOURCES.json"), include_str!("../../../docs/model-notices/sources.json"))?;
    let _ = model;
    Ok(())
}

pub struct InstallReport {
    pub dir: PathBuf,
    pub skipped: bool,
}

/// Download sources all serve the same pinned BGE-M3 files.
pub const MIRRORS: &[&str] = &["auto", "https://hf-mirror.com", "https://hf-mirror.net", "https://huggingface.co"];

pub fn mirror_from_env() -> Option<String> {
    respire_app::env::var("RSRS_MIRROR").ok().filter(|s| !s.trim().is_empty())
        .or_else(|| respire_app::service::read_agent_config()["model_mirror"].as_str().map(str::to_owned))
}

pub fn install_target_dir(explicit: Option<&str>) -> PathBuf {
    explicit.filter(|s| !s.trim().is_empty()).map(|s| expand_home(s.trim()))
        .unwrap_or_else(respire_app::memory::bge::m3_model_dir)
}

pub fn install_m3(mirror: Option<&str>) -> Result<InstallReport> {
    let _operation = model_progress::Operation::begin_download()?;
    install_m3_inner(mirror)
}

/// Cheap runtime inventory for settings UIs. Presence/size is not a checksum or
/// provider compatibility claim; inference and the installer still verify hashes.
pub fn variant_inventory() -> Result<serde_json::Value> {
    let directory = respire_app::memory::bge::resolve_model_dir().unwrap_or_else(|_| install_target_dir(None));
    let baseline = model_files_present(&directory);
    respire_app::memory::onnx::MODEL_VARIANTS.iter().map(|variant| {
        let state = if baseline {
            variant_file_state(&directory.join(respire_app::memory::onnx::variant_file_name(variant.name)), variant.size)?
        } else { "baseline_missing" };
        Ok(serde_json::json!({"name":variant.name,"size":variant.size,"state":state}))
    }).collect::<Result<Vec<_>>>().map(serde_json::Value::from)
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
    let dest = install_target_dir(None);
    let origins = model_origins(mirror)?;
    install_variant_into(variant, &dest, &origins)
}

fn install_variant_into(variant: respire_app::memory::onnx::ModelVariant, dest: &Path, origins: &[String]) -> Result<()> {
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
            let sources = origins.iter().map(|origin| file_url(origin, &file)).collect::<Vec<_>>();
            download_with_fallback(&sources, &tmp_path, variant.sha256, true, DownloadTimeouts::default())?;
        }
        std::fs::create_dir_all(dest.join("onnx"))?;
        anyhow::ensure!(variant_file_valid(&tmp_path, variant)?, "downloaded variant size or checksum mismatch");
        replace_file(&tmp_path, &dest_path)?;
    }
    anyhow::ensure!(variant_file_valid(&dest_path, variant)?, "BGE-M3 {} install is incomplete", variant.name);
    Ok(())
}

/// Used by the runtime's reserved background operation after a source change.
pub fn prepare_m3_from_mirror(mirror: &str) -> Result<()> {
    install_m3_inner(Some(mirror)).map(|_| ())
}

/// Called with the background index operation already reserved. Preparing files
/// must not try to reserve that operation a second time or acquire a library lock.
pub fn prepare_m3_for_index() -> Result<()> {
    let user = install_target_dir(None);
    let explicit = respire_app::env::var("RSRS_M3_DIR").ok().is_some_and(|value| !value.trim().is_empty());
    let mut candidates = vec![user];
    if !explicit {
        if let Some(parent) = std::env::current_exe()?.parent() {
            candidates.push(parent.join("models/bge-m3"));
        }
        candidates.push(PathBuf::from("/usr/lib/respire/models/bge-m3"));
    }
    for path in candidates {
        if file_valid(&path.join("tokenizer.json"), TOKENIZER_SHA256)?
            && m3_model_valid(&path.join("onnx/model_quantized.onnx"))? {
            prepare_cpu_ort(&path)?;
            return Ok(());
        }
    }
    install_m3_inner(None)?;
    Ok(())
}

fn install_m3_inner(mirror: Option<&str>) -> Result<InstallReport> {
    let dest = install_target_dir(None);
    let origins = model_origins(mirror)?;
    let files = [("tokenizer.json", TOKENIZER_SHA256), ("onnx/model_quantized.onnx", ONNX_SHA256)];
    std::fs::create_dir_all(&dest)?;
    // A pinned revision allows cancellation, restart and mirror changes to reuse
    // partial bytes without exposing an incomplete file to the model loader.
    let tmp = dest.join(format!(".download-{MODEL_REVISION}"));
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let mut skipped = true;
    for (name, sha) in files {
        if file_valid(&dest.join(name), sha)? { continue; }
        if file_valid(&tmp.join(name), sha)? { skipped = false; continue; }
        let sources = origins.iter().map(|origin| file_url(origin, name)).collect::<Vec<_>>();
        download_with_fallback(&sources, &tmp.join(name), sha, name.ends_with(".onnx"), DownloadTimeouts::default())?;
        skipped = false;
    }
    // Publish only after every required replacement has passed the pinned checksum.
    std::fs::create_dir_all(dest.join("onnx"))?;
    for (name, _) in files { if tmp.join(name).is_file() { replace_file(&tmp.join(name), &dest.join(name))?; } }
    std::fs::remove_dir_all(&tmp)?;
    anyhow::ensure!(model_files_present(&dest) && m3_model_valid(&dest.join("onnx/model_quantized.onnx"))?, "BGE-M3 quantized install is incomplete");
    write_model_notices(&dest, "m3", MODEL_REPO, MODEL_REVISION)?;
    let cpu_ready = prepare_cpu_ort(&dest)?;
    Ok(InstallReport { dir: dest, skipped: skipped && cpu_ready })
}

/// Runs outside the Core worker on the existing cancellable model-operation thread.
/// Keep ONNX for GPU/NPU. A CPU container upgrade does not change stored vectors or index schema.
fn prepare_cpu_ort(directory: &Path) -> Result<bool> {
    use respire_app::memory::bge;
    if !bge::cpu_owned_mode(respire_app::memory::onnx::configured_engine()?)? { return Ok(true); }
    if file_valid(&bge::cpu_ort_path(directory), bge::CPU_ORT_SHA256)? { return Ok(true); }
    // Legacy packaged/system model directories may be read-only. Upgrade into the user cache.
    let dest = bge::cpu_ort_cache_path();
    if file_valid(&dest, bge::CPU_ORT_SHA256)? { return Ok(true); }
    let parent = dest.parent().context("CPU model cache directory missing")?;
    std::fs::create_dir_all(parent)?;
    let partial = parent.join(format!(".download-{}.ort", bge::CPU_ORT_REVISION));
    let sources = cpu_ort_sources()?;
    let downloaded_from = if !file_valid(&partial, bge::CPU_ORT_SHA256)? {
        Some(download_with_fallback(&sources, &partial, bge::CPU_ORT_SHA256, true, DownloadTimeouts::default())?)
    } else { None };
    anyhow::ensure!(partial.metadata()?.len() == bge::CPU_ORT_SIZE, "CPU model size mismatch");
    remove_download_parts(&partial)?;
    replace_file(&partial, &dest)?;
    bge::invalidate_cpu_ort_validation()?;
    std::fs::write(parent.join("CPU-MODEL-SOURCE.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "container_version":bge::CPU_ORT_REVISION,"source_repository":MODEL_REPO,
        "source_revision":MODEL_REVISION,"source_onnx_sha256":ONNX_SHA256,
        "cpu_ort_sha256":bge::CPU_ORT_SHA256,"url":bge::CPU_ORT_URL,
        "downloaded_from":downloaded_from,
        "ort_version":"1.28.0","graph_optimization":99,"weights_changed":false
    }))?)?;
    Ok(false)
}

pub fn cpu_model_preparation_needed() -> Result<bool> {
    if !respire_app::memory::bge::cpu_owned_mode(respire_app::memory::onnx::configured_engine()?)? { return Ok(false); }
    Ok(match respire_app::memory::bge::resolve_model_dir() {
        Ok(directory) => !respire_app::memory::bge::cpu_ort_present(&directory)?,
        Err(_) => true,
    })
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
    let dest = install_target_dir(None);
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
    if value == "auto" { return Ok(()); }
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
    anyhow::ensure!(!hostport.contains(['@', '?', '#']) && !hostport.chars().any(char::is_whitespace), "mirror must be a host without credentials, query or fragment");
    Ok(format!("{scheme}://{hostport}"))
}

fn model_origins(mirror: Option<&str>) -> Result<Vec<String>> {
    let setting = mirror.map(str::to_owned).or_else(mirror_from_env).unwrap_or_else(|| "auto".to_owned());
    if setting.trim() == "auto" {
        Ok(MIRRORS[1..].iter().map(|origin| (*origin).to_owned()).collect())
    } else {
        Ok(vec![origin_from_mirror(&setting)?])
    }
}

fn cpu_ort_sources() -> Result<Vec<String>> {
    let setting = respire_app::env::var("RSRS_CPU_ORT_MIRROR").ok().filter(|value| !value.trim().is_empty())
        .or_else(|| respire_app::service::read_agent_config()["model_cpu_ort_mirror"].as_str()
            .filter(|value| !value.trim().is_empty()).map(str::to_owned))
        .unwrap_or_else(|| "auto".to_owned());
    cpu_ort_sources_from_setting(&setting)
}

fn cpu_ort_sources_from_setting(setting: &str) -> Result<Vec<String>> {
    use respire_app::memory::bge::CPU_ORT_URL;
    // Release containers and Hugging Face ONNX files use different URL layouts.
    // Never turn a Hugging Face model into a substitute for the pinned CPU ORT.
    match setting.trim() {
        "auto" => Ok(vec![format!("https://gh-proxy.org/{CPU_ORT_URL}"), CPU_ORT_URL.to_owned()]),
        "github" | "https://github.com" | "https://github.com/" => Ok(vec![CPU_ORT_URL.to_owned()]),
        value => {
            anyhow::ensure!(!value.is_empty() && !value.chars().any(char::is_whitespace),
                "CPU ORT mirror must be a nonempty origin without whitespace");
            let supplied = if value.contains("://") { value.to_owned() } else { format!("https://{value}") };
            let origin = url::Url::parse(&supplied).context("invalid CPU ORT mirror origin")?;
            anyhow::ensure!(matches!(origin.scheme(), "http" | "https") && origin.host_str().is_some(),
                "CPU ORT mirror must be an http/https origin");
            anyhow::ensure!(origin.username().is_empty() && origin.password().is_none()
                && origin.query().is_none() && origin.fragment().is_none() && origin.path() == "/",
                "CPU ORT mirror must be an origin without credentials, path, query or fragment");
            // Only the public release URL goes to the proxy. No account headers.
            Ok(vec![format!("{}/{CPU_ORT_URL}", origin.as_str().trim_end_matches('/'))])
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

fn variant_file_valid(path: &Path, variant: respire_app::memory::onnx::ModelVariant) -> Result<bool> {
    if !path.is_file() || path.metadata()?.len() != variant.size { return Ok(false); }
    file_valid(path, variant.sha256)
}

fn pinned_size(expected: &str) -> Option<u64> {
    // tokenizer.json at the same fixed upstream revision (LFS size/hash verified).
    if expected == TOKENIZER_SHA256 { return Some(17_082_821); }
    if expected == respire_app::memory::bge::CPU_ORT_SHA256 {
        Some(respire_app::memory::bge::CPU_ORT_SIZE)
    } else {
        respire_app::memory::onnx::MODEL_VARIANTS.iter()
            .find(|variant| variant.sha256.eq_ignore_ascii_case(expected)).map(|variant| variant.size)
    }
}

fn file_valid(path: &Path, expected: &str) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    if let Some(size) = pinned_size(expected) {
        if path.metadata()?.len() != size { return Ok(false); }
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
        Self { connect: Duration::from_secs(10), read: Duration::from_secs(30), write: Duration::from_secs(10) }
    }
}

/// Every source must provide the same pinned artifact. Network/checksum errors
/// advance to the next source; cancellation and local filesystem failures do not.
/// A single explicit source therefore never silently falls back to another host.
fn download_with_fallback(sources: &[String], dest: &Path, expected: &str, parallel: bool,
    timeouts: DownloadTimeouts) -> Result<String> {
    let mut failures = Vec::new();
    for url in sources {
        model_progress::check()?;
        let result = if parallel && !dest.exists() {
            download_parallel_with_timeouts(url, dest, expected, 16 * 1024 * 1024, timeouts)
                .and_then(|used| if used { Ok(()) } else { download_verified_with_timeouts(url, dest, expected, timeouts) })
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
                if error.downcast_ref::<std::io::Error>().is_some() { return Err(error); }
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

fn download_verified_with_timeouts(url: &str, dest: &Path, expected: &str, timeouts: DownloadTimeouts) -> Result<()> {
    download_verified_bounded(url, dest, expected, timeouts, pinned_size(expected))
}

fn download_verified_bounded(url: &str, dest: &Path, expected: &str, timeouts: DownloadTimeouts, expected_size: Option<u64>) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if dest.is_file() && expected_size.is_some_and(|size| dest.metadata().map(|m| m.len() > size).unwrap_or(false)) {
        std::fs::remove_file(dest)?;
    }
    let offset = if dest.is_file() { dest.metadata()?.len() } else { 0 };
    let resp = match download_response(url, dest, offset, timeouts) {
        Ok(response) => response,
        Err(error) if offset > 0 && error.downcast_ref::<ureq::Error>().is_some_and(|error| matches!(error, ureq::Error::Status(416, _))) => {
            std::fs::remove_file(dest)?;
            download_response(url, dest, 0, timeouts)?
        }
        Err(error) => return Err(error),
    };
    let resumed = resp.status() == 206;
    let total = if resumed {
        let range = resp.header("Content-Range").ok_or_else(|| anyhow!("partial response has no Content-Range"))?;
        let (start, total) = parse_content_range(range)?;
        anyhow::ensure!(start == offset, "partial response starts at {start}, expected {offset}");
        Some(total)
    } else {
        anyhow::ensure!(resp.status() == 200, "unexpected download status {}", resp.status());
        resp.header("Content-Length").and_then(|v| v.parse::<u64>().ok())
    };
    if let (Some(pinned), Some(reported)) = (expected_size, total) {
        anyhow::ensure!(pinned == reported, "model size mismatch: response {reported}, expected {pinned}");
    }
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    let mut reader = resp.into_reader();
    let mut file =
        OpenOptions::new().create(true).write(true).append(resumed).truncate(!resumed)
            .open(dest).with_context(|| format!("failed to write {}", dest.display()))?;
    let mut buf = [0u8; 64 * 1024];
    let mut written: u64 = if resumed { offset } else { 0 };
    loop {
        model_progress::update("download", &item, written, total)?;
        let n = read_download(&mut reader, &mut buf, url)?;
        if n == 0 {
            break;
        }
        if let Some(limit) = expected_size {
            anyhow::ensure!(written <= limit && n as u64 <= limit - written,
                "model response exceeds pinned size {limit}");
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("failed to write {}", dest.display()))?;
        written += n as u64;
    }
    file.flush()
        .with_context(|| format!("failed to write {}", dest.display()))?;
    drop(file);
    if let Some(total) = total {
        anyhow::ensure!(written == total, "download incomplete: {written}/{total} bytes; partial file retained");
    }
    if let Some(expected) = expected_size {
        anyhow::ensure!(written == expected, "model size mismatch: {written}/{expected}");
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
        if total.is_some() { std::fs::remove_file(dest)?; }
        anyhow::bail!(
            "checksum failed: {} SHA256={actual} (expected {expected})",
            dest.display()
        );
    }
    Ok(())
}

fn parse_content_range(value: &str) -> Result<(u64, u64)> {
    let value = value.strip_prefix("bytes ").ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (range, total) = value.split_once('/').ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (start, end) = range.split_once('-').ok_or_else(|| anyhow!("invalid Content-Range"))?;
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

fn download_parallel_with_timeouts(url: &str, dest: &Path, expected: &str, minimum: u64,
    timeouts: DownloadTimeouts) -> Result<bool> {
    use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc};
    use std::time::Duration;
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, 0, None)?;
    let response = download_agent(timeouts).get(url).set("Accept-Encoding", "identity").set("Range", "bytes=0-0").call()
        .with_context(|| format!("download probe failed ({url})"))?;
    model_progress::check()?;
    if response.status() == 200 { return Ok(false); }
    anyhow::ensure!(response.status() == 206, "unexpected range probe status");
    let range = response.header("Content-Range").ok_or_else(|| anyhow!("range probe has no Content-Range"))?;
    let (start, total) = parse_content_range(range)?;
    anyhow::ensure!(start == 0, "range probe starts at {start}");
    if let Some(pinned) = pinned_size(expected) {
        anyhow::ensure!(total == pinned, "model size mismatch: response {total}, expected {pinned}");
    }
    drop(response);
    if total < minimum || total < 4 { return Ok(false); }
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
                if failed { stop.store(true, Ordering::Relaxed); }
            });
        }
        drop(sender);
        let mut finished = 0;
        let mut failure = None;
        while finished < 4 {
            let done = counts.iter().map(|count| count.load(Ordering::Relaxed)).sum();
            if let Err(error) = model_progress::update("download", &item, done, Some(total)) {
                stop.store(true, Ordering::Relaxed);
                if failure.is_none() { failure = Some(error); }
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
                Err(mpsc::RecvTimeoutError::Disconnected) => anyhow::bail!("download workers disconnected"),
            }
        }
        if let Some(error) = failure { return Err(error); }
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

fn download_part(url: &str, path: &Path, begin: u64, end: u64, total: u64,
    count: &std::sync::atomic::AtomicU64, stop: &std::sync::atomic::AtomicBool, timeouts: DownloadTimeouts) -> Result<()> {
    use std::sync::atomic::Ordering;
    let length = end - begin;
    let mut offset = if path.is_file() { path.metadata()?.len() } else { 0 };
    anyhow::ensure!(offset <= length, "saved download segment is too long");
    count.store(offset, Ordering::Relaxed);
    if offset == length { return Ok(()); }
    anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
    let start = begin + offset;
    let response = download_agent(timeouts).get(url).set("Accept-Encoding", "identity").set("Range", &format!("bytes={start}-{}", end - 1)).call()
        .with_context(|| format!("segment download failed ({url})"))?;
    anyhow::ensure!(response.status() == 206, "source did not honor the segment range");
    let expected_range = format!("bytes {start}-{}/{total}", end - 1);
    anyhow::ensure!(response.header("Content-Range") == Some(expected_range.as_str()), "source returned an incorrect segment range");
    let mut reader = response.into_reader();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    while offset < length {
        anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
        let limit = buffer.len().min((length - offset) as usize);
        let received = reader.read(&mut buffer[..limit]).map_err(|error| anyhow!("segment interrupted ({url}): {error}"))?;
        anyhow::ensure!(received > 0, "segment download incomplete; partial bytes retained");
        file.write_all(&buffer[..received])?;
        offset += received as u64;
        count.store(offset, Ordering::Relaxed);
    }
    file.flush()?;
    Ok(())
}

fn download_agent(timeouts: DownloadTimeouts) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout_connect(timeouts.connect)
        .timeout_read(timeouts.read).timeout_write(timeouts.write).build()
}

fn download_response(url: &str, dest: &Path, offset: u64, timeouts: DownloadTimeouts) -> Result<ureq::Response> {
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, offset, None)?;
    // Headers and body reads share the same bounded idle wait. No total deadline
    // cuts off a large model while bytes are still arriving.
    let request = download_agent(timeouts).get(url).set("Accept-Encoding", "identity");
    let request = if offset > 0 { request.set("Range", &format!("bytes={offset}-")) } else { request };
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
    fn missing_explicit_cpu_variant_does_not_load_the_owned_quantized_container() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.0 {
                    if let Some(value) = value { std::env::set_var(key, value); }
                    else { std::env::remove_var(key); }
                }
            }
        }
        let keys = ["RSRS_M3_DIR", "RSRS_DATA_DIR", "RSRS_ENGINE", "RSRS_MODEL_VARIANT", "RSRS_CPU_OWNED_ORT_EXPERIMENT"];
        let _restore = Restore(keys.into_iter().map(|key| (key, std::env::var_os(key))).collect());
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join("onnx"))?;
        std::fs::write(dir.path().join("onnx/model_quantized.onnx"), b"baseline presence only")?;
        std::fs::write(dir.path().join("tokenizer.json"), b"{}")?;
        std::env::set_var("RSRS_M3_DIR", dir.path());
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::set_var("RSRS_ENGINE", "cpu");
        std::env::set_var("RSRS_MODEL_VARIANT", "fp16");
        std::env::remove_var("RSRS_CPU_OWNED_ORT_EXPERIMENT");
        let error = respire_app::memory::bge::BgeEmbedder::load().err()
            .ok_or_else(|| anyhow!("missing explicit fp16 must fail"))?;
        let message = format!("{error:#}");
        assert!(message.contains("model_fp16.onnx"), "{message}");
        assert!(message.contains("--model fp16"), "{message}");
        assert!(!message.contains("model_quantized.cpu-v1.ort"), "{message}");
        Ok(())
    }

    #[test]
    fn verified_variant_survives_base_cleanup_and_publishes_without_network() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let variant = respire_app::memory::onnx::ModelVariant { name: "fp16", size: 3,
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" };
        let staging = variant_staging_dir(dir.path());
        std::fs::create_dir_all(staging.join("onnx"))?;
        std::fs::write(staging.join("onnx/model_fp16.onnx"), b"abc")?;
        let base_staging = dir.path().join(format!(".download-{MODEL_REVISION}"));
        std::fs::create_dir_all(&base_staging)?;
        std::fs::remove_dir_all(base_staging)?;
        install_variant_into(variant, dir.path(), &[])?;
        install_variant_into(variant, dir.path(), &[])?;
        assert_eq!(std::fs::read(dir.path().join("onnx/model_fp16.onnx"))?, b"abc");
        assert!(!staging.join("onnx/model_fp16.onnx").exists());
        Ok(())
    }

    #[test]
    fn bounded_download_rejects_headers_stream_overflow_and_short_eof() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        for (headers, body, valid) in [
            ("Content-Length: 4\r\n", "abcd", false),
            ("Transfer-Encoding: chunked\r\n", "4\r\nabcd\r\n0\r\n\r\n", false),
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
            let result = download_verified_bounded(&url, &target, expected, fast_timeouts(), Some(3));
            worker.join().map_err(|_| anyhow!("server panicked"))??;
            assert_eq!(result.is_ok(), valid, "unexpected result: {result:?}");
            if target.exists() { assert!(target.metadata()?.len() <= 3); }
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
        assert_eq!(cpu_ort_sources_from_setting("auto")?, vec![format!("https://gh-proxy.org/{official}"), official.to_owned()]);
        assert_eq!(cpu_ort_sources_from_setting(" github ")?, vec![official.to_owned()]);
        assert_eq!(cpu_ort_sources_from_setting("https://github.com/")?, vec![official.to_owned()]);
        assert_eq!(cpu_ort_sources_from_setting("mirror.example")?, vec![format!("https://mirror.example/{official}")]);
        assert_eq!(cpu_ort_sources_from_setting("http://127.0.0.1:8080/")?, vec![format!("http://127.0.0.1:8080/{official}")]);
        for value in ["", "https://user:secret@mirror.example", "file:///tmp/model",
            "https://mirror.example/path", "https://mirror.example/?token=secret", "https://mirror.example/#fragment"] {
            assert!(cpu_ort_sources_from_setting(value).is_err(), "accepted unsafe mirror {value}");
        }
        assert_eq!(model_origins(Some("auto"))?, MIRRORS[1..].iter().map(|value| (*value).to_owned()).collect::<Vec<_>>());
        assert_eq!(model_origins(Some("hf-mirror.com"))?, vec!["https://hf-mirror.com"]);
        assert_eq!(respire_app::memory::bge::CPU_ORT_SIZE, 569654128);
        assert_eq!(respire_app::memory::bge::CPU_ORT_SHA256, "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff");
        Ok(())
    }

    fn fast_timeouts() -> DownloadTimeouts {
        use std::time::Duration;
        DownloadTimeouts { connect: Duration::from_millis(500), read: Duration::from_millis(200), write: Duration::from_millis(500) }
    }

    /// Hold the connection open until the test releases it, so advancing to the
    /// next source proves the client timeout fired rather than the server's EOF.
    fn stalled_source(body: Option<(&[u8], usize)>) -> Result<(String, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<Result<()>>)> {
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
                anyhow::ensure!(socket.read(&mut byte)? == 1, "request closed before headers");
                request.push(byte[0]);
            }
            if let Some((prefix, total)) = body {
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n")?;
                socket.write_all(&prefix)?;
                socket.flush()?;
            }
            wait.recv_timeout(Duration::from_secs(10))?;
            Ok(())
        });
        Ok((url, release, server))
    }

    fn responding_source(body: &[u8], offset: usize) -> Result<(String, std::thread::JoinHandle<Result<()>>)> {
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let body = body.to_vec();
        let worker = std::thread::spawn(move || -> Result<()> {
            let request = server.recv_timeout(std::time::Duration::from_secs(5))?.ok_or_else(|| anyhow!("fallback source not requested"))?;
            let range = request.headers().iter().find(|header| header.field.equiv("Range"));
            let response = if offset > 0 {
                assert_eq!(range.map(|header| header.value.as_str()), Some(format!("bytes={offset}-").as_str()));
                tiny_http::Response::from_data(body[offset..].to_vec()).with_status_code(206)
                    .with_header(tiny_http::Header::from_bytes("Content-Range", format!("bytes {offset}-{}/{}", body.len() - 1, body.len()))
                        .map_err(|_| anyhow!("invalid test header"))?)
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
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let body = b"pinned artifact from healthy fallback";
        let expected = hex::encode(Sha256::digest(body));
        for offset in [0, 7] {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join("model.ort");
            let prefix = if offset == 0 { None } else { Some((&body[..offset], body.len())) };
            let (first, release, stalled) = stalled_source(prefix)?;
            let (second, healthy) = responding_source(body, offset)?;
            let started = std::time::Instant::now();
            let result = download_with_fallback(&[first, second.clone()], &target, &expected, false, fast_timeouts());
            let elapsed = started.elapsed();
            release.send(())?;
            stalled.join().map_err(|_| anyhow!("stalled source panicked"))??;
            healthy.join().map_err(|_| anyhow!("healthy source panicked"))??;
            assert_eq!(result?, second);
            assert!(elapsed < std::time::Duration::from_secs(5), "fallback was not bounded: {elapsed:?}");
            assert_eq!(std::fs::read(target)?, body);
        }
        Ok(())
    }

    #[test]
    fn stalled_range_probe_fails_over_without_publishing_unverified_bytes() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let parts = download_parts_path(&target);
        std::fs::create_dir_all(&parts)?;
        std::fs::write(parts.join("0"), b"saved segment from an interrupted range source")?;
        let body = b"healthy model";
        let expected = hex::encode(Sha256::digest(body));
        let (first, release, stalled) = stalled_source(None)?;
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let second = format!("http://{}/model", server.server_addr());
        let healthy = std::thread::spawn(move || -> Result<()> {
            let probe = server.recv_timeout(std::time::Duration::from_secs(5))?.ok_or_else(|| anyhow!("probe missing"))?;
            assert!(probe.headers().iter().any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=0-0"));
            probe.respond(tiny_http::Response::from_data(body.to_vec()))?;
            let request = server.recv_timeout(std::time::Duration::from_secs(5))?.ok_or_else(|| anyhow!("full request missing"))?;
            request.respond(tiny_http::Response::from_data(body.to_vec()))?;
            Ok(())
        });
        let result = download_with_fallback(&[first, second.clone()], &target, &expected, true, fast_timeouts());
        release.send(())?;
        stalled.join().map_err(|_| anyhow!("stalled source panicked"))??;
        healthy.join().map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(result?, second);
        assert_eq!(std::fs::read(target)?, body);
        assert!(!parts.exists(), "no-Range fallback left unused CPU segments behind");
        Ok(())
    }

    #[test]
    fn progressing_transfer_outlives_the_per_read_timeout() -> Result<()> {
        use std::time::Duration;
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
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
                anyhow::ensure!(socket.read(&mut byte)? == 1, "request closed before headers");
                request.push(byte[0]);
            }
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
            for byte in body {
                socket.write_all(&[*byte])?;
                socket.flush()?;
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        });
        let timeouts = DownloadTimeouts { read: Duration::from_millis(500), ..fast_timeouts() };
        let started = std::time::Instant::now();
        download_with_fallback(&[url], &target, &expected, false, timeouts)?;
        assert!(started.elapsed() > timeouts.read);
        worker.join().map_err(|_| anyhow!("progressing source panicked"))??;
        assert_eq!(std::fs::read(target)?, body);
        Ok(())
    }

    #[test]
    fn corrupt_source_is_rejected_before_clean_fallback() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let expected = hex::encode(Sha256::digest(b"trusted model"));
        let (first, corrupt) = responding_source(b"corrupt model", 0)?;
        let (second, healthy) = responding_source(b"trusted model", 0)?;
        assert_eq!(download_with_fallback(&[first, second.clone()], &target, &expected, false, fast_timeouts())?, second);
        corrupt.join().map_err(|_| anyhow!("corrupt source panicked"))??;
        healthy.join().map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(std::fs::read(target)?, b"trusted model");
        Ok(())
    }

    #[test]
    fn failed_source_releases_operation_slot_and_can_retry() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let body = b"verified retry";
        let expected = hex::encode(Sha256::digest(body));
        let (first, release, stalled) = stalled_source(None)?;
        let failed = {
            let _operation = model_progress::Operation::begin_download()?;
            let result = download_with_fallback(&[first], &target, &expected, false, fast_timeouts());
            assert_eq!(model_progress::status()?["active"], true);
            result
        };
        release.send(())?;
        stalled.join().map_err(|_| anyhow!("stalled source panicked"))??;
        assert!(failed.is_err());
        assert!(!target.exists());
        assert_eq!(model_progress::status()?["active"], false);
        let (second, healthy) = responding_source(body, 0)?;
        {
            let _operation = model_progress::Operation::begin_download()?;
            download_with_fallback(&[second], &target, &expected, false, fast_timeouts())?;
        }
        healthy.join().map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(model_progress::status()?["active"], false);
        assert_eq!(std::fs::read(target)?, body);
        Ok(())
    }

    #[test]
    fn local_disk_failure_is_not_retried_as_a_mirror_outage() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let parent = dir.path().join("not-a-directory");
        std::fs::write(&parent, b"keep")?;
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let error = download_with_fallback(&[url.clone(), url], &parent.join("model.ort"), "unused", false, fast_timeouts()).unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_some(), "disk failure identity lost: {error:#}");
        assert!(server.recv_timeout(std::time::Duration::from_millis(10))?.is_none());
        assert_eq!(std::fs::read(parent)?, b"keep");
        Ok(())
    }

    #[test]
    fn partial_download_resumes_across_sources_and_ignoring_range_restarts_safely() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let body = b"pinned model contents";
        let expected = hex::encode(Sha256::digest(body));
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial.bin");
        for supports_range in [true, false] {
            std::fs::write(&target, &body[..7])?;
            let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
            let url = format!("http://{}/model", server.server_addr());
            let worker = std::thread::spawn(move || -> Result<()> {
                let request = server.recv_timeout(std::time::Duration::from_secs(10))?.ok_or_else(|| anyhow!("download not requested"))?;
                assert!(request.headers().iter().any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=7-"));
                let response = if supports_range {
                    tiny_http::Response::from_data(body[7..].to_vec()).with_status_code(206)
                        .with_header(tiny_http::Header::from_bytes("Content-Range", format!("bytes 7-{}/{}", body.len() - 1, body.len())).map_err(|_| anyhow!("invalid test header"))?)
                } else { tiny_http::Response::from_data(body.to_vec()) };
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
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
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
            let header = |value: String| tiny_http::Header::from_bytes("Content-Range", value).map_err(|_| anyhow!("invalid test header"));
            let probe = server.recv_timeout(std::time::Duration::from_secs(10))?.ok_or_else(|| anyhow!("probe missing"))?;
            probe.respond(tiny_http::Response::from_data(vec![source[0]]).with_status_code(206)
                .with_header(header(format!("bytes 0-0/{}", source.len()))?))?;
            // Hold all four responses until all requests arrive. A sequential
            // implementation times out here instead of passing this test.
            let mut requests = Vec::new();
            for _ in 0..4 {
                requests.push(server.recv_timeout(std::time::Duration::from_secs(10))?.ok_or_else(|| anyhow!("four concurrent requests did not arrive"))?);
            }
            for request in requests {
                let range = request.headers().iter().find(|header| header.field.equiv("Range"))
                    .ok_or_else(|| anyhow!("segment Range missing"))?.value.as_str();
                let (start, end) = range.strip_prefix("bytes=").and_then(|value| value.split_once('-')).ok_or_else(|| anyhow!("bad range"))?;
                let start = start.parse::<usize>()?;
                let end = end.parse::<usize>()?;
                assert_eq!(start % (source.len() / 4), 3);
                request.respond(tiny_http::Response::from_data(source[start..=end].to_vec()).with_status_code(206)
                    .with_header(header(format!("bytes {start}-{end}/{}", source.len()))?))?;
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
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
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
            let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
            let url = format!("http://{}/model", server.server_addr());
            let source = body.clone();
            let worker = std::thread::spawn(move || -> Result<()> {
                let header = |value: String| tiny_http::Header::from_bytes("Content-Range", value).map_err(|_| anyhow!("invalid test header"));
                let next = || server.recv_timeout(std::time::Duration::from_secs(5))?.ok_or_else(|| anyhow!("download request missing"));
                next()?.respond(tiny_http::Response::from_data(vec![source[0]]).with_status_code(206)
                    .with_header(header(format!("bytes 0-0/{}", source.len()))?))?;
                for _ in 0..4 {
                    let request = next()?;
                    let range = request.headers().iter().find(|header| header.field.equiv("Range"))
                        .ok_or_else(|| anyhow!("segment Range missing"))?.value.as_str();
                    let (start, end) = range.strip_prefix("bytes=").and_then(|value| value.split_once('-')).ok_or_else(|| anyhow!("bad range"))?;
                    let start = start.parse::<usize>()?;
                    let end = end.parse::<usize>()?;
                    assert_eq!(start % (source.len() / 4), if overlong { 0 } else { 3 });
                    request.respond(tiny_http::Response::from_data(source[start..=end].to_vec()).with_status_code(206)
                        .with_header(header(format!("bytes {start}-{end}/{}", source.len()))?))?;
                }
                if !overlong {
                    let fresh = next()?;
                    assert!(!fresh.headers().iter().any(|header| header.field.equiv("Range")));
                    fresh.respond(tiny_http::Response::from_data(source))?;
                }
                Ok(())
            });
            assert!(download_parallel_with_timeouts(&url, &target, &expected, 0, fast_timeouts())?);
            worker.join().map_err(|_| anyhow!("range source panicked"))??;
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
        let explicit = install_target_dir(Some("D:/models/bge"));
        assert!(explicit.ends_with("bge") || explicit.to_string_lossy().contains("models"));
        let saved = std::env::var("RSRS_M3_DIR").ok();
        std::env::set_var("RSRS_M3_DIR", "/tmp/om-model-test");
        let from_env = install_target_dir(None);
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
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
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
            let request = first.recv_timeout(Duration::from_secs(10))?.ok_or_else(|| anyhow!("first source was not used"))?;
            started.send(())?;
            resume.recv_timeout(Duration::from_secs(10))?;
            request.respond(tiny_http::Response::from_string("cancelled body"))?;
            Ok(())
        });
        let download_dir = temporary.clone();
        let download = std::thread::spawn(move || -> Result<()> {
            let _operation = model_progress::Operation::begin("connect")?;
            download_verified(&first_url, &download_dir.join("tokenizer.json"), "unused-on-cancel")
        });
        waiting.recv_timeout(Duration::from_secs(10))?;
        let status = model_progress::status()?;
        let id = status["id"].as_str().ok_or_else(|| anyhow!("task id missing"))?;
        assert_eq!(model_progress::control("stale-task", true)?["stale"], true);
        assert_eq!(model_progress::status()?["cancelled"], false);
        assert_eq!(model_progress::control(id, true)?["cancelled"], true);
        release.send(())?;
        server.join().map_err(|_| anyhow!("download server panicked"))??;
        let error = download.join().map_err(|_| anyhow!("download worker panicked"))?.err().ok_or_else(|| anyhow!("cancelled download succeeded"))?;
        assert!(matches!(error.downcast_ref::<model_progress::OperationStopped>(), Some(model_progress::OperationStopped::Cancelled)));
        assert_eq!(model_progress::status()?["active"], false);
        assert!(temporary.exists());
        assert_eq!(std::fs::read(&verified)?, b"keep verified file");
        let second = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let second_url = file_url(&format!("http://{}", second.server_addr()), "tokenizer.json");
        let server = std::thread::spawn(move || -> Result<()> {
            let request = second.recv_timeout(Duration::from_secs(10))?.ok_or_else(|| anyhow!("replacement source was not used"))?;
            assert!(request.url().contains(MODEL_REVISION));
            request.respond(tiny_http::Response::from_string("replacement body"))?;
            Ok(())
        });
        let _operation = model_progress::Operation::begin("connect")?;
        let expected = hex::encode(Sha256::digest(b"replacement body"));
        let target = dir.path().join("tokenizer.json");
        download_verified(&second_url, &target, &expected)?;
        server.join().map_err(|_| anyhow!("replacement server panicked"))??;
        assert_eq!(std::fs::read(target)?, b"replacement body");
        assert_eq!(std::fs::read(verified)?, b"keep verified file");
        Ok(())
    }

    #[test]
    fn unknown_length_partial_is_retained_and_resumed_after_checksum_failure() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial");
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let handler = std::thread::spawn(move || -> Result<()> {
            let request = server.recv()?;
            request.respond(tiny_http::Response::new(tiny_http::StatusCode(200), vec![],
                std::io::Cursor::new(b"abc"), None, None))?;
            let request = server.recv()?;
            assert!(request.headers().iter().any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=3-"));
            let range = tiny_http::Header::from_bytes("Content-Range", "bytes 3-5/6").map_err(|_| anyhow!("range header"))?;
            request.respond(tiny_http::Response::from_string("def").with_status_code(206).with_header(range))?;
            let request = server.recv_timeout(std::time::Duration::from_secs(10))?
                .ok_or_else(|| anyhow!("corrupt-prefix resume request missing"))?;
            assert!(request.headers().iter().any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=3-"));
            let range = tiny_http::Header::from_bytes("Content-Range", "bytes 3-5/6").map_err(|_| anyhow!("range header"))?;
            request.respond(tiny_http::Response::from_string("def").with_status_code(206).with_header(range))?;
            let request = server.recv_timeout(std::time::Duration::from_secs(10))?
                .ok_or_else(|| anyhow!("fresh request after corrupt prefix missing"))?;
            assert!(!request.headers().iter().any(|header| header.field.equiv("Range")));
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
        handler.join().map_err(|_| anyhow!("test server panicked"))??;
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

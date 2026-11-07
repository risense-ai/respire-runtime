//! Explicitly install the local BGE-M3 model files.
//!
//! Does not touch the session or create a memory store. A failed download leaves
//! partial files outside the loader's paths. A model that already
//! verifies is not overwritten. Hugging Face mirrors only replace the host;
//! CPU release proxies have their own source list and retain the pinned bytes.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

#[cfg(test)]
use crate::model_asset_files::{file_url, replace_file};
use crate::model_progress;
use respire_app::memory::bge::{expand_home, model_files_present};

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

pub use crate::model_asset_files::{MODEL_REPO, MODEL_REVISION};
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

pub use crate::model_download::{validate_mirror, MIRRORS};
pub(crate) use crate::model_download::origin_from_mirror;

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
    crate::model_asset_files::install_variant_into(
        variant.name,
        &file,
        variant.sha256,
        variant.size,
        pinned_size(variant.sha256),
        dest,
        origins,
    )
}

/// Used by the runtime's reserved background operation after a source change.
pub fn prepare_m3_from_mirror(mirror: &str) -> Result<()> {
    install_m3_inner(Some(mirror)).map(|_| ())
}

/// Called with the background index operation already reserved. Preparing files
/// must not try to reserve that operation a second time or acquire a library lock.
pub fn prepare_m3_for_index() -> Result<()> {
    let user = install_target_dir(None)?;
    let explicit = respire_app::env::var_os("RSRS_M3_DIR").is_some()
        || respire_app::env::var_os("RSRS_DATA_DIR").is_some();
    let mut candidates = vec![user];
    if !explicit {
        if let Some(parent) = std::env::current_exe()?.parent() {
            candidates.push(parent.join("models/bge-m3"));
        }
        candidates.push(PathBuf::from("/usr/lib/respire/models/bge-m3"));
    }
    for path in candidates {
        if file_valid(&path.join("tokenizer.json"), TOKENIZER_SHA256)?
            && m3_model_valid(&path.join("onnx/model_quantized.onnx"))?
        {
            prepare_cpu_ort(&path)?;
            return Ok(());
        }
    }
    install_m3_inner(None)?;
    Ok(())
}

fn install_m3_inner(mirror: Option<&str>) -> Result<InstallReport> {
    let dest = install_target_dir(None)?;
    let origins = model_origins(mirror)?;
    let files = [
        ("tokenizer.json", TOKENIZER_SHA256),
        ("onnx/model_quantized.onnx", ONNX_SHA256),
    ];
    let files = files.map(|(name, sha)| (name, sha, pinned_size(sha)));
    let skipped = crate::model_asset_files::install_baseline_into(&files, &dest, &origins)?;
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
    let downloaded_from = crate::model_asset_files::install_cpu_container_into(
        &partial,
        &dest,
        &sources,
        bge::CPU_ORT_SHA256,
        bge::CPU_ORT_SIZE,
        pinned_size(bge::CPU_ORT_SHA256),
    )?;
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

fn m3_model_valid(path: &Path) -> Result<bool> {
    file_valid(path, ONNX_SHA256)
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
    crate::model_download::file_valid(path, expected, pinned_size(expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use sha2::{Digest, Sha256};

    use crate::model_download::{download_verified, sha256_file};

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
                pinned_size("unused-on-cancel"),
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
        download_verified(
            &second_url,
            &target,
            &expected,
            pinned_size(&expected),
        )?;
        server
            .join()
            .map_err(|_| anyhow!("replacement server panicked"))??;
        assert_eq!(std::fs::read(target)?, b"replacement body");
        assert_eq!(std::fs::read(verified)?, b"keep verified file");
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

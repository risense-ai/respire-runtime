//! Host-only CPU container selection/readiness. No private graph interpretation.
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{io::Read, path::{Path, PathBuf}, sync::Mutex, time::SystemTime};

pub const CPU_ORT_REVISION: &str = "bge-m3-cpu-ort-v1";
pub const CPU_ORT_NAME: &str = "model_quantized.cpu-v1.ort";
pub const CPU_ORT_SHA256: &str = "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff";
pub const CPU_ORT_SIZE: u64 = 569654128;
pub const CPU_ORT_URL: &str = "https://github.com/risense-ai/respire-cli/releases/download/model-bge-m3-ort-v1/model_quantized.cpu-v1.ort";

pub fn cpu_owned_mode(engine: crate::onnx::Engine) -> Result<bool> {
    mode(engine, cfg!(feature="cpu-owned-ort-experiment"),
        crate::env::var("RSRS_CPU_OWNED_ORT_EXPERIMENT").ok().as_deref(),
        crate::env::var_os("RSRS_ORT_PROFILE").is_some())
}
fn mode(engine: crate::onnx::Engine, compiled: bool, setting: Option<&str>, profiling: bool) -> Result<bool> {
    let requested = match setting {
        Some("1") => true,
        Some("0") => false,
        Some(_) => anyhow::bail!("CPU owned ORT setting must be 0 or 1"),
        None => compiled && engine == crate::onnx::Engine::Cpu && !profiling,
    };
    anyhow::ensure!(!requested || compiled, "CPU owned ORT requires a compatible SDK build");
    anyhow::ensure!(!requested || engine == crate::onnx::Engine::Cpu, "CPU owned ORT requires CPU; GPU/NPU use ONNX");
    anyhow::ensure!(!requested || !profiling, "CPU owned ORT does not support profiling; unset the explicit owned setting to profile legacy CPU");
    Ok(requested)
}
pub fn cpu_ort_cache_path() -> PathBuf { crate::bge::default_user_model_dir().join("onnx").join(CPU_ORT_NAME) }
pub fn cpu_ort_path(directory: &Path) -> PathBuf {
    let cached = cpu_ort_cache_path();
    if cached.is_file() { cached } else { directory.join("onnx").join(CPU_ORT_NAME) }
}
struct Validated { path: PathBuf, size: u64, modified: SystemTime, valid: bool }
static VALIDATION: Mutex<Option<Validated>> = Mutex::new(None);
#[cfg(test)]
static HASH_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn invalidate_cpu_ort_validation() -> Result<()> {
    *VALIDATION.lock().map_err(|_|anyhow::anyhow!("CPU model validation lock poisoned"))? = None;
    Ok(())
}
pub fn cpu_ort_present(directory: &Path) -> Result<bool> { validated_path(cpu_ort_path(directory)) }
fn validated_path(path: PathBuf) -> Result<bool> {
    let metadata = match std::fs::metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect CPU model container"),
    };
    if !metadata.is_file() || metadata.len() != CPU_ORT_SIZE { return Ok(false); }
    let modified = metadata.modified()?;
    let mut slot = VALIDATION.lock().map_err(|_|anyhow::anyhow!("CPU model validation lock poisoned"))?;
    if let Some(value) = slot.as_ref().filter(|value|value.path == path && value.size == metadata.len() && value.modified == modified) {
        return Ok(value.valid);
    }
    #[cfg(test)]
    HASH_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut file = std::fs::File::open(&path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64*1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    let valid = format!("{:x}",hasher.finalize()) == CPU_ORT_SHA256;
    *slot = Some(Validated { path, size:metadata.len(), modified, valid });
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_and_loading_share_legacy_selection() -> Result<()> {
        use crate::onnx::Engine::{Cpu,Gpu,Npu};
        for engine in [Cpu,Gpu,Npu] {
            assert!(!mode(engine,true,Some("0"),false)?);
            assert!(!mode(engine,false,None,false)?);
            assert!(!mode(engine,true,None,true)?);
        }
        assert!(mode(Cpu,true,None,false)?);
        assert!(!mode(Gpu,true,None,false)?);
        assert!(!mode(Npu,true,None,false)?);
        assert!(mode(Cpu,false,Some("1"),false).is_err());
        assert!(mode(Gpu,true,Some("1"),false).is_err());
        assert!(mode(Cpu,true,Some("1"),true).is_err());
        assert!(mode(Cpu,true,Some("invalid"),false).is_err());
        Ok(())
    }
    #[test]
    fn same_size_corruption_is_not_ready_and_cached_checks_do_not_rehash() -> Result<()> {
        let Some(source)=std::env::var_os("RSRS_CORE_TEST_ORT_FILE") else { return Ok(()); };
        let nonce=SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos();
        let directory=std::env::temp_dir().join(format!("respire-cpu-validation-{}-{nonce}",std::process::id()));
        std::fs::create_dir(&directory)?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.0); } }
        let _cleanup=Cleanup(directory);
        let target=_cleanup.0.join(CPU_ORT_NAME);
        std::fs::copy(source,&target)?;
        invalidate_cpu_ort_validation()?;
        assert!(validated_path(PathBuf::from(&target))?);
        let reads=HASH_READS.load(std::sync::atomic::Ordering::Relaxed);
        assert!(validated_path(PathBuf::from(&target))?);
        assert_eq!(HASH_READS.load(std::sync::atomic::Ordering::Relaxed),reads);
        let original_modified=target.metadata()?.modified()?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        use std::io::Write;
        std::fs::OpenOptions::new().write(true).open(&target)?.write_all(b"CORRUPT!")?;
        assert_eq!(target.metadata()?.len(),CPU_ORT_SIZE);
        assert_ne!(target.metadata()?.modified()?, original_modified);
        assert!(!validated_path(PathBuf::from(&target))?);
        assert!(!validated_path(PathBuf::from(&target))?);
        assert_eq!(HASH_READS.load(std::sync::atomic::Ordering::Relaxed),reads+1);
        Ok(())
    }
}

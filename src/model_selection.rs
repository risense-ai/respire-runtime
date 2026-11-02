//! Host transaction for installed model selection. No downloader or library access.
use anyhow::{Context, Result};
use crate::{bge, onnx::{self, Engine, ModelVariant}};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{cell::Cell, io::{Read, Write}, path::Path};

static MODEL_GATE: std::sync::RwLock<()> = std::sync::RwLock::new(());
thread_local! {
    static EXCLUSIVE: Cell<bool> = const { Cell::new(false) };
    static SHARED: Cell<bool> = const { Cell::new(false) };
}
#[allow(dead_code)]
pub(crate) enum Gate {
    Shared(std::sync::RwLockReadGuard<'static, ()>),
    Exclusive(std::sync::RwLockWriteGuard<'static, ()>),
    Nested,
}
impl Drop for Gate {
    fn drop(&mut self) {
        if matches!(self, Self::Exclusive(_)) { EXCLUSIVE.with(|slot| slot.set(false)); }
        if matches!(self, Self::Shared(_)) { SHARED.with(|slot| slot.set(false)); }
    }
}
pub(crate) fn gate(exclusive: bool) -> Result<Gate> {
    if EXCLUSIVE.with(Cell::get) { return Ok(Gate::Nested); }
    if SHARED.with(Cell::get) {
        anyhow::ensure!(!exclusive, "cannot change model selection from an active inference callback");
        return Ok(Gate::Nested);
    }
    if exclusive {
        let guard = MODEL_GATE.write().map_err(|_| anyhow::anyhow!("model selection gate poisoned"))?;
        EXCLUSIVE.with(|slot| slot.set(true));
        Ok(Gate::Exclusive(guard))
    } else {
        let guard = MODEL_GATE.read().map_err(|_| anyhow::anyhow!("model selection gate poisoned"))?;
        SHARED.with(|slot| slot.set(true));
        Ok(Gate::Shared(guard))
    }
}

thread_local! {
    static SELECTION: Cell<Option<(Engine, ModelVariant)>> = const { Cell::new(None) };
}
pub(crate) fn selection() -> Option<(Engine, ModelVariant)> { SELECTION.with(Cell::get) }
pub(crate) fn scoped<T>(engine: Engine, variant: ModelVariant, action: impl FnOnce() -> Result<T>) -> Result<T> {
    struct Restore(Option<(Engine, ModelVariant)>);
    impl Drop for Restore { fn drop(&mut self) { SELECTION.with(|slot| slot.set(self.0)); } }
    let _restore = Restore(SELECTION.with(|slot| slot.replace(Some((engine, variant)))));
    action()
}
fn verify(path: &Path, size: u64, hash: &str) -> Result<()> {
    let mut file = std::fs::File::open(path).with_context(|| format!("missing weights/dependency: {}; download first", path.display()))?;
    anyhow::ensure!(file.metadata()?.is_file() && file.metadata()?.len() == size,
        "invalid size: {}; download the pinned model again", path.display());
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop { let count = file.read(&mut buffer)?; if count == 0 { break; } digest.update(&buffer[..count]); }
    anyhow::ensure!(format!("{:x}",digest.finalize()) == hash,
        "SHA-256/model identity mismatch: {}", path.display());
    Ok(())
}
pub(crate) fn validate(engine: Engine, variant: ModelVariant) -> Result<()> {
    anyhow::ensure!(engine == Engine::Cpu || cfg!(windows) || cfg!(target_os="macos"),
        "selected engine is unsupported on this OS");
    anyhow::ensure!(crate::env::var_os("RSRS_CPU_OWNED_ORT_FILE").is_none(),
        "unset RSRS_CPU_OWNED_ORT_FILE before loading pinned weights");
    let directory = bge::resolve_model_dir()?;
    verify(&directory.join("tokenizer.json"), 17_082_821,
        "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790")?;
    verify(&directory.join(onnx::variant_file_name(variant.name)), variant.size, variant.sha256)?;
    if bge::cpu_owned_mode(engine)? {
        verify(&bge::cpu_ort_path(&directory), bge::CPU_ORT_SIZE, bge::CPU_ORT_SHA256)?;
    }
    Ok(())
}
fn probe() -> Result<Value> {
    #[cfg(test)]
    if tests::FAIL_PROBES.with(|fail| { let count = fail.get(); fail.set(count.saturating_sub(1)); count > 0 }) {
        anyhow::bail!("injected post-reset trial failure");
    }
    let result = bge::BgeEmbedder::load_model("m3")?.probe("Respire model load verification 本地推理验证")?;
    anyhow::ensure!(result["ready"] == true && result["cosine"].as_f64().is_some_and(|v| v.is_finite() && v >= 0.99),
        "actual model inference receipt rejected: {result}");
    Ok(result)
}
fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("settings parent missing")?;
    std::fs::create_dir_all(parent)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path).map_err(|error| error.error)?;
    Ok(())
}
pub(crate) fn check_overrides(engine: Engine, variant: ModelVariant) -> Result<()> {
    // An explicit UI selection must never silently lose to an environment override.
    if let Ok(value) = crate::env::var("RSRS_ENGINE") {
        anyhow::ensure!(Engine::parse(&value)? == engine, "RSRS_ENGINE overrides selection; unset it first");
    }
    if let Ok(value) = crate::env::var("RSRS_MODEL_VARIANT") {
        anyhow::ensure!(onnx::parse_variant(&value)? == variant, "RSRS_MODEL_VARIANT overrides selection; unset it first");
    }
    Ok(())
}
pub(crate) fn load(engine: Engine, variant: ModelVariant) -> Result<Value> {
    let _gate = gate(true)?;
    check_overrides(engine, variant)?;
    let (path, settings) = onnx::engine_settings(engine, false, Some(variant.name))?;
    let previous = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    // Failures before reset preserve the old canonical session and settings.
    scoped(engine, variant, || validate(engine, variant))?;
    let mut commit_attempted = false;
    let result = scoped(engine, variant, || {
        onnx::reset_sessions()?;
        let receipt = probe()?;
        commit_attempted = true;
        persist(&path, &serde_json::to_vec_pretty(&settings)?)?;
        Ok(receipt)
    }).and_then(|receipt| {
        anyhow::ensure!(onnx::configured_engine()? == engine && onnx::configured_variant(engine)? == variant,
            "persisted selection read-back mismatch");
        Ok(receipt)
    });
    match result {
        Ok(receipt) => Ok(json!({"engine":engine,"model":variant.name,"validated":true,
            "loaded":true,"saved":true,"probe":receipt})),
        Err(error) => {
            let restore_settings = if commit_attempted {
                match previous {
                    Some(bytes) => persist(&path, &bytes),
                    None => match std::fs::remove_file(&path) {
                        Ok(()) => Ok(()),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(error) => Err(error.into()),
                    },
                }
            } else { Ok(()) };
            let restored = restore_settings.and_then(|_| {
                onnx::reset_sessions()?;
                probe().map(|_| ())
            });
            match restored {
                Ok(()) => anyhow::bail!("load failed: {error:#}; previous model restored and trial inference passed"),
                Err(restore) => anyhow::bail!("load failed: {error:#}; RECOVERY FAILED: {restore:#}; model availability unverified; inspect settings and use CPU recovery"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn model_transaction_excludes_concurrent_requests_and_rejects_callback_upgrades() -> Result<()> {
        let exclusive = gate(true)?;
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || -> Result<()> {
            let _shared = gate(false)?;
            sent.send(())?;
            let _nested = gate(false)?;
            assert!(gate(true).is_err(), "a callback cannot upgrade an active inference lock");
            Ok(())
        });
        assert!(received.recv_timeout(std::time::Duration::from_millis(30)).is_err());
        drop(exclusive);
        received.recv_timeout(std::time::Duration::from_secs(2))?;
        reader.join().unwrap()?;
        Ok(())
    }
    #[test]
    fn shared_callback_reenters_while_model_writer_is_waiting() -> Result<()> {
        let shared = gate(false)?;
        let (sent, received) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || -> Result<()> {
            sent.send("waiting")?;
            let _exclusive = gate(true)?;
            sent.send("entered")?;
            Ok(())
        });
        assert_eq!(received.recv()?, "waiting");
        assert!(received.recv_timeout(std::time::Duration::from_millis(30)).is_err());
        let nested = gate(false)?;
        assert!(gate(true).is_err());
        drop(nested);
        drop(shared);
        assert_eq!(received.recv_timeout(std::time::Duration::from_secs(2))?, "entered");
        writer.join().unwrap()?;
        Ok(())
    }
    #[test]
    fn checks_file_identity_size_and_type_and_keeps_settings_untouched() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let model = dir.path().join("model");
        let hash = format!("{:x}", Sha256::digest(b"abc"));
        assert!(verify(&model, 3, &hash).is_err());
        std::fs::write(&model, b"abc")?;
        verify(&model, 3, &hash)?;
        assert!(verify(&model, 4, &hash).is_err());
        std::fs::write(&model, b"bad")?;
        assert!(verify(&model, 3, &hash).is_err());
        assert!(verify(dir.path(), 3, &hash).is_err());
        let path = dir.path().join("inference.json");
        persist(&path, b"old")?;
        persist(&path, b"new")?;
        assert_eq!(std::fs::read(path)?, b"new");
        Ok(())
    }
    #[test]
    fn draft_scopes_restore_after_failure_and_never_change_other_threads() -> Result<()> {
        let variant = onnx::parse_variant("fp16")?;
        assert!(selection().is_none());
        let failure: Result<()> = scoped(Engine::Gpu, variant, || {
            assert_eq!(onnx::configured_engine()?, Engine::Gpu);
            assert_eq!(onnx::configured_variant(Engine::Gpu)?, variant);
            std::thread::spawn(|| assert!(selection().is_none())).join().unwrap();
            anyhow::bail!("trial failure")
        });
        assert!(failure.is_err());
        assert!(selection().is_none());
        Ok(())
    }

    // Only this thread's real-model test can inject a single post-reset failure.
    thread_local! { pub(super) static FAIL_PROBES: Cell<u8> = const { Cell::new(0) }; }
    #[test]
    #[ignore = "requires RSRS_CORE_TEST_MODEL_DIR with pinned real quantized ONNX, tokenizer and CPU ORT"]
    fn real_cpu_load_persist_and_failure_recovery() -> Result<()> {
        let models = std::env::var_os("RSRS_CORE_TEST_MODEL_DIR").context("real fixture not configured")?;
        let profile = tempfile::tempdir()?;
        for name in ["RSRS_ENGINE","RSRS_MODEL_VARIANT","RSRS_CPU_OWNED_ORT_FILE","RSRS_CPU_OWNED_ORT_EXPERIMENT"] {
            anyhow::ensure!(crate::env::var_os(name).is_none(), "test requires an isolated environment: {name}");
        }
        std::env::set_var("RSRS_DATA_DIR", profile.path());
        std::env::set_var("RSRS_M3_DIR", models);
        let variant = onnx::parse_variant("quantized")?;
        let receipt = load(Engine::Cpu, variant)?;
        assert_eq!(receipt["loaded"], true);
        assert_eq!(receipt["probe"]["ready"], true);
        let path = profile.path().join("inference.json");
        let previous = std::fs::read(&path)?;
        FAIL_PROBES.with(|fail| fail.set(1));
        let error = load(Engine::Cpu, variant).unwrap_err().to_string();
        assert!(error.contains("previous model restored and trial inference passed"), "{error}");
        assert_eq!(std::fs::read(&path)?, previous);
        probe()?;
        FAIL_PROBES.with(|fail| fail.set(2));
        let error = load(Engine::Cpu, variant).unwrap_err().to_string();
        assert!(error.contains("RECOVERY FAILED"), "{error}");
        assert_eq!(std::fs::read(&path)?, previous);
        load(Engine::Cpu, variant)?;
        Ok(())
    }
}

//! Embedding-specific installation selection, without a second command engine.
use anyhow::{Context, Result};
use respire_host_control::{HostLifecycle, VerifiedRuntime};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// The Runtime supplies its existing installation verifier and host lifecycle.
/// These are process-local callbacks, never command-line authority or credentials.
pub struct RuntimeEmbedding {
    pub verify_runtime: fn() -> Result<VerifiedRuntime>,
    pub account_host: fn() -> Arc<dyn HostLifecycle>,
    /// Compiled implementation support, revalidated against the same installed image.
    /// None preserves ordinary legacy operations but refuses the new handoff.
    pub offline_keygen_handoff: Option<fn() -> Result<VerifiedRuntime>>,
}

pub(crate) struct Selection {
    runtime: VerifiedRuntime,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) manifest_path: PathBuf,
    embedding: RuntimeEmbedding,
}

static EMBEDDING: OnceLock<Selection> = OnceLock::new();

/// Bind the frontend to the Runtime image already selected and checked by its
/// caller. Call only after private Runtime entry points have been dispatched.
pub fn install_runtime_embedding(embedding: RuntimeEmbedding) -> Result<()> {
    let runtime = (embedding.verify_runtime)()?;
    anyhow::ensure!(
        runtime.path() == std::env::current_exe()?.canonicalize()?,
        "embedded host frontend must use its selected Runtime image"
    );
    let directory = runtime
        .path()
        .parent()
        .context("Runtime image has no directory")?;
    anyhow::ensure!(
        directory.file_name().and_then(|value| value.to_str()) == Some(runtime.version()),
        "embedded Runtime is not in its selected version directory"
    );
    let runtime_dir = directory
        .parent()
        .context("Runtime version directory has no parent")?
        .to_path_buf();
    let manifest_path = runtime_dir
        .parent()
        .context("Runtime installation has no parent")?
        .join("runtime.json");
    EMBEDDING
        .set(Selection {
            runtime,
            runtime_dir,
            manifest_path,
            embedding,
        })
        .map_err(|_| anyhow::anyhow!("Runtime host frontend was already initialized"))
}

pub(crate) fn selection() -> Option<&'static Selection> {
    EMBEDDING.get()
}

pub(crate) fn account_host() -> Option<Arc<dyn HostLifecycle>> {
    selection().map(|selected| (selected.embedding.account_host)())
}

impl Selection {
    pub(crate) fn verify_offline_keygen_handoff(&self) -> Result<VerifiedRuntime> {
        let current = self.verify()?;
        let verify = require_handoff_callback(self.embedding.offline_keygen_handoff)?;
        let capable = verify()?;
        require_same_image(&current, &capable)?;
        require_same_image(&self.verify()?, &capable)?;
        anyhow::ensure!(capable.path() == std::env::current_exe()?.canonicalize()?,
            "offline keygen capability must belong to the current Runtime image");
        Ok(capable)
    }

    pub(crate) fn version(&self) -> &str {
        self.runtime.version()
    }

    /// Revalidate through the embedding's original inventory and ownership checks.
    pub(crate) fn verify(&self) -> Result<VerifiedRuntime> {
        let current = (self.embedding.verify_runtime)()?;
        anyhow::ensure!(
            current.path() == self.runtime.path()
                && current.version() == self.runtime.version()
                && current.sha256().eq_ignore_ascii_case(self.runtime.sha256())
                && current.port() == self.runtime.port(),
            "selected Runtime changed during host command"
        );
        if let Some(path) = respire_client_host::env::var_os("RSRS_RUNTIME_BIN") {
            anyhow::ensure!(
                PathBuf::from(path).canonicalize()? == current.path(),
                "embedded host cannot replace the selected Client2 Runtime with an override"
            );
        }
        Ok(current)
    }
}

fn require_handoff_callback(callback: Option<fn() -> Result<VerifiedRuntime>>)
    -> Result<fn() -> Result<VerifiedRuntime>> {
    callback.context("offline_keygen_handoff_unsupported: embedded Runtime lacks the implementation")
}

/// Callback output cannot confer capability on a different selected executable.
fn require_same_image(expected: &VerifiedRuntime, actual: &VerifiedRuntime) -> Result<()> {
    anyhow::ensure!(expected.path() == actual.path()
        && expected.version() == actual.version()
        && expected.sha256().eq_ignore_ascii_case(actual.sha256())
        && expected.port() == actual.port(), "offline keygen capability Runtime binding changed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn missing_handoff_callback_is_not_implementation_support() {
        assert!(require_handoff_callback(None).is_err());
    }

    #[test]
    fn handoff_capability_rejects_every_changed_image_binding() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let image = dir.path().join("runtime");
        let other = dir.path().join("other");
        std::fs::write(&image, b"synthetic-runtime")?;
        std::fs::write(&other, b"synthetic-runtime")?;
        let hash = format!("{:x}", Sha256::digest(b"synthetic-runtime"));
        let selected = VerifiedRuntime::verify_installed(&image, &hash, "4.0.1-dev.5", 12345)?;
        require_same_image(&selected, &selected)?;
        for changed in [
            VerifiedRuntime::verify_installed(&other, &hash, "4.0.1-dev.5", 12345)?,
            VerifiedRuntime::verify_installed(&image, &hash, "4.0.1-dev.4", 12345)?,
            VerifiedRuntime::verify_installed(&image, &hash, "4.0.1-dev.5", 12346)?,
        ] { assert!(require_same_image(&selected, &changed).is_err()); }
        std::fs::write(&image, b"changed-image")?;
        let changed_hash = format!("{:x}", Sha256::digest(b"changed-image"));
        let changed = VerifiedRuntime::verify_installed(&image, &changed_hash, "4.0.1-dev.5", 12345)?;
        assert!(require_same_image(&selected, &changed).is_err());
        Ok(())
    }
}

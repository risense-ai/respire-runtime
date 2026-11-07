use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) fn cli_bin() -> std::io::Result<PathBuf> {
    let raw = std::env::var_os("RSRS_CLI_BIN").ok_or_else(|| {
        std::io::Error::other("supply RSRS_CLI_BIN with the exact source-bound CLI executable")
    })?;
    let binary = PathBuf::from(raw).canonicalize()?;
    if !binary.is_file() {
        return Err(std::io::Error::other("RSRS_CLI_BIN is not a file"));
    }
    Ok(binary)
}

pub(super) fn runtime_bin() -> std::io::Result<PathBuf> {
    let raw = std::env::var_os("RSRS_RUNTIME_BIN").ok_or_else(|| {
        std::io::Error::other("supply RSRS_RUNTIME_BIN with a verified standalone Runtime fixture")
    })?;
    let binary = PathBuf::from(raw).canonicalize()?;
    if !binary.is_file() || binary == cli_bin()? {
        return Err(std::io::Error::other("CLI shim cannot substitute for the Runtime fixture"));
    }
    Ok(binary)
}

pub(super) fn cli_source() -> anyhow::Result<PathBuf> {
    let source = PathBuf::from(std::env::var_os("RSRS_CLI_SOURCE_DIR")
        .context("supply the exact CLI source checkout used to build RSRS_CLI_BIN")?)
        .canonicalize()?;
    let expected = std::env::var("RSRS_CLI_SOURCE_SHA")
        .context("supply the exact CLI source SHA")?;
    anyhow::ensure!(expected.len() == 40 && expected.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid CLI source SHA");
    // The native workflow verifies both checkout HEADs before it builds either side.
    anyhow::ensure!(source.join("runtime-pin.json").is_file(), "CLI source pin is missing");
    Ok(source)
}

// Candidate mode is test-only and opt-in. It accepts the unmodified receipt from
// the real offline installer, never a replacement official pin or release claim.
fn candidate_version(selected: &Value, pinned: &str, binary: &Path) -> anyhow::Result<String> {
    let path = std::env::var_os("RSRS_RUNTIME_CANDIDATE_METADATA")
        .context("candidate metadata path missing")?;
    let raw = std::fs::read_to_string(path)?;
    let metadata: Value = serde_json::from_str(&raw)?;
    let source = std::env::var("RSRS_RUNTIME_SOURCE_SHA")?;
    anyhow::ensure!(source.len() == 40 && source.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid Runtime source SHA");
    let version = metadata["runtime_version"].as_str().context("candidate version missing")?;
    anyhow::ensure!(version != pinned && metadata["schema_version"] == 2
        && metadata["candidate"]["kind"] == "unpublished-source-fixture"
        && metadata["source_commit"] == source
        && metadata["candidate"]["cli_source_sha"] == std::env::var("RSRS_CLI_SOURCE_SHA")?
        && metadata["candidate"]["cli_binary_sha256"]
            == format!("{:x}", Sha256::digest(std::fs::read(cli_bin()?)?))
        && selected["version"] == version
        && selected["release"]["metadata_json"] == raw
        && selected["release"]["metadata_sha256"] == format!("{:x}", Sha256::digest(raw.as_bytes()))
        && selected["sha256"] == metadata["binary_sha256"]
        && selected["sha256"] == format!("{:x}", Sha256::digest(std::fs::read(binary)?)),
        "candidate fixture identity differs from its source-bound offline installation");
    Ok(version.to_owned())
}

// Copy the installer receipt and inventory verbatim. Product trust validation
// still runs against the copied installation; no selection receipt is fabricated.
pub(super) fn install_runtime_fixture(root: &Path) -> anyhow::Result<()> {
    let binary = runtime_bin()?;
    let version_dir = binary.parent().context("Runtime fixture version directory missing")?;
    let source_root = version_dir.parent().and_then(Path::parent)
        .context("Runtime fixture installation root missing")?;
    let receipt = source_root.join("runtime.json");
    let selected: Value = serde_json::from_slice(&std::fs::read(&receipt)?)?;
    let pin: Value = serde_json::from_slice(&std::fs::read(cli_source()?.join("runtime-pin.json"))?)?;
    let pinned = pin["required"].as_str().context("Runtime pin required missing")?;
    let version = if std::env::var_os("RSRS_RUNTIME_CANDIDATE_METADATA").is_some() {
        candidate_version(&selected, pinned, &binary)?
    } else {
        pinned.to_owned()
    };
    anyhow::ensure!(selected["version"] == version
        && selected["release"]["metadata_json"].is_string()
        && source_root.join("runtime").join(&version) == version_dir,
        "Runtime fixture must be a verified managed installation");
    let mut pending = vec![(version_dir.to_path_buf(), root.join("runtime").join(&version))];
    while let Some((source, target)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&source)?;
        anyhow::ensure!(!metadata.file_type().is_symlink(), "Runtime fixture contains a link");
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(metadata.file_attributes() & 0x400 == 0,
                "Runtime fixture contains a reparse point");
        }
        if metadata.is_dir() {
            std::fs::create_dir_all(&target)?;
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                pending.push((entry.path(), target.join(entry.file_name())));
            }
        } else {
            anyhow::ensure!(metadata.is_file(), "Runtime fixture contains a non-file");
            std::fs::copy(source, target)?;
        }
    }
    anyhow::ensure!(std::fs::symlink_metadata(&receipt)?.is_file(), "Runtime fixture receipt missing");
    std::fs::copy(receipt, root.join("runtime.json"))?;
    Ok(())
}

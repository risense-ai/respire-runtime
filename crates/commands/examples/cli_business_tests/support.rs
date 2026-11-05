use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::Value;

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
        std::io::Error::other("supply RSRS_RUNTIME_BIN with the official standalone Runtime fixture")
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

// Copy the official installation receipt and inventory verbatim. Product trust
// validation still runs against the copied installation; no manifest is fabricated.
pub(super) fn install_runtime_fixture(root: &Path) -> anyhow::Result<()> {
    let binary = runtime_bin()?;
    let version_dir = binary.parent().context("Runtime fixture version directory missing")?;
    let source_root = version_dir.parent().and_then(Path::parent)
        .context("Runtime fixture installation root missing")?;
    let receipt = source_root.join("runtime.json");
    let selected: Value = serde_json::from_slice(&std::fs::read(&receipt)?)?;
    let pin: Value = serde_json::from_slice(&std::fs::read(cli_source()?.join("runtime-pin.json"))?)?;
    let version = pin["required"].as_str().context("Runtime pin required missing")?;
    anyhow::ensure!(selected["version"] == version
        && selected["release"]["metadata_json"].is_string()
        && source_root.join("runtime").join(version) == version_dir,
        "Runtime fixture must be the official pinned managed installation");
    let mut pending = vec![(version_dir.to_path_buf(), root.join("runtime").join(version))];
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

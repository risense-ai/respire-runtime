//! Read and validate client configuration without inspecting model state.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

/// Resolve only the host-control roots; never inspect models or create directories.
pub fn control_roots() -> Result<(PathBuf, PathBuf)> {
    let (root, profile, _) = read_control_config()?;
    Ok((root, profile))
}

/// Keep validated roots and the selected profile tied to one client.json read.
pub(crate) fn read_control_config() -> Result<(PathBuf, PathBuf, Option<serde_json::Value>)> {
    if let Some(raw) = crate::env::var_os("RSRS_DATA_DIR") {
        anyhow::ensure!(raw.to_str().is_some_and(|value| !value.trim().is_empty()),
            "RSRS_DATA_DIR must be a nonempty UTF-8 path");
        // Also validate an internally forwarded override that root selection ignores.
        let value = raw.to_str().context("RSRS_DATA_DIR is not UTF-8")?;
        absolute_control_path(crate::paths::expand_tilde(value.trim()))?;
    }
    let root = absolute_control_path(crate::paths::main_data_dir())?;
    let config_path = absolute_control_path(crate::paths::client_config_path())?;
    let config = read_client_config(&config_path)?;
    // Validate even a configured path that legacy whole-installation isolation ignores.
    if let Some(value) = config.as_ref().and_then(|config| config["data_dir"].as_str())
        .filter(|value| !value.is_empty()) {
        absolute_control_path(crate::paths::expand_tilde(value))?;
    }
    let profile = absolute_control_path(crate::paths::data_dir_from_config(config.as_ref()))?;
    Ok((root, profile, config))
}

fn absolute_control_path(path: PathBuf) -> Result<PathBuf> {
    anyhow::ensure!(!path.components().any(|part| part == Component::ParentDir),
        "host control does not support parent traversal; use an explicit root without '..'");
    normalize_control_path(&path)
}

/// Normalize only known macOS system ancestor aliases. All custom redirects,
/// including the requested path itself, remain forbidden. Missing suffixes are
/// allowed; this is a preflight, not an OS nofollow/open-by-handle guarantee.
pub fn normalize_control_path(path: &Path) -> Result<PathBuf> {
    anyhow::ensure!(!path.components().any(|part| part == Component::ParentDir),
        "host control does not support parent traversal");
    let absolute = std::path::absolute(path)?;
    let mut resolved = PathBuf::new();
    let mut parts = absolute.components().peekable();
    while let Some(part) = parts.next() {
        resolved.push(part);
        if matches!(part, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&resolved) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("cannot inspect host control path"),
        };
        let redirected = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let redirected = {
            use std::os::windows::fs::MetadataExt;
            redirected || metadata.file_attributes() & 0x400 != 0
        };
        if !redirected {
            anyhow::ensure!(parts.peek().is_none() || metadata.is_dir(),
                "host control ancestor is not a directory");
            continue;
        }
        #[cfg(target_os = "macos")]
        if parts.peek().is_some() {
            let system_target = match resolved.to_str() {
                Some("/var") => Some(Path::new("/private/var")),
                Some("/tmp") => Some(Path::new("/private/tmp")),
                Some("/etc") => Some(Path::new("/private/etc")),
                _ => None,
            };
            if let Some(target) = system_target {
                // Never turn an altered system alias into an arbitrary redirect.
                for ancestor in target.ancestors() {
                    let metadata = std::fs::symlink_metadata(ancestor)?;
                    anyhow::ensure!(metadata.is_dir() && !metadata.file_type().is_symlink(),
                        "macOS system alias target is redirected");
                }
                anyhow::ensure!(resolved.canonicalize()? == target,
                    "macOS system alias target changed");
                resolved = target.to_path_buf();
                continue;
            }
        }
        anyhow::bail!("host control path contains a symlink/reparse point: {}", resolved.display());
    }
    Ok(resolved)
}

pub fn read_client_config(path: &Path) -> Result<Option<serde_json::Value>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot read client config {}", path.display()))
        }
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("client config {} contains invalid JSON", path.display()))?;
    validate_client_config(&value, path)?;
    Ok(Some(value))
}

/// Validate a read-modify-write candidate using the same rules as the reader.
pub fn validate_client_config(value: &serde_json::Value, path: &Path) -> Result<()> {
    anyhow::ensure!(
        value.is_object(),
        "client config {} must contain a JSON object",
        path.display()
    );
    for key in [
        "lang",
        "data_dir",
        "addr",
        "api_base",
        "service_mode",
        "engine",
        "model",
    ] {
        if let Some(field) = value.get(key) {
            anyhow::ensure!(
                field.is_string(),
                "client config {} has invalid type for {key}",
                path.display()
            );
        }
    }
    for key in ["autosync", "cure_auto"] {
        if let Some(field) = value.get(key) {
            anyhow::ensure!(
                field.is_boolean(),
                "client config {} has invalid type for {key}",
                path.display()
            );
        }
    }
    if let Some(field) = value.get("rpc_parallelism") {
        anyhow::ensure!(
            field.as_u64().is_some_and(|value| value <= u32::MAX as u64),
            "client config {} has invalid rpc_parallelism",
            path.display()
        );
    }
    Ok(())
}

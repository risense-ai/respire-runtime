//! Validate explicit filesystem paths used by the host identity reader.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

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

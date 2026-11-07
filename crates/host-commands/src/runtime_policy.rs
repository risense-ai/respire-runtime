//! A sandbox is an HTTP client; only the host owns runtime lifecycle.

use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

pub fn client_only() -> bool {
    if ["RSRS_CLIENT_ONLY", "RSRS_NO_AUTOSTART"]
        .iter()
        .any(|name| {
            respire_client_host::env::var(name).is_ok_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
        })
    {
        return true;
    }
    static RESTRICTED: OnceLock<bool> = OnceLock::new();
    *RESTRICTED.get_or_init(|| match respire_spawn::is_restricted() {
        Ok(restricted) => restricted,
        Err(error) => {
            eprintln!("cannot inspect process confinement; using client-only mode: {error}");
            true
        }
    })
}

pub fn require_host(action: &str) -> Result<()> {
    if client_only() {
        bail!("client_only: {action} is host-managed; connect to the host loopback HTTP runtime. Start or update rsrs from the host terminal, outside the sandbox");
    }
    Ok(())
}

// This is a preflight, not an OS nofollow/open-by-handle guarantee. An external
// rename between checking a component and SQLite opening it is still a TOCTOU risk.
fn checked_takeover_directory() -> Result<std::path::PathBuf> {
    let (root, _) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(
        root.is_absolute()
            && !root
                .components()
                .any(|part| part == std::path::Component::ParentDir),
        "takeover requires an exact absolute installation root"
    );
    // System aliases above the installation (for example macOS /var) are allowed.
    // Pin their resolution even when the installation itself does not exist yet.
    let mut canonical_root = None;
    for ancestor in root.ancestors() {
        match ancestor.canonicalize() {
            Ok(resolved) => {
                anyhow::ensure!(resolved.is_dir(), "installation ancestor is not a directory");
                canonical_root = Some(resolved.join(root.strip_prefix(ancestor)?));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("cannot resolve takeover installation root"),
        }
    }
    let canonical_root = canonical_root.context("installation root has no existing ancestor")?;
    let directory = root.join("runtime/takeover");
    for name in ["lock.db", "lock.db-journal", "lock.db-wal", "lock.db-shm"] {
        let path = directory.join(name);
        for (index, ancestor) in path
            .ancestors()
            .take_while(|ancestor| ancestor.starts_with(&root))
            .enumerate()
        {
            let metadata = match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot inspect takeover path {}", ancestor.display())
                    })
                }
            };
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "takeover path contains a symlink: {}",
                ancestor.display()
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.file_attributes() & 0x400 == 0,
                    "takeover path contains a reparse point: {}",
                    ancestor.display()
                );
            }
            anyhow::ensure!(
                if index == 0 {
                    metadata.is_file()
                } else {
                    metadata.is_dir()
                },
                "takeover path has an invalid file type: {}",
                ancestor.display()
            );
            anyhow::ensure!(
                ancestor.canonicalize()? == canonical_root.join(ancestor.strip_prefix(&root)?),
                "takeover path escapes or changed its resolved installation root"
            );
        }
    }
    // Acquire the pinned path, then compare it again after locking.
    Ok(canonical_root.join("runtime/takeover"))
}

fn acquire_takeover(
    max_wait: std::time::Duration,
) -> Result<respire_client_host::lock::LibraryLock> {
    let directory = checked_takeover_directory()?;
    let guard = respire_client_host::lock::LibraryLock::acquire(&directory, max_wait)?;
    let current = checked_takeover_directory()?;
    anyhow::ensure!(
        current == directory && guard.protects(&current)?,
        "takeover installation root or lock ownership changed"
    );
    Ok(guard)
}

pub fn takeover_lock() -> Result<respire_client_host::lock::LibraryLock> {
    require_host("runtime lifecycle")?;
    acquire_takeover(std::time::Duration::from_secs(60))
}

/// Background commits must yield to a lifecycle owner that is draining them,
/// rather than wait for that owner's lock and deadlock the drain.
pub fn try_takeover_lock() -> Result<respire_client_host::lock::LibraryLock> {
    require_host("background diary cache commit")?;
    acquire_takeover(std::time::Duration::ZERO)
}

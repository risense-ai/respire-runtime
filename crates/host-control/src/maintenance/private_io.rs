//! Durable compare-and-replace support, extracted from the CLI autostart owner.
use super::{marker_path, RegistrationMode, MAINTENANCE_MARKER_MAX_BYTES};
use crate::launch::hash;
use anyhow::{Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

pub(super) fn bounded_bytes(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64,
        "maintenance record must be a bounded regular file"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        anyhow::ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "maintenance record is a reparse point"
        );
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "maintenance record exceeds size limit"
    );
    Ok(Some(bytes))
}

pub(super) fn marker_bytes(root: &Path) -> Result<Option<Vec<u8>>> {
    bounded_bytes(&marker_path(root), MAINTENANCE_MARKER_MAX_BYTES)
}

pub(super) fn registration_digest(root: &Path, mode: &RegistrationMode) -> Result<Option<String>> {
    if !matches!(mode, RegistrationMode::Unregistered) {
        let bytes = bounded_bytes(&root.join("runtime/autostart/registration.json"), 64 * 1024)?
            .context("maintenance registration disappeared")?;
        Ok(Some(hash(&bytes)))
    } else {
        Ok(None)
    }
}

pub(super) fn private_write(path: &Path, bytes: &[u8], expected: Option<&str>) -> Result<()> {
    anyhow::ensure!(
        bytes.len() <= MAINTENANCE_MARKER_MAX_BYTES,
        "maintenance marker exceeds size limit"
    );
    let parent = path.parent().context("maintenance file has no parent")?;
    // Like the source implementation, this is a conservative path preflight,
    // not a claim of kernel nofollow protection against another writer's rename.
    for ancestor in parent.ancestors() {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "maintenance parent is not an exact directory"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "maintenance parent is a reparse point"
            );
        }
    }
    let actual = bounded_bytes(path, MAINTENANCE_MARKER_MAX_BYTES)?;
    match actual.as_ref() {
        Some(actual) => anyhow::ensure!(
            expected == Some(hash(actual).as_str()),
            "maintenance file changed before replacement"
        ),
        None => anyhow::ensure!(expected.is_none(), "owned maintenance file disappeared"),
    }
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".respire-autostart-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // Recheck immediately before publication. Cooperating callers also hold
        // the installation takeover lock; external races remain fail-closed on
        // the following exact-digest ownership check.
        let latest = bounded_bytes(path, MAINTENANCE_MARKER_MAX_BYTES)?;
        anyhow::ensure!(
            latest == actual,
            "maintenance file changed during publication"
        );
        if expected.is_some() {
            respire_spawn::durable::replace_file(&temporary, path)?;
        } else {
            respire_spawn::durable::publish_new_file(&temporary, path)?;
        }
        Ok(())
    })();
    if result.is_err() && temporary.try_exists()? {
        fs::remove_file(&temporary)?;
    }
    result
}

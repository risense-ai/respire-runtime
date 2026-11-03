//! Same-directory file publication used by host snapshot transactions.
use std::{fs, io, path::Path};

fn same_parent(source: &Path, destination: &Path) -> io::Result<()> {
    let source_parent = source
        .parent()
        .ok_or_else(|| io::Error::other("source has no parent"))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("destination has no parent"))?;
    if fs::canonicalize(source_parent)? != fs::canonicalize(destination_parent)? {
        return Err(io::Error::other(
            "durable publication requires the same directory",
        ));
    }
    Ok(())
}

/// Publish an already-flushed regular file without overwriting an existing name.
pub fn publish_new_file(source: &Path, destination: &Path) -> io::Result<()> {
    same_parent(source, destination)?;
    #[cfg(unix)]
    {
        fs::hard_link(source, destination)?;
        fs::remove_file(source)?;
        sync_directory(
            destination
                .parent()
                .ok_or_else(|| io::Error::other("missing parent"))?,
        )
    }
    #[cfg(windows)]
    {
        move_windows(source, destination, false)
    }
}

/// Replace a regular file in the same directory and flush namespace changes.
pub fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    same_parent(source, destination)?;
    #[cfg(unix)]
    {
        fs::rename(source, destination)?;
        sync_directory(
            destination
                .parent()
                .ok_or_else(|| io::Error::other("missing parent"))?,
        )
    }
    #[cfg(windows)]
    {
        move_windows(source, destination, true)
    }
}

/// Unix fsyncs the containing directory. Windows publication uses the native
/// MOVEFILE_WRITE_THROUGH path instead; callers must publish with these helpers.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(windows)]
fn move_windows(source: &Path, destination: &Path, replace: bool) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |path: &Path| -> io::Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        value.push(0);
        Ok(value)
    };
    let source = wide(source)?;
    let destination = wide(destination)?;
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    // SAFETY: both owned UTF-16 buffers are NUL terminated, remain live for the
    // synchronous call, and MoveFileExW does not retain either pointer.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

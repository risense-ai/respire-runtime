//! Invalid command input is distinct from storage, network and engine failures.

#[derive(Debug)]
pub struct InputError(pub String);

impl std::fmt::Display for InputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for InputError {}

/// Validate a user-selected output directory without reclassifying write or storage failures.
pub fn validate_output_parent(path: &std::path::Path) -> anyhow::Result<()> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let metadata = std::fs::metadata(parent).map_err(|error| {
        let message = format!("invalid output directory: {} ({error})", parent.display());
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::Error::new(InputError(message))
        } else {
            anyhow::Error::new(error).context(message)
        }
    })?;
    if !metadata.is_dir() {
        return Err(InputError(format!("output parent is not a directory: {}", parent.display())).into());
    }
    Ok(())
}

/// Missing user-selected files are input errors. Other I/O failures remain runtime failures.
pub fn read_file(path: &std::path::Path, purpose: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|error| {
        let message = format!("failed to read {purpose}: {} ({error})", path.display());
        if error.kind() == std::io::ErrorKind::NotFound {
            InputError(message).into()
        } else {
            anyhow::Error::new(error).context(message)
        }
    })
}

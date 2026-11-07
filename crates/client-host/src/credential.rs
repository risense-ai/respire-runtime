//! Read existing runtime tokens and generate host-managed token material.

use std::path::Path;

use anyhow::{Context, Result};
use rand::RngCore;

/// The caller must authorize host credential creation before generating a token.
pub fn generate_runtime_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("cannot generate runtime token from OS randomness")?;
    Ok(hex::encode(bytes))
}

pub fn read_token_file(path: &Path) -> Result<Option<String>> {
    let value = match std::fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot read runtime token {}", path.display()))
        }
    };
    let token = value.trim();
    anyhow::ensure!(
        !token.is_empty(),
        "runtime token {} is empty",
        path.display()
    );
    Ok(Some(token.to_owned()))
}

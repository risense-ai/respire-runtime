//! Read-only installation, profile and model paths; no native backend is loaded.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::paths::{client_config_path, data_dir_from_config, env_root_dir, expand_tilde, main_data_dir};

#[derive(serde::Serialize)]
pub struct ResolvedRoots {
    pub schema_version: u32,
    pub layout: &'static str,
    pub installation_root: PathBuf,
    pub device_config_root: PathBuf,
    pub client_config_path: PathBuf,
    pub account_data_root: PathBuf,
    pub accounts_root: PathBuf,
    pub asset_root: PathBuf,
    pub runtime_state_root: PathBuf,
    pub legacy_whole_isolation: bool,
    pub sources: std::collections::BTreeMap<&'static str, &'static str>,
}

pub fn resolved_roots() -> Result<ResolvedRoots> {
    // Do not clean parent traversals: symlinks can change their actual target.
    let absolute = |path: PathBuf| -> Result<PathBuf> {
        anyhow::ensure!(
            !path
                .components()
                .any(|part| part == std::path::Component::ParentDir),
            "root summary does not support parent traversal; use an explicit root without '..'"
        );
        Ok(std::path::absolute(path)?)
    };
    let asset_root = absolute(m3_model_dir()?)?;
    let installation_root = absolute(main_data_dir())?;
    let client_config_path = absolute(client_config_path())?;
    let config = crate::config::read_client_config(&client_config_path)?
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(value) = config["data_dir"]
        .as_str()
        .filter(|value| !value.is_empty())
    {
        absolute(expand_tilde(value))?;
    }
    let device_config_root = client_config_path
        .parent()
        .context("client config has no parent")?
        .to_path_buf();
    let account = data_dir_from_config(Some(&config));
    let legacy_whole_isolation = env_root_dir().is_some();
    let root_source = if legacy_whole_isolation {
        "RSRS_DATA_DIR"
    } else {
        "default_data_dir"
    };
    let account_source = if config["data_dir"]
        .as_str()
        .is_some_and(|value| !value.is_empty() && expand_tilde(value) == account)
    {
        "client.json:data_dir"
    } else {
        root_source
    };
    let asset_source = if crate::env::var("RSRS_M3_DIR").is_ok_and(|value| !value.trim().is_empty())
    {
        "RSRS_M3_DIR"
    } else {
        root_source
    };
    anyhow::ensure!(
        !legacy_whole_isolation || asset_source == "RSRS_M3_DIR" || asset_root.starts_with(&installation_root),
        "model root expansion conflicts with legacy isolation; use an explicit absolute data root or model root"
    );
    Ok(ResolvedRoots {
        schema_version: 1,
        layout: "phase1",
        runtime_state_root: installation_root.join("runtime"),
        installation_root,
        device_config_root,
        client_config_path,
        account_data_root: absolute(account)?,
        accounts_root: absolute(main_data_dir().join("accounts"))?,
        asset_root,
        legacy_whole_isolation,
        sources: std::collections::BTreeMap::from([
            ("installation_root", root_source),
            ("device_config_root", root_source),
            ("client_config_path", root_source),
            ("account_data_root", account_source),
            ("accounts_root", root_source),
            ("asset_root", asset_source),
            ("runtime_state_root", root_source),
        ]),
    })
}

fn model_dir_setting(name: &str) -> Result<Option<PathBuf>> {
    match crate::env::var(name) {
        Ok(value) => {
            anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty or whitespace");
            Ok(Some(expand_model_home(value.trim())))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must contain valid Unicode"),
    }
}

pub fn default_user_model_dir() -> Result<PathBuf> {
    let root = model_dir_setting("RSRS_DATA_DIR")?;
    // CPU cache callers must reject an invalid model override too.
    model_dir_setting("RSRS_M3_DIR")?;
    Ok(root.map(|root| root.join("models/bge-m3"))
        .unwrap_or_else(|| expand_model_home("~/.rsrs/models/bge-m3")))
}

pub fn m3_model_dir() -> Result<PathBuf> {
    // Validate the isolation root even when a model override is present.
    let default = default_user_model_dir()?;
    Ok(model_dir_setting("RSRS_M3_DIR")?.unwrap_or(default))
}

fn expand_model_home(value: &str) -> PathBuf {
    match value.strip_prefix("~/") {
        Some(rest) => dirs::home_dir()
            .or_else(|| crate::env::var_os("HOME").map(PathBuf::from))
            .or_else(|| crate::env::var_os("USERPROFILE").map(PathBuf::from))
            .map(|base| base.join(rest))
            .unwrap_or_else(|| PathBuf::from(value)),
        None => PathBuf::from(value),
    }
}

/// Validate configuration without opening a library or loading a native backend.
pub fn validate_client_environment() -> Result<()> {
    m3_model_dir()?;
    crate::config::read_client_config(&crate::paths::client_config_path()).map(|_| ())
}

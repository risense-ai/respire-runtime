//! Persistent read heat configuration, explicitly loaded by the resident runtime.

use anyhow::{Context, Result};
use serde_json::Value;
use std::{path::PathBuf, sync::Mutex};

// None means not loaded; Some(None) preserves the paired Core's legacy default.
static EFFECTIVE: Mutex<Option<(PathBuf, Option<bool>)>> = Mutex::new(None);

pub fn configured() -> Result<Option<bool>> {
    let path = crate::service::agent_config_path();
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let config: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid agent configuration: {}", path.display()))?;
    let object = config.as_object().context("agent config must be an object")?;
    object.get("read_heat").map(|value| {
        value.as_bool().context("read_heat must be true or false")
    }).transpose()
}

pub fn require_support() -> Result<()> {
    let capabilities: Value = crate::core_sdk::execute("capabilities", Value::Null)?;
    anyhow::ensure!(capabilities["read_heat_contract"].as_u64() == Some(1),
        "explicit read_heat requires Core SDK read_heat_contract 1; install the paired SDK/CLI version");
    Ok(())
}

/// Failed reloads retain the last successfully loaded value.
pub fn reload() -> Result<Option<bool>> {
    let configured = configured()?;
    if configured.is_some() {
        require_support()?;
    }
    let mut effective = EFFECTIVE.lock().map_err(|_| anyhow::anyhow!("read_heat configuration lock poisoned"))?;
    *effective = Some((crate::service::agent_config_path(), configured));
    Ok(configured)
}

pub fn effective() -> Result<Option<bool>> {
    let path = crate::service::agent_config_path();
    let effective = EFFECTIVE.lock().map_err(|_| anyhow::anyhow!("read_heat configuration lock poisoned"))?;
    if let Some((loaded_path, value)) = effective.as_ref() {
        if loaded_path == &path {
            return Ok(*value);
        }
    }
    drop(effective);
    reload()
}

/// Configuration observed inside this process; Core routing separately reports scoring.
pub fn receipt() -> Result<Value> {
    let configured = configured()?;
    let loaded = effective()?;
    Ok(serde_json::json!({
        "configured": configured,
        "loaded": loaded,
        "effective": loaded.unwrap_or(true),
        "default": true,
        "pending_reload": configured != loaded,
    }))
}

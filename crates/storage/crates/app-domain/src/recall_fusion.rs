//! Host-owned persistent recall settings. Environment overrides remain per request.
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

pub const MODES: &[&str] = &["legacy", "attention", "attention_anchor", "auto"];
pub const NUMERIC: &[(&str, f64)] = &[
    ("fusion_alpha", 0.20),
    ("fusion_beta", 0.25),
    ("fusion_temperature", 1.0),
    ("fusion_gate_recency", 0.02),
    ("fusion_gate_recency_temporal", 1.0),
    ("fusion_gate_hot", 0.10),
    ("fusion_gate_tree", 0.02),
    ("fusion_temporal_alpha", 0.15),
];

pub fn defaults() -> Map<String, Value> {
    let mut values = Map::new();
    values.insert("fusion".into(), json!("legacy"));
    for &(key, value) in NUMERIC {
        values.insert(key.into(), json!(value));
    }
    values
}

pub fn validate(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("recall_fusion must be an object")?;
    for (key, value) in object {
        if key == "fusion" {
            anyhow::ensure!(
                value.as_str().is_some_and(|mode| MODES.contains(&mode)),
                "fusion must be legacy, attention, attention_anchor or auto"
            );
        } else {
            anyhow::ensure!(
                NUMERIC.iter().any(|(name, _)| *name == key),
                "unknown recall_fusion setting {key}"
            );
            let number = value
                .as_f64()
                .with_context(|| format!("{key} must be a number"))?;
            let valid = if key == "fusion_temperature" {
                number > 0.0 && number <= 10.0
            } else {
                (0.0..=1.0).contains(&number)
            };
            anyhow::ensure!(
                number.is_finite() && valid && (key != "fusion_temperature" || number as f32 > 0.0),
                "invalid recall_fusion setting {key}"
            );
        }
    }
    let alpha = object
        .get("fusion_alpha")
        .and_then(Value::as_f64)
        .unwrap_or(0.20) as f32;
    let beta = object
        .get("fusion_beta")
        .and_then(Value::as_f64)
        .unwrap_or(0.25) as f32;
    anyhow::ensure!(
        alpha + beta <= 1.0,
        "fusion_alpha + fusion_beta must not exceed 1"
    );
    Ok(())
}

pub fn configured() -> Result<Value> {
    let path = crate::service::agent_config_path();
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(json!({})),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let config: Value = serde_json::from_slice(&bytes).context("invalid agent configuration")?;
    let object = config
        .as_object()
        .context("agent config must be an object")?;
    let configured = object
        .get("recall_fusion")
        .cloned()
        .unwrap_or_else(|| json!({}));
    validate(&configured)?;
    Ok(configured)
}

pub fn effective(configured: &Value) -> Result<Map<String, Value>> {
    validate(configured)?;
    let mut settings = crate::core_sdk::query_settings_from_env()?;
    for (key, default) in defaults() {
        settings
            .entry(key.clone())
            .or_insert_with(|| configured.get(&key).cloned().unwrap_or(default));
    }
    let fusion: Map<String, Value> = defaults()
        .keys()
        .filter_map(|key| settings.get(key).map(|value| (key.clone(), value.clone())))
        .collect();
    validate(&Value::Object(fusion))?;
    Ok(settings)
}

pub fn query_settings() -> Result<Map<String, Value>> {
    effective(&configured()?)
}

pub fn receipt() -> Result<Value> {
    let configured = configured()?;
    let settings = effective(&configured)?;
    let defaults = defaults();
    let effective: Map<String, Value> = defaults
        .keys()
        .filter_map(|key| settings.get(key).map(|value| (key.clone(), value.clone())))
        .collect();
    let overrides: Vec<String> = defaults
        .keys()
        .filter(|key| {
            let name = format!("RSRS_RECALL_{}", key.to_uppercase());
            crate::env::var_os(&name).is_some()
                || (key.as_str() == "fusion"
                    && crate::env::var("RSRS_RECALL_PROFILE").is_ok_and(|v| v == "legacy"))
        })
        .cloned()
        .collect();
    Ok(
        json!({"configured":configured,"effective":effective,"defaults":defaults,
        "overrides":overrides,"applies":"next_query"}),
    )
}

//! Defaults and validation for the host recall-settings form.
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

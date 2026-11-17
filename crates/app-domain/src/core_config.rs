//! Atomically installed query parameters; no host configuration or database writes.
use anyhow::{Context, Result};
use respire_protocol::core_config::{CoreConfigCandidate, CoreConfigReceipt};
use serde_json::{json, Map, Value};
use std::{path::PathBuf, sync::Mutex};

struct Applied {
    profile: PathBuf,
    revision: u64,
    candidate: CoreConfigCandidate,
}

static APPLIED: Mutex<Option<Applied>> = Mutex::new(None);

fn settings(candidate: &CoreConfigCandidate) -> Result<Map<String, Value>> {
    anyhow::ensure!(candidate.read_heat.is_null() || candidate.read_heat.is_boolean(),
        "read_heat must be true, false or null");
    let fusion = if candidate.recall_fusion.is_null() { json!({}) }
        else { candidate.recall_fusion.clone() };
    let mut settings = crate::recall_fusion::effective(&fusion)?;
    if let Some(value) = candidate.read_heat.as_bool() {
        settings.insert("read_heat".into(), json!(value));
    }
    Ok(settings)
}

fn receipt(candidate: CoreConfigCandidate, revision: u64, state: &str) -> Result<CoreConfigReceipt> {
    let settings = settings(&candidate)?;
    let capabilities: Value = crate::core_sdk::execute("capabilities", Value::Null)?;
    for capability in ["read_heat_contract", "recall_fusion_contract"] {
        anyhow::ensure!(capabilities[capability].as_u64() == Some(1),
            "Core SDK requires {capability} 1; install the paired SDK/Runtime version");
    }
    let fusion: Map<String, Value> = crate::recall_fusion::defaults().keys()
        .filter_map(|key| settings.get(key).map(|value| (key.clone(), value.clone())))
        .collect();
    Ok(CoreConfigReceipt {
        state: state.into(), revision, candidate,
        effective: json!({"read_heat":settings.get("read_heat").and_then(Value::as_bool).unwrap_or(true),
            "recall_fusion":fusion}),
        capabilities: json!({"read_heat_contract":capabilities["read_heat_contract"],
            "recall_fusion_contract":capabilities["recall_fusion_contract"]}),
        applies: "next_query".into(),
    })
}

pub fn validate(candidate: CoreConfigCandidate) -> Result<CoreConfigReceipt> {
    receipt(candidate, revision()?, "validated")
}

pub fn revision() -> Result<u64> {
    let applied = APPLIED.lock().map_err(|_| anyhow::anyhow!("core configuration lock poisoned"))?;
    Ok(applied.as_ref().filter(|state| state.profile == crate::service::data_dir())
        .map_or(0, |state| state.revision))
}

pub fn apply(candidate: CoreConfigCandidate, expected_revision: u64) -> Result<CoreConfigReceipt> {
    // Complete every fallible check and build the receipt before changing query state.
    let mut receipt = receipt(candidate.clone(), expected_revision, "applied")?;
    let profile = crate::service::data_dir();
    let mut applied = APPLIED.lock().map_err(|_| anyhow::anyhow!("core configuration lock poisoned"))?;
    let revision = applied.as_ref().filter(|state| state.profile == profile)
        .map_or(0, |state| state.revision);
    anyhow::ensure!(revision == expected_revision, "core configuration revision changed");
    receipt.revision = revision.checked_add(1).context("core configuration revision exhausted")?;
    *applied = Some(Applied { profile, revision: receipt.revision, candidate });
    Ok(receipt)
}

pub fn active() -> Result<Option<CoreConfigCandidate>> {
    let applied = APPLIED.lock().map_err(|_| anyhow::anyhow!("core configuration lock poisoned"))?;
    Ok(applied.as_ref().filter(|state| state.profile == crate::service::data_dir())
        .map(|state| state.candidate.clone()))
}

pub fn query_settings() -> Result<Map<String, Value>> {
    if let Some(candidate) = active()? { return settings(&candidate); }
    let mut settings = crate::recall_fusion::query_settings()?;
    if let Some(read_heat) = crate::read_heat::effective()? {
        settings.insert("read_heat".into(), json!(read_heat));
    }
    Ok(settings)
}

pub fn read() -> Result<CoreConfigReceipt> {
    let candidate = match active()? {
        Some(candidate) => candidate,
        None => CoreConfigCandidate {
            read_heat: json!(crate::read_heat::effective()?),
            recall_fusion: crate::recall_fusion::configured()?,
        },
    };
    receipt(candidate, revision()?, "current")
}

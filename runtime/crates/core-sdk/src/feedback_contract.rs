//! Public optional feedback wire contract, checked before every native call.
use anyhow::{Context, Result};
use serde_json::Value;

pub(crate) fn requested(payload: &Value) -> Result<bool> {
    let Some(feedback) = payload
        .get("query_settings")
        .and_then(|settings| settings.get("feedback"))
    else {
        return Ok(false);
    };
    if feedback.is_null() {
        return Ok(false);
    }
    let object = feedback
        .as_object()
        .context("feedback settings must be an object or null")?;
    anyhow::ensure!(
        object
            .keys()
            .all(|key| matches!(key.as_str(), "enabled" | "good" | "bad" | "bad_penalty")),
        "unknown feedback setting"
    );
    for name in ["enabled", "bad_penalty"] {
        if let Some(value) = object.get(name) {
            anyhow::ensure!(value.is_boolean(), "feedback switches must be booleans");
        }
    }
    for name in ["good", "bad"] {
        if let Some(value) = object.get(name) {
            let counts = value
                .as_object()
                .context("feedback counts must be an object")?;
            anyhow::ensure!(
                counts.values().all(|count| count.as_u64().is_some()),
                "feedback counts must be nonnegative u64 integers"
            );
        }
    }
    Ok(object
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}
pub(crate) fn require(contract: Option<u64>) -> Result<()> {
    anyhow::ensure!(contract==Some(1),"enabled feedback requires Core SDK feedback contract 1; install the paired SDK/CLI version");
    Ok(())
}
pub(crate) fn validate(payload: &Value, contract: Option<u64>) -> Result<bool> {
    let enabled = requested(payload)?;
    if enabled {
        require(contract)?;
    }
    Ok(enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn explicit_requests_require_exact_capability_and_disabled_retains_compatibility() -> Result<()>
    {
        for contract in [None, Some(0), Some(2)] {
            assert!(validate(
                &json!({"query_settings":{"feedback":{"enabled":true}}}),
                contract
            )
            .is_err());
            assert!(!validate(
                &json!({"query_settings":{"feedback":{"enabled":false}}}),
                contract
            )?);
            assert!(!validate(
                &json!({"query_settings":{"feedback":null}}),
                contract
            )?);
        }
        assert!(validate(
            &json!({"query_settings":{"feedback":{"enabled":true,"good":{"id":1},"bad":{},"bad_penalty":true}}}),
            Some(1)
        )?);
        Ok(())
    }
    #[test]
    fn malformed_explicit_feedback_is_never_silently_ignored() {
        for feedback in [
            json!({"enabled":"false"}),
            json!({"enabled":true,"good":{"id":-1}}),
            json!({"bad":{"id":"1"}}),
            json!({"unknown":true}),
            json!("enabled"),
        ] {
            assert!(validate(&json!({"query_settings":{"feedback":feedback}}), Some(1)).is_err());
        }
    }
}

//! Credentials travel only over an inherited private control pipe or authenticated loopback unlock.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const CREDENTIAL_SCHEMA_V: u32 = 1;
pub const RUNTIME_UNLOCK_SCHEMA_V2: u32 = 2;

// Deliberately no Debug: these frames can contain private keys and passwords.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    pub credential_request: u32,
    pub id: String,
    pub service: String,
    pub account: String,
    pub backend: String,
    pub operation: CredentialOperation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CredentialOperation {
    Read,
    ReadConfigured,
    Write(String),
    Delete,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialReply {
    pub credential_reply: u32,
    pub id: String,
    pub result: Result<Option<String>, CredentialError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CredentialError {
    NoEntry,
    Ambiguous,
    BadEncoding,
    Invalid,
    Unavailable,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("host credential operation failed")
    }
}

impl std::error::Error for CredentialError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnlock {
    pub schema_version: u32,
    pub profile: PathBuf,
    pub session_sha256: String,
    pub instance_id: String,
    pub generation: u64,
    pub super_password: Option<String>,
    pub login_password: Option<String>,
    #[serde(default)]
    pub legacy_secret: Option<String>,
    #[serde(default)]
    pub provider_credentials: Vec<ProvidedCredential>,
}

// Deliberately no Debug: unlock messages and snapshots contain secrets.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnlockV2 {
    pub schema_version: u32,
    pub profile: PathBuf,
    pub session_sha256: String,
    pub instance_id: String,
    pub generation: u64,
    pub super_password: Option<String>,
    pub login_password: Option<String>,
    pub legacy_secret: Option<String>,
    pub provider_update: ProviderCredentialUpdate,
}

/// Required V2 outcome for all optional provider credentials, authenticated with the session.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderCredentialUpdate {
    /// Complete snapshot, including an explicitly verified empty snapshot. Never a patch.
    Replace { credentials: Vec<ProvidedCredential> },
    /// Retain the previous snapshot but revoke every provider read until a complete replacement.
    /// Only these public codes cross the boundary; host error text may contain private data.
    Unavailable { code: ProviderUnavailableCode },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderUnavailableCode {
    AccessDenied,
    PlatformFailure,
    BackendUnavailable,
    InvalidConfiguration,
    Ambiguous,
    BadEncoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderCredentialStatus {
    NotLoaded,
    Ready,
    Unavailable { code: ProviderUnavailableCode },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnlockReceipt {
    pub schema_version: u32,
    pub store_ready: bool,
    pub provider_status: ProviderCredentialStatus,
}

pub enum RuntimeUnlockRequest {
    V1(RuntimeUnlock),
    V2(RuntimeUnlockV2),
}

impl RuntimeUnlockRequest {
    pub fn schema_version(&self) -> u32 {
        match self {
            Self::V1(input) => input.schema_version,
            Self::V2(input) => input.schema_version,
        }
    }
}

pub fn parse_runtime_unlock(bytes: &[u8]) -> Result<RuntimeUnlockRequest, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    match value.get("schema_version").and_then(serde_json::Value::as_u64) {
        Some(1) => serde_json::from_slice(bytes).map(RuntimeUnlockRequest::V1),
        Some(2) => serde_json::from_slice(bytes).map(RuntimeUnlockRequest::V2),
        _ => Err(<serde_json::Error as serde::de::Error>::custom("unsupported runtime unlock schema")),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidedCredential {
    pub service: String,
    pub account: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> serde_json::Value {
        serde_json::json!({"schema_version":2,"profile":"/fixture","session_sha256":"digest",
            "instance_id":"instance","generation":1,
            "provider_update":{"kind":"unavailable","code":"access_denied"}})
    }

    #[test]
    fn unlock_v2_requires_explicit_provider_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let valid = message();
        assert!(matches!(parse_runtime_unlock(&serde_json::to_vec(&valid)?)?, RuntimeUnlockRequest::V2(_)));
        for update in [serde_json::Value::Null, serde_json::json!({}),
            serde_json::json!({"kind":"replace"}),
            serde_json::json!({"kind":"unavailable"}),
            serde_json::json!({"kind":"unavailable","code":"private arbitrary text"}),
            serde_json::json!({"kind":"unavailable","code":"access_denied","credentials":[]}),
            serde_json::json!({"kind":"replace","credentials":[],"code":"access_denied"})] {
            let mut invalid = valid.clone();
            invalid["provider_update"] = update;
            assert!(parse_runtime_unlock(&serde_json::to_vec(&invalid)?).is_err());
        }
        for field in ["schema_version", "provider_update", "profile", "session_sha256", "instance_id", "generation"] {
            let mut invalid = valid.clone();
            invalid.as_object_mut().ok_or("message must be an object")?.remove(field);
            assert!(parse_runtime_unlock(&serde_json::to_vec(&invalid)?).is_err());
        }
        let mut replace = valid;
        replace["provider_update"] = serde_json::json!({"kind":"replace","credentials":[]});
        assert!(parse_runtime_unlock(&serde_json::to_vec(&replace)?).is_ok());
        Ok(())
    }

    #[test]
    fn unlock_v1_stays_distinct_and_versions_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut v1 = message();
        v1["schema_version"] = serde_json::json!(1);
        v1.as_object_mut().ok_or("message must be an object")?.remove("provider_update");
        match parse_runtime_unlock(&serde_json::to_vec(&v1)?)? {
            RuntimeUnlockRequest::V1(input) => assert!(input.provider_credentials.is_empty()),
            _ => panic!("V1 request was reinterpreted"),
        }
        for version in [serde_json::json!(0), serde_json::json!(3), serde_json::json!("2"), serde_json::Value::Null] {
            let mut invalid = message();
            invalid["schema_version"] = version;
            assert!(parse_runtime_unlock(&serde_json::to_vec(&invalid)?).is_err());
        }
        let duplicate = br#"{"schema_version":2,"schema_version":1,"profile":"/fixture","session_sha256":"digest","instance_id":"instance","generation":1}"#;
        assert!(parse_runtime_unlock(duplicate).is_err());
        let mut mixed = message();
        mixed["provider_credentials"] = serde_json::json!([]);
        assert!(parse_runtime_unlock(&serde_json::to_vec(&mixed)?).is_err());
        Ok(())
    }
}

//! Credentials travel only over an inherited private control pipe or authenticated loopback unlock.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const CREDENTIAL_SCHEMA_V: u32 = 1;

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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidedCredential {
    pub service: String,
    pub account: String,
    pub value: String,
}

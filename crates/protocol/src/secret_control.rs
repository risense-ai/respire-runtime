//! Secret-bearing results are exclusive to the inherited private control channel.
//! Never persist these results as operation receipts or include them in logs.

use serde::{Deserialize, Serialize};

use crate::{ControlBinding, HostAuthIdentity};

pub const HOST_SECRET_SCHEMA_V: u32 = 1;
pub const HOST_SECRET_READ_METHOD: &str = "control.secret.read";
pub const HOST_KEYS_EXPORT_READ_METHOD: &str = "control.keys_export.read";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSecretReadParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub reveal: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeysExportReadParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSecretSession {
    pub has_session: bool,
    pub user: String,
    pub addr: String,
    pub has_token: bool,
    pub secret_masked: String,
    pub has_local_keys: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSecretReadResult {
    pub session: HostSecretSession,
    pub secret: Option<String>,
    pub five: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeysExportReadResult {
    pub version: i64,
    pub user: String,
    pub body: String,
    pub legacy_warning: bool,
}

//! Fixed identity reads on the inherited private control channel.

use serde::{Deserialize, Serialize};

use crate::{ControlBinding, HostAuthIdentity};

pub const HOST_IDENTITY_SCHEMA_V: u32 = 1;
pub const HOST_IDENTITY_SESSION_LIST_METHOD: &str = "control.identity.session_list";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentitySessionListParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
}

/// Preserve the server's session-list details without logging or journaling them.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentitySessionListResult {
    pub details: serde_json::Value,
}

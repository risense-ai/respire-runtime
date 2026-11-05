//! Fixed identity mutations on the inherited, authenticated control channel.
use serde::{Deserialize, Serialize};
use crate::{ControlBinding, HostAuthIdentity};

pub const HOST_IDENTITY_WRITE_SCHEMA_V: u32 = 1;
pub const HOST_IDENTITY_LOGOUT_METHOD: &str = "control.identity.logout";
pub const HOST_IDENTITY_SESSION_REVOKE_METHOD: &str = "control.identity.session_revoke";
pub const HOST_IDENTITY_WRITE_RESULT_METHOD: &str = "control.identity.write_result";

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostIdentityWriteOperation {
    Logout { full: bool },
    SessionRevoke { session_id: String },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentityWriteParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    /// Current launch identity; this may differ after the owned mutation.
    pub identity: HostAuthIdentity,
    /// Immutable initial identity, included in the original operation fingerprint.
    pub source_identity: HostAuthIdentity,
    pub operation: HostIdentityWriteOperation,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostIdentityWriteOutcome { Pending, Unknown, Committed }

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSessionRevokeResult {
    pub revoked: bool,
    pub session_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentityWriteResult {
    pub operation_id: String,
    pub fingerprint: String,
    pub operation: HostIdentityWriteOperation,
    pub outcome: HostIdentityWriteOutcome,
    pub path: std::path::PathBuf,
    pub session_found: bool,
    pub session_sha256: Option<String>,
    pub identity: HostAuthIdentity,
    pub revoke: Option<HostSessionRevokeResult>,
}

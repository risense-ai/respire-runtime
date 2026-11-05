//! Space membership operations are available only on inherited private control.
use serde::{Deserialize, Serialize};
use crate::{ControlBinding, HostAuthIdentity};

pub const HOST_SPACE_SCHEMA_V: u32 = 1;
pub const HOST_SPACE_INVITE_METHOD: &str = "control.space.invite";
pub const HOST_SPACE_JOIN_METHOD: &str = "control.space.join";
pub const HOST_SPACE_KICK_METHOD: &str = "control.space.kick";
pub const HOST_SPACE_RESULT_METHOD: &str = "control.space.result";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostSpaceOperation {
    Invite { note: Option<String>, readonly: bool },
    Join { invite_sha256: String, space: String, addr: String, user: String, readonly: bool },
    Kick { session_id: Option<String>, all: bool },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpaceParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub source_identity: HostAuthIdentity,
    pub operation: HostSpaceOperation,
    /// Supplemental secret; never persist this field in host recovery metadata.
    pub invite_code: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSpaceOutcome { Pending, Unknown, Committed, Rejected }

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSpaceKickState { Queued, RemotePending, Revoked, Absent, Rejected, Unknown }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpaceKickItem {
    pub session_id: String,
    pub state: HostSpaceKickState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpaceResult {
    pub operation_id: String,
    pub fingerprint: String,
    pub profile: std::path::PathBuf,
    pub identity: HostAuthIdentity,
    pub operation: HostSpaceOperation,
    pub outcome: HostSpaceOutcome,
    /// The invite code is a secret private response, never a public progress item.
    pub invite_code: Option<String>,
    pub session_id: Option<String>,
    pub target_profile: Option<std::path::PathBuf>,
    pub target_account_id: Option<String>,
    pub target_session_sha256: Option<String>,
    pub kick: Vec<HostSpaceKickItem>,
    pub remaining: Option<usize>,
}

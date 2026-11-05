//! Fixed key operations; secret inputs/results use only the inherited channel.
use serde::{Deserialize, Serialize};
use crate::{ControlBinding, HostAuthIdentity};

pub const HOST_KEY_SCHEMA_V: u32 = 1;
pub const HOST_KEY_SUPER_RESET_METHOD: &str = "control.key.super_reset";
pub const HOST_KEY_RESULT_METHOD: &str = "control.key.result";
pub const HOST_KEY_ROLLBACK_METHOD: &str = "control.key.rollback";

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostKeyOperation {
    SuperReset { addr: Option<String> },
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeyInput {
    pub password: Option<String>,
    pub super_password: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeyParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub source_identity: HostAuthIdentity,
    pub operation: HostKeyOperation,
    #[serde(default)]
    pub input: Option<HostKeyInput>,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyOutcome { Pending, AwaitingInput, Unknown, Committed, RolledBack }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeyResult {
    pub operation_id: String,
    pub fingerprint: String,
    pub operation: HostKeyOperation,
    pub outcome: HostKeyOutcome,
    pub source_profile: std::path::PathBuf,
    pub target_profile: Option<std::path::PathBuf>,
    pub account_id: Option<String>,
    pub session_sha256: Option<String>,
    pub identity: HostAuthIdentity,
    pub required_inputs: Vec<String>,
    /// Generated only by super-reset. Never copy to public progress or a ledger.
    pub super_password: Option<String>,
}

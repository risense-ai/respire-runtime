//! Private, one-request host control. Scope fields are constraints, not credentials.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const HOST_CONTROL_SCHEMA_V: u32 = 1;
pub const HOST_CONTROL_MAX_FRAME_BYTES: usize = 64 * 1024;

/// The serving grant's identity checks are also used by the inherited channel.
/// This value never authorizes a public HTTP request or a detached process.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostControlLaunchGrant {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub nonce: String,
    pub instance_id: String,
    pub installation_root: PathBuf,
    pub installation_id: String,
    pub profile: PathBuf,
    pub account_id: String,
    pub sync_generation: usize,
    pub image_path: PathBuf,
    pub image_sha256: String,
    pub supervisor_pid: u32,
    pub supervisor_birth: String,
    pub managed_id: Option<String>,
    pub registration_sha256: Option<String>,
    pub maintenance: Option<HostControlMaintenanceBinding>,
    pub port: u16,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostControlMaintenanceBinding {
    pub marker_sha256: String,
    pub coordinator_id: String,
    pub controller_pid: u32,
    pub controller_birth: String,
    pub issuer_cli_version: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostControlOperation {
    MemoryRevision,
    ModelInstallPlan,
    ModelInstallVerify,
}

impl HostControlOperation {
    pub fn method(self) -> &'static str {
        match self {
            Self::MemoryRevision => "control.memory_revision",
            Self::ModelInstallPlan => "control.model_install_plan",
            Self::ModelInstallVerify => "control.model_install_verify",
        }
    }
}

/// Checked against the grant already consumed from the inherited channel.
/// None asserts absence of an account; it never means "accept any account".
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBinding {
    pub installation_root: PathBuf,
    pub profile: PathBuf,
    pub launch_id: String,
    pub expected_account_id: Option<String>,
}

/// The sole JSON argument of the fixed control RPC method, never CLI argv.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostControlParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
}

/// Auth-only identity. A valid unbound session needs its committed keygen receipt.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostAuthIdentity {
    Absent,
    Unbound { operation_id: String, session_sha256: String },
    Bound { account_id: String, session_sha256: String },
}

/// Operation ID and idempotency key are mandatory in the outer RpcRequest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthKeygenParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub force: bool,
}

/// Fixed private recovery only; no business operation or credential is accepted.
pub const HOST_LOGIN_RECOVERY_STATUS_METHOD: &str = "control.auth.recovery_status";
pub const HOST_LOGIN_RECOVERY_METHOD: &str = "control.auth.recover_legacy";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostLoginRecoveryParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostLoginRecoveryState {
    Clear,
    LegacyPending,
    OperationPending,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostLoginRecoveryResult {
    pub state: HostLoginRecoveryState,
    pub recovered: bool,
}

pub const HOST_AUTH_SCHEMA_V: u32 = 1;
pub const HOST_AUTH_KEYGEN_METHOD: &str = "control.auth.keygen";
pub const HOST_AUTH_RESULT_METHOD: &str = "control.auth.result";

pub const HOST_AUTH_REGISTER_METHOD: &str = "control.auth.register";
pub const HOST_AUTH_LOGIN_METHOD: &str = "control.auth.login";
pub const HOST_AUTH_ACCOUNT_RESULT_METHOD: &str = "control.auth.account_result";
pub const HOST_AUTH_ACCOUNT_COMPLETE_METHOD: &str = "control.auth.account_complete";
pub const HOST_AUTH_ACCOUNT_ROLLBACK_METHOD: &str = "control.auth.account_rollback";

/// Secrets travel only in the inherited request frame. Never log this value.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthRegisterParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub addr: String,
    pub user: String,
    pub password: String,
    pub super_password: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostAuthAuthorization {
    Password { password: String, totp: Option<String> },
    Browser { token: String, session_id: Option<String> },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthLoginParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub addr: String,
    pub user: String,
    pub authorization: HostAuthAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub super_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<HostAuthLoginContinuation>,
}

/// Supplemental input travels on the inherited channel; never journal this object.
/// Reuse the original operation/key; these fields cannot replace its bound intent.
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthLoginContinuation {
    pub legacy_password: Option<String>,
    pub account_secret: Option<String>,
    pub source_secret: Option<String>,
    pub secret_key: Option<String>,
    pub new_super: Option<String>,
    // Admission intent: repeat these unchanged on every continuation of this operation.
    #[serde(default)]
    pub migrate_local: bool,
    #[serde(default)]
    pub migrate_vault: bool,
    #[serde(default)]
    pub offer_local_merge: bool,
    // Supplemental confirmation of the destination already offered by Runtime.
    pub merge_local: Option<bool>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthLoginStatus {
    pub required_inputs: Vec<String>,
    pub user: String,
    pub addr: String,
    pub dir: Option<PathBuf>,
    pub super_issued: Option<String>,
    pub import: Option<serde_json::Value>,
    pub sync: Option<serde_json::Value>,
}

/// Query/finalization uses the original outer operation ID and idempotency key.
/// Identity describes the current selected profile, not a caller-supplied proof.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthAccountParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostAuthAccountOutcome {
    AwaitingInput,
    AwaitingVerification,
    Committed,
    RolledBack,
    Unknown,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthAccountResult {
    pub operation_id: String,
    pub outcome: HostAuthAccountOutcome,
    pub source_profile: PathBuf,
    pub target_profile: Option<PathBuf>,
    pub account_id: Option<String>,
    pub session_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub super_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<HostAuthLoginStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostAuthOutcome {
    Committed,
    RolledBack,
    Unknown,
}

/// The recovery code is returned only over the inherited private response pipe.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthResult {
    pub operation_id: String,
    pub outcome: HostAuthOutcome,
    pub session_sha256: Option<String>,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub super_password: Option<String>,
}

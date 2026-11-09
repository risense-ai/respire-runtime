//! Account operations on the inherited channel, after the parent's grant checks.
use anyhow::{ensure, Context, Result};
use respire_app::login_transaction::{self, AuthOwnership};
use respire_protocol::host_control::*;
use respire_protocol::RpcRequest;
use sha2::{Digest, Sha256};

pub(crate) enum AccountRequest {
    Register(HostAuthRegisterParams),
    Login(HostAuthLoginParams),
    Result(HostAuthAccountParams),
    Complete(HostAuthAccountParams),
    Rollback(HostAuthAccountParams),
}

impl AccountRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V
            && canonical(&request.id) && request.operation_id.as_deref().is_some_and(canonical)
            && request.idempotency_key.as_ref().is_some_and(|key| !key.is_empty() && key.len() <= 128
                && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)))
            && request.args.len() == 1 && request.scope.is_none() && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none() && request.lifecycle.is_none(), "invalid account control request");
        let (parsed, schema) = match request.method.as_str() {
            HOST_AUTH_REGISTER_METHOD => {
                let params: HostAuthRegisterParams = serde_json::from_str(&request.args[0]).context("invalid register parameters")?;
                let schema = params.schema_version;
                (Self::Register(params), schema)
            }
            HOST_AUTH_LOGIN_METHOD => {
                let params: HostAuthLoginParams = serde_json::from_str(&request.args[0]).context("invalid login parameters")?;
                let schema = params.schema_version;
                (Self::Login(params), schema)
            }
            HOST_AUTH_ACCOUNT_RESULT_METHOD | HOST_AUTH_ACCOUNT_COMPLETE_METHOD | HOST_AUTH_ACCOUNT_ROLLBACK_METHOD => {
                let params: HostAuthAccountParams = serde_json::from_str(&request.args[0]).context("invalid account receipt parameters")?;
                let schema = params.schema_version;
                let parsed = match request.method.as_str() {
                    HOST_AUTH_ACCOUNT_RESULT_METHOD => Self::Result(params),
                    HOST_AUTH_ACCOUNT_COMPLETE_METHOD => Self::Complete(params),
                    _ => Self::Rollback(params),
                };
                (parsed, schema)
            }
            _ => anyhow::bail!("unsupported account control method"),
        };
        ensure!(schema == HOST_AUTH_SCHEMA_V, "unsupported account control schema");
        Ok(parsed)
    }

    pub(crate) fn binding(&self) -> &ControlBinding {
        match self {
            Self::Register(params) => &params.binding,
            Self::Login(params) => &params.binding,
            Self::Result(params) | Self::Complete(params) | Self::Rollback(params) => &params.binding,
        }
    }

    pub(crate) fn identity(&self) -> &HostAuthIdentity {
        match self {
            Self::Register(params) => &params.identity,
            Self::Login(params) => &params.identity,
            Self::Result(params) | Self::Complete(params) | Self::Rollback(params) => &params.identity,
        }
    }

    /// Only completion may run alongside the receipt's verified target Runtime.
    pub(crate) fn is_completion(&self) -> bool { matches!(self, Self::Complete(_)) }

    /// The caller has consumed the launch grant, checked its maintenance phase,
    /// bound these parameters to it, and installed the private parent watcher.
    pub(crate) fn execute(&self, request: &RpcRequest, ownership: Option<AuthOwnership>) -> Result<HostAuthAccountResult> {
        let id = request.operation_id.as_deref().context("account operation ID is missing")?;
        let key = request.idempotency_key.as_deref().context("account idempotency key is missing")?;
        if let Self::Complete(params) = self {
            ensure!(ownership.is_none(), "completion must not hold the running target's library lock");
            return login_transaction::control_account_complete(&params.binding.installation_root,
                &params.binding.profile, &params.identity, id, key, verify_target_runtime);
        }
        let ownership = ownership.context("account library ownership is missing")?;
        match self {
            Self::Register(params) => login_transaction::control_register(&ownership, id, key, params),
            Self::Login(params) => login_transaction::control_login(&ownership, id, key, params),
            Self::Result(params) => login_transaction::control_account_result(&ownership, &params.identity, id, key),
            Self::Rollback(params) => login_transaction::control_account_rollback(ownership, &params.identity, id, key),
            Self::Complete(_) => anyhow::bail!("completion cannot use account library ownership"),
        }
    }
}

pub(crate) fn verify_target_runtime(receipt: &HostAuthAccountResult) -> Result<()> {
    let target = receipt.target_profile.as_ref().context("receipt target is missing")?;
    let account = receipt.account_id.as_deref().context("receipt account is missing")?;
    verify_ready_target_runtime(target, account)
}

pub(crate) fn verify_ready_target_runtime(target: &std::path::Path, account: &str) -> Result<()> {
    verified_target_health(target, account).map(|_| ())
}

fn verified_target_health(target: &std::path::Path, account: &str) -> Result<respire_commands::net_rpc::Health> {
    crate::startup_identity::verify_account_completion_authority()?;
    let health = respire_commands::net_rpc::health()?;
    respire_commands::net_rpc::request_scope(&health)?;
    ensure!(health.store_ready && health.account_id == account
        && std::fs::canonicalize(&health.data_dir)? == target.canonicalize()?
        && health.runtime_version == env!("CARGO_PKG_VERSION"), "target Runtime is not ready for this account receipt");
    let process = respire_commands::net_rpc::runtime_process_identity(health.pid)?;
    ensure!(respire_commands::net_rpc::instance_is_running(&health)?,
        "target Runtime birth identity mismatch");
    let image = std::env::current_exe()?.canonicalize()?;
    ensure!(std::fs::canonicalize(&process.executable)? == image
        && std::fs::canonicalize(&health.image_path)? == image,
        "target Runtime process identity mismatch");
    let mut file = std::fs::File::open(&image)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    ensure!(format!("{:x}", hasher.finalize()) == health.image_sha256, "target Runtime image digest mismatch");
    ensure!(respire_commands::net_rpc::runtime_process_identity(health.pid)? == process,
        "target Runtime changed during verification");
    ensure!(respire_commands::net_rpc::instance_is_running(&health)?,
        "target Runtime birth identity changed during verification");
    crate::startup_identity::verify_account_completion_authority()?;
    Ok(health)
}

pub(crate) fn verify_keygen_target(target: &std::path::Path, identity: &HostAuthIdentity)
    -> Result<HostKeygenRuntimeIdentity> {
    ensure!(matches!(identity, HostAuthIdentity::Unbound { .. }), "keygen handoff must remain unbound");
    let root = respire_app::service::main_data_dir().canonicalize()?;
    login_transaction::verify_auth_identity(&root, target, identity)?;
    let account = format!("{:x}", Sha256::digest(target.display().to_string().as_bytes()));
    let snapshot = |health: respire_commands::net_rpc::Health| -> Result<HostKeygenRuntimeIdentity> {
        ensure!(std::fs::canonicalize(&health.installation_root)? == root
            && !health.installation_id.is_empty() && !health.instance_id.is_empty()
            && !health.process_start_id.is_empty(), "keygen serving identity incomplete");
        Ok(HostKeygenRuntimeIdentity { pid: health.pid, process_start_id: health.process_start_id,
            instance_id: health.instance_id, generation: health.generation, image_path: health.image_path,
            image_sha256: health.image_sha256, installation_root: health.installation_root,
            installation_id: health.installation_id, profile: health.data_dir, account_id: health.account_id })
    };
    let before = snapshot(verified_target_health(target, &account)?)?;
    login_transaction::verify_auth_identity(&root, target, identity)?;
    let after = snapshot(verified_target_health(target, &account)?)?;
    ensure!(before == after, "keygen serving actor changed during handoff");
    login_transaction::verify_auth_identity(&root, target, identity)?;
    Ok(after)
}

pub(crate) fn recovery_request(request: &RpcRequest) -> Result<respire_protocol::host_control::HostLoginRecoveryParams> {
    use respire_protocol::host_control::{HostLoginRecoveryParams,
        HOST_AUTH_SCHEMA_V, HOST_LOGIN_RECOVERY_METHOD, HOST_LOGIN_RECOVERY_STATUS_METHOD};
    let id = uuid::Uuid::parse_str(&request.id)?;
    anyhow::ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V
        && id.get_version_num() == 4 && id.to_string() == request.id
        && [HOST_LOGIN_RECOVERY_METHOD, HOST_LOGIN_RECOVERY_STATUS_METHOD].contains(&request.method.as_str())
        && request.args.len() == 1 && request.scope.is_none()
        && request.operation_id.is_none() && request.idempotency_key.is_none()
        && request.parent_operation_id.is_none() && request.queue_wait_ms.is_none()
        && request.lifecycle.is_none(), "invalid fixed login recovery request");
    let params: HostLoginRecoveryParams = serde_json::from_str(&request.args[0])?;
    anyhow::ensure!(params.schema_version == HOST_AUTH_SCHEMA_V, "unsupported login recovery schema");
    Ok(params)
}

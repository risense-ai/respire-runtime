//! Fixed key adapters. The dispatcher owns launch binding and parent supervision.
use anyhow::{ensure, Context, Result};
use respire_app::login_transaction::{self, AuthOwnership};
use respire_protocol::key_control::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};

pub(crate) enum KeyRequest {
    Execute(HostKeyParams), Result(HostKeyParams), Rollback(HostKeyParams), Complete(HostKeyParams),
}

impl KeyRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V && canonical(&request.id)
            && request.operation_id.as_deref().is_some_and(canonical)
            && request.idempotency_key.as_ref().is_some_and(|key| !key.is_empty() && key.len() <= 128
                && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)))
            && request.args.len() == 1 && request.scope.is_none() && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none() && request.lifecycle.is_none(), "invalid private key request");
        let params: HostKeyParams = serde_json::from_str(&request.args[0])
            .map_err(|_| anyhow::anyhow!("invalid private key parameters"))?;
        ensure!(params.schema_version == HOST_KEY_SCHEMA_V, "unsupported key control schema");
        Ok(match request.method.as_str() {
            HOST_KEY_SUPER_RESET_METHOD if matches!(params.operation, HostKeyOperation::SuperReset { .. }) => Self::Execute(params),
            HOST_KEY_FIVEKEYS_METHOD if matches!(params.operation, HostKeyOperation::Fivekeys { .. }) => Self::Execute(params),
            HOST_KEY_COMPLETE_METHOD if matches!(params.operation, HostKeyOperation::Fivekeys { .. }) => Self::Complete(params),
            HOST_KEY_RESULT_METHOD => Self::Result(params),
            HOST_KEY_ROLLBACK_METHOD => Self::Rollback(params),
            _ => anyhow::bail!("unsupported key method or mismatched operation"),
        })
    }

    fn params(&self) -> &HostKeyParams {
        match self { Self::Execute(params) | Self::Result(params) | Self::Rollback(params) | Self::Complete(params) => params }
    }
    pub(crate) fn binding(&self) -> &ControlBinding { &self.params().binding }
    pub(crate) fn identity(&self) -> &HostAuthIdentity { &self.params().identity }
    pub(crate) fn verify_result(&self, request: &RpcRequest, result: &HostKeyResult) -> Result<()> {
        let params = self.params();
        let (root, profile) = (respire_app::service::main_data_dir().canonicalize()?,
            respire_app::service::data_dir().canonicalize()?);
        login_transaction::verify_key_receipt(&root, &profile,
            request.operation_id.as_deref().context("key operation ID missing")?,
            request.idempotency_key.as_deref().context("key idempotency key missing")?, params, result)?;
        crate::startup_identity::verify_key_control_result(&params.binding, &params.identity, result)
    }
    /// All actions require exact Paused ownership and the parent's private watcher.
    pub(crate) fn execute(&self, request: &RpcRequest, ownership: AuthOwnership) -> Result<HostKeyResult> {
        let id = request.operation_id.as_deref().context("key operation ID missing")?;
        let key = request.idempotency_key.as_deref().context("key idempotency key missing")?;
        match self {
            Self::Execute(params) => login_transaction::control_key(&ownership, id, key, params),
            Self::Result(params) => login_transaction::control_key_result(&ownership, id, key, params),
            Self::Rollback(params) => login_transaction::control_key_rollback(ownership, id, key, params),
            Self::Complete(_) => anyhow::bail!("key completion requires the trusted live Runtime verifier"),
        }
    }

    pub(crate) fn is_complete(&self) -> bool { matches!(self, Self::Complete(_)) }

    /// Completion must use the parent's Verified producer, not Paused ownership.
    pub(crate) fn complete(&self, request: &RpcRequest,
        verify_runtime: impl FnMut(&HostKeyResult) -> Result<()>) -> Result<HostKeyResult> {
        let Self::Complete(params) = self else { anyhow::bail!("not a key completion request"); };
        login_transaction::control_key_complete(&params.binding.installation_root, &params.binding.profile,
            request.operation_id.as_deref().context("key operation ID missing")?,
            request.idempotency_key.as_deref().context("key idempotency key missing")?, params, verify_runtime)
    }
}

pub(crate) fn verify_target_runtime(receipt: &HostKeyResult) -> Result<()> {
    use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult};
    ensure!(receipt.verification_required && receipt.outcome == HostKeyOutcome::Pending
        && matches!(receipt.operation, HostKeyOperation::Fivekeys { .. }), "fivekeys candidate is not awaiting verification");
    // Reuse the account verifier's live image, birth, scope and store checks;
    // this local view is not an account admission or a public business receipt.
    crate::auth_control::verify_target_runtime(&HostAuthAccountResult {
        operation_id: receipt.operation_id.clone(), outcome: HostAuthAccountOutcome::AwaitingVerification,
        source_profile: receipt.source_profile.clone(), target_profile: receipt.target_profile.clone(),
        account_id: receipt.account_id.clone(), session_sha256: receipt.session_sha256.clone(),
        super_password: None, login: None,
    })
}

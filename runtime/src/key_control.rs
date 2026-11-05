//! Fixed key adapters. The dispatcher owns launch binding and parent supervision.
use anyhow::{ensure, Context, Result};
use respire_app::login_transaction::{self, AuthOwnership};
use respire_protocol::key_control::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};

pub(crate) enum KeyRequest {
    Execute(HostKeyParams), Result(HostKeyParams), Rollback(HostKeyParams),
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
            HOST_KEY_RESULT_METHOD => Self::Result(params),
            HOST_KEY_ROLLBACK_METHOD => Self::Rollback(params),
            _ => anyhow::bail!("unsupported key method or mismatched operation"),
        })
    }

    fn params(&self) -> &HostKeyParams {
        match self { Self::Execute(params) | Self::Result(params) | Self::Rollback(params) => params }
    }
    pub(crate) fn binding(&self) -> &ControlBinding { &self.params().binding }
    pub(crate) fn identity(&self) -> &HostAuthIdentity { &self.params().identity }
    /// All actions require exact Paused ownership and the parent's private watcher.
    pub(crate) fn execute(&self, request: &RpcRequest, ownership: AuthOwnership) -> Result<HostKeyResult> {
        let id = request.operation_id.as_deref().context("key operation ID missing")?;
        let key = request.idempotency_key.as_deref().context("key idempotency key missing")?;
        match self {
            Self::Execute(params) => login_transaction::control_key(&ownership, id, key, params),
            Self::Result(params) => login_transaction::control_key_result(&ownership, id, key, params),
            Self::Rollback(params) => login_transaction::control_key_rollback(ownership, id, key, params),
        }
    }
}

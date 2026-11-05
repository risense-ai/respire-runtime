//! Fixed private writes. The dispatcher owns grant/Paused/parent-pipe checks.
use anyhow::{ensure, Context, Result};
use respire_app::login_transaction::{self, AuthOwnership};
use respire_protocol::identity_write_control::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};

pub(crate) struct IdentityWriteRequest {
    params: HostIdentityWriteParams,
    query_only: bool,
}

impl IdentityWriteRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        ensure!(request.v == respire_commands::rpc_client::PROTOCOL_V && canonical(&request.id)
            && request.operation_id.as_deref().is_some_and(canonical)
            && request.idempotency_key.as_ref().is_some_and(|key| !key.is_empty() && key.len() <= 128
                && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)))
            && request.args.len() == 1 && request.scope.is_none() && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none() && request.lifecycle.is_none(), "invalid private identity write request");
        let params: HostIdentityWriteParams = serde_json::from_str(&request.args[0])
            .map_err(|_| anyhow::anyhow!("invalid identity write parameters"))?;
        ensure!(params.schema_version == HOST_IDENTITY_WRITE_SCHEMA_V, "unsupported identity write schema");
        let query_only = request.method == HOST_IDENTITY_WRITE_RESULT_METHOD;
        ensure!(query_only || matches!((&*request.method, &params.operation),
            (HOST_IDENTITY_LOGOUT_METHOD, HostIdentityWriteOperation::Logout { .. })
            | (HOST_IDENTITY_SESSION_REVOKE_METHOD, HostIdentityWriteOperation::SessionRevoke { .. })),
            "identity write method and operation mismatch");
        if let HostIdentityWriteOperation::SessionRevoke { session_id } = &params.operation {
            uuid::Uuid::parse_str(session_id).context("session id must be a full UUID")?;
        }
        Ok(Self { params, query_only })
    }

    pub(crate) fn binding(&self) -> &ControlBinding { &self.params.binding }
    pub(crate) fn identity(&self) -> &HostAuthIdentity { &self.params.identity }

    /// The owned original transaction is the only allowed recovery while Paused.
    /// Do not call generic keygen/login rollback before this operation/result.
    pub(crate) fn execute(&self, request: &RpcRequest, ownership: &AuthOwnership) -> Result<HostIdentityWriteResult> {
        let id = request.operation_id.as_deref().context("identity operation ID is missing")?;
        let key = request.idempotency_key.as_deref().context("identity idempotency key is missing")?;
        if self.query_only {
            login_transaction::control_identity_write_result(ownership, id, key, &self.params)
        } else {
            login_transaction::control_identity_write(ownership, id, key, &self.params)
        }
    }
}

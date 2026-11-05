//! Fixed private membership operations; never exposed by the HTTP router.
use anyhow::{ensure, Context, Result};
use respire_app::login_transaction::{self, AuthOwnership};
use respire_protocol::space_control::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};

pub(crate) struct SpaceRequest { params: HostSpaceParams, query_only: bool }

impl SpaceRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V && canonical(&request.id)
            && request.operation_id.as_deref().is_some_and(canonical)
            && request.idempotency_key.as_ref().is_some_and(|key| !key.is_empty() && key.len() <= 128
                && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)))
            && request.args.len() == 1 && request.scope.is_none() && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none() && request.lifecycle.is_none(), "invalid private space request");
        let params: HostSpaceParams = serde_json::from_str(&request.args[0]).map_err(|_| anyhow::anyhow!("invalid private space parameters"))?;
        let query_only = request.method == HOST_SPACE_RESULT_METHOD;
        ensure!(params.schema_version == HOST_SPACE_SCHEMA_V && (query_only || matches!((&*request.method,&params.operation),
            (HOST_SPACE_INVITE_METHOD,HostSpaceOperation::Invite { .. })
            | (HOST_SPACE_JOIN_METHOD,HostSpaceOperation::Join { .. })
            | (HOST_SPACE_KICK_METHOD,HostSpaceOperation::Kick { .. }))), "space method and operation mismatch");
        ensure!(params.invite_code.is_none() || matches!(params.operation,HostSpaceOperation::Join { .. }), "unexpected space secret input");
        Ok(Self { params, query_only })
    }
    pub(crate) fn binding(&self) -> &ControlBinding { &self.params.binding }
    pub(crate) fn identity(&self) -> &HostAuthIdentity { &self.params.identity }
    pub(crate) fn execute(&self, request: &RpcRequest, ownership: &AuthOwnership) -> Result<HostSpaceResult> {
        login_transaction::control_space(ownership,
            request.operation_id.as_deref().context("space operation ID missing")?,
            request.idempotency_key.as_deref().context("space key missing")?,&self.params,self.query_only)
    }
}

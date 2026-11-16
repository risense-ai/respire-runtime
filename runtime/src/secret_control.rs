//! Fixed private reads. The caller owns authorization, scope locks and parent watching.
//! No store is opened, no session is changed, and no result is journaled here.

use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};
use respire_protocol::secret_control::{
    HostSecretReadParams, HostSecretReadResult, HostSecretSession,
    HOST_SECRET_READ_METHOD, HOST_SECRET_SCHEMA_V,
};

pub(crate) struct SecretRequest(HostSecretReadParams);

impl SecretRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&request.id).context("invalid secret read request ID")?;
        anyhow::ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V
            && id.get_version_num() == 4 && id.to_string() == request.id
            && request.args.len() == 1 && request.scope.is_none()
            && request.operation_id.is_none() && request.idempotency_key.is_none()
            && request.parent_operation_id.is_none() && request.queue_wait_ms.is_none()
            && request.lifecycle.is_none(), "invalid private secret read request");
        anyhow::ensure!(request.method == HOST_SECRET_READ_METHOD,
            "unsupported private secret read method; key export belongs to the host");
        let params: HostSecretReadParams = serde_json::from_str(&request.args[0])
            .map_err(|_| anyhow::anyhow!("invalid secret read parameters"))?;
        anyhow::ensure!(params.schema_version == HOST_SECRET_SCHEMA_V,
            "unsupported private secret read schema");
        Ok(Self(params))
    }

    pub(crate) fn binding(&self) -> &ControlBinding {
        &self.0.binding
    }

    pub(crate) fn identity(&self) -> &HostAuthIdentity {
        &self.0.identity
    }

    /// Call only with ownership held and identity checked before/after execution.
    /// The returned envelope goes directly to the private response, never progress/receipts.
    pub(crate) fn execute(
        &self,
        _ownership: &respire_app::login_transaction::AuthOwnership,
    ) -> Result<ResultEnvelope> {
        let details = serde_json::to_value(read_secret(self.0.reveal)?)
            .map_err(|_| anyhow::anyhow!("private secret read result encoding failed"))?;
        let mut envelope = ResultEnvelope::new("secret-read", Status::Ok, serde_json::json!({}), Vec::new());
        envelope.details = details;
        Ok(envelope)
    }
}

fn read_secret(reveal: bool) -> Result<HostSecretReadResult> {
    let info = respire_app::service::session_info();
    let (secret, five) = if info.has_session && reveal {
        (Some(respire_app::service::session_secret_full()?), Some(respire_app::service::session_five_keys()?))
    } else { (None, None) };
    Ok(HostSecretReadResult {
        session: HostSecretSession { has_session: info.has_session, user: info.user, addr: info.addr,
            has_token: info.has_token, secret_masked: info.secret_masked, has_local_keys: info.has_local_keys },
        secret, five,
    })
}

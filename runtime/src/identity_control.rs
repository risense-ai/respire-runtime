//! Fixed private identity reads; the dispatcher must first consume the launch
//! grant, require Paused maintenance and install the parent watcher.

use std::io::Read;

use anyhow::{ensure, Context, Result};
use respire_app::login_transaction::{self, AuthOwnership};
use respire_protocol::identity_control::{
    HostIdentitySessionListParams, HostIdentitySessionListResult,
    HOST_IDENTITY_SCHEMA_V, HOST_IDENTITY_SESSION_LIST_METHOD,
};
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};

pub(crate) enum IdentityRequest {
    SessionList(HostIdentitySessionListParams),
}

impl IdentityRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&request.id).context("invalid identity read request ID")?;
        ensure!(request.v == respire_commands::rpc_client::PROTOCOL_V
            && id.get_version_num() == 4 && id.to_string() == request.id
            && request.method == HOST_IDENTITY_SESSION_LIST_METHOD
            && request.args.len() == 1 && request.scope.is_none()
            && request.operation_id.is_none() && request.idempotency_key.is_none()
            && request.parent_operation_id.is_none() && request.queue_wait_ms.is_none()
            && request.lifecycle.is_none(), "invalid private identity read request");
        let params: HostIdentitySessionListParams = serde_json::from_str(&request.args[0])
            .map_err(|_| anyhow::anyhow!("invalid session list parameters"))?;
        ensure!(params.schema_version == HOST_IDENTITY_SCHEMA_V, "unsupported identity read schema");
        Ok(Self::SessionList(params))
    }

    pub(crate) fn binding(&self) -> &ControlBinding {
        match self { Self::SessionList(params) => &params.binding }
    }

    pub(crate) fn identity(&self) -> &HostAuthIdentity {
        match self { Self::SessionList(params) => &params.identity }
    }

    /// Ownership must be acquired by the dispatcher for this exact binding.
    /// Only the inherited response may receive these details, never progress.
    pub(crate) fn execute(&self, _ownership: &AuthOwnership) -> Result<HostIdentitySessionListResult> {
        self.verify_selection()?;
        let result = match self { Self::SessionList(_) => read_sessions() };
        self.verify_selection()?;
        result.map(|details| HostIdentitySessionListResult { details })
    }

    fn verify_selection(&self) -> Result<()> {
        let binding = self.binding();
        ensure!(binding.installation_root == respire_app::service::main_data_dir().canonicalize()?
            && binding.profile == respire_app::service::data_dir().canonicalize()?,
            "identity read selection mismatch");
        ensure!(!login_transaction::auth_recovery_pending()?, "finish auth recovery before listing sessions");
        login_transaction::verify_auth_identity(&binding.installation_root, &binding.profile, self.identity())
    }
}

fn read_sessions() -> Result<serde_json::Value> {
    let data = respire_app::auth::read_session_json()?;
    let addr = data["addr"].as_str().filter(|value| !value.is_empty())
        .context("cloud address is not configured")?;
    let token = data["token"].as_str().filter(|value| !value.is_empty())
        .context("not logged in")?;
    // The legacy sessions helper has no timeout. Reuse its selected-session
    // credentials and endpoint, but bound this private control read explicitly.
    let response = ureq::AgentBuilder::new().redirects(0)
        .timeout(std::time::Duration::from_secs(30)).build()
        .get(&format!("{}/api/self/sessions", addr.trim().trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {token}"))
        .call().map_err(|_| anyhow::anyhow!("session list request failed"))?;
    let limit = respire_protocol::host_control::HOST_CONTROL_MAX_FRAME_BYTES;
    let mut bytes = Vec::new();
    response.into_reader().take(limit as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("session list response read failed"))?;
    ensure!(bytes.len() <= limit, "session list exceeds the private control frame limit");
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid session list response"))
}

//! Fixed private profile removal; the dispatcher supplies actual Paused authority.
use anyhow::Result;
use respire_protocol::profile_maintenance::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};
use sha2::{Digest, Sha256};

pub(crate) struct ProfileRemoveRequest {
    params: HostProfileRemoveParams,
    query_only: bool,
}

impl ProfileRemoveRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        anyhow::ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V
            && canonical(&request.id) && request.args.len() == 1
            && request.scope.is_none() && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none() && request.lifecycle.is_none(),
            "invalid private profile removal request");
        let params: HostProfileRemoveParams = serde_json::from_str(&request.args[0])?;
        let original = &params.original;
        anyhow::ensure!(params.schema_version == HOST_PROFILE_SCHEMA_V
            && original.schema_version == HOST_PROFILE_SCHEMA_V
            && canonical(&original.operation_id) && original.key == original.operation_id
            && !original.name.is_empty() && original.name != "main"
            && original.name.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
            && request.operation_id.as_deref() == Some(original.operation_id.as_str())
            && request.idempotency_key.as_deref() == Some(original.key.as_str())
            && params.binding.installation_root == original.installation_root
            && params.binding.profile == original.profile && params.identity == original.identity
            && original.fingerprint == format!("{:x}", Sha256::digest(original.fingerprint_bytes()?)),
            "private profile removal changed its original binding");
        let query_only = match request.method.as_str() {
            HOST_PROFILE_REMOVE_METHOD => false,
            HOST_PROFILE_RESULT_METHOD => true,
            _ => anyhow::bail!("unsupported private profile removal method"),
        };
        Ok(Self { params, query_only })
    }

    pub(crate) fn binding(&self) -> &ControlBinding { &self.params.binding }
    pub(crate) fn identity(&self) -> &HostAuthIdentity { &self.params.identity }

    /// The caller keeps root/profile/journal ownership and checks authority before
    /// and after this call, exactly as for the other auth maintenance adapters.
    pub(crate) fn execute(&self, ownership: &respire_app::login_transaction::AuthOwnership)
        -> Result<HostProfileRemoveResult> {
        respire_app::login_transaction::control_profile_remove(
            ownership, &self.params.original, self.query_only)
    }
}

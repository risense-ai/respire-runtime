//! Fixed profile migration; the dispatcher supplies Paused authorization and parent watching.
use anyhow::{Context, Result};
use respire_protocol::migration_control::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};
use sha2::{Digest, Sha256};

pub(crate) struct MigrationRequest {
    params: HostMigrationParams,
    query_only: bool,
}

impl MigrationRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        anyhow::ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V && canonical(&request.id)
            && request.args.len() == 1 && request.scope.is_none() && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none() && request.lifecycle.is_none(), "invalid private migration request");
        let params: HostMigrationParams = serde_json::from_str(&request.args[0])
            .map_err(|_| anyhow::anyhow!("invalid private migration parameters"))?;
        let original = &params.original;
        anyhow::ensure!(params.schema_version == HOST_MIGRATION_SCHEMA_V
            && original.schema_version == HOST_MIGRATION_SCHEMA_V && canonical(&original.operation_id)
            && original.key == original.operation_id
            && request.operation_id.as_deref() == Some(original.operation_id.as_str())
            && request.idempotency_key.as_deref() == Some(original.key.as_str())
            && params.binding.installation_root == original.installation_root
            && params.binding.profile == original.profile && params.identity == original.identity
            && original.fingerprint == format!("{:x}", Sha256::digest(original.fingerprint_bytes()?)),
            "migration request changed its original binding");
        let query_only = match request.method.as_str() {
            HOST_MIGRATION_PROFILE_METHOD => false,
            HOST_MIGRATION_RESULT_METHOD => true,
            _ => anyhow::bail!("unsupported private migration method"),
        };
        Ok(Self { params, query_only })
    }

    pub(crate) fn binding(&self) -> &ControlBinding { &self.params.binding }
    pub(crate) fn identity(&self) -> &HostAuthIdentity { &self.params.identity }
    pub(crate) fn original(&self) -> &HostMigrationOperation { &self.params.original }

    pub(crate) fn execute(&self, ownership: &respire_app::login_transaction::AuthOwnership)
        -> Result<HostMigrationResult> {
        anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
            "finish authentication recovery before migrating a legacy profile");
        // Do not recover or modify another account operation's journal.
        respire_app::migration::control_migrate_profile(ownership, &self.params.original, self.query_only)
            .context("query the original migration operation before retrying")
    }
}

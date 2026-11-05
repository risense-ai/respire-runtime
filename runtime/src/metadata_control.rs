//! Fixed metadata maintenance and offline configuration reads; no business RPC admission.
use std::time::Duration;
use anyhow::{Context, Result};
use respire_protocol::metadata_control::*;
use respire_protocol::{ControlBinding, RpcRequest};
use sha2::{Digest, Sha256};

fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}

fn check_request(request: &RpcRequest) -> Result<()> {
    anyhow::ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V && canonical_id(&request.id)
        && request.args.len() == 1 && request.scope.is_none() && request.parent_operation_id.is_none()
        && request.queue_wait_ms.is_none() && request.lifecycle.is_none(), "invalid private metadata request");
    Ok(())
}

pub(crate) struct MetadataChange {
    params: HostMetadataParams,
    query_only: bool,
}

impl MetadataChange {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        check_request(request)?;
        let params: HostMetadataParams = serde_json::from_str(&request.args[0])
            .map_err(|_| anyhow::anyhow!("invalid private metadata parameters"))?;
        let original = &params.original;
        original.intent.validate().map_err(anyhow::Error::msg)?;
        anyhow::ensure!(params.schema_version == HOST_METADATA_SCHEMA_V
            && original.schema_version == HOST_METADATA_SCHEMA_V && canonical_id(&original.operation_id)
            && original.key == original.operation_id
            && request.operation_id.as_deref() == Some(original.operation_id.as_str())
            && request.idempotency_key.as_deref() == Some(original.key.as_str())
            && params.binding.installation_root == original.installation_root
            && params.binding.profile == original.profile && params.identity == original.identity
            && original.fingerprint == format!("{:x}", Sha256::digest(original.fingerprint_bytes()?)),
            "metadata original operation binding changed");
        let query_only = request.method == HOST_METADATA_RESULT_METHOD;
        anyhow::ensure!(query_only || matches!((&original.intent, request.method.as_str()),
            (HostMetadataIntent::Enable { .. }, HOST_METADATA_ENABLE_METHOD)
            | (HostMetadataIntent::Disable, HOST_METADATA_DISABLE_METHOD)), "metadata method differs from its intent");
        Ok(Self { params, query_only })
    }

    pub(crate) fn binding(&self) -> &ControlBinding { &self.params.binding }
    pub(crate) fn identity(&self) -> &HostMetadataIdentity { &self.params.identity }

    pub(crate) fn execute(&self) -> Result<HostMetadataResult> {
        let original = &self.params.original;
        let root = respire_app::service::main_data_dir().canonicalize()?;
        let profile = respire_app::service::data_dir().canonicalize()?;
        anyhow::ensure!(root == original.installation_root && profile == original.profile,
            "metadata selected profile changed");
        // Same root-before-profile order as account maintenance, without touching its journal.
        let root_lock = respire_app::lock::LibraryLock::acquire(&root, Duration::from_secs(15))?;
        let profile_lock = if root == profile { None } else {
            Some(respire_app::lock::LibraryLock::acquire(&profile, Duration::from_secs(15))?)
        };
        let lock = profile_lock.as_ref().unwrap_or(&root_lock);
        crate::startup_identity::verify_metadata_control_binding(&self.params.binding, &original.identity)?;
        anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
            "finish authentication recovery before metadata maintenance");
        let existing = respire_app::metadata_gate::control_result(&profile, lock, original)?;
        if self.query_only || existing.outcome == HostMetadataOutcome::Committed { return Ok(existing); }
        respire_app::service::ensure_writable()?;
        anyhow::ensure!(!respire_app::service::off_mode(), "restore normal service before changing the metadata gate");
        match &original.intent {
            HostMetadataIntent::Enable { mode, .. } => {
                let deployment = if mode == "isolated" { respire_app::metadata_gate::Deployment::Isolated }
                    else { respire_app::metadata_gate::Deployment::ControlledWriters {
                        all_writers_upgraded: true, old_clients_disconnected: true, offline_writes_reconciled: true } };
                respire_app::metadata_gate::require_support()?;
                let keys = respire_commands::engine::build_session()?;
                let account = respire_app::service::session_user_of_dir(&profile);
                respire_app::metadata_gate::enable_control(&profile, lock, &account, &keys, deployment, original)?;
            }
            HostMetadataIntent::Disable => respire_app::metadata_gate::disable_control(&profile, lock, original)?,
        }
        crate::startup_identity::verify_metadata_control_binding(&self.params.binding, &original.identity)?;
        respire_app::metadata_gate::control_result(&profile, lock, original)
    }
}

pub(crate) struct OfflineReadRequest {
    pub(crate) kind: HostOfflineRead,
    params: HostMetadataReadParams,
}

impl OfflineReadRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        check_request(request)?;
        anyhow::ensure!(request.operation_id.is_none() && request.idempotency_key.is_none(),
            "offline reads do not accept operation IDs or keys");
        let kind = match request.method.as_str() {
            HOST_METADATA_STATUS_METHOD => HostOfflineRead::MetadataStatus,
            HOST_AGENT_CONFIG_READ_METHOD => HostOfflineRead::AgentConfigRead,
            HOST_SNAPSHOT_PREFLIGHT_METHOD => HostOfflineRead::SnapshotPreflight,
            _ => anyhow::bail!("unsupported offline configuration read"),
        };
        let params: HostMetadataReadParams = serde_json::from_str(&request.args[0])
            .context("invalid offline read parameters")?;
        anyhow::ensure!(params.schema_version == HOST_METADATA_SCHEMA_V, "invalid offline read schema");
        Ok(Self { kind, params })
    }

    pub(crate) fn binding(&self) -> &ControlBinding { &self.params.binding }

    pub(crate) fn execute(&self) -> Result<respire_commands::output::ResultEnvelope> {
        match self.kind {
            HostOfflineRead::MetadataStatus => respire_commands::engine::metadata_status_result(),
            HostOfflineRead::AgentConfigRead => respire_commands::engine::agent_config_read_result(),
            HostOfflineRead::SnapshotPreflight => {
                respire_app::snapshot::ensure_no_incomplete_restore(&self.params.binding.profile)?;
                Ok(respire_commands::output::ResultEnvelope::new("snapshot-preflight",
                    respire_commands::output::Status::Ok, serde_json::json!({"allowed":true}), Vec::new()))
            }
        }
    }
}

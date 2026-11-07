//! Fixed metadata changes and offline reads; all store/key work stays in Runtime.
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::metadata_control::*;
use respire_protocol::{ControlBinding, HostControlLaunchGrant, RpcRequest, RpcResponse};
use serde::{Deserialize, Serialize};

/// Original intent and owner metadata only; the gate receipt is held by Runtime SQLite.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    operation: HostMetadataOperation,
    token: String,
    coordinator: String,
    was_serving: bool,
    store_ready: bool,
    sent: bool,
    finished: bool,
}

fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}

fn read_original(path: &Path) -> Result<Option<(Original, String)>> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(!metadata.file_type().is_symlink(), "metadata recovery path is a symlink");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "metadata recovery path is a reparse point");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 65536, "invalid metadata recovery metadata");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "metadata recovery metadata exceeds its bound");
    let original = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid metadata recovery metadata"))?;
    Ok(Some((original, super::hash(&bytes))))
}

pub(crate) fn control_metadata(command: &respire_commands::metadata::Command, direct: bool) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("metadata deployment configuration")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "metadata must own host maintenance");
    let intent = match command {
        respire_commands::metadata::Command::Enable { mode, deployment_review } => {
            let review = deployment_review.as_ref().map(|path| -> Result<MetadataDeploymentReview> {
                Ok(serde_json::from_slice(&std::fs::read(path)?)?)
            }).transpose()?;
            HostMetadataIntent::Enable { mode: mode.clone(), deployment_review: review }
        }
        respire_commands::metadata::Command::Disable => HostMetadataIntent::Disable,
        respire_commands::metadata::Command::Status => return control_offline_read(HostOfflineRead::MetadataStatus),
    };
    intent.validate().map_err(anyhow::Error::msg)?;
    let takeover = crate::runtime_policy::takeover_lock()?;
    if crate::runtime_fetch::read_manifest()?.is_none() {
        crate::runtime_fetch::download_and_install(None, None)?;
    }
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let identity = metadata_identity(&profile, super::hash)?;
    let mut operation = HostMetadataOperation { schema_version: HOST_METADATA_SCHEMA_V,
        operation_id: String::new(), key: String::new(), installation_root: root.clone(), profile: profile.clone(),
        identity, intent, fingerprint: String::new() };
    operation.fingerprint = super::hash(&operation.fingerprint_bytes()?);
    let path = root.join("runtime/autostart/metadata").join(format!("{}.json", super::hash(profile.display().to_string().as_bytes())));
    let saved = read_original(&path)?;
    let previous_digest = saved.as_ref().map(|(_, digest)| digest.clone());
    let saved = saved.filter(|(original, _)| !original.finished);
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "metadata has a recorded owner without verifiable health");
    anyhow::ensure!(!direct || owner.is_none(), "stop the local runtime before direct metadata configuration");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "metadata cannot identify the registered supervisor's owner");
    }
    let account_id = operation.identity.account_id.clone()
        .unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest, Some(&account_id))?;
    }
    let (mut original, mut digest, mut maintenance) = if let Some((original, digest)) = saved {
        operation.operation_id = original.operation.operation_id.clone();
        operation.key = original.operation.key.clone();
        anyhow::ensure!(operation == original.operation && canonical_id(&operation.operation_id)
            && operation.key == operation.operation_id && canonical_id(&original.token), "metadata recovery binding changed");
        let maintenance = super::lifecycle::resume_identity_write_maintenance(
            &root, &profile, &original.token, &original.coordinator)?;
        (original, digest, maintenance)
    } else {
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        let binding = maintenance.auth_launch_binding(&profile)?.context("metadata requires actual Paused maintenance")?;
        operation.operation_id = uuid::Uuid::new_v4().to_string();
        operation.key = operation.operation_id.clone();
        let original = Original { operation,
            token: super::lifecycle::current_boot_token().context("metadata maintenance token missing")?,
            coordinator: binding["coordinator_id"].as_str().context("metadata coordinator missing")?.to_owned(),
            was_serving: owner.is_some(), store_ready: owner.as_ref().is_some_and(|health| health.store_ready),
            sent: false, finished: false };
        let bytes = serde_json::to_vec(&original)?;
        anyhow::ensure!(bytes.len() <= 65536, "metadata review exceeds the private recovery record bound");
        super::private_write(&path, &bytes, previous_digest.as_deref())?;
        (original, super::hash(&bytes), maintenance)
    };
    let expected_identity = original.operation.identity.clone();
    let unchanged = || -> Result<()> {
        let (current_binary, current_manifest) = super::model_control::installed_model_runtime()?;
        let (current_root, current_profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(current_binary == binary && current_manifest.version == manifest.version
            && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
            && current_root.canonicalize()? == root && current_profile.canonicalize()? == profile
            && metadata_identity(&profile, super::hash)? == expected_identity, "metadata installation or selection changed");
        Ok(())
    };
    let mut finished = false;
    let result: Result<ResultEnvelope> = (|| {
        maintenance.auth_launch_binding(&profile)?.context("metadata lost its actual Paused grant")?;
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "metadata requires a drained Runtime");
        unchanged()?;
        let method = if original.sent { HOST_METADATA_RESULT_METHOD } else {
            original.sent = true;
            let bytes = serde_json::to_vec(&original)?;
            super::private_write(&path, &bytes, Some(&digest))?;
            digest = super::hash(&bytes);
            match &original.operation.intent {
                HostMetadataIntent::Enable { .. } => HOST_METADATA_ENABLE_METHOD,
                HostMetadataIntent::Disable => HOST_METADATA_DISABLE_METHOD,
            }
        };
        // A saved sent request always queries. A timeout never admits a replacement operation.
        let receipt = exchange(&takeover, &mut maintenance, &original.operation, method)?;
        if receipt.outcome == HostMetadataOutcome::Unknown {
            let mut envelope = ResultEnvelope::new("metadata", Status::Fail, serde_json::json!({"outcome":"unknown"}), Vec::new());
            envelope.details = serde_json::to_value(&receipt)?;
            envelope.actions.push(format!("repeat the same metadata command to query original operation {}; do not start another change",
                original.operation.operation_id));
            crate::set_exit_code(2);
            return Ok(envelope);
        }
        unchanged()?;
        let restore_owner = original.was_serving;
        let restore_store = original.store_ready;
        if restore_owner {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("original metadata owner did not resume")?;
            super::model_control::verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest, Some(&account_id))?;
            anyhow::ensure!(!restore_store || restored.store_ready, "restored metadata owner did not confirm its original store readiness");
        }
        unchanged()?;
        maintenance.finish()?;
        finished = true;
        original.finished = true;
        let envelope = metadata_result(&receipt)?;
        super::private_write(&path, &serde_json::to_vec(&original)?, Some(&digest))?;
        Ok(envelope)
    })();
    if !finished {
        maintenance.mark(super::lifecycle::Phase::Paused).map_err(|_| anyhow::anyhow!(
            "metadata_outcome_unknown operation_id={}; Paused publication failed; query the original operation before recovery",
            original.operation.operation_id))?;
    }
    result.map_err(|_| anyhow::anyhow!("metadata_outcome_unknown operation_id={}; repeat the same metadata command to query; no metadata was replayed", original.operation.operation_id))
}


fn exchange(takeover: &LibraryLock, maintenance: &mut super::lifecycle::Maintenance,
    original: &HostMetadataOperation, method: &str) -> Result<HostMetadataResult> {
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(root == original.installation_root && profile == original.profile
        && metadata_identity(&profile, super::hash)? == original.identity
        && takeover.protects(&root.join("runtime/takeover"))?, "metadata exchange selection or ownership changed");
    let maintenance = maintenance.auth_launch_binding(&profile)?
        .context("metadata exchange requires actual Paused maintenance")?;
    let registration = super::read_registration(&root)?;
    let managed_id = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped)
        .map(|config| config.id.as_str());
    let account = original.identity.account_id.clone()
        .unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let (grant, _) = super::prepare_grant_for_identity(&binary, &root, &profile, managed_id,
        crate::net_rpc::rpc_port(), &account, Some(maintenance))?;
    let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
    anyhow::ensure!(grant.image_path == binary && grant.image_sha256.eq_ignore_ascii_case(&manifest.sha256),
        "metadata exchange image changed");
    let params = HostMetadataParams { schema_version: HOST_METADATA_SCHEMA_V,
        binding: ControlBinding { installation_root: root, profile: profile.clone(),
            launch_id: grant.instance_id.clone(), expected_account_id: original.identity.account_id.clone() },
        identity: original.identity.clone(), original: original.clone() };
    let request = RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
        method: method.to_owned(), args: vec![serde_json::to_string(&params)?], scope: None,
        operation_id: Some(original.operation_id.clone()), idempotency_key: Some(original.key.clone()),
        parent_operation_id: None, queue_wait_ms: None, lifecycle: None };
    let envelope = super::exchange_control(&binary, &grant, &request, Instant::now() + Duration::from_secs(185),
        |response, pid| validate_response(response, &request, &profile, pid, original))?;
    serde_json::from_value(envelope.summary).map_err(|_| anyhow::anyhow!("invalid private metadata result"))
}

fn validate_response(response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path,
    pid: u32, original: &HostMetadataOperation) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
        && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
        && response.operation_id.as_deref() == Some(original.operation_id.as_str())
        && response.idempotency_key.as_deref() == Some(original.key.as_str()), "metadata response binding mismatch");
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(Path::new(directory).canonicalize()? == profile, "metadata response profile mismatch");
    }
    let envelope = response.envelope.context("private metadata envelope missing")?;
    anyhow::ensure!(envelope.command == "metadata-control" && envelope.details.is_null()
        && envelope.items.len() == 2 && envelope.errors.is_empty() && envelope.actions.is_empty()
        && envelope.related.is_empty(), "invalid private metadata envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value && if name == "control_ready" {
            matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "metadata readiness mismatch");
    }
    let receipt: HostMetadataResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid private metadata result"))?;
    anyhow::ensure!(receipt.original == *original && metadata_identity(profile, super::hash)? == original.identity,
        "metadata result changed its original intent or identity");
    if receipt.outcome == HostMetadataOutcome::Unknown {
        anyhow::ensure!(!response.ok && response.exit == 2 && response.code.as_deref() == Some("metadata_outcome_unknown")
            && response.error.is_none() && matches!(envelope.status, Status::Fail) && receipt.details.is_null(),
            "invalid unknown metadata result");
    } else {
        anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none()
            && matches!(envelope.status, Status::Ok), "invalid terminal metadata result");
        metadata_result(&receipt)?;
    }
    Ok(envelope)
}

fn metadata_result(receipt: &HostMetadataResult) -> Result<ResultEnvelope> {
    anyhow::ensure!(receipt.outcome == HostMetadataOutcome::Committed && receipt.details.is_object(),
        "metadata result is not a committed receipt");
    let enabled = matches!(&receipt.original.intent, HostMetadataIntent::Enable { .. });
    if let HostMetadataIntent::Enable { mode, deployment_review } = &receipt.original.intent {
        anyhow::ensure!(receipt.details["receipt"]["enabled"] == true
            && receipt.details["receipt"]["deployment"]["mode"].as_str() == Some(mode.as_str())
            && receipt.details["receipt"]["backup"].is_object()
            && receipt.details["deployment_review"] == serde_json::to_value(deployment_review)?
            && receipt.details["deployment_assurance"] == "operator_attestation_only"
            && receipt.details["old_client_access_enforced"] == false, "invalid metadata enable receipt");
    } else {
        anyhow::ensure!(receipt.details["enabled"] == false && receipt.details["metadata_retained"].is_boolean()
            && receipt.details["sync_isolation_retained"] == true
            && matches!(receipt.details["mode"].as_str(), Some("isolated" | "controlled_writers")),
            "invalid metadata disable receipt");
    }
    let mut envelope = ResultEnvelope::new("metadata", Status::Ok,
        serde_json::json!({"action":if enabled { "enabled" } else { "disabled" },"enabled":enabled}), Vec::new());
    envelope.details = receipt.details.clone();
    Ok(envelope)
}

/// One fixed private read; never takes maintenance, creates a directory, or starts serving.
pub(crate) fn control_offline_read(kind: HostOfflineRead) -> Result<ResultEnvelope> {
    offline_read(kind, false)
}

pub(crate) fn discover_legacy_snapshot() -> Result<Option<super::super::super::snapshot_control::LegacySnapshotDescriptor>> {
    let envelope = offline_read(HostOfflineRead::SnapshotPreflight, true)?;
    serde_json::from_value(envelope.summary["legacy_recovery"].clone())
        .context("invalid legacy snapshot descriptor")
}

fn offline_read(kind: HostOfflineRead, legacy_snapshot_discovery: bool) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("offline configuration read")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(),
        "offline configuration read cannot inherit a maintenance boot token");
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = metadata_status_path(&root)?;
    let profile = metadata_status_path(&profile)?;
    let identity = if kind == HostOfflineRead::SnapshotPreflight {
        HostMetadataIdentity { account_id: None, session_sha256: None }
    } else { metadata_identity(&profile, super::hash)? };
    let account = identity.account_id.clone()
        .unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let grant: HostControlLaunchGrant = serde_json::from_value(super::prepare_offline_read_grant(
        &binary, &root, &profile, crate::net_rpc::rpc_port(), &account, kind)?)?;
    anyhow::ensure!(grant.image_path == binary && grant.image_sha256.eq_ignore_ascii_case(&manifest.sha256)
        && (kind == HostOfflineRead::SnapshotPreflight || metadata_identity(&profile, super::hash)? == identity),
        "offline read image or identity changed");
    let params = HostMetadataReadParams { schema_version: HOST_METADATA_SCHEMA_V,
        binding: ControlBinding { installation_root: root.clone(), profile: profile.clone(),
            launch_id: grant.instance_id.clone(), expected_account_id: identity.account_id.clone() },
        legacy_snapshot_discovery };
    let request = RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
        method: kind.method().to_owned(), args: vec![serde_json::to_string(&params)?], scope: None,
        operation_id: None, idempotency_key: None, parent_operation_id: None, queue_wait_ms: None, lifecycle: None };
    let mut envelope = super::exchange_control(&binary, &grant, &request, Instant::now() + Duration::from_secs(185),
        |response, pid| {
            anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
                && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
                && response.operation_id.is_none() && response.idempotency_key.is_none(),
                "invalid fixed offline read response");
            if let Some(directory) = &response.data_dir {
                anyhow::ensure!(metadata_status_path(Path::new(directory))? == profile, "offline read profile mismatch");
            }
            if !response.ok {
                return offline_read_rejection(&response, kind);
            }
            let envelope = response.envelope.context("offline read envelope missing")?;
            anyhow::ensure!(response.exit == 0 && response.code.is_none() && response.error.is_none(),
                "invalid fixed offline read response");
            anyhow::ensure!(envelope.command == kind.command() && matches!(envelope.status, Status::Ok)
                && envelope.errors.is_empty() && envelope.actions.is_empty() && envelope.related.is_empty()
                && envelope.items.len() >= 2, "invalid offline read envelope");
            let split = envelope.items.len() - 2;
            let readiness = &envelope.items[split..];
            anyhow::ensure!(readiness[0].name == "control_ready" && readiness[0].value == "true"
                && matches!(readiness[0].status, Status::Ok)
                && readiness[1].name == "store_ready" && readiness[1].value == "false"
                && matches!(readiness[1].status, Status::Skip), "offline read cannot claim store readiness");
            match kind {
                HostOfflineRead::SnapshotPreflight => {
                    anyhow::ensure!(split == 0 && envelope.details.is_null(), "invalid snapshot preflight envelope");
                    if legacy_snapshot_discovery {
                        let summary = envelope.summary.as_object().context("snapshot discovery must be an object")?;
                        anyhow::ensure!(summary.len() == 2 && summary.get("allowed").is_some_and(serde_json::Value::is_boolean)
                            && summary.contains_key("legacy_recovery"), "invalid snapshot discovery result");
                        let descriptor: Option<super::super::super::snapshot_control::LegacySnapshotDescriptor> =
                            serde_json::from_value(summary["legacy_recovery"].clone())?;
                        if let Some(descriptor) = descriptor {
                            super::super::super::snapshot_control::validate_legacy_descriptor(&descriptor)?;
                        }
                    } else {
                        anyhow::ensure!(envelope.summary == serde_json::json!({"allowed":true})
                            || (envelope.summary["allowed"] == true && envelope.summary["legacy_recovery"].is_null()
                                && envelope.summary.as_object().is_some_and(|summary| summary.len() == 2)),
                            "snapshot preflight did not explicitly allow access");
                    }
                }
                HostOfflineRead::MetadataStatus => anyhow::ensure!(split == 0 && envelope.summary["action"] == "status"
                    && envelope.summary["enabled"].is_boolean() && envelope.summary["sdk_supported"].is_boolean()
                    && envelope.summary["enabled"] == envelope.details["enabled"]
                    && envelope.summary["mode"] == envelope.details["mode"]
                    && matches!(envelope.details["mode"].as_str(), Some("isolated" | "controlled_writers"))
                    && envelope.details["metadata_retained"].is_boolean()
                    && (envelope.details["backup"].is_null() || envelope.details["backup"].is_object()),
                    "invalid metadata status result"),
                HostOfflineRead::AgentConfigRead => {
                    let config = envelope.summary.as_object().context("agent configuration result must be an object")?;
                    anyhow::ensure!(envelope.details.is_null() && config.len() == split
                        && config.get("read_heat_runtime").is_some_and(serde_json::Value::is_object)
                        && config.get("recall_fusion_runtime").is_some_and(serde_json::Value::is_object)
                        && config.get("readonly").is_some_and(serde_json::Value::is_boolean)
                        && config.get("memory_off").is_some_and(serde_json::Value::is_boolean)
                        && config.get("workspace_mode").is_some_and(serde_json::Value::is_string),
                        "invalid agent configuration receipts");
                    for (key, value) in config {
                        anyhow::ensure!(envelope.items[..split].iter().filter(|item| item.name == *key
                            && matches!(item.status, Status::Ok) && item.value == value.to_string()).count() == 1,
                            "agent configuration row differs from its receipt");
                    }
                }
            }
            Ok(envelope)
        })?;
    let (current_binary, current_manifest) = super::model_control::installed_model_runtime()?;
    let (current_root, current_profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(current_binary == binary && current_manifest.version == manifest.version
        && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
        && metadata_status_path(&current_root)? == root && metadata_status_path(&current_profile)? == profile
        && (kind == HostOfflineRead::SnapshotPreflight || metadata_identity(&profile, super::hash)? == identity),
        "offline read selection or installation changed");
    // Preserve the existing public output; readiness belongs only to the private response.
    envelope.items.truncate(envelope.items.len() - 2);
    Ok(envelope)
}


fn offline_read_rejection(response: &RpcResponse<ResultEnvelope>, kind: HostOfflineRead) -> Result<ResultEnvelope> {
    let envelope = response.envelope.as_ref().context("offline read envelope missing")?;
    anyhow::ensure!(response.exit == 2 && envelope.command == kind.command()
        && matches!(envelope.status, Status::Fail) && envelope.summary == serde_json::json!({})
        && envelope.details.is_null() && envelope.actions.is_empty() && envelope.related.is_empty()
        && envelope.errors.len() == 1 && response.error.as_ref() == envelope.errors.first()
        && envelope.items.len() == 2
        && envelope.items[0].name == "control_ready" && envelope.items[0].value == "false"
        && matches!(envelope.items[0].status, Status::Fail)
        && envelope.items[1].name == "store_ready" && envelope.items[1].value == "false"
        && matches!(envelope.items[1].status, Status::Skip),
        "invalid fixed offline read rejection");
    // Only local fixed messages cross this boundary, never the Runtime diagnostic.
    let (code, message) = match response.code.as_deref() {
        Some("unauthorized") => ("unauthorized", "offline read launch or parent authorization failed"),
        Some("scope_mismatch") => ("scope_mismatch", "offline read binding changed or does not match"),
        Some("snapshot_preflight_blocked") if kind == HostOfflineRead::SnapshotPreflight =>
            ("snapshot_preflight_blocked", "snapshot validation blocked access; inspect snapshot recovery"),
        Some("offline_read_unavailable") if kind != HostOfflineRead::SnapshotPreflight =>
            ("offline_read_unavailable", "offline configuration read is unavailable"),
        Some("control_unavailable") => ("control_unavailable", "offline read controller is unavailable"),
        _ => anyhow::bail!("invalid fixed offline read rejection code"),
    };
    anyhow::bail!("Runtime rejected fixed offline read ({code}): {message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn offline_read_rejections_keep_fixed_codes_and_reject_malformed_envelopes() -> Result<()> {
        use respire_commands::output::{Item, ResultEnvelope, Status};
        use respire_protocol::metadata_control::HostOfflineRead;
        use respire_protocol::RpcResponse;

        let diagnostic = "synthetic-private-diagnostic";
        let fixture = |kind: HostOfflineRead, code: &str| -> Result<serde_json::Value> {
            let mut envelope = ResultEnvelope::new(kind.command(), Status::Fail, json!({}), vec![
                Item::new("control_ready", Status::Fail, "false"),
                Item::new("store_ready", Status::Skip, "false"),
            ]);
            envelope.errors.push(diagnostic.into());
            Ok(json!({"v":1,"id":"offline-read-test","ok":false,"exit":2,"bin":"rsrs-runtime",
                "code":code,"error":diagnostic,"envelope":serde_json::to_value(envelope)?}))
        };
        let classify = |value: serde_json::Value, kind: HostOfflineRead| -> Result<String> {
            let response: RpcResponse<ResultEnvelope> = serde_json::from_value(value)?;
            match super::offline_read_rejection(&response, kind) {
                Err(error) => Ok(error.to_string()),
                Ok(_) => anyhow::bail!("Runtime rejection was accepted as success"),
            }
        };
        for (kind, code) in [
            (HostOfflineRead::SnapshotPreflight, "unauthorized"),
            (HostOfflineRead::SnapshotPreflight, "scope_mismatch"),
            (HostOfflineRead::SnapshotPreflight, "snapshot_preflight_blocked"),
            (HostOfflineRead::MetadataStatus, "offline_read_unavailable"),
            (HostOfflineRead::SnapshotPreflight, "control_unavailable"),
        ] {
            let message = classify(fixture(kind, code)?, kind)?;
            assert!(message.starts_with(&format!("Runtime rejected fixed offline read ({code}): ")));
            assert!(!message.contains(diagnostic));
        }
        let kind = HostOfflineRead::SnapshotPreflight;
        let base = fixture(kind, "unauthorized")?;
        for (pointer, value) in [
            ("/exit", json!(0)),
            ("/error", json!("different-private-diagnostic")),
            ("/envelope/command", json!("other-command")),
            ("/envelope/status", json!("ok")),
            ("/envelope/summary", json!({"allowed":true})),
            ("/envelope/details", json!({})),
            ("/envelope/actions", json!(["unexpected-action"])),
            ("/envelope/errors", json!([])),
            ("/envelope/items", json!([])),
            ("/envelope/items/0/name", json!("unexpected")),
            ("/envelope/items/0/status", json!("ok")),
            ("/envelope/items/0/value", json!("true")),
            ("/envelope/items/1/name", json!("unexpected")),
            ("/envelope/items/1/status", json!("ok")),
            ("/envelope/items/1/value", json!("true")),
        ] {
            let mut changed = base.clone();
            *changed.pointer_mut(pointer).context("rejection fixture field missing")? = value;
            assert_eq!(classify(changed, kind)?, "invalid fixed offline read rejection");
        }
        assert_eq!(classify(fixture(kind, "unrecognized_code")?, kind)?,
            "invalid fixed offline read rejection code");
        for (kind, code) in [
            (HostOfflineRead::SnapshotPreflight, "offline_read_unavailable"),
            (HostOfflineRead::MetadataStatus, "snapshot_preflight_blocked"),
        ] {
            assert_eq!(classify(fixture(kind, code)?, kind)?, "invalid fixed offline read rejection code");
        }
        Ok(())
    }
}

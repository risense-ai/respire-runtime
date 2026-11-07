//! One reviewed agent setting, using the existing maintenance marker and config CAS.
use std::time::{Duration, Instant};
use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::config_control::*;
use respire_protocol::metadata_control::metadata_identity;
use respire_protocol::{ControlBinding, HostControlLaunchGrant, RpcRequest};

pub(crate) fn control_agent_config(kv: &str) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("agent configuration changes")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "agent config must own maintenance");
    let (key, raw_value) = kv.split_once('=').ok_or_else(|| respire_client_host::input_error::InputError(
        "format must be key=value (e.g. diary_mode=verbose)".into()))?;
    let intent = AgentConfigIntent { key: key.into(), raw_value: raw_value.into() };
    intent.apply(&serde_json::json!({})).map_err(|message|
        respire_client_host::input_error::InputError(message.into()))?;
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
    let account = identity.account_id.clone().unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let saved = super::lifecycle::pending_agent_config(&root)?;
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?, "agent config owner is not verifiable");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "agent config cannot identify the registered owner");
    }
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest, Some(&account))?;
    }
    let (mut record, mut maintenance) = if let Some((record, token, coordinator)) = saved {
        anyhow::ensure!(record.review.intent == intent && record.review.identity == identity
            && record.review.installation_root == root && record.review.profile == profile,
            "repeat the original agent-config intent and identity; a new operation is not allowed");
        let maintenance = super::lifecycle::resume_agent_config_maintenance(&root, &profile, &token, &coordinator)?;
        (record, maintenance)
    } else {
        super::metadata_control::control_offline_read(
            respire_protocol::metadata_control::HostOfflineRead::SnapshotPreflight)?;
        let review = crate::client_config::review_agent_config(intent, root.clone(), profile.clone())?;
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        maintenance.auth_launch_binding(&profile)?.context("agent config requires actual Paused maintenance")?;
        let record = AgentConfigMaintenance { review, was_serving: owner.is_some(),
            store_ready: owner.as_ref().is_some_and(|health| health.store_ready), sent: false, receipt: None };
        maintenance.save_agent_config(&record)?;
        (record, maintenance)
    };
    let operation = record.review.operation_id.clone();
    let mut finished = false;
    let result = (|| -> Result<ResultEnvelope> {
        maintenance.auth_launch_binding(&profile)?.context("agent config lost its Paused grant")?;
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "agent config requires a drained Runtime");
        let query = record.sent;
        if !query {
            record.sent = true;
            maintenance.save_agent_config(&record)?;
        }
        let binding = maintenance.auth_launch_binding(&profile)?.context("agent config lost its Paused grant")?;
        let (grant, _) = super::prepare_grant_for_identity(&binary, &root, &profile,
            managed.map(|config| config.id.as_str()), crate::net_rpc::rpc_port(), &account, Some(binding))?;
        let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
        anyhow::ensure!(grant.image_path == binary && grant.image_sha256.eq_ignore_ascii_case(&manifest.sha256), "agent config image changed");
        let params = AgentConfigParams { schema_version: CONFIG_VALIDATE_SCHEMA_V,
            binding: ControlBinding { installation_root: root.clone(), profile: profile.clone(),
                launch_id: grant.instance_id.clone(), expected_account_id: identity.account_id.clone() }, review: record.review.clone() };
        let request = RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
            method: if query { AGENT_CONFIG_RESULT_METHOD } else { AGENT_CONFIG_SET_METHOD }.into(),
            args: vec![serde_json::to_string(&params)?], scope: None, operation_id: Some(operation.clone()),
            idempotency_key: Some(operation.clone()), parent_operation_id: None, queue_wait_ms: None, lifecycle: None };
        let envelope = super::exchange_control(&binary, &grant, &request, Instant::now() + Duration::from_secs(185), |response, pid| {
            anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
                && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
                && response.operation_id.as_ref() == Some(&operation) && response.idempotency_key.as_ref() == Some(&operation),
                "agent config response binding mismatch");
            anyhow::ensure!(response.data_dir.as_deref().is_some_and(|directory| std::path::Path::new(directory) == profile),
                "agent config response profile mismatch");
            let envelope = response.envelope.context("agent config response missing")?;
            anyhow::ensure!(envelope.command == "agent-config-control" && envelope.details.is_null()
                && envelope.errors.is_empty() && envelope.actions.is_empty() && envelope.related.is_empty()
                && envelope.items.len() == 2, "invalid private agent config envelope");
            for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
                anyhow::ensure!(envelope.items.iter().filter(|item| item.name == name && item.value == value
                    && if name == "control_ready" { matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) }).count() == 1,
                    "agent config response cannot claim store readiness");
            }
            let receipt: AgentConfigReceipt = serde_json::from_value(envelope.summary.clone())?;
            anyhow::ensure!(receipt.review == record.review, "agent config response changed original intent");
            let terminal = receipt.outcome != AgentConfigOutcome::Unknown;
            anyhow::ensure!(response.ok == terminal && response.exit == if terminal { 0 } else { 2 }
                && matches!(envelope.status, Status::Ok) == terminal
                && if terminal { response.code.is_none() && response.error.is_none() }
                    else { response.code.as_deref() == Some("agent_config_outcome_unknown") }, "agent config outcome mismatch");
            Ok(envelope)
        })?;
        let receipt: AgentConfigReceipt = serde_json::from_value(envelope.summary)?;
        let actual = maintenance.refresh_agent_config()?;
        if receipt.outcome == AgentConfigOutcome::Unknown {
            anyhow::ensure!(actual.receipt.is_none(), "agent config unknown conflicts with terminal receipt");
            anyhow::bail!("agent_config_outcome_unknown operation_id={operation}; repeat the same command to query; do not replay");
        }
        anyhow::ensure!(actual.receipt.as_ref() == Some(&receipt), "agent config lacks its durable original O receipt");
        let (current_binary, current_manifest) = super::model_control::installed_model_runtime()?;
        let (current_root, current_profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(current_binary == binary && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
            && current_manifest.version == manifest.version && current_root.canonicalize()? == root
            && current_profile.canonicalize()? == profile && metadata_identity(&profile, super::hash)? == identity,
            "agent config installation or identity changed");
        if record.was_serving {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("agent config original owner did not resume")?;
            super::model_control::verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest, Some(&account))?;
            anyhow::ensure!(!record.store_ready || restored.store_ready || respire_client_host::settings::off_mode()?,
                "agent config original owner lacks store readiness");
        }
        let result: ResultEnvelope = serde_json::from_value(receipt.result)?;
        anyhow::ensure!(result.command == "agent-config" && matches!(result.status, Status::Ok)
            == (receipt.outcome == AgentConfigOutcome::Committed), "invalid agent config setter result");
        if receipt.outcome == AgentConfigOutcome::Committed {
            let intent = &record.review.intent;
            anyhow::ensure!(result.summary["action"] == "updated" && result.summary["key"] == intent.key
                && result.summary["value"] == intent.value() && result.items.len() == 1
                && result.items[0].name == intent.key && result.items[0].value == intent.raw_value
                && matches!(result.items[0].status, Status::Ok) && result.details.is_null()
                && result.errors.is_empty() && result.actions.is_empty() && result.related.is_empty()
                && (intent.key.trim() != "read_heat" || result.summary["read_heat_runtime"].is_object()),
                "agent config result differs from original setter output");
        }
        maintenance.finish()?;
        finished = true;
        Ok(result)
    })();
    if !finished {
        if result.as_ref().err().is_some_and(|error| error.chain().any(|cause|
            cause.to_string().starts_with("cleanup_failed owned_pid="))) {
            return result.map_err(|error| error.context(format!(
                "agent_config_outcome_unknown operation_id={operation}; helper cleanup unconfirmed; keep Paused and query original O")));
        }
        // Never replace a Runtime-written receipt with the controller's stale copy.
        maintenance.refresh_agent_config()?;
        maintenance.mark(super::lifecycle::Phase::Paused)?;
    }
    result.map_err(|error| error.context(format!("agent config operation_id={operation}; repeat the same command to query original O")))
}

//! The existing metadata sync gate for one staged client configuration.
use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::config_control::{
    ConfigValidateParams, ConfigValidationReceipt, CONFIG_VALIDATE_METHOD, CONFIG_VALIDATE_SCHEMA_V,
};
use respire_protocol::{HostControlLaunchGrant, RpcRequest};
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Dispatcher supplies the already-read frames and adds its control_ready/store_ready items.
pub(crate) fn execute(
    grant: HostControlLaunchGrant,
    request: &RpcRequest,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        request.v == respire_commands::rpc_worker::PROTOCOL_V
            && uuid::Uuid::parse_str(&request.id)
                .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == request.id)
            && request.method == CONFIG_VALIDATE_METHOD
            && request.args.len() == 1
            && request.scope.is_none()
            && request.operation_id.is_none()
            && request.idempotency_key.is_none()
            && request.parent_operation_id.is_none()
            && request.lifecycle.is_none()
            && request.queue_wait_ms.is_none(),
        "invalid private config validation request"
    );
    let params: ConfigValidateParams = serde_json::from_str(&request.args[0])
        .map_err(|_| anyhow::anyhow!("invalid private config validation parameters"))?;
    anyhow::ensure!(
        params.schema_version == CONFIG_VALIDATE_SCHEMA_V
            && params.target_profile == params.binding.profile,
        "config validation schema or target binding mismatch"
    );
    for path in [&params.source_profile, &params.target_profile] {
        anyhow::ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
                && path.canonicalize()? == *path,
            "config validation requires exact profile paths"
        );
    }
    anyhow::ensure!(
        !respire_app::login_transaction::auth_recovery_pending()?,
        "finish authentication recovery before changing client configuration"
    );
    crate::startup_identity::authorize_auth_control(grant)?;
    crate::host_control::watch_control_parent()?;
    let _ownership =
        crate::startup_identity::acquire_auth_ownership(&params.binding, &params.identity)?;
    let _source = if params.source_profile != params.binding.installation_root
        && params.source_profile != params.target_profile
    {
        Some(respire_app::lock::LibraryLock::acquire(
            &params.source_profile,
            std::time::Duration::from_secs(1),
        )?)
    } else {
        None
    };
    let _config_lock = respire_app::service::client_config_lock()?;
    respire_app::snapshot::ensure_no_incomplete_restore(&params.source_profile)?;
    verify_context(&params)?;
    let path = respire_app::service::client_config_path();
    let before =
        crate::startup_identity::read_private_file(&path)?.context("staged config is missing")?;
    anyhow::ensure!(
        hash(&before) == params.candidate_revision,
        "staged config Revision mismatch"
    );
    let original_bytes = params.original_config.as_deref().map(str::as_bytes);
    anyhow::ensure!(
        original_bytes.map(hash) == params.original_revision,
        "reviewed original config Revision mismatch"
    );
    let original = match params.original_config.as_deref() {
        Some(text) => serde_json::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid reviewed original config"))?,
        None => serde_json::json!({}),
    };
    let expected = params.intent.apply(&original).map_err(anyhow::Error::msg)?;
    let actual: serde_json::Value = serde_json::from_slice(&before)
        .map_err(|_| anyhow::anyhow!("invalid staged client config"))?;
    anyhow::ensure!(
        actual == expected,
        "staged config does not match the complete reviewed modification intent"
    );
    anyhow::ensure!(
        respire_app::service::data_dir_from_config(Some(&original)).canonicalize()?
            == params.source_profile
            && respire_app::service::data_dir_from_config(Some(&actual)).canonicalize()?
                == params.target_profile,
        "config validation source or effective target profile mismatch"
    );
    respire_app::service::validate_client_config()?;
    // This is the same gate used by the original setters, against the selected target DB.
    respire_app::service::validate_config_sync_change(
        params.intent.addr.is_some(),
        params.intent.autosync == Some(true),
    )?;
    verify_context(&params)?;
    let after =
        crate::startup_identity::read_private_file(&path)?.context("staged config disappeared")?;
    anyhow::ensure!(
        after == before,
        "staged config changed during metadata validation"
    );
    let receipt = ConfigValidationReceipt {
        original_revision: params.original_revision,
        candidate_revision: params.candidate_revision,
        intent: params.intent,
        source_profile: params.source_profile,
        target_profile: params.target_profile,
        source_identity: params.source_identity,
        target_identity: params.identity,
        off_mode: respire_app::service::off_mode(),
    };
    Ok(ResultEnvelope::new(
        "config-validate",
        Status::Ok,
        serde_json::to_value(receipt)?,
        Vec::new(),
    ))
}

fn verify_context(params: &ConfigValidateParams) -> Result<()> {
    crate::startup_identity::verify_auth_control_binding(&params.binding, &params.identity)?;
    respire_app::login_transaction::verify_auth_identity(
        &params.binding.installation_root,
        &params.source_profile,
        &params.source_identity,
    )?;
    anyhow::ensure!(
        respire_app::service::main_data_dir().canonicalize()? == params.binding.installation_root
            && respire_app::service::data_dir().canonicalize()? == params.target_profile,
        "config validation installation or selected target changed"
    );
    Ok(())
}

/// Agent settings use the same Paused/config-CAS boundary, without requiring an enabled store.
pub(crate) fn execute_agent_config(grant: HostControlLaunchGrant, request: &RpcRequest) -> Result<ResultEnvelope> {
    use respire_protocol::config_control::*;
    use respire_protocol::metadata_control::metadata_identity;
    let canonical = |value: &str| uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
    anyhow::ensure!(request.v == respire_commands::rpc_worker::PROTOCOL_V && canonical(&request.id)
        && matches!(request.method.as_str(), AGENT_CONFIG_SET_METHOD | AGENT_CONFIG_RESULT_METHOD)
        && request.args.len() == 1 && request.scope.is_none() && request.parent_operation_id.is_none()
        && request.lifecycle.is_none() && request.queue_wait_ms.is_none(), "invalid agent config request");
    let params: AgentConfigParams = serde_json::from_str(&request.args[0])
        .map_err(|_| anyhow::anyhow!("invalid agent config parameters"))?;
    let review = &params.review;
    anyhow::ensure!(params.schema_version == CONFIG_VALIDATE_SCHEMA_V && canonical(&review.operation_id)
        && request.operation_id.as_ref() == Some(&review.operation_id)
        && request.idempotency_key.as_ref() == Some(&review.operation_id)
        && params.binding.installation_root == review.installation_root && params.binding.profile == review.profile
        && review.fingerprint == hash(&review.fingerprint_bytes()?)
        && review.original_config.as_deref().map(|text| hash(text.as_bytes())) == review.original_revision,
        "agent config original operation binding changed");
    anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?, "finish authentication recovery first");
    crate::startup_identity::authorize_auth_control(grant)?;
    crate::host_control::watch_control_parent()?;
    let root = respire_app::service::main_data_dir().canonicalize()?;
    let profile = respire_app::service::data_dir().canonicalize()?;
    anyhow::ensure!(root == review.installation_root && profile == review.profile, "agent config selection changed");
    let _root = respire_app::lock::LibraryLock::acquire(&root, std::time::Duration::from_secs(15))?;
    let _profile = if root == profile { None } else {
        Some(respire_app::lock::LibraryLock::acquire(&profile, std::time::Duration::from_secs(15))?)
    };
    let _config = respire_app::service::client_config_lock()?;
    let verify = || -> Result<()> {
        crate::startup_identity::verify_metadata_control_binding(&params.binding, &review.identity)?;
        anyhow::ensure!(metadata_identity(&profile, hash)? == review.identity
            && respire_app::service::main_data_dir().canonicalize()? == root
            && respire_app::service::data_dir().canonicalize()? == profile, "agent config context changed");
        Ok(())
    };
    verify()?;
    respire_app::snapshot::ensure_no_incomplete_restore(&profile)?;
    let marker_path = root.join("runtime/autostart/maintenance.json");
    let marker_bytes = crate::startup_identity::read_private_file(&marker_path)?.context("agent maintenance missing")?;
    anyhow::ensure!(marker_bytes.len() <= 16 * 1024, "agent maintenance exceeds its bound");
    let mut marker: serde_json::Value = serde_json::from_slice(&marker_bytes)?;
    let mut record: AgentConfigMaintenance = serde_json::from_value(marker["agent_config"].clone())?;
    anyhow::ensure!(record.review == *review && record.sent && marker["phase"] == "Paused"
        && marker["snapshot"].is_null(), "agent maintenance differs from original intent");
    let workspace = review.intent.workspace_mode().map_err(anyhow::Error::msg)?.is_some();
    let path = if workspace { respire_app::service::client_config_path() } else { profile.join("agent.json") };
    let actual = crate::startup_identity::read_private_file(&path)?;
    let original_bytes = review.original_config.as_deref().map(str::as_bytes);
    let original = if workspace {
        review.original_config.as_deref().map(serde_json::from_str).transpose()?.unwrap_or_else(|| serde_json::json!({}))
    } else {
        review.original_config.as_deref().and_then(|text| serde_json::from_str(text).ok()).unwrap_or_else(|| serde_json::json!({}))
    };
    let candidate = serde_json::to_vec_pretty(&review.intent.apply(&original).map_err(anyhow::Error::msg)?)?;
    anyhow::ensure!(hash(&candidate) == review.candidate_revision, "agent candidate differs from full intent");
    let receipt_only = record.receipt.is_some() || request.method == AGENT_CONFIG_RESULT_METHOD;
    let receipt = if let Some(receipt) = record.receipt.as_ref() {
        anyhow::ensure!(receipt.review == *review && match receipt.outcome {
            AgentConfigOutcome::Committed => actual.as_deref() == Some(candidate.as_slice()),
            AgentConfigOutcome::RolledBack => actual.as_deref() == original_bytes,
            AgentConfigOutcome::Unknown => false,
        }, "agent receipt or config changed; keep maintenance Paused");
        receipt.clone()
    } else if request.method == AGENT_CONFIG_RESULT_METHOD {
        AgentConfigReceipt { review: review.clone(), outcome: AgentConfigOutcome::Unknown, result: serde_json::Value::Null }
    } else {
        anyhow::ensure!(actual.as_deref() == original_bytes, "agent config CAS conflict");
        let validation: Result<()> = (|| {
            let command = respire_commands::cli_def::Command::AgentConfig { set: Some(format!("{}={}", review.intent.key, review.intent.raw_value)) };
            if respire_app::service::readonly_team() && respire_commands::gates::is_readonly_switch_off(&command) {
                anyhow::bail!("this space is read-only - you cannot lift read-only yourself");
            }
            respire_app::service::validate_agent_runtime_setting(&review.intent.key, &review.intent.value())?;
            verify()?;
            Ok(())
        })();
        let changed: Result<ResultEnvelope> = validation.and_then(|()| {
            replace_reviewed_file(&path, Some(&candidate))?;
            if review.intent.key.trim() == "read_heat" { respire_app::read_heat::reload()?; }
            anyhow::ensure!(crate::startup_identity::read_private_file(&path)?.as_deref() == Some(candidate.as_slice()),
                "agent candidate changed during validation");
            verify()?;
            let result = respire_commands::engine::agent_config_updated_result(&review.intent.key, &review.intent.raw_value, &review.intent.value())?;
            let mut preview = record.clone();
            preview.receipt = Some(AgentConfigReceipt { review: review.clone(), outcome: AgentConfigOutcome::Committed,
                result: serde_json::to_value(&result)? });
            let mut preview_marker = marker.clone();
            preview_marker["agent_config"] = serde_json::to_value(preview)?;
            anyhow::ensure!(serde_json::to_vec(&preview_marker)?.len() <= 16 * 1024,
                "agent config result exceeds the existing maintenance bound");
            Ok(result)
        });
        let (outcome, result) = match changed {
            Ok(result) => (AgentConfigOutcome::Committed, result),
            Err(error) => {
                let current = crate::startup_identity::read_private_file(&path)?;
                if current.as_deref() != original_bytes {
                    anyhow::ensure!(current.as_deref() == Some(candidate.as_slice()), "agent rollback CAS conflict");
                    replace_reviewed_file(&path, original_bytes)?;
                    if review.intent.key.trim() == "read_heat" { respire_app::read_heat::reload()?; }
                }
                let mut result = ResultEnvelope::new("agent-config", Status::Fail, serde_json::json!({"action":"rolled_back"}), Vec::new());
                result.errors.push(error.to_string());
                (AgentConfigOutcome::RolledBack, result)
            }
        };
        let receipt = AgentConfigReceipt { review: review.clone(), outcome, result: serde_json::to_value(result)? };
        verify()?;
        record.receipt = Some(receipt.clone());
        marker["agent_config"] = serde_json::to_value(&record)?;
        let bytes = serde_json::to_vec(&marker)?;
        anyhow::ensure!(bytes.len() <= 16 * 1024
            && crate::startup_identity::read_private_file(&marker_path)?.as_deref() == Some(marker_bytes.as_slice()),
            "agent maintenance changed before receipt publication");
        // The original O receipt is durable before replying. This changes no launch/owner field.
        replace_reviewed_file(&marker_path, Some(&bytes))?;
        receipt
    };
    if receipt_only { verify()?; }
    Ok(ResultEnvelope::new("agent-config-control", if receipt.outcome == AgentConfigOutcome::Unknown { Status::Fail } else { Status::Ok },
        serde_json::to_value(receipt)?, Vec::new()))
}

/// Same exact-byte durable publication as the existing CLI config CAS transaction.
fn replace_reviewed_file(path: &std::path::Path, bytes: Option<&[u8]>) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("config parent missing")?;
    let Some(bytes) = bytes else {
        std::fs::remove_file(path)?;
        respire_spawn::durable::sync_directory(parent)?;
        return Ok(());
    };
    let temporary = parent.join(format!(".client-json-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        respire_spawn::durable::replace_file(&temporary, path)?;
        Ok(())
    })();
    if let Err(error) = result {
        if let Err(cleanup) = std::fs::remove_file(&temporary) {
            if cleanup.kind() != std::io::ErrorKind::NotFound { return Err(error.context(format!("config temporary cleanup failed: {cleanup}"))); }
        }
        return Err(error);
    }
    Ok(())
}

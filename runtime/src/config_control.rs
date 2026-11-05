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
    respire_spawn::watch_control_parent()?;
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

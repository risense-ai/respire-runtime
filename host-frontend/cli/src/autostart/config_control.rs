//! Fixed client configuration transaction over the existing owned control helper.
use crate::client_config::{self, ConfigEdit, ConfigPlan};
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::config_control::{
    ConfigValidateParams, ConfigValidationReceipt, CONFIG_VALIDATE_METHOD,
};
use respire_protocol::{
    ControlBinding, HostAuthIdentity, RpcRequest, RpcResponse, HOST_CONTROL_MAX_FRAME_BYTES,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn roots() -> Result<(PathBuf, PathBuf)> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    Ok((root.canonicalize()?, profile.canonicalize()?))
}

fn account(identity: &HostAuthIdentity, profile: &Path) -> String {
    match identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => super::hash(profile.display().to_string().as_bytes()),
    }
}

fn workers(health: &crate::net_rpc::Health) -> Option<usize> {
    health.rpc["effective_parallelism"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
}

/// Same five flags as main::run_config. Never starts a Runtime for a read or a pure host edit.
pub(crate) fn run_config_control(
    data_dir: Option<&str>,
    addr: Option<&str>,
    autosync: Option<bool>,
    cure_auto: Option<bool>,
    rpc_parallelism: Option<u32>,
) -> Result<ResultEnvelope> {
    run_config_control_inner(data_dir, addr, autosync, cure_auto, rpc_parallelism, None)
        .map(|(envelope, _)| envelope)
}

/// Profile paths are prepared only after the existing coordinator takes takeover.
pub(crate) fn run_profile_config_control(
    name: &str,
    create_missing: bool,
) -> Result<(ResultEnvelope, HostAuthIdentity)> {
    let target = crate::profile_control::ProfileTarget::new(name, create_missing)?;
    let path = target
        .directory()
        .to_str()
        .context("profile path is not UTF-8")?;
    let (envelope, identity) =
        run_config_control_inner(Some(path), None, None, None, None, Some(&target))?;
    Ok((
        envelope,
        identity.context("profile switch has no verified target identity")?,
    ))
}

/// Space creation requires a newly owned directory; an existing target is never adopted.
pub(crate) fn run_space_config_control(name: &str) -> Result<(ResultEnvelope, HostAuthIdentity)> {
    let target = crate::profile_control::ProfileTarget::new_space(name)?;
    let path = target.directory().to_str().context("space path is not UTF-8")?;
    let (envelope, identity) =
        run_config_control_inner(Some(path), None, None, None, None, Some(&target))?;
    Ok((envelope, identity.context("space creation has no verified target identity")?))
}

fn run_config_control_inner(
    data_dir: Option<&str>,
    addr: Option<&str>,
    autosync: Option<bool>,
    cure_auto: Option<bool>,
    rpc_parallelism: Option<u32>,
    profile_target: Option<&crate::profile_control::ProfileTarget>,
) -> Result<(ResultEnvelope, Option<HostAuthIdentity>)> {
    let plan = client_config::prepare_config(data_dir, addr, autosync, cure_auto, rpc_parallelism)?;
    if let ConfigPlan::ReadOnly(snapshot) = plan {
        return Ok((snapshot.envelope(observed_workers()?, false), None));
    }
    crate::runtime_policy::require_host("client configuration changes")?;
    let takeover = crate::runtime_policy::takeover_lock()?;
    let prepared = if let Some(target) = profile_target {
        let next = match &plan {
            ConfigPlan::ProfileMaintenance(edit) => &edit.next_profile,
            _ => anyhow::bail!("profile switch requires a reviewed data_dir edit"),
        };
        Some(target.prepare_locked(&takeover, next)?)
    } else {
        None
    };
    let result = (|| -> Result<(ResultEnvelope, Option<HostAuthIdentity>)> {
        let edit = match plan {
            ConfigPlan::HostWrite(edit) => {
                let marker = respire_client_host::paths::main_data_dir()
                    .join("runtime/autostart/maintenance.json");
                match std::fs::symlink_metadata(marker) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => {
                        anyhow::bail!(
                            "finish existing host maintenance before changing configuration"
                        )
                    }
                }
                let observed = observed_workers()?;
                return Ok((
                    edit.publish_host()?
                        .envelope(observed, rpc_parallelism.is_some()),
                    None,
                ));
            }
            ConfigPlan::ProfileMaintenance(edit) | ConfigPlan::RuntimeValidation(edit) => edit,
            ConfigPlan::ReadOnly(_) => anyhow::bail!("read-only config was not handled"),
        };
        anyhow::ensure!(
            super::lifecycle::current_boot_token().is_none(),
            "config must own its host maintenance"
        );
        let (binary, manifest) = super::model_control::installed_model_runtime()?;
        let (root, source) = respire_client_host::config::control_roots()?;
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&source)?;
        let (root, source) = roots()?;
        anyhow::ensure!(
            edit.previous_profile.canonicalize()? == source,
            "config source profile changed since review"
        );
        let source_identity = super::control::identity(&source)?;
        let registration = super::read_registration(&root)?;
        let managed = registration
            .as_ref()
            .filter(|config| config.enabled && !config.manually_stopped);
        let owner = crate::rpc::probe_runtime()?;
        anyhow::ensure!(
            owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
            "config has a recorded Runtime owner without a verifiable drain identity"
        );
        if let Some(config) = managed {
            super::lifecycle::owned(config)?;
            super::lifecycle::ensure_control_endpoint(config)?;
            anyhow::ensure!(
                owner.is_some() || !super::super::super::manager::inspect(config)?.running,
                "config cannot identify the registered supervisor's serving owner"
            );
        }
        if let Some(health) = owner.as_ref() {
            super::model_control::verify_model_owner(
                health,
                &root,
                &source,
                managed,
                &binary,
                &manifest,
                Some(&account(&source_identity, &source)),
            )?;
        }
        if let Some(target) = profile_target {
            target.verify_existing()?;
        } else {
            std::fs::create_dir_all(&edit.next_profile)?;
        }
        let target = edit.next_profile.canonicalize()?;
        let target_identity = super::control::identity(&target)?;
        // Preview the exact request shape; real grant and request IDs are also canonical UUIDv4s.
        let preview_binding = ControlBinding {
            installation_root: root.clone(),
            profile: target.clone(),
            launch_id: uuid::Uuid::new_v4().to_string(),
            expected_account_id: match &target_identity {
                HostAuthIdentity::Bound { account_id, .. } => Some(account_id.clone()),
                _ => None,
            },
        };
        validation_request(edit.validation_params(
            preview_binding,
            target_identity.clone(),
            source_identity.clone(),
            source.clone(),
            target.clone(),
        )?)?;
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        maintenance
            .auth_launch_binding(&source)?
            .context("config requires persistent Paused maintenance")?;
        maintenance.check_account_runtime()?;
        if let Some(health) = owner.as_ref() {
            maintenance.drain_runtime(health)?;
        }
        anyhow::ensure!(
            !crate::net_rpc::port_is_open(),
            "config validation requires the serving Runtime to be drained"
        );
        let mut attempted_start = false;
        let changed: Result<(ResultEnvelope, Option<HostAuthIdentity>)> = (|| {
            anyhow::ensure!(
                super::control::identity(&source)? == source_identity,
                "config source identity changed while draining"
            );
            if let Some(target) = profile_target {
                target.verify_existing()?;
            }
            edit.stage_candidate()?;
            anyhow::ensure!(
                roots()? == (root.clone(), target.clone()),
                "candidate selected a different target profile"
            );
            let validation = validate_config_locked(
                &takeover,
                &mut maintenance,
                &edit,
                &source,
                &target,
                &source_identity,
                &target_identity,
            )?;
            edit.assert_candidate()?;
            anyhow::ensure!(
                super::control::identity(&source)? == source_identity
                    && super::control::identity(&target)? == target_identity,
                "config account identity changed during validation"
            );
            let fresh_empty = matches!(&validation.target_identity, HostAuthIdentity::Absent)
                && prepared
                    .as_ref()
                    .map(|profile| profile.fresh_empty_target())
                    .transpose()?
                    .unwrap_or(false);
            let metadata_only = match &validation.target_identity {
                HostAuthIdentity::Unbound { .. } => true,
                HostAuthIdentity::Absent => fresh_empty,
                HostAuthIdentity::Bound { .. } => false,
            };
            let actual_workers = if metadata_only {
                anyhow::ensure!(
                    validation.target_identity == target_identity
                        && validation.target_profile == target,
                    "idle target lacks exact Runtime identity validation"
                );
                // Only verified keygen-Unbound or newly created Absent targets stay idle.
                // A control receipt is not a serving/store-ready proof.
                maintenance.mark(super::lifecycle::Phase::Paused)?;
                None
            } else {
                attempted_start = true;
                maintenance.start_account_runtime()?;
                let health = crate::rpc::probe_runtime()?
                    .context("configured target Runtime did not start")?;
                super::model_control::verify_model_owner(
                    &health,
                    &root,
                    &target,
                    managed,
                    &binary,
                    &manifest,
                    Some(&account(&target_identity, &target)),
                )?;
                anyhow::ensure!(
                    health.store_ready || validation.off_mode,
                    "configured target Runtime did not confirm store readiness"
                );
                if owner.is_some() {
                    workers(&health)
                } else {
                    // Startup verifies the target but must not turn an idle/manual-stop owner on.
                    maintenance.drain_runtime(&health)?;
                    attempted_start = false;
                    maintenance.mark(super::lifecycle::Phase::Paused)?;
                    None
                }
            };
            let (current_binary, current_manifest) =
                super::model_control::installed_model_runtime()?;
            anyhow::ensure!(
                current_binary == binary
                    && current_manifest.version == manifest.version
                    && current_manifest
                        .sha256
                        .eq_ignore_ascii_case(&manifest.sha256)
                    && roots()? == (root.clone(), target.clone())
                    && super::control::identity(&source)? == source_identity
                    && super::control::identity(&target)? == target_identity,
                "config installation, profile, image or account changed before confirmation"
            );
            if let Some(target) = profile_target {
                target.verify_existing()?;
            }
            if fresh_empty {
                anyhow::ensure!(
                    prepared
                        .as_ref()
                        .context("new profile ownership missing")?
                        .fresh_empty_target()?,
                    "new profile changed before config completion"
                );
            }
            let confirmed = edit.assert_candidate()?;
            maintenance.finish()?;
            let mut envelope = confirmed.envelope(actual_workers, rpc_parallelism.is_some());
            if matches!(
                &validation.target_identity,
                HostAuthIdentity::Unbound { .. }
            ) {
                envelope.actions.push("Verified unbound keygen profile selected; Runtime remains stopped. Run rsrs login or rsrs register for this profile.".into());
            } else if fresh_empty {
                envelope.actions.push("New empty profile selected; Runtime remains stopped. Run rsrs login or rsrs register for this profile.".into());
            }
            Ok((envelope, Some(validation.target_identity)))
        })();
        match changed {
            Ok(envelope) => Ok(envelope),
            Err(error) => {
                // Shared transport makes failed cleanup visible. Never race an unconfirmed child.
                if error
                    .chain()
                    .any(|cause| cause.to_string().starts_with("cleanup_failed owned_pid="))
                {
                    let pause = maintenance.mark(super::lifecycle::Phase::Paused);
                    return Err(error.context(format!("config helper cleanup is unconfirmed; candidate retained; Paused publication: {pause:?}")));
                }
                if attempted_start {
                    let cleanup: Result<()> = (|| {
                        let health = crate::rpc::probe_runtime()?
                            .context("target exit cannot be confirmed from an absent listener")?;
                        super::model_control::verify_model_owner(
                            &health,
                            &root,
                            &target,
                            managed,
                            &binary,
                            &manifest,
                            Some(&account(&target_identity, &target)),
                        )?;
                        maintenance.drain_runtime(&health)
                    })();
                    if let Err(cleanup) = cleanup {
                        let pause = maintenance.mark(super::lifecycle::Phase::Paused);
                        return Err(error.context(format!("config target cleanup unconfirmed: {cleanup:#}; Paused publication: {pause:?}; candidate retained")));
                    }
                }
                if let Err(pause) = maintenance.mark(super::lifecycle::Phase::Paused) {
                    return Err(error.context(format!(
                        "config Paused publication failed: {pause:#}; candidate retained"
                    )));
                }
                if let Err(rollback) = edit.rollback_candidate() {
                    return Err(error.context(format!(
                        "config rollback failed: {rollback:#}; maintenance retained"
                    )));
                }
                if let Err(rebind) = maintenance
                    .auth_launch_binding(&source)
                    .and_then(|binding| binding.context("Paused source binding is unavailable"))
                {
                    return Err(error.context(format!(
                        "original config restored; Paused source rebind failed: {rebind:#}"
                    )));
                }
                Err(error.context(
                "original config restored by CAS; maintenance remains Paused for explicit recovery",
            ))
            }
        }
    })();
    // Directory cleanup runs under this same takeover, after the existing CAS/rollback path.
    let (result, identity) = match result {
        Ok((envelope, identity)) => (Ok(envelope), identity),
        Err(error) => (Err(error), None),
    };
    let result = match prepared {
        Some(prepared) => prepared.finish(result),
        None => result,
    };
    result.map(|envelope| (envelope, identity))
}

fn observed_workers() -> Result<Option<usize>> {
    let Some(health) = crate::rpc::probe_runtime()? else {
        return Ok(None);
    };
    let (root, profile) = roots()?;
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let registration = super::read_registration(&root)?;
    let managed = registration
        .as_ref()
        .filter(|config| config.enabled && !config.manually_stopped);
    let identity = super::control::identity(&profile)?;
    super::model_control::verify_model_owner(
        &health,
        &root,
        &profile,
        managed,
        &binary,
        &manifest,
        Some(&account(&identity, &profile)),
    )?;
    Ok(workers(&health))
}

fn validation_request(params: ConfigValidateParams) -> Result<RpcRequest> {
    let request = RpcRequest {
        v: respire_commands::rpc_client::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        method: CONFIG_VALIDATE_METHOD.to_owned(),
        args: vec![serde_json::to_string(&params)?],
        scope: None,
        operation_id: None,
        idempotency_key: None,
        parent_operation_id: None,
        queue_wait_ms: None,
        lifecycle: None,
    };
    anyhow::ensure!(
        serde_json::to_vec(&request)?.len() <= HOST_CONTROL_MAX_FRAME_BYTES,
        "host control request frame exceeds the protocol limit"
    );
    Ok(request)
}

fn validate_config_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    edit: &ConfigEdit,
    source: &Path,
    target: &Path,
    source_identity: &HostAuthIdentity,
    target_identity: &HostAuthIdentity,
) -> Result<ConfigValidationReceipt> {
    let envelope = super::control::auth_exchange(
        takeover,
        maintenance,
        Instant::now() + Duration::from_secs(10),
        None,
        |binding, identity| {
            anyhow::ensure!(
                binding.profile == target
                    && identity == *target_identity
                    && super::control::identity(source)? == *source_identity,
                "config profile or account changed while authorizing validation"
            );
            validation_request(edit.validation_params(
                binding,
                identity,
                source_identity.clone(),
                source.to_path_buf(),
                target.to_path_buf(),
            )?)
        },
        validate_response,
        |error| error,
    )?;
    maintenance
        .auth_launch_binding(target)?
        .context("config validation lost its exact Paused marker")?;
    serde_json::from_value(envelope.summary)
        .map_err(|_| anyhow::anyhow!("invalid config validation receipt"))
}

fn validate_response(
    response: RpcResponse<ResultEnvelope>,
    request: &RpcRequest,
    profile: &Path,
    pid: u32,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        response.v == request.v
            && response.id == request.id
            && response.bin == "rsrs-runtime"
            && response.pid == Some(pid)
            && response.scope.is_none()
            && response.operation_id.is_none()
            && response.idempotency_key.is_none()
            && response.web_url.is_none()
            && response.ok
            && response.exit == 0
            && response.code.is_none()
            && response.error.is_none(),
        "Runtime did not confirm private config validation"
    );
    if let Some(path) = response.data_dir.as_deref() {
        anyhow::ensure!(
            Path::new(path).canonicalize()? == profile,
            "config validation response profile mismatch"
        );
    }
    let envelope = response
        .envelope
        .context("config validation receipt missing")?;
    anyhow::ensure!(
        envelope.command == "config-validate"
            && matches!(envelope.status, Status::Ok)
            && envelope.details.is_null()
            && envelope.errors.is_empty(),
        "invalid config validation envelope"
    );
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(
            items.next().is_some_and(|item| item.value == value
                && if name == "control_ready" {
                    matches!(item.status, Status::Ok)
                } else {
                    matches!(item.status, Status::Skip)
                })
                && items.next().is_none(),
            "config helper readiness was not confirmed"
        );
    }
    let params: ConfigValidateParams = serde_json::from_str(
        request
            .args
            .first()
            .context("config validation params missing")?,
    )
    .map_err(|_| anyhow::anyhow!("invalid config validation request"))?;
    let receipt: ConfigValidationReceipt = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid config validation receipt"))?;
    anyhow::ensure!(
        receipt.original_revision == params.original_revision
            && receipt.candidate_revision == params.candidate_revision
            && receipt.intent == params.intent
            && receipt.source_profile == params.source_profile
            && receipt.target_profile == params.target_profile
            && receipt.target_profile == profile
            && receipt.source_identity == params.source_identity
            && receipt.target_identity == params.identity,
        "config validation receipt differs from the reviewed intent, Revision or account"
    );
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use respire_protocol::config_control::{ConfigChangeIntent, CONFIG_VALIDATE_SCHEMA_V};

    #[test]
    fn validation_request_checks_complete_frame_boundaries_and_escaping() -> Result<()> {
        let params = |padding: &str| -> Result<ConfigValidateParams> {
            Ok(ConfigValidateParams {
                schema_version: CONFIG_VALIDATE_SCHEMA_V,
                binding: ControlBinding {
                    installation_root: PathBuf::from("/config-frame/root"),
                    profile: PathBuf::from("/config-frame/profile"),
                    launch_id: uuid::Uuid::new_v4().to_string(),
                    expected_account_id: None,
                },
                identity: HostAuthIdentity::Absent,
                source_identity: HostAuthIdentity::Absent,
                source_profile: PathBuf::from("/config-frame/profile"),
                target_profile: PathBuf::from("/config-frame/profile"),
                original_revision: Some("a".repeat(64)),
                original_config: Some(serde_json::to_string(&serde_json::json!({
                    "padding": padding,
                }))?),
                candidate_revision: "b".repeat(64),
                intent: ConfigChangeIntent {
                    data_dir: None,
                    addr: Some("https://fixture.invalid".into()),
                    autosync: None,
                    cure_auto: None,
                    rpc_parallelism: None,
                },
            })
        };
        let base = validation_request(params("")?)?;
        let base_len = serde_json::to_vec(&base)?.len();
        for size in [65_535_usize, 65_536, 65_537] {
            let padding_len = size
                .checked_sub(base_len)
                .context("fixture exceeds boundary")?;
            let candidate = params(&"x".repeat(padding_len))?;
            let mut frame = base.clone();
            frame.args = vec![serde_json::to_string(&candidate)?];
            assert_eq!(serde_json::to_vec(&frame)?.len(), size);
            assert_eq!(
                validation_request(candidate).is_ok(),
                size <= HOST_CONTROL_MAX_FRAME_BYTES
            );
        }
        let escaped = params(&"\\\"".repeat(10_000))?;
        let original = escaped
            .original_config
            .as_deref()
            .context("fixture config missing")?;
        let _: serde_json::Value = serde_json::from_str(original)?;
        assert!(original.len() < HOST_CONTROL_MAX_FRAME_BYTES);
        let mut frame = base;
        frame.args = vec![serde_json::to_string(&escaped)?];
        assert!(serde_json::to_vec(&frame)?.len() > HOST_CONTROL_MAX_FRAME_BYTES);
        assert!(validation_request(escaped).is_err());
        Ok(())
    }
}

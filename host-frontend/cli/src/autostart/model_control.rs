//! Model preparation under the existing private launch-control transport.
//! Mount as a child of launch_authorization, alongside control.rs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::{
    AssetState, AssetsStatus, BackendLoadState, ControlBinding, HostControlLaunchGrant,
    HostControlOperation, HostModelParams, ModelInstallIntent, ModelPreparation,
    RpcRequest, RpcResponse, HOST_MODEL_SCHEMA_V,
};

/// No destination supplied by a plan can extend this local allowlist.
pub(crate) fn allowed_model_roots() -> Result<Vec<PathBuf>> {
    let (root, profile) = local_roots()?;
    let mut roots = vec![root.join("models")];
    let selected = profile.join("models");
    if !roots.contains(&selected) {
        roots.push(selected);
    }
    // Only an explicit local override extends the root set; never a response path.
    if let Some(raw) = respire_client_host::env::var_os("RSRS_M3_DIR") {
        let value = raw.to_str().context("RSRS_M3_DIR must contain valid Unicode")?.trim();
        anyhow::ensure!(!value.is_empty(), "RSRS_M3_DIR must not be empty or whitespace");
        // Preserve the SDK's ~/ expansion order, including its platform home lookup.
        let path = match value.strip_prefix("~/") {
            Some(rest) => dirs::home_dir()
                .or_else(|| respire_client_host::env::var_os("HOME").map(PathBuf::from))
                .or_else(|| respire_client_host::env::var_os("USERPROFILE").map(PathBuf::from))
                .map(|home| home.join(rest)).unwrap_or_else(|| PathBuf::from(value)),
            None => PathBuf::from(value),
        };
        let path = std::path::absolute(path)?;
        if !roots.contains(&path) { roots.push(path); }
    }
    Ok(roots)
}

fn local_roots() -> Result<(PathBuf, PathBuf)> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    Ok((root.canonicalize()?, profile.canonicalize()?))
}

fn account(profile: &Path) -> Result<Option<String>> {
    Ok(respire_client_host::identity::session_user_of_dir(profile)?
        .map(|user| super::hash(user.as_bytes())))
}

// Runtime scopes always have an identity; an absent session uses the canonical
// profile path, while the optional account binding remains absent in the grant.
pub(super) fn owner_scope_id(profile: &Path, account_id: Option<&str>) -> Result<String> {
    match account_id {
        Some(account_id) => Ok(account_id.to_owned()),
        None => Ok(super::hash(profile.canonicalize()?.display().to_string().as_bytes())),
    }
}

/// Host entry point. Only a previously serving owner is restarted on success.
pub(crate) fn control_prepare_model(intent: &ModelInstallIntent) -> Result<(AssetsStatus, bool)> {
    crate::runtime_policy::require_host("model preparation")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(),
        "model preparation must own its host maintenance transaction");
    let takeover = crate::runtime_policy::takeover_lock()?;
    // Bootstrap only an absent component; damaged installations still require explicit repair.
    if crate::runtime_fetch::read_manifest()?.is_none() {
        crate::runtime_fetch::download_and_install(None, None)?;
    }
    let (binary, manifest) = installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let (root, profile) = local_roots()?;
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let expected_account = account(&profile)?;
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "model preparation has a recorded owner without verifiable health");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        let state = super::super::super::manager::inspect(config)?;
        anyhow::ensure!(owner.is_some() || !state.running,
            "model preparation cannot identify the running registered supervisor's owner");
    }
    if let Some(owner) = owner.as_ref() {
        verify_model_owner(owner, &root, &profile, managed, &binary, &manifest, expected_account.as_deref())?;
    }
    let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
    let prepared: Result<(AssetsStatus, bool)> = (|| {
        maintenance.auth_launch_binding(&profile)?
            .context("model preparation requires persistent Paused host maintenance")?;
        maintenance.check_account_runtime()?;
        let assets = prepare_model_locked(&takeover, &mut maintenance, owner.as_ref(), intent)?;
        let (current_binary, current_manifest) = installed_model_runtime()?;
        anyhow::ensure!(current_binary == binary && current_manifest.version == manifest.version
            && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
            && local_roots()? == (root.clone(), profile.clone())
            && account(&profile)? == expected_account,
            "model preparation owner selection changed before restoration");
        if let Some(original) = owner.as_ref() {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("original model owner did not resume")?;
            verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest, expected_account.as_deref())?;
            anyhow::ensure!(!original.store_ready || restored.store_ready,
                "restored model owner did not confirm its original store readiness");
        }
        maintenance.finish()?;
        Ok(assets)
    })();
    match prepared {
        Ok(assets) => Ok(assets),
        Err(error) => {
            if let Err(pause) = maintenance.mark(super::lifecycle::Phase::Paused) {
                return Err(error.context(format!("model preparation failed; Paused marker publication failed: {pause:#}")));
            }
            Err(error.context("model preparation failed; maintenance remains Paused"))
        }
    }
}

pub(super) fn installed_model_runtime() -> Result<(PathBuf, crate::runtime_fetch::ManagedManifest)> {
    let manifest = crate::runtime_fetch::read_manifest()?.context("model control Runtime manifest is missing")?;
    // This verifier authenticates the official metadata, full inventory and binary hash.
    let (binary, image_sha256) = super::control::installed_auth_runtime()?;
    anyhow::ensure!(crate::runtime_fetch::version_in_accept(&manifest.version)
        && image_sha256.eq_ignore_ascii_case(&manifest.sha256)
        && binary == crate::runtime_fetch::managed_binary_path(&manifest.version).canonicalize()?,
        "model control Runtime version or image differs from the verified release manifest");
    Ok((binary, manifest))
}

pub(in crate::autostart) fn verify_model_owner(
    health: &crate::net_rpc::Health, root: &Path, profile: &Path,
    managed: Option<&super::super::super::Registration>, binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest, expected_account: Option<&str>,
) -> Result<()> {
    crate::net_rpc::request_scope(health)?;
    if let Some(config) = managed {
        super::lifecycle::verify_owned_runtime(config, health)?;
    }
    let process = crate::net_rpc::runtime_process_identity(health.pid)?;
    let birth = crate::autostart::process_birth(health.pid)?.context("model owner exited during verification")?;
    let prefix = if cfg!(windows) { "windows-filetime-" }
        else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
    let expected_scope = owner_scope_id(profile, expected_account)?;
    anyhow::ensure!(health.managed_id.as_deref() == managed.map(|config| config.id.as_str())
        && health.account_id == expected_scope
        && Path::new(&health.installation_root).canonicalize()? == root
        && health.installation_id == super::hash(root.display().to_string().as_bytes())
        && Path::new(&health.data_dir).canonicalize()? == profile
        && Path::new(&health.exe).canonicalize()? == binary
        && Path::new(&health.image_path).canonicalize()? == binary
        && Path::new(&process.executable).canonicalize()? == binary
        && health.image_sha256.eq_ignore_ascii_case(&manifest.sha256)
        && health.runtime_version == manifest.version
        && health.process_start_id == format!("{prefix}{birth}")
        && (process.started_at == birth || process.started_at == health.process_start_id)
        && !health.inference_stalled(),
        "model owner differs from the installed Runtime, account, profile or registration");
    anyhow::ensure!(crate::net_rpc::runtime_process_identity(health.pid)? == process,
        "model owner changed during verification");
    Ok(())
}

/// Caller owns takeover and maintenance, and supplies the verified serving owner if present.
/// Resume the original owner and finish maintenance only after this returns verified success;
/// errors deliberately leave maintenance paused for explicit recovery.
pub(crate) fn prepare_model_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    owner: Option<&crate::net_rpc::Health>,
    intent: &ModelInstallIntent,
) -> Result<(AssetsStatus, bool)> {
    crate::runtime_policy::require_host("model preparation")?;
    let roots = local_roots()?;
    let allowed = allowed_model_roots()?;
    anyhow::ensure!(
        takeover.protects(&roots.0.join("runtime/takeover"))?,
        "model preparation requires this installation's takeover ownership"
    );
    anyhow::ensure!(
        owner.is_some() || !crate::rpc::endpoint_path().exists(),
        "model preparation has no verifiable owner drain receipt"
    );
    if let Some(owner) = owner {
        maintenance.drain_runtime(owner)?;
    }
    anyhow::ensure!(
        !crate::net_rpc::port_is_open(),
        "model preparation requires the serving Runtime to be drained"
    );
    let expected_account = account(&roots.1)?;
    let plan = model_install_plan_locked(takeover, maintenance, intent)?;
    anyhow::ensure!(
        local_roots()? == roots
            && allowed_model_roots()? == allowed
            && account(&roots.1)? == expected_account,
        "local model preparation scope changed while obtaining the plan"
    );
    let sources = local_model_sources(intent, &plan.assets)?;
    let skipped = respire_commands::model_asset_files::prepare_model_assets_with_sources(&plan.assets, &allowed, &sources)?;
    let verified = model_install_verify_locked(takeover, maintenance, intent, &plan.selection_sha256)?.assets;
    anyhow::ensure!(
        local_roots()? == roots
            && allowed_model_roots()? == allowed
            && account(&roots.1)? == expected_account,
        "local model preparation scope changed during verification"
    );
    let backend = verified
        .backend_load
        .as_ref()
        .context("Runtime did not return backend verification")?;
    let evidence = backend
        .evidence
        .as_ref()
        .with_context(|| format!(
            "Runtime did not return fresh backend evidence (state={:?}, reason={:?}, incomplete_assets={})",
            backend.state, backend.reason, verified.missing.len()
        ))?;
    anyhow::ensure!(
        verified.complete
            && verified.missing.is_empty()
            && !verified.assets.is_empty()
            && verified
                .assets
                .iter()
                .all(|asset| asset.state == AssetState::Complete)
            && backend.state == BackendLoadState::Loaded
            && backend.reason.is_none()
            && evidence.contract == 1
            && evidence.status == BackendLoadState::Loaded
            && evidence.ready
            && evidence.fresh_session
            && evidence.inference_completed,
        "Runtime did not verify the prepared model and fresh backend loading"
    );
    Ok((verified, skipped))
}

/// One bounded read against the pinned installed image. Never auto-start serving or retry.
pub(crate) fn model_install_plan_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    intent: &ModelInstallIntent,
) -> Result<ModelPreparation> {
    let plan = model_control_locked(takeover, maintenance, HostControlOperation::ModelInstallPlan, intent, None)?;
    anyhow::ensure!(!plan.assets.complete && plan.assets.backend_load.is_none() && !plan.assets.assets.is_empty()
        && plan.assets.missing == plan.assets.assets, "Runtime returned readiness status instead of an installation plan");
    Ok(plan)
}

pub(crate) fn model_install_verify_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    intent: &ModelInstallIntent,
    selection_sha256: &str,
) -> Result<ModelPreparation> {
    model_control_locked(takeover, maintenance, HostControlOperation::ModelInstallVerify, intent, Some(selection_sha256))
}

fn model_control_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    operation: HostControlOperation,
    intent: &ModelInstallIntent,
    selection_sha256: Option<&str>,
) -> Result<ModelPreparation> {
    crate::runtime_policy::require_host("private model preparation control")?;
    let (command, budget) = match operation {
        HostControlOperation::ModelInstallPlan => {
            anyhow::ensure!(selection_sha256.is_none(), "plan requests must not supply a selection digest");
            ("model-install-plan", 10)
        }
        HostControlOperation::ModelInstallVerify => {
            validate_selection_digest(selection_sha256.context("verification requires the plan selection digest")?)?;
            ("model-install-verify", 185)
        }
        _ => anyhow::bail!("unsupported model control operation"),
    };
    let deadline = Instant::now() + Duration::from_secs(budget);
    // Reuse B's installed-image verifier; it does not perform an auth operation.
    let (binary, manifest) = installed_model_runtime()?;
    let (root, profile) = local_roots()?;
    anyhow::ensure!(
        takeover.protects(&root.join("runtime/takeover"))?,
        "model control requires this installation's takeover ownership"
    );
    let paused = maintenance
        .auth_launch_binding(&profile)?
        .context("model control requires an actual Paused maintenance grant")?;
    let expected_account_id = account(&profile)?;
    let grant_account = expected_account_id
        .clone()
        .unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let registration = super::read_registration(&root)?;
    let managed_id = registration
        .as_ref()
        .filter(|config| config.enabled && !config.manually_stopped)
        .map(|config| config.id.as_str());
    let (grant, _) = super::prepare_grant_for_identity(
        &binary,
        &root,
        &profile,
        managed_id,
        crate::net_rpc::rpc_port(),
        &grant_account,
        Some(paused),
    )?;
    let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
    anyhow::ensure!(
        grant.image_path == binary
            && grant.image_sha256.eq_ignore_ascii_case(&manifest.sha256)
            && grant.maintenance.is_some()
            && account(&profile)? == expected_account_id,
        "model control image, account or maintenance authorization changed"
    );
    let params = HostModelParams {
        schema_version: HOST_MODEL_SCHEMA_V,
        intent: intent.clone(),
        selection_sha256: selection_sha256.map(str::to_owned),
        binding: ControlBinding {
            installation_root: root.clone(),
            profile: profile.clone(),
            launch_id: grant.instance_id.clone(),
            expected_account_id: expected_account_id.clone(),
        },
    };
    let request = RpcRequest {
        v: respire_commands::rpc_client::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        method: operation.method().to_owned(),
        args: vec![serde_json::to_string(&params)?],
        scope: None,
        operation_id: None,
        idempotency_key: None,
        parent_operation_id: None,
        queue_wait_ms: None,
        lifecycle: None,
    };
    let mut plan = None;
    super::exchange_control(&binary, &grant, &request, deadline, |response, pid| {
        let envelope = validate_plan_response(response, &request, &profile, pid, command)?;
        let preparation: ModelPreparation = serde_json::from_value(envelope.details.clone())
            .context("invalid model preparation details")?;
        validate_selection_digest(&preparation.selection_sha256)?;
        if let Some(expected) = selection_sha256 {
            anyhow::ensure!(preparation.selection_sha256 == expected,
                "Runtime verified a different model preparation selection");
        }
        plan = Some(preparation);
        Ok(envelope)
    })?;
    let (current_binary, current_manifest) = installed_model_runtime()?;
    anyhow::ensure!(
        current_binary == binary && current_manifest.version == manifest.version
            && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
            && local_roots()? == (root, profile.clone()) && account(&profile)? == expected_account_id,
        "model control scope changed during the private read"
    );
    maintenance
        .auth_launch_binding(&profile)?
        .context("model control lost its Paused maintenance grant")?;
    plan.context("model control returned no preparation status")
}

fn validate_selection_digest(value: &str) -> Result<()> {
    anyhow::ensure!(value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid model preparation selection digest");
    Ok(())
}

/// Local policy only: the Runtime supplies artifact identity, never mirror authority.
fn local_model_sources(intent: &ModelInstallIntent, plan: &AssetsStatus) -> Result<Vec<Vec<String>>> {
    let config = respire_client_host::config::read_client_config(
        &respire_client_host::paths::client_config_path())?;
    let config_value = |name: &str| config.as_ref().and_then(|config| config[name].as_str()).map(str::to_owned);
    let mirror = intent.mirror.clone()
        .or_else(|| respire_client_host::env::var("RSRS_MIRROR").ok().filter(|value| !value.trim().is_empty()))
        .or_else(|| config_value("model_mirror")).unwrap_or_else(|| "auto".to_owned());
    let origins = if mirror.trim() == "auto" {
        vec!["https://hf-mirror.com".to_owned(), "https://hf-mirror.net".to_owned(), "https://huggingface.co".to_owned()]
    } else { vec![model_mirror_origin(&mirror)?] };
    let cpu_mirror = respire_client_host::env::var("RSRS_CPU_ORT_MIRROR").ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| config_value("model_cpu_ort_mirror").filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| "auto".to_owned());
    plan.assets.iter().map(|asset| {
        let official = &asset.suggested_source;
        if asset.name == "bge-m3-cpu-ort" {
            anyhow::ensure!(official.starts_with("https://github.com/risense-ai/respire-cli/releases/download/"),
                "CPU artifact lacks its official pinned source");
            return match cpu_mirror.trim() {
                "auto" => Ok(vec![format!("https://gh-proxy.org/{official}"), official.clone()]),
                "github" | "https://github.com" | "https://github.com/" => Ok(vec![official.clone()]),
                value => {
                    anyhow::ensure!(!value.is_empty() && !value.chars().any(char::is_whitespace),
                        "CPU ORT mirror must be a nonempty origin without whitespace");
                    let supplied = if value.contains("://") { value.to_owned() } else { format!("https://{value}") };
                    let origin = url::Url::parse(&supplied).context("invalid CPU ORT mirror origin")?;
                    anyhow::ensure!(matches!(origin.scheme(), "http" | "https") && origin.host_str().is_some()
                        && origin.username().is_empty() && origin.password().is_none()
                        && origin.query().is_none() && origin.fragment().is_none() && origin.path() == "/",
                        "CPU ORT mirror must be an origin without credentials, path, query or fragment");
                    Ok(vec![format!("{}/{official}", origin.as_str().trim_end_matches('/'))])
                }
            };
        }
        let relative = official.strip_prefix("https://huggingface.co/")
            .context("model artifact lacks its official immutable source")?;
        // Profile resources previously used their own pinned download URL, not the M3 mirror.
        if asset.name.starts_with("profile-") { return Ok(vec![official.clone()]); }
        Ok(origins.iter().map(|origin| format!("{origin}/{relative}")).collect())
    }).collect()
}

fn model_mirror_origin(raw: &str) -> Result<String> {
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "--mirror must not be empty");
    let supplied = if raw.contains("://") { raw.to_owned() } else { format!("https://{raw}") };
    let (scheme, rest) = supplied.split_once("://").context("--mirror is invalid")?;
    anyhow::ensure!(scheme == "http" || scheme == "https", "--mirror only supports http/https");
    let host = rest.split('/').next().filter(|host| !host.is_empty()).context("--mirror is missing a host")?.trim();
    anyhow::ensure!(!host.contains(['@', '?', '#']) && !host.chars().any(char::is_whitespace),
        "mirror must be a host without credentials, query or fragment");
    Ok(format!("{scheme}://{host}"))
}

fn validate_plan_response(
    response: RpcResponse<ResultEnvelope>,
    request: &RpcRequest,
    profile: &Path,
    pid: u32,
    command: &str,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        response.v == request.v
            && response.id == request.id
            && response.bin == "rsrs-runtime"
            && response.pid == Some(pid)
            && response.scope.is_none()
            && response.operation_id.is_none()
            && response.idempotency_key.is_none()
            && response.web_url.is_none(),
        "model control response identity mismatch"
    );
    if response.code.as_deref() == Some("auth_recovery_pending") {
        anyhow::bail!("auth_recovery_pending: finish account recovery before preparing models");
    }
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(
            Path::new(directory).canonicalize()? == profile,
            "model control response profile mismatch"
        );
    }
    anyhow::ensure!(
        response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none(),
        "private Runtime model plan was rejected"
    );
    let envelope = response
        .envelope
        .context("model control result is missing")?;
    anyhow::ensure!(
        envelope.command == command
            && matches!(envelope.status, Status::Ok)
            && envelope.errors.is_empty(),
        "invalid model control result envelope"
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
            "model control readiness was not confirmed"
        );
    }
    Ok(envelope)
}

#[cfg(test)]
mod owner_scope_tests {
    use super::*;

    #[test]
    fn absent_account_uses_the_canonical_profile_scope() -> Result<()> {
        let root = tempfile::tempdir()?;
        let profile = root.path().join("profile");
        let other = root.path().join("other");
        std::fs::create_dir(&profile)?;
        std::fs::create_dir(&other)?;
        let canonical = profile.canonicalize()?;
        let expected = super::super::hash(canonical.display().to_string().as_bytes());
        assert_eq!(account(&profile)?, None);
        assert_eq!(owner_scope_id(&profile, None)?, expected);
        assert_eq!(owner_scope_id(&profile.join("..").join("profile"), None)?, expected);
        assert_ne!(owner_scope_id(&other, None)?, expected);
        let bound = "a".repeat(64);
        assert_eq!(owner_scope_id(&profile, Some(&bound))?, bound);
        Ok(())
    }

    #[test]
    fn invalid_existing_session_does_not_become_anonymous() -> Result<()> {
        let root = tempfile::tempdir()?;
        let session = root.path().join("session.json");
        for bytes in [b"not-json".as_slice(), br#"{}"#, br#"{"user":""}"#] {
            std::fs::write(&session, bytes)?;
            assert!(account(root.path()).is_err());
            assert_eq!(std::fs::read(&session)?, bytes);
        }
        std::fs::write(&session, br#"{"user":"synthetic-owner"}"#)?;
        let bound = account(root.path())?.context("bound test account missing")?;
        assert_eq!(bound, super::super::hash(b"synthetic-owner"));
        assert_eq!(owner_scope_id(root.path(), Some(&bound))?, bound);
        Ok(())
    }
}

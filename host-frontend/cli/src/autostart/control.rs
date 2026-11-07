//! Auth-only client. Lifecycle ownership stays with the host caller; keys stay in Runtime.
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_client_host::identity::{auth_session_identity, AuthSessionIdentity};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::{
    ControlBinding, HostAuthIdentity, HostAuthKeygenParams, HostAuthOutcome, HostAuthResult,
    HostControlLaunchGrant, RpcRequest, RpcResponse,
    HOST_AUTH_KEYGEN_METHOD, HOST_AUTH_RESULT_METHOD, HOST_AUTH_SCHEMA_V,
};
use respire_protocol::host_control::{
    HostAuthAccountOutcome, HostAuthAccountParams, HostAuthAccountResult, HostAuthAuthorization,
    HostAuthLoginContinuation, HostAuthLoginParams, HostAuthRegisterParams, HOST_AUTH_ACCOUNT_COMPLETE_METHOD,
    HOST_AUTH_ACCOUNT_RESULT_METHOD, HOST_AUTH_ACCOUNT_ROLLBACK_METHOD,
    HOST_AUTH_LOGIN_METHOD, HOST_AUTH_REGISTER_METHOD,
};

/// Parameters only: the Runtime account response wrapper and completion grant are separate gates.
/// Never derive Debug or put these credentials in process arguments or environment variables.
pub(crate) enum AccountControl {
    Register { addr: String, user: String, password: String, super_password: Option<String> },
    Login { addr: String, user: String, authorization: HostAuthAuthorization, super_password: String },
    LoginStep { addr: String, user: String, authorization: HostAuthAuthorization, super_password: Option<String>,
        input: HostAuthLoginContinuation },
    Result,
    Complete,
    Rollback,
}

pub(crate) fn account_request(
    binding: ControlBinding,
    identity: HostAuthIdentity,
    operation_id: &str,
    operation: AccountControl,
) -> Result<RpcRequest> {
    let id = uuid::Uuid::parse_str(operation_id).context("invalid account operation ID")?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == operation_id,
        "account operation ID must be a canonical random UUID");
    let (method, argument) = match operation {
        AccountControl::Register { addr, user, password, super_password } =>
            (HOST_AUTH_REGISTER_METHOD, serde_json::to_string(&HostAuthRegisterParams {
                schema_version: HOST_AUTH_SCHEMA_V, binding, identity, addr, user, password, super_password,
            })?),
        AccountControl::Login { addr, user, authorization, super_password } =>
            (HOST_AUTH_LOGIN_METHOD, serde_json::to_string(&HostAuthLoginParams {
                schema_version: HOST_AUTH_SCHEMA_V, binding, identity, addr, user, authorization,
                super_password: Some(super_password),
                continuation: None,
            })?),
        AccountControl::LoginStep { addr, user, authorization, super_password, input } =>
            (HOST_AUTH_LOGIN_METHOD, serde_json::to_string(&HostAuthLoginParams {
                schema_version: HOST_AUTH_SCHEMA_V, binding, identity, addr, user, authorization, super_password,
                continuation: Some(input),
            })?),
        receipt => {
            let method = match receipt {
                AccountControl::Result => HOST_AUTH_ACCOUNT_RESULT_METHOD,
                AccountControl::Complete => HOST_AUTH_ACCOUNT_COMPLETE_METHOD,
                AccountControl::Rollback => HOST_AUTH_ACCOUNT_ROLLBACK_METHOD,
                _ => anyhow::bail!("invalid account receipt operation"),
            };
            (method, serde_json::to_string(&HostAuthAccountParams {
                schema_version: HOST_AUTH_SCHEMA_V, binding, identity,
            })?)
        }
    };
    Ok(RpcRequest {
        v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
        method: method.to_owned(), args: vec![argument], scope: None,
        operation_id: Some(operation_id.to_owned()), idempotency_key: Some(operation_id.to_owned()),
        parent_operation_id: None, queue_wait_ms: None, lifecycle: None,
    })
}

/// Validate receipt fields, not transport success or permission to leave maintenance.
pub(crate) fn validate_account_receipt(
    receipt: &HostAuthAccountResult,
    operation_id: &str,
    source_profile: &Path,
    register: bool,
) -> Result<()> {
    let strict_path = |path: &Path| path.is_absolute()
        && !path.components().any(|part| part == std::path::Component::ParentDir);
    anyhow::ensure!(receipt.operation_id == operation_id && strict_path(&receipt.source_profile)
        && receipt.source_profile == source_profile
        && receipt.target_profile.as_deref().is_none_or(strict_path),
        "account receipt operation or profile mismatch");
    anyhow::ensure!(!register || receipt.login.is_none(), "register receipt contains login continuation state");
    match receipt.outcome {
        HostAuthAccountOutcome::AwaitingInput => {
            let login = receipt.login.as_ref().context("awaiting-input login status is missing")?;
            let mut inputs = std::collections::BTreeSet::new();
            anyhow::ensure!(!register && receipt.account_id.is_none() && receipt.session_sha256.is_none()
                && receipt.super_password.is_none() && login.super_issued.is_none()
                && !login.user.is_empty() && !login.addr.is_empty()
                && !login.required_inputs.is_empty()
                && login.required_inputs.iter().all(|input| matches!(input.as_str(),
                    "totp" | "super_password" | "legacy_password" | "account_secret" | "source_secret"
                    | "secret_key" | "new_super" | "merge_local") && inputs.insert(input.as_str()))
                && login.dir.as_deref().is_none_or(strict_path),
                "invalid awaiting-input account receipt");
        }
        HostAuthAccountOutcome::RolledBack => {
            anyhow::ensure!(receipt.account_id.is_none() && receipt.session_sha256.is_none()
                && receipt.super_password.is_none(), "invalid rolled-back account receipt");
        }
        HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Committed => {
            let target = receipt.target_profile.as_ref().context("account receipt target is missing")?;
            let (_, selected) = respire_client_host::config::control_roots()?;
            let target = respire_client_host::config::normalize_control_path(target)?.canonicalize()?;
            anyhow::ensure!(selected.canonicalize()? == target, "account receipt target is not selected");
            let actual = identity(&target)?;
            anyhow::ensure!(matches!(actual, HostAuthIdentity::Bound { account_id, session_sha256 }
                if Some(&account_id) == receipt.account_id.as_ref()
                    && Some(&session_sha256) == receipt.session_sha256.as_ref()),
                "account receipt target identity mismatch");
            anyhow::ensure!(if register {
                receipt.super_password.as_deref().is_some_and(|value| !value.is_empty())
            } else { receipt.super_password.is_none() }, "invalid account recovery-code presence");
        }
        HostAuthAccountOutcome::Unknown => {
            // Even a complete-looking vault-pending receipt is not a terminal result.
            anyhow::ensure!(receipt.account_id.is_some() == receipt.session_sha256.is_some()
                && (receipt.account_id.is_none() || receipt.target_profile.is_some())
                && (receipt.super_password.is_none() || (register && receipt.account_id.is_some()))
                && receipt.super_password.as_deref().is_none_or(|value| !value.is_empty()),
                "invalid unknown account receipt");
        }
    }
    Ok(())
}

/// A failed exchange cannot prove that the write did not commit. Never replay it.
#[derive(Debug)]
pub(crate) struct AuthOutcomeUnknown {
    pub operation_id: String,
    pub force: bool,
}

impl std::fmt::Display for AuthOutcomeUnknown {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "auth_outcome_unknown operation_id={} force={}; query the same operation, do not replay keygen",
            self.operation_id, self.force)
    }
}
impl std::error::Error for AuthOutcomeUnknown {}

/// Caller holds takeover and has drained the serving owner under maintenance.
/// It must not hold installation/profile LibraryLock while waiting for the helper.
pub(crate) fn auth_keygen_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    operation_id: &str,
    force: bool,
) -> Result<ResultEnvelope> {
    auth_request(takeover, maintenance, operation_id, force, false)
}

/// Reconnect with the original operation ID and force; this never issues keygen.
pub(crate) fn auth_result_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    operation_id: &str,
    force: bool,
) -> Result<ResultEnvelope> {
    auth_request(takeover, maintenance, operation_id, force, true)
}

pub(crate) fn identity(profile: &Path) -> Result<HostAuthIdentity> {
    Ok(match auth_session_identity(profile, super::hash)? {
        AuthSessionIdentity::Absent => HostAuthIdentity::Absent,
        AuthSessionIdentity::Unbound { operation_id, session_sha256 } =>
            HostAuthIdentity::Unbound { operation_id, session_sha256 },
        AuthSessionIdentity::Bound { account_id, session_sha256 } =>
            HostAuthIdentity::Bound { account_id, session_sha256 },
    })
}

pub(crate) fn login_recovery_status(takeover: &LibraryLock) -> Result<respire_protocol::host_control::HostLoginRecoveryState> {
    crate::runtime_policy::require_host("login recovery status")?;
    let (binary, manifest_sha256) = installed_auth_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(takeover.protects(&root.join("runtime/takeover"))?,
        "login recovery status requires installation takeover ownership");
    let expected = identity(&profile)?;
    let account = match &expected {
        HostAuthIdentity::Bound { account_id, .. } => Some(account_id.clone()),
        _ => None,
    };
    let grant_account = account.clone().unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let grant: HostControlLaunchGrant = serde_json::from_value(super::prepare_login_recovery_status_grant(
        &binary, &root, &profile, crate::net_rpc::rpc_port(), &grant_account)?)?;
    anyhow::ensure!(grant.image_path == binary && grant.image_sha256.eq_ignore_ascii_case(&manifest_sha256)
        && identity(&profile)? == expected, "login recovery image or identity changed");
    let request = login_recovery_request(
        ControlBinding { installation_root: root, profile: profile.clone(),
            launch_id: grant.instance_id.clone(), expected_account_id: account }, expected, false)?;
    let envelope = super::exchange_control(&binary, &grant, &request,
        Instant::now() + Duration::from_secs(12),
        |response, pid| validate_login_recovery_response(response, &request, &profile, pid))?;
    let result: respire_protocol::host_control::HostLoginRecoveryResult = serde_json::from_value(envelope.summary)?;
    Ok(result.state)
}

pub(crate) fn recover_legacy_login_locked(
    takeover: &LibraryLock, maintenance: &mut super::lifecycle::Maintenance,
) -> Result<bool> {
    let envelope = auth_exchange(takeover, maintenance, Instant::now() + Duration::from_secs(12), None,
        |binding, identity| login_recovery_request(binding, identity, true),
        validate_login_recovery_response,
        |error| error.context("login recovery completion is unknown; retain the journal and maintenance"))?;
    let result: respire_protocol::host_control::HostLoginRecoveryResult = serde_json::from_value(envelope.summary)?;
    Ok(result.recovered)
}

fn login_recovery_request(binding: ControlBinding, identity: HostAuthIdentity, recover: bool) -> Result<RpcRequest> {
    use respire_protocol::host_control::{HostLoginRecoveryParams,
        HOST_LOGIN_RECOVERY_METHOD, HOST_LOGIN_RECOVERY_STATUS_METHOD};
    let params = HostLoginRecoveryParams { schema_version: HOST_AUTH_SCHEMA_V, binding, identity };
    Ok(RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
        method: if recover { HOST_LOGIN_RECOVERY_METHOD } else { HOST_LOGIN_RECOVERY_STATUS_METHOD }.to_owned(),
        args: vec![serde_json::to_string(&params)?], scope: None, operation_id: None, idempotency_key: None,
        parent_operation_id: None, queue_wait_ms: None, lifecycle: None })
}

fn validate_login_recovery_response(
    response: RpcResponse<ResultEnvelope>, request: &RpcRequest, _profile: &Path, pid: u32,
) -> Result<ResultEnvelope> {
    use respire_protocol::host_control::{HostLoginRecoveryResult, HostLoginRecoveryState,
        HOST_LOGIN_RECOVERY_METHOD};
    anyhow::ensure!(response.v == request.v && response.id == request.id
        && response.bin == "rsrs-runtime" && response.pid == Some(pid)
        && response.operation_id.is_none() && response.idempotency_key.is_none()
        && response.scope.is_none() && response.web_url.is_none() && response.data_dir.is_none()
        && response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none(),
        "login recovery failed or its completion is unknown; retain recovery state");
    let envelope = response.envelope.context("login recovery result is missing")?;
    anyhow::ensure!(envelope.command == "login-recovery" && matches!(envelope.status, Status::Ok)
        && envelope.errors.is_empty() && envelope.actions.is_empty() && envelope.related.is_empty()
        && envelope.details.is_null() && envelope.items.len() == 2,
        "invalid login recovery envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value
            && if name == "control_ready" { matches!(item.status, Status::Ok) }
                else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "login recovery authorization was not confirmed");
    }
    let result: HostLoginRecoveryResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid login recovery result"))?;
    if request.method == HOST_LOGIN_RECOVERY_METHOD {
        anyhow::ensure!(result.state == HostLoginRecoveryState::Clear,
            "login recovery did not clear the journal");
    } else {
        anyhow::ensure!(!result.recovered, "login recovery status cannot claim a write");
    }
    Ok(envelope)
}

pub(crate) fn installed_auth_runtime() -> Result<(std::path::PathBuf, String)> {
    let binary = crate::runtime_fetch::managed_runtime_path()?
        .context("auth control requires an installed managed Runtime")?.canonicalize()?;
    let manifest = crate::runtime_fetch::read_manifest()?
        .context("auth control Runtime manifest is missing")?;
    anyhow::ensure!(crate::runtime_fetch::version_in_accept(&manifest.version)
        && super::hash_file(&binary)?.eq_ignore_ascii_case(&manifest.sha256),
        "auth control Runtime version or image does not match the managed manifest");
    Ok((binary, manifest.sha256))
}

fn auth_request(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    operation_id: &str,
    force: bool,
    query_only: bool,
) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private account control")?;
    let id = uuid::Uuid::parse_str(operation_id).context("invalid auth operation ID")?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == operation_id,
        "auth operation ID must be a canonical random UUID");
    auth_exchange(takeover, maintenance, Instant::now() + Duration::from_secs(12), None,
        |binding, identity| {
            let params = HostAuthKeygenParams { schema_version: HOST_AUTH_SCHEMA_V, binding, identity, force };
            Ok(RpcRequest {
                v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
                method: if query_only { HOST_AUTH_RESULT_METHOD } else { HOST_AUTH_KEYGEN_METHOD }.to_owned(),
                args: vec![serde_json::to_string(&params)?], scope: None,
                operation_id: Some(operation_id.to_owned()), idempotency_key: Some(operation_id.to_owned()),
                parent_operation_id: None, queue_wait_ms: None, lifecycle: None,
            })
        }, validate_auth_response,
        |error| error.context(AuthOutcomeUnknown { operation_id: operation_id.to_owned(), force }))
}

pub(super) fn auth_exchange(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    deadline: Instant,
    completion: Option<(&Path, &str, &HostAuthAccountResult, bool)>,
    build: impl FnOnce(ControlBinding, HostAuthIdentity) -> Result<RpcRequest>,
    validate: impl FnOnce(RpcResponse<ResultEnvelope>, &RpcRequest, &Path, u32) -> Result<ResultEnvelope>,
    exchange_error: impl FnOnce(anyhow::Error) -> anyhow::Error,
) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private account control")?;
    let (binary, manifest_sha256) = installed_auth_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(takeover.protects(&root.join("runtime/takeover"))?,
        "auth control requires this installation's takeover ownership");
    let maintenance = match completion {
        Some((source, operation_id, receipt, register)) =>
            maintenance.account_complete_launch_binding(source, operation_id, receipt, register)?,
        None => maintenance.auth_launch_binding(&profile)?,
    };
    let expected = identity(&profile)?;
    let account_id = match &expected {
        HostAuthIdentity::Bound { account_id, .. } => Some(account_id.clone()),
        _ => None,
    };
    let grant_account = account_id.clone()
        .unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let registration = super::read_registration(&root)?;
    let managed_id = registration.as_ref()
        .filter(|config| config.enabled && !config.manually_stopped)
        .map(|config| config.id.as_str());
    let (grant, _) = super::prepare_grant_for_identity(&binary, &root, &profile,
        managed_id, crate::net_rpc::rpc_port(), &grant_account,
        maintenance)?;
    let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
    anyhow::ensure!(grant.image_path == binary
        && grant.image_sha256.eq_ignore_ascii_case(&manifest_sha256)
        && identity(&profile)? == expected,
        "auth control image or identity changed while preparing authorization");
    let request = build(ControlBinding { installation_root: root, profile: profile.clone(),
        launch_id: grant.instance_id.clone(), expected_account_id: account_id }, expected)?;
    // Exactly one exchange: errors retain the original operation, never retry a write.
    super::exchange_control(&binary, &grant, &request, deadline, |response, pid| {
        validate(response, &request, &profile, pid)
    }).map_err(exchange_error)
}

pub(crate) use respire_host_control::AccountOutcomeUnknown;

fn account_process_start_matches(birth: &str, start_id: &str) -> Result<bool> {
    let prefix = match crate::autostart::Platform::current()? {
        crate::autostart::Platform::Windows => "windows-filetime-",
        crate::autostart::Platform::Linux => "linux-starttime-",
        crate::autostart::Platform::Macos => "darwin-lstart-",
    };
    Ok(!birth.is_empty() && start_id.strip_prefix(prefix) == Some(birth))
}

pub(crate) fn verify_account_target(
    receipt: &HostAuthAccountResult, operation_id: &str, source: &Path, register: bool,
) -> Result<()> {
    validate_account_receipt(receipt, operation_id, source, register)?;
    anyhow::ensure!(matches!(receipt.outcome, HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Committed),
        "account target has no verifiable candidate receipt");
    let health = crate::net_rpc::health()?;
    crate::net_rpc::request_scope(&health)?;
    let (binary, digest) = installed_auth_runtime()?;
    let target = receipt.target_profile.as_ref().context("account target is missing")?;
    let target = respire_client_host::config::normalize_control_path(target)?.canonicalize()?;
    let process = crate::net_rpc::runtime_process_identity(health.pid)?;
    anyhow::ensure!(health.store_ready && health.account_id == *receipt.account_id.as_ref().context("account identity is missing")?
        && std::fs::canonicalize(&health.data_dir)? == target
        && std::fs::canonicalize(&health.image_path)? == binary
        && std::fs::canonicalize(&process.executable)? == binary
        && account_process_start_matches(&process.started_at, &health.process_start_id)? && health.image_sha256.eq_ignore_ascii_case(&digest),
        "target Runtime does not match the account receipt or managed image");
    anyhow::ensure!(crate::net_rpc::runtime_process_identity(health.pid)? == process,
        "target Runtime changed during account verification");
    Ok(())
}

pub(crate) fn validate_account_response(
    response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path, pid: u32,
    source: &Path, register: bool,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id
        && response.bin == "rsrs-runtime" && response.pid == Some(pid)
        && response.operation_id == request.operation_id && response.idempotency_key == request.idempotency_key
        && response.scope.is_none() && response.web_url.is_none(),
        "account control response identity mismatch");
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(Path::new(directory).canonicalize()? == profile, "account response launch profile mismatch");
    }
    if response.error.is_some() {
        let envelope = response.envelope.as_ref().context("account control rejection envelope missing")?;
        let (code, message) = match response.code.as_deref() {
            Some("unauthorized") => ("unauthorized", "account launch or parent authorization failed"),
            Some("scope_mismatch") => ("scope_mismatch", "account control binding changed or does not match"),
            Some("auth_ownership_unavailable") => ("auth_ownership_unavailable", "account library ownership is unavailable"),
            Some("control_unavailable") => ("control_unavailable", "account controller is unavailable"),
            Some("account_outcome_unknown") => ("account_outcome_unknown", "account outcome is unknown; query the original operation without replaying"),
            Some("control_outcome_unknown") => ("control_outcome_unknown", "account deadline or parent authorization ended; query the original operation without replaying"),
            _ => anyhow::bail!("invalid account control rejection code"),
        };
        let deadline = code == "control_outcome_unknown";
        let executed = code == "account_outcome_unknown";
        anyhow::ensure!(!response.ok && response.exit == 2
            && response.error.as_deref().is_some_and(|error| !error.is_empty())
            && envelope.command == "auth-account" && matches!(envelope.status, Status::Fail)
            && envelope.details.is_null() && envelope.actions.is_empty() && envelope.related.is_empty()
            && envelope.items.len() == 2
            && envelope.items[0].name == "control_ready"
            && envelope.items[0].value == (if deadline { "unknown" } else if executed { "true" } else { "false" })
            && (if deadline { matches!(envelope.items[0].status, Status::Skip) }
                else if executed { matches!(envelope.items[0].status, Status::Ok) }
                else { matches!(envelope.items[0].status, Status::Fail) })
            && envelope.items[1].name == "store_ready" && envelope.items[1].value == "false"
            && matches!(envelope.items[1].status, Status::Skip)
            && (if deadline { envelope.summary == serde_json::json!({"outcome":"unknown"}) && envelope.errors.is_empty() }
                else { envelope.summary == serde_json::json!({}) && envelope.errors.len() == 1
                    && response.error.as_ref() == envelope.errors.first() }),
            "invalid account control rejection envelope");
        // Never echo the Runtime diagnostic; every rejection retains the original operation.
        anyhow::bail!("Runtime rejected account control ({code}): {message}");
    }
    let envelope = response.envelope.context("account control result is missing")?;
    anyhow::ensure!(envelope.command == "auth-account" && envelope.details.is_null() && envelope.errors.is_empty(),
        "invalid account control envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value
            && if name == "control_ready" { matches!(item.status, Status::Ok) }
                else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "account helper readiness was not confirmed");
    }
    let receipt: HostAuthAccountResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid account receipt shape"))?;
    validate_account_receipt(&receipt, request.operation_id.as_deref().context("account operation is missing")?, source, register)?;
    if request.method == HOST_AUTH_LOGIN_METHOD {
        let params: HostAuthLoginParams = serde_json::from_str(request.args.first()
            .context("login request parameters are missing")?)
            .map_err(|_| anyhow::anyhow!("invalid login request parameters"))?;
        if let Some(login) = receipt.login.as_ref() {
            anyhow::ensure!(login.user == params.user
                && login.addr.trim_end_matches('/') == params.addr.trim().trim_end_matches('/'),
                "login receipt user or server differs from the original request");
        }
    }
    let code = match receipt.outcome {
        HostAuthAccountOutcome::AwaitingInput | HostAuthAccountOutcome::AwaitingVerification
            | HostAuthAccountOutcome::Committed => None,
        HostAuthAccountOutcome::Unknown => Some("account_outcome_unknown"),
        HostAuthAccountOutcome::RolledBack => Some("account_rolled_back"),
    };
    anyhow::ensure!(response.code.as_deref() == code && if code.is_none() {
        response.ok && response.exit == 0 && if receipt.outcome == HostAuthAccountOutcome::AwaitingInput {
            matches!(envelope.status, Status::Pending)
                && matches!(request.method.as_str(), HOST_AUTH_LOGIN_METHOD | HOST_AUTH_ACCOUNT_RESULT_METHOD)
        } else { matches!(envelope.status, Status::Ok) }
    } else { !response.ok && response.exit == 2 && matches!(envelope.status, Status::Fail) },
        "account control outcome/status mismatch");
    Ok(envelope)
}

pub(super) fn validate_auth_response(
    response: RpcResponse<ResultEnvelope>,
    request: &RpcRequest,
    profile: &Path,
    pid: u32,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id
        && response.bin == "rsrs-runtime" && response.pid == Some(pid)
        && response.operation_id == request.operation_id
        && response.idempotency_key == request.idempotency_key
        && response.scope.is_none() && response.web_url.is_none(),
        "auth control response identity mismatch");
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(Path::new(directory).canonicalize()? == profile,
            "auth control response profile mismatch");
    }
    let envelope = response.envelope.context("auth control result is missing")?;
    anyhow::ensure!(envelope.command == "keygen", "unexpected auth control command");
    anyhow::ensure!(!matches!(response.code.as_deref(),
        Some("control_outcome_unknown" | "auth_outcome_unknown")),
        "auth control completion is unknown; query the original operation");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value
            && if name == "control_ready" { matches!(item.status, Status::Ok) }
                else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "auth control readiness was not confirmed");
    }
    // Do not echo untrusted response/error contents into diagnostics.
    let result: HostAuthResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid auth control result shape"))?;
    anyhow::ensure!(Some(result.operation_id.as_str()) == request.operation_id.as_deref()
        && result.path == profile.join("session.json"), "auth control result owner mismatch");
    match result.outcome {
        HostAuthOutcome::Committed => {
            anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none()
                && response.error.is_none() && matches!(envelope.status, Status::Ok)
                && envelope.errors.is_empty()
                && result.super_password.as_deref().is_some_and(|value| !value.is_empty()),
                "invalid committed auth result");
            let actual = identity(profile)?;
            anyhow::ensure!(matches!(&actual, HostAuthIdentity::Unbound { operation_id, session_sha256 }
                if operation_id == &result.operation_id && Some(session_sha256) == result.session_sha256.as_ref()),
                "committed auth session does not match the Runtime receipt");
        }
        HostAuthOutcome::RolledBack => {
            anyhow::ensure!(!response.ok && response.exit == 2
                && response.code.as_deref() == Some("auth_not_committed")
                && response.error.is_none() && matches!(envelope.status, Status::Fail)
                && envelope.errors.is_empty() && result.session_sha256.is_none()
                && result.super_password.is_none(), "invalid rolled-back auth result");
        }
        HostAuthOutcome::Unknown => anyhow::bail!("auth control completion is unknown; query the original operation"),
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_process_start_requires_exact_native_birth() -> Result<()> {
        let birth = "123456789";
        let prefix = match crate::autostart::Platform::current()? {
            crate::autostart::Platform::Windows => "windows-filetime-",
            crate::autostart::Platform::Linux => "linux-starttime-",
            crate::autostart::Platform::Macos => "darwin-lstart-",
        };
        let start_id = format!("{prefix}{birth}");
        assert!(account_process_start_matches(birth, &start_id)?);
        for invalid in [birth.to_owned(), format!("{prefix}987654321"),
            format!("{prefix}{start_id}"), format!("{start_id} "), String::new()] {
            assert!(!account_process_start_matches(birth, &invalid)?);
        }
        assert!(!account_process_start_matches("", prefix)?);
        assert!(!account_process_start_matches(&start_id, &start_id)?);
        for foreign in ["windows-filetime-", "linux-starttime-", "darwin-lstart-"] {
            if foreign != prefix {
                assert!(!account_process_start_matches(birth, &format!("{foreign}{birth}"))?);
            }
        }
        Ok(())
    }
}

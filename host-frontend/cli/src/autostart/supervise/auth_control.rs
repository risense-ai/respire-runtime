//! CLI account adapter. Shared host control owns transactions and continuations.
//! The existing keygen flow remains separate from account and key recovery.

use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::host_control::{
    HostAuthAccountResult, HostAuthAuthorization, HostAuthLoginContinuation,
};
use respire_protocol::{HostAuthOutcome, HostAuthResult};
use std::path::Path;

use super::super::lifecycle;
use super::launch_authorization::{control, shared_host};

pub(crate) use respire_host_control::AccountContinuation;

pub(crate) fn control_register(
    addr: &str,
    user: &str,
    password: &str,
    super_password: Option<&str>,
) -> Result<ResultEnvelope> {
    if crate::output_state::HOST_RPC_OUTPUT.get() {
        anyhow::ensure!(super_password.is_none(), "host registration does not accept supplied recovery material");
        return shared_host::accounts().register_or_query(addr, user, password);
    }
    shared_host::accounts().register(addr, user, password, super_password)
}

pub(crate) fn control_login(
    addr: &str,
    user: &str,
    authorization: HostAuthAuthorization,
    super_password: &str,
) -> Result<ResultEnvelope> {
    control_login_step(
        addr,
        user,
        authorization,
        Some(super_password),
        HostAuthLoginContinuation::default(),
        None,
        &mut None,
    )
}

/// Preserve the original live maintenance capability through every input prompt.
pub(crate) fn control_login_step(
    addr: &str,
    user: &str,
    authorization: HostAuthAuthorization,
    super_password: Option<&str>,
    input: HostAuthLoginContinuation,
    resume: Option<&HostAuthAccountResult>,
    continuation: &mut Option<AccountContinuation>,
) -> Result<ResultEnvelope> {
    if crate::output_state::HOST_RPC_OUTPUT.get() && resume.is_none() && continuation.is_none() {
        return shared_host::accounts().login_or_continue(addr, user, authorization, super_password, input);
    }
    shared_host::accounts().login_step(
        addr,
        user,
        authorization,
        super_password,
        input,
        resume,
        continuation,
    )
}

/// Query only the original operation, never replay authentication.
pub(crate) fn control_account_result(
    operation_id: &str,
    source_profile: &Path,
    register: bool,
) -> Result<ResultEnvelope> {
    shared_host::accounts().result(operation_id, source_profile, register)
}

pub(crate) fn control_account_rollback(
    operation_id: &str,
    source_profile: &Path,
    register: bool,
) -> Result<ResultEnvelope> {
    shared_host::accounts().rollback(operation_id, source_profile, register)
}

/// New keygen operation. The legacy pass argument is deliberately not a credential.
pub(crate) fn control_keygen(pass: Option<&str>, force: bool) -> Result<ResultEnvelope> {
    if pass.is_some() {
        eprintln!("INFO from v4, --pass is not used for encryption: the super password is system-generated; copy the output below");
    }
    keygen_operation(&uuid::Uuid::new_v4().to_string(), force, false)
}

/// Query the original write, never issue another keygen or choose a new operation ID.
pub(crate) fn control_auth_result(operation_id: &str, force: bool) -> Result<ResultEnvelope> {
    keygen_operation(operation_id, force, true)
}

fn keygen_operation(operation_id: &str, force: bool, query_only: bool) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private account control")?;
    let id = uuid::Uuid::parse_str(operation_id).context("invalid auth operation ID")?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == operation_id,
        "auth operation ID must be a canonical random UUID");
    control::installed_auth_runtime()?;
    // Validate configuration before takeover acquisition can create its lock directory.
    let (_, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(lifecycle::current_boot_token().is_none(),
        "private account control must own its maintenance transaction");
    let takeover = crate::runtime_policy::takeover_lock()?;
    if !query_only {
        std::fs::create_dir_all(&profile)?;
    }
    let health = crate::rpc::probe_runtime()?;
    anyhow::ensure!(health.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "account control blocked: recorded owner has no verifiable health/drain receipt");
    let mut maintenance = if query_only {
        lifecycle::with_explicit_recovery(lifecycle::begin_maintenance_locked)?
    } else {
        lifecycle::begin_maintenance_locked()?
    };
    if let Some(health) = health.as_ref() {
        maintenance.drain_runtime(health)?;
    }
    let response = if query_only {
        control::auth_result_locked(&takeover, &mut maintenance, operation_id, force)
    } else {
        control::auth_keygen_locked(&takeover, &mut maintenance, operation_id, force)
    };
    finish_keygen(response, operation_id, force, query_only, || {
        if health.is_some() {
            maintenance.start_account_runtime()?;
        }
        maintenance.finish()
    })
}

pub(super) fn finish_keygen(
    response: Result<ResultEnvelope>,
    operation_id: &str,
    force: bool,
    query_only: bool,
    finish_rollback: impl FnOnce() -> Result<()>,
) -> Result<ResultEnvelope> {
    // An exchange error leaves the durable Paused marker intact, including cleanup failures.
    let envelope = response?;
    let result: HostAuthResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid auth control result shape"))?;
    match result.outcome {
        HostAuthOutcome::Committed => {
            let secret = result.super_password.filter(|value| !value.is_empty())
                .context("committed auth result is missing the recovery code")?;
            // Unbound keys cannot serve business requests. Register/login must resume Paused.
            let mut output = ResultEnvelope::new("keygen", Status::Ok,
                serde_json::json!({"path": result.path.to_string_lossy(), "super": secret}),
                vec![Item::new("keys", Status::Ok, result.path.display().to_string())]);
            output.actions.push("login --interactive --user <user> --pass <password>".into());
            Ok(output)
        }
        HostAuthOutcome::RolledBack => {
            // A new query process does not know the original serving state. Leave it Paused.
            if !query_only {
                finish_rollback()?;
            }
            Ok(envelope)
        }
        HostAuthOutcome::Unknown => Err(control::AuthOutcomeUnknown {
            operation_id: operation_id.to_owned(), force,
        }.into()),
    }
}

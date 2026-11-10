//! CLI account adapter. Shared host control owns transactions and continuations.
//! Offline keygen retains its original controller until a verified Start or typed account handoff.

use anyhow::Result;
#[cfg(test)]
use anyhow::Context;
use respire_commands::output::ResultEnvelope;
#[cfg(test)]
use respire_commands::output::{Item, Status};
use respire_protocol::host_control::{
    HostAuthAccountResult, HostAuthAuthorization, HostAuthLoginContinuation,
};
#[cfg(test)]
use respire_protocol::{HostAuthOutcome, HostAuthResult};
use std::path::Path;

use super::launch_authorization::shared_host;
#[cfg(test)]
use super::launch_authorization::control;

pub(crate) use respire_host_control::AccountContinuation;

pub(crate) fn control_register(
    addr: &str,
    user: &str,
    password: &str,
    super_password: Option<&str>,
) -> Result<ResultEnvelope> {
    if crate::output_state::HOST_RPC_OUTPUT.get() {
        anyhow::ensure!(super_password.is_none(), "host registration does not accept supplied recovery material");
        super::offline_keygen::prepare_account(true, user, addr)?;
        return shared_host::accounts().register_or_query(addr, user, password);
    }
    super::offline_keygen::prepare_account(true, user, addr)?;
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
    if resume.is_none() && continuation.is_none() {
        super::offline_keygen::prepare_account(false, user, addr)?;
    }
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
    super::offline_keygen::keygen(None, force)
}

/// Query the original write, never issue another keygen or choose a new operation ID.
pub(crate) fn control_auth_result(operation_id: &str, force: bool) -> Result<ResultEnvelope> {
    super::offline_keygen::keygen(Some(operation_id), force)
}

// Legacy adapter output contract only; production uses the durable coordinator.
#[cfg(test)]
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

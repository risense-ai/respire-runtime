//! Foreground supervisor started by the sign-in registration. It owns and
//! restarts the separate `rsrs-runtime` child process; the runtime binary
//! itself never registers, restarts or updates anything.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::{lifecycle, read_registration, Registration};

#[path = "launch_authorization.rs"]
mod launch_authorization;
mod auth_control;
pub(crate) use launch_authorization::migration_control::control_migrate_profile;
pub(crate) use launch_authorization::metadata_control::{control_metadata, control_offline_read, discover_legacy_snapshot};
pub(crate) use launch_authorization::agent_config_control::control_agent_config;
pub(crate) use launch_authorization::key_control::{
    control_super_reset, control_super_reset_step, control_key_result, control_key_rollback,
    control_fivekeys,
    KeyRecoveryRequired,
};
pub(crate) use launch_authorization::identity_write_control::{control_logout, control_session_revoke, IdentityWriteRecoveryRequired};
pub(crate) use launch_authorization::space_control::{control_space_invite, control_space_join, control_space_kick};
pub(crate) use launch_authorization::profile_maintenance::{control_account_remove, control_space_remove};
pub(crate) use auth_control::{control_account_result, control_account_rollback,
    control_auth_result, control_keygen, control_login, control_login_step, control_register};
pub(crate) use launch_authorization::secret_control::{control_secret, control_keys_export, control_session_list};
pub(super) use launch_authorization::control::{installed_auth_runtime, verify_account_target};
pub(crate) use launch_authorization::control::{login_recovery_status, recover_legacy_login_locked};
pub(crate) use launch_authorization::model_control::{
    prepare_model_locked, model_install_plan_locked, model_install_verify_locked,
};
pub(crate) use launch_authorization::model_control::control_prepare_model;
pub(crate) use launch_authorization::model_maintenance::{
    control_install_engines, control_reset_cpu, control_uninstall_m3,
};
pub(crate) use launch_authorization::config_control::{run_config_control, run_profile_config_control, run_space_config_control};
pub(crate) use launch_authorization::exchange_control as exchange_snapshot_control;
pub(crate) use launch_authorization::prepare_grant_for_identity as prepare_snapshot_grant;
pub(crate) use launch_authorization::control::{
    account_request as prepare_auth_account_request, validate_account_receipt as validate_auth_account_receipt,
    AccountControl as AuthAccountControl, AccountOutcomeUnknown,
    auth_keygen_locked, auth_result_locked, AuthOutcomeUnknown,
};

/// Delay between a failed child attempt and the next start.
const RESTART_DELAY: Duration = Duration::from_secs(60);
/// Child uptime after which the consecutive-failure counter resets.
const STABLE_UPTIME_RESET: Duration = Duration::from_secs(120);
/// Consecutive short-lived failures that trip the circuit breaker.
const MAX_CONSECUTIVE_FAILURES: u8 = 3;

/// Registration entry point (`rsrs runtime supervise --data-dir <root>`).
/// Resolves the managed runtime, spawns `rsrs-runtime serve --supervised` and
/// keeps it alive with a bounded retry budget.
pub(crate) fn supervise(data_dir: &Path) -> Result<()> {
    let root = data_dir
        .canonicalize()
        .with_context(|| format!("invalid --data-dir {}", data_dir.display()))?;
    let config = read_registration(&root)?
        .context("no startup registration for this installation; enable runtime autostart first")?;
    lifecycle::owned(&config)?;
    let registered_root = PathBuf::from(
        config
            .environment
            .get("RSRS_DATA_DIR")
            .context("registered runtime root is missing")?,
    );
    anyhow::ensure!(
        registered_root.canonicalize()? == root,
        "registered runtime root belongs to another installation"
    );
    // Align this process with the registration environment before resolving
    // the runtime, exactly like the managed foreground run does.
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| {
            key.starts_with("RSRS_") || key.starts_with("ONEMEMORY_") || key.starts_with("RESPIRE_")
        }) {
            std::env::remove_var(key);
        }
    }
    for (key, value) in &config.environment {
        std::env::set_var(key, value);
    }
    // The registered task is the foreground owner. A kill-on-close job keeps a
    // dead supervisor from orphaning the runtime child (Windows 8+ nested jobs
    // preserve the enclosing Task Scheduler job).
    #[cfg(windows)]
    respire_spawn::confine_supervisor_tree()
        .context("cannot establish owned supervisor process tree")?;
    // Unix delivery forwards the signal to the child and exits without
    // counting the shutdown against the retry budget.
    #[cfg(unix)]
    let stopped = {
        let stopped = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
        stopped
    };
    #[cfg(not(unix))]
    let stopped = Arc::new(AtomicBool::new(false));
    let mut failures: u8 = 0;
    loop {
        if !supervise_may_run(&root, &config)? {
            return Ok(());
        }
        let started = Instant::now();
        let binary = match resolve_child_plan() {
            Ok(binary) => binary,
            Err(error) => {
                eprintln!("runtime resolution failed: {error:#}");
                if error.is::<crate::runtime_fetch::ManagedRuntimeRepairRequired>() {
                    lifecycle::record_supervise_event(&config, "exit_error");
                    return Err(error);
                }
                if !failure_backoff(&config, &root, &mut failures, Duration::ZERO)? {
                    return Err(error);
                }
                continue;
            }
        };
        lifecycle::record_supervise_event(&config, "starting");
        let arguments: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("serve"),
            std::ffi::OsString::from("--data-dir"),
            registered_root.clone().into_os_string(),
            std::ffi::OsString::from("--supervised"),
        ];
        let outcome = spawn_authorized_runtime(&binary, &arguments, Some(&config.id))
            .map(|(mut child, _instance_id)| wait_child(&mut child, &stopped));
        let uptime = started.elapsed();
        match outcome {
            // Signalled shutdown: the supervisor exits without retrying.
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(status))) if status.success() => {
                lifecycle::record_supervise_event(&config, "exit_ok");
                return Ok(());
            }
            Ok(Ok(Some(_))) => {
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
            Ok(Err(error)) => {
                eprintln!("runtime child supervision failed: {error:#}");
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
            Err(error) => {
                eprintln!("runtime child could not be started: {error:#}");
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
        }
    }
}

/// Both detached and supervised children use the same single-use startup grant.
pub(crate) fn spawn_authorized_runtime(
    binary: &Path,
    arguments: &[std::ffi::OsString],
    managed_id: Option<&str>,
) -> Result<(std::process::Child, String)> {
    launch_authorization::spawn(binary, arguments, managed_id)
}

pub(crate) fn control_memory_revision() -> Result<respire_commands::output::ResultEnvelope> {
    launch_authorization::control_memory_revision()
}

/// Wait for the child, honoring a signal flag. `Ok(None)` means the supervisor
/// was signalled and the child has been stopped.
fn wait_child(
    child: &mut std::process::Child,
    stopped: &AtomicBool,
) -> Result<Option<std::process::ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if stopped.load(Ordering::Acquire) {
            let _ = child.kill();
            child
                .wait()
                .context("cannot reap the stopped runtime child")?;
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The supervisor only starts independent Runtime images. Legacy compatibility
/// remains available through the explicit CLI foreground entry.
fn resolve_child_plan() -> Result<PathBuf> {
    let binary = crate::rpc::resolve_runtime_executable()?;
    anyhow::ensure!(
        !crate::rpc::explicit_cli_runtime(&binary)?,
        "supervision requires the independent Runtime; use --runtime-internal explicitly for legacy CLI compatibility"
    );
    Ok(binary)
}

/// Record the failure, keep the restart budget bounded and sleep out the retry
/// delay while still honoring disablement. `Ok(false)` stops the supervisor.
fn failure_backoff(
    config: &Registration,
    root: &Path,
    failures: &mut u8,
    uptime: Duration,
) -> Result<bool> {
    lifecycle::record_supervise_event(config, "exit_error");
    if !supervise_may_run(root, config)? {
        return Ok(false);
    }
    if !supervise_retry(failures, uptime) {
        lifecycle::record_supervise_event(config, "crash_limit");
        return Ok(false);
    }
    let deadline = Instant::now() + RESTART_DELAY;
    while Instant::now() < deadline {
        if !supervise_may_run(root, config)? {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(true)
}

/// Continue only while the registration still exists unchanged, enabled and
/// not manually stopped. Identity changes fail loudly instead of silently
/// abandoning a runtime we no longer own.
fn supervise_may_run(root: &Path, expected: &Registration) -> Result<bool> {
    let Some(current) = read_registration(root)? else {
        return Ok(false);
    };
    anyhow::ensure!(
        current.id == expected.id
            && current.owner == expected.owner
            && current.executable == expected.executable,
        "supervised registration identity changed"
    );
    Ok(current.enabled && !current.manually_stopped)
}

/// Bounded retry budget: three consecutive short-lived failures trip the
/// circuit breaker; stable uptime resets the counter.
fn supervise_retry(failures: &mut u8, uptime: Duration) -> bool {
    if uptime >= STABLE_UPTIME_RESET {
        *failures = 0;
    }
    *failures = failures.saturating_add(1);
    *failures < MAX_CONSECUTIVE_FAILURES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_never_turns_resolution_failure_into_a_shim() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow::anyhow!("test environment lock poisoned: {error}"))?;
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("RSRS_RUNTIME_BIN", value),
                    None => std::env::remove_var("RSRS_RUNTIME_BIN"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("RSRS_RUNTIME_BIN"));
        let directory = tempfile::tempdir()?;
        std::env::set_var("RSRS_RUNTIME_BIN", directory.path().join("missing-runtime"));
        anyhow::ensure!(resolve_child_plan().is_err());

        // A file override is a selection fixture only; this test executes no binary.
        let binary = directory.path().join("synthetic-runtime");
        std::fs::write(&binary, b"synthetic runtime selection")?;
        std::env::set_var("RSRS_RUNTIME_BIN", &binary);
        anyhow::ensure!(resolve_child_plan()? == binary);
        std::env::set_var("RSRS_RUNTIME_BIN", std::env::current_exe()?);
        anyhow::ensure!(resolve_child_plan().is_err());
        Ok(())
    }

    #[test]
    fn supervisor_retries_are_bounded_and_reset_only_after_stability() -> Result<()> {
        let _environment = crate::TEST_ENV_LOCK.lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        let mut failures = 0;
        assert!(supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(!supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(supervise_retry(&mut failures, Duration::from_secs(120)));
        assert_eq!(failures, 1);
        use respire_commands::output::{ResultEnvelope, Status};
        use std::cell::Cell;
        let finished = Cell::new(false);
        let operation_id = uuid::Uuid::new_v4().to_string();
        let response = |outcome: &str, secret: serde_json::Value| {
            ResultEnvelope::new("keygen", Status::Ok, serde_json::json!({
                "operation_id": operation_id, "outcome": outcome,
                "path": "fixture/session.json", "session_sha256": null,
                "super_password": secret,
            }), Vec::new())
        };
        let finish = || { finished.set(true); Ok(()) };
        let output = auth_control::finish_keygen(
            Ok(response("committed", serde_json::json!("synthetic-recovery-code"))), &operation_id, false, false, finish)?;
        assert!(!finished.get());
        assert_eq!(output.summary, serde_json::json!({
            "path": "fixture/session.json", "super": "synthetic-recovery-code"}));
        assert_eq!(output.items[0].name, "keys");
        assert_eq!(output.actions, ["login --interactive --user <user> --pass <password>"]);
        for missing in [serde_json::Value::Null, serde_json::json!("")] {
            assert!(auth_control::finish_keygen(Ok(response("committed", missing)), &operation_id, false, false, finish).is_err());
            assert!(!finished.get());
        }
        let unknown = anyhow::Error::new(AuthOutcomeUnknown { operation_id: operation_id.clone(), force: true });
        let error = auth_control::finish_keygen(Err(unknown), &operation_id, true, false, finish)
            .err().context("unknown result must not finish maintenance")?;
        assert_eq!(error.downcast_ref::<AuthOutcomeUnknown>()
            .context("original operation error was lost")?.operation_id, operation_id);
        assert!(!finished.get());
        for force in [false, true] {
            let error = auth_control::finish_keygen(
                Ok(response("unknown", serde_json::Value::Null)), &operation_id, force, false, finish,
            ).err().context("explicit unknown must not finish maintenance")?;
            let original = error.downcast_ref::<AuthOutcomeUnknown>()
                .context("explicit unknown lost its operation context")?;
            assert_eq!(original.operation_id, operation_id);
            assert_eq!(original.force, force);
            assert!(!finished.get());
        }
        let refused = auth_control::finish_keygen(
            Err(anyhow::anyhow!("synthetic preflight rejection")), &operation_id, true, false, finish,
        ).err().context("preflight rejection must remain an error")?;
        assert!(refused.downcast_ref::<AuthOutcomeUnknown>().is_none());
        assert!(!finished.get());
        auth_control::finish_keygen(Ok(response("rolled_back", serde_json::Value::Null)), &operation_id, false, true, finish)?;
        assert!(!finished.get());
        auth_control::finish_keygen(Ok(response("rolled_back", serde_json::Value::Null)), &operation_id, false, false, finish)?;
        assert!(finished.get());
        assert!(auth_control::finish_keygen(Ok(response("rolled_back", serde_json::Value::Null)), &operation_id, false, false,
            || anyhow::bail!("synthetic resume failure")).is_err());
        use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult,
            HostAuthAuthorization, HostAuthLoginParams, HostAuthRegisterParams, HostAuthAccountParams};
        let binding = respire_protocol::ControlBinding {
            installation_root: std::env::current_dir()?.canonicalize()?, profile: std::env::current_dir()?.canonicalize()?,
            launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: None,
        };
        let identity = respire_protocol::HostAuthIdentity::Absent;
        let fixture_password = "test-only-password";
        let fixture_recovery = "test-only-recovery";
        for (operation, method) in [
            (AuthAccountControl::Register { addr: "https://fixture.invalid".into(), user: "fixture".into(),
                password: fixture_password.into(), super_password: None }, "control.auth.register"),
            (AuthAccountControl::Login { addr: "https://fixture.invalid".into(), user: "fixture".into(),
                authorization: HostAuthAuthorization::Password { password: fixture_password.into(), totp: None },
                super_password: fixture_recovery.into() }, "control.auth.login"),
            (AuthAccountControl::Login { addr: "https://fixture.invalid".into(), user: "fixture".into(),
                authorization: HostAuthAuthorization::Browser { token: "synthetic-token".into(), session_id: None },
                super_password: fixture_recovery.into() }, "control.auth.login"),
            (AuthAccountControl::Result, "control.auth.account_result"),
            (AuthAccountControl::Complete, "control.auth.account_complete"),
            (AuthAccountControl::Rollback, "control.auth.account_rollback"),
        ] {
            let request = prepare_auth_account_request(binding.clone(), identity.clone(), &operation_id, operation)?;
            assert_eq!(request.method, method);
            assert_eq!(request.operation_id.as_deref(), Some(operation_id.as_str()));
            assert_eq!(request.idempotency_key.as_deref(), Some(operation_id.as_str()));
            assert_eq!(uuid::Uuid::parse_str(&request.id)?.get_version_num(), 4);
            assert_ne!(request.id, operation_id);
            assert!(request.scope.is_none() && request.lifecycle.is_none()
                && request.queue_wait_ms.is_none() && request.parent_operation_id.is_none());
            assert_eq!(request.args.len(), 1);
            match method {
                "control.auth.register" => {
                    let params: HostAuthRegisterParams = serde_json::from_str(&request.args[0])?;
                    assert_eq!(params.password, fixture_password);
                }
                "control.auth.login" => {
                    let params: HostAuthLoginParams = serde_json::from_str(&request.args[0])?;
                    assert_eq!(params.super_password.as_deref(), Some(fixture_recovery));
                }
                _ => { let _: HostAuthAccountParams = serde_json::from_str(&request.args[0])?; }
            }
        }
        assert!(prepare_auth_account_request(binding.clone(), identity, "not-a-uuid", AuthAccountControl::Result).is_err());
        let mut receipt = HostAuthAccountResult {
            operation_id: operation_id.clone(), outcome: HostAuthAccountOutcome::RolledBack,
            source_profile: binding.profile.clone(), target_profile: Some(binding.profile.join("historical-absent-target")),
            account_id: None, session_sha256: None, super_password: None, login: None,
        };
        validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true)?;
        receipt.super_password = Some("synthetic-recovery-code".into());
        assert!(validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true).is_err());
        receipt.super_password = None;
        receipt.account_id = Some("synthetic-account-digest".into());
        assert!(validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true).is_err());
        receipt.outcome = HostAuthAccountOutcome::Unknown;
        assert!(validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true).is_err());
        receipt.account_id = None;
        validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true)?;
        assert_eq!(receipt.outcome, HostAuthAccountOutcome::Unknown);
        assert!(validate_auth_account_receipt(&receipt, &uuid::Uuid::new_v4().to_string(), &binding.profile, true).is_err());
        receipt.outcome = HostAuthAccountOutcome::AwaitingVerification;
        receipt.target_profile = None;
        assert!(validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true).is_err());
        struct RestoreRoot(Option<std::ffi::OsString>);
        impl Drop for RestoreRoot {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
                    None => std::env::remove_var("RSRS_DATA_DIR"),
                }
            }
        }
        let _restore = RestoreRoot(std::env::var_os("RSRS_DATA_DIR"));
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let target = root.join("accounts/fixture");
        std::fs::create_dir_all(&target)?;
        let target = target.canonicalize()?;
        let session = br#"{"user":"Fixture-Account"}"#;
        std::fs::write(target.join("session.json"), session)?;
        std::fs::write(root.join("client.json"), serde_json::to_vec(&serde_json::json!({"data_dir": target}))?)?;
        std::env::set_var("RSRS_DATA_DIR", &root);
        receipt.target_profile = Some(target);
        receipt.account_id = Some(super::super::hash(b"Fixture-Account"));
        receipt.session_sha256 = Some(super::super::hash(session));
        receipt.super_password = Some(fixture_recovery.into());
        validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true)?;
        receipt.outcome = HostAuthAccountOutcome::Committed;
        validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, true)?;
        assert!(validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, false).is_err());
        receipt.super_password = None;
        validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, false)?;
        receipt.session_sha256 = Some(super::super::hash(b"wrong-session"));
        assert!(validate_auth_account_receipt(&receipt, &operation_id, &binding.profile, false).is_err());
        receipt.session_sha256 = Some(super::super::hash(session));
        let request = prepare_auth_account_request(binding.clone(), respire_protocol::HostAuthIdentity::Absent,
            &operation_id, AuthAccountControl::Result)?;
        let response: respire_protocol::RpcResponse<ResultEnvelope> = serde_json::from_value(serde_json::json!({
            "v": request.v, "id": request.id, "operation_id": operation_id, "idempotency_key": operation_id,
            "bin": "rsrs-runtime", "pid": 5252, "ok": true, "exit": 0,
            "envelope": ResultEnvelope::new("auth-account", Status::Ok, serde_json::to_value(&receipt)?,
                vec![respire_commands::output::Item::new("control_ready", Status::Ok, "true"),
                    respire_commands::output::Item::new("store_ready", Status::Skip, "false")]),
        }))?;
        let validate = |response| launch_authorization::control::validate_account_response(
            response, &request, &binding.profile, 5252, &binding.profile, false);
        assert!(validate(response.clone()).is_ok());
        let diagnostic = "synthetic-private-account-diagnostic";
        let rejection = |code: &str| -> Result<respire_protocol::RpcResponse<ResultEnvelope>> {
            let mut rejected = response.clone();
            rejected.ok = false;
            rejected.exit = 2;
            rejected.code = Some(code.to_owned());
            rejected.error = Some(diagnostic.into());
            rejected.data_dir = Some(binding.profile.to_string_lossy().into_owned());
            let deadline = code == "control_outcome_unknown";
            let executed = code == "account_outcome_unknown";
            let mut envelope = ResultEnvelope::new("auth-account", Status::Fail,
                if deadline { serde_json::json!({"outcome":"unknown"}) } else { serde_json::json!({}) },
                vec![respire_commands::output::Item::new("control_ready",
                    if deadline { Status::Skip } else if executed { Status::Ok } else { Status::Fail },
                    if deadline { "unknown" } else if executed { "true" } else { "false" }),
                    respire_commands::output::Item::new("store_ready", Status::Skip, "false")]);
            if !deadline { envelope.errors.push(diagnostic.into()); }
            rejected.envelope = Some(envelope);
            Ok(rejected)
        };
        for code in ["unauthorized", "scope_mismatch", "auth_ownership_unavailable",
            "control_unavailable", "account_outcome_unknown", "control_outcome_unknown"] {
            let error = validate(rejection(code)?).err().context("rejection was accepted")?.to_string();
            assert!(error.contains(&format!("Runtime rejected account control ({code})")));
            assert!(!error.contains(diagnostic));
        }
        let mut valid_rejection = serde_json::to_value(rejection("unauthorized")?)?;
        valid_rejection["scope"] = serde_json::Value::Null;
        for (pointer, value) in [
            ("/v", serde_json::json!(request.v + 1)),
            ("/id", serde_json::json!("foreign-request")),
            ("/pid", serde_json::json!(5253)),
            ("/bin", serde_json::json!("foreign-image")),
            ("/operation_id", serde_json::json!(uuid::Uuid::new_v4().to_string())),
            ("/idempotency_key", serde_json::json!("foreign-key")),
            ("/scope", serde_json::json!({"account_id":"foreign-account","instance_id":"foreign-instance","generation":1})),
            ("/web_url", serde_json::json!("https://fixture.invalid")),
            ("/data_dir", serde_json::json!(root)),
            ("/ok", serde_json::json!(true)),
            ("/exit", serde_json::json!(0)),
            ("/code", serde_json::json!("unrecognized-private-code")),
            ("/error", serde_json::Value::Null),
            ("/envelope/command", serde_json::json!("foreign-command")),
            ("/envelope/status", serde_json::json!("ok")),
            ("/envelope/summary", serde_json::json!({"outcome":"committed"})),
            ("/envelope/details", serde_json::json!({})),
            ("/envelope/actions", serde_json::json!(["untrusted-action"])),
            ("/envelope/errors", serde_json::json!(["different-diagnostic"])),
            ("/envelope/items/0/value", serde_json::json!("true")),
            ("/envelope/items/1/value", serde_json::json!("true")),
        ] {
            let mut malformed = valid_rejection.clone();
            *malformed.pointer_mut(pointer).context("account rejection fixture field missing")? = value;
            let error = validate(serde_json::from_value(malformed)?)
                .err().context("malformed rejection was accepted")?.to_string();
            assert!(!error.contains("Runtime rejected account control"), "accepted malformed field {pointer}");
            assert!(!error.contains(diagnostic));
        }
        let mut awaiting = response.clone();
        awaiting.envelope.as_mut().context("account fixture envelope missing")?
            .summary["outcome"] = serde_json::json!("awaiting_verification");
        assert!(validate(awaiting).is_ok());
        let mut unknown = response.clone();
        unknown.ok = false; unknown.exit = 2; unknown.code = Some("account_outcome_unknown".into());
        let envelope = unknown.envelope.as_mut().context("account fixture envelope missing")?;
        envelope.status = Status::Fail;
        envelope.summary["outcome"] = serde_json::json!("unknown");
        assert!(validate(unknown.clone()).is_ok());
        unknown.ok = true;
        assert!(validate(unknown).is_err());
        let mut wrong = response.clone(); wrong.id = uuid::Uuid::new_v4().to_string();
        assert!(validate(wrong).is_err());
        let mut wrong = response.clone(); wrong.pid = Some(5253);
        assert!(validate(wrong).is_err());
        let mut duplicate = response.clone();
        duplicate.envelope.as_mut().context("account fixture envelope missing")?.items.push(
            respire_commands::output::Item::new("control_ready", Status::Ok, "true"));
        assert!(validate(duplicate).is_err());
        let mut mirrored = response;
        let envelope = mirrored.envelope.as_mut().context("account fixture envelope missing")?;
        envelope.details = envelope.summary.clone();
        assert!(validate(mirrored).is_err());
        Ok(())
    }
}

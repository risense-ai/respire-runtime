//! Injection point for services that stay in the CLI host binary.
//!
//! The shared worker and engine call the accessor functions in this module;
//! the binary installs the host implementations once at startup through
//! [`install`]. Unset hooks fall back conservatively (maintenance reported as
//! not paused, outcome-unknown calls rejected) so shared-crate tests never
//! need the host wiring and a missing installer can never silently authorize
//! a lifecycle action.

use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::Result;

use crate::output::ResultEnvelope;

/// Projection of a runtime RPC reply for callers outside the CLI client surface.
pub struct MethodOutcome {
    pub ok: bool,
    pub error: Option<String>,
    pub envelope: Option<ResultEnvelope>,
}

/// Normalised CLI update status (mirror of the host `update_check` report).
pub struct UpdateStatus {
    pub current: String,
    pub latest: String,
    pub outdated: bool,
    pub cached: bool,
}

pub type BackgroundPaused = fn() -> bool;
pub type CheckDirectAccess = fn() -> Result<()>;
pub type NoteCredentialAccess = fn(bool);
pub type ContextChanged = fn();
pub type CallRuntimeMethod = fn(&str, Vec<String>, bool) -> Result<MethodOutcome>;
pub type UpdateHint = fn(bool) -> Option<String>;
pub type UpdateEnabled = fn() -> bool;
pub type UpdateCheckRun = fn(bool) -> Option<UpdateStatus>;
pub type MaterializeBin = fn() -> std::result::Result<PathBuf, String>;

#[derive(Default)]
pub struct HostHooks {
    pub background_paused: Option<BackgroundPaused>,
    pub check_direct_access: Option<CheckDirectAccess>,
    pub note_credential_access: Option<NoteCredentialAccess>,
    pub context_changed: Option<ContextChanged>,
    pub call_runtime_method: Option<CallRuntimeMethod>,
    pub update_hint: Option<UpdateHint>,
    pub update_enabled: Option<UpdateEnabled>,
    pub update_check_run: Option<UpdateCheckRun>,
    pub materialize_bin: Option<MaterializeBin>,
}

static BACKGROUND_PAUSED: OnceLock<BackgroundPaused> = OnceLock::new();
static CHECK_DIRECT_ACCESS: OnceLock<CheckDirectAccess> = OnceLock::new();
static NOTE_CREDENTIAL_ACCESS: OnceLock<NoteCredentialAccess> = OnceLock::new();
static CONTEXT_CHANGED: OnceLock<ContextChanged> = OnceLock::new();
static CALL_RUNTIME_METHOD: OnceLock<CallRuntimeMethod> = OnceLock::new();
static UPDATE_HINT: OnceLock<UpdateHint> = OnceLock::new();
static UPDATE_ENABLED: OnceLock<UpdateEnabled> = OnceLock::new();
static UPDATE_CHECK_RUN: OnceLock<UpdateCheckRun> = OnceLock::new();
static MATERIALIZE_BIN: OnceLock<MaterializeBin> = OnceLock::new();

/// Install the host implementations. Returns `false` when a previous installer
/// already ran; the first installation wins.
pub fn install(hooks: HostHooks) -> bool {
    let HostHooks {
        background_paused,
        check_direct_access,
        note_credential_access,
        context_changed,
        call_runtime_method,
        update_hint,
        update_enabled,
        update_check_run,
        materialize_bin,
    } = hooks;
    let installed = [
        background_paused.map(|hook| BACKGROUND_PAUSED.set(hook).is_ok()),
        check_direct_access.map(|hook| CHECK_DIRECT_ACCESS.set(hook).is_ok()),
        note_credential_access.map(|hook| NOTE_CREDENTIAL_ACCESS.set(hook).is_ok()),
        context_changed.map(|hook| CONTEXT_CHANGED.set(hook).is_ok()),
        call_runtime_method.map(|hook| CALL_RUNTIME_METHOD.set(hook).is_ok()),
        update_hint.map(|hook| UPDATE_HINT.set(hook).is_ok()),
        update_enabled.map(|hook| UPDATE_ENABLED.set(hook).is_ok()),
        update_check_run.map(|hook| UPDATE_CHECK_RUN.set(hook).is_ok()),
        materialize_bin.map(|hook| MATERIALIZE_BIN.set(hook).is_ok()),
    ];
    installed.iter().all(|slot| slot.as_ref().is_none_or(|ok| *ok))
}

/// Whether runtime maintenance fences background mutations.
pub fn background_paused() -> bool {
    BACKGROUND_PAUSED.get().map(|hook| hook()).unwrap_or(false)
}

/// Fail closed before touching the library while host maintenance is pending.
pub fn check_direct_access() -> Result<()> {
    match CHECK_DIRECT_ACCESS.get() {
        Some(hook) => hook(),
        None => Ok(()),
    }
}

/// Record whether host credentials were available for this session.
pub fn note_credential_access(available: bool) {
    if let Some(hook) = NOTE_CREDENTIAL_ACCESS.get() {
        hook(available);
    }
}

/// Sync schedules, index work and the resident catalog must react to a
/// generation change; the host owns the concrete schedulers.
pub fn context_changed() {
    if let Some(hook) = CONTEXT_CHANGED.get() {
        hook();
    }
}

/// Submit one method to the resident runtime through the host client surface.
pub fn call_runtime_method(method: &str, args: Vec<String>, auto_start: bool) -> Result<MethodOutcome> {
    match CALL_RUNTIME_METHOD.get() {
        Some(hook) => hook(method, args, auto_start),
        None => Err(anyhow::anyhow!("runtime client is unavailable in this process")),
    }
}

/// Cached update hint for maintenance notes, without a network round trip.
pub fn update_hint(force: bool) -> Option<String> {
    UPDATE_HINT.get().and_then(|hook| hook(force))
}

/// Whether the update checker is enabled (registry and RSRS_UPDATE_CHECK).
pub fn update_enabled() -> bool {
    UPDATE_ENABLED.get().map(|hook| hook()).unwrap_or(false)
}

/// Known CLI update status; `None` means "not checked yet".
pub fn update_check_run(force: bool) -> Option<UpdateStatus> {
    UPDATE_CHECK_RUN.get().and_then(|hook| hook(force))
}

/// Materialise the stable MCP stdio binary copy; host-owned installation.
pub fn materialize_bin() -> std::result::Result<PathBuf, String> {
    match MATERIALIZE_BIN.get() {
        Some(hook) => hook(),
        None => Err("the MCP binary installer is host-managed".to_owned()),
    }
}

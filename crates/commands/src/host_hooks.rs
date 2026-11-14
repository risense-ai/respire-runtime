//! Runtime admission, lifecycle and transport wiring. CLI installers, update
//! checks, terminal UI and command dispatch are not hook points in Runtime.

use std::sync::OnceLock;

use anyhow::Result;

use crate::output::ResultEnvelope;

/// Projection of a runtime RPC reply for callers outside the CLI client surface.
pub struct MethodOutcome {
    pub ok: bool,
    pub error: Option<String>,
    pub envelope: Option<ResultEnvelope>,
}

/// Normalised MCP HTTP bridge request (mirror of the host `mcp::HttpIn`).
pub struct McpHttpIn {
    pub method: String,
    pub path: String,
    pub origin: String,
    pub accept: String,
    pub body: String,
}

/// Loopback HTTP handler result shared by the runtime transport.
pub type HttpReply = (u16, &'static str, Vec<u8>);

pub type BackgroundPaused = fn() -> bool;
pub type CheckDirectAccess = fn() -> Result<()>;
pub type NoteCredentialAccess = fn(bool);
pub type ContextChanged = fn();
pub type CallRuntimeMethod = fn(&str, Vec<String>, bool) -> Result<MethodOutcome>;
pub type ForegroundProgress = fn(&str) -> anyhow::Result<serde_json::Value>;
pub type RuntimeIsUp = fn() -> bool;
pub type ChangeProfile = fn(Box<dyn FnOnce() -> anyhow::Result<()> + Send>) -> anyhow::Result<()>;
pub type ManagedId = fn() -> Option<&'static str>;
pub type VerifyManagedBoot = fn() -> Result<()>;
pub type RuntimeListenerReady = fn() -> Result<()>;
pub type RecordExit = fn(bool);
pub type CredentialState = fn() -> &'static str;
pub type CaptureRun = fn(Vec<String>) -> crate::output_state::Captured;
pub type McpHttpResponse = fn(McpHttpIn) -> HttpReply;

#[derive(Default)]
pub struct HostHooks {
    pub background_paused: Option<BackgroundPaused>,
    pub check_direct_access: Option<CheckDirectAccess>,
    pub note_credential_access: Option<NoteCredentialAccess>,
    pub context_changed: Option<ContextChanged>,
    pub call_runtime_method: Option<CallRuntimeMethod>,
    pub foreground_progress: Option<ForegroundProgress>,
    pub runtime_is_up: Option<RuntimeIsUp>,
    pub change_profile: Option<ChangeProfile>,
    pub managed_id: Option<ManagedId>,
    pub verify_managed_boot: Option<VerifyManagedBoot>,
    pub runtime_listener_ready: Option<RuntimeListenerReady>,
    pub record_exit: Option<RecordExit>,
    pub credential_state: Option<CredentialState>,
    pub capture_run: Option<CaptureRun>,
    pub mcp_http_response: Option<McpHttpResponse>,
}

static BACKGROUND_PAUSED: OnceLock<BackgroundPaused> = OnceLock::new();
static CHECK_DIRECT_ACCESS: OnceLock<CheckDirectAccess> = OnceLock::new();
static NOTE_CREDENTIAL_ACCESS: OnceLock<NoteCredentialAccess> = OnceLock::new();
static CONTEXT_CHANGED: OnceLock<ContextChanged> = OnceLock::new();
static CALL_RUNTIME_METHOD: OnceLock<CallRuntimeMethod> = OnceLock::new();
static FOREGROUND_PROGRESS: OnceLock<ForegroundProgress> = OnceLock::new();
static RUNTIME_IS_UP: OnceLock<RuntimeIsUp> = OnceLock::new();
static CHANGE_PROFILE: OnceLock<ChangeProfile> = OnceLock::new();
static MANAGED_ID: OnceLock<ManagedId> = OnceLock::new();
static VERIFY_MANAGED_BOOT: OnceLock<VerifyManagedBoot> = OnceLock::new();
static RUNTIME_LISTENER_READY: OnceLock<RuntimeListenerReady> = OnceLock::new();
static RECORD_EXIT: OnceLock<RecordExit> = OnceLock::new();
static CREDENTIAL_STATE: OnceLock<CredentialState> = OnceLock::new();
static CAPTURE_RUN: OnceLock<CaptureRun> = OnceLock::new();
static MCP_HTTP_RESPONSE: OnceLock<McpHttpResponse> = OnceLock::new();

/// Install the host implementations. Returns `false` when a previous installer
/// already ran; the first installation wins.
pub fn install(hooks: HostHooks) -> bool {
    let HostHooks {
        background_paused,
        check_direct_access,
        note_credential_access,
        context_changed,
        call_runtime_method,
        foreground_progress,
        runtime_is_up,
        change_profile,
        managed_id,
        verify_managed_boot,
        runtime_listener_ready,
        record_exit,
        credential_state,
        capture_run,
        mcp_http_response,
    } = hooks;
    let installed = [
        background_paused.map(|hook| BACKGROUND_PAUSED.set(hook).is_ok()),
        check_direct_access.map(|hook| CHECK_DIRECT_ACCESS.set(hook).is_ok()),
        note_credential_access.map(|hook| NOTE_CREDENTIAL_ACCESS.set(hook).is_ok()),
        context_changed.map(|hook| CONTEXT_CHANGED.set(hook).is_ok()),
        call_runtime_method.map(|hook| CALL_RUNTIME_METHOD.set(hook).is_ok()),
        foreground_progress.map(|hook| FOREGROUND_PROGRESS.set(hook).is_ok()),
        runtime_is_up.map(|hook| RUNTIME_IS_UP.set(hook).is_ok()),
        change_profile.map(|hook| CHANGE_PROFILE.set(hook).is_ok()),
        managed_id.map(|hook| MANAGED_ID.set(hook).is_ok()),
        verify_managed_boot.map(|hook| VERIFY_MANAGED_BOOT.set(hook).is_ok()),
        runtime_listener_ready.map(|hook| RUNTIME_LISTENER_READY.set(hook).is_ok()),
        record_exit.map(|hook| RECORD_EXIT.set(hook).is_ok()),
        credential_state.map(|hook| CREDENTIAL_STATE.set(hook).is_ok()),
        capture_run.map(|hook| CAPTURE_RUN.set(hook).is_ok()),
        mcp_http_response.map(|hook| MCP_HTTP_RESPONSE.set(hook).is_ok()),
    ];
    installed.iter().all(|slot| slot.as_ref().is_none_or(|ok| *ok))
}

/// Whether runtime maintenance fences background mutations.
pub fn background_paused() -> bool {
    if BACKGROUND_PAUSED.get().is_some_and(|hook| hook()) {
        return true;
    }
    let Ok(roots) = respire_app::service::resolved_roots() else {
        return true;
    };
    persisted_maintenance(&roots.installation_root)
}

fn persisted_maintenance(root: &std::path::Path) -> bool {
    // A malformed or unreadable marker still fences the standalone worker.
    !matches!(
        std::fs::symlink_metadata(root.join("runtime/autostart/maintenance.json")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

#[cfg(test)]
mod maintenance_tests {
    #[test]
    fn persisted_marker_fences_without_a_host_hook() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        assert!(!super::persisted_maintenance(root.path()));
        let marker = root.path().join("runtime/autostart/maintenance.json");
        let parent = marker
            .parent()
            .ok_or_else(|| anyhow::anyhow!("marker parent missing"))?;
        std::fs::create_dir_all(parent)?;
        std::fs::write(&marker, b"malformed")?;
        assert!(super::persisted_maintenance(root.path()));
        std::fs::remove_file(&marker)?;
        std::fs::create_dir(&marker)?;
        assert!(super::persisted_maintenance(root.path()));
        Ok(())
    }
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

/// Poll a remote foreground command's progress through the host RPC client.
pub fn foreground_progress(id: &str) -> anyhow::Result<serde_json::Value> {
    match FOREGROUND_PROGRESS.get() {
        Some(hook) => hook(id),
        None => Err(anyhow::anyhow!("runtime progress is unavailable in this process")),
    }
}

/// Whether a resident runtime answers right now (host client surface).
pub fn runtime_is_up() -> bool {
    RUNTIME_IS_UP.get().map(|hook| hook()).unwrap_or(false)
}

/// Run a profile change under the host lifecycle coordinator.
pub fn change_profile(change: Box<dyn FnOnce() -> anyhow::Result<()> + Send>) -> anyhow::Result<()> {
    match CHANGE_PROFILE.get() {
        Some(hook) => hook(change),
        None => Err(anyhow::anyhow!("profile changes are host-managed")),
    }
}

/// Registration id of the host-managed runtime owner, if any.
pub fn managed_id() -> Option<&'static str> {
    MANAGED_ID.get().and_then(|hook| hook())
}

/// Prove this startup is authorized by the host's managed coordinator.
pub fn verify_managed_boot() -> Result<()> {
    match VERIFY_MANAGED_BOOT.get() {
        Some(hook) => hook(),
        None => Ok(()),
    }
}

/// Only the owning host may receive a private readiness frame. Ordinary hosts
/// without this optional hook keep their existing readiness behavior.
pub fn runtime_listener_ready() -> Result<()> {
    match RUNTIME_LISTENER_READY.get() {
        Some(hook) => hook(),
        None => Ok(()),
    }
}

/// Record the process exit outcome with the host lifecycle bookkeeping.
pub fn record_exit(success: bool) {
    if let Some(hook) = RECORD_EXIT.get() {
        hook(success);
    }
}

/// Host credential bookkeeping state reported through /api/health.
pub fn credential_state() -> &'static str {
    CREDENTIAL_STATE.get().map(|hook| hook()).unwrap_or("unknown")
}

/// Execute one argv vector through the host command engine and capture its envelope.
pub fn capture_run(args: Vec<String>) -> crate::output_state::Captured {
    match CAPTURE_RUN.get() {
        Some(hook) => hook(args),
        None => {
            eprintln!("argv execution is host-managed; refusing {args:?}");
            crate::output_state::Captured {
                exit: 1,
                envelope: crate::output::ResultEnvelope::new(
                    "cli",
                    crate::output::Status::Fail,
                    serde_json::json!({"reason": "host-managed engine"}),
                    Vec::new(),
                ),
            }
        }
    }
}

/// Forward one MCP-over-HTTP request to the host MCP bridge.
pub fn mcp_http_response(request: McpHttpIn) -> HttpReply {
    match MCP_HTTP_RESPONSE.get() {
        Some(hook) => hook(request),
        None => (
            503,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"the MCP bridge is host-managed"}).to_string().into_bytes(),
        ),
    }
}

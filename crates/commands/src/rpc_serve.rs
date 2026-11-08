//! Server face of the runtime RPC surface.
//!
//! Owns the request queue (Job/admission), the dispatch loop and its worker
//! threads, the health body and the loopback HTTP wiring used by both the
//! CLI-hosted runtime and the standalone `rsrs-runtime` binary. The CLI binary
//! re-imports these items so `crate::rpc::...` call sites keep resolving.
//!
//! Boundaries:
//! - depends on `respire_app` (app-core) and `respire_protocol`, never on the
//!   `respire` CLI package;
//! - host-only services (argv execution, MCP bridge, managed registration)
//!   arrive through `host_hooks`.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use respire_protocol::{
    RuntimeCompat, RuntimeIdentity, RuntimeRequestScope, RuntimeStopOutcome, RuntimeStopReceipt,
    RuntimeUnfinishedOperation,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ---- Runtime identity (split-era health extension) ----

static RUNTIME_IDENTITY: OnceLock<RuntimeIdentity> = OnceLock::new();

/// Publish the serving binary's identity; the first call wins. The health body
/// and every RPC reply report it so clients can pin-check the managed runtime.
pub fn set_runtime_identity(identity: RuntimeIdentity) -> bool {
    RUNTIME_IDENTITY.set(identity).is_ok()
}

pub(crate) fn runtime_identity() -> RuntimeIdentity {
    RUNTIME_IDENTITY.get().cloned().unwrap_or(RuntimeIdentity {
        runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
        runtime_compat: RuntimeCompat {
            min_cli: env!("CARGO_PKG_VERSION").to_owned(),
            max_cli: "*".to_owned(),
        },
    })
}

#[derive(Clone)]
struct ProcessIdentity {
    installation_id: String,
    instance_id: String,
    process_start_id: String,
    image_path: String,
    image_sha256: String,
}

static PROCESS_IDENTITY: OnceLock<ProcessIdentity> = OnceLock::new();

/// Install the consumed launch nonce before any process identity is published.
pub fn set_launch_instance_id(instance_id: &str) -> Result<()> {
    let nonce = uuid::Uuid::parse_str(instance_id)
        .map_err(|_| anyhow::anyhow!("invalid runtime launch instance ID"))?;
    anyhow::ensure!(nonce.get_version_num() == 4 && nonce.to_string() == instance_id,
        "runtime launch instance ID must be a canonical random UUID");
    let executable = std::env::current_exe()?.canonicalize()?;
    let installation = respire_app::service::main_data_dir().canonicalize()?;
    let identity = ProcessIdentity {
        installation_id: sha256_hex(installation.display().to_string().as_bytes()),
        instance_id: instance_id.to_owned(),
        process_start_id: os_process_start_identity()
            .context("runtime process start identity is unavailable")?,
        image_path: executable.display().to_string(),
        image_sha256: sha256_file(&executable)
            .context("runtime executable digest is unavailable")?,
    };
    PROCESS_IDENTITY.set(identity)
        .map_err(|_| anyhow::anyhow!("runtime process identity was already published"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &std::path::Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(format!("{:x}", digest.finalize()))
}

fn os_process_start_identity() -> Option<String> {
    let pid = std::process::id();
    #[cfg(windows)]
    {
        return respire_spawn::process_birth(pid)
            .ok()
            .flatten()
            .map(|birth| format!("windows-filetime-{birth}"));
    }
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields = raw.rsplit_once(')')?.1;
        let state = fields.split_whitespace().next()?;
        if state == "Z" {
            return None;
        }
        let birth = fields.split_whitespace().nth(19)?;
        return Some(format!("linux-starttime-{birth}"));
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = std::process::Command::new("ps")
            .arg("-p")
            .arg(pid.to_string())
            .arg("-o")
            .arg("lstart=")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let birth = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return (!birth.is_empty()).then(|| format!("darwin-lstart-{birth}"));
    }
}

fn process_identity() -> ProcessIdentity {
    PROCESS_IDENTITY
        .get_or_init(|| {
            let exe = std::env::current_exe().unwrap_or_default();
            let installation = respire_app::service::main_data_dir();
            ProcessIdentity {
                installation_id: sha256_hex(installation.display().to_string().as_bytes()),
                instance_id: uuid::Uuid::new_v4().to_string(),
                process_start_id: os_process_start_identity().unwrap_or_default(),
                image_path: exe.display().to_string(),
                image_sha256: sha256_file(&exe).unwrap_or_default(),
            }
        })
        .clone()
}

pub fn validate_process_identity() -> Result<()> {
    let identity = process_identity();
    anyhow::ensure!(
        !identity.process_start_id.is_empty()
            && !account_identity().is_empty()
            && std::path::Path::new(&identity.image_path).is_absolute()
            && identity.image_sha256.len() == 64
            && identity
                .image_sha256
                .bytes()
                .all(|ch| ch.is_ascii_hexdigit()),
        "runtime cannot establish its OS process and executable identity"
    );
    Ok(())
}

fn account_identity() -> String {
    let data_dir = respire_app::service::data_dir();
    let account = respire_app::service::session_user_of_dir(&data_dir);
    let source = if account.is_empty() {
        match data_dir.canonicalize() {
            Ok(profile) => profile.display().to_string(),
            Err(_) => return String::new(),
        }
    } else {
        account
    };
    sha256_hex(source.as_bytes())
}

/// Version string this serving process reports in RPC replies and health.
fn bin_version() -> &'static str {
    RUNTIME_IDENTITY
        .get()
        .map(|identity| identity.runtime_version.as_str())
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Publish the identity of a host binary that serves in-process as the
/// split-transition shim (the CLI exe behind `--runtime-internal`): it reports
/// its own train so client version gates keep matching, with an unbounded
/// compatibility window. First publication still wins.
pub fn publish_shim_identity(version: &'static str) -> bool {
    set_runtime_identity(RuntimeIdentity {
        runtime_version: version.to_owned(),
        runtime_compat: RuntimeCompat {
            min_cli: version.to_owned(),
            max_cli: "*".to_owned(),
        },
    })
}

// Worker-face state (worker flag, sync context, generation, index work,
// write gate, recall statistics) lives in the shared rpc_worker module.
use crate::i18n;
use crate::output::{Item as OutputItem, ResultEnvelope, Status as OutputStatus};
use crate::rpc_worker::{
    check_sync_context, command_name, current_url, index_has_work, index_loop, index_status,
    is_context_query, is_status, kick_index, mark_worker, needs_inference, recall_stats_status,
    runtime_dir, shared_exclusive, sync_local, write_endpoint, RecallStats,
    GENERATION, INDEX_CV, INDEX_ON, MAX_PENDING_STATS, PROTOCOL_V, STATS_ENQUEUED,
    STATS_FAILED, STATS_PENDING, STATS_PERSISTED, STATS_REJECTED, STOPPING, SYNC_CONTEXT, WEB_URL,
};

pub static RUNNING: AtomicUsize = AtomicUsize::new(0);
static RUNNING_STATUS: AtomicUsize = AtomicUsize::new(0);
pub static LIGHT_RUNNING: AtomicUsize = AtomicUsize::new(0);
pub static WORKERS: AtomicUsize = AtomicUsize::new(1);
static STORE_READY: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_BOOT_ID: Mutex<Option<String>> = Mutex::new(None);
pub static JOB_TX: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();
static DISPATCH_THREAD: OnceLock<std::thread::Thread> = OnceLock::new();
pub const QUEUE_EXPIRED: &str = "request queue deadline exceeded; command was not started";
static WRITE_TX: Mutex<Option<mpsc::SyncSender<WriteJob>>> = Mutex::new(None);
static WRITE_RUNNING: AtomicBool = AtomicBool::new(false);
static CLASSIFY_RUNNING: AtomicBool = AtomicBool::new(false);
static SYNC_KICK: Mutex<SyncSchedule> = Mutex::new(SyncSchedule {
    due: None,
    manual: VecDeque::new(),
    backoff: 0,
    blocked_generation: None,
    last_success: None,
});
struct SyncSchedule {
    due: Option<Instant>,
    manual: VecDeque<(Job, usize, i64)>,
    backoff: u32,
    blocked_generation: Option<usize>,
    last_success: Option<u64>,
}
static SYNC_CV: Condvar = Condvar::new();
pub static SYNC_RUNNING: AtomicBool = AtomicBool::new(false);
static FLIGHT_ON: AtomicBool = AtomicBool::new(false);
struct CachedResponse {
    operation_id: String,
    response: RpcResponse,
}

struct IdempotencyRecord {
    operation_id: String,
    fingerprint: String,
}

#[derive(Clone, Debug)]
struct OperationIdentity {
    scope: RuntimeRequestScope,
    operation_id: String,
    storage_id: String,
    storage_key: String,
    fingerprint: String,
}

static CACHE: Mutex<Vec<CachedResponse>> = Mutex::new(Vec::new());
static IDEMPOTENCY: std::sync::LazyLock<Mutex<HashMap<String, IdempotencyRecord>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
static OPERATION_KEYS: std::sync::LazyLock<Mutex<HashMap<String, String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
static INFLIGHT: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

#[derive(Debug)]
enum Admission {
    New(AdmissionGuard),
    Replay(RpcResponse),
    InProgress,
    Unknown,
}

static CONTROL_STATE: Mutex<&'static str> = Mutex::new("running");
static STARTUP_COMPLETE: AtomicBool = AtomicBool::new(false);
static STOP_OPERATION: OnceLock<String> = OnceLock::new();
static STOP_UNFINISHED: Mutex<Vec<Admitted>> = Mutex::new(Vec::new());
const FORCE_DRAIN_GRACE: Duration = Duration::from_secs(4);
static STOP_FORCE_REQUESTED: Mutex<Option<Instant>> = Mutex::new(None);
static STOP_FORCE_TRIGGERED: AtomicBool = AtomicBool::new(false);
// Order: scope lock, write gate (except short control), ADMISSIONS, then ledger.
// Stop takes scope + ADMISSIONS; generation advances take ADMISSIONS without upgrading scope.
static SCOPE_EXECUTION: std::sync::RwLock<()> = std::sync::RwLock::new(());
static ADMISSIONS: std::sync::LazyLock<Mutex<Vec<Admitted>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

#[derive(Clone)]
struct Admitted {
    operation_id: String,
    kind: &'static str,
}

#[derive(Debug)]
pub(crate) struct AdmissionGuard(String);

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if let Ok(mut admitted) = ADMISSIONS.lock() {
            if let Some(index) = admitted.iter().position(|item| item.operation_id == self.0) {
                admitted.remove(index);
            }
        }
    }
}

pub(crate) fn begin_admission(operation_id: String, kind: &'static str) -> Option<AdmissionGuard> {
    let mut admitted = ADMISSIONS.lock().ok()?;
    if business_paused() {
        return None;
    }
    admitted.push(Admitted {
        operation_id: operation_id.clone(),
        kind,
    });
    Some(AdmissionGuard(operation_id))
}

fn business_paused() -> bool {
    STOPPING.load(Ordering::Acquire) || crate::host_hooks::background_paused()
}

fn maintenance_control_method(method: &str) -> bool {
    matches!(method, "runtime.status" | "runtime.stop" | "runtime.result" | "model.control" | "cli.progress")
}

pub(crate) fn admitted_list() -> Value {
    let items = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
    Value::Array(
        items
            .iter()
            .map(|item| {
                json!({
                    "operation_id": item.operation_id,
                    "kind": item.kind,
                })
            })
            .collect(),
    )
}

fn unfinished_admitted() -> Vec<Admitted> {
    ADMISSIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

fn busy_background() -> Vec<&'static str> {
    let mut busy = Vec::new();
    if WRITE_RUNNING.load(Ordering::Acquire) {
        busy.push("write");
    }
    if CLASSIFY_RUNNING.load(Ordering::Acquire) {
        busy.push("classify");
    }
    if sync_running() {
        busy.push("sync");
    }
    if index_has_work() {
        busy.push("index");
    }
    if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) {
        busy.push("model_switch");
    }
    busy
}

enum WriteJob {
    Command(Job),
    Prepare(PrepareJob),
    RecallStats(RecallStats, usize, AdmissionGuard),
}

struct PrepareJob {
    job: Job,
    operation_id: String,
    operation: crate::model_progress::Operation,
}

pub fn enqueue_recall_stats_local(stats: RecallStats, generation: usize) {
    if respire_app::service::workspace_mode() != "normal" {
        return;
    }
    if STATS_PENDING
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
            (pending < MAX_PENDING_STATS).then_some(pending + 1)
        })
        .is_err()
    {
        STATS_REJECTED.fetch_add(1, Ordering::AcqRel);
        eprintln!("recall statistics rejected: pending statistics limit reached");
        return;
    }
    let queued = (|| -> Result<()> {
        check_sync_context(generation)?;
        let tx = WRITE_TX
            .lock()
            .map_err(|_| anyhow::anyhow!("write queue lock poisoned"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("write worker is not running"))?;
        let gate = shared_exclusive();
        gate.reserve();
        let Some(admission) = begin_admission(uuid::Uuid::new_v4().to_string(), "background_write")
        else {
            gate.cancel_reservation();
            return Err(anyhow::anyhow!("runtime is draining"));
        };
        match tx.try_send(WriteJob::RecallStats(stats, generation, admission)) {
            Ok(()) => Ok(()),
            Err(error) => {
                gate.cancel_reservation();
                match error {
                    mpsc::TrySendError::Full(_) => bail!("write request queue is full"),
                    mpsc::TrySendError::Disconnected(_) => bail!("write worker is gone"),
                }
            }
        }
    })();
    match queued {
        Ok(()) => {
            STATS_ENQUEUED.fetch_add(1, Ordering::AcqRel);
        }
        Err(error) => {
            STATS_PENDING.fetch_sub(1, Ordering::AcqRel);
            STATS_REJECTED.fetch_add(1, Ordering::AcqRel);
            eprintln!("recall statistics rejected: {error:#}");
        }
    }
}

pub fn sync_scheduler_status() -> Value {
    let state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
    let blocked = state.blocked_generation == Some(GENERATION.load(Ordering::Acquire));
    let phase = if sync_running() {
        "running"
    } else if blocked {
        "blocked"
    } else if state.backoff > 0 {
        "backoff"
    } else if state.due.is_some() {
        "scheduled"
    } else {
        "idle"
    };
    json!({"state":phase, "next_run_ms":state.due.map(|due| due.saturating_duration_since(Instant::now()).as_millis() as u64),
        "manual_waiters":state.manual.len(), "last_success_unix":state.last_success})
}

pub fn context_changed() {
    if let Err(error) = respire_app::resident::clear() {
        eprintln!("resident catalog reset failed: {error:#}");
    }
    let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
    state.blocked_generation = None;
    state.backoff = 0;
    state.due = Some(Instant::now() + Duration::from_secs(3));
    drop(state);
    SYNC_CV.notify_one();
    kick_index();
}

static PROFILE_SWITCH_RUNNING: AtomicBool = AtomicBool::new(false);

static PROFILE_ADMISSION: Mutex<()> = Mutex::new(());
static PROFILE_SWITCH_STATE: Mutex<Value> = Mutex::new(Value::Null);

fn profile_state() -> Value {
    PROFILE_SWITCH_STATE
        .lock()
        .map(|v| v.clone())
        .unwrap_or_else(|_| json!({"state":"failed","error":"switch state lock poisoned"}))
}
fn set_profile_state(value: Value) {
    if let Ok(mut slot) = PROFILE_SWITCH_STATE.lock() {
        *slot = value;
    }
}
fn start_profile_switch(
    choice: respire_app::embedding::Choice,
    request: &RpcRequest,
    identity: &OperationIdentity,
) -> Result<RpcResponse> {
    anyhow::ensure!(
        !respire_app::service::service_paused() && !crate::host_hooks::background_paused(),
        "model switching is paused by service mode"
    );
    start_profile_switch_target(respire_app::embedding::select(choice)?, request, identity)
}
fn start_profile_switch_target(
    mut target: respire_app::core_sdk::profiles::Selection,
    request: &RpcRequest,
    identity: &OperationIdentity,
) -> Result<RpcResponse> {
    anyhow::ensure!(
        !respire_app::service::service_paused() && !crate::host_hooks::background_paused(),
        "model switching is paused by service mode"
    );
    target.validate()?;
    let task_id = identity.operation_id.clone();
    let scope = identity.scope.clone();
    let epoch = scope_generation(&scope).map_err(anyhow::Error::msg)?;
    let completion_admission = begin_admission(task_id.clone(), "model_switch")
        .context("runtime is draining and rejected new business")?;
    let library = respire_app::service::data_dir();
    let admission = PROFILE_ADMISSION
        .lock()
        .map_err(|_| anyhow::anyhow!("model admission lock poisoned"))?;
    anyhow::ensure!(
        PROFILE_SWITCH_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        "another model switch is running"
    );
    let operation = match crate::model_progress::Operation::reserve_task(task_id.clone()) {
        Ok(operation) => operation,
        Err(error) => {
            PROFILE_SWITCH_RUNNING.store(false, Ordering::Release);
            return Err(error);
        }
    };
    let queued = (|| -> Result<()> {
        check_sync_context(epoch)?;
        let store = respire_app::service::open_store()?;
        anyhow::ensure!(
            library == respire_app::service::data_dir(),
            "model switch library changed before acceptance"
        );
        store.queue_selection(&target, &task_id)
    })();
    if let Err(error) = queued {
        PROFILE_SWITCH_RUNNING.store(false, Ordering::Release);
        return Err(error);
    }
    drop(admission);
    let pending = json!({"id":task_id,"state":"pending","target":target.model,"active_changed":false,"semantic":"busy"});
    set_profile_state(pending.clone());
    let mut response = status_response(request);
    response.operation_id = Some(task_id.clone());
    response.envelope = Some(ResultEnvelope::new(
        &request.method, OutputStatus::Pending, pending, Vec::new(),
    ));
    // Publish Pending before the worker can fail or finish, including before it takes the gate.
    remember(&identity.storage_id, &response);
    let reply = deferred_reply(request, identity, completion_admission);
    let method = request.method.clone();
    let spawn = std::thread::Builder::new().name("respire-model-switch".into()).stack_size(16 * 1024 * 1024).spawn(move || {
        struct Finish;
        impl Drop for Finish { fn drop(&mut self) { PROFILE_SWITCH_RUNNING.store(false,Ordering::Release); } }
        let _finish = Finish;
        operation.enter_thread();
        let _operation = operation;
        let _scope = crate::model_progress::TaskScope::new(Some(task_id.clone()));
        let result = (|| -> Result<Value> {
            crate::model_progress::update("switch-verify",&target.model,0,None)?;
            let waiting = Instant::now();
            while RUNNING.load(Ordering::Acquire).saturating_sub(RUNNING_STATUS.load(Ordering::Acquire)) > 0 || CLASSIFY_RUNNING.load(Ordering::Acquire) || sync_running() {
                check_sync_context(epoch)?;
                crate::model_progress::check()?;
                anyhow::ensure!(waiting.elapsed() < Duration::from_secs(1800),"model switch timed out draining in-flight requests");
                std::thread::sleep(Duration::from_millis(25));
            }
            let _identity = SCOPE_EXECUTION.read()
                .map_err(|_| anyhow::anyhow!("scope_mismatch: identity fence poisoned"))?;
            let gate = shared_exclusive();
            let _write = gate.acquire(true);
            validate_job_scope(&scope).map_err(anyhow::Error::msg)?;
            check_sync_context(epoch)?;
            anyhow::ensure!(library == respire_app::service::data_dir(), "model switch library changed");
            let store = respire_app::service::open_store()?;
            let previous = store.active_selection()?;
            let source_revision = store.meta_get("memory_revision_v1")?.context("source revision unavailable")?;
            let keys = crate::engine::build_session()?;
            store.meta_set("embedding_pending_task_v1",&serde_json::to_string(&json!({"id":task_id,"phase":"prepare"}))?)?;
            check_sync_context(epoch)?;
            crate::model_progress::check()?;
            crate::model_install::verify_selection_assets(&target)?;
            check_sync_context(epoch)?;
            crate::model_progress::check()?;
            target.generation = respire_app::core_sdk::profiles::generation_key_for_profile(&target)?;
            store.meta_set("embedding_pending_selection_v1",&serde_json::to_string(&target)?)?;
            respire_app::core_sdk::profiles::exclusive(|| {
                let attempt = respire_app::core_sdk::profiles::scoped(target.clone(), || {
                    store.meta_set("embedding_pending_task_v1",&serde_json::to_string(&json!({"id":task_id,"phase":"load"}))?)?;
                    crate::model_progress::update("switch-load",&target.model,0,None)?;
                    respire_app::core_sdk::profiles::load(&target)?;
                    crate::model_progress::check()?;
                    let embedder = respire_app::memory::bge::BgeEmbedder::load_model(&target.model)?;
                    store.meta_set("embedding_pending_task_v1",&serde_json::to_string(&json!({"id":task_id,"phase":"main-index"}))?)?;
                    store.build_index_with_progress(&keys,&embedder,&target.model,false,|done,total| {
                        check_sync_context(epoch)?;
                        crate::model_progress::update("switch-index",&target.model,done as u64,Some(total as u64))
                    })?;
                    store.meta_set("embedding_pending_task_v1",&serde_json::to_string(&json!({"id":task_id,"phase":"diary-index"}))?)?;
                    respire_app::diary::rebuild_with_progress(&store,&keys,&embedder,
                        || { check_sync_context(epoch)?; crate::model_progress::check() },
                        |action| { check_sync_context(epoch)?; crate::model_progress::commit(action) },
                        |done| crate::model_progress::update("switch-diary",&target.model,done as u64,None))?;
                    check_sync_context(epoch)?;
                    anyhow::ensure!(library == respire_app::service::data_dir(), "model switch library changed");
                    anyhow::ensure!(!store.index_pending(&target.model)? && !respire_app::diary::needs_rebuild(&store)?, "candidate index/source validation failed");
                    respire_app::resident::clear()?;
                    *crate::engine::EMBEDDER_SLOT.lock().map_err(|_|anyhow::anyhow!("embedder cache poisoned"))? = None;
                    crate::model_progress::commit_final(|| store.activate_selection(&target,&source_revision))?;
                    Ok(())
                });
                if let Err(error) = attempt {
                    let restored = match previous {
                        Some(ref selection) => respire_app::core_sdk::profiles::load(selection).map(|_| ()),
                        None => {
                            respire_app::core_sdk::profiles::set_active(None);
                            respire_app::memory::onnx::reset_sessions().and_then(|_| respire_app::memory::bge::BgeEmbedder::load_model("m3")?.probe("Respire rollback verification").map(|_| ()))
                        }
                    };
                    return match restored {
                        Ok(()) => Err(anyhow::anyhow!("model switch failed: {error:#}; previous selection restored and trial inference passed")),
                        Err(recovery) => Err(anyhow::anyhow!("recovery_failed: model switch failed: {error:#}; previous model reload failed: {recovery:#}; semantic availability is unverified")),
                    };
                }
                respire_app::core_sdk::profiles::set_active(Some(target.clone()));
                Ok(json!({"selection":target,"active_changed":true,"semantic":"ready"}))
            })
        })();
        let final_state = match &result {
            Ok(result) => json!({"id":task_id,"state":"ready","active_changed":true,"semantic":"ready","result":result}),
            Err(error) => json!({"id":task_id,"state":"failed","active_changed":false,"error":format!("{error:#}"),"semantic":if format!("{error:#}").contains("recovery_failed") {"unverified"} else if format!("{error:#}").contains("previous selection restored and trial inference passed") {"previous_ready"} else {"unchanged"}}),
        };
        set_profile_state(final_state.clone());
        let completion = result.map(|_| crate::output_state::Captured {
            exit: 0,
            envelope: ResultEnvelope::new(&method, OutputStatus::Ok, final_state, Vec::new()),
        }).map_err(|error| format!("{error:#}"));
        let _ = reply.send(completion);
        kick_index();
    });
    if let Err(error) = spawn {
        PROFILE_SWITCH_RUNNING.store(false, Ordering::Release);
        set_profile_state(
            json!({"state":"failed","active_changed":false,"error":error.to_string()}),
        );
        return Err(error.into());
    }
    Ok(response)
}

pub fn sync_running() -> bool {
    SYNC_RUNNING.load(Ordering::Acquire)
}

fn ensure_sync_worker() {
    if FLIGHT_ON
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    if std::thread::Builder::new()
        .name("respire-sync".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(flight_loop)
        .is_err()
    {
        FLIGHT_ON.store(false, Ordering::Release);
        eprintln!("command=sync status=warn error=failed to start sync worker");
    }
}

/// Notifications are hints; the durable outbox holds the work.
pub fn kick_autosync() {
    let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
    if state.due.is_none() {
        state.due = Some(Instant::now() + Duration::from_secs(3));
    }
    drop(state);
    SYNC_CV.notify_one();
    ensure_sync_worker();
}

fn enqueue_manual(job: Job) {
    let captured = job
        .sync_context
        .ok_or_else(|| anyhow::anyhow!("missing sync request context"));
    match captured {
        Ok((generation, boundary)) => {
            let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
            if state.manual.len() >= 64 {
                let _ = job.reply.send(Err("sync request queue is full".into()));
                return;
            }
            state.manual.push_back((job, generation, boundary));
            drop(state);
            SYNC_CV.notify_one();
            ensure_sync_worker();
        }
        Err(error) => {
            let _ = job.reply.send(Err(format!("{error:#}")));
        }
    }
}

fn flight_loop() {
    mark_worker();
    loop {
        let manual = {
            let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if STOPPING.load(Ordering::Acquire) {
                    for (job, _, _) in state.manual.drain(..) {
                        let _ = job.reply.send(Err("runtime is stopping".into()));
                    }
                    FLIGHT_ON.store(false, Ordering::Release);
                    return;
                }
                if crate::host_hooks::background_paused() {
                    state = SYNC_CV
                        .wait_timeout(state, Duration::from_millis(250))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                    continue;
                }
                if let Some(job) = state.manual.pop_front() {
                    break Some(job);
                }
                let current_generation = GENERATION.load(Ordering::Acquire);
                if state.blocked_generation == Some(current_generation) {
                    state = SYNC_CV.wait(state).unwrap_or_else(|e| e.into_inner());
                    continue;
                }
                state.blocked_generation = None;
                let now = Instant::now();
                let due = state.due.get_or_insert(now + Duration::from_secs(300));
                if *due <= now {
                    state.due = None;
                    break None;
                }
                let wait = *due - now;
                state = SYNC_CV
                    .wait_timeout(state, wait)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        };
        let admission = PROFILE_ADMISSION
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) {
            if let Some((job, _, _)) = manual {
                let _ = job.reply.send(Err("model_switch_busy".into()));
            } else {
                SYNC_KICK
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .due = Some(Instant::now() + Duration::from_secs(1));
            }
            drop(admission);
            continue;
        }
        SYNC_RUNNING.store(true, Ordering::Release);
        drop(admission);
        if let Some((job, generation, boundary)) = manual {
            let _scope_held = match SCOPE_EXECUTION.read() {
                Ok(held) => held,
                Err(_) => {
                    let _ = job.reply.send(Err("scope_mismatch: identity fence poisoned".into()));
                    SYNC_RUNNING.store(false, Ordering::Release);
                    continue;
                }
            };
            let boundary = if boundary < 0 {
                let gate = shared_exclusive();
                let held = gate.acquire(true);
                let snapshot = if job.deadline.expired() {
                    Err(anyhow::anyhow!(QUEUE_EXPIRED))
                } else {
                    validate_job_scope(&job.scope).map_err(anyhow::Error::msg)
                        .and_then(|_| check_sync_context(generation))
                        .and_then(|_| crate::engine::build_local())
                        .and_then(|store| store.outgoing_boundary())
                };
                drop(held);
                match snapshot {
                    Ok(boundary) => boundary,
                    Err(error) => {
                        let _ = job.reply.send(Err(format!("{error:#}")));
                        SYNC_RUNNING.store(false, Ordering::Release);
                        continue;
                    }
                }
            } else {
                boundary
            };
            if !job.deadline.start() {
                let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                SYNC_RUNNING.store(false, Ordering::Release);
                continue;
            }
            SYNC_CONTEXT.with(|context| context.set(Some((generation, boundary))));
            let result = capture_scoped_locked(&job.scope, job.args);
            if result.as_ref().is_ok_and(|captured| captured.exit == 0) {
                let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
                state.blocked_generation = None;
                state.backoff = 0;
            }
            let _ = job.reply.send(result.map_err(|error| format!("{error:#}")));
        } else {
            let generation = GENERATION.load(Ordering::Acquire);
            let boundary = sync_local(generation, || {
                anyhow::ensure!(
                    !respire_app::service::service_paused(),
                    "background sync paused by service mode"
                );
                crate::engine::build_local()?.outgoing_boundary()
            });
            let result = boundary.and_then(|boundary| {
                SYNC_CONTEXT.with(|context| context.set(Some((generation, boundary))));
                crate::engine::background_sync_once()
            });
            let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
            match result {
                Ok(synchronized) => {
                    state.backoff = 0;
                    state.blocked_generation = None;
                    if synchronized {
                        state.last_success = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|v| v.as_secs());
                    }
                }
                Err(error)
                    if error
                        .downcast_ref::<respire_app::sync::SyncBoundaryChanged>()
                        .is_some() =>
                {
                    state.backoff = 0;
                    state.blocked_generation = None;
                    state.due = Some(Instant::now() + Duration::from_secs(3));
                    eprintln!("command=sync status=warn mode=auto error={error}");
                }
                Err(error) if generation != GENERATION.load(Ordering::Acquire) => {
                    state.backoff = 0;
                    eprintln!("command=sync status=warn mode=auto error={error}");
                }
                Err(error) => {
                    let transport = crate::sync_flow::is_retriable_sync_error(&error);
                    let delay = if transport {
                        30_u64.saturating_mul(1 << state.backoff.min(4)).min(300)
                    } else {
                        300
                    };
                    state.backoff = state.backoff.saturating_add(1);
                    if transport {
                        state.due = Some(Instant::now() + Duration::from_secs(delay));
                    } else {
                        state.blocked_generation = Some(generation);
                        state.due = None;
                    }
                    eprintln!("command=sync status=warn mode=auto error={error}");
                }
            }
        }
        SYNC_CONTEXT.with(|context| context.set(None));
        SYNC_RUNNING.store(false, Ordering::Release);
        kick_index();
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeFlags {
    pub port: Option<u16>,
    pub host: String,
    pub status: bool,
    pub stop: bool,
}

pub use respire_protocol::RpcRequest;
pub type RpcResponse = respire_protocol::RpcResponse<ResultEnvelope>;

pub struct Job {
    pub scope: RuntimeRequestScope,
    pub args: Vec<String>,
    pub stop: bool,
    pub reply: Reply,
    pub sync_context: Option<(usize, i64)>,
    pub deadline: Arc<crate::admission::QueueDeadline>,
}

type CommandResult = std::result::Result<crate::output_state::Captured, String>;
type ReplyAction = Box<dyn FnOnce(CommandResult) + Send>;

/// A queued transport owns its reply without keeping a connection thread alive.
#[derive(Clone)]
pub struct Reply(Arc<Mutex<Option<ReplyAction>>>);
impl Reply {
    pub fn new(action: impl FnOnce(CommandResult) + Send + 'static) -> Self {
        Self(Arc::new(Mutex::new(Some(Box::new(action)))))
    }
    pub fn send(&self, result: CommandResult) -> std::result::Result<(), String> {
        let action = self
            .0
            .lock()
            .map_err(|_| "reply lock poisoned".to_owned())?
            .take();
        let action = action.ok_or_else(|| "reply already delivered".to_owned())?;
        action(result);
        Ok(())
    }
}

struct QueueWatch {
    deadline: std::sync::Weak<crate::admission::QueueDeadline>,
    reply: std::sync::Weak<Mutex<Option<ReplyAction>>>,
}

fn watch_queue(deadline: &Arc<crate::admission::QueueDeadline>, reply: &Reply) -> Result<()> {
    static WATCH: OnceLock<Mutex<Vec<QueueWatch>>> = OnceLock::new();
    let entries = WATCH.get_or_init(|| Mutex::new(Vec::new()));
    static STARTED: OnceLock<()> = OnceLock::new();
    let network = crate::network::runtime()?;
    STARTED.get_or_init(|| {
        network.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            loop {
                tick.tick().await;
                let mut expired = Vec::new();
                {
                    let mut entries = entries.lock().unwrap_or_else(|error| error.into_inner());
                    entries.retain(|entry| {
                        let Some(deadline) = entry.deadline.upgrade() else {
                            return false;
                        };
                        if deadline.expired() {
                            if let Some(reply) = entry.reply.upgrade() {
                                expired.push(Reply(reply));
                            }
                            false
                        } else {
                            !deadline.running()
                        }
                    });
                }
                // Reply actions only hand off in-memory results or spawn async I/O.
                for reply in expired {
                    let _ = reply.send(Err(QUEUE_EXPIRED.into()));
                }
            }
        });
    });
    entries
        .lock()
        .map_err(|_| anyhow::anyhow!("queue watch lock poisoned"))?
        .push(QueueWatch {
            deadline: Arc::downgrade(deadline),
            reply: Arc::downgrade(&reply.0),
        });
    Ok(())
}

pub fn serve(flags: RuntimeFlags) -> Result<()> {
    respire_app::service::validate_client_config()?;
    validate_process_identity()?;
    crate::runtime_policy::require_host("runtime startup")?;
    // Ignore SIGHUP off this thread. signal_hook's handler install must not sit
    // in front of bind: under llvm-cov that call can stall the thread that has
    // to become the listener, and the coverage run then never sees the runtime.
    #[cfg(unix)]
    {
        let _ = std::thread::Builder::new()
            .name("respire-sighup".into())
            .spawn(|| {
                let _ = signal_hook::flag::register(
                    signal_hook::consts::SIGHUP,
                    Arc::new(AtomicBool::new(false)),
                );
            });
    }
    // Children only bind. The host caller owns stop/copy/upgrade decisions.
    if probe_runtime()?.is_some() {
        return Ok(());
    }
    // Keep installation ownership for the listener's entire lifetime. A port
    // override must not start a second host for the same installation or replace
    // its endpoint record, which the former local-socket name also prevented.
    let _owner =
        match respire_app::lock::LibraryLock::acquire(&runtime_dir(), Duration::from_secs(15)) {
            Ok(owner) => owner,
            Err(error) => {
                // Another host may have completed startup while this caller waited.
                if probe_runtime()?.is_some() {
                    return Ok(());
                }
                return Err(error).context("another runtime owns this installation");
            }
        };
    if probe_runtime()?.is_some() {
        return Ok(());
    }
    // Acquire the existing library ownership before publishing readiness. This
    // also guards an older runtime using another port, and direct-mode clients.
    let library = respire_app::lock::LibraryLock::acquire(
        &respire_app::service::data_dir(),
        Duration::from_secs(120),
    )
    .context("runtime failed to lock the library")?;
    crate::host_hooks::verify_managed_boot()?;
    // Probe and bind only the existing loopback HTTP/TCP transport; no legacy
    // pipe/socket fallback is necessary.
    let bound = crate::runtime_http::bind_runtime(flags.port, &flags.host)?;
    {
        let mut url = WEB_URL.lock().unwrap_or_else(|err| err.into_inner());
        *url = bound.url.clone();
    }
    let publication = crate::rpc_worker::publish_endpoint(&bound.url)?;
    let owner = Arc::new(Mutex::new(_owner));
    let (tx, rx) = mpsc::channel();
    let _ = JOB_TX.set(Mutex::new(tx.clone()));
    // Sandboxed clients cannot restart an idle-exited host runtime.
    let idle = None;
    let limit = worker_limit();
    WORKERS.store(limit, Ordering::Release);
    RUNNING.store(0, Ordering::Release);
    let startup = StartupEndpoint { owner: owner.clone(), publication: publication.clone() };
    if let Err(error) = std::thread::Builder::new()
        .name("respire-dispatch".into())
        // Services do not inherit a terminal's RUST_MIN_STACK. Context-query
        // parsing needs the same explicit stack as the command workers.
        .stack_size(16 * 1024 * 1024)
        .spawn(move || dispatch_loop_inner(rx, limit, idle, library, Some(startup)))
    {
        StartupEndpoint { owner: owner.clone(), publication }.revoke();
        return Err(error).context("failed to start the runtime dispatcher");
    }
    // Keep the host entry alive on its actual listener. Drain/worker shutdown
    // retains its existing ownership and process-exit path in dispatch_loop.
    crate::runtime_http::serve_loop(bound.server)
}

pub fn dispatch(request: RpcRequest, tx: &Sender<Job>) -> RpcResponse {
    dispatch_inner(request, tx, false)
}

fn dispatch_inner(request: RpcRequest, tx: &Sender<Job>, legacy: bool) -> RpcResponse {
    if request.v != PROTOCOL_V {
        return error_response(
            &request,
            "protocol_version_mismatch",
            "protocol version mismatch",
        );
    }
    if request.id.trim().is_empty()
        || request.id.len() > 256
        || request.id.chars().any(char::is_whitespace)
    {
        return error_response(
            &request,
            "invalid_request_id",
            "request ID must contain 1 to 256 characters and no whitespace",
        );
    }
    if let Err((code, error)) = validate_request_scope(&request) {
        return error_response(&request, &code, &error);
    }
    if matches!(request.method.as_str(), "model.prepare" | "index.prepare")
        && crate::host_hooks::background_paused()
    {
        return error_response(
            &request,
            "runtime_maintenance",
            "runtime maintenance pauses model/index preparation",
        );
    }
    if request.method == "cli.exec"
        && PROFILE_SWITCH_RUNNING.load(Ordering::Acquire)
        && !is_status(&request.args)
    {
        return error_response(
            &request,
            "model_switch_busy",
            "model switch in progress; semantic queries and writes are paused; inspect model.progress",
        );
    }
    let operation = if (legacy && request.method != "runtime.result") || !matches!(
        request.method.as_str(),
        "runtime.result"
            | "runtime.status"
            | "runtime.stop"
            | "assets.status"
            | "cli.progress"
            | "model.catalog"
            | "model.progress"
    ) {
        match operation_identity_mode(&request, legacy) {
            Ok(operation) => Some(operation),
            Err((code, error)) => return error_response(&request, &code, &error),
        }
    } else {
        None
    };
    let _admission = if let Some(operation) = operation.as_ref() {
        Some(match admit_with_retention(&request, operation, legacy) {
            Ok(Admission::New(guard)) => guard,
            Ok(Admission::Replay(response)) => return response,
            Ok(Admission::InProgress) => {
                return error_response(
                    &request,
                    "request_in_progress",
                    "operation ID is already executing or queued; inspect runtime.result; command was not replayed",
                )
            }
            Ok(Admission::Unknown) => {
                return error_response(
                    &request,
                    "result_unknown",
                    "operation was admitted but its in-memory receipt is unavailable; non-idempotent writes are not replayed",
                )
            }
            Err((code, error)) => return error_response(&request, &code, &error),
        })
    } else {
        None
    };
    let _scope_held = if request.method == "runtime.result"
        || (operation.is_some() && request.method != "cli.exec")
    {
        let held = if request.method == "runtime.result" {
            SCOPE_EXECUTION.try_read().map_err(|_| ())
        } else {
            SCOPE_EXECUTION.read().map_err(|_| ())
        };
        match held {
            Ok(held) => Some(held),
            Err(_) => {
                let response = error_response(&request, "scope_mismatch", "identity fence poisoned");
                if let Some(operation) = &operation {
                    remember(&operation.storage_id, &response);
                    INFLIGHT.lock().unwrap_or_else(|error| error.into_inner()).remove(&operation.storage_id);
                }
                return response;
            }
        }
    } else { None };
    #[cfg(test)]
    tests::wait_before_direct_gate(&request.id);
    let gate = shared_exclusive();
    let _held = if operation.is_some() && !matches!(request.method.as_str(), "cli.exec" | "model.control" | "cli.progress") {
        Some(gate.acquire(true))
    } else {
        None
    };
    let mut deferred_operation = false;
    let response = (|| {
        // Recheck after waiting for the execution gate, including unscoped reads.
        if !maintenance_control_method(&request.method) && business_paused() {
            return error_response(&request, "runtime_maintenance", "runtime maintenance rejected business execution");
        }
        if operation.is_some() || request.method == "runtime.result" {
            let _fence = match ADMISSIONS.lock() {
                Ok(fence) => fence,
                Err(_) => return error_response(&request, "admission_lock_poisoned", "runtime admission lock is poisoned"),
            };
            let current = match request_current_scope(&request) {
                Ok(current) => current,
                Err((code, error)) => return error_response(&request, &code, &error),
            };
            if let Err((code, error)) = validate_scope(request.scope.as_ref(), &current) {
                return error_response(&request, &code, &error);
            }
            // Direct handlers do not pass through the queued-command boundary.
            // Recheck the same host binding after any execution-gate wait.
            if let Err(error) = crate::legacy_host::verify_execution(&current) {
                return error_response(&request, "legacy_host_binding_changed", &format!("{error:#}"));
            }
        }
        match request.method.as_str() {
        #[cfg(feature = "native-fault-tests")]
        "runtime.test_worker_lifecycle" => {
            let action = request.args.first().map(String::as_str).unwrap_or("");
            match respire_app::core_sdk::worker::fixture_control(action) {
                Ok(result) => {
                    let mut response = status_response(&request);
                    response.envelope = Some(ResultEnvelope::new(
                        "runtime.test_worker_lifecycle",
                        OutputStatus::Ok,
                        result,
                        Vec::new(),
                    ));
                    response
                }
                Err(error) => {
                    error_response(&request, "worker_fixture_failed", &format!("{error:#}"))
                }
            }
        }
        #[cfg(feature = "native-fault-tests")]
        "runtime.test_worker_hold" => {
            match respire_app::core_sdk::execute::<Value>("test_worker_hold", json!({})) {
                Ok(_) => status_response(&request),
                Err(error) => {
                    error_response(&request, "worker_fixture_failed", &format!("{error:#}"))
                }
            }
        }
        #[cfg(feature = "native-fault-tests")]
        "runtime.test_native_fault" => {
            let mode = request
                .args
                .first()
                .and_then(|mode| mode.parse::<u64>().ok())
                .unwrap_or(0);
            match respire_app::core_sdk::execute::<Value>(
                "engine_control",
                json!({"action":"test_native_fault","mode":mode}),
            ) {
                Ok(result) => {
                    let mut response = status_response(&request);
                    response.envelope = Some(ResultEnvelope::new(
                        "runtime.test_native_fault",
                        OutputStatus::Ok,
                        result,
                        Vec::new(),
                    ));
                    response
                }
                Err(error) => {
                    error_response(&request, "native_fixture_failed", &format!("{error:#}"))
                }
            }
        }
        "model.catalog" | "model.configure" | "model.switch" | "model.resume"
        | "model.progress" => {
            let result = (|| -> Result<RpcResponse> {
                let value = match request.method.as_str() {
                    "model.catalog" => {
                        let store = respire_app::service::open_store()?;
                        Ok(
                            json!({"registry":respire_app::embedding::registry()?,"active":store.active_selection()?,"switch":profile_state()}),
                        )
                    }
                    "model.configure" => {
                        let config = serde_json::from_str(
                            request
                                .args
                                .first()
                                .context("configuration JSON required")?,
                        )?;
                        respire_app::embedding::configure(config)
                    }
                    "model.switch" => {
                        let choice = serde_json::from_str(
                            request.args.first().context("selection JSON required")?,
                        )?;
                        let response = start_profile_switch(
                            choice,
                            &request,
                            operation.as_ref().context("model switch requires an operation")?,
                        )?;
                        deferred_operation = true;
                        return Ok(response);
                    }
                    "model.resume" => {
                        let store = respire_app::service::open_store()?;
                        let target = serde_json::from_str(
                            &store
                                .meta_get("embedding_pending_selection_v1")?
                                .context("no pending model selection")?,
                        )?;
                        let response = start_profile_switch_target(
                            target,
                            &request,
                            operation.as_ref().context("model resume requires an operation")?,
                        )?;
                        deferred_operation = true;
                        return Ok(response);
                    }
                    _ => {
                        let store = respire_app::service::open_store()?;
                        Ok(
                            json!({"switch":profile_state(),"operation":crate::model_progress::status()?,"pending_selection":store.meta_get("embedding_pending_selection_v1")?.map(|v|serde_json::from_str::<Value>(&v)).transpose()?,"pending_task":store.meta_get("embedding_pending_task_v1")?.map(|v|serde_json::from_str::<Value>(&v)).transpose()?}),
                        )
                    }
                }?;
                let mut response = status_response(&request);
                response.envelope = Some(ResultEnvelope::new(
                    &request.method, OutputStatus::Ok, value, Vec::new(),
                ));
                Ok(response)
            })();
            match result {
                Ok(response) => response,
                Err(error) => {
                    error_response(&request, "model_profile_failed", &format!("{error:#}"))
                }
            }
        }
        "model.prepare" => {
            let mirror = request.args.first().map(String::as_str).unwrap_or("auto");
            let result = (|| -> Result<RpcResponse> {
                crate::model_install::validate_mirror(mirror)?;
                anyhow::ensure!(!respire_app::service::service_paused(), "model preparation is paused by service mode");
                let operation = operation.as_ref().context("model preparation requires an operation")?;
                let mut response = status_response(&request);
                response.operation_id = Some(operation.operation_id.clone());
                response.envelope = Some(ResultEnvelope::new(
                    "model.prepare", OutputStatus::Pending,
                    json!({"state":"scheduled", "operation_id":operation.operation_id}), Vec::new(),
                ));
                // The dispatch gate prevents execution before this pending receipt exists.
                remember(&operation.storage_id, &response);
                enqueue_prepare(&request, operation)?;
                deferred_operation = true;
                Ok(response)
            })();
            match result {
                Ok(response) => response,
                Err(error) => error_response(&request, "model_prepare_failed", &format!("{error:#}")),
            }
        }
        "index.prepare" => {
            kick_index();
            let mut response = status_response(&request);
            response.envelope = Some(ResultEnvelope::new(
                "index.prepare",
                OutputStatus::Pending,
                index_status(),
                Vec::new(),
            ));
            response
        }
        "model.control" => {
            // Cancellation must remain callable while a scoped prepare holds the write gate.
            let _fence = match ADMISSIONS.lock() {
                Ok(fence) => fence,
                Err(_) => return error_response(&request, "admission_lock_poisoned", "runtime admission lock is poisoned"),
            };
            if let Err((code, error)) = validate_scope(request.scope.as_ref(), &current_scope()) {
                return error_response(&request, &code, &error);
            }
            match crate::model_progress::control(
                request.args.first().map(String::as_str).unwrap_or(""),
                request.args.get(1).is_some_and(|arg| arg == "true"),
            ) {
                Ok(progress) => {
                    let mut response = status_response(&request);
                    response.envelope = Some(ResultEnvelope::new(
                        "model.control", OutputStatus::Ok, progress, Vec::new(),
                    ));
                    response
                }
                Err(error) => error_response(&request, "model_control_failed", &error.to_string()),
            }
        },
        "runtime.status" => {
            let mut response = status_response(&request);
            response.envelope = Some(ResultEnvelope::new(
                "runtime.status",
                OutputStatus::Ok,
                json!({
                    "state": control_state(),
                    "operation_id": STOP_OPERATION.get(),
                    "admitted": admitted_list(),
                    "background": busy_background(),
                    "unfinished": stop_unfinished(),
                }),
                Vec::new(),
            ));
            response
        }
        "assets.status" => match crate::model_install::assets_status() {
            Ok(status) => match serde_json::to_value(status) {
                Ok(value) => {
                    let mut response = status_response(&request);
                    response.envelope = Some(ResultEnvelope::new(
                        "assets.status",
                        OutputStatus::Ok,
                        value,
                        Vec::new(),
                    ));
                    response
                }
                Err(error) => error_response(&request, "asset_status_failed", &error.to_string()),
            },
            Err(error) => error_response(&request, "asset_status_failed", &format!("{error:#}")),
        },
        "cli.progress" => {
            let mut response = status_response(&request);
            let mut summary =
                crate::progress::status(request.args.first().map(String::as_str).unwrap_or(""));
            if summary.is_null() {
                summary = json!({});
            }
            summary["inference"] = inference_health_status();
            response.envelope = Some(ResultEnvelope::new(
                "cli.progress",
                OutputStatus::Ok,
                summary,
                Vec::new(),
            ));
            response
        }
        "runtime.result" => {
            let id = request.args.first().map(String::as_str).unwrap_or("");
            let Some(scope) = request.scope.as_ref() else {
                return error_response(&request, "scope_required", "result queries require scope");
            };
            let storage_id = if legacy { legacy_operation_key(scope, id) }
                else { scoped_operation_key(&operation_scope(scope), id) };
            let result = cached(&storage_id);
            let pending = INFLIGHT
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains(&storage_id);
            let state = result_state(result.as_ref(), pending);
            let mut response = status_response(&request);
            let mut summary = json!({"request_id":request.id,"operation_id":id,"scope":scope,
                "state":state,"response":result,
                "retention":"last 64 receipts; up to 4096 admission identities until runtime exit; account-directory and generation scoped; unknown is not proof of non-commit; never replay a write automatically"});
            if let Some(key) = &request.idempotency_key {
                summary["idempotency_key"] = json!(key);
            }
            response.envelope = Some(ResultEnvelope::new(
                "runtime.result",
                OutputStatus::Ok,
                summary,
                Vec::new(),
            ));
            response
        }
        "runtime.stop" => {
            if crate::host_hooks::managed_id().is_some()
                && request.lifecycle.as_deref() != Some("coordinator-v1")
            {
                error_response(
                    &request,
                    "managed_lifecycle_required",
                    "use the current host runtime lifecycle coordinator",
                )
            } else {
                error_response(
                    &request,
                    "stop_identity_required",
                    "use the lifecycle stop endpoint with the exact instance, account and generation",
                )
            }
        }
        "cli.exec" => match submit_scoped(tx, request.args.clone(), false,
            operation.as_ref().map_or_else(|| request.id.clone(), |op| op.operation_id.clone()),
            request.scope.clone()) {
            Ok(captured) => RpcResponse {
                v: PROTOCOL_V,
                id: request.id.clone(),
                operation_id: operation.as_ref().map(|item| item.operation_id.clone()),
                scope: request.scope.clone(),
                idempotency_key: request.idempotency_key.clone(),
                ok: captured.exit == 0,
                exit: captured.exit,
                bin: bin_version().to_owned(),
                envelope: Some(captured.envelope),
                error: None,
                code: None,
                web_url: Some(current_url()),
                pid: Some(std::process::id()),
                data_dir: Some(respire_app::service::data_dir().display().to_string()),
            },
            Err(error) => error_response(&request,
                if error.starts_with("runtime_maintenance") { "runtime_maintenance" } else if error.starts_with("invalid_config:") { "invalid_config" } else if error.starts_with("scope_mismatch") { "scope_mismatch" } else { "daemon_unavailable" }, &error),
        },
        other => error_response(
            &request,
            "protocol_version_mismatch",
            &format!("unknown method {other}"),
        ),
        }
    })();
    if let Some(operation) = operation.filter(|_| !deferred_operation) {
        remember(&operation.storage_id, &response);
        INFLIGHT
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&operation.storage_id);
    }
    response
}

fn command_response(request: &RpcRequest, result: CommandResult) -> RpcResponse {
    match result {
        Ok(captured) => RpcResponse {
            v: PROTOCOL_V,
            id: request.id.clone(),
            operation_id: request.operation_id.clone(),
            scope: request.scope.clone(),
            idempotency_key: request.idempotency_key.clone(),
            ok: captured.exit == 0,
            exit: captured.exit,
            bin: bin_version().to_owned(),
            envelope: Some(captured.envelope),
            error: None,
            code: None,
            web_url: Some(current_url()),
            pid: Some(std::process::id()),
            data_dir: Some(respire_app::service::data_dir().display().to_string()),
        },
        Err(error) => error_response(request,
            if error.starts_with("runtime_maintenance") { "runtime_maintenance" } else if error.starts_with("invalid_config:") { "invalid_config" } else if error.starts_with("scope_mismatch") { "scope_mismatch" } else { "daemon_unavailable" }, &error),
    }
}

pub fn dispatch_deferred(
    request: RpcRequest,
    tx: &Sender<Job>,
    action: impl FnOnce(RpcResponse) + Send + 'static,
) {
    dispatch_deferred_inner(request, tx, false, action)
}

fn dispatch_deferred_inner(
    request: RpcRequest, tx: &Sender<Job>, legacy: bool,
    action: impl FnOnce(RpcResponse) + Send + 'static,
) {
    if request.v != PROTOCOL_V {
        action(error_response(
            &request,
            "protocol_version_mismatch",
            "protocol version mismatch",
        ));
        return;
    }
    if request.id.trim().is_empty()
        || request.id.len() > 256
        || request.id.chars().any(char::is_whitespace)
    {
        action(error_response(
            &request,
            "invalid_request_id",
            "request ID must contain 1 to 256 characters and no whitespace",
        ));
        return;
    }
    if let Err((code, error)) = validate_request_scope(&request) {
        action(error_response(&request, &code, &error));
        return;
    }
    if request.method == "cli.exec"
        && PROFILE_SWITCH_RUNNING.load(Ordering::Acquire)
        && !is_status(&request.args)
    {
        action(error_response(
            &request,
            "model_switch_busy",
            "model switch in progress; semantic queries and writes are paused; inspect model.progress",
        ));
        return;
    }
    if request.method != "cli.exec" {
        action(dispatch_inner(request, tx, legacy));
        return;
    }
    let operation = match operation_identity_mode(&request, legacy) {
        Ok(operation) => operation,
        Err((code, error)) => {
            action(error_response(&request, &code, &error));
            return;
        }
    };
    let admission = match admit_with_retention(&request, &operation, legacy) {
        Ok(Admission::New(guard)) => guard,
        Ok(Admission::Replay(response)) => {
            action(response);
            return;
        }
        Ok(Admission::InProgress) => {
            action(error_response(
                    &request,
                    "request_in_progress",
                    "operation ID is already executing or queued; inspect runtime.result; command was not replayed",
                ));
            return;
        }
        Ok(Admission::Unknown) => {
            action(error_response(
                    &request,
                    "result_unknown",
                    "operation was admitted but its in-memory receipt is unavailable; non-idempotent writes are not replayed",
                ));
            return;
        }
        Err((code, error)) => {
            action(error_response(&request, &code, &error));
            return;
        }
    };
    let scope = operation.scope.clone();
    let args = request.args.clone();
    let wait = request
        .queue_wait_ms
        .map(Duration::from_millis)
        .unwrap_or_else(queue_wait)
        .min(queue_wait());
    let operation_id = operation.operation_id.clone();
    let reply = Reply::new(move |result| {
        let _admission = admission;
        let response = command_response(&request, result);
        remember(&operation.storage_id, &response);
        INFLIGHT
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&operation.storage_id);
        action(response);
    });
    if let Err(error) = enqueue_job_scoped(tx, args, false, reply.clone(), wait, operation_id, scope) {
        let _ = reply.send(Err(error));
    }
}

pub fn status_response(request: &RpcRequest) -> RpcResponse {
    RpcResponse {
        v: PROTOCOL_V,
        id: request.id.clone(),
        operation_id: request.operation_id.clone(),
        scope: request.scope.clone(),
        idempotency_key: request.idempotency_key.clone(),
        ok: true,
        exit: 0,
        bin: bin_version().to_owned(),
        envelope: None,
        error: None,
        code: None,
        web_url: Some(current_url()),
        pid: Some(std::process::id()),
        data_dir: Some(respire_app::service::data_dir().display().to_string()),
    }
}

pub fn error_response(request: &RpcRequest, code: &str, error: &str) -> RpcResponse {
    RpcResponse {
        v: PROTOCOL_V,
        id: request.id.clone(),
        operation_id: request.operation_id.clone(),
        scope: request.scope.clone(),
        idempotency_key: request.idempotency_key.clone(),
        ok: false,
        exit: 1,
        bin: bin_version().to_owned(),
        envelope: None,
        error: Some(error.to_owned()),
        code: Some(code.to_owned()),
        web_url: None,
        pid: Some(std::process::id()),
        data_dir: None,
    }
}

fn deferred_reply(request: &RpcRequest, identity: &OperationIdentity, admission: AdmissionGuard) -> Reply {
    let mut request = request.clone();
    request.operation_id = Some(identity.operation_id.clone());
    let storage_id = identity.storage_id.clone();
    Reply::new(move |result| {
        let _admission = admission;
        let response = command_response(&request, result);
        remember(&storage_id, &response);
        INFLIGHT
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&storage_id);
    })
}

fn enqueue_prepare(request: &RpcRequest, identity: &OperationIdentity) -> Result<()> {
    let tx = WRITE_TX
        .lock()
        .map_err(|_| anyhow::anyhow!("write queue lock poisoned"))?
        .clone()
        .context("write worker is not running")?;
    let admission = begin_admission(identity.operation_id.clone(), "model_prepare")
        .context("runtime is draining and rejected new business")?;
    let operation = crate::model_progress::Operation::reserve_task(identity.operation_id.clone())?;
    let wait = request
        .queue_wait_ms
        .map(Duration::from_millis)
        .unwrap_or_else(queue_wait)
        .min(queue_wait());
    let reply = deferred_reply(request, identity, admission);
    let deadline = Arc::new(crate::admission::QueueDeadline::new(wait));
    watch_queue(&deadline, &reply)?;
    let prepare = PrepareJob {
        job: Job {
            scope: identity.scope.clone(),
            args: Vec::new(),
            stop: false,
            reply,
            sync_context: None,
            deadline,
        },
        operation_id: identity.operation_id.clone(),
        operation,
    };
    let gate = shared_exclusive();
    gate.reserve();
    match tx.try_send(WriteJob::Prepare(prepare)) {
        Ok(()) => Ok(()),
        Err(error) => {
            gate.cancel_reservation();
            let (work, message) = match error {
                mpsc::TrySendError::Full(work) => (work, "write request queue is full"),
                mpsc::TrySendError::Disconnected(work) => (work, "write worker is gone"),
            };
            if let WriteJob::Prepare(prepare) = work {
                let _ = prepare.job.reply.send(Err(message.to_owned()));
            }
            bail!(message)
        }
    }
}

fn run_prepare(prepare: PrepareJob) {
    let PrepareJob {
        job,
        operation_id,
        operation,
    } = prepare;
    let scope_held = SCOPE_EXECUTION.read();
    let gate = shared_exclusive();
    let held = gate.acquire_reserved();
    WRITE_RUNNING.store(true, Ordering::Release);
    let result = (|| -> Result<crate::output_state::Captured> {
        scope_held
            .as_ref()
            .map_err(|_| anyhow::anyhow!("scope_mismatch: identity fence poisoned"))?;
        anyhow::ensure!(job.deadline.start(), QUEUE_EXPIRED);
        validate_job_scope(&job.scope).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(!STOPPING.load(Ordering::Acquire), "runtime is stopping");
        anyhow::ensure!(
            !respire_app::service::service_paused() && !crate::host_hooks::background_paused(),
            "model preparation is paused by service mode"
        );
        let _task = crate::model_progress::TaskScope::new(Some(operation_id.clone()));
        operation.enter_thread();
        crate::model_progress::check()?;
        crate::model_install::verify_m3_assets()?;
        crate::model_progress::check()?;
        Ok(crate::output_state::Captured {
            exit: 0,
            envelope: ResultEnvelope::new(
                "model.prepare",
                OutputStatus::Ok,
                json!({"state":"completed", "operation_id":operation_id}),
                Vec::new(),
            ),
        })
    })();
    drop(held);
    drop(scope_held);
    drop(operation);
    if result.is_ok() {
        kick_index();
    }
    WRITE_RUNNING.store(false, Ordering::Release);
    let _ = job.reply.send(result.map_err(|error| format!("{error:#}")));
}

pub fn enqueue_job(
    tx: &Sender<Job>,
    args: Vec<String>,
    stop: bool,
    reply: Reply,
    wait: Duration,
    operation_id: String,
) -> std::result::Result<Arc<crate::admission::QueueDeadline>, String> {
    if !stop { validate_business_config()?; }
    enqueue_job_scoped(tx, args, stop, reply, wait, operation_id, current_scope())
}

fn enqueue_job_scoped(
    tx: &Sender<Job>,
    args: Vec<String>,
    stop: bool,
    reply: Reply,
    wait: Duration,
    operation_id: String,
    scope: RuntimeRequestScope,
) -> std::result::Result<Arc<crate::admission::QueueDeadline>, String> {
    if !stop && business_paused() {
        return Err("runtime_maintenance: runtime maintenance rejected queued business".to_owned());
    }
    if !stop { validate_business_config()?; }
    if !stop
        && !respire_app::service::off_mode()
        && needs_inference(&args)
        && inference_health_status()["host_recovery_required"] == true
    {
        return Err("inference is unresponsive after cancellation; host runtime recovery is required; request was not queued".into());
    }
    let slots = WORKERS.load(Ordering::Acquire).max(1);
    if !stop
        && is_status(&args)
        && LIGHT_RUNNING.load(Ordering::Acquire) >= 2
        && RUNNING
            .load(Ordering::Acquire)
            .saturating_sub(LIGHT_RUNNING.load(Ordering::Acquire))
            >= slots
    {
        let mut envelope = ResultEnvelope::new(
            "status",
            OutputStatus::Warn,
            json!({"state": "busy", "workers": slots}),
            Vec::new(),
        );
        envelope.errors.push(i18n::text("busy").to_owned());
        reply.send(Ok(crate::output_state::Captured { exit: 2, envelope }))?;
        return Ok(Arc::new(crate::admission::QueueDeadline::new(
            Duration::ZERO,
        )));
    }
    let sync_context = if !stop && !respire_app::service::off_mode()
        && matches!(
            command_name(&args),
            Some(
                "sync"
                    | "sync-conflicts"
                    | "sync-resolve"
                    | "sync-history"
                    | "sync-restore"
                    | "classify"
            )
        ) {
        // Use the caller's wire generation; the sync worker takes its snapshot later.
        Some((scope_generation(&scope)?, -1))
    } else {
        None
    };
    let deadline = Arc::new(crate::admission::QueueDeadline::new(wait));
    watch_queue(&deadline, &reply).map_err(|error| error.to_string())?;
    let admission = {
        let _scope_held = SCOPE_EXECUTION.read().map_err(|_| "scope_mismatch: identity fence poisoned".to_owned())?;
        let gate = shared_exclusive();
        let _held = gate.acquire(true);
        let mut admitted = ADMISSIONS.lock().map_err(|_| "admission_lock_poisoned".to_owned())?;
        if stop {
            validate_scope(Some(&scope), &current_scope()).map_err(|(code, _)| code)?;
        } else {
            validate_job_scope(&scope)?;
        }
        admitted.push(Admitted {
            operation_id: operation_id.clone(),
            kind: if stop { "stop" } else { "rpc" },
        });
        AdmissionGuard(operation_id)
    };
    let reply = Reply::new(move |result| {
        let _ = reply.send(result);
        drop(admission);
    });
    tx.send(Job {
        scope,
        args,
        stop,
        reply,
        sync_context,
        deadline: Arc::clone(&deadline),
    })
    .map_err(|_| "runtime worker is gone".to_owned())?;
    wake_dispatcher();
    Ok(deadline)
}

pub fn submit(
    tx: &Sender<Job>,
    args: Vec<String>,
    stop: bool,
    operation_id: String,
) -> CommandResult {
    // Internal MCP callers have no external scope: capture once, never at execution.
    validate_business_config()?;
    submit_scoped(tx, args, stop, operation_id, Some(current_scope()))
}

fn submit_scoped(
    tx: &Sender<Job>,
    args: Vec<String>,
    stop: bool,
    operation_id: String,
    scope: Option<RuntimeRequestScope>,
) -> CommandResult {
    let scope = scope.ok_or_else(|| "scope_required".to_owned())?;
    let (reply_tx, reply_rx) = mpsc::channel();
    let deadline = enqueue_job_scoped(
        tx,
        args,
        stop,
        Reply::new(move |result| {
            let _ = reply_tx.send(result);
        }),
        queue_wait(),
        operation_id,
        scope,
    )?;
    let wait = queue_wait();
    match reply_rx.recv_timeout(wait) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("runtime worker dropped the reply".to_owned())
        }
        Err(mpsc::RecvTimeoutError::Timeout) if deadline.cancel() => Err(QUEUE_EXPIRED.to_owned()),
        // Execution won admission. Especially for writes, preserve the actual
        // commit outcome instead of returning an ambiguous client timeout.
        Err(mpsc::RecvTimeoutError::Timeout) => reply_rx
            .recv()
            .map_err(|_| "runtime worker dropped the reply".to_owned())?,
    }
}

fn mcp_request(args: Vec<String>, scope: RuntimeRequestScope) -> RpcRequest {
    RpcRequest {
        scope: Some(scope),
        v: PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        operation_id: Some(uuid::Uuid::new_v4().to_string()),
        idempotency_key: None,
        parent_operation_id: None,
        method: "cli.exec".to_owned(),
        args,
        queue_wait_ms: None,
        lifecycle: None,
    }
}

pub fn execute_json(args: Vec<String>) -> std::result::Result<Value, String> {
    let tx = {
        let guard = JOB_TX
            .get()
            .ok_or_else(|| "runtime worker is not running".to_owned())?
            .lock()
            .map_err(|_| "runtime worker lock poisoned".to_owned())?;
        guard.clone()
    };
    validate_business_config().map_err(|error| {
        json!({"error": error, "code": "invalid_config"}).to_string()
    })?;
    let request = mcp_request(args, current_scope());
    let operation_id = request.operation_id.clone();
    let scope = request.scope.clone();
    let (send, receive) = mpsc::channel();
    dispatch_deferred(request, &tx, move |response| {
        let _ = send.send(response);
    });
    let response = receive
        .recv()
        .map_err(|_| "runtime worker dropped the MCP receipt".to_owned())?;
    let mut envelope = match response.envelope.as_ref() {
        Some(envelope) => serde_json::to_value(envelope).map_err(|error| error.to_string())?,
        None => json!({"error":response.error, "code":response.code}),
    };
    envelope["request_id"] = json!(response.id);
    envelope["operation_id"] = json!(operation_id);
    envelope["scope"] = json!(scope);
    if !response.ok {
        return Err(envelope.to_string());
    }
    Ok(envelope)
}

pub fn wait_for_drain(_supervised: bool, mut busy: impl FnMut() -> bool) {
    while busy() {
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn set_control_state(state: &'static str) {
    *CONTROL_STATE
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = state;
}

pub fn control_state() -> &'static str {
    *CONTROL_STATE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn health_state() -> &'static str {
    match control_state() {
        "maintenance_requested" | "draining" => "draining",
        "resources_closing" | "forced_timeout" | "compatibility_timeout" => "stopping",
        "drained" => "stopped",
        "running" => "ready",
        other => other,
    }
}

fn mark_stop_unfinished(mut items: Vec<Admitted>) {
    // RPC retention and queue execution each hold an admission guard for the
    // same wire operation. The durable receipt records that operation once.
    let mut seen = std::collections::HashSet::new();
    items.retain(|item| seen.insert(item.operation_id.clone()));
    *STOP_UNFINISHED
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = items;
}

fn stop_unfinished() -> Value {
    let items = STOP_UNFINISHED
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    Value::Array(
        items
            .iter()
            .map(|item| {
                json!({
                    "operation_id": item.operation_id,
                    "result": "unknown",
                })
            })
            .collect(),
    )
}

fn stop_operation_status(request_id: &str, operation_id: &str) -> Value {
    json!({
        "request_id": request_id,
        "operation_id": operation_id,
        "state": control_state(),
        "admitted": admitted_list(),
        "background": busy_background(),
        "unfinished": stop_unfinished(),
    })
}

fn drain_busy() -> bool {
    drain_background_busy()
        || ADMISSIONS
            .lock()
            .map_or(true, |items| items.iter().any(|item| item.kind != "stop"))
}

fn drain_background_busy() -> bool {
    RUNNING.load(Ordering::Acquire) != 0
        || WRITE_RUNNING.load(Ordering::Acquire)
        || CLASSIFY_RUNNING.load(Ordering::Acquire)
        || sync_running()
        || index_has_work()
        || PROFILE_SWITCH_RUNNING.load(Ordering::Acquire)
}

fn validate_stop_force(expected: &Value, accepted: Option<&str>) -> Result<bool> {
    match expected.get("force") {
        None | Some(Value::Bool(false)) => Ok(false),
        Some(Value::Bool(true)) => {
            anyhow::ensure!(
                accepted.is_some_and(|id| expected["operation_id"].as_str() == Some(id)),
                "stop_operation_mismatch"
            );
            Ok(true)
        }
        Some(_) => bail!("invalid_stop_force"),
    }
}

fn force_stop_after_grace() {
    std::thread::sleep(FORCE_DRAIN_GRACE);
    let background_busy = drain_background_busy();
    {
        let admitted = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
        if control_state() != "draining"
            || (!background_busy && !admitted.iter().any(|item| item.kind != "stop"))
        {
            return;
        }
        // An admitted operation may already have committed. Retirement never proves abortion.
        mark_stop_unfinished(
            admitted.iter().filter(|item| item.kind != "stop").cloned().collect(),
        );
        STOP_FORCE_TRIGGERED.store(true, Ordering::Release);
        set_control_state("forced_timeout");
    }
    // Reap the owned native child to unblock callers, then retain the ordinary host joins/flush.
    if let Err(error) = respire_app::core_sdk::worker::shutdown() {
        eprintln!("explicit forced stop could not confirm Core worker cleanup: {error:#}");
    }
    wake_dispatcher();
    SYNC_CV.notify_all();
    INDEX_CV.notify_all();
}

pub fn stop_force_deadline_ms() -> Option<u64> {
    STOP_FORCE_REQUESTED
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .map(|started| FORCE_DRAIN_GRACE.saturating_sub(started.elapsed()).as_millis() as u64)
}

pub(crate) fn advance_generation(generation: usize) -> Result<()> {
    // Callers may hold a scope read lock and the write gate: never upgrade it.
    let _fence = ADMISSIONS
        .lock()
        .map_err(|_| anyhow::anyhow!("runtime admission lock is poisoned"))?;
    anyhow::ensure!(!STOPPING.load(Ordering::Acquire), "runtime is stopping");
    GENERATION
        .compare_exchange(
            generation,
            generation.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| anyhow::anyhow!("sync context changed; pending work kept locally"))?;
    // Keep the durable scope at the actual wire generation, under the same fence.
    if JOB_TX.get().is_some() {
        write_endpoint(&current_url())?;
    }
    Ok(())
}

pub fn request_drain_exit(expected: &Value) -> Result<&'static str> {
    // Identity writers take the scope write lock; generation changes share ADMISSIONS.
    let _identity = SCOPE_EXECUTION.read().map_err(|_| anyhow::anyhow!("identity fence poisoned"))?;
    let operation_id;
    {
        let _admitted = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
        let process = process_identity();
        validate_stop_target(
            expected,
            &process,
            &account_identity(),
            crate::rpc_worker::wire_generation(),
        )?;
        let force = validate_stop_force(expected, STOP_OPERATION.get().map(String::as_str))?;
        if force {
            let mut requested = STOP_FORCE_REQUESTED
                .lock()
                .map_err(|_| anyhow::anyhow!("force stop state poisoned"))?;
            if requested.is_none() {
                let _controller = std::thread::Builder::new()
                    .name("runtime-force-stop".to_owned())
                    .spawn(force_stop_after_grace)
                    .context("start explicit force stop controller")?;
                *requested = Some(Instant::now());
            }
        }
        operation_id = STOP_OPERATION.get_or_init(|| uuid::Uuid::new_v4().to_string());
        if STOPPING.swap(true, Ordering::AcqRel) {
            return Ok(operation_id.as_str());
        }
        set_control_state("maintenance_requested");
    }
    set_control_state("draining");
    wake_dispatcher();
    SYNC_CV.notify_all();
    INDEX_CV.notify_all();
    Ok(operation_id.as_str())
}

fn validate_stop_target(
    expected: &Value,
    process: &ProcessIdentity,
    account: &str,
    generation: u64,
) -> Result<()> {
    anyhow::ensure!(
        expected["installation_id"] == process.installation_id
            && expected["instance_id"] == process.instance_id
            && expected["account_id"] == account
            && expected["generation"] == generation,
        "stop_identity_mismatch"
    );
    Ok(())
}

pub fn handle_http_rpc(body: &[u8]) -> Result<RpcResponse> {
    let request: RpcRequest = serde_json::from_slice(body).context("rpc body is not JSON")?;
    let tx = {
        let guard = JOB_TX
            .get()
            .ok_or_else(|| anyhow::anyhow!("runtime worker is not running"))?
            .lock()
            .map_err(|_| anyhow::anyhow!("runtime worker lock poisoned"))?;
        guard.clone()
    };
    Ok(dispatch(request, &tx))
}

/// Internal compatibility entry: no wire flag can change retention policy.
pub(crate) fn handle_http_legacy(request: RpcRequest) -> Result<RpcResponse> {
    let tx = JOB_TX.get().context("runtime worker is not running")?
        .lock().map_err(|_| anyhow::anyhow!("runtime worker lock poisoned"))?.clone();
    Ok(dispatch_inner(request, &tx, true))
}
pub(crate) fn handle_http_legacy_deferred(request: RpcRequest,
    action: impl FnOnce(RpcResponse) + Send + 'static) -> Result<()> {
    let tx = JOB_TX.get().context("runtime worker is not running")?
        .lock().map_err(|_| anyhow::anyhow!("runtime worker lock poisoned"))?.clone();
    dispatch_deferred_inner(request, &tx, true, action);
    Ok(())
}

pub fn handle_http_rpc_deferred(
    body: &[u8],
    action: impl FnOnce(RpcResponse) + Send + 'static,
) -> Result<()> {
    let request: RpcRequest = serde_json::from_slice(body).context("rpc body is not JSON")?;
    let tx = JOB_TX
        .get()
        .ok_or_else(|| anyhow::anyhow!("runtime worker is not running"))?
        .lock()
        .map_err(|_| anyhow::anyhow!("runtime worker lock poisoned"))?
        .clone();
    dispatch_deferred(request, &tx, action);
    Ok(())
}

fn inference_health_status() -> Value {
    match respire_app::memory::onnx::inference_status() {
        Ok(status) => status,
        Err(error) => json!({"state":"error","error":format!("{error:#}")}),
    }
}

/// The durable endpoint uses the same process/account identity as live health.
pub(crate) fn endpoint_identity(url: &str) -> Result<Value> {
    validate_process_identity()?;
    let process = process_identity();
    let roots = respire_app::service::resolved_roots()?;
    Ok(json!({
        "schema_version": 2, "server": "respire", "v": PROTOCOL_V,
        "pid": std::process::id(), "bin": bin_version(), "url": url,
        "runtime_version": runtime_identity().runtime_version,
        "exe": process.image_path, "image_path": process.image_path,
        "image_sha256": process.image_sha256,
        "installation_root": roots.installation_root,
        "data_dir": roots.account_data_root,
        "installation_id": process.installation_id, "instance_id": process.instance_id,
        "process_start_id": process.process_start_id,
        "account_id": account_identity(), "generation": crate::rpc_worker::wire_generation(),
        "managed_id": crate::host_hooks::managed_id(),
    }))
}

pub fn startup_complete() -> bool {
    STARTUP_COMPLETE.load(Ordering::Acquire)
}

pub fn health_body() -> Value {
    let roots = match respire_app::service::resolved_roots()
        .and_then(|roots| serde_json::to_value(roots).map_err(anyhow::Error::from))
    {
        Ok(roots) => roots,
        Err(_) => return json!({
            "server": "respire", "v": PROTOCOL_V, "state": "error",
            "error": {"code": "roots_resolution_failed"},
        }),
    };
    let inference = inference_health_status();
    let (queue_cancelled, timings) = crate::admission::timings();
    let (queued, executing) = crate::admission::occupancy();
    let identity = runtime_identity();
    let process = process_identity();
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let mut body = json!({
        "server": "respire",
        "bin": bin_version(),
        "pid": std::process::id(),
        "state": health_state(),
        "v": PROTOCOL_V,
        "url": current_url(),
        "exe": exe,
        "data_dir": roots["account_data_root"],
        "resolved_roots": roots,
        "store_ready": STORE_READY.load(Ordering::Acquire),
        "installation_root": roots["installation_root"],
        "managed_id": crate::host_hooks::managed_id(),
        "installation_id": process.installation_id,
        "instance_id": process.instance_id,
        "process_start_id": process.process_start_id,
        "image_path": process.image_path,
        "image_sha256": process.image_sha256,
        "account_id": account_identity(),
        "generation": crate::rpc_worker::wire_generation(),
        "protocol_range": {"minimum": PROTOCOL_V, "maximum": PROTOCOL_V},
        "capabilities": ["business_executor", "mcp_server"],
        "credential_state": crate::host_hooks::credential_state(),
        "snapshot_restore_id": SNAPSHOT_BOOT_ID.lock().ok().and_then(|slot|slot.clone()),
        "recall_statistics": recall_stats_status(),
        "retrieval_index": index_status(),
        "inference": inference,
        // Split-era identity: the extension lives under the `runtime` key per
        // the protocol contract; the flattened runtime_version keeps the
        // existing Health consumers (pin checks, shell banner) working.
        "runtime": identity.health_extension_json(),
        "control": {
            "state": control_state(),
            "operation_id": STOP_OPERATION.get(),
            "admitted": admitted_list(),
            "background": busy_background(),
            "unfinished": stop_unfinished(),
        },
        "runtime_version": identity.runtime_version,
        "rpc": {
            "available_parallelism": cpu_count(),
            "effective_parallelism": WORKERS.load(Ordering::Acquire),
            "ordinary_running": RUNNING.load(Ordering::Acquire).saturating_sub(LIGHT_RUNNING.load(Ordering::Acquire)),
            "lightweight_running": LIGHT_RUNNING.load(Ordering::Acquire),
            "lightweight_capacity": 2,
            "queue_wait_timeout_secs": queue_wait().as_secs(),
            "queue_cancelled": queue_cancelled,
            "queued_or_cancelled_pending_removal": queued,
            "executing_until_reply": executing,
            "recent_timing_micros": timings,
            "timing_scope": "queue admission to execution start; command execution to reply consumption",
        },
    });
    body["startup_complete"] = json!(startup_complete());
    body
}

fn write_stop_receipt(directory: &std::path::Path, receipt: &RuntimeStopReceipt) -> Result<()> {
    anyhow::ensure!(
        !receipt.instance_id.is_empty()
            && receipt.instance_id.len() <= 128
            && receipt
                .instance_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'),
        "invalid stop receipt instance ID"
    );
    let temporary = directory.join(format!(".stop-{}.tmp", uuid::Uuid::new_v4()));
    let target = directory.join(format!("stop-{}.json", receipt.instance_id));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec(receipt)?)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &target)?;
        #[cfg(unix)]
        std::fs::File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        if let Err(error) = std::fs::remove_file(&temporary) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("stop receipt staging cleanup failed: {error}");
            }
        }
    }
    result
}

fn final_stop_receipt(operation_id: &str, success: bool) -> RuntimeStopReceipt {
    let process = process_identity();
    let unfinished = STOP_UNFINISHED
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .map(|item| RuntimeUnfinishedOperation {
            operation_id: item.operation_id.clone(),
            result: respire_protocol::RuntimeUnfinishedOutcome::Unknown,
        })
        .collect::<Vec<_>>();
    RuntimeStopReceipt {
        schema_version: 1,
        protocol_version: PROTOCOL_V,
        operation_id: operation_id.to_owned(),
        installation_id: process.installation_id,
        instance_id: process.instance_id,
        pid: std::process::id(),
        process_start_id: process.process_start_id,
        image_path: process.image_path,
        image_sha256: process.image_sha256,
        runtime_version: runtime_identity().runtime_version,
        account_id: account_identity(),
        generation: crate::rpc_worker::wire_generation(),
        state: stop_outcome(
            success,
            STOP_FORCE_TRIGGERED.load(Ordering::Acquire),
            unfinished.is_empty(),
        ),
        unfinished,
    }
}

fn stop_outcome(clean: bool, forced: bool, unfinished_empty: bool) -> RuntimeStopOutcome {
    if !clean {
        RuntimeStopOutcome::Failed
    } else if forced {
        RuntimeStopOutcome::ForcedTimeout
    } else if unfinished_empty {
        RuntimeStopOutcome::Drained
    } else {
        RuntimeStopOutcome::Failed
    }
}

fn stop_process(code: i32) -> ! {
    #[cfg(test)]
    {
        let _ = code;
        loop {
            std::thread::park();
        }
    }
    #[cfg(not(test))]
    {
        let mut exit_code = code;
        if let Err(error) = respire_app::core_sdk::worker::shutdown() {
            eprintln!(
                "runtime retained its library lock because Core worker cleanup failed: {error:#}"
            );
            exit_code = 1;
            while respire_app::core_sdk::worker::shutdown().is_err() {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        if let Some(operation_id) = STOP_OPERATION.get() {
            let receipt = final_stop_receipt(operation_id, exit_code == 0);
            let directory = respire_app::service::main_data_dir().join("runtime");
            let written = std::fs::create_dir_all(&directory)
                .map_err(anyhow::Error::from)
                .and_then(|_| write_stop_receipt(&directory, &receipt));
            if receipt.state == RuntimeStopOutcome::ForcedTimeout {
                exit_code = 1;
            }
            if let Err(error) = written {
                eprintln!("runtime failed to persist its final stop receipt: {error:#}");
                exit_code = 1;
            }
        }
        crate::host_hooks::record_exit(exit_code == 0);
        std::process::exit(exit_code);
    }
}

/// Job slots for this process. `RSRS_RPC_PARALLELISM` wins, then
/// `client.json` `rpc_parallelism`, otherwise OS-reported available parallelism.
/// Explicit settings cannot exceed the CPUs available to this process.
/// Two additional lightweight slots keep show/list/status/revision responsive.
/// Simple writes prepare concurrently and use short source-checked commits.
/// Foreground and background ONNX sessions have independent serial queues.
pub fn worker_limit() -> usize {
    let available = cpu_count();
    if let Ok(raw) = respire_app::env::var("RSRS_RPC_PARALLELISM") {
        let raw = raw.trim();
        if raw.is_empty() || raw.eq_ignore_ascii_case("cpu") {
            return cpu_count();
        }
        if let Ok(parsed) = raw.parse::<usize>() {
            if parsed == 0 {
                return cpu_count();
            }
            return parsed.clamp(1, available);
        }
    }
    if let Some(saved) = respire_app::service::rpc_parallelism_setting() {
        return saved.clamp(1, available);
    }
    cpu_count()
}

/// OS-reported parallelism for this process; the floor keeps a single-CPU
/// host usable when the metric is unavailable.
pub fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn queue_wait() -> Duration {
    Duration::from_secs(
        respire_app::env::var("RSRS_RPC_QUEUE_WAIT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(120)
            .clamp(1, 3600),
    )
}

pub fn is_exclusive(args: &[String]) -> bool {
    if is_context_query(args) {
        return false;
    }
    if command_name(args) == Some("update") {
        return false;
    }
    if command_name(args) == Some("remember")
        && !args.iter().any(|arg| {
            matches!(arg.as_str(), "--merge-ids" | "--supersedes" | "--see-also")
                || arg.starts_with("--merge-ids=")
                || arg.starts_with("--supersedes=")
                || arg.starts_with("--see-also=")
        })
    {
        return false;
    }
    matches!(
        command_name(args),
        Some(
            "remember"
                | "update"
                | "forget"
                | "restore"
                | "purge"
                | "attach"
                | "promote"
                | "demote"
                | "retitle"
                | "retitle-many"
                | "import"
                | "reembed"
                | "resort"
                | "split"
                | "tree-deepen"
                | "tree-cure"
                | "tree-float"
                | "sync"
                | "sync-conflicts"
                | "sync-resolve"
                | "sync-restore"
                | "sync-reset"
                | "repack"
                | "inject"
                | "keygen"
                | "account"
                | "space"
                | "fivekeys"
                | "super-reset"
                | "register"
                | "login"
                | "logout"
                | "config"
                | "agent-config"
                | "model"
                | "grant"
                | "session"
                | "query-log"
                | "doctor"
                | "root-create"
                | "share-import"
                | "backup"
                | "snapshot"
        )
    )
}

fn wake_dispatcher() {
    if let Some(thread) = DISPATCH_THREAD.get() {
        thread.unpark();
    }
}

// The unpark token survives a completion between try_recv and park_timeout.
// Keep the periodic check as a fallback for shutdown and queue expiry.
pub fn receive_dispatch_job<T>(
    rx: &Receiver<T>,
    wait: Duration,
) -> Result<T, mpsc::RecvTimeoutError> {
    match rx.try_recv() {
        Ok(job) => return Ok(job),
        Err(mpsc::TryRecvError::Disconnected) => return Err(mpsc::RecvTimeoutError::Disconnected),
        Err(mpsc::TryRecvError::Empty) => {}
    }
    std::thread::park_timeout(wait);
    rx.try_recv().map_err(|error| match error {
        mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
        mpsc::TryRecvError::Disconnected => mpsc::RecvTimeoutError::Disconnected,
    })
}

struct RunningGuard {
    status: bool,
    light: bool,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        RUNNING.fetch_sub(1, Ordering::AcqRel);
        if self.light {
            LIGHT_RUNNING.fetch_sub(1, Ordering::AcqRel);
        }
        if self.status {
            RUNNING_STATUS.fetch_sub(1, Ordering::AcqRel);
        }
        wake_dispatcher();
    }
}

struct ClassifyGuard;
impl Drop for ClassifyGuard {
    fn drop(&mut self) {
        SYNC_CONTEXT.with(|context| context.set(None));
        CLASSIFY_RUNNING.store(false, Ordering::Release);
    }
}

struct StartupEndpoint {
    owner: Arc<Mutex<respire_app::lock::LibraryLock>>,
    publication: crate::rpc_worker::EndpointPublication,
}

impl StartupEndpoint {
    fn revoke(&self) {
        let result = self.owner.lock()
            .map_err(|_| anyhow::anyhow!("installation ownership lock poisoned"))
            .and_then(|owner| self.publication.revoke_failed_start(&owner));
        if let Err(error) = result {
            eprintln!("runtime failed to revoke its startup endpoint: {error:#}");
        }
    }
}

pub fn dispatch_loop(
    rx: Receiver<Job>,
    limit: usize,
    idle: Option<Duration>,
    _lock: respire_app::lock::LibraryLock,
) {
    dispatch_loop_inner(rx, limit, idle, _lock, None)
}

fn dispatch_loop_inner(
    rx: Receiver<Job>,
    limit: usize,
    idle: Option<Duration>,
    _lock: respire_app::lock::LibraryLock,
    startup: Option<StartupEndpoint>,
) {
    mark_worker();
    let _ = DISPATCH_THREAD.set(std::thread::current());
    #[cfg(not(test))]
    respire_app::core_sdk::worker::enable();
    // Keep WAL open across requests: closing the last connection can briefly lock
    // a concurrent opener during checkpoint/cleanup, even for read-only status.
    let mut _store = if respire_app::service::off_mode() {
        None
    } else {
        Some(match respire_app::service::open_runtime_store(&_lock) {
            Ok((store, snapshot_id)) => {
                if let Ok(mut slot) = SNAPSHOT_BOOT_ID.lock() {
                    *slot = snapshot_id;
                }
                STORE_READY.store(true, Ordering::Release);
                store
            }
            Err(error) => {
                eprintln!("runtime failed to initialize the library: {error:#}");
                if let Some(startup) = startup.as_ref() {
                    startup.revoke();
                }
                stop_process(1);
            }
        })
    };
    respire_app::service::install_runtime_profile(respire_app::service::data_dir());
    if let Err(error) = respire_app::read_heat::reload() {
        eprintln!("runtime failed to load read_heat configuration: {error:#}");
        stop_process(1);
    }
    let (classify_tx, classify_rx) = mpsc::sync_channel::<Job>(16);
    let classifier = std::thread::Builder::new()
        .name("respire-classify".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            mark_worker();
            while let Ok(job) = classify_rx.recv() {
                if STOPPING.load(Ordering::Acquire) {
                    let _ = job.reply.send(Err("runtime is stopping".into()));
                    continue;
                }
                if !job.deadline.start() {
                    let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                    continue;
                }
                let Some((generation, _)) = job.sync_context else {
                    let _ = job.reply.send(Err("missing classification context".into()));
                    continue;
                };
                let admission = PROFILE_ADMISSION
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) {
                    let _ = job.reply.send(Err("model_switch_busy".into()));
                    continue;
                }
                CLASSIFY_RUNNING.store(true, Ordering::Release);
                drop(admission);
                let _active = ClassifyGuard;
                SYNC_CONTEXT.with(|context| context.set(Some((generation, -1))));
                let result = capture_scoped(&job.scope, job.args);
                let _ = job.reply.send(result);
            }
        });
    if classifier.is_err() {
        stop_process(1);
    }
    let (write_tx, write_rx) = mpsc::sync_channel::<WriteJob>(256);
    if let Ok(mut installed) = WRITE_TX.lock() {
        *installed = Some(write_tx.clone());
    } else {
        eprintln!("runtime failed to install the write queue");
        stop_process(1);
    }
    let writer = std::thread::Builder::new()
        .name("respire-write".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            mark_worker();
            while let Ok(work) = write_rx.recv() {
                let job = match work {
                    WriteJob::Command(job) => job,
                    WriteJob::Prepare(prepare) => {
                        run_prepare(prepare);
                        continue;
                    }
                    WriteJob::RecallStats(stats, generation, _admission) => {
                        let result = if STOPPING.load(Ordering::Acquire) {
                            shared_exclusive().cancel_reservation();
                            Err(anyhow::anyhow!("runtime is stopping"))
                        } else {
                            WRITE_RUNNING.store(true, Ordering::Release);
                            let gate = shared_exclusive();
                            let _held = gate.acquire_reserved();
                            let result = check_sync_context(generation)
                                .and_then(|_| respire_app::service::open_store())
                                .and_then(|store| stats.persist(&store));
                            drop(_held);
                            WRITE_RUNNING.store(false, Ordering::Release);
                            result
                        };
                        STATS_PENDING.fetch_sub(1, Ordering::AcqRel);
                        match result {
                            Ok(()) => {
                                STATS_PERSISTED.fetch_add(1, Ordering::AcqRel);
                            }
                            Err(error) => {
                                STATS_FAILED.fetch_add(1, Ordering::AcqRel);
                                eprintln!("recall statistics writeback failed: {error:#}");
                            }
                        }
                        continue;
                    }
                };
                if STOPPING.load(Ordering::Acquire) {
                    shared_exclusive().cancel_reservation();
                    let _ = job.reply.send(Err("runtime is stopping".into()));
                    continue;
                }
                let admission = PROFILE_ADMISSION
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) {
                    shared_exclusive().cancel_reservation();
                    let _ = job.reply.send(Err("model_switch_busy".into()));
                    continue;
                }
                WRITE_RUNNING.store(true, Ordering::Release);
                drop(admission);
                let changing_context = !is_context_query(&job.args)
                    && matches!(command_name(&job.args), Some("login" | "logout" | "register" | "keygen" | "config" | "session" | "agent-config" | "sync-reset" | "account" | "space" | "fivekeys" | "super-reset"));
                let scope_write = if changing_context { Some(SCOPE_EXECUTION.write()) } else { None };
                let scope_read = if !changing_context { Some(SCOPE_EXECUTION.read()) } else { None };
                if scope_write.as_ref().is_some_and(|held| held.is_err())
                    || scope_read.as_ref().is_some_and(|held| held.is_err())
                {
                    shared_exclusive().cancel_reservation();
                    WRITE_RUNNING.store(false, Ordering::Release);
                    let _ = job.reply.send(Err("scope_mismatch: identity fence poisoned".into()));
                    continue;
                }
                let gate = shared_exclusive();
                let _held = gate.acquire_reserved();
                if !job.deadline.start() {
                    drop(_held);
                    WRITE_RUNNING.store(false, Ordering::Release);
                    let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                    continue;
                }
                if let Some(rejected) = readonly_sync_reset_rejection_locked(&job.scope, &job.args) {
                    drop(_held);
                    WRITE_RUNNING.store(false, Ordering::Release);
                    let _ = job.reply.send(rejected);
                    continue;
                }
                let captured = capture_scoped_locked(&job.scope, job.args);
                // A host-owned command was rejected before execution; its scope did not change.
                let changing_context = changing_context && !captured.as_ref().is_ok_and(|captured| {
                    captured.envelope.details.get("error_type").and_then(Value::as_str)
                        == Some("host_boundary")
                });
                let captured = captured.and_then(|captured| {
                    if changing_context {
                        advance_generation(scope_generation(&job.scope)?)
                            .map_err(|error| format!("{error:#}"))?;
                        SYNC_CV.notify_one();
                    }
                    Ok(captured)
                });
                drop(_held);
                kick_index();
                if changing_context {
                    context_changed();
                }
                WRITE_RUNNING.store(false, Ordering::Release);
                let _ = job.reply.send(captured);
            }
        });
    if writer.is_err() {
        stop_process(1);
    }
    respire_app::service::install_autosync_notifier(kick_autosync);
    respire_app::service::install_index_notifier(kick_index);
    INDEX_ON.store(true, Ordering::Release);
    let indexer = std::thread::Builder::new()
        .name("respire-index".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(index_loop);
    if let Err(error) = indexer.as_ref() {
        eprintln!("runtime failed to start the index worker: {error}");
        stop_process(1);
    }
    kick_index();
    kick_autosync();
    STARTUP_COMPLETE.store(true, Ordering::Release);
    // The private legacy host frame must follow successful library/queue setup,
    // not merely socket binding. Failure revokes the endpoint and fails closed.
    if let Err(error) = crate::host_hooks::runtime_listener_ready() {
        eprintln!("runtime private readiness failed: {error:#}");
        if let Some(startup) = startup.as_ref() {
            startup.revoke();
        }
        stop_process(1);
    }
    let mut pending = VecDeque::<Job>::new();
    let mut idle_since = Instant::now();
    loop {
        if STOPPING.load(Ordering::Acquire) {
            break;
        }
        match receive_dispatch_job(&rx, Duration::from_millis(10)) {
            Ok(job) => {
                if job.stop {
                    break;
                }
                if job.deadline.expired() {
                    let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                    continue;
                }
                idle_since = Instant::now();
                let _scope_held = match SCOPE_EXECUTION.read() {
                    Ok(held) => held,
                    Err(_) => {
                        let _ = job.reply.send(Err("scope_mismatch: identity fence poisoned".into()));
                        continue;
                    }
                };
                {
                    let gate = shared_exclusive();
                    let _held = gate.acquire(true);
                    if let Err(error) = validate_job_scope(&job.scope) {
                        let _ = job.reply.send(Err(error));
                        continue;
                    }
                }
                if respire_app::service::off_mode() {
                    let parsed = crate::cli_def::Cli::try_parse_from(
                        std::iter::once("rsrs".to_owned()).chain(job.args.iter().cloned()),
                    );
                    if parsed.is_ok_and(|cli| {
                        cli.command
                            .as_ref()
                            .is_some_and(|command| !crate::gates::is_off_allowed(command))
                    }) {
                        if !job.deadline.start() {
                            let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                            continue;
                        }
                        let captured = capture_scoped_locked(&job.scope, job.args);
                        let _ = job.reply.send(captured);
                        continue;
                    }
                } else if _store.is_none()
                    && !matches!(
                        command_name(&job.args),
                        Some("agent-config" | "memory-revision")
                    )
                {
                    let gate = shared_exclusive();
                    let _held = gate.acquire(true);
                    let opened = if !respire_app::service::service_paused() {
                        respire_app::service::initialize_runtime_store()
                    } else {
                        respire_app::service::open_store()
                    };
                    match opened {
                        Ok(store) => _store = Some(store),
                        Err(error) => {
                            let _ = job.reply.send(Err(format!("{error:#}")));
                            continue;
                        }
                    }
                }
                if matches!(
                    command_name(&job.args),
                    Some(
                        "sync"
                            | "sync-conflicts"
                            | "sync-resolve"
                            | "sync-history"
                            | "sync-restore"
                    )
                ) {
                    enqueue_manual(job);
                } else if command_name(&job.args) == Some("classify") {
                    match classify_tx.try_send(job) {
                        Ok(()) => {}
                        Err(mpsc::TrySendError::Full(job)) => {
                            let _ = job
                                .reply
                                .send(Err("classification request queue is full".into()));
                        }
                        Err(mpsc::TrySendError::Disconnected(job)) => {
                            let _ = job.reply.send(Err("classification worker is gone".into()));
                        }
                    }
                } else if is_exclusive(&job.args) {
                    shared_exclusive().reserve();
                    match write_tx.try_send(WriteJob::Command(job)) {
                        Ok(()) => {}
                        Err(mpsc::TrySendError::Full(WriteJob::Command(job))) => {
                            shared_exclusive().cancel_reservation();
                            let _ = job.reply.send(Err("write request queue is full".into()));
                        }
                        Err(mpsc::TrySendError::Disconnected(WriteJob::Command(job))) => {
                            shared_exclusive().cancel_reservation();
                            let _ = job.reply.send(Err("write worker is gone".into()));
                        }
                        Err(_) => unreachable!("only a command was submitted"),
                    }
                } else {
                    pending.push_back(job);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        pending.retain(|job| {
            if job.deadline.expired() {
                let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                false
            } else {
                true
            }
        });
        loop {
            let ordinary_available = RUNNING
                .load(Ordering::Acquire)
                .saturating_sub(LIGHT_RUNNING.load(Ordering::Acquire))
                < limit;
            let position = if LIGHT_RUNNING.load(Ordering::Acquire) < 2 {
                pending.iter().position(|job| {
                    matches!(
                        command_name(&job.args),
                        Some("show" | "list" | "status" | "memory-revision")
                    )
                })
            } else {
                None
            };
            let job = if let Some(position) = position {
                pending.remove(position)
            } else if ordinary_available {
                pending
                    .iter()
                    .position(|job| {
                        !matches!(
                            command_name(&job.args),
                            Some("show" | "list" | "status" | "memory-revision")
                        )
                    })
                    .and_then(|position| pending.remove(position))
            } else {
                None
            };
            let Some(job) = job else {
                break;
            };
            let admission = PROFILE_ADMISSION
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) && !is_status(&job.args) {
                let _ = job.reply.send(Err("model_switch_busy".into()));
                continue;
            }
            let light_job = matches!(
                command_name(&job.args),
                Some("show" | "list" | "status" | "memory-revision")
            );
            if light_job {
                LIGHT_RUNNING.fetch_add(1, Ordering::AcqRel);
            }
            let status_job = is_status(&job.args);
            if status_job {
                RUNNING_STATUS.fetch_add(1, Ordering::AcqRel);
            }
            RUNNING.fetch_add(1, Ordering::AcqRel);
            drop(admission);
            let reply = job.reply.clone();
            let spawned = std::thread::Builder::new()
                .name("respire-read".into())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let _slot = RunningGuard {
                        status: status_job,
                        light: light_job,
                    };
                    if !job.deadline.start() {
                        let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                        return;
                    }
                    mark_worker();
                    let scope = job.scope.clone();
                    let revision_probe = command_name(&job.args) == Some("memory-revision");
                    let captured = capture_scoped(&scope, job.args);
                    if !revision_probe {
                        kick_index();
                    }
                    let result = captured.and_then(|captured| validate_job_scope(&scope).map(|_| captured));
                    let _ = job.reply.send(result);
                });
            if spawned.is_err() {
                RUNNING.fetch_sub(1, Ordering::AcqRel);
                if light_job {
                    LIGHT_RUNNING.fetch_sub(1, Ordering::AcqRel);
                }
                if status_job {
                    RUNNING_STATUS.fetch_sub(1, Ordering::AcqRel);
                }
                let _ = reply.send(Err("failed to start a read thread".into()));
            }
        }
        if let Some(idle) = idle {
            if RUNNING.load(Ordering::Acquire) > 0
                || WRITE_RUNNING.load(Ordering::Acquire)
                || CLASSIFY_RUNNING.load(Ordering::Acquire)
                || sync_running()
                || index_has_work()
                || !pending.is_empty()
            {
                idle_since = Instant::now();
            } else if idle_since.elapsed() >= idle {
                break;
            }
        }
    }
    {
        let _fence = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
        STOPPING.store(true, Ordering::Release);
    }
    SYNC_CV.notify_all();
    INDEX_CV.notify_all();
    if let Ok(mut installed) = WRITE_TX.lock() {
        installed.take();
    }
    drop(write_tx);
    drop(classify_tx);
    for job in pending {
        let _ = job.reply.send(Err("runtime is stopping".into()));
    }
    let mut clean = true;
    if let Ok(writer) = writer {
        if writer.join().is_err() {
            eprintln!("write worker panicked during shutdown");
            clean = false;
        }
    }
    if let Ok(classifier) = classifier {
        if classifier.join().is_err() {
            eprintln!("classification worker panicked during shutdown");
            clean = false;
        }
    }
    if let Ok(indexer) = indexer {
        if indexer.join().is_err() {
            eprintln!("background index worker panicked during shutdown");
            clean = false;
        }
    }
    wait_for_drain(crate::host_hooks::managed_id().is_some(), || {
        for job in rx.try_iter() {
            let _ = job.reply.send(Err("runtime is stopping".into()));
        }
        drain_busy()
    });
    {
        let _admitted = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
        set_control_state("resources_closing");
    }
    STORE_READY.store(false, Ordering::Release);
    if let Err(error) = respire_app::core_sdk::worker::shutdown() {
        eprintln!("Core worker shutdown failed: {error:#}");
        set_control_state("failed");
        // Keep ownership until stop_process confirms native-child cleanup.
        stop_process(1);
    }
    drop(_store);
    drop(_lock);
    if !STOP_FORCE_TRIGGERED.load(Ordering::Acquire) {
        mark_stop_unfinished(Vec::new());
    }
    set_control_state(if !clean {
        "failed"
    } else if STOP_FORCE_TRIGGERED.load(Ordering::Acquire) {
        "forced_timeout"
    } else {
        "drained"
    });
    stop_process(if clean { 0 } else { 1 });
}

fn result_state(response: Option<&RpcResponse>, pending: bool) -> &'static str {
    if pending {
        "pending"
    } else {
        match response {
            Some(response) if response.ok => "completed",
            Some(_) => "failed",
            None => "unknown",
        }
    }
}

pub fn cached(id: &str) -> Option<RpcResponse> {
    CACHE
        .lock()
        .ok()?
        .iter()
        .find(|entry| entry.operation_id == id)
        .map(|entry| entry.response.clone())
}

pub fn remember(operation_id: &str, response: &RpcResponse) {
    if operation_id.is_empty() {
        return;
    }
    if let Ok(mut cache) = CACHE.lock() {
        cache.retain(|entry| entry.operation_id != operation_id);
        cache.push(CachedResponse {
            operation_id: operation_id.to_owned(),
            response: response.clone(),
        });
        if cache.len() > 64 {
            let extra = cache.len() - 64;
            cache.drain(0..extra);
        }
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_whitespace)
}

fn requires_scope(method: &str) -> bool {
    !matches!(method, "runtime.status" | "runtime.stop" | "assets.status" | "cli.progress" | "model.catalog" | "model.progress")
}

fn validate_request_scope(request: &RpcRequest) -> Result<(), (String, String)> {
    if !requires_scope(&request.method) { return Ok(()); }
    if request.scope.is_none() {
        return Err(("scope_required".to_owned(), "business requests require scope".to_owned()));
    }
    if matches!(request.method.as_str(), "runtime.result" | "model.control") {
        let _scope_held = SCOPE_EXECUTION.try_read().map_err(|_| (
            "scope_mismatch".to_owned(), "Runtime identity is changing or unavailable".to_owned(),
        ))?;
        let _fence = ADMISSIONS.lock().map_err(|_| (
            "admission_lock_poisoned".to_owned(), "runtime admission lock is poisoned".to_owned(),
        ))?;
        return validate_scope(request.scope.as_ref(), &current_scope());
    }
    let _scope_held = SCOPE_EXECUTION.read().map_err(|_| (
        "scope_mismatch".to_owned(), "identity fence poisoned".to_owned(),
    ))?;
    let gate = shared_exclusive();
    let _held = gate.acquire(true);
    let _fence = ADMISSIONS.lock().map_err(|_| (
        "admission_lock_poisoned".to_owned(), "runtime admission lock is poisoned".to_owned(),
    ))?;
    validate_scope(request.scope.as_ref(), &request_current_scope(request)?)
}

fn validate_business_config() -> Result<(), String> {
    respire_app::service::validate_client_config()
        .map_err(|error| format!("invalid_config: {error:#}"))
}

fn request_current_scope(request: &RpcRequest) -> Result<RuntimeRequestScope, (String, String)> {
    // Result lookup and cancellation keep their identity fence even with broken config.
    if !matches!(request.method.as_str(), "runtime.result" | "model.control") {
        validate_business_config().map_err(|error| ("invalid_config".to_owned(), error))?;
    }
    Ok(current_scope())
}

fn current_scope() -> RuntimeRequestScope {
    RuntimeRequestScope {
        account_id: account_identity(),
        instance_id: process_identity().instance_id,
        generation: crate::rpc_worker::wire_generation(),
    }
}

fn validate_scope(
    scope: Option<&RuntimeRequestScope>,
    current: &RuntimeRequestScope,
) -> Result<(), (String, String)> {
    let Some(scope) = scope else {
        return Err(("scope_required".to_owned(), "business requests require scope".to_owned()));
    };
    if scope.account_id.trim().is_empty()
        || scope.instance_id.trim().is_empty()
        || scope.generation == 0
        || current.account_id.trim().is_empty()
        || current.instance_id.trim().is_empty()
        || current.generation == 0
        || scope != current
    {
        return Err(("scope_mismatch".to_owned(), "request scope does not match this Runtime identity".to_owned()));
    }
    Ok(())
}

fn operation_scope(scope: &RuntimeRequestScope) -> String {
    format!("{}:{}:{}:{}:{}", scope.account_id.len(), scope.account_id,
        scope.instance_id.len(), scope.instance_id, scope.generation)
}

fn operation_identity(request: &RpcRequest) -> Result<OperationIdentity, (String, String)> {
    let scope = request.scope.as_ref().ok_or_else(|| (
        "scope_required".to_owned(), "business requests require scope".to_owned(),
    ))?;
    operation_identity_for_scope(request, scope)
}

// Legacy result IDs remain valid across a legitimate in-process generation
// transition, but never cross an account or process instance. Modern keys retain
// their existing generation fencing and lifetime idempotency policy.
fn legacy_operation_key(scope: &RuntimeRequestScope, id: &str) -> String {
    scoped_operation_key(&format!("legacy:{}:{}:{}:{}", scope.account_id.len(),
        scope.account_id, scope.instance_id.len(), scope.instance_id), id)
}
fn operation_identity_mode(request: &RpcRequest, legacy: bool)
    -> Result<OperationIdentity, (String, String)> {
    let mut operation = operation_identity(request)?;
    if legacy {
        operation.storage_id = legacy_operation_key(&operation.scope, &operation.operation_id);
        operation.storage_key = operation.storage_id.clone();
    }
    Ok(operation)
}

// The writer already owns the shared gate; other executors take it before
// this check, then retain the captured generation in their thread context.
fn validate_job_scope(scope: &RuntimeRequestScope) -> Result<(), String> {
    // Reads can write querylog/statistics, so queued reads have no maintenance exemption.
    if business_paused() {
        return Err("runtime_maintenance: runtime maintenance rejected queued execution".to_owned());
    }
    validate_business_config()?;
    validate_scope(Some(scope), &current_scope()).map_err(|(code, _)| code)?;
    respire_app::service::ensure_runtime_profile().map_err(|error| format!("scope_mismatch: {error:#}"))?;
    crate::legacy_host::verify_execution(scope).map_err(|error| format!("{error:#}"))
}

fn capture_scoped(scope: &RuntimeRequestScope, args: Vec<String>) -> CommandResult {
    let _scope_held = SCOPE_EXECUTION.read().map_err(|_| "scope_mismatch: identity fence poisoned".to_owned())?;
    {
        let gate = shared_exclusive();
        let _held = gate.acquire(true);
        validate_job_scope(scope)?;
    }
    capture_scoped_locked(scope, args)
}

// Called with the scope and exclusive execution fences held, before any command effects.
fn readonly_sync_reset_rejection_locked(
    scope: &RuntimeRequestScope,
    args: &[String],
) -> Option<CommandResult> {
    if command_name(args) != Some("sync-reset") {
        return None;
    }
    let parsed = crate::cli_def::Cli::try_parse_from(
        std::iter::once("rsrs".to_owned()).chain(args.iter().cloned()),
    ).ok()?;
    if !matches!(parsed.command, Some(crate::cli_def::Command::SyncReset)) {
        return None;
    }
    if let Err(error) = validate_job_scope(scope) {
        return Some(Err(error));
    }
    let error = respire_app::service::ensure_writable().err()?;
    let (envelope, exit) = crate::output_emit::command_failure(&error);
    Some(Ok(crate::output_state::Captured { exit, envelope }))
}

fn capture_scoped_locked(scope: &RuntimeRequestScope, args: Vec<String>) -> CommandResult {
    validate_job_scope(scope)?;
    let generation = scope_generation(scope)?;
    SYNC_CONTEXT.with(|context| {
        let previous = context.get();
        let boundary = previous.filter(|(epoch, _)| *epoch == generation)
            .map_or(-1, |(_, boundary)| boundary);
        context.set(Some((generation, boundary)));
        let captured = crate::host_hooks::capture_run(args);
        context.set(previous);
        Ok(captured)
    })
}

fn scope_generation(scope: &RuntimeRequestScope) -> Result<usize, String> {
    scope.generation.checked_sub(1)
        .and_then(|generation| usize::try_from(generation).ok())
        .ok_or_else(|| "scope_mismatch".to_owned())
}

fn scoped_operation_key(scope: &str, id: &str) -> String {
    format!("{}:{scope}{id}", scope.len())
}

fn operation_identity_for_scope(
    request: &RpcRequest,
    scope: &RuntimeRequestScope,
) -> Result<OperationIdentity, (String, String)> {
    let scope_key = operation_scope(scope);
    let operation_id = request.operation_id.as_deref().unwrap_or(&request.id);
    let idempotency_key = request.idempotency_key.as_deref().unwrap_or(operation_id);
    for (value, code) in [
        (operation_id, "invalid_operation_id"),
        (idempotency_key, "invalid_idempotency_key"),
    ] {
        if !valid_identifier(value) {
            return Err((
                code.to_owned(),
                "operation identifiers must contain 1 to 256 non-space characters".to_owned(),
            ));
        }
    }
    if request
        .parent_operation_id
        .as_deref()
        .is_some_and(|parent| !valid_identifier(parent))
    {
        return Err((
            "invalid_parent_operation_id".to_owned(),
            "parent operation ID is invalid".to_owned(),
        ));
    }
    let mut args = request
        .args
        .iter()
        .map(|arg| Value::String(arg.clone()))
        .collect::<Vec<_>>();
    if matches!(request.method.as_str(), "model.configure" | "model.switch") {
        if let Some(first) = args.first_mut() {
            *first = serde_json::from_str(&request.args[0]).map_err(|_| {
                (
                    "invalid_arguments".to_owned(),
                    "model request requires valid configuration JSON".to_owned(),
                )
            })?;
        }
    }
    let encoded = serde_json::to_vec(&json!({
        "protocol": request.v, "method": request.method, "args": args,
        "parent_operation_id": request.parent_operation_id,
        "lifecycle": request.lifecycle, "scope": scope,
    }))
    .map_err(|_| {
        (
            "fingerprint_failed".to_owned(),
            "failed to normalize request fingerprint".to_owned(),
        )
    })?;
    Ok(OperationIdentity {
        scope: scope.clone(),
        operation_id: operation_id.to_owned(),
        storage_id: scoped_operation_key(&scope_key, operation_id),
        storage_key: scoped_operation_key(&scope_key, idempotency_key),
        fingerprint: format!("{:x}", Sha256::digest(encoded)),
    })
}

fn admit(
    request: &RpcRequest,
    operation: &OperationIdentity,
) -> Result<Admission, (String, String)> {
    admit_with_retention(request, operation, false)
}

fn admit_with_retention(request: &RpcRequest, operation: &OperationIdentity,
    legacy: bool) -> Result<Admission, (String, String)> {
    let _scope_held = SCOPE_EXECUTION.read().map_err(|_| (
        "scope_mismatch".to_owned(), "identity fence poisoned".to_owned(),
    ))?;
    let gate = shared_exclusive();
    // Legacy progress must observe the command while it holds the execution gate.
    let _held = if matches!(request.method.as_str(), "model.control" | "cli.progress") { None } else { Some(gate.acquire(true)) };
    let mut admitted = ADMISSIONS.lock().map_err(|_| (
        "admission_lock_poisoned".to_owned(), "runtime admission lock is poisoned".to_owned(),
    ))?;
    let current = request_current_scope(request)?;
    if legacy { admit_legacy_locked(request, operation, &current, &mut admitted) }
    else { admit_locked(request, operation, &current, &mut admitted) }
}

// Released v1 semantics: only inflight and last-64 completed results. No
// persistence or lifetime tombstones; an unknown result never authorizes retry.
fn admit_legacy_locked(request: &RpcRequest, operation: &OperationIdentity,
    current: &RuntimeRequestScope, admitted: &mut Vec<Admitted>)
    -> Result<Admission, (String, String)> {
    validate_scope(request.scope.as_ref(), current)?;
    validate_scope(Some(&operation.scope), current)?;
    let mut inflight = INFLIGHT.lock().map_err(|_| (
        "admission_lock_poisoned".into(), "inflight lock poisoned".into()))?;
    let cache = CACHE.lock().map_err(|_| (
        "admission_lock_poisoned".into(), "cache lock poisoned".into()))?;
    if let Some(entry) = cache.iter().find(|entry| entry.operation_id == operation.storage_id) {
        return Ok(Admission::Replay(entry.response.clone()));
    }
    if inflight.contains(&operation.storage_id) { return Ok(Admission::InProgress); }
    if request.method != "model.control" && business_paused() {
        return Err(("runtime_maintenance".into(), "runtime is draining".into()));
    }
    inflight.insert(operation.storage_id.clone());
    admitted.push(Admitted { operation_id: operation.operation_id.clone(), kind: "rpc" });
    Ok(Admission::New(AdmissionGuard(operation.operation_id.clone())))
}

#[cfg(test)]
fn admit_scoped(
    request: &RpcRequest,
    operation: &OperationIdentity,
    current: &RuntimeRequestScope,
) -> Result<Admission, (String, String)> {
    let mut admitted = ADMISSIONS.lock().map_err(|_| (
        "admission_lock_poisoned".to_owned(), "runtime admission lock is poisoned".to_owned(),
    ))?;
    admit_locked(request, operation, current, &mut admitted)
}

fn admit_locked(
    request: &RpcRequest,
    operation: &OperationIdentity,
    current: &RuntimeRequestScope,
    admitted: &mut Vec<Admitted>,
) -> Result<Admission, (String, String)> {
    // Caller holds the admission/stop fence before reading the current identity.
    validate_scope(request.scope.as_ref(), current)?;
    validate_scope(Some(&operation.scope), current)?;
    let lock_error = || {
        (
            "idempotency_lock_poisoned".to_owned(),
            "runtime idempotency lock is poisoned".to_owned(),
        )
    };
    let mut idempotency = IDEMPOTENCY.lock().map_err(|_| lock_error())?;
    let mut operation_keys = OPERATION_KEYS.lock().map_err(|_| lock_error())?;
    let mut inflight = INFLIGHT.lock().map_err(|_| lock_error())?;
    let cache = CACHE.lock().map_err(|_| lock_error())?;
    if let Some(previous_key) = operation_keys.get(&operation.storage_id) {
        if *previous_key != operation.storage_key {
            return Err((
                "idempotency_conflict".to_owned(),
                "operation ID is bound to a different idempotency key".to_owned(),
            ));
        }
    }
    if let Some(record) = idempotency.get(&operation.storage_key) {
        if record.fingerprint != operation.fingerprint
            || record.operation_id != operation.storage_id
        {
            return Err((
                "idempotency_conflict".to_owned(),
                "idempotency key is bound to a different request".to_owned(),
            ));
        }
        if let Some(mut response) = cache
            .iter()
            .find(|entry| entry.operation_id == operation.storage_id)
            .map(|entry| entry.response.clone())
        {
            response.id = request.id.clone();
            return Ok(Admission::Replay(response));
        }
        return Ok(if inflight.contains(&operation.storage_id) {
            Admission::InProgress
        } else {
            Admission::Unknown
        });
    }
    if request.method != "model.control" && business_paused() {
        return Err((
            "runtime_maintenance".to_owned(),
            "runtime is draining and rejected new business".to_owned(),
        ));
    }
    // Retain admission tombstones until exit; evicting them could replay a committed write.
    if idempotency.len() >= 4096 {
        return Err(("idempotency_capacity".to_owned(), "runtime retained 4096 operation identities; existing results remain queryable, but new operations are not accepted".to_owned()));
    }
    idempotency.insert(
        operation.storage_key.clone(),
        IdempotencyRecord {
            operation_id: operation.storage_id.clone(),
            fingerprint: operation.fingerprint.clone(),
        },
    );
    operation_keys.insert(operation.storage_id.clone(), operation.storage_key.clone());
    inflight.insert(operation.storage_id.clone());
    admitted.push(Admitted {
        operation_id: operation.operation_id.clone(),
        kind: "rpc",
    });
    Ok(Admission::New(AdmissionGuard(operation.operation_id.clone())))
}

/// Only a refused connection permits startup; authentication and access failures
/// leave the existing service untouched.
pub fn probe_runtime() -> Result<Option<crate::net_rpc::Health>> {
    match crate::net_rpc::health() {
        Ok(health) => Ok(Some(health)),
        Err(error)
            if matches!(
                error.downcast_ref::<crate::runtime_error::RuntimeError>(),
                Some(crate::runtime_error::RuntimeError::Unavailable)
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static DIRECT_GATE_BARRIER: std::sync::OnceLock<(String, Arc<std::sync::Barrier>)> = std::sync::OnceLock::new();
    pub(super) fn wait_before_direct_gate(id: &str) {
        if let Some((_, barrier)) = DIRECT_GATE_BARRIER.get().filter(|(expected, _)| expected == id) {
            barrier.wait(); barrier.wait();
        }
    }
    #[test]
    fn legacy_v1_retention_and_generation_isolated() -> Result<()> {
        let root = tempfile::tempdir()?;
        for mode in ["exercise", "restart"] {
            let status = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "rpc_serve::tests::legacy_v1_retention_helper", "--ignored", "--nocapture"])
                .env("RSRS_SYNTHETIC_LEGACY_TEST", mode)
                .env("RSRS_SYNTHETIC_LEGACY_ROOT", root.path())
                .stdin(std::process::Stdio::null()).status()?;
            anyhow::ensure!(status.success(), "isolated legacy v1 test failed: {mode}");
        }
        Ok(())
    }
    #[test]
    #[ignore = "spawned separately by the legacy v1 retention test"]
    fn legacy_v1_retention_helper() -> Result<()> {
        static VALID: AtomicBool = AtomicBool::new(true);
        static EFFECTS: AtomicUsize = AtomicUsize::new(0);
        fn verify() -> Result<()> {
            anyhow::ensure!(VALID.load(Ordering::Acquire), "synthetic account changed"); Ok(())
        }
        fn execute(_: Vec<String>) -> crate::output_state::Captured {
            EFFECTS.fetch_add(1, Ordering::AcqRel);
            crate::output_state::Captured { exit: 7, envelope: ResultEnvelope::new(
                "synthetic", OutputStatus::Fail, json!({"synthetic":true}), Vec::new()) }
        }
        fn prepare(id: &str, method: &str, args: &[&str]) -> Result<(RpcRequest, crate::legacy_host::Projection)> {
            crate::legacy_host::prepare(&serde_json::to_vec(&json!({"v":1,"id":id,
                "method":method,"args":args,"lifecycle":null}))?)?.context("legacy mode absent")
        }
        let root = std::path::PathBuf::from(std::env::var_os("RSRS_SYNTHETIC_LEGACY_ROOT")
            .context("missing synthetic root")?);
        std::env::set_var("RSRS_DATA_DIR", &root);
        std::env::set_var("RSRS_M3_DIR", root.join("models"));
        std::fs::write(root.join("client.json"), br#"{"service_mode":"off","autosync":false,"cure_auto":false}"#)?;
        assert!(crate::host_hooks::install(crate::host_hooks::HostHooks {
            capture_run: Some(execute), ..Default::default()
        }));
        let initial = current_scope();
        crate::legacy_host::install(initial.clone(), "synthetic-installation".into(), verify)?;
        let (jobs, queued) = std::sync::mpsc::channel();
        if std::env::var("RSRS_SYNTHETIC_LEGACY_TEST").as_deref() == Ok("restart") {
            let previous: Value = serde_json::from_slice(&std::fs::read(root.join("previous.json"))?)?;
            assert_eq!(previous["account_id"], initial.account_id);
            assert_ne!(previous["instance_id"], initial.instance_id);
            let (query, projection) = prepare("inspect-after-restart", "runtime.result", &["before-restart"])?;
            let response = crate::legacy_host::project(dispatch_inner(query, &jobs, true), projection);
            assert_eq!(response.envelope.context("missing lookup")?.summary["state"], "unknown");
            assert_eq!(EFFECTS.load(Ordering::Acquire), 0);
            return Ok(());
        }
        let progress_scope = crate::progress::Scope::start(Some("busy-parent".into()), false, false)
            .context("missing progress scope")?;
        crate::progress::phase("Waiting for synthetic server", "Waiting for synthetic server");
        let (progress, _) = prepare("progress-during-exclusive", "cli.progress", &["busy-parent"])?;
        let mut stale_progress = progress.clone();
        stale_progress.id = "stale-progress".into();
        let gate = shared_exclusive();
        let held = gate.acquire(true);
        let (progress_reply, progress_result) = std::sync::mpsc::channel();
        let progress_jobs = jobs.clone();
        let progress_worker = std::thread::spawn(move || {
            let _ = progress_reply.send(dispatch_inner(progress, &progress_jobs, true));
        });
        let observed = progress_result.recv_timeout(Duration::from_secs(5));
        // Release the gate even when the old blocking behavior regresses.
        drop(held);
        progress_worker.join().map_err(|_| anyhow::anyhow!("progress handler panicked"))?;
        let observed = observed.context("legacy progress blocked behind the business execution gate")?;
        assert!(observed.ok);
        assert_eq!(observed.envelope.context("missing progress response")?.summary["phase"],
            "Waiting for synthetic server");
        assert_eq!(EFFECTS.load(Ordering::Acquire), 0, "progress must not execute business");
        assert!(queued.try_recv().is_err(), "progress must not queue business");
        drop(progress_scope);
        let old_wire = serde_json::to_vec(&json!({"v":1,"id":"optional-fields","method":"cli.exec",
            "args":["--json","status"],"queue_wait_ms":1200,"lifecycle":null}))?;
        let (optional, _) = crate::legacy_host::prepare(&old_wire)?.context("missing old request")?;
        assert_eq!(optional.queue_wait_ms, Some(1200));
        assert!(crate::legacy_host::prepare(&serde_json::to_vec(&optional)?)?.is_none(),
            "modern scoped request must keep modern retention");
        let (request, original_projection) = prepare("same-id", "cli.exec", &["--json", "sync-reset"])?;
        let modern_before = operation_identity_mode(&request, false).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let legacy_before = operation_identity_mode(&request, true).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let (reply, results) = std::sync::mpsc::channel();
        for _ in 0..2 {
            let reply = reply.clone();
            dispatch_deferred_inner(request.clone(), &jobs, true, move |response| { let _ = reply.send(response); });
        }
        let job = queued.recv_timeout(Duration::from_secs(5))?;
        assert!(queued.try_recv().is_err(), "same inflight ID must queue only once");
        assert_eq!(results.recv_timeout(Duration::from_secs(5))?.code.as_deref(), Some("request_in_progress"));
        assert!(job.deadline.start());
        let captured = {
            let _scope = SCOPE_EXECUTION.write().map_err(|_| anyhow::anyhow!("scope poisoned"))?;
            let gate = shared_exclusive(); let _held = gate.acquire(true);
            let captured = capture_scoped_locked(&job.scope, job.args);
            // The same production generation transition used after sync-reset.
            advance_generation(scope_generation(&job.scope).map_err(anyhow::Error::msg)?)?;
            captured
        };
        job.reply.send(captured).map_err(anyhow::Error::msg)?;
        let original = crate::legacy_host::project(results.recv_timeout(Duration::from_secs(5))?, original_projection);
        assert_eq!(original.exit, 7); assert!(!original.ok);
        assert_eq!(EFFECTS.load(Ordering::Acquire), 1);
        assert_eq!(current_scope().generation, initial.generation + 1);
        assert_eq!(dispatch_inner(stale_progress, &jobs, true).code.as_deref(), Some("scope_mismatch"));
        assert!(capture_scoped(&initial, vec!["status".into()]).is_err(),
            "old queued generation must not execute after the transition");
        assert!(crate::legacy_host::health().is_ok(), "legal generation change must not revoke the actor");
        let (after, _) = prepare("same-id", "cli.exec", &["--json", "sync-reset"])?;
        let modern_after = operation_identity_mode(&after, false).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let legacy_after = operation_identity_mode(&after, true).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        assert_ne!(modern_before.storage_id, modern_after.storage_id);
        assert_eq!(legacy_before.storage_id, legacy_after.storage_id);
        let (query, projection) = prepare("inspect-same-id", "runtime.result", &["same-id"])?;
        let found = crate::legacy_host::project(dispatch_inner(query, &jobs, true), projection);
        let summary = found.envelope.context("missing original result")?.summary;
        assert_eq!(summary["state"], "completed");
        assert_eq!(summary["response"]["id"], "same-id"); assert_eq!(summary["response"]["exit"], 7);
        let (reply, result) = std::sync::mpsc::channel();
        dispatch_deferred_inner(after, &jobs, true, move |response| { let _ = reply.send(response); });
        assert_eq!(result.recv_timeout(Duration::from_secs(5))?.exit, 7);
        assert!(queued.try_recv().is_err()); assert_eq!(EFFECTS.load(Ordering::Acquire), 1);
        // Adapter admission/cache capacity, not full HTTP engine performance.
        for number in 0..4_100 {
            let (request, _) = prepare(&format!("poll-{number}"), "cli.exec", &["--json", "status"])?;
            let operation = operation_identity_mode(&request, true).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let guard = match admit_with_retention(&request, &operation, true) {
                Ok(Admission::New(guard)) => guard, _ => anyhow::bail!("poll incorrectly consumed a lifetime slot"),
            };
            remember(&operation.storage_id, &status_response(&request));
            INFLIGHT.lock().map_err(|_| anyhow::anyhow!("inflight poisoned"))?.remove(&operation.storage_id);
            drop(guard);
        }
        assert_eq!(CACHE.lock().map_err(|_| anyhow::anyhow!("cache poisoned"))?.len(), 64);
        assert!(IDEMPOTENCY.lock().map_err(|_| anyhow::anyhow!("ledger poisoned"))?.is_empty());
        assert!(OPERATION_KEYS.lock().map_err(|_| anyhow::anyhow!("keys poisoned"))?.is_empty());
        let (query, projection) = prepare("inspect-expired", "runtime.result", &["same-id"])?;
        let unknown = crate::legacy_host::project(dispatch_inner(query, &jobs, true), projection);
        assert_eq!(unknown.envelope.context("missing expired lookup")?.summary["state"], "unknown");
        assert_eq!(EFFECTS.load(Ordering::Acquire), 1, "queries never resubmit business");
        let (retained, _) = prepare("before-restart", "cli.exec", &["--json", "status"])?;
        let retained_key = operation_identity_mode(&retained, true).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        remember(&retained_key.storage_id, &status_response(&retained));
        assert!(cached(&retained_key.storage_id).is_some());
        std::fs::write(root.join("previous.json"), serde_json::to_vec(&initial)?)?;
        // Modern retention still keeps a lifetime tombstone after a lost receipt.
        let modern = operation_identity_mode(&retained, false).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let guard = match admit_with_retention(&retained, &modern, false) {
            Ok(Admission::New(guard)) => guard, _ => anyhow::bail!("modern admission changed"),
        };
        INFLIGHT.lock().map_err(|_| anyhow::anyhow!("inflight poisoned"))?.remove(&modern.storage_id);
        drop(guard);
        assert!(matches!(admit_with_retention(&retained, &modern, false), Ok(Admission::Unknown)));
        // A direct handler already admitted before revocation must recheck after
        // the execution gate. Invalid payloads distinguish rejection before the
        // real model handlers without configuring or loading any model.
        let (configure, _) = prepare("waiting-configure", "model.configure", &["{}"])?;
        let (control, _) = prepare("waiting-control", "model.control", &["not-an-action"])?;
        let (revoked_progress, _) = prepare("revoked-progress", "cli.progress", &["busy-parent"])?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        DIRECT_GATE_BARRIER.set((configure.id.clone(), barrier.clone()))
            .map_err(|_| anyhow::anyhow!("direct gate barrier already installed"))?;
        let worker_jobs = jobs.clone();
        let worker = std::thread::spawn(move || dispatch_inner(configure, &worker_jobs, true));
        barrier.wait();
        let gate = shared_exclusive();
        let held = gate.acquire(true);
        barrier.wait();
        VALID.store(false, Ordering::Release); assert!(crate::legacy_host::health().is_err());
        VALID.store(true, Ordering::Release);
        drop(held);
        let refused = worker.join().map_err(|_| anyhow::anyhow!("direct handler panicked"))?;
        assert_eq!(refused.code.as_deref(), Some("legacy_host_binding_changed"));
        assert_eq!(dispatch_inner(control, &jobs, true).code.as_deref(), Some("legacy_host_binding_changed"));
        assert_eq!(dispatch_inner(revoked_progress, &jobs, true).code.as_deref(), Some("legacy_host_binding_changed"));
        assert!(capture_scoped(&current_scope(), vec!["status".into()]).is_err());
        assert_eq!(EFFECTS.load(Ordering::Acquire), 1);
        Ok(())
    }
    fn fixture_scope(account: &str, generation: u64) -> RuntimeRequestScope {
        RuntimeRequestScope {
            account_id: account.to_owned(),
            instance_id: "instance-1".to_owned(),
            generation,
        }
    }

    #[test]
    fn business_scope_rejects_missing_empty_and_stale_identity() {
        for scope in [None, Some(fixture_scope("", 0))] {
            let (jobs, queued) = std::sync::mpsc::channel();
            let (reply, received) = std::sync::mpsc::channel();
            dispatch_deferred(RpcRequest {
                v: PROTOCOL_V + 1,
                id: "wrong-version".to_owned(),
                method: "cli.exec".to_owned(),
                args: Vec::new(),
                scope,
                operation_id: None,
                idempotency_key: None,
                parent_operation_id: None,
                queue_wait_ms: None,
                lifecycle: None,
            }, &jobs, move |response| { let _ = reply.send(response); });
            assert!(matches!(received.try_recv(), Ok(response)
                if response.code.as_deref() == Some("protocol_version_mismatch")));
            assert!(matches!(queued.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
        }
        let current = fixture_scope("account-a", 8);
        assert_eq!(scope_generation(&current), Ok(7));
        let initial: u64 = crate::rpc_worker::generation_on_wire(0);
        assert_eq!(initial, 1);
        assert_eq!(crate::rpc_worker::generation_on_wire(7), current.generation);
        assert_eq!(crate::rpc_worker::generation_on_wire(usize::MAX), usize::MAX as u64);
        assert!(scope_generation(&fixture_scope("account-a", 0)).is_err());
        assert!(matches!(validate_scope(None, &current), Err((code, _)) if code == "scope_required"));
        assert!(validate_scope(Some(&current), &current).is_ok());
        for stale in [
            fixture_scope("account-b", 8),
            fixture_scope("account-a", 7),
            fixture_scope("account-a", 0),
            fixture_scope("", 8),
            RuntimeRequestScope { instance_id: String::new(), ..current.clone() },
            RuntimeRequestScope { instance_id: "instance-2".to_owned(), ..current.clone() },
        ] {
            assert!(matches!(validate_scope(Some(&stale), &current), Err((code, _)) if code == "scope_mismatch"));
        }
        assert!(validate_scope(Some(&fixture_scope("", 8)), &fixture_scope("", 8)).is_err());
        for method in ["cli.exec", "model.configure", "model.switch", "model.resume", "model.prepare", "index.prepare", "model.control", "runtime.result"] {
            assert!(requires_scope(method), "{method} must be scoped");
        }
        for method in ["runtime.status", "model.catalog", "model.progress", "assets.status", "cli.progress"] {
            assert!(!requires_scope(method), "{method} must remain queryable during drain");
        }
    }

    #[test]
    fn idempotent_admission_replays_or_reports_unknown() -> Result<()> {
        let _serial = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        struct RestoreConfigEnv(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for RestoreConfigEnv {
            fn drop(&mut self) {
                for (key, value) in [("RSRS_DATA_DIR", self.0.as_ref()), ("RSRS_M3_DIR", self.1.as_ref())] {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
        let root = tempfile::tempdir()?;
        let _environment = RestoreConfigEnv(std::env::var_os("RSRS_DATA_DIR"), std::env::var_os("RSRS_M3_DIR"));
        std::env::set_var("RSRS_DATA_DIR", root.path());
        std::env::set_var("RSRS_M3_DIR", root.path().join("models"));
        fn request(id: &str, args: &[&str]) -> RpcRequest {
            RpcRequest {
                scope: Some(fixture_scope("account-a", 1)),
                v: PROTOCOL_V,
                id: id.to_owned(),
                operation_id: Some("operation-1".to_owned()),
                idempotency_key: Some("idempotency-1".to_owned()),
                parent_operation_id: None,
                method: "runtime.status".to_owned(),
                args: args.iter().map(|item| item.to_string()).collect(),
                queue_wait_ms: None,
                lifecycle: None,
            }
        }

        let first = request("request-1", &["a"]);
        for (error, code) in [
            ("runtime_maintenance: queued execution was fenced", "runtime_maintenance"),
            ("invalid_config: malformed client config", "invalid_config"),
            ("scope_mismatch: stale generation", "scope_mismatch"),
            ("runtime worker is gone", "daemon_unavailable"),
        ] {
            let response = command_response(&first, Err(error.to_owned()));
            assert!(!response.ok);
            assert_eq!(response.code.as_deref(), Some(code));
            assert_eq!(result_state(Some(&response), false), "failed");
        }
        let current = fixture_scope("account-a", 1);
        let Some(operation) = operation_identity_for_scope(&first, &current).ok() else {
            panic!("operation identity must be valid");
        };
        *CACHE.lock().unwrap_or_else(|error| error.into_inner()) = Vec::new();
        IDEMPOTENCY
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        OPERATION_KEYS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        INFLIGHT
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();

        let admission = match admit_scoped(&first, &operation, &current) {
            Ok(Admission::New(guard)) => guard,
            other => panic!("expected admission, got {other:?}"),
        };
        assert!(ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner())
            .iter().any(|item| item.operation_id == operation.operation_id));
        assert!(matches!(
            admit_scoped(&request("request-in-flight", &["a"]), &operation, &current),
            Ok(Admission::InProgress)
        ));
        for stale in [
            fixture_scope("account-b", 1),
            fixture_scope("account-a", 2),
            RuntimeRequestScope { instance_id: "new-instance".to_owned(), ..current.clone() },
        ] {
            assert!(matches!(admit_scoped(&first, &operation, &stale),
                Err((code, _)) if code == "scope_mismatch"));
            assert_ne!(scoped_operation_key(&operation_scope(&stale), "operation-1"), operation.storage_id);
        }

        let mut pending_response = status_response(&first);
        pending_response.envelope = Some(ResultEnvelope::new("model.prepare", OutputStatus::Pending,
            json!({"operation_id":operation.operation_id}), Vec::new()));
        remember(&operation.storage_id, &pending_response);
        assert_eq!(result_state(cached(&operation.storage_id).as_ref(), true), "pending");
        assert!(matches!(admit_scoped(&first, &operation, &current), Ok(Admission::Replay(_))));
        let mut response = status_response(&first);
        response.operation_id = Some(operation.operation_id.clone());
        remember(&operation.storage_id, &response);
        INFLIGHT
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&operation.storage_id);
        drop(admission);
        assert_eq!(result_state(cached(&operation.storage_id).as_ref(), false), "completed");
        match admit_scoped(&request("request-2", &["a"]), &operation, &current) {
            Ok(Admission::Replay(replay)) => {
                assert_eq!(replay.id, "request-2");
                assert_eq!(replay.operation_id.as_deref(), Some("operation-1"));
                assert_eq!(replay.v, PROTOCOL_V);
                assert_eq!(replay.scope, first.scope);
                assert_eq!(replay.idempotency_key, first.idempotency_key);
                assert_eq!(cached(&operation.storage_id).map(|receipt| receipt.id), Some(first.id.clone()));
            }
            other => panic!("expected replay, got {other:?}"),
        }

        CACHE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        assert!(matches!(
            admit_scoped(&request("request-3", &["a"]), &operation, &current),
            Ok(Admission::Unknown)
        ));

        let changed = request("request-4", &["different"]);
        let Some(changed_operation) = operation_identity_for_scope(&changed, &current).ok()
        else {
            panic!("changed operation identity must be valid");
        };
        match admit_scoped(&changed, &changed_operation, &current) {
            Err((code, _)) => assert_eq!(code, "idempotency_conflict"),
            other => panic!("expected conflict, got {other:?}"),
        }
        let other_scope = fixture_scope("account-b", 1);
        let mut other_request = request("request-other-account", &["a"]);
        other_request.scope = Some(other_scope.clone());
        let other_account = match operation_identity_for_scope(&other_request, &other_scope) {
            Ok(value) => value,
            Err(error) => panic!("isolated account identity failed: {error:?}"),
        };
        assert_ne!(operation.storage_id, other_account.storage_id);
        assert!(cached(&other_account.storage_id).is_none());
        assert!(matches!(admit_scoped(&other_request, &other_account, &other_scope), Ok(Admission::New(_))));
        for method in ["model.prepare", "model.switch", "model.resume"] {
            for succeeded in [true, false] {
                let id = format!("deferred-{method}-{succeeded}");
                let mut deferred = request(&id, &["{}"]);
                deferred.method = method.to_owned();
                deferred.operation_id = Some(id.clone());
                deferred.idempotency_key = None;
                let identity = match operation_identity_for_scope(&deferred, &current) {
                    Ok(identity) => identity,
                    Err(error) => panic!("deferred identity failed: {error:?}"),
                };
                let guard = match admit_scoped(&deferred, &identity, &current) {
                    Ok(Admission::New(guard)) => guard,
                    other => panic!("deferred admission failed: {other:?}"),
                };
                let mut pending = status_response(&deferred);
                pending.envelope = Some(ResultEnvelope::new(method, OutputStatus::Pending,
                    json!({"state":"pending"}), Vec::new()));
                remember(&identity.storage_id, &pending);
                let reply = deferred_reply(&deferred, &identity, guard);
                assert!(INFLIGHT.lock().unwrap_or_else(|error| error.into_inner())
                    .contains(&identity.storage_id));
                assert_eq!(result_state(cached(&identity.storage_id).as_ref(), true), "pending");
                assert!(ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner())
                    .iter().any(|item| item.operation_id == id));
                let completion = if succeeded {
                    Ok(crate::output_state::Captured { exit: 0, envelope: ResultEnvelope::new(
                        method, OutputStatus::Ok, json!({"state":"ready"}), Vec::new(),
                    ) })
                } else {
                    Err("model switch cancelled".to_owned())
                };
                assert!(reply.send(completion).is_ok());
                assert!(!INFLIGHT.lock().unwrap_or_else(|error| error.into_inner())
                    .contains(&identity.storage_id));
                assert!(!ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner())
                    .iter().any(|item| item.operation_id == id));
                let receipt = cached(&identity.storage_id);
                assert_eq!(result_state(receipt.as_ref(), false),
                    if succeeded { "completed" } else { "failed" });
                match receipt {
                    Some(receipt) => {
                        assert_eq!(receipt.operation_id.as_deref(), Some(id.as_str()));
                        assert_eq!(receipt.ok, succeeded);
                    }
                    None => panic!("deferred receipt is missing"),
                }
                let next_scope = fixture_scope("account-a", current.generation + 1);
                assert!(cached(&scoped_operation_key(&operation_scope(&next_scope), &id)).is_none());
                assert!(matches!(admit_scoped(&deferred, &identity, &current), Ok(Admission::Replay(_))));
            }
        }
        let mut missing = request("request-missing-scope", &["a"]);
        missing.scope = None;
        assert!(matches!(admit_scoped(&missing, &operation, &current),
            Err((code, _)) if code == "scope_required"));
        // The same lock fences stop and ledger insertion. Replays remain available.
        struct RestoreStopping(bool);
        impl Drop for RestoreStopping {
            fn drop(&mut self) {
                let _fence = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
                STOPPING.store(self.0, Ordering::Release);
            }
        }
        let restore = {
            let _fence = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
            RestoreStopping(STOPPING.swap(true, Ordering::AcqRel))
        };
        assert!(matches!(admit_scoped(&first, &operation, &current), Ok(Admission::Unknown)));
        let stopped_generation = GENERATION.load(Ordering::Acquire);
        assert!(advance_generation(stopped_generation).is_err());
        assert_eq!(GENERATION.load(Ordering::Acquire), stopped_generation);
        let mut fresh = request("request-after-stop", &["a"]);
        fresh.operation_id = Some("operation-after-stop".to_owned());
        fresh.idempotency_key = Some("key-after-stop".to_owned());
        let fresh_operation = match operation_identity(&fresh) {
            Ok(operation) => operation,
            Err(error) => panic!("fresh operation identity failed: {error:?}"),
        };
        assert!(matches!(admit_scoped(&fresh, &fresh_operation, &current),
            Err((code, _)) if code == "runtime_maintenance"));
        assert!(!INFLIGHT.lock().unwrap_or_else(|error| error.into_inner())
            .contains(&fresh_operation.storage_id));
        drop(restore);
        let marker = root.path().join("runtime/autostart/maintenance.json");
        std::fs::create_dir_all(marker.parent().context("maintenance marker parent missing")?)?;
        for phase in ["Paused", "Starting", "Verified", "malformed"] {
            let bytes = if phase == "malformed" { b"invalid JSON".to_vec() }
                else { serde_json::to_vec(&json!({"phase":phase}))? };
            std::fs::write(&marker, bytes)?;
            assert!(business_paused(), "{phase} must fence business without STOPPING");
            assert!(begin_admission(format!("background-{phase}"), "background_write").is_none());
            assert!(matches!(admit_scoped(&fresh, &fresh_operation, &current),
                Err((code, _)) if code == "runtime_maintenance"));
            assert!(!INFLIGHT.lock().unwrap_or_else(|error| error.into_inner())
                .contains(&fresh_operation.storage_id));
            assert!(matches!(admit_scoped(&first, &operation, &current), Ok(Admission::Unknown)));
            let mut control = request("maintenance-cancel", &["cancel"]);
            control.method = "model.control".to_owned();
            control.operation_id = Some(format!("cancel-{phase}"));
            control.idempotency_key = None;
            let cancellation = operation_identity_for_scope(&control, &current)
                .map_err(|(code, error)| anyhow::anyhow!("{code}: {error}"))?;
            match admit_scoped(&control, &cancellation, &current) {
                Ok(Admission::New(guard)) => drop(guard),
                _ => anyhow::bail!("maintenance must retain the scoped cancellation channel"),
            }
            INFLIGHT.lock().unwrap_or_else(|error| error.into_inner()).remove(&cancellation.storage_id);
            let (jobs, queued) = mpsc::channel();
            for args in [vec!["recall".to_owned(), "query".to_owned()], vec!["show".to_owned(), "entry".to_owned()], vec!["remember".to_owned(), "value".to_owned()]] {
                assert!(matches!(enqueue_job_scoped(&jobs, args.clone(), false, Reply::new(|_| {}),
                    Duration::from_secs(1), format!("queued-{phase}"), current.clone()),
                    Err(error) if error.starts_with("runtime_maintenance")));
                assert!(matches!(capture_scoped_locked(&current, args),
                    Err(error) if error.starts_with("runtime_maintenance")));
            }
            assert!(matches!(queued.try_recv(), Err(mpsc::TryRecvError::Empty)));
            let mut catalog = request("fenced-catalog", &[]);
            catalog.method = "model.catalog".to_owned();
            assert_eq!(dispatch(catalog, &jobs).code.as_deref(), Some("runtime_maintenance"));
            let mut status = request("maintenance-status", &[]);
            status.method = "runtime.status".to_owned();
            assert!(dispatch(status, &jobs).ok);
            let live = current_scope();
            let mut lookup = request("original-result-query", &["original-operation"]);
            lookup.method = "runtime.result".to_owned();
            lookup.scope = Some(live.clone());
            let storage_id = scoped_operation_key(&operation_scope(&live), "original-operation");
            remember(&storage_id, &status_response(&lookup));
            let result = dispatch(lookup, &jobs);
            assert!(result.ok);
            assert!(result.envelope.is_some_and(|envelope| envelope.summary["state"] == "completed"));
            for method in ["runtime.status", "runtime.stop", "runtime.result", "model.control", "cli.progress"] {
                assert!(maintenance_control_method(method));
            }
            for method in ["cli.exec", "model.catalog", "model.progress", "assets.status", "model.prepare", "index.prepare"] {
                assert!(!maintenance_control_method(method));
            }
        }
        std::fs::remove_file(&marker)?;
        assert!(!business_paused());
        {
            let _scope = SCOPE_EXECUTION.write()
                .map_err(|_| anyhow::anyhow!("test scope fence poisoned"))?;
            let gate = shared_exclusive();
            let _held = gate.acquire(true);
            let config = root.path().join("client.json");
            std::fs::write(&config, br#"{"service_mode":"readonly"}"#)?;
            let live = current_scope();
            let before = GENERATION.load(Ordering::Acquire);
            let args = vec!["--json".to_owned(), "sync-reset".to_owned()];
            let rejected = readonly_sync_reset_rejection_locked(&live, &args)
                .context("readonly sync-reset must be rejected before capture")?;
            let mut reset = request("readonly-reset", &["--json", "sync-reset"]);
            reset.method = "cli.exec".to_owned();
            reset.scope = Some(live.clone());
            let response = command_response(&reset, rejected);
            assert!(!response.ok);
            assert_eq!(response.exit, 1);
            assert_eq!(response.operation_id, reset.operation_id);
            assert_eq!(response.idempotency_key, reset.idempotency_key);
            assert_eq!(response.scope, reset.scope);
            assert!(response.envelope.context("readonly rejection envelope missing")?
                .errors.iter().any(|error| error.contains("read-only")));
            assert_eq!(GENERATION.load(Ordering::Acquire), before);
            assert_eq!(current_scope(), live);
            assert!(validate_job_scope(&live).is_ok(), "next request must retain the original scope");
            assert!(!root.path().join("rsrs.db").exists());
            assert!(readonly_sync_reset_rejection_locked(&live, &["remember".into(), "value".into()]).is_none());
            assert!(readonly_sync_reset_rejection_locked(&live, &["sync-reset".into(), "--invalid-option".into()]).is_none());
            let mut stale = live.clone();
            stale.generation += 1;
            assert!(matches!(readonly_sync_reset_rejection_locked(&stale, &args),
                Some(Err(error)) if error == "scope_mismatch"));
            std::fs::write(&config, br#"{"service_mode":"normal"}"#)?;
            assert!(readonly_sync_reset_rejection_locked(&live, &args).is_none(),
                "writable sync-reset must retain execution and generation fencing");
            std::fs::remove_file(config)?;
        }
        {
            struct RestoreGeneration(usize);
            impl Drop for RestoreGeneration {
                fn drop(&mut self) {
                    let _fence = ADMISSIONS.lock().unwrap_or_else(|error| error.into_inner());
                    GENERATION.store(self.0, Ordering::Release);
                }
            }
            let original_generation = GENERATION.load(Ordering::Acquire);
            let _restore = RestoreGeneration(original_generation);
            let _scope = SCOPE_EXECUTION.read().unwrap_or_else(|error| error.into_inner());
            assert!(advance_generation(original_generation).is_ok(), "generation advance must not upgrade a held read lock");
            assert_eq!(GENERATION.load(Ordering::Acquire), original_generation.saturating_add(1));
            assert!(advance_generation(original_generation).is_err(), "stale generation must not advance again");
        }
        let mut model_a = request("request-json-a", &[r#"{"engine":"cpu","model":"bge"}"#]);
        model_a.method = "model.configure".to_owned();
        let mut model_b = request("request-json-b", &[r#"{"model":"bge","engine":"cpu"}"#]);
        model_b.method = "model.configure".to_owned();
        let a = operation_identity_for_scope(&model_a, &current);
        let b = operation_identity_for_scope(&model_b, &current);
        match (a, b) {
            (Ok(a), Ok(b)) => assert_eq!(a.fingerprint, b.fingerprint),
            other => panic!("model fingerprints failed: {other:?}"),
        }
        let internal = mcp_request(vec!["status".to_owned()], current.clone());
        assert_eq!(internal.scope.as_ref(), Some(&current));
        assert_eq!(internal.method, "cli.exec");
        let internal_identity = match operation_identity(&internal) {
            Ok(identity) => identity,
            Err(error) => panic!("internal MCP identity failed: {error:?}"),
        };
        let internal_admission = match admit_scoped(&internal, &internal_identity, &current) {
            Ok(Admission::New(guard)) => guard,
            other => panic!("internal MCP admission failed: {other:?}"),
        };
        let failed = command_response(&internal, Err("scope_mismatch".to_owned()));
        remember(&internal_identity.storage_id, &failed);
        INFLIGHT.lock().unwrap_or_else(|error| error.into_inner()).remove(&internal_identity.storage_id);
        drop(internal_admission);
        assert_eq!(result_state(cached(&internal_identity.storage_id).as_ref(), false), "failed");
        let switched = fixture_scope("account-a", current.generation + 1);
        assert!(cached(&scoped_operation_key(&operation_scope(&switched), &internal_identity.operation_id)).is_none());
        assert!(matches!(admit_scoped(&internal, &internal_identity, &current), Ok(Admission::Replay(_))));
        Ok(())
    }

    #[test]
    fn normal_drain_waits_past_the_legacy_four_second_budget() {
        for supervised in [false, true] {
            let mut polls = 0;
            wait_for_drain(supervised, || {
                polls += 1;
                polls < 83
            });
            assert_eq!(polls, 83, "normal drain returned while work remained");
        }
    }

    #[test]
    fn stop_target_rejects_stale_instance_account_and_generation() -> Result<()> {
        let process = ProcessIdentity {
            installation_id: "installation-1".to_owned(),
            instance_id: "instance-1".to_owned(),
            process_start_id: "start-1".to_owned(),
            image_path: "/isolated/rsrs-runtime".to_owned(),
            image_sha256: "2".repeat(64),
        };
        let expected = json!({"installation_id":"installation-1", "instance_id":"instance-1", "account_id":"account-1", "generation":7});
        validate_stop_target(&expected, &process, "account-1", 7)?;
        assert!(!validate_stop_force(&expected, None)?);
        let mut force = expected.clone();
        force["force"] = json!(false);
        force["operation_id"] = json!("unrelated-old-field");
        assert!(!validate_stop_force(&force, None)?);
        force["force"] = json!(true);
        assert!(validate_stop_force(&force, None).is_err());
        assert!(validate_stop_force(&force, Some("accepted-stop")).is_err());
        force["operation_id"] = json!("accepted-stop");
        assert!(validate_stop_force(&force, Some("accepted-stop"))?);
        for invalid in [Value::Null, json!(1), json!("true"), json!({})] {
            force["force"] = invalid;
            assert!(validate_stop_force(&force, Some("accepted-stop")).is_err());
        }
        assert_eq!(stop_outcome(true, false, true), RuntimeStopOutcome::Drained);
        assert_eq!(stop_outcome(true, false, false), RuntimeStopOutcome::Failed);
        assert_eq!(stop_outcome(true, true, false), RuntimeStopOutcome::ForcedTimeout);
        assert_eq!(stop_outcome(false, true, false), RuntimeStopOutcome::Failed);
        assert_eq!(FORCE_DRAIN_GRACE, Duration::from_secs(4));
        for key in ["installation_id", "instance_id", "account_id", "generation"] {
            let mut missing = expected.clone();
            missing
                .as_object_mut()
                .context("stop target object")?
                .remove(key);
            assert!(validate_stop_target(&missing, &process, "account-1", 7).is_err());
            let mut stale = expected.clone();
            stale[key] = if key == "generation" {
                json!(6)
            } else {
                json!("other")
            };
            assert!(validate_stop_target(&stale, &process, "account-1", 7).is_err());
        }
        Ok(())
    }
}

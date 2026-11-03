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

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use respire_protocol::{AssetsStatus, RuntimeCompat, RuntimeIdentity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ---- Runtime identity (split-era health extension) ----

static RUNTIME_IDENTITY: OnceLock<RuntimeIdentity> = OnceLock::new();

/// Publish the serving binary's identity; the first call wins. The health body
/// and every RPC reply report it so clients can pin-check the managed runtime.
pub fn set_runtime_identity(identity: RuntimeIdentity) -> bool {
    RUNTIME_IDENTITY.set(identity).is_ok()
}

fn runtime_identity() -> RuntimeIdentity {
    RUNTIME_IDENTITY.get().cloned().unwrap_or(RuntimeIdentity {
        runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
        runtime_compat: RuntimeCompat {
            min_cli: env!("CARGO_PKG_VERSION").to_owned(),
            max_cli: "*".to_owned(),
        },
    })
}

/// Version string this serving process reports in RPC replies and health.
fn bin_version() -> &'static str {
    RUNTIME_IDENTITY
        .get()
        .map(|identity| identity.runtime_version.as_str())
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

// Worker-face state (worker flag, sync context, generation, index work,
// write gate, recall statistics) lives in the shared rpc_worker module.
use crate::i18n;
use crate::output::{Item as OutputItem, ResultEnvelope, Status as OutputStatus};
use crate::rpc_worker::{
    check_sync_context, command_name, current_url, index_has_work, index_loop, index_status,
    is_context_query, is_status, kick_index, mark_worker, needs_inference, recall_stats_status,
    runtime_dir, shared_exclusive, sync_generation, sync_local, write_endpoint, GENERATION,
    INDEX_CV, INDEX_ON, INDEX_WORK, MAX_PENDING_STATS, PROTOCOL_V, RecallStats, STATS_ENQUEUED,
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
static CACHE: Mutex<Vec<(String, RpcResponse)>> = Mutex::new(Vec::new());
static INFLIGHT: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

enum WriteJob {
    Command(Job),
    RecallStats(RecallStats, usize),
}

pub fn enqueue_recall_stats_local(stats: RecallStats, generation: usize) {
    if respire_app::service::workspace_mode() != "normal" { return; }
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
        match tx.try_send(WriteJob::RecallStats(stats, generation)) {
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
    if let Err(error) = respire_app::resident::clear() { eprintln!("resident catalog reset failed: {error:#}"); }
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
    PROFILE_SWITCH_STATE.lock().map(|v| v.clone()).unwrap_or_else(|_| json!({"state":"failed","error":"switch state lock poisoned"}))
}
fn set_profile_state(value: Value) {
    if let Ok(mut slot) = PROFILE_SWITCH_STATE.lock() { *slot = value; }
}
fn start_profile_switch(choice: respire_app::embedding::Choice, task_id: String) -> Result<Value> {
    anyhow::ensure!(!respire_app::service::service_paused() && !crate::host_hooks::background_paused(), "model switching is paused by service mode");
    start_profile_switch_target(respire_app::embedding::select(choice)?,task_id)
}
fn start_profile_switch_target(mut target: respire_app::core_sdk::profiles::Selection, task_id: String) -> Result<Value> {
    anyhow::ensure!(!respire_app::service::service_paused() && !crate::host_hooks::background_paused(),"model switching is paused by service mode");
    target.validate()?;
    let epoch = GENERATION.load(Ordering::Acquire);
    let library = respire_app::service::data_dir();
    let admission = PROFILE_ADMISSION.lock().map_err(|_|anyhow::anyhow!("model admission lock poisoned"))?;
    anyhow::ensure!(PROFILE_SWITCH_RUNNING.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire).is_ok(), "another model switch is running");
    let operation = match crate::model_progress::Operation::reserve_task(task_id.clone()) {
        Ok(operation) => operation,
        Err(error) => { PROFILE_SWITCH_RUNNING.store(false,Ordering::Release); return Err(error); }
    };
    let queued = (|| -> Result<()> {
        check_sync_context(epoch)?;
        let store = respire_app::service::open_store()?;
        anyhow::ensure!(library == respire_app::service::data_dir(),"model switch library changed before acceptance");
        store.queue_selection(&target,&task_id)
    })();
    if let Err(error) = queued { PROFILE_SWITCH_RUNNING.store(false,Ordering::Release); return Err(error); }
    drop(admission);
    set_profile_state(json!({"id":task_id,"state":"pending","target":target.model,"active_changed":false,"semantic":"busy"}));
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
            let gate = shared_exclusive();
            let _write = gate.acquire(true);
            check_sync_context(epoch)?;
            anyhow::ensure!(library == respire_app::service::data_dir(), "model switch library changed");
            let store = respire_app::service::open_store()?;
            let previous = store.active_selection()?;
            let source_revision = store.meta_get("memory_revision_v1")?.context("source revision unavailable")?;
            let keys = crate::engine::build_session()?;
            store.meta_set("embedding_pending_task_v1",&serde_json::to_string(&json!({"id":task_id,"phase":"prepare"}))?)?;
            respire_app::embedding::prepare(&target, |item,done,total| {
                check_sync_context(epoch)?;
                crate::model_progress::update("switch-download",item,done,total)
            })?;
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
        match result {
            Ok(result) => set_profile_state(json!({"id":task_id,"state":"ready","active_changed":true,"semantic":"ready","result":result})),
            Err(error) => set_profile_state(json!({"id":task_id,"state":"failed","active_changed":false,"error":format!("{error:#}"),"semantic":if format!("{error:#}").contains("recovery_failed") {"unverified"} else if format!("{error:#}").contains("previous selection restored and trial inference passed") {"previous_ready"} else {"unchanged"}})),
        }
        kick_index();
    });
    if let Err(error) = spawn {
        PROFILE_SWITCH_RUNNING.store(false,Ordering::Release);
        set_profile_state(json!({"state":"failed","active_changed":false,"error":error.to_string()}));
        return Err(error.into());
    }
    Ok(profile_state())
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
                    state = SYNC_CV.wait_timeout(state, Duration::from_millis(250)).unwrap_or_else(|e| e.into_inner()).0;
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
        let admission = PROFILE_ADMISSION.lock().unwrap_or_else(|error|error.into_inner());
        if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) {
            if let Some((job,_,_)) = manual { let _ = job.reply.send(Err("model_switch_busy".into())); }
            else { SYNC_KICK.lock().unwrap_or_else(|error|error.into_inner()).due = Some(Instant::now()+Duration::from_secs(1)); }
            drop(admission);
            continue;
        }
        SYNC_RUNNING.store(true, Ordering::Release);
        drop(admission);
        if let Some((job, generation, boundary)) = manual {
            let boundary = if boundary < 0 {
                let gate = shared_exclusive();
                let held = gate.acquire(true);
                let snapshot = if job.deadline.expired() {
                    Err(anyhow::anyhow!(QUEUE_EXPIRED))
                } else {
                    check_sync_context(generation).and_then(|_| crate::engine::build_local()).and_then(|store| store.outgoing_boundary())
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
            } else { boundary };
            if !job.deadline.start() {
                let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                SYNC_RUNNING.store(false, Ordering::Release);
                continue;
            }
            SYNC_CONTEXT.with(|context| context.set(Some((generation, boundary))));
            let result = check_sync_context(generation).map(|_| crate::host_hooks::capture_run(job.args));
            if result.as_ref().is_ok_and(|captured| captured.exit == 0) {
                let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
                state.blocked_generation = None;
                state.backoff = 0;
            }
            let _ = job.reply.send(result.map_err(|error| format!("{error:#}")));
        } else {
            let generation = GENERATION.load(Ordering::Acquire);
            let boundary = sync_local(generation, || {
                anyhow::ensure!(!respire_app::service::service_paused(), "background sync paused by service mode");
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    pub v: u32,
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_wait_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    pub v: u32,
    pub id: String,
    pub ok: bool,
    pub exit: i32,
    #[serde(default)]
    pub bin: String,
    #[serde(default)]
    pub envelope: Option<ResultEnvelope>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub data_dir: Option<String>,
}

pub struct Job {
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
        let action = self.0.lock().map_err(|_| "reply lock poisoned".to_owned())?.take();
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
    let entries = WATCH.get_or_init(|| {
        Mutex::new(Vec::new())
    });
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
                        let Some(deadline) = entry.deadline.upgrade() else { return false; };
                        if deadline.expired() {
                            if let Some(reply) = entry.reply.upgrade() { expired.push(Reply(reply)); }
                            false
                        } else { !deadline.running() }
                    });
                }
                // Reply actions only hand off in-memory results or spawn async I/O.
                for reply in expired { let _ = reply.send(Err(QUEUE_EXPIRED.into())); }
            }
        });
    });
    entries.lock().map_err(|_| anyhow::anyhow!("queue watch lock poisoned"))?.push(QueueWatch {
        deadline: Arc::downgrade(deadline),
        reply: Arc::downgrade(&reply.0),
    });
    Ok(())
}

pub fn serve(flags: RuntimeFlags) -> Result<()> {
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
    let _owner = match respire_app::lock::LibraryLock::acquire(&runtime_dir(), Duration::from_secs(15)) {
        Ok(owner) => owner,
        Err(error) => {
            // Another host may have completed startup while this caller waited.
            if probe_runtime()?.is_some() { return Ok(()); }
            return Err(error).context("another runtime owns this installation");
        }
    };
    if probe_runtime()?.is_some() { return Ok(()); }
    // Acquire the existing library ownership before publishing readiness. This
    // also guards an older runtime using another port, and direct-mode clients.
    let library = respire_app::lock::LibraryLock::acquire(
        &respire_app::service::data_dir(), Duration::from_secs(120),
    ).context("runtime failed to lock the library")?;
    crate::host_hooks::verify_managed_boot()?;
    // Probe and bind only the existing loopback HTTP/TCP transport; no legacy
    // pipe/socket fallback is necessary.
    let bound = crate::runtime_http::bind_runtime(flags.port, &flags.host)?;
    {
        let mut url = WEB_URL.lock().unwrap_or_else(|err| err.into_inner());
        *url = bound.url.clone();
    }
    write_endpoint(&bound.url)?;
    let (tx, rx) = mpsc::channel();
    let _ = JOB_TX.set(Mutex::new(tx.clone()));
    // Sandboxed clients cannot restart an idle-exited host runtime.
    let idle = None;
    let limit = worker_limit();
    WORKERS.store(limit, Ordering::Release);
    RUNNING.store(0, Ordering::Release);
    std::thread::Builder::new()
        .name("respire-dispatch".into())
        // Services do not inherit a terminal's RUST_MIN_STACK. Context-query
        // parsing needs the same explicit stack as the command workers.
        .stack_size(16 * 1024 * 1024)
        .spawn(move || dispatch_loop(rx, limit, idle, library))
        .context("failed to start the runtime dispatcher")?;
    // Keep the host entry alive on its actual listener. Drain/worker shutdown
    // retains its existing ownership and process-exit path in dispatch_loop.
    crate::runtime_http::serve_loop(bound.server)
}

pub fn dispatch(request: RpcRequest, tx: &Sender<Job>) -> RpcResponse {
    if request.v != PROTOCOL_V {
        return error_response(
            &request,
            "protocol_version_mismatch",
            "protocol version mismatch",
        );
    }
    if request.method != "runtime.result" {
        if let Some(hit) = cached(&request.id) { return hit; }
    }
    if matches!(request.method.as_str(), "model.prepare" | "index.prepare") && crate::host_hooks::background_paused() {
        return error_response(&request,"runtime_maintenance","runtime maintenance pauses model/index preparation");
    }
    if request.method == "cli.exec" && PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) && !is_status(&request.args) {
        return error_response(&request,"model_switch_busy","model switch in progress; semantic queries and writes are paused; inspect model.progress");
    }
    let response = match request.method.as_str() {
        #[cfg(feature = "native-fault-tests")]
        "runtime.test_worker_lifecycle" => {
            let action = request.args.first().map(String::as_str).unwrap_or("");
            match respire_app::core_sdk::worker::fixture_control(action) {
                Ok(result) => { let mut response = status_response(&request); response.envelope =
                    Some(ResultEnvelope::new("runtime.test_worker_lifecycle", OutputStatus::Ok, result, Vec::new())); response },
                Err(error) => error_response(&request, "worker_fixture_failed", &format!("{error:#}")),
            }
        }
        #[cfg(feature = "native-fault-tests")]
        "runtime.test_worker_hold" => {
            match respire_app::core_sdk::execute::<Value>("test_worker_hold", json!({})) {
                Ok(_) => status_response(&request),
                Err(error) => error_response(&request, "worker_fixture_failed", &format!("{error:#}")),
            }
        }
        #[cfg(feature = "native-fault-tests")]
        "runtime.test_native_fault" => {
            let mode = request.args.first().and_then(|mode| mode.parse::<u64>().ok()).unwrap_or(0);
            match respire_app::core_sdk::execute::<Value>("engine_control", json!({"action":"test_native_fault","mode":mode})) {
                Ok(result) => { let mut response = status_response(&request); response.envelope = Some(ResultEnvelope::new("runtime.test_native_fault", OutputStatus::Ok, result, Vec::new())); response },
                Err(error) => error_response(&request, "native_fixture_failed", &format!("{error:#}")),
            }
        }
        "model.catalog" | "model.configure" | "model.switch" | "model.resume" | "model.progress" => {
            let result = (|| -> Result<Value> {
                match request.method.as_str() {
                    "model.catalog" => {
                        let store = respire_app::service::open_store()?;
                        Ok(json!({"registry":respire_app::embedding::registry()?,"active":store.active_selection()?,"switch":profile_state()}))
                    }
                    "model.configure" => {
                        let config = serde_json::from_str(request.args.first().context("configuration JSON required")?)?;
                        respire_app::embedding::configure(config)
                    }
                    "model.switch" => {
                        let choice = serde_json::from_str(request.args.first().context("selection JSON required")?)?;
                        start_profile_switch(choice,request.id.clone())
                    }
                    "model.resume" => {
                        let store = respire_app::service::open_store()?;
                        let target = serde_json::from_str(&store.meta_get("embedding_pending_selection_v1")?.context("no pending model selection")?)?;
                        start_profile_switch_target(target,request.id.clone())
                    }
                    _ => {
                        let store = respire_app::service::open_store()?;
                        Ok(json!({"switch":profile_state(),"operation":crate::model_progress::status()?,"pending_selection":store.meta_get("embedding_pending_selection_v1")?.map(|v|serde_json::from_str::<Value>(&v)).transpose()?,"pending_task":store.meta_get("embedding_pending_task_v1")?.map(|v|serde_json::from_str::<Value>(&v)).transpose()?}))
                    },
                }
            })();
            match result {
                Ok(value) => { let mut response = status_response(&request); response.envelope = Some(ResultEnvelope::new(&request.method,if matches!(request.method.as_str(),"model.switch" | "model.resume") {OutputStatus::Pending} else {OutputStatus::Ok},value,Vec::new())); response }
                Err(error) => error_response(&request,"model_profile_failed",&format!("{error:#}")),
            }
        }
        "model.prepare" => {
            let mirror = request.args.first().map(String::as_str).unwrap_or("auto");
            match crate::model_install::validate_mirror(mirror).and_then(|_| {
                anyhow::ensure!(!respire_app::service::service_paused(), "model preparation is paused by service mode");
                let mut work = INDEX_WORK.lock().map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
                work.prepare_mirror = Some(mirror.to_owned());
                work.requested = true;
                work.error = None;
                work.state = "scheduled";
                drop(work);
                INDEX_CV.notify_one();
                Ok(())
            }) {
                Ok(()) => {
                    let mut response = status_response(&request);
                    response.envelope = Some(ResultEnvelope::new("model.prepare", OutputStatus::Pending, index_status(), Vec::new()));
                    response
                }
                Err(error) => error_response(&request, "model_prepare_failed", &error.to_string()),
            }
        }
        "index.prepare" => {
            kick_index();
            let mut response = status_response(&request);
            response.envelope = Some(ResultEnvelope::new(
                "index.prepare", OutputStatus::Pending, index_status(), Vec::new(),
            ));
            response
        }
        "model.control" => match crate::model_progress::control(
            request.args.first().map(String::as_str).unwrap_or(""),
            request.args.get(1).is_some_and(|arg| arg == "true"),
        ) {
            Ok(progress) => {
                let mut response = status_response(&request);
                response.envelope = Some(ResultEnvelope::new(
                    "model.control",
                    OutputStatus::Ok,
                    progress,
                    Vec::new(),
                ));
                response
            }
            Err(error) => error_response(&request, "model_control_failed", &error.to_string()),
        },
        "runtime.status" => status_response(&request),
        "assets.status" => {
            // Host assets (models, ORT, providers.json) are installed by the
            // CLI before the runtime starts, so this train reports a complete
            // inventory. TODO(P4): report model_install::variant_inventory()
            // here once the runtime owns asset verification.
            let status = AssetsStatus { complete: true, missing: Vec::new() };
            let mut response = status_response(&request);
            response.envelope = Some(ResultEnvelope::new(
                "assets.status",
                OutputStatus::Ok,
                serde_json::to_value(status)
                    .unwrap_or_else(|_| json!({"complete":true,"missing":[]})),
                Vec::new(),
            ));
            response
        }
        "cli.progress" => {
            let mut response = status_response(&request);
            let mut summary = crate::progress::status(request.args.first().map(String::as_str).unwrap_or(""));
            if summary.is_null() { summary = json!({}); }
            summary["inference"] = inference_health_status();
            response.envelope = Some(ResultEnvelope::new(
                "cli.progress", OutputStatus::Ok,
                summary, Vec::new(),
            ));
            response
        }
        "runtime.result" => {
            let id = request.args.first().map(String::as_str).unwrap_or("");
            let result = cached(id);
            let pending = INFLIGHT.lock().unwrap_or_else(|error| error.into_inner()).contains(id);
            let mut response = status_response(&request);
            response.envelope = Some(ResultEnvelope::new(
                "runtime.result", OutputStatus::Ok,
                json!({"request_id":id,"state":if result.is_some() {"completed"} else if pending {"pending"} else {"unknown"},"response":result,
                    "retention":"last 64 completed requests in this runtime; unknown is not proof of non-commit; never replay a write automatically"}),
                Vec::new(),
            ));
            response
        }
        "runtime.stop" => {
            if crate::host_hooks::managed_id().is_some() && request.lifecycle.as_deref() != Some("coordinator-v1") {
                return error_response(&request, "managed_lifecycle_required", "use the current host runtime lifecycle coordinator");
            }
            request_drain_exit();
            status_response(&request)
        }
        "cli.exec" => match submit(tx, request.args.clone(), false) {
            Ok(captured) => RpcResponse {
                v: PROTOCOL_V,
                id: request.id.clone(),
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
            Err(error) => error_response(&request, "daemon_unavailable", &error),
        },
        other => error_response(
            &request,
            "protocol_version_mismatch",
            &format!("unknown method {other}"),
        ),
    };
    if request.method != "runtime.result" { remember(&request.id, &response); }
    response
}

fn command_response(request: &RpcRequest, result: CommandResult) -> RpcResponse {
    match result {
        Ok(captured) => RpcResponse {
            v: PROTOCOL_V, id: request.id.clone(), ok: captured.exit == 0,
            exit: captured.exit, bin: bin_version().to_owned(),
            envelope: Some(captured.envelope), error: None, code: None,
            web_url: Some(current_url()), pid: Some(std::process::id()),
            data_dir: Some(respire_app::service::data_dir().display().to_string()),
        },
        Err(error) => error_response(request, "daemon_unavailable", &error),
    }
}

pub fn dispatch_deferred(request: RpcRequest, tx: &Sender<Job>, action: impl FnOnce(RpcResponse) + Send + 'static) {
    if request.method == "cli.exec" && PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) && !is_status(&request.args) {
        action(error_response(&request,"model_switch_busy","model switch in progress; semantic queries and writes are paused; inspect model.progress"));
        return;
    }
    if request.method != "cli.exec" || request.v != PROTOCOL_V {
        action(dispatch(request, tx));
        return;
    }
    {
        let mut inflight = INFLIGHT.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(response) = cached(&request.id) { drop(inflight); action(response); return; }
        if !inflight.insert(request.id.clone()) {
            drop(inflight);
            action(error_response(&request, "request_in_progress", "request ID is already executing or queued; inspect runtime.result; command was not replayed"));
            return;
        }
    }
    let args = request.args.clone();
    let wait = request.queue_wait_ms.map(Duration::from_millis).unwrap_or_else(queue_wait).min(queue_wait());
    let reply = Reply::new(move |result| {
        let response = command_response(&request, result);
        remember(&request.id, &response);
        INFLIGHT.lock().unwrap_or_else(|error| error.into_inner()).remove(&request.id);
        action(response);
    });
    if let Err(error) = enqueue_job(tx, args, false, reply.clone(), wait) {
        let _ = reply.send(Err(error));
    }
}

pub fn status_response(request: &RpcRequest) -> RpcResponse {
    RpcResponse {
        v: PROTOCOL_V,
        id: request.id.clone(),
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

pub fn enqueue_job(
    tx: &Sender<Job>,
    args: Vec<String>,
    stop: bool,
    reply: Reply,
    wait: Duration,
) -> std::result::Result<Arc<crate::admission::QueueDeadline>, String> {
    if !stop && !respire_app::service::off_mode() && needs_inference(&args) && inference_health_status()["host_recovery_required"] == true {
        return Err("inference is unresponsive after cancellation; host runtime recovery is required; request was not queued".into());
    }
    let slots = WORKERS.load(Ordering::Acquire).max(1);
    if !stop
        && is_status(&args)
        && LIGHT_RUNNING.load(Ordering::Acquire) >= 2
        && RUNNING.load(Ordering::Acquire).saturating_sub(LIGHT_RUNNING.load(Ordering::Acquire)) >= slots
    {
        let mut envelope = ResultEnvelope::new(
            "status",
            OutputStatus::Warn,
            json!({"state": "busy", "workers": slots}),
            Vec::new(),
        );
        envelope.errors.push(i18n::text("busy").to_owned());
        reply.send(Ok(crate::output_state::Captured { exit: 2, envelope }))?;
        return Ok(Arc::new(crate::admission::QueueDeadline::new(Duration::ZERO)));
    }
    let sync_context = if !respire_app::service::off_mode() && matches!(
        command_name(&args),
        Some("sync" | "sync-conflicts" | "sync-resolve" | "sync-history" | "sync-restore" | "classify")
    ) {
        // Capture account generation without blocking a network executor on
        // the write gate. The existing sync worker takes the snapshot later.
        Some((GENERATION.load(Ordering::Acquire), -1))
    } else {
        None
    };
    let deadline = Arc::new(crate::admission::QueueDeadline::new(wait));
    watch_queue(&deadline, &reply).map_err(|error| error.to_string())?;
    tx.send(Job {
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

pub fn submit(tx: &Sender<Job>, args: Vec<String>, stop: bool) -> CommandResult {
    let (reply_tx, reply_rx) = mpsc::channel();
    let deadline = enqueue_job(tx, args, stop, Reply::new(move |result| { let _ = reply_tx.send(result); }), queue_wait())?;
    let wait = queue_wait();
    match reply_rx.recv_timeout(wait) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("runtime worker dropped the reply".to_owned()),
        Err(mpsc::RecvTimeoutError::Timeout) if deadline.cancel() => Err(QUEUE_EXPIRED.to_owned()),
        // Execution won admission. Especially for writes, preserve the actual
        // commit outcome instead of returning an ambiguous client timeout.
        Err(mpsc::RecvTimeoutError::Timeout) => reply_rx.recv()
            .map_err(|_| "runtime worker dropped the reply".to_owned())?,
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
    let captured = submit(&tx, args, false)?;
    serde_json::to_value(&captured.envelope).map_err(|err| err.to_string())
}

pub fn wait_for_drain(supervised: bool, mut busy: impl FnMut() -> bool) {
    let mut polls=0;
    while busy() {
        // Preserve legacy explicit-shutdown timing, but never silently turn a
        // supervised upgrade/profile transition into a four-second forced exit.
        if !supervised && polls >= 80 { break; }
        std::thread::sleep(Duration::from_millis(50));
        polls+=1;
    }
}

pub fn request_drain_exit() {
    STOPPING.store(true, Ordering::Release);
    wake_dispatcher();
    SYNC_CV.notify_all();
    INDEX_CV.notify_all();
    let supervised=crate::host_hooks::managed_id().is_some();
    std::thread::spawn(move || {
        wait_for_drain(supervised, ||RUNNING.load(Ordering::Acquire) != 0
            || WRITE_RUNNING.load(Ordering::Acquire)
            || CLASSIFY_RUNNING.load(Ordering::Acquire)
            || sync_running() || index_has_work() || PROFILE_SWITCH_RUNNING.load(Ordering::Acquire));
        while PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) { std::thread::sleep(Duration::from_millis(25)); }
        stop_process(0);
    });
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

pub fn handle_http_rpc_deferred(body: &[u8], action: impl FnOnce(RpcResponse) + Send + 'static) -> Result<()> {
    let request: RpcRequest = serde_json::from_slice(body).context("rpc body is not JSON")?;
    let tx = JOB_TX.get().ok_or_else(|| anyhow::anyhow!("runtime worker is not running"))?
        .lock().map_err(|_| anyhow::anyhow!("runtime worker lock poisoned"))?.clone();
    dispatch_deferred(request, &tx, action);
    Ok(())
}

fn inference_health_status() -> Value {
    match respire_app::memory::onnx::inference_status() {
        Ok(status) => status,
        Err(error) => json!({"state":"error","error":format!("{error:#}")}),
    }
}

pub fn health_body() -> Value {
    let inference = inference_health_status();
    let (queue_cancelled, timings) = crate::admission::timings();
    let (queued, executing) = crate::admission::occupancy();
    let identity = runtime_identity();
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    json!({
        "server": "respire",
        "bin": bin_version(),
        "pid": std::process::id(),
        "v": PROTOCOL_V,
        "url": current_url(),
        "exe": exe,
        "data_dir": respire_app::service::data_dir().display().to_string(),
        "store_ready": STORE_READY.load(Ordering::Acquire),
        "installation_root": respire_app::service::main_data_dir().display().to_string(),
        "managed_id": crate::host_hooks::managed_id(),
        "credential_state": crate::host_hooks::credential_state(),
        "snapshot_restore_id": SNAPSHOT_BOOT_ID.lock().ok().and_then(|slot|slot.clone()),
        "recall_statistics": recall_stats_status(),
        "retrieval_index": index_status(),
        "inference": inference,
        // Split-era identity: the extension lives under the `runtime` key per
        // the protocol contract; the flattened runtime_version keeps the
        // existing Health consumers (pin checks, shell banner) working.
        "runtime": identity.health_extension_json(),
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
    })
}

fn stop_process(code: i32) -> ! {
    crate::host_hooks::record_exit(code == 0);
    #[cfg(test)]
    {
        let _ = code;
        loop {
            std::thread::park();
        }
    }
    #[cfg(not(test))]
    {
        if let Err(error) = respire_app::core_sdk::worker::shutdown() {
            eprintln!("runtime retained its library lock because Core worker cleanup failed: {error:#}");
            // Keep control/health alive and ownership intact; never overlap a
            // new host with an unconfirmed native child.
            while respire_app::core_sdk::worker::shutdown().is_err() {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        std::process::exit(code);
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
    Duration::from_secs(respire_app::env::var("RSRS_RPC_QUEUE_WAIT_SECS").ok()
        .and_then(|value| value.parse::<u64>().ok()).unwrap_or(120).clamp(1, 3600))
}

pub fn is_exclusive(args: &[String]) -> bool {
    if is_context_query(args) {
        return false;
    }
    if command_name(args) == Some("update") { return false; }
    if command_name(args) == Some("remember") && !args.iter().any(|arg|
        matches!(arg.as_str(), "--merge-ids" | "--supersedes" | "--see-also")
        || arg.starts_with("--merge-ids=") || arg.starts_with("--supersedes=")
        || arg.starts_with("--see-also=")) { return false; }
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
    if let Some(thread) = DISPATCH_THREAD.get() { thread.unpark(); }
}

// The unpark token survives a completion between try_recv and park_timeout.
// Keep the periodic check as a fallback for shutdown and queue expiry.
pub fn receive_dispatch_job<T>(rx: &Receiver<T>, wait: Duration) -> Result<T, mpsc::RecvTimeoutError> {
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
        if self.light { LIGHT_RUNNING.fetch_sub(1, Ordering::AcqRel); }
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

pub fn dispatch_loop(rx: Receiver<Job>, limit: usize, idle: Option<Duration>, _lock: respire_app::lock::LibraryLock) {
    mark_worker();
    let _ = DISPATCH_THREAD.set(std::thread::current());
    #[cfg(not(test))]
    respire_app::core_sdk::worker::enable();
    // Keep WAL open across requests: closing the last connection can briefly lock
    // a concurrent opener during checkpoint/cleanup, even for read-only status.
    let mut _store = if respire_app::service::off_mode() { None } else { Some(match respire_app::service::open_runtime_store(&_lock) {
        Ok((store,snapshot_id)) => {
            if let Ok(mut slot)=SNAPSHOT_BOOT_ID.lock(){*slot=snapshot_id;}
            STORE_READY.store(true,Ordering::Release);
            store
        },
        Err(error) => {
            eprintln!("runtime failed to initialize the library: {error:#}");
            stop_process(1);
        }
    }) };
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
                let admission = PROFILE_ADMISSION.lock().unwrap_or_else(|error|error.into_inner());
                if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) { let _ = job.reply.send(Err("model_switch_busy".into())); continue; }
                CLASSIFY_RUNNING.store(true, Ordering::Release);
                drop(admission);
                let _active = ClassifyGuard;
                SYNC_CONTEXT.with(|context| context.set(Some((generation, -1))));
                let result = check_sync_context(generation)
                    .map(|_| crate::host_hooks::capture_run(job.args))
                    .map_err(|error| format!("{error:#}"));
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
                    WriteJob::RecallStats(stats, generation) => {
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
                let admission = PROFILE_ADMISSION.lock().unwrap_or_else(|error|error.into_inner());
                if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) {
                    shared_exclusive().cancel_reservation();
                    let _ = job.reply.send(Err("model_switch_busy".into()));
                    continue;
                }
                WRITE_RUNNING.store(true, Ordering::Release);
                drop(admission);
                let gate = shared_exclusive();
                let _held = gate.acquire_reserved();
                if !job.deadline.start() {
                    drop(_held);
                    WRITE_RUNNING.store(false, Ordering::Release);
                    let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                    continue;
                }
                let changing_context = !is_context_query(&job.args) && matches!(
                    command_name(&job.args),
                    Some(
                        "login"
                            | "logout"
                            | "register"
                            | "keygen"
                            | "config"
                            | "session"
                            | "agent-config"
                            | "sync-reset"
                            | "account"
                            | "space"
                            | "fivekeys"
                            | "super-reset"
                    )
                );
                if changing_context {
                    GENERATION.fetch_add(1, Ordering::AcqRel);
                    SYNC_CV.notify_one();
                }
                let captured = crate::host_hooks::capture_run(job.args);
                drop(_held);
                kick_index();
                if changing_context {
                    context_changed();
                }
                WRITE_RUNNING.store(false, Ordering::Release);
                let _ = job.reply.send(Ok(captured));
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
                if respire_app::service::off_mode() {
                    let parsed = crate::cli_def::Cli::try_parse_from(std::iter::once("rsrs".to_owned()).chain(job.args.iter().cloned()));
                    if parsed.is_ok_and(|cli| cli.command.as_ref().is_some_and(|command| !crate::gates::is_off_allowed(command))) {
                        if !job.deadline.start() {
                            let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                            continue;
                        }
                        let captured = crate::host_hooks::capture_run(job.args);
                        let _ = job.reply.send(Ok(captured));
                        continue;
                    }
                } else if _store.is_none() && !matches!(command_name(&job.args), Some("agent-config" | "memory-revision")) {
                    let gate = shared_exclusive();
                    let _held = gate.acquire(true);
                    let opened = if !respire_app::service::service_paused() {
                        respire_app::service::initialize_runtime_store()
                    } else { respire_app::service::open_store() };
                    match opened {
                        Ok(store) => _store = Some(store),
                        Err(error) => { let _ = job.reply.send(Err(format!("{error:#}"))); continue; }
                    }
                }
                if matches!(
                    command_name(&job.args),
                    Some("sync" | "sync-conflicts" | "sync-resolve" | "sync-history" | "sync-restore")
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
            } else { true }
        });
        loop {
            let ordinary_available = RUNNING.load(Ordering::Acquire).saturating_sub(LIGHT_RUNNING.load(Ordering::Acquire)) < limit;
            let position = if LIGHT_RUNNING.load(Ordering::Acquire) < 2 {
                pending.iter().position(|job| matches!(command_name(&job.args), Some("show" | "list" | "status" | "memory-revision")))
            } else { None };
            let job = if let Some(position) = position { pending.remove(position) }
                else if ordinary_available {
                    pending.iter().position(|job| !matches!(command_name(&job.args), Some("show" | "list" | "status" | "memory-revision")))
                        .and_then(|position| pending.remove(position))
                } else { None };
            let Some(job) = job else { break; };
            let admission = PROFILE_ADMISSION.lock().unwrap_or_else(|error|error.into_inner());
            if PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) && !is_status(&job.args) {
                let _ = job.reply.send(Err("model_switch_busy".into()));
                continue;
            }
            let light_job = matches!(command_name(&job.args), Some("show" | "list" | "status" | "memory-revision"));
            if light_job { LIGHT_RUNNING.fetch_add(1, Ordering::AcqRel); }
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
                    let _slot = RunningGuard { status: status_job, light: light_job };
                    if !job.deadline.start() {
                        let _ = job.reply.send(Err(QUEUE_EXPIRED.into()));
                        return;
                    }
                    mark_worker();
                    let generation = sync_generation();
                    let revision_probe = command_name(&job.args) == Some("memory-revision");
                    let captured = crate::host_hooks::capture_run(job.args);
                    if !revision_probe { kick_index(); }
                    let result = check_sync_context(generation).map(|_| captured).map_err(|error| format!("{error:#}"));
                    let _ = job.reply.send(result);
                });
            if spawned.is_err() {
                RUNNING.fetch_sub(1, Ordering::AcqRel);
                if light_job { LIGHT_RUNNING.fetch_sub(1, Ordering::AcqRel); }
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
    STOPPING.store(true, Ordering::Release);
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
    while PROFILE_SWITCH_RUNNING.load(Ordering::Acquire) { std::thread::sleep(Duration::from_millis(25)); }
    if let Err(error) = respire_app::core_sdk::worker::shutdown() {
        eprintln!("Core worker shutdown failed: {error:#}");
        // This stack still owns LibraryLock. Never reach drop(_lock) while a
        // native child has not been confirmed dead.
        stop_process(0);
    }
    if let Ok(writer) = writer {
        let _ = writer.join();
    }
    if let Ok(classifier) = classifier {
        let _ = classifier.join();
    }
    if let Ok(indexer) = indexer {
        if indexer.join().is_err() {
            eprintln!("background index worker panicked during shutdown");
        }
    }
    while RUNNING.load(Ordering::Acquire) > 0 || sync_running() {
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(_lock);
    stop_process(0);
}

pub fn cached(id: &str) -> Option<RpcResponse> {
    CACHE
        .lock()
        .ok()?
        .iter()
        .find(|(key, _)| key == id)
        .map(|(_, response)| response.clone())
}

pub fn remember(id: &str, response: &RpcResponse) {
    if id.is_empty() {
        return;
    }
    if let Ok(mut cache) = CACHE.lock() {
        cache.retain(|(key, _)| key != id);
        cache.push((id.to_owned(), response.clone()));
        if cache.len() > 64 {
            let extra = cache.len() - 64;
            cache.drain(0..extra);
        }
    }
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

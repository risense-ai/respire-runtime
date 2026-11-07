//! Runtime worker infrastructure shared by the CLI binary and the resident
//! runtime engine.
//!
//! The command-execution engine and its worker plumbing migrate here from the
//! CLI binary in steps of the runtime split. This module currently hosts the
//! argv classification rules shared by client timeout budgets and server
//! routing, plus the loopback endpoint record that both sides read and write.
//!
//! Boundaries:
//! - depends on `respire_app` (app-core) and `cli_def`, never on the `respire`
//!   CLI package;
//! - the CLI binary re-imports these items so `crate::rpc::...` paths and bare
//!   call sites keep resolving.

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::app_version;

pub use crate::rpc_client::{
    command_name, command_words, diary_lexical_mode, is_context_query, is_status, needs_inference,
    GLOBAL_VALUE_FLAGS, PROTOCOL_V,
};

pub static WEB_URL: Mutex<String> = Mutex::new(String::new());

pub fn current_url() -> String {
    WEB_URL
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clone()
}

pub fn runtime_dir_path() -> PathBuf {
    runtime_dir()
}

pub fn runtime_dir() -> PathBuf {
    respire_app::service::main_data_dir().join("runtime")
}

pub fn endpoint_path() -> PathBuf {
    runtime_dir().join("endpoint.json")
}

pub fn write_endpoint(url: &str) -> Result<()> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir)?;
    let body = json!({
        "v": PROTOCOL_V,
        "pid": std::process::id(),
        "bin": app_version::embedded(),
        "url": url,
    });
    std::fs::write(endpoint_path(), serde_json::to_vec_pretty(&body)?)?;
    Ok(())
}

pub fn endpoint_pid() -> Option<u32> {
    let text = std::fs::read_to_string(endpoint_path()).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    data.get("pid")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
}

// ---- Worker face migrated from the CLI rpc module (runtime split WP-2b) ----
// Sync-context, write gate, background index worker and recall-statistics
// plumbing, verbatim from their extraction source apart from rebinding
// app-core paths rebind to respire_app and CLI-host services go through host_hooks.

thread_local! {
    static WORKER: Cell<bool> = const { Cell::new(false) };
    pub static SYNC_CONTEXT: Cell<Option<(usize, i64)>> = const { Cell::new(None) };
}

pub static STOPPING: AtomicBool = AtomicBool::new(false);
pub static STATS_PENDING: AtomicUsize = AtomicUsize::new(0);
pub static STATS_ENQUEUED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_PERSISTED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_REJECTED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_FAILED: AtomicUsize = AtomicUsize::new(0);
pub const MAX_PENDING_STATS: usize = 16;
pub static EXCLUSIVE: OnceLock<Arc<WriteGate>> = OnceLock::new();
pub static GENERATION: AtomicUsize = AtomicUsize::new(0);
pub static INDEX_ON: AtomicBool = AtomicBool::new(false);
pub static INDEX_RUNNING: AtomicBool = AtomicBool::new(false);
pub static INDEX_CV: Condvar = Condvar::new();
pub static INDEX_WORK: Mutex<IndexWork> = Mutex::new(IndexWork {
    requested: false,
    state: "idle",
    error: None,
    prepare_mirror: None,
});

pub struct IndexWork {
    pub(crate) requested: bool,
    pub(crate) state: &'static str,
    pub(crate) error: Option<String>,
    pub(crate) prepare_mirror: Option<String>,
}
#[derive(Default)]
pub struct GateState {
    held: bool,
    foreground: usize,
}
#[derive(Default)]
pub struct WriteGate {
    state: Mutex<GateState>,
    changed: Condvar,
}
pub struct WriteGuard<'a>(&'a WriteGate);
impl WriteGate {
    pub(crate) fn reserve(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .foreground += 1;
    }
    pub(crate) fn cancel_reservation(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.foreground -= 1;
        self.changed.notify_all();
    }
    pub fn acquire_reserved(&self) -> WriteGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while state.held {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.foreground -= 1;
        state.held = true;
        WriteGuard(self)
    }
    pub fn acquire(&self, foreground: bool) -> WriteGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if foreground {
            state.foreground += 1;
        }
        while state.held || (!foreground && state.foreground > 0) {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        if foreground {
            state.foreground -= 1;
        }
        state.held = true;
        WriteGuard(self)
    }
}
impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.held = false;
        self.0.changed.notify_all();
    }
}
pub fn worker_active() -> bool {
    WORKER.with(|flag| flag.get())
}

pub fn set_worker_active(on: bool) {
    WORKER.with(|flag| flag.set(on));
}

pub fn mark_worker() {
    WORKER.with(|flag| flag.set(true));
}

pub struct RecallStats {
    pub request_id: String,
    pub query: String,
    pub project: String,
    pub candidates: Vec<String>,
    pub scores: Vec<f32>,
}

impl RecallStats {
    pub fn persist(&self, store: &respire_app::transport::local::LocalStore) -> Result<()> {
        if respire_app::service::workspace_mode() != "normal" {
            return Ok(());
        }
        store.write_transaction(|| {
            store.log_query_request(
                &self.request_id,
                &self.query,
                &self.project,
                "",
                &self.candidates,
                &self.scores,
            )?;
            store.bump_recall(&self.candidates)?;
            store.bump_recall_pairs(&self.candidates)
        })
    }
}

pub fn recall_stats_status() -> Value {
    json!({
        "pending": STATS_PENDING.load(Ordering::Acquire),
        "enqueued": STATS_ENQUEUED.load(Ordering::Acquire),
        "persisted": STATS_PERSISTED.load(Ordering::Acquire),
        "rejected": STATS_REJECTED.load(Ordering::Acquire),
        "failed": STATS_FAILED.load(Ordering::Acquire),
    })
}

/// Statistics are best effort; never wait for queue capacity on the recall reply path.
pub fn shared_exclusive() -> Arc<WriteGate> {
    EXCLUSIVE
        .get_or_init(|| Arc::new(WriteGate::default()))
        .clone()
}

pub fn sync_generation() -> usize {
    SYNC_CONTEXT
        .with(|context| context.get().map(|v| v.0))
        .unwrap_or_else(|| GENERATION.load(Ordering::Acquire))
}

pub fn sync_boundary() -> Option<i64> {
    SYNC_CONTEXT.with(|context| {
        let value = context.get()?;
        context.set(Some((value.0, -1)));
        (value.1 >= 0).then_some(value.1)
    })
}

pub fn sync_local<T>(generation: usize, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let gate = shared_exclusive();
    let _held = gate.acquire(false);
    check_sync_context(generation)?;
    action()
}

/// Short local preparation/commit for commands whose Core call performs networking.
pub fn foreground_phase<T>(generation: usize, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let gate = shared_exclusive();
    let _held = gate.acquire(true);
    check_sync_context(generation)?;
    action()
}

pub fn invalidate_sync_boundary(generation: usize) -> Result<()> {
    check_sync_context(generation)?;
    GENERATION.fetch_add(1, Ordering::AcqRel);
    // The sync scheduler and resident catalog live beside the dispatch loop.
    crate::rpc_serve::context_changed();
    Ok(())
}

pub fn check_sync_context(generation: usize) -> Result<()> {
    anyhow::ensure!(
        !crate::host_hooks::background_paused(),
        "runtime maintenance pauses background work"
    );
    respire_app::service::ensure_runtime_profile()?;
    if STOPPING.load(Ordering::Acquire) {
        bail!("runtime is stopping");
    }
    if GENERATION.load(Ordering::Acquire) != generation {
        bail!("sync context changed; pending work kept locally");
    }
    Ok(())
}

pub fn index_status() -> Value {
    let state = match INDEX_WORK.lock() {
        Ok(state) => state,
        Err(_) => return json!({"state":"failed", "error":"index work lock poisoned"}),
    };
    json!({"state": state.state, "scheduled": state.requested,
        "worker_active": INDEX_ON.load(Ordering::Acquire),
        "running": INDEX_RUNNING.load(Ordering::Acquire), "error": state.error,
        "model_setup": (state.state == "failed").then_some("Automatic BGE-M3 preparation or indexing failed; inspect the reported error and download source settings.")})
}

pub fn kick_index() {
    if STOPPING.load(Ordering::Acquire) {
        return;
    }
    {
        let mut work = match INDEX_WORK.lock() {
            Ok(work) => work,
            Err(_) => {
                eprintln!("background retrieval indexing failed: index work lock poisoned");
                return;
            }
        };
        work.requested = true;
        if !INDEX_RUNNING.load(Ordering::Acquire) && work.error.is_none() {
            work.state = "scheduled";
        }
    }
    INDEX_CV.notify_one();
}

pub fn index_yield_to_foreground(generation: usize) -> Result<()> {
    anyhow::ensure!(
        !respire_app::service::service_paused(),
        "background index paused by service mode"
    );
    // A separate background Session no longer waits for foreground inference.
    // Context and cancellation checks still occur between every committed source.
    check_sync_context(generation)?;
    crate::model_progress::check()
}

pub fn diary_commit(generation: usize, action: &mut dyn FnMut() -> Result<()>) -> Result<()> {
    let gate = shared_exclusive();
    let _write = gate.acquire(false);
    // Account/mode transitions use the write gate; lifecycle transitions use
    // takeover. Never block on takeover while its owner waits for INDEX_RUNNING.
    let _lifecycle = crate::runtime_policy::try_takeover_lock()?;
    crate::model_progress::commit(|| {
        check_sync_context(generation)?;
        anyhow::ensure!(
            !respire_app::service::service_paused(),
            "background index paused by service mode"
        );
        action()
    })
}

/// The database's source-checked missing artifacts are the resumable work queue.
/// Model preparation runs on this thread without taking the foreground write gate.
pub fn index_loop() {
    mark_worker();
    if let Err(error) = index_loop_inner() {
        eprintln!("background retrieval index worker stopped: {error:#}");
    }
    INDEX_RUNNING.store(false, Ordering::Release);
    INDEX_ON.store(false, Ordering::Release);
}

pub fn index_has_work() -> bool {
    INDEX_RUNNING.load(Ordering::Acquire) || INDEX_WORK.lock().is_ok_and(|work| work.requested)
}

pub fn index_loop_inner() -> Result<()> {
    let mut model_wait_started: Option<Instant> = None;
    loop {
        if respire_app::service::service_paused() || crate::host_hooks::background_paused() {
            if STOPPING.load(Ordering::Acquire) {
                let mut work = INDEX_WORK
                    .lock()
                    .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
                work.requested = false;
                work.state = "stopped";
                return Ok(());
            }
            let mut work = INDEX_WORK
                .lock()
                .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
            work.state = "paused";
            let _paused = INDEX_CV
                .wait_timeout(work, Duration::from_secs(1))
                .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
            continue;
        }
        {
            let mut work = INDEX_WORK
                .lock()
                .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
            while !work.requested && !STOPPING.load(Ordering::Acquire) {
                work = INDEX_CV
                    .wait(work)
                    .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
            }
            if STOPPING.load(Ordering::Acquire) {
                work.state = "stopped";
                work.requested = false;
                return Ok(());
            }
            work.requested = false;
            work.state = "running";
        }
        INDEX_RUNNING.store(true, Ordering::Release);
        let generation = GENERATION.load(Ordering::Acquire);
        let result = (|| -> Result<bool> {
            check_sync_context(generation)?;
            let store = respire_app::service::open_store()?;
            let model = store.retrieval_model()?;
            let prepare_requested = INDEX_WORK
                .lock()
                .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?
                .prepare_mirror
                .is_some();
            let pending = store.index_missing(&model)?;
            let diary_pending = respire_app::diary::needs_rebuild(&store)?;
            // An indexed library still needs the CPU container for its next query.
            // Empty libraries wait for a write or explicit preparation instead of
            // starting an unsolicited model download during status/restart.
            let active_profile = store.active_selection()?;
            let cpu_upgrade = active_profile.is_none()
                && model == "m3"
                && respire_app::MemoryTransport::count(&store)? > 0
                && crate::model_install::cpu_model_preparation_needed()?;
            if !pending && !diary_pending && !prepare_requested && !cpu_upgrade {
                return Ok(true);
            }
            let Some(_operation) = crate::model_progress::Operation::try_begin_background_index()?
            else {
                return Ok(false);
            };
            index_yield_to_foreground(generation)?;
            if diary_pending
                && !pending
                && !prepare_requested
                && !cpu_upgrade
                && respire_app::diary::clear_if_empty(&store, |action| {
                    diary_commit(generation, action)
                })?
            {
                return Ok(true);
            }
            let mirror = INDEX_WORK
                .lock()
                .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?
                .prepare_mirror
                .take();
            if let Some(mirror) = mirror {
                crate::model_install::prepare_m3_from_mirror(&mirror)?;
            } else if let Some(selection) = active_profile.as_ref() {
                respire_app::embedding::prepare(selection, |item, done, total| {
                    check_sync_context(generation)?;
                    crate::model_progress::update("prepare", item, done, total)
                })?;
            } else if model == "m3" {
                crate::model_progress::update("prepare", "BGE-M3", 0, None)?;
                crate::model_install::prepare_m3_for_index()?;
                check_sync_context(generation)?;
            }
            if !pending && !diary_pending {
                return Ok(true);
            }
            let keys = crate::engine::build_session()?;
            let embedder = respire_app::memory::bge::BgeEmbedder::load_model(&model)?;
            while pending {
                let rebuilt =
                    store.rebuild_index_with_progress(&keys, &embedder, &model, |done, total| {
                        index_yield_to_foreground(generation)?;
                        crate::model_progress::update(
                            "index",
                            &model,
                            done as u64,
                            Some(total as u64),
                        )
                    });
                match rebuilt {
                    Ok(_) => break,
                    Err(error)
                        if error
                            .downcast_ref::<respire_app::transport::local::IndexSourceChanged>()
                            .is_some() =>
                    {
                        // Keep this Operation across source changes: cancellation and
                        // the 30-minute idle budget apply to the whole resumed task.
                        crate::model_progress::check()?;
                        let mut work = INDEX_WORK
                            .lock()
                            .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
                        work.error = Some(format!("{error:#}"));
                        drop(work);
                        for _ in 0..5 {
                            check_sync_context(generation)?;
                            crate::model_progress::check()?;
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            respire_app::diary::rebuild_with_progress(
                &store,
                &keys,
                &embedder,
                || {
                    index_yield_to_foreground(generation)?;
                    crate::model_progress::check()
                },
                |action| diary_commit(generation, action),
                |done| crate::model_progress::update("index", "diary-fragments", done as u64, None),
            )?;
            check_sync_context(generation)?;
            Ok(true)
        })();
        INDEX_RUNNING.store(false, Ordering::Release);
        let mut work = INDEX_WORK
            .lock()
            .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
        match result {
            Ok(true) => {
                work.state = "ready";
                work.error = None;
                model_wait_started = None;
            }
            Ok(false) => {
                let started = model_wait_started.get_or_insert_with(Instant::now);
                if started.elapsed() >= Duration::from_secs(1800) {
                    work.state = "failed";
                    work.requested = false;
                    work.error = Some(
                        "background indexing timed out waiting for another model operation".into(),
                    );
                    model_wait_started = None;
                    continue;
                }
                work.state = "waiting_model";
                work.requested = true;
                work = INDEX_CV
                    .wait_timeout(work, Duration::from_secs(1))
                    .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?
                    .0;
            }
            Err(error)
                if error
                    .downcast_ref::<crate::model_progress::OperationStopped>()
                    .is_some() =>
            {
                model_wait_started = None;
                if work.prepare_mirror.is_some() {
                    work.state = "scheduled";
                    work.requested = true;
                    work.error = None;
                } else {
                    work.state = "paused";
                    work.requested = false;
                    work.error = Some(format!("{error:#}"));
                }
            }
            Err(error) if generation != GENERATION.load(Ordering::Acquire) => {
                model_wait_started = None;
                work.state = "scheduled";
                work.requested = true;
                work.error = Some(format!("{error:#}"));
            }
            Err(error) => {
                model_wait_started = None;
                work.state = "failed";
                work.error = Some(format!("{error:#}"));
                eprintln!("background retrieval indexing failed: {error:#}");
            }
        }
        drop(work);
    }
}

/// An explicit direct command releases its library lock before starting this work.
pub fn request_index() -> Result<Value> {
    if worker_active() {
        kick_index();
        return Ok(index_status());
    }
    let response = crate::host_hooks::call_runtime_method("index.prepare", Vec::new(), true)?;
    anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
    response
        .envelope
        .map(|envelope| envelope.summary)
        .ok_or_else(|| anyhow::anyhow!("runtime did not acknowledge background indexing"))
}

// ---- Recall-statistics enqueue bridge ----
// The write queue itself (WriteJob/WRITE_TX) still lives beside the runtime
// Job/admission machinery in the CLI binary; the engine reaches it through
// this installed hook so the shared recall path has one call spelling.

pub type EnqueueRecallStats = fn(RecallStats, usize);

static RECALL_STATS_ENQUEUE: OnceLock<EnqueueRecallStats> = OnceLock::new();

/// Install the host write-queue enqueue implementation. First installer wins.
pub fn install_recall_stats_enqueue(hook: EnqueueRecallStats) -> bool {
    RECALL_STATS_ENQUEUE.set(hook).is_ok()
}

/// Statistics are best effort; never wait for queue capacity on the recall reply path.
pub fn queue_recall_stats(stats: RecallStats, generation: usize) {
    match RECALL_STATS_ENQUEUE.get() {
        Some(enqueue) => enqueue(stats, generation),
        None => {
            STATS_REJECTED.fetch_add(1, Ordering::AcqRel);
            eprintln!("recall statistics rejected: recall statistics queue is not installed");
        }
    }
}

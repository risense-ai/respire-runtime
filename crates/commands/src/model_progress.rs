//! Runtime-owned model work, polled independently of the command worker queue.
use std::cell::{Cell, RefCell};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

thread_local! { static TRACKED: Cell<bool> = const { Cell::new(false) }; }
thread_local! { static TASK_ID: RefCell<Option<String>> = const { RefCell::new(None) }; }
static CURRENT: Mutex<Option<Progress>> = Mutex::new(None);

pub struct TaskScope(Option<String>);
impl TaskScope {
    pub fn new(id: Option<String>) -> Self {
        Self(TASK_ID.replace(id))
    }
}
impl Drop for TaskScope {
    fn drop(&mut self) {
        TASK_ID.replace(self.0.take());
    }
}

struct Progress {
    id: String,
    phase: String,
    item: String,
    done: u64,
    total: Option<u64>,
    started: Instant,
    updated: Instant,
    idle_timeout: bool,
    cancelled: bool,
    cancellable: bool,
}

pub struct Operation;

#[derive(Debug)]
pub enum OperationStopped {
    Cancelled,
    TimedOut,
    IdleTimedOut,
}

impl std::fmt::Display for OperationStopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "model operation cancelled",
            Self::TimedOut => "model operation timed out after 30 minutes",
            Self::IdleTimedOut => "model operation made no progress for 30 minutes",
        })
    }
}

impl std::error::Error for OperationStopped {}

fn check_progress(progress: &Progress) -> Result<()> {
    check_progress_at(progress, Instant::now())
}

fn check_progress_at(progress: &Progress, now: Instant) -> Result<()> {
    if progress.cancelled {
        return Err(OperationStopped::Cancelled.into());
    }
    if progress.idle_timeout {
        if now.duration_since(progress.updated).as_secs() >= 1800 {
            return Err(OperationStopped::IdleTimedOut.into());
        }
    } else if now.duration_since(progress.started).as_secs() >= 1800 {
        return Err(OperationStopped::TimedOut.into());
    }
    Ok(())
}

impl Operation {
    /// Reserve cancellation/progress before acknowledging a queued task.
    pub fn reserve_task(id: String) -> Result<Self> {
        let _scope = TaskScope::new(Some(id));
        let operation = Self::try_begin_inner("queued", true, true)?
            .ok_or_else(|| anyhow!("another model operation is running"))?;
        TRACKED.set(false);
        Ok(operation)
    }
    pub fn enter_thread(&self) {
        TRACKED.set(true);
    }
    /// Download duration depends on bandwidth. Keep progressing downloads alive.
    pub fn begin_download() -> Result<Self> {
        Self::try_begin_with_idle_timeout("verify", true)?
            .ok_or_else(|| anyhow!("another model operation is running"))
    }
    /// Loading crosses a native replacement boundary and commits inside the
    /// isolated SDK worker. Do not acknowledge a cancellation it cannot honor.
    pub fn begin_load() -> Result<Self> {
        Self::try_begin_inner("verify", false, false)?
            .ok_or_else(|| anyhow!("another model operation is running"))
    }
    pub fn begin(phase: &str) -> Result<Self> {
        Self::try_begin(phase)?.ok_or_else(|| anyhow!("another model operation is running"))
    }

    /// Reserve the model slot without waiting, with the foreground total budget.
    pub fn try_begin(phase: &str) -> Result<Option<Self>> {
        Self::try_begin_with_idle_timeout(phase, false)
    }

    /// Large libraries may take hours; only a lack of progress pauses indexing.
    pub fn try_begin_background_index() -> Result<Option<Self>> {
        Self::try_begin_with_idle_timeout("index-load", true)
    }

    fn try_begin_with_idle_timeout(phase: &str, idle_timeout: bool) -> Result<Option<Self>> {
        Self::try_begin_inner(phase, idle_timeout, true)
    }
    fn try_begin_inner(phase: &str, idle_timeout: bool, cancellable: bool) -> Result<Option<Self>> {
        let mut slot = CURRENT
            .lock()
            .map_err(|_| anyhow!("model progress lock poisoned"))?;
        if slot.is_some() {
            return Ok(None);
        }
        *slot = Some(Progress {
            id: TASK_ID
                .with_borrow(|id| id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            phase: phase.to_owned(),
            item: String::new(),
            done: 0,
            total: None,
            started: Instant::now(),
            updated: Instant::now(),
            idle_timeout,
            cancelled: false,
            cancellable,
        });
        TRACKED.set(true);
        Ok(Some(Self))
    }
}

pub fn status() -> Result<Value> {
    let slot = CURRENT
        .lock()
        .map_err(|_| anyhow!("model progress lock poisoned"))?;
    Ok(match slot.as_ref() {
        Some(progress) => json!({
            "active": true, "id": progress.id, "phase": progress.phase,
            "item": progress.item, "done": progress.done, "total": progress.total,
            "elapsed": progress.started.elapsed().as_secs(),
            "idle": progress.updated.elapsed().as_secs(), "cancelled": progress.cancelled,
            "cancellable": progress.cancellable,
        }),
        None => json!({"active": false}),
    })
}

impl Drop for Operation {
    fn drop(&mut self) {
        TRACKED.set(false);
        if let Ok(mut slot) = CURRENT.lock() {
            *slot = None;
        }
    }
}

pub fn update(phase: &str, item: &str, done: u64, total: Option<u64>) -> Result<()> {
    if !TRACKED.get() {
        return Ok(());
    }
    let mut slot = CURRENT
        .lock()
        .map_err(|_| anyhow!("model progress lock poisoned"))?;
    if let Some(progress) = slot.as_mut() {
        check_progress(progress)?;
        if progress.phase != phase || progress.item != item || progress.done != done {
            progress.updated = Instant::now();
        }
        progress.phase = phase.to_owned();
        progress.item = item.to_owned();
        progress.done = done;
        progress.total = total;
    }
    Ok(())
}

pub fn check() -> Result<()> {
    if TRACKED.get() {
        let slot = CURRENT
            .lock()
            .map_err(|_| anyhow!("model progress lock poisoned"))?;
        if let Some(progress) = slot.as_ref() {
            check_progress(progress)?;
        }
    }
    Ok(())
}

/// Linearize a short durable commit with cancellation acknowledgement. The
/// expensive model call runs before this guard, never while CURRENT is held.
#[doc(hidden)]
pub fn commit<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    let slot = CURRENT
        .lock()
        .map_err(|_| anyhow!("model progress lock poisoned"))?;
    anyhow::ensure!(
        TRACKED.get(),
        "diary commit requires an active model operation"
    );
    check_progress(
        slot.as_ref()
            .ok_or_else(|| anyhow!("model operation already ended"))?,
    )?;
    action()
}

pub fn commit_final<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut slot = CURRENT
        .lock()
        .map_err(|_| anyhow!("model progress lock poisoned"))?;
    anyhow::ensure!(
        TRACKED.get(),
        "final commit requires an active model operation"
    );
    let progress = slot
        .as_mut()
        .ok_or_else(|| anyhow!("model operation already ended"))?;
    check_progress(progress)?;
    let result = action()?;
    progress.cancellable = false;
    progress.phase = "committed".to_owned();
    Ok(result)
}

pub fn control(task_id: &str, cancel: bool) -> Result<Value> {
    let mut slot = CURRENT
        .lock()
        .map_err(|_| anyhow!("model progress lock poisoned"))?;
    let Some(p) = slot.as_mut() else {
        return Ok(json!({"active":false}));
    };
    if p.id != task_id {
        return Ok(json!({"active":true,"stale":true}));
    }
    if cancel {
        anyhow::ensure!(p.cancellable,
            "model loading cannot be cancelled; cancellation was not accepted; wait for the load result");
        p.cancelled = true;
    }
    Ok(json!({
        "active": true,
        "id": p.id,
        "phase": p.phase,
        "item": p.item,
        "done": p.done,
        "total": p.total,
        "elapsed": p.started.elapsed().as_secs(),
        "idle": p.updated.elapsed().as_secs(),
        "cancelled": p.cancelled,
        "cancellable": p.cancellable,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn loading_rejects_cancel_without_acknowledgement_at_validation_and_native_phases() -> Result<()>
    {
        let _serial = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _scope = TaskScope::new(Some("synthetic-uncancellable-load".into()));
        let _operation = Operation::begin_load()?;
        for phase in ["verify", "load"] {
            update(phase, "int8", 0, None)?;
            let before = control("synthetic-uncancellable-load", false)?;
            assert_eq!(before["cancellable"], false);
            assert_eq!(before["cancelled"], false);
            let error = control("synthetic-uncancellable-load", true).unwrap_err();
            assert!(error.to_string().contains("cancellation was not accepted"));
            assert_eq!(
                control("synthetic-uncancellable-load", false)?["cancelled"],
                false
            );
            check()?;
        }
        Ok(())
    }

    #[test]
    fn cancellation_acknowledgement_is_serialized_with_durable_commit() -> Result<()> {
        let _serial = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _scope = TaskScope::new(Some("synthetic-commit-cancel".into()));
        let _operation = Operation::begin("index")?;
        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let mut worker = None;
        commit(|| {
            worker = Some(std::thread::spawn(move || {
                assert!(
                    CURRENT.try_lock().is_err(),
                    "commit must hold the cancellation lock"
                );
                attempt_tx.send(()).unwrap();
                let reply = control("synthetic-commit-cancel", true);
                ack_tx.send(reply).unwrap();
            }));
            attempt_rx.recv_timeout(Duration::from_secs(2))?;
            assert!(
                ack_rx.recv_timeout(Duration::from_millis(20)).is_err(),
                "cancellation acknowledged before the protected commit ended"
            );
            Ok(())
        })?;
        assert_eq!(
            ack_rx.recv_timeout(Duration::from_secs(2))??["cancelled"],
            true
        );
        worker.unwrap().join().unwrap();
        assert!(check().is_err());
        let mut wrote = false;
        assert!(commit(|| {
            wrote = true;
            Ok(())
        })
        .is_err());
        assert!(
            !wrote,
            "an acknowledged cancellation must reject later durable writes"
        );
        Ok(())
    }

    fn long_operation(now: Instant, idle_timeout: bool, idle: u64) -> Progress {
        Progress {
            id: "fixture".to_owned(),
            phase: "index".to_owned(),
            item: "m3".to_owned(),
            done: 100,
            total: Some(4000),
            started: now - Duration::from_secs(3600),
            updated: now - Duration::from_secs(idle),
            idle_timeout,
            cancelled: false,
            cancellable: true,
        }
    }

    #[test]
    fn long_rebuild_survives_progress_but_still_honors_idle_timeout_and_cancellation() {
        let now = Instant::now() + Duration::from_secs(3600);
        assert!(check_progress_at(&long_operation(now, true, 1), now).is_ok());
        assert!(check_progress_at(&long_operation(now, false, 1), now).is_err());
        assert!(check_progress_at(&long_operation(now, true, 1801), now).is_err());
        let mut cancelled = long_operation(now, true, 1);
        cancelled.cancelled = true;
        assert!(check_progress_at(&cancelled, now).is_err());
    }
}

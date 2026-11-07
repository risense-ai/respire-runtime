//! Two-way ciphertext sync flow shared by engine arms, the status report and
//! the runtime's background sync worker.
//!
//! Live progress state (`SYNC_LIVE`), the retry policy and the tracked sync
//! entry points migrated verbatim from the CLI binary; runtime-worker
//! interaction goes through the shared `rpc_worker` module.

use std::sync::Mutex;

use anyhow::{anyhow, Result};

use respire_app::sync::SyncStats;
use respire_app::transport::local::LocalStore;
use respire_app::transport::remote::RemoteTransport;
use respire_app::SessionKeys;

use crate::progress;
// The worker face keeps its `rpc::` call spelling from the extraction source.
use crate::rpc_worker as rpc;

pub struct SyncLive {
    pub phase: String,
    pub pulled: u64,
    pub pushed: u64,
    pub remote_alive: u64,
    pub pending: i64,
    pub conflicts: i64,
    pub error: String,
}

static SYNC_LIVE: Mutex<SyncLive> = Mutex::new(SyncLive {
    phase: String::new(),
    pulled: 0,
    pushed: 0,
    remote_alive: 0,
    pending: 0,
    conflicts: 0,
    error: String::new(),
});

pub fn sync_live() -> SyncLive {
    let guard = SYNC_LIVE.lock().unwrap_or_else(|err| err.into_inner());
    SyncLive {
        phase: guard.phase.clone(),
        pulled: guard.pulled,
        pushed: guard.pushed,
        remote_alive: guard.remote_alive,
        pending: guard.pending,
        conflicts: guard.conflicts,
        error: guard.error.clone(),
    }
}

const SYNC_ATTEMPTS: u32 = 3;
pub fn is_retriable_sync_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(ureq::Error::Transport(_)) = cause.downcast_ref::<ureq::Error>() {
            return true;
        }
    }
    let text = format!("{err:#}").to_ascii_lowercase();
    text.contains("timed out")
        || text.contains("timeout")
        || text.contains("connection reset")
        || text.contains("connection refused")
        || text.contains("connection aborted")
}

/// Run a sync attempt up to three times. Only transport failures retry.
/// Backoff is 1s then 2s. Protocol and epoch errors return immediately.
pub fn run_sync_attempts<T>(mut once: impl FnMut() -> Result<T>) -> Result<T> {
    let mut last = None;
    for attempt in 0..SYNC_ATTEMPTS {
        match once() {
            Ok(value) => return Ok(value),
            Err(err) if attempt + 1 < SYNC_ATTEMPTS && is_retriable_sync_error(&err) => {
                progress::phase("\u{540c}\u{6b65}\u{8fde}\u{63a5}\u{5931}\u{8d25}\u{ff1b}\u{7b49}\u{5f85}\u{91cd}\u{8bd5}", "Sync connection failed; waiting to retry");
                let pause = if cfg!(test) {
                    std::time::Duration::from_millis(0)
                } else {
                    std::time::Duration::from_secs(1_u64 << attempt)
                };
                last = Some(err);
                if !pause.is_zero() {
                    std::thread::sleep(pause);
                }
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("sync failed")))
}

struct RuntimeSyncControl {
    generation: usize,
}
impl respire_app::sync::SyncControl for RuntimeSyncControl {
    fn progress(&self, phase: &str) {
        match phase {
            "capabilities" => progress::phase("\u{534f}\u{5546}\u{540c}\u{6b65}\u{534f}\u{8bae}\u{ff1b}\u{7b49}\u{5f85}\u{670d}\u{52a1}\u{5668}", "Negotiating sync protocol; waiting for server"),
            "pull" => progress::phase("\u{4e0b}\u{8f7d}\u{53d8}\u{66f4}\u{ff1b}\u{7b49}\u{5f85}\u{670d}\u{52a1}\u{5668}", "Downloading changes; waiting for server"),
            "push" => progress::phase("\u{4e0a}\u{4f20}\u{53d8}\u{66f4}\u{ff1b}\u{7b49}\u{5f85}\u{670d}\u{52a1}\u{5668}\u{786e}\u{8ba4}", "Uploading changes; waiting for server acknowledgement"),
            "apply" => progress::phase("\u{4fdd}\u{5b58}\u{540c}\u{6b65}\u{6570}\u{636e}", "Saving synchronized data"),
            "materialize" => progress::phase("\u{89e3}\u{5bc6}\u{540c}\u{6b65}\u{6570}\u{636e}", "Decrypting synchronized data"),
            "conflicts" => progress::phase("\u{68c0}\u{67e5}\u{540c}\u{6b65}\u{51b2}\u{7a81}", "Checking sync conflicts"),
            "verify" => progress::phase("\u{6838}\u{5bf9}\u{540c}\u{6b65}\u{7ed3}\u{679c}", "Verifying sync result"),
            _ => {}
        }
    }
    fn boundary_changed(&self) -> Result<()> {
        if rpc::worker_active() {
            rpc::invalidate_sync_boundary(self.generation)?;
        }
        Ok(())
    }
    fn local<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        if rpc::worker_active() {
            rpc::sync_local(self.generation, action)
        } else {
            action()
        }
    }
    fn remote<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        if rpc::worker_active() {
            rpc::check_sync_context(self.generation)?;
        }
        action()
    }
}
pub fn sync_phase<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    if rpc::worker_active() {
        rpc::sync_local(rpc::sync_generation(), action)
    } else {
        action()
    }
}
pub fn sync_with_retry(
    session: &SessionKeys,
    local: &LocalStore,
    remote: &RemoteTransport,
) -> Result<SyncStats> {
    let boundary = sync_phase(|| local.outgoing_boundary())?;
    let boundary = rpc::sync_boundary().unwrap_or(boundary);
    run_sync_attempts(|| sync_tracked_boundary(session, local, remote, boundary))
}

pub fn sync_tracked(
    session: &SessionKeys,
    local: &LocalStore,
    remote: &RemoteTransport,
) -> Result<SyncStats> {
    let boundary = sync_phase(|| local.outgoing_boundary())?;
    let boundary = rpc::sync_boundary().unwrap_or(boundary);
    sync_tracked_boundary(session, local, remote, boundary)
}

pub fn read_remote_sync_history(
    transport: &impl respire_app::transport::MemoryTransport,
    epoch: &str,
    id: Option<&str>,
    op_id: Option<&str>,
    rev: Option<i64>,
) -> Result<Vec<respire_app::transport::protocol::Change>> {
    let mut history = std::collections::VecDeque::with_capacity(200);
    let mut after = 0;
    let mut until = None;
    loop {
        let page = transport.pull_v2(epoch, after, until, false)?;
        if page.epoch != epoch
            || page.cursor < after
            || page.cursor > page.until
            || (page.has_more && page.cursor == after)
            || until.is_some_and(|value| value != page.until)
        {
            anyhow::bail!("illegal history page");
        }
        let mut previous = after;
        for change in page.changes {
            if change.rev <= previous || change.rev > page.cursor {
                anyhow::bail!("illegal history version order");
            }
            previous = change.rev;
            if id.is_some_and(|value| change.blob.id != value)
                || op_id.is_some_and(|value| change.op_id.as_deref() != Some(value))
                || rev.is_some_and(|value| change.rev != value)
            {
                continue;
            }
            history.push_back(change);
            if op_id.is_some() || rev.is_some() {
                return Ok(history.into_iter().collect());
            }
            if history.len() > 200 {
                history.pop_front();
            }
        }
        after = page.cursor;
        until = Some(page.until);
        if !page.has_more {
            break;
        }
    }
    Ok(history.into_iter().rev().collect())
}
pub fn sync_tracked_boundary(
    session: &SessionKeys,
    local: &LocalStore,
    remote: &RemoteTransport,
    boundary: i64,
) -> Result<SyncStats> {
    {
        let mut guard = SYNC_LIVE.lock().unwrap_or_else(|err| err.into_inner());
        guard.phase = "running".to_owned();
        guard.error.clear();
    }
    let control = RuntimeSyncControl {
        generation: rpc::sync_generation(),
    };
    let result = respire_app::sync::sync_controlled(
        session,
        local,
        remote,
        &control,
        rpc::worker_active().then_some(boundary),
    );
    {
        let mut guard = SYNC_LIVE.lock().unwrap_or_else(|err| err.into_inner());
        match &result {
            Ok(stats) => {
                guard.phase = "ok".to_owned();
                guard.pulled = stats.pulled as u64;
                guard.pushed = stats.pushed as u64;
                guard.remote_alive = stats.remote_alive as u64;
                guard.pending = stats.pending;
                guard.conflicts = stats.conflicts;
                guard.error.clear();
            }
            Err(error) => {
                guard.phase = "err".to_owned();
                guard.error = format!("{error:#}");
            }
        }
    }
    result
}

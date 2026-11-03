//! Queue deadlines distinguish commands that never started from executing writes.
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const QUEUED: u8 = 0;
const RUNNING: u8 = 1;
const CANCELLED: u8 = 2;

pub struct QueueDeadline {
    state: AtomicU8,
    deadline: Instant,
    created: Instant,
    started_micros: AtomicU64,
}

static TIMINGS: Mutex<VecDeque<(u64, u64)>> = Mutex::new(VecDeque::new());
static QUEUE_CANCELLED: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicU64 = AtomicU64::new(0);
static EXECUTING: AtomicU64 = AtomicU64::new(0);

pub fn occupancy() -> (u64, u64) {
    let executing = EXECUTING.load(Ordering::Acquire);
    (
        LIVE.load(Ordering::Acquire).saturating_sub(executing),
        executing,
    )
}

pub fn timings() -> (u64, Vec<(u64, u64)>) {
    (
        QUEUE_CANCELLED.load(Ordering::Acquire),
        TIMINGS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .copied()
            .collect(),
    )
}

impl QueueDeadline {
    pub fn new(wait: Duration) -> Self {
        LIVE.fetch_add(1, Ordering::AcqRel);
        let created = Instant::now();
        Self {
            state: AtomicU8::new(QUEUED),
            deadline: created + wait,
            created,
            started_micros: AtomicU64::new(0),
        }
    }

    /// The winner determines whether the command may have any side effects.
    pub fn start(&self) -> bool {
        if Instant::now() >= self.deadline {
            self.cancel();
            return false;
        }
        let started = self
            .state
            .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if started {
            EXECUTING.fetch_add(1, Ordering::AcqRel);
            self.started_micros.store(
                self.created.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Release,
            );
        }
        started
    }

    pub fn cancel(&self) -> bool {
        let cancelled = self
            .state
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if cancelled {
            QUEUE_CANCELLED.fetch_add(1, Ordering::AcqRel);
        }
        cancelled
    }

    pub fn expired(&self) -> bool {
        if Instant::now() >= self.deadline {
            self.cancel();
        }
        self.state.load(Ordering::Acquire) == CANCELLED
    }

    pub fn running(&self) -> bool {
        self.state.load(Ordering::Acquire) == RUNNING
    }
}

impl Drop for QueueDeadline {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::AcqRel);
        if self.state.load(Ordering::Acquire) != RUNNING {
            return;
        }
        EXECUTING.fetch_sub(1, Ordering::AcqRel);
        let wait = self.started_micros.load(Ordering::Acquire);
        let total = self.created.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let mut samples = TIMINGS.lock().unwrap_or_else(|error| error.into_inner());
        if samples.len() == 1024 {
            samples.pop_front();
        }
        samples.push_back((wait, total.saturating_sub(wait)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_write_cannot_start() {
        let deadline = QueueDeadline::new(Duration::ZERO);
        assert!(!deadline.start());
        assert!(!deadline.start());
    }

    #[test]
    fn cancellation_and_execution_have_exactly_one_winner() {
        for _ in 0..100 {
            let deadline = QueueDeadline::new(Duration::from_secs(1));
            std::thread::scope(|scope| {
                let start = scope.spawn(|| deadline.start());
                let cancel = scope.spawn(|| deadline.cancel());
                assert_ne!(start.join().unwrap(), cancel.join().unwrap());
            });
        }
    }

    #[test]
    fn started_write_cannot_report_not_started() {
        let deadline = QueueDeadline::new(Duration::from_secs(1));
        assert!(deadline.start());
        assert!(!deadline.cancel());
    }
}

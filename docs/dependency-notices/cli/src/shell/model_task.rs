//! Model task feedback remains responsive even while all command workers are occupied.
use super::{fail_line, line, t, Line, FAST};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(super) struct Task {
    pub id: String,
    pub cancel: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
    progress: Arc<Mutex<Result<Value, String>>>,
    started: Instant,
}

impl Task {
    pub(super) fn start() -> Self {
        let task = Self {
            id: uuid::Uuid::new_v4().to_string(),
            cancel: Arc::new(AtomicBool::new(false)),
            finished: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(Ok(Value::Null))),
            started: Instant::now(),
        };
        let cancel = Arc::clone(&task.cancel);
        let finished = Arc::clone(&task.finished);
        let progress = Arc::clone(&task.progress);
        let id = task.id.clone();
        std::thread::spawn(move || {
            while !finished.load(Ordering::Acquire) {
                let result = crate::rpc::model_control(&id, cancel.load(Ordering::Acquire))
                    .map_err(|error| error.to_string());
                if let Ok(mut slot) = progress.lock() {
                    *slot = result;
                }
                std::thread::sleep(FAST);
            }
        });
        task
    }

    pub(super) fn lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![line(t("\u{6a21}\u{578b}\u{4efb}\u{52a1}", "Model task"))];
        let progress = self
            .progress
            .lock()
            .map(|value| value.clone())
            .unwrap_or_else(|_| Err("progress lock poisoned".into()));
        match progress {
            Ok(value) if value["active"] == true => {
                let phase = value["phase"].as_str().unwrap_or("");
                let label = match phase {
                    "connect" => t("\u{8fde}\u{63a5}\u{4e0b}\u{8f7d}\u{6e90} / \u{7b49}\u{5f85}\u{54cd}\u{5e94}", "Connecting / waiting for response"),
                    "download" => t("\u{4e0b}\u{8f7d}", "Downloading"),
                    "verify" => t("\u{6821}\u{9a8c}\u{6587}\u{4ef6}", "Verifying files"),
                    "load" => t("\u{52a0}\u{8f7d}\u{6a21}\u{578b}", "Loading model"),
                    "index" => t("\u{91cd}\u{5efa}\u{7d22}\u{5f15}", "Rebuilding index"),
                    _ => phase.to_owned(),
                };
                lines.push(line(format!(
                    "{label}: {}",
                    value["item"].as_str().unwrap_or("")
                )));
                let done = value["done"].as_u64().unwrap_or(0);
                let total = value["total"].as_u64().filter(|total| *total > 0);
                if let Some(total) = total {
                    let ratio = (done as f64 / total as f64).min(1.0);
                    let filled = (ratio * 24.0) as usize;
                    lines.push(line(format!(
                        "[{}{}] {:.1}%",
                        "#".repeat(filled),
                        "-".repeat(24 - filled),
                        ratio * 100.0
                    )));
                }
                if phase == "download" || phase == "verify" {
                    lines.push(line(format!(
                        "{:.1} MiB / {}",
                        done as f64 / 1048576.0,
                        total
                            .map(|n| format!("{:.1} MiB", n as f64 / 1048576.0))
                            .unwrap_or_else(|| t("\u{603b}\u{5927}\u{5c0f}\u{672a}\u{77e5}", "unknown total"))
                    )));
                } else if phase == "index" {
                    lines.push(line(format!(
                        "{done} / {} {}",
                        total.unwrap_or(0),
                        t("\u{6761}\u{8bb0}\u{5fc6}", "memories")
                    )));
                }
                lines.push(line(format!(
                    "{} {}s",
                    t("\u{8ddd}\u{4e0a}\u{6b21}\u{8fdb}\u{5c55}", "Since last progress"),
                    value["idle"].as_u64().unwrap_or(0)
                )));
            }
            Ok(_) => lines.push(line(t(
                "\u{7b49}\u{5f85}\u{4efb}\u{52a1}\u{542f}\u{52a8}\u{6216}\u{5207}\u{6362}\u{9636}\u{6bb5}\u{2026}",
                "Waiting for task / next phase...",
            ))),
            Err(error) => lines.push(fail_line(format!(
                "{}: {error}",
                t("\u{8fdb}\u{5ea6}\u{8fde}\u{63a5}\u{5931}\u{8d25}", "Progress connection failed")
            ))),
        }
        lines.push(line(format!(
            "{} {}s",
            t("\u{5df2}\u{7528}\u{65f6}", "Elapsed"),
            self.started.elapsed().as_secs()
        )));
        lines.push(line(if self.cancel.load(Ordering::Acquire) {
            t(
                "\u{5df2}\u{8bf7}\u{6c42}\u{53d6}\u{6d88}\u{ff0c}\u{7b49}\u{5f85}\u{5f53}\u{524d}\u{7f51}\u{7edc}\u{8bfb}\u{53d6}\u{6216}\u{63a8}\u{7406}\u{7ed3}\u{675f}\u{2026}",
                "Cancellation requested; waiting for the current read / inference...",
            )
        } else {
            t(
                "Esc / C \u{53d6}\u{6d88}\u{4efb}\u{52a1}\u{ff1b}\u{5b8c}\u{6210}\u{524d}\u{4fdd}\u{7559}\u{5f53}\u{524d}\u{7d22}\u{5f15}",
                "Esc / C cancels; current index stays active until complete",
            )
        }));
        lines
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
    }
}

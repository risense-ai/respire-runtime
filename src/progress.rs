//! Human progress is separate from stdout and scoped to one foreground request.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

struct Entry {
    id: String,
    phase: Mutex<String>,
    remote: AtomicBool,
    finished: AtomicBool,
}
static ACTIVE: OnceLock<Mutex<HashMap<String, Arc<Entry>>>> = OnceLock::new();
thread_local! {
    static CURRENT: RefCell<Option<Arc<Entry>>> = const { RefCell::new(None) };
}

pub struct Scope {
    entry: Arc<Entry>,
    stop: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Scope {
    pub fn start(id: Option<String>, display: bool, immediate: bool) -> Option<Self> {
        if id.is_none() && !display { return None; }
        let entry = Arc::new(Entry {
            id: id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            phase: Mutex::new(text("\u{6b63}\u{5728}\u{51c6}\u{5907}\u{547d}\u{4ee4}", "Preparing command")),
            remote: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        });
        if let Ok(mut active) = ACTIVE.get_or_init(|| Mutex::new(HashMap::new())).lock() {
            active.insert(entry.id.clone(), entry.clone());
        }
        CURRENT.with(|current| *current.borrow_mut() = Some(entry.clone()));
        let (stop, receiver) = mpsc::channel();
        if display && immediate {
            print(&text("\u{6b63}\u{5728}\u{51c6}\u{5907}\u{547d}\u{4ee4}", "Preparing command"), 0, stderr_is_terminal());
        }
        let worker = if display {
            let entry = entry.clone();
            Some(std::thread::spawn(move || {
                let started = Instant::now();
                let mut last = String::new();
                let mut shown = Instant::now();
                while receiver.recv_timeout(Duration::from_millis(250)).is_err() {
                    if entry.finished.load(Ordering::Acquire) { break; }
                    let mut phase = entry.phase.lock().map(|phase| phase.clone()).unwrap_or_default();
                    if entry.remote.load(Ordering::Acquire) {
                        // Poll outside the command worker pool, so saturated workers can report their wait.
                        match crate::host_hooks::foreground_progress(&entry.id) {
                            Ok(value) => {
                                if let Some(current) = value["phase"].as_str() { phase = current.to_owned(); }
                                else { phase = text("\u{7b49}\u{5f85} runtime \u{6267}\u{884c}\u{547d}\u{4ee4}", "Waiting for runtime to execute command"); }
                                if value["model_operation"]["active"] == true {
                                    phase = crate::output::model_task_text(&value["model_operation"]);
                                }
                                if let Some(inference) = inference_progress_text(&value["inference"]) {
                                    phase = format!("{phase} \u{b7} {inference}");
                                }
                            }
                            Err(_) => phase = text("\u{7b49}\u{5f85} runtime \u{54cd}\u{5e94}", "Waiting for runtime response"),
                        }
                    }
                    if phase != last || shown.elapsed() >= Duration::from_secs(5) {
                        let mut stderr = std::io::stderr().lock();
                        if entry.finished.load(Ordering::Acquire) { break; }
                        write_line(&mut stderr, &phase, started.elapsed().as_secs(), stderr_is_terminal());
                        last = phase;
                        shown = Instant::now();
                    }
                }
            }))
        } else { None };
        Some(Self { entry, stop, worker })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        finish();
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
        if let Some(active) = ACTIVE.get() {
            if let Ok(mut active) = active.lock() { active.remove(&self.entry.id); }
        }
        CURRENT.with(|current| *current.borrow_mut() = None);
    }
}

fn text(zh: &str, en: &str) -> String {
    if crate::i18n::lang() == crate::i18n::Lang::Zh { zh } else { en }.to_owned()
}

pub(crate) fn inference_progress_text(status: &serde_json::Value) -> Option<String> {
    if status["host_recovery_required"] == true {
        return Some(text("\u{63a8}\u{7406}\u{65e0}\u{54cd}\u{5e94}\u{ff0c}\u{9700}\u{8981}\u{5bbf}\u{4e3b}\u{6062}\u{590d}", "Inference unresponsive; host recovery required"));
    }
    let queued = status["queued"].as_u64()?;
    if status["phase"] == "loading" {
        return Some(text("\u{63a8}\u{7406}\u{72b6}\u{6001}\u{ff1a}\u{6b63}\u{5728}\u{52a0}\u{8f7d}\u{524d}\u{540e}\u{53f0}\u{6a21}\u{578b}", "Inference status: loading foreground and background models"));
    }
    if status["foreground"].is_object() && status["background"].is_object()
        && (status["active"] == true || queued > 0) {
        let lane = |name: &str, zh: &str, en: &str| {
            let active = status[name]["active"] == true;
            let waiting = status[name]["queued"].as_u64().unwrap_or(0);
            let state = if active { text("\u{8fd0}\u{884c}\u{4e2d}", "active") } else { text("\u{7a7a}\u{95f2}", "idle") };
            format!("{} {state}; {} {waiting}", text(zh, en), text("\u{7b49}\u{5f85}", "queued"))
        };
        return Some(format!("{}: {}; {}", text("\u{63a8}\u{7406}\u{72b6}\u{6001}", "Inference status"),
            lane("foreground", "\u{524d}\u{53f0}", "foreground"), lane("background", "\u{540e}\u{53f0}", "background")));
    }
    if status["active"] == true || queued > 0 {
        let label = if status["phase"] == "loading" {
            text("\u{63a8}\u{7406}\u{670d}\u{52a1}\u{ff08}\u{5168}\u{5c40}\u{ff09}\u{ff1a}\u{52a0}\u{8f7d}\u{6a21}\u{578b}\u{ff1b}\u{7b49}\u{5f85}\u{4efb}\u{52a1}", "Inference service (global): loading; queued")
        } else {
            text("\u{63a8}\u{7406}\u{670d}\u{52a1}\u{ff08}\u{5168}\u{5c40}\u{ff09}\u{ff1a}\u{8fd0}\u{884c}\u{4e2d}\u{ff1b}\u{7b49}\u{5f85}\u{4efb}\u{52a1}", "Inference service (global): active; queued")
        };
        return Some(format!("{label} {queued}"));
    }
    None
}

pub fn phase(zh: &str, en: &str) {
    CURRENT.with(|current| {
        if let Some(entry) = current.borrow().as_ref() {
            if let Ok(mut phase) = entry.phase.lock() { *phase = text(zh, en); }
        }
    });
}

/// Determinate variant of [`phase`]: appends `done/total (pct%)`.
pub fn phase_count(zh: &str, en: &str, done: usize, total: usize) {
    let percent = if total == 0 { 100 } else { done.saturating_mul(100) / total };
    phase(
        &format!("{zh} {done}/{total} ({percent}%)"),
        &format!("{en} {done}/{total} ({percent}%)"),
    );
}

pub fn remote_id() -> Option<String> {
    CURRENT.with(|current| current.borrow().as_ref().map(|entry| {
        phase("\u{8fde}\u{63a5} runtime\u{ff1b}\u{7b49}\u{5f85}\u{547d}\u{4ee4}\u{7ed3}\u{679c}", "Connecting to runtime; waiting for command result");
        entry.remote.store(true, Ordering::Release);
        entry.id.clone()
    }))
}

pub fn status(id: &str) -> serde_json::Value {
    let mut value = ACTIVE.get().and_then(|active| active.lock().ok())
        .and_then(|active| active.get(id).cloned())
        .and_then(|entry| entry.phase.lock().ok().map(|phase| serde_json::json!({"phase":*phase})))
        .unwrap_or(serde_json::Value::Null);
    if !value.is_null() {
        if let Ok(task) = crate::model_progress::status() {
            if task["id"].as_str() == Some(id) { value["model_operation"] = task; }
        }
    }
    value
}

pub fn finish() {
    CURRENT.with(|current| {
        if let Some(entry) = current.borrow().as_ref() {
            if !entry.finished.swap(true, Ordering::AcqRel) && stderr_is_terminal() {
                let mut stderr = std::io::stderr().lock();
                let _ = write!(stderr, "\r\x1b[2K");
                let _ = stderr.flush();
            }
        }
    });
}

fn stderr_is_terminal() -> bool { std::io::stderr().is_terminal() }
fn print(phase: &str, elapsed: u64, tty: bool) {
    write_line(&mut std::io::stderr().lock(), phase, elapsed, tty);
}
fn write_line(writer: &mut impl Write, phase: &str, elapsed: u64, tty: bool) {
    if tty { let _ = write!(writer, "\r\x1b[2K{phase} ({elapsed}s)"); }
    else { let _ = writeln!(writer, "{phase} ({elapsed}s)"); }
    let _ = writer.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_progress_is_brief_and_reports_stalls() {
        assert!(inference_progress_text(&serde_json::json!({"active":false,"queued":0})).is_none());
        let busy = inference_progress_text(&serde_json::json!({"active":true,"queued":3}));
        assert!(busy.is_some_and(|text| text.ends_with("3") && !text.contains('{')));
        let independent = inference_progress_text(&serde_json::json!({"active":true,"queued":2,
            "foreground":{"active":false,"queued":0},"background":{"active":true,"queued":2}}));
        assert!(independent.is_some_and(|text| !text.contains('{') && text.contains("0") && text.contains("2")));
        let stalled = inference_progress_text(&serde_json::json!({"host_recovery_required":true}));
        assert!(stalled.is_some_and(|text| !text.contains('{')));
    }

    #[test]
    fn json_is_silent_and_redirected_progress_has_no_terminal_codes() -> anyhow::Result<()> {
        assert!(Scope::start(None, false, false).is_none());
        let mut plain = Vec::new();
        write_line(&mut plain, "Waiting for server", 5, false);
        assert_eq!(String::from_utf8(plain)?, "Waiting for server (5s)\n");
        let mut terminal = Vec::new();
        write_line(&mut terminal, "Downloading 25%", 2, true);
        assert_eq!(String::from_utf8(terminal)?, "\r\x1b[2KDownloading 25% (2s)");
        Ok(())
    }
}

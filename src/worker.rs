//! A host-owned process isolates synchronous native calls. It never owns SQLite.
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const HEARTBEAT_LIMIT: Duration = Duration::from_secs(10);
const CANCEL_GRACE: Duration = Duration::from_secs(5);
// Load + native queue + execution budgets, plus cancellation grace.
#[cfg(not(feature = "native-fault-tests"))]
const CALL_LIMIT: Duration = Duration::from_secs(365);
#[cfg(feature = "native-fault-tests")]
const CALL_LIMIT: Duration = Duration::from_secs(10);
static ENABLED: AtomicBool = AtomicBool::new(false);
static STOPPING: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
static PROCESS: Mutex<Option<Arc<Process>>> = Mutex::new(None);

struct Pending {
    sender: mpsc::Sender<Value>,
    started: Instant,
}

struct Process {
    child: Mutex<Child>,
    input: Mutex<Option<ChildStdin>>,
    pending: Mutex<HashMap<u64, Pending>>,
    heartbeat: Mutex<(Instant, Value, Option<Instant>)>,
    retired: AtomicBool,
    reaped: AtomicBool,
    pid: u32,
    generation: u64,
}

/// Call only in the resident host after acquiring its library lock.
pub fn enable() {
    ENABLED.store(true, Ordering::Release);
}
pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

pub fn status() -> Result<Value> {
    let process = PROCESS
        .lock()
        .map_err(|_| anyhow::anyhow!("Core worker state poisoned"))?
        .clone();
    let Some(process) = process else {
        return Ok(
            json!({"phase":"idle", "host_recovery_required":false, "worker_generation":generation()}),
        );
    };
    let mut status = process
        .heartbeat
        .lock()
        .map_err(|_| anyhow::anyhow!("Core worker heartbeat poisoned"))?
        .1
        .clone();
    status["worker_generation"] = json!(process.generation);
    status["worker_pending_calls"] = json!(process
        .pending
        .lock()
        .map_err(|_| anyhow::anyhow!("Core worker pending poisoned"))?
        .len());
    status["worker_call_deadline_secs"] = json!(CALL_LIMIT.as_secs());
    status["worker_pid"] = json!(process.pid);
    status["worker_retired"] = json!(process.retired.load(Ordering::Acquire));
    status["worker_reaped"] = json!(process.reaped.load(Ordering::Acquire));
    if process.retired.load(Ordering::Acquire) && !process.reaped.load(Ordering::Acquire) {
        status["phase"] = json!("worker_retiring");
        status["host_recovery_required"] = json!(true);
    }
    if process.reaped.load(Ordering::Acquire) {
        let previous = status.clone();
        status = json!({"phase":"worker_recovery_pending", "host_recovery_required":false,
            "worker_generation":generation(),"retired_worker":previous});
    }
    Ok(status)
}

fn read_frame(input: &mut impl Read) -> Result<Value> {
    let mut length = [0; 8];
    input.read_exact(&mut length)?;
    let length =
        usize::try_from(u64::from_le_bytes(length)).context("Core worker frame length overflow")?;
    anyhow::ensure!(length > 0, "invalid Core worker frame length");
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .context("Core worker frame allocation failed")?;
    bytes.resize(length, 0);
    input.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).context("invalid Core worker frame")
}

fn write_frame(output: &mut impl Write, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    output.write_all(&(bytes.len() as u64).to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}

impl Process {
    fn send(&self, value: &Value) -> Result<()> {
        anyhow::ensure!(
            !self.retired.load(Ordering::Acquire),
            "Core worker retired; command was not replayed"
        );
        let mut input = self
            .input
            .lock()
            .map_err(|_| anyhow::anyhow!("Core worker input poisoned"))?;
        write_frame(input.as_mut().context("Core worker pipe closed")?, value)
    }

    fn retire(&self, reason: &str) -> Result<()> {
        // The Child handle, rather than an endpoint PID, identifies the owned process.
        if !self.retired.swap(true, Ordering::AcqRel) {
            GENERATION.fetch_add(1, Ordering::AcqRel);
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("Core worker pending poisoned"))?;
            for (id, pending) in pending.drain() {
                let _ = pending.sender.send(json!({"id":id,"error":format!("Core worker retired: {reason}; command was not replayed")}));
            }
        }
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("Core worker child poisoned"))?;
        if self.reaped.load(Ordering::Acquire) {
            return Ok(());
        }
        if child.try_wait()?.is_none() {
            child
                .kill()
                .context("terminate unresponsive owned Core worker")?;
        }
        let started = Instant::now();
        while child.try_wait()?.is_none() {
            anyhow::ensure!(
                started.elapsed() < Duration::from_secs(5),
                "owned Core worker did not exit; replacement prohibited"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.reaped.store(true, Ordering::Release);
        self.input
            .lock()
            .map_err(|_| anyhow::anyhow!("Core worker input poisoned"))?
            .take();
        Ok(())
    }
}

fn process() -> Result<Arc<Process>> {
    let mut slot = PROCESS
        .lock()
        .map_err(|_| anyhow::anyhow!("Core worker state poisoned"))?;
    anyhow::ensure!(
        !STOPPING.load(Ordering::Acquire),
        "Core worker host is stopping; command was not submitted"
    );
    if let Some(process) = slot
        .as_ref()
        .filter(|process| !process.retired.load(Ordering::Acquire))
    {
        return Ok(Arc::clone(process));
    }
    anyhow::ensure!(
        slot.as_ref()
            .is_none_or(|process| process.reaped.load(Ordering::Acquire)),
        "previous Core worker has not exited; replacement prohibited; command was not submitted"
    );
    let mut command = Command::new(std::env::current_exe()?);
    // Transport credentials and account keys remain in the owning host. Only
    // OS loader paths and explicit local inference settings reach the child.
    command.env_clear();
    for name in [
        "PATH",
        "SystemRoot",
        "SystemDrive",
        "USERPROFILE",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for name in [
        "RSRS_DATA_DIR",
        "RSRS_M3_DIR",
        "RSRS_ENGINE",
        "RSRS_ORT_PROFILE",
        "RSRS_CORE_TEST_MODE",
    ] {
        if let Some(value) = crate::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .arg("--core-worker-internal")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().context("start owned Core worker")?;
    let input = child.stdin.take().context("missing Core worker stdin")?;
    let mut output = child.stdout.take().context("missing Core worker stdout")?;
    let pid = child.id();
    let process = Arc::new(Process {
        child: Mutex::new(child),
        input: Mutex::new(Some(input)),
        pending: Mutex::new(HashMap::new()),
        heartbeat: Mutex::new((
            Instant::now(),
            json!({"phase":"starting","host_recovery_required":false}),
            None,
        )),
        retired: AtomicBool::new(false),
        reaped: AtomicBool::new(false),
        pid,
        generation: generation(),
    });
    let reader = Arc::clone(&process);
    std::thread::Builder::new()
        .name("respire-core-replies".into())
        .spawn(move || loop {
            let frame = match read_frame(&mut output) {
                Ok(frame) => frame,
                Err(error) => {
                    if let Err(retire) = reader.retire(&format!("IPC closed: {error:#}")) {
                        eprintln!("Core recovery failed: {retire:#}");
                    }
                    break;
                }
            };
            if reader.retired.load(Ordering::Acquire) {
                break;
            }
            if let Some(status) = frame.get("heartbeat") {
                if let Ok(mut heartbeat) = reader.heartbeat.lock() {
                    let stalled = status["host_recovery_required"].as_bool() == Some(true);
                    heartbeat.0 = Instant::now();
                    heartbeat.1 = status.clone();
                    heartbeat.2 = if stalled {
                        heartbeat.2.or(Some(Instant::now()))
                    } else {
                        None
                    };
                }
            } else if let Some(id) = frame["id"].as_u64() {
                if let Ok(mut pending) = reader.pending.lock() {
                    if let Some(pending) = pending.get(&id) {
                        let _ = pending.sender.send(frame.clone());
                    }
                    if frame.get("callback").is_none() {
                        pending.remove(&id);
                    }
                }
            }
        })
        .map_err(|error| {
            let _ = process.retire("reply reader could not start");
            error
        })?;
    let supervisor = Arc::clone(&process);
    std::thread::Builder::new()
        .name("respire-core-supervisor".into())
        .spawn(move || {
            while !supervisor.retired.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(100));
                let expired = match supervisor.pending.lock() {
                    Ok(pending) => pending
                        .values()
                        .any(|pending| pending.started.elapsed() >= CALL_LIMIT),
                    Err(_) => true,
                };
                let reason = if expired {
                    Some("Core call deadline exceeded")
                } else {
                    match supervisor.heartbeat.lock() {
                        Ok(heartbeat) if heartbeat.0.elapsed() > HEARTBEAT_LIMIT => {
                            Some("worker heartbeat timed out")
                        }
                        Ok(heartbeat)
                            if heartbeat
                                .2
                                .is_some_and(|since| since.elapsed() >= CANCEL_GRACE) =>
                        {
                            Some("native call did not return after cancellation")
                        }
                        Ok(_) => None,
                        Err(_) => Some("worker heartbeat poisoned"),
                    }
                };
                if let Some(reason) = reason {
                    if let Err(error) = supervisor.retire(reason) {
                        eprintln!("Core recovery failed: {error:#}");
                    }
                }
            }
        })
        .map_err(|error| {
            let _ = process.retire("supervisor could not start");
            error
        })?;
    *slot = Some(Arc::clone(&process));
    Ok(process)
}

pub(crate) fn execute(
    operation: &str,
    payload: &Value,
    mut transport: Option<&mut dyn FnMut(&Value) -> Result<Value>>,
) -> Result<Value> {
    let process = process()?;
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let (sender, receiver) = mpsc::channel();
    {
        let mut pending = process
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("Core worker pending poisoned"))?;
        anyhow::ensure!(
            !process.retired.load(Ordering::Acquire),
            "Core worker retired before submission"
        );
        pending.insert(
            id,
            Pending {
                sender,
                started: Instant::now(),
            },
        );
    }
    let root = crate::business::index_root().ok();
    if let Err(error) = process.send(&json!({"id":id,"operation":operation,"payload":payload,
        "index_root":root,"transport":transport.is_some()}))
    {
        let _ = process.retire(&format!("IPC write failed: {error:#}"));
        return Err(error);
    }
    loop {
        let frame = receiver
            .recv()
            .context("Core worker reply unavailable; command was not replayed")?;
        if let Some(request) = frame.get("callback") {
            let result = match transport.as_mut() {
                Some(transport) => transport(request),
                None => Err(anyhow::anyhow!("unexpected Core worker transport callback")),
            };
            let frame = match result {
                Ok(value) => json!({"id":id,"callback_result":value}),
                Err(error) => json!({"id":id,"callback_error":format!("{error:#}")}),
            };
            if let Err(error) = process.send(&frame) {
                let _ = process.retire("host callback IPC failed");
                return Err(error);
            }
        } else if let Some(error) = frame["error"].as_str() {
            bail!("{error}");
        } else {
            anyhow::ensure!(
                !process.retired.load(Ordering::Acquire) && process.generation == generation(),
                "Core worker generation changed; late response discarded; command was not replayed"
            );
            return frame
                .get("result")
                .cloned()
                .context("Core worker result missing");
        }
    }
}

/// Stop before releasing the host's LibraryLock. Replacement never overlaps a retired child.
pub fn shutdown() -> Result<()> {
    STOPPING.store(true, Ordering::Release);
    let process = PROCESS
        .lock()
        .map_err(|_| anyhow::anyhow!("Core worker state poisoned"))?
        .clone();
    if let Some(process) = process {
        process.retire("host shutdown")?;
    }
    Ok(())
}

type CallbackMap = Arc<Mutex<HashMap<u64, mpsc::Sender<Value>>>>;

/// Hidden binary entry. No App, profile migration, store, or LibraryLock is opened.
pub fn run() -> Result<()> {
    let output = Arc::new(Mutex::new(std::io::stdout()));
    let callbacks: CallbackMap = Arc::new(Mutex::new(HashMap::new()));
    let (ordinary_tx, ordinary_rx) = mpsc::channel::<Value>();
    let ordinary_rx = Arc::new(Mutex::new(ordinary_rx));
    let (background_tx, background_rx) = mpsc::channel::<Value>();
    let background_rx = Arc::new(Mutex::new(background_rx));
    let count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    for index in 0..=count {
        let receiver = if index == count {
            Arc::clone(&background_rx)
        } else {
            Arc::clone(&ordinary_rx)
        };
        let output = Arc::clone(&output);
        let callbacks = Arc::clone(&callbacks);
        std::thread::Builder::new()
            .name(format!("respire-core-{index}"))
            .stack_size(16 * 1024 * 1024)
            .spawn(move || loop {
                let frame = match receiver.lock() {
                    Ok(receiver) => receiver.recv(),
                    Err(_) => break,
                };
                let Ok(frame) = frame else {
                    break;
                };
                let id = frame["id"].as_u64().unwrap_or(u64::MAX);
                let result = (|| -> Result<Value> {
                    if let Some(root) = frame["index_root"].as_str() {
                        crate::business::set_index_root(std::path::Path::new(root))?;
                    }
                    let operation = frame["operation"]
                        .as_str()
                        .context("Core worker operation missing")?;
                    #[cfg(feature = "native-fault-tests")]
                    if operation == "test_worker_hold" {
                        loop {
                            std::thread::park();
                        }
                    }
                    let payload = frame["payload"].clone();
                    let mut callback = |request: &Value| -> Result<Value> {
                        let (sender, receiver) = mpsc::channel();
                        callbacks
                            .lock()
                            .map_err(|_| anyhow::anyhow!("Core worker callbacks poisoned"))?
                            .insert(id, sender);
                        write_frame(
                            &mut *output
                                .lock()
                                .map_err(|_| anyhow::anyhow!("Core worker output poisoned"))?,
                            &json!({"id":id,"callback":request}),
                        )?;
                        let response = receiver
                            .recv()
                            .context("host transport callback unavailable")?;
                        if let Some(error) = response["callback_error"].as_str() {
                            bail!("{error}");
                        }
                        response
                            .get("callback_result")
                            .cloned()
                            .context("host transport callback result missing")
                    };
                    let result = if frame["transport"].as_bool() == Some(true) {
                        crate::business::execute_with_transport::<Value>(
                            operation,
                            payload,
                            &mut callback,
                        )
                    } else {
                        crate::business::execute::<Value>(operation, payload)
                    }?;
                    if operation == "engine_control" && frame["payload"]["action"] == "reset" {
                        crate::host::reset_model_cache()?;
                    }
                    Ok(result)
                })();
                let response = match result {
                    Ok(value) => json!({"id":id,"result":value}),
                    Err(error) => json!({"id":id,"error":format!("{error:#}")}),
                };
                if let Ok(mut output) = output.lock() {
                    if write_frame(&mut *output, &response).is_err() {
                        break;
                    }
                }
            })?;
    }
    let heartbeat_output = Arc::clone(&output);
    std::thread::Builder::new()
        .name("respire-core-heartbeat".into())
        .spawn(move || {
            let result = crate::Core::new();
            let Ok(mut core) = result else {
                return;
            };
            loop {
                let status = core
                    .call("engine_control", json!({"action":"inference_status"}))
                    .and_then(|mut status| {
                        let diagnostics = crate::host::provider_diagnostics()?;
                        if !diagnostics.is_empty() {
                            status["provider_registration_errors"] = json!(diagnostics);
                        }
                        Ok(status)
                    });
                match (status, heartbeat_output.lock()) {
                    (Ok(status), Ok(mut output)) => {
                        if write_frame(&mut *output, &json!({"heartbeat":status})).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        })?;
    let mut input = std::io::stdin();
    loop {
        let frame = read_frame(&mut input)?;
        let id = frame["id"]
            .as_u64()
            .context("Core worker request ID missing")?;
        if frame.get("callback_result").is_some() || frame.get("callback_error").is_some() {
            if let Some(sender) = callbacks
                .lock()
                .map_err(|_| anyhow::anyhow!("Core worker callbacks poisoned"))?
                .remove(&id)
            {
                let _ = sender.send(frame);
            }
        } else if frame["operation"] == "prepare" {
            background_tx.send(frame)?;
        } else {
            ordinary_tx.send(frame)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_frames_preserve_values_and_reject_truncation() {
        let value = json!({"id":9,"result":{"text":"synthetic unicode fixture 中文"}});
        let mut bytes = Vec::new();
        assert!(write_frame(&mut bytes, &value).is_ok());
        assert_eq!(read_frame(&mut bytes.as_slice()).ok(), Some(value));
        bytes.pop();
        assert!(read_frame(&mut bytes.as_slice()).is_err());
        assert!(read_frame(&mut [0u8; 8].as_slice()).is_err());
    }
}

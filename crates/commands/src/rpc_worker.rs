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

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use clap::Parser;
use serde_json::{json, Value};

use crate::cli_def::{Cli, Command, SessionCommand};

pub const PROTOCOL_V: u32 = 1;

pub static WEB_URL: Mutex<String> = Mutex::new(String::new());

pub fn is_status(args: &[String]) -> bool {
    command_name(args) == Some("status")
}

/// Viewing account/configuration state must not invalidate ongoing sync or indexing.
pub fn is_context_query(args: &[String]) -> bool {
    if !matches!(
        command_name(args),
        Some("account" | "space" | "config" | "agent-config" | "session")
    ) {
        return false;
    }
    let Ok(cli) =
        Cli::try_parse_from(std::iter::once("rsrs".to_owned()).chain(args.iter().cloned()))
    else {
        return false;
    };
    match cli.command {
        Some(Command::Account { action, .. }) => action == "list",
        Some(Command::Space { action, .. }) => matches!(action.as_str(), "list" | "members"),
        Some(Command::Config {
            data_dir: None,
            addr: None,
            autosync: None,
            cure_auto: None,
            rpc_parallelism: None,
        })
        | Some(Command::AgentConfig { set: None })
        | Some(Command::Session {
            command: SessionCommand::List,
        }) => true,
        _ => false,
    }
}

pub const GLOBAL_VALUE_FLAGS: [&str; 2] = ["--progress-id", "--model-task-id"];

// Keep client timeout classification and server routing on the same argv rules.
// A tracked request ID is a value even when it spells a command such as sync.
pub fn command_words(args: &[String]) -> impl Iterator<Item = &str> + '_ {
    let mut values = args.iter();
    std::iter::from_fn(move || {
        while let Some(arg) = values.next() {
            if GLOBAL_VALUE_FLAGS.contains(&arg.as_str()) {
                let _ = values.next();
            } else if !arg.starts_with('-') {
                return Some(arg.as_str());
            }
        }
        None
    })
}

pub fn command_name(args: &[String]) -> Option<&str> {
    command_words(args).next()
}

pub fn diary_lexical_mode(args: &[String]) -> bool {
    // Values after -- are literal queries, never runtime routing flags.
    let options = &args[..args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len())];
    let modes: Vec<&str> = options
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| {
            if arg == "--mode" {
                Some(options.get(index + 1).map(String::as_str).unwrap_or(""))
            } else {
                arg.strip_prefix("--mode=")
            }
        })
        .collect();
    modes == ["lexical"]
}

pub fn needs_inference(args: &[String]) -> bool {
    matches!(
        command_name(args),
        Some("remember" | "recall" | "related" | "reembed" | "classify" | "update")
    ) || (command_name(args) == Some("diary-search") && !diary_lexical_mode(args))
        || (command_name(args) == Some("model")
            && args
                .iter()
                .any(|arg| matches!(arg.as_str(), "probe" | "load")))
}

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

// Both publication and receipt lookup reject linked or unbounded local records.
fn endpoint_record_bytes(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(!metadata.file_type().is_symlink(), "endpoint path contains a symlink");
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "endpoint path contains a reparse point");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 65536, "invalid endpoint/receipt file");
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "endpoint/receipt file is too large");
    Ok(Some(bytes))
}

#[derive(Clone)]
pub(crate) struct EndpointPublication {
    path: PathBuf,
    bytes: Vec<u8>,
    identity: Value,
    receipt: PathBuf,
    receipt_bytes: Option<Vec<u8>>,
}

impl EndpointPublication {
    pub(crate) fn revoke_failed_start(
        &self,
        owner: &respire_app::lock::LibraryLock,
    ) -> Result<()> {
        let url = self.identity["url"].as_str().context("published endpoint URL missing")?;
        let (identity, receipt, receipt_bytes) = endpoint_body(url)?;
        self.revoke_matching(owner, &endpoint_path(), &identity, &receipt, &receipt_bytes)
    }

    fn revoke_matching(
        &self,
        owner: &respire_app::lock::LibraryLock,
        path: &std::path::Path,
        identity: &Value,
        receipt: &std::path::Path,
        receipt_bytes: &Option<Vec<u8>>,
    ) -> Result<()> {
        let directory = self.path.parent().context("published endpoint parent missing")?;
        anyhow::ensure!(owner.protects(directory)?, "startup endpoint ownership lock changed");
        anyhow::ensure!(
            path == self.path && receipt == self.receipt && identity == &self.identity
                && receipt_bytes == &self.receipt_bytes,
            "startup endpoint path/identity/launch receipt changed; record retained"
        );
        anyhow::ensure!(
            endpoint_record_bytes(&self.receipt)? == self.receipt_bytes
                && endpoint_record_bytes(&self.path)?.as_deref() == Some(self.bytes.as_slice()),
            "startup endpoint or launch receipt bytes changed; record retained"
        );
        // Only the live publisher can revoke this exact publication, never a dead owner.
        std::fs::remove_file(&self.path)?;
        respire_spawn::durable::sync_directory(directory)?;
        Ok(())
    }
}

/// Revoke only the live publisher's current generation after admission is shut
/// down. Unlike failed startup, normal serving may have republished its scope.
/// Never derive authority from the bytes found in the endpoint file.
pub(crate) fn revoke_current_endpoint(
    owner: &respire_app::lock::LibraryLock,
    url: &str,
) -> Result<()> {
    let path = endpoint_path();
    let (identity, receipt, receipt_bytes) = endpoint_body(url)?;
    let expected = current_publication(path.clone(), identity, receipt, receipt_bytes)?;
    // Re-read actual identity and the claimed receipt before the final byte CAS.
    let (identity, receipt, receipt_bytes) = endpoint_body(url)?;
    expected.revoke_matching(owner, &path, &identity, &receipt, &receipt_bytes)
}

fn current_publication(path: PathBuf, identity: Value, receipt: PathBuf,
    receipt_bytes: Option<Vec<u8>>) -> Result<EndpointPublication> {
    let bytes = serde_json::to_vec_pretty(&identity)?;
    Ok(EndpointPublication { path, bytes, identity, receipt, receipt_bytes })
}

fn endpoint_body(url: &str) -> Result<(Value, PathBuf, Option<Vec<u8>>)> {
    let dir = runtime_dir();
    let mut body = crate::rpc_serve::endpoint_identity(url)?;
    let instance = body["instance_id"].as_str().context("endpoint instance missing")?;
    let nonce = uuid::Uuid::parse_str(instance)?;
    anyhow::ensure!(nonce.get_version_num() == 4 && nonce.to_string() == instance, "invalid endpoint instance");
    let receipt = dir.join("autostart/launch").join(format!("launch-{instance}.claimed"));
    let receipt_bytes = endpoint_record_bytes(&receipt)?;
    if let Some(bytes) = receipt_bytes.as_ref() {
        body["launch_receipt_sha256"] = json!(format!("{:x}", Sha256::digest(bytes)));
    }
    Ok((body, receipt, receipt_bytes))
}

pub fn write_endpoint(url: &str) -> Result<()> {
    publish_endpoint(url).map(|_| ())
}

pub(crate) fn publish_endpoint(url: &str) -> Result<EndpointPublication> {
    let dir = runtime_dir();
    let (body, receipt, receipt_bytes) = endpoint_body(url)?;
    let bytes = serde_json::to_vec_pretty(&body)?;
    let target = endpoint_path();
    let previous = endpoint_record_bytes(&target)?;
    std::fs::create_dir_all(&dir)?;
    let temporary = dir.join(format!(".endpoint-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        anyhow::ensure!(endpoint_record_bytes(&target)? == previous, "endpoint changed before publication");
        respire_spawn::durable::replace_file(&temporary, &target)?;
        Ok(())
    })();
    if result.is_err() && temporary.try_exists()? {
        std::fs::remove_file(&temporary)?;
    }
    result?;
    Ok(EndpointPublication { path: target, bytes, identity: body, receipt, receipt_bytes })
}

pub fn endpoint_pid() -> Option<u32> {
    let text = std::fs::read_to_string(endpoint_path()).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    data.get("pid")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
}

#[cfg(test)]
mod endpoint_publication_tests {
    use super::*;

    #[test]
    fn clean_stop_uses_current_generation_and_rejects_changed_evidence() -> Result<()> {
        for change in ["none", "old-generation", "foreign-instance", "bytes", "claim", "owner"] {
            let directory = tempfile::tempdir()?;
            let other = tempfile::tempdir()?;
            let owner = respire_app::lock::LibraryLock::acquire(directory.path(), Duration::from_secs(1))?;
            let wrong_owner = respire_app::lock::LibraryLock::acquire(other.path(), Duration::from_secs(1))?;
            let path = directory.path().join("endpoint.json");
            let receipt = directory.path().join("launch.claimed");
            // These expected values model current process state, not parsed disk input.
            let current = json!({"pid":std::process::id(),"instance_id":"same-live-publisher","generation":2});
            let claimed = Some(b"original claimed receipt".to_vec());
            std::fs::write(&receipt, claimed.as_ref().context("synthetic claim absent")?)?;
            std::fs::write(&path, serde_json::to_vec_pretty(&current)?)?;
            let expected = current_publication(path.clone(),current.clone(),receipt.clone(),claimed.clone())?;
            match change {
                "old-generation" => {
                    let mut old=current.clone(); old["generation"]=json!(1);
                    std::fs::write(&path,serde_json::to_vec_pretty(&old)?)?;
                }
                "foreign-instance" => {
                    let mut foreign=current.clone(); foreign["instance_id"]=json!("foreign");
                    std::fs::write(&path,serde_json::to_vec_pretty(&foreign)?)?;
                }
                "bytes" => std::fs::write(&path,b"foreign bytes")?,
                "claim" => std::fs::write(&receipt,b"changed claim")?,
                _ => {}
            }
            let before=endpoint_record_bytes(&path)?;
            let before_claim=endpoint_record_bytes(&receipt)?;
            let result=expected.revoke_matching(if change == "owner" { &wrong_owner } else { &owner },
                &path,&current,&receipt,&claimed);
            if change == "none" {
                result?;
                assert!(!path.try_exists()?);
            } else {
                assert!(result.is_err(),"accepted changed {change}");
                assert_eq!(endpoint_record_bytes(&path)?,before);
            }
            assert_eq!(endpoint_record_bytes(&receipt)?,before_claim);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn clean_stop_does_not_follow_endpoint_symlink() -> Result<()> {
        let directory=tempfile::tempdir()?;
        let owner=respire_app::lock::LibraryLock::acquire(directory.path(),Duration::from_secs(1))?;
        let target=directory.path().join("foreign.json");
        let path=directory.path().join("endpoint.json");
        let receipt=directory.path().join("launch.claimed");
        let identity=json!({"generation":2});
        let bytes=serde_json::to_vec_pretty(&identity)?;
        std::fs::write(&target,&bytes)?;
        std::os::unix::fs::symlink(&target,&path)?;
        let expected=current_publication(path.clone(),identity.clone(),receipt.clone(),None)?;
        assert!(expected.revoke_matching(&owner,&path,&identity,&receipt,&None).is_err());
        assert_eq!(std::fs::read(target)?,bytes);
        assert!(std::fs::symlink_metadata(path)?.file_type().is_symlink());
        Ok(())
    }

    #[test]
    fn failed_start_revokes_only_unchanged_owned_publication() -> Result<()> {
        for change in ["none", "no-claim", "bytes", "claim", "missing-claim", "new-claim", "path", "receipt-path", "lock", "missing"] {
            let directory = tempfile::tempdir()?;
            let other = tempfile::tempdir()?;
            let owner = respire_app::lock::LibraryLock::acquire(directory.path(), Duration::from_secs(1))?;
            let wrong_owner = respire_app::lock::LibraryLock::acquire(other.path(), Duration::from_secs(1))?;
            let path = directory.path().join("endpoint.json");
            let receipt = directory.path().join("launch.claimed");
            let identity = json!({"pid": std::process::id(), "instance_id": "owned-startup"});
            let bytes = serde_json::to_vec(&identity)?;
            let receipt_bytes = if matches!(change, "no-claim" | "new-claim") {
                None
            } else {
                Some(b"consumed; never reusable".to_vec())
            };
            std::fs::write(&path, &bytes)?;
            if let Some(bytes) = receipt_bytes.as_ref() {
                std::fs::write(&receipt, bytes)?;
            }
            let published = EndpointPublication {
                path: path.clone(), bytes, identity: identity.clone(),
                receipt: receipt.clone(), receipt_bytes: receipt_bytes.clone(),
            };
            match change {
                "bytes" => std::fs::write(&path, b"foreign endpoint")?,
                "claim" | "new-claim" => std::fs::write(&receipt, b"changed claim")?,
                "missing-claim" => std::fs::remove_file(&receipt)?,
                "missing" => std::fs::remove_file(&path)?,
                _ => {}
            }
            let before_endpoint = endpoint_record_bytes(&path)?;
            let before_claim = endpoint_record_bytes(&receipt)?;
            let result = published.revoke_matching(
                if change == "lock" { &wrong_owner } else { &owner },
                if change == "path" { &receipt } else { &path },
                &identity,
                if change == "receipt-path" { &path } else { &receipt },
                &receipt_bytes,
            );
            if matches!(change, "none" | "no-claim") {
                result?;
                assert!(!path.try_exists()?);
            } else {
                assert!(result.is_err(), "accepted changed {change}");
                assert_eq!(endpoint_record_bytes(&path)?, before_endpoint);
            }
            assert_eq!(endpoint_record_bytes(&receipt)?, before_claim);
        }
        Ok(())
    }

    #[test]
    fn failed_start_retains_endpoint_on_any_identity_change() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let owner = respire_app::lock::LibraryLock::acquire(directory.path(), Duration::from_secs(1))?;
        let path = directory.path().join("endpoint.json");
        let receipt = directory.path().join("launch.claimed");
        let identity = json!({
            "schema_version": 2, "server": "respire", "v": PROTOCOL_V,
            "pid": std::process::id(), "bin": "test", "url": "http://127.0.0.1:1",
            "runtime_version": "test", "exe": "image", "image_path": "image",
            "image_sha256": "digest", "installation_root": "root", "data_dir": "profile",
            "installation_id": "installation", "instance_id": "instance",
            "process_start_id": "birth", "account_id": "account", "generation": 1,
            "managed_id": null, "launch_receipt_sha256": "claim-digest"
        });
        let bytes = serde_json::to_vec(&identity)?;
        std::fs::write(&path, &bytes)?;
        let published = EndpointPublication {
            path: path.clone(), bytes: bytes.clone(), identity: identity.clone(),
            receipt: receipt.clone(), receipt_bytes: None,
        };
        for key in identity.as_object().context("identity object")?.keys() {
            let mut changed = identity.clone();
            changed[key] = json!("changed");
            assert!(published.revoke_matching(&owner, &path, &changed, &receipt, &None).is_err(),
                "accepted changed {key}");
            assert_eq!(std::fs::read(&path)?, bytes);
        }
        Ok(())
    }
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
});

pub struct IndexWork {
    pub(crate) requested: bool,
    pub(crate) state: &'static str,
    pub(crate) error: Option<String>,
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

/// Shared with standalone startup checks so grant and serving generations match.
pub fn generation_on_wire(generation: usize) -> u64 {
    generation.saturating_add(1).max(1) as u64
}

pub(crate) fn wire_generation() -> u64 {
    generation_on_wire(GENERATION.load(Ordering::Acquire))
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
    crate::rpc_serve::advance_generation(generation)?;
    // The sync scheduler and resident catalog live beside the dispatch loop.
    crate::rpc_serve::context_changed();
    Ok(())
}

pub fn check_sync_context(generation: usize) -> Result<()> {
    respire_app::service::validate_client_config()?;
    respire_app::service::ensure_runtime_profile()?;
    if GENERATION.load(Ordering::Acquire) != generation {
        bail!("sync context changed; pending work kept locally");
    }
    let retained = crate::rpc_serve::active_execution_retained(generation)?;
    anyhow::ensure!(
        retained || !crate::host_hooks::background_paused(),
        "runtime maintenance pauses background work"
    );
    if !retained && STOPPING.load(Ordering::Acquire) {
        bail!("runtime is stopping");
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
    check_sync_context(generation)?;
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
        if !crate::rpc_serve::store_ready() || respire_app::service::service_paused() || crate::host_hooks::background_paused() {
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
            let pending = store.index_missing(&model)?;
            let diary_pending = respire_app::diary::needs_rebuild(&store)?;
            // An indexed library still needs the CPU container for its next query.
            // Missing assets are reported; only the CLI may install them.
            let active_profile = store.active_selection()?;
            let cpu_upgrade = active_profile.is_none()
                && model == "m3"
                && respire_app::MemoryTransport::count(&store)? > 0
                && crate::model_assets::cpu_model_preparation_needed()?;
            if !pending && !diary_pending && !cpu_upgrade {
                return Ok(true);
            }
            let Some(_operation) = crate::model_progress::Operation::try_begin_background_index()?
            else {
                return Ok(false);
            };
            index_yield_to_foreground(generation)?;
            if diary_pending
                && !pending
                && !cpu_upgrade
                && respire_app::diary::clear_if_empty(&store, |action| {
                    diary_commit(generation, action)
                })?
            {
                return Ok(true);
            }
            if let Some(selection) = active_profile.as_ref() {
                crate::model_progress::update("verify", &selection.model, 0, None)?;
                crate::model_assets::verify_selection_assets(selection)?;
            } else if model == "m3" {
                crate::model_progress::update("verify", "BGE-M3", 0, None)?;
                crate::model_assets::verify_m3_assets()?;
            }
            check_sync_context(generation)?;
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
                work.state = "paused";
                work.requested = false;
                work.error = Some(format!("{error:#}"));
            }
            Err(error) if generation != GENERATION.load(Ordering::Acquire) => {
                model_wait_started = None;
                work.state = "scheduled";
                work.requested = true;
                work.error = Some(format!("{error:#}"));
            }
            Err(error)
                if error
                    .downcast_ref::<crate::model_assets::AssetsUnavailable>()
                    .is_some() =>
            {
                model_wait_started = None;
                work.state = "missing";
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

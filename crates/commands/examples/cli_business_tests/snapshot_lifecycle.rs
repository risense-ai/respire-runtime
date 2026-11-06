//! Public snapshot commands with an isolated synthetic vault, not user data.
//! Uses the CI-provided standalone Runtime; not release artifact acceptance.
use anyhow::{Context, Result};
use respire_app as respire;
use respire::memory::{crypto, search::HashingEmbedder};
use respire::transport::local::LocalStore;
use respire::{MemoryEngine, MemoryEntry, MemoryTransport, SessionKeys};
use serde_json::{json, Value};
use std::{
    io::{Read, Seek, SeekFrom},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use super::support;

struct Fixture {
    cli: std::path::PathBuf,
    runtime: Option<std::process::Child>,
    runtime_bin: std::path::PathBuf,
    root: tempfile::TempDir,
    port: u16,
    secret: String,
}
impl Fixture {
    fn new() -> Result<Self> {
        let cli = support::cli_bin()?;
        let runtime_bin = std::path::PathBuf::from(
            std::env::var_os("RSRS_RUNTIME_BIN")
                .context("supply RSRS_RUNTIME_BIN with the official standalone Runtime fixture")?,
        ).canonicalize()?;
        anyhow::ensure!(runtime_bin.is_file(), "standalone Runtime fixture missing");
        anyhow::ensure!(
            runtime_bin != cli,
            "CLI shim cannot substitute for the standalone Runtime fixture"
        );
        let root = tempfile::tempdir()?;
        support::install_runtime_fixture(root.path())?;
        let runtime_bin = root.path().join("runtime")
            .join(runtime_bin.parent().and_then(std::path::Path::file_name)
                .context("Runtime fixture version directory missing")?)
            .join(runtime_bin.file_name().context("Runtime fixture binary name missing")?)
            .canonicalize()?;
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
            .local_addr()?
            .port();
        let secret = format!("A3-{}", "07".repeat(18));
        let salt = "08".repeat(16);
        let kek = crypto::derive_rsrs_kek(&secret, &salt)?;
        let (nonce, wrapped) = crypto::wrap_key(&[9; 32], &kek)?;
        std::fs::write(
            root.path().join("session.json"),
            serde_json::to_vec(
                &json!({"user":"snapshot-fixture","vault_version":4,"kdf_salt":salt,"wrapped_urk":format!("{}{wrapped}",crypto::RSRS_PREFIX),"urk_nonce":nonce}),
            )?,
        )?;
        let mut fixture = Self {
            cli,
            runtime: None,
            runtime_bin,
            root,
            port,
            secret,
        };
        let entry = MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            id: "12345678-1234-4234-8234-123456789abc".into(),
            user: "snapshot-fixture".into(),
            title: "synthetic snapshot".into(),
            content: "synthetic body".into(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            kind: respire::Kind::Context,
            tags: Vec::new(),
            computer: "fixture".into(),
            project: "fixture".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            emotion: 0.0,
            parent_id: String::new(),
            importance: "normal".into(),
            device: "fixture".into(),
            modified_by: "fixture".into(),
        };
        let _defer = respire::core_sdk::defer_indexing();
        let stored = MemoryEngine::seal(
            &SessionKeys::from_urk([9; 32])?,
            &HashingEmbedder::default(),
            &entry,
            "snapshot-fixture",
        )?;
        assert!(LocalStore::open(&fixture.root.path().join("rsrs.db"))?.put(&stored)?);
        fixture.start_runtime()?;
        Ok(fixture)
    }
    fn start_runtime(&mut self) -> Result<()> {
        let runtime_stderr = self.root.path().join("runtime-stderr.log");
        let ready_stdout = self.root.path().join("ready-stdout.log");
        let ready_stderr = self.root.path().join("ready-stderr.log");
        let runtime = self.runtime_command()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&runtime_stderr)?))
            .spawn()?;
        self.runtime = Some(runtime);
        let began = Instant::now();
        loop {
            if let Some(status) = self.runtime.as_mut().context("fixture runtime missing")?.try_wait()? {
                anyhow::bail!("runtime exited during fixture startup: {status}; stderr={}",
                    std::fs::read_to_string(&runtime_stderr)?);
            }
            let mut ready = self.command(&["--client-only", "--json", "status"])
                .stdin(Stdio::null())
                .stdout(Stdio::from(std::fs::File::create(&ready_stdout)?))
                .stderr(Stdio::from(std::fs::File::create(&ready_stderr)?))
                .spawn()?;
            // A single RPC must not outlive the fixture's existing startup budget.
            let status = loop {
                if let Some(status) = ready.try_wait()? {
                    break Some(status);
                }
                if began.elapsed() > Duration::from_secs(15) {
                    let _ = ready.kill();
                    let _ = ready.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            if status.is_some_and(|status| status.success()) {
                return Ok(());
            }
            if began.elapsed() > Duration::from_secs(15) {
                if let Some(mut runtime) = self.runtime.take() {
                    let _ = runtime.kill();
                    let _ = runtime.wait();
                }
                anyhow::bail!("runtime did not become ready; probe={status:?}; stdout={}; stderr={}; runtime stderr={}",
                    std::fs::read_to_string(&ready_stdout)?,
                    std::fs::read_to_string(&ready_stderr)?,
                    std::fs::read_to_string(&runtime_stderr)?);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn stop_runtime(&mut self) -> Result<()> {
        let _ = self.run(&["--json", "--runtime-internal", "--stop"]);
        if let Some(mut runtime) = self.runtime.take() {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match runtime.try_wait()? {
                    Some(status) => {
                        let _ = runtime.wait();
                        if !status.success() {
                            anyhow::bail!("runtime exited unsuccessfully during cleanup: {status}");
                        }
                        return Ok(());
                    }
                    None if Instant::now() >= deadline => {
                        runtime.kill()?;
                        runtime.wait()?;
                        anyhow::bail!("runtime did not stop after its stop acknowledgement");
                    }
                    None => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        }
        Ok(())
    }
    fn command(&self, args: &[&str]) -> Command {
        self.command_for(&self.cli, args)
    }
    fn runtime_command(&self) -> Command {
        let mut command = self.command_for(&self.runtime_bin, &["serve"]);
        command.env("RSRS_PASS", &self.secret);
        command
    }
    fn command_for(&self, executable: &std::path::Path, args: &[&str]) -> Command {
        let mut command = Command::new(executable);
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|n| {
                n.starts_with("RSRS_") || n.starts_with("ONEMEMORY_") || n.starts_with("RESPIRE_")
            }) {
                command.env_remove(name);
            }
        }
        command
            .args(args)
            .current_dir(self.root.path())
            .env("HOME", self.root.path())
            .env("USERPROFILE", self.root.path())
            .env("RSRS_DATA_DIR", self.root.path())
            .env("RSRS_RPC_PORT", self.port.to_string())
            .env("RSRS_SUPER", &self.secret)
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env("RSRS_RUNTIME_BIN", &self.runtime_bin)
            .env("RSRS_LANG", "en")
            .env("RSRS_MIRROR", "http://127.0.0.1:9")
            .env("RSRS_CPU_ORT_MIRROR", "http://127.0.0.1:9");
        command
    }
    fn run(&self, args: &[&str]) -> Result<(bool, Value)> {
        self.run_feedback(args, None)
    }
    fn run_feedback(&self, args: &[&str], feedback: Option<&str>) -> Result<(bool, Value)> {
        let mut stdout = tempfile::tempfile()?;
        let mut stderr = tempfile::tempfile()?;
        let mut command = self.command(args);
        if let Some(value) = feedback {
            command.env("RSRS_FEEDBACK", value);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .spawn()?;
        let began = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if began.elapsed() > Duration::from_secs(90) {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("snapshot fixture command timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        stdout.seek(SeekFrom::Start(0))?;
        stderr.seek(SeekFrom::Start(0))?;
        let mut text = String::new();
        stdout.read_to_string(&mut text)?;
        let value = serde_json::from_str(&text)
            .context("snapshot command did not emit a single JSON envelope")?;
        Ok((status.success(), value))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // The unique port and profile are ours. Check the profile before lifecycle cleanup.
        if let Ok((true, status)) = self.run(&["--json", "--runtime-internal", "--status"]) {
            if status["summary"]["data_dir"]
                .as_str()
                .is_some_and(|root| std::path::Path::new(root) == self.root.path())
            {
                let _ = self.run(&["--json", "--runtime-internal", "--stop"]);
            }
        }
        let _ = self.stop_runtime();
    }
}

#[test]
fn public_snapshot_restore_reopens_runtime_and_keeps_sync_quarantined() -> Result<()> {
    let fixture = Fixture::new()?;
    let (ok, created) = fixture.run(&[
        "--direct",
        "--json",
        "snapshot",
        "create",
        "--note",
        "synthetic regression",
    ])?;
    anyhow::ensure!(ok, "snapshot create failed: {}", created["errors"]);
    let id = created["details"]["id"].as_str().context("snapshot id")?;
    let (ok, listed) = fixture.run(&["--direct", "--json", "snapshot", "list"])?;
    assert!(ok);
    assert_eq!(
        listed["details"]["snapshots"]
            .as_array()
            .context("list")?
            .len(),
        1
    );
    let (_, before) = fixture.run(&["--json", "status"])?;
    let (ok, _) = fixture.run(&[
        "--client-only",
        "--json",
        "snapshot",
        "restore",
        id,
        "--confirm",
    ])?;
    assert!(!ok, "sandbox restored database");
    let (ok, restored) = fixture.run(&["--json", "snapshot", "restore", id, "--confirm"])?;
    anyhow::ensure!(ok, "snapshot restore failed: {}", restored["errors"]);
    assert_eq!(restored["summary"]["sync_quarantined"], true);
    assert_eq!(restored["summary"]["cloud_rollback"], false);
    assert!(restored["details"]["before_restore"]
        .as_str()
        .is_some_and(|v| v != id));
    let (ok, status) = fixture.run(&["--client-only", "--json", "status"])?;
    assert!(ok);
    assert_eq!(
        status["summary"]["local_alive"],
        before["summary"]["local_alive"]
    );
    let (ok, failed) = fixture.run(&["--client-only", "--json", "sync"])?;
    assert!(!ok);
    assert!(failed["errors"].to_string().contains("quarantined"));
    let (ok, _) = fixture.run(&[
        "--client-only",
        "--json",
        "snapshot",
        "resume-sync",
        "--reviewed-revision",
        "stale",
    ])?;
    assert!(!ok);
    let (ok, revision) = fixture.run(&["--client-only", "--json", "memory-revision"])?;
    assert!(ok);
    let token = revision["summary"]["revision"]
        .as_str()
        .context("revision token")?;
    let (ok, resumed) = fixture.run(&[
        "--client-only",
        "--json",
        "snapshot",
        "resume-sync",
        "--reviewed-revision",
        token,
    ])?;
    anyhow::ensure!(ok, "resume failed: {}", resumed["errors"]);
    assert_eq!(resumed["details"]["sync_quarantined"], false);
    Ok(())
}

fn wait_bounded(mut child: std::process::Child) -> Result<std::process::Output> {
    let began = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if began.elapsed() > Duration::from_secs(90) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("owned snapshot subprocess timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn concurrent_host_recover_cannot_interleave_with_restore_commit() -> Result<()> {
    let fixture = Fixture::new()?;
    let (ok, created) = fixture.run(&["--direct", "--json", "snapshot", "create"])?;
    assert!(ok);
    let id = created["details"]["id"].as_str().context("snapshot id")?;
    let primary = fixture
        .command(&["--json", "snapshot", "restore", id, "--confirm"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let competing = fixture
        .command(&["--json", "snapshot", "recover", "--confirm"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let primary = wait_bounded(primary)?;
    let competing = wait_bounded(competing)?;
    anyhow::ensure!(
        primary.status.success(),
        "restore failed under lifecycle contention: {}",
        String::from_utf8_lossy(&primary.stdout)
    );
    assert!(
        !competing.status.success(),
        "recover interleaved with the successful restore"
    );
    let (ok, status) = fixture.run(&["--client-only", "--json", "status"])?;
    assert!(ok);
    assert_eq!(status["summary"]["local_alive"], 1);
    assert!(!fixture
        .root
        .path()
        .join(".snapshot-maintenance.json")
        .exists());
    assert!(!fixture.root.path().join(".snapshot-recovery.json").exists());
    Ok(())
}

#[test]
fn staged_store_open_failure_cannot_pass_boot_readiness_and_is_recoverable() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let (ok, created) = fixture.run(&["--direct", "--json", "snapshot", "create"])?;
    assert!(ok);
    let id = created["details"]["id"].as_str().context("snapshot id")?;
    fixture.stop_runtime()?;
    {
        // Diagnostics: if the fixture lock is already held at this point,
        // print the holders so the CI log identifies the leaking process.
        let ownership = match respire_app::lock::LibraryLock::acquire(
            fixture.root.path(),
            Duration::from_secs(1),
        ) {
            Ok(ownership) => ownership,
            Err(error) => {
                let lock_path = fixture.root.path().join("lock.db");
                let lock_target = std::fs::canonicalize(&lock_path)
                    .map(|path| path.to_string_lossy().to_string());
                eprintln!("DIAG staged: lock held; scanning fd holders of {lock_path:?}");
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        let pid = entry.file_name().to_string_lossy().to_string();
                        if !pid.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }
                        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                            continue;
                        };
                        for fd in fds.flatten() {
                            let Ok(target) = std::fs::read_link(fd.path()) else {
                                continue;
                            };
                            let target = target.to_string_lossy().to_string();
                            let matches = match &lock_target {
                                Ok(canonical) => target == *canonical,
                                Err(_) => target.ends_with("lock.db"),
                            };
                            if matches {
                                let cmd = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                                    .map(|cmd| cmd.replace('\0', " "))
                                    .unwrap_or_default();
                                let env = std::fs::read_to_string(format!("/proc/{pid}/environ"))
                                    .map(|env| {
                                        env.split('\0')
                                            .find(|entry| entry.starts_with("RSRS_DATA_DIR="))
                                            .unwrap_or("RSRS_DATA_DIR=<unset>")
                                            .to_owned()
                                    })
                                    .unwrap_or_default();
                                eprintln!("DIAG staged holder pid={pid} fd={:?} target={target} cmd={cmd} {env}", fd.file_name());
                            }
                        }
                    }
                }
                eprintln!("DIAG staged create child error: {error:#}");
                return Err(error);
            }
        };
        respire_app::snapshot::restore_locked(
            fixture.root.path(),
            "snapshot-fixture",
            &SessionKeys::from_urk([9; 32])?,
            id,
            &ownership,
        )?;
        std::fs::write(
            fixture.root.path().join("rsrs.db"),
            b"controlled invalid staged database",
        )?;
    }
    // Split-era semantics: the runtime either exits with a boot failure
    // (legacy combined behavior) or recovers in place and keeps serving.
    // Both are acceptable; a broken staged store must never report ready
    // without recovery. Afterwards the serving child is reaped so the
    // library lock is released for the following tests.
    let mut serving = fixture
        .runtime_command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stderr = serving.stderr.take().context("serve stderr")?;
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                eprintln!("DIAG staged serve: {line}");
            }
        });
    }
    let recovered_at = Instant::now();
    let mut exited_failed = false;
    let mut exited = false;
    loop {
        if let Some(status) = serving.try_wait()? {
            let _ = serving.wait();
            exited_failed = !status.success();
            exited = true;
            break;
        }
        let healthy = std::fs::metadata(fixture.root.path().join("rsrs.db"))
            .map(|meta| meta.len() > 0)
            .unwrap_or(false)
            && !fixture.root.path().join(".snapshot-recovery.json").exists();
        if healthy && recovered_at.elapsed() > Duration::from_secs(3) {
            break;
        }
        if recovered_at.elapsed() > Duration::from_secs(60) {
            let _ = serving.kill();
            let _ = serving.wait();
            anyhow::bail!("runtime neither exited nor recovered the staged store");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        exited_failed || !exited,
        "runtime reported ready with a broken staged store"
    );
    let _ = serving.kill();
    let _ = serving.wait();
    let (ok, recovered) = fixture.run(&["--json", "snapshot", "recover", "--confirm"])?;
    anyhow::ensure!(ok, "host recovery failed: {}", recovered["errors"]);
    let (ok, status) = fixture.run(&["--client-only", "--json", "status"])?;
    assert!(ok);
    assert_eq!(status["summary"]["local_alive"], 1);
    Ok(())
}

#[test]
fn queued_direct_resume_rechecks_maintenance_after_library_ownership_wait() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let (ok, created) = fixture.run(&["--direct", "--json", "snapshot", "create"])?;
    assert!(ok);
    let id = created["details"]["id"].as_str().context("snapshot id")?;
    let (ok, revision) = fixture.run(&["--direct", "--json", "memory-revision"])?;
    anyhow::ensure!(ok, "host control revision failed: {}", revision["errors"]);
    let token = revision["summary"]["revision"]
        .as_str()
        .context("revision token")?;
    fixture.stop_runtime()?;
    // Parallel tests may briefly hold a serve child; wait patiently for the
    // fixture's own lock instead of a hard 1s budget.
    let ownership = {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match respire_app::lock::LibraryLock::acquire(fixture.root.path(), Duration::from_secs(1)) {
                Ok(lock) => break lock,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(error) => return Err(error),
            }
        }
    };
    let mut queued = fixture
        .command(&[
            "--direct",
            "--json",
            "snapshot",
            "resume-sync",
            "--reviewed-revision",
            token,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // The lock wait moved inside the runtime process, so stderr no longer
    // reports it. Prove the wait by requiring the child to remain alive while
    // ownership is held, then verify the post-wait quarantine recheck.
    let began = Instant::now();
    while began.elapsed() < Duration::from_millis(500) {
        anyhow::ensure!(
            queued.try_wait()?.is_none(),
            "direct command completed while maintenance held library ownership"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let receipt = respire_app::snapshot::restore_locked(
        fixture.root.path(),
        "snapshot-fixture",
        &SessionKeys::from_urk([9; 32])?,
        id,
        &ownership,
    )?;
    drop(ownership);
    let rejected = wait_bounded(queued)?;
    assert!(
        !rejected.status.success(),
        "queued direct command removed maintenance quarantine"
    );
    let error: Value = serde_json::from_slice(&rejected.stdout)?;
    assert!(error["errors"].to_string().contains("snapshot"));
    assert_eq!(
        LocalStore::open(&fixture.root.path().join("rsrs.db"))?
            .snapshot_quarantine_id()?
            .as_deref(),
        Some(id)
    );
    fixture.stop_runtime()?;
    let ownership =
        respire_app::lock::LibraryLock::acquire(fixture.root.path(), Duration::from_secs(1))?;
    respire_app::snapshot::rollback_locked(fixture.root.path(), &receipt, &ownership)?;
    Ok(())
}

#[test]
fn public_witness_verifies_restored_chain_and_reports_tamper_without_writes() -> Result<()> {
    let fixture = Fixture::new()?;
    let (ok, before) = fixture.run(&["--direct", "--json", "witness", "--verify"])?;
    assert!(ok);
    assert_eq!(before["summary"]["count"], 1);
    assert_eq!(before["summary"]["intact"], true);
    let (ok, created) = fixture.run(&["--direct", "--json", "snapshot", "create"])?;
    assert!(ok);
    let id = created["details"]["id"].as_str().context("snapshot id")?;
    assert_eq!(
        created["details"]["witness_head"],
        before["summary"]["head"]
    );
    assert_eq!(created["details"]["witness_count"], 1);
    assert_eq!(created["details"]["witness_intact"], true);
    {
        let store = LocalStore::open(&fixture.root.path().join("rsrs.db"))?;
        assert!(store.forget("12345678-1234-4234-8234-123456789abc")?);
    }
    let (ok, changed) = fixture.run(&["--direct", "--json", "witness", "--verify"])?;
    assert!(ok);
    assert_eq!(changed["summary"]["count"], 2);
    let (ok, restored) = fixture.run(&["--json", "snapshot", "restore", id, "--confirm"])?;
    anyhow::ensure!(
        ok,
        "restore of witnessed library failed: {}",
        restored["errors"]
    );
    let (ok, verified) = fixture.run(&["--client-only", "--json", "witness", "--verify"])?;
    assert!(ok);
    assert_eq!(verified["summary"]["head"], before["summary"]["head"]);
    assert_eq!(verified["summary"]["count"], 1);
    {
        let injection = rusqlite::Connection::open(fixture.root.path().join("rsrs.db"))?;
        injection.execute(
            "UPDATE witness_log SET after_digest='synthetic-tamper' WHERE seq=1",
            [],
        )?;
    }
    let (ok, broken) = fixture.run(&["--client-only", "--json", "witness", "--verify"])?;
    assert!(!ok);
    assert_eq!(broken["command"], "witness");
    assert_eq!(broken["status"], "fail");
    assert_eq!(broken["summary"]["broken_at"], 1);
    assert!(!broken["errors"]
        .as_array()
        .context("diagnostics")?
        .is_empty());
    let (ok, status) = fixture.run(&["--client-only", "--json", "status"])?;
    assert!(ok);
    assert_eq!(status["summary"]["local_alive"], 1);
    // The damaged current chain is still preserved in a pre-restore copy; it
    // must not prevent selecting a separate healthy checkpoint by exact ID.
    let (ok, rescued) = fixture.run(&["--json", "snapshot", "restore", id, "--confirm"])?;
    anyhow::ensure!(
        ok,
        "healthy witness snapshot rescue failed: {}",
        rescued["errors"]
    );
    let (ok, rechecked) = fixture.run(&["--client-only", "--json", "witness", "--verify"])?;
    assert!(ok);
    assert_eq!(rechecked["summary"]["head"], before["summary"]["head"]);
    // The whole database hash is unchanged: this specifically tests manifest
    // checkpoint binding rather than merely file-byte integrity validation.
    let manifest_path = fixture
        .root
        .path()
        .join("snapshots")
        .join(format!("{id}.json"));
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    manifest["witness_head"] = json!("0".repeat(64));
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let (ok, rejected) = fixture.run(&["--json", "snapshot", "restore", id, "--confirm"])?;
    assert!(!ok);
    assert!(rejected["errors"]
        .to_string()
        .contains("witness checkpoint"));

    Ok(())
}

#[test]
fn healthy_snapshot_rescue_preserves_unparseable_current_witness() -> Result<()> {
    for malformed in [true, false] {
        let fixture = Fixture::new()?;
        let (ok, created) = fixture.run(&["--direct", "--json", "snapshot", "create"])?;
        assert!(ok);
        let id = created["details"]["id"]
            .as_str()
            .context("healthy snapshot id")?;
        {
            let database = rusqlite::Connection::open(fixture.root.path().join("rsrs.db"))?;
            if malformed {
                database.execute(
                    "UPDATE witness_log SET after_digest=x'ff0001' WHERE seq=1",
                    [],
                )?;
            } else {
                database.execute("DELETE FROM meta WHERE key='witness_library_id_v1'", [])?;
            }
        }
        let (ok, restored) = fixture.run(&["--json", "snapshot", "restore", id, "--confirm"])?;
        anyhow::ensure!(
            ok,
            "unverifiable witness prevented healthy rescue: {}",
            restored["errors"]
        );
        let mut diagnostic = None;
        for entry in std::fs::read_dir(fixture.root.path().join("snapshots"))? {
            let path = entry?.path();
            if path.extension().and_then(|name| name.to_str()) != Some("json") {
                continue;
            }
            let manifest: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            if manifest["witness_problem"].is_string() {
                diagnostic = Some(manifest);
                break;
            }
        }
        let diagnostic = diagnostic
            .context("damaged state must be retained as an explicit diagnostic snapshot")?;
        assert_eq!(diagnostic["witness_intact"], false);
        let bad_id = diagnostic["id"]
            .as_str()
            .context("diagnostic snapshot id")?;
        let saved = rusqlite::Connection::open(
            fixture
                .root
                .path()
                .join("snapshots")
                .join(format!("{bad_id}.db")),
        )?;
        if malformed {
            let value: Vec<u8> = saved.query_row(
                "SELECT after_digest FROM witness_log WHERE seq=1",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(value, [255, 0, 1]);
        } else {
            let count: i64 = saved.query_row(
                "SELECT COUNT(*) FROM meta WHERE key='witness_library_id_v1'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0);
        }
        drop(saved);
        let (ok, proof) = fixture.run(&["--client-only", "--json", "witness", "--verify"])?;
        assert!(ok);
        assert_eq!(proof["summary"]["head"], created["details"]["witness_head"]);
        let (ok, rejected) =
            fixture.run(&["--json", "snapshot", "restore", bad_id, "--confirm"])?;
        assert!(!ok);
        assert!(rejected["errors"].to_string().contains("diagnostic copy"));
    }
    Ok(())
}

#[test]
fn public_feedback_attribution_uses_exact_request_and_refuses_readonly_writes() -> Result<()> {
    let fixture = Fixture::new()?;
    let id = "12345678-1234-4234-8234-123456789abc";
    let request = uuid::Uuid::new_v4().to_string();
    {
        let store = LocalStore::open(&fixture.root.path().join("rsrs.db"))?;
        store.log_query_request(
            &request,
            "synthetic retrieval",
            "fixture",
            "",
            &[id.into()],
            &[0.8],
        )?;
    }
    let mark = [
        "--direct",
        "--json",
        "query-log",
        "mark",
        id,
        "--good",
        "--query-log-id",
        request.as_str(),
        "--source",
        "human",
    ];
    let (ok, marked) = fixture.run(&mark)?;
    anyhow::ensure!(ok, "explicit feedback failed: {}", marked["errors"]);
    assert_eq!(marked["summary"]["marked"], 1);
    assert_eq!(marked["summary"]["source"], "human");
    assert_eq!(marked["summary"]["query_log_id"], request);
    let revision = marked["summary"]["revision"].as_u64().context("revision")?;
    let (ok, repeated) = fixture.run(&mark)?;
    assert!(ok);
    assert_eq!(repeated["summary"]["revision"], revision);
    let (ok, unsupported) = fixture.run(&[
        "--direct",
        "--json",
        "query-log",
        "mark",
        id,
        "--bad",
        "--source",
        "human",
    ])?;
    assert!(!ok);
    assert!(unsupported["errors"]
        .to_string()
        .contains("supports only --source model"));
    let persisted = LocalStore::open(&fixture.root.path().join("rsrs.db"))?.query_log_rows(1)?;
    assert_eq!(persisted[0].good, [id]);
    assert!(persisted[0].bad.is_empty());
    let (ok, legacy) = fixture.run_feedback(
        &["--direct", "--json", "query-log", "mark", id, "--bad"],
        Some("0"),
    )?;
    assert!(ok);
    assert_eq!(legacy["summary"]["good"], false);
    {
        let store = LocalStore::open(&fixture.root.path().join("rsrs.db"))?;
        let allowed = std::collections::BTreeSet::from([id.to_owned()]);
        let counts = store.feedback_counts(
            "synthetic retrieval",
            "fixture",
            "",
            &allowed,
            0.5,
            chrono::Utc::now().timestamp(),
        )?;
        assert!(counts.good.is_empty());
        assert_eq!(counts.bad.get(id), Some(&1));
        let row = store.query_log_rows(1)?.remove(0);
        assert!(row.good.is_empty());
        assert_eq!(row.bad, [id]);
    }
    let (ok, reenabled) = fixture.run_feedback(&mark, Some("1"))?;
    assert!(ok);
    let new_revision = reenabled["summary"]["revision"]
        .as_u64()
        .context("reenabled revision")?;
    assert!(new_revision > revision);
    let revision = new_revision;
    {
        let raw = rusqlite::Connection::open(fixture.root.path().join("rsrs.db"))?;
        raw.execute(
            "UPDATE query_log SET good_ids='[]',bad_ids=?1",
            [serde_json::to_string(&[id])?],
        )?;
    }
    let (ok, repaired) = fixture.run_feedback(&mark, Some("1"))?;
    assert!(ok);
    assert_eq!(repaired["summary"]["revision"], revision);
    let rows = LocalStore::open(&fixture.root.path().join("rsrs.db"))?.query_log_rows(1)?;
    assert_eq!(rows[0].good, [id]);
    assert!(rows[0].bad.is_empty());
    let (ok, invalid) = fixture.run(&[
        "--direct",
        "--json",
        "query-log",
        "mark",
        "12345678",
        "--bad",
        "--query-log-id",
        &request,
    ])?;
    assert!(!ok);
    assert!(invalid["errors"].to_string().contains("complete candidate"));
    let (ok, list) = fixture.run(&["--direct", "--json", "query-log"])?;
    assert!(ok);
    assert!(list.to_string().contains(&request));
    let (ok, mode) = fixture.run(&[
        "--direct",
        "--json",
        "agent-config",
        "--set",
        "workspace_mode=readonly",
    ])?;
    anyhow::ensure!(ok, "readonly configuration failed: {}", mode["errors"]);
    let (ok, denied) = fixture.run(&mark)?;
    assert!(!ok);
    assert!(denied["errors"].to_string().contains("read-only"));
    let database = rusqlite::Connection::open(fixture.root.path().join("rsrs.db"))?;
    let persisted: u64 =
        database.query_row("SELECT revision FROM query_feedback", [], |row| row.get(0))?;
    assert_eq!(persisted, revision);
    Ok(())
}

#[test]
fn public_empty_recall_returns_its_query_log_identity() -> Result<()> {
    let fixture = Fixture::new()?;
    let (ok, result) = fixture.run(&[
        "--direct",
        "--json",
        "recall",
        "synthetic absent query",
        "--project",
        "not-in-fixture",
    ])?;
    anyhow::ensure!(ok, "empty recall failed: {}", result["errors"]);
    assert_eq!(result["summary"]["count"], 0);
    let request = result["summary"]["query_log_id"]
        .as_str()
        .context("empty recall query identity")?;
    assert!(uuid::Uuid::parse_str(request).is_ok());
    let store = LocalStore::open(&fixture.root.path().join("rsrs.db"))?;
    assert!(store
        .query_log_rows(20)?
        .iter()
        .any(|row| row.request_id.as_deref() == Some(request) && row.candidates.is_empty()));
    let rows = store.query_log_rows(20)?;
    let recorded = rows
        .iter()
        .find(|row| row.request_id.as_deref() == Some(request))
        .context("persisted empty recall record")?;
    assert_eq!(recorded.query, "synthetic absent query");
    assert_eq!(recorded.project, "not-in-fixture");
    let before: Vec<_> = rows.iter().map(|row| row.request_id.clone()).collect();
    drop(store);

    // A successful response must not advertise an identity whose INSERT failed.
    let database = rusqlite::Connection::open(fixture.root.path().join("rsrs.db"))?;
    database.execute_batch(
        "CREATE TRIGGER reject_empty_query_log BEFORE INSERT ON query_log
         BEGIN SELECT RAISE(ABORT, 'synthetic empty query log refused'); END;",
    )?;
    drop(database);
    let (ok, denied) = fixture.run(&[
        "--direct",
        "--json",
        "recall",
        "synthetic rejected query",
        "--project",
        "not-in-fixture",
    ])?;
    assert!(!ok);
    assert!(denied["errors"].to_string().contains("synthetic empty query log refused"));
    assert!(denied["summary"]["query_log_id"].is_null());
    let database = rusqlite::Connection::open(fixture.root.path().join("rsrs.db"))?;
    database.execute_batch("DROP TRIGGER reject_empty_query_log;")?;
    drop(database);

    let (ok, mode) = fixture.run(&[
        "--direct",
        "--json",
        "agent-config",
        "--set",
        "workspace_mode=readonly",
    ])?;
    anyhow::ensure!(ok, "readonly configuration failed: {}", mode["errors"]);
    let (ok, readonly) = fixture.run(&[
        "--direct",
        "--json",
        "recall",
        "synthetic readonly query",
        "--project",
        "not-in-fixture",
    ])?;
    anyhow::ensure!(ok, "readonly recall failed: {}", readonly["errors"]);
    assert_eq!(readonly["summary"]["count"], 0);
    assert!(readonly["summary"]["query_log_id"].is_null());
    let store = LocalStore::open(&fixture.root.path().join("rsrs.db"))?;
    let after: Vec<_> = store
        .query_log_rows(20)?
        .into_iter()
        .map(|row| row.request_id)
        .collect();
    assert_eq!(after, before);
    Ok(())
}

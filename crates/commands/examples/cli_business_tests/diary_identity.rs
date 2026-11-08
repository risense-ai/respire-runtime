//! Actual client-only commands against a fresh synthetic runtime and local library.
//! No real account, keyring, model download, or remote memory service is used.
//! Supply RSRS_RUNTIME_BIN or a neighboring standalone Runtime bundle.
//! RSRS_CORE_TEST_MODEL_DIR must contain the separately verified real CPU model.
//! These synthetic business regressions alone are not standalone G1 evidence.
use anyhow::Context;
use respire_app as respire;
use super::support;
use respire::memory::{crypto, search::HashingEmbedder};
use respire::transport::local::LocalStore;
use respire::{MemoryEngine, MemoryEntry, MemoryTransport, SessionKeys, StoredMemory};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

struct Fixture {
    cli: PathBuf,
    business_cli: Option<PathBuf>,
    home: tempfile::TempDir,
    port: u16,
    secret: String,
    keys: SessionKeys,
    child: Option<Child>,
    runtime: PathBuf,
    models: PathBuf,
    runtime_owner: RefCell<Option<Value>>,
    extra_env: Vec<(&'static str, String)>,
}

impl Fixture {
    /// Create an isolated local vault containing only deterministic synthetic keys.
    fn new() -> anyhow::Result<Self> {
        let cli = support::cli_bin()?;
        let runtime = support::runtime_bin()?;
        anyhow::ensure!(
            runtime.is_file(),
            "standalone Runtime fixture missing at {}; supply RSRS_RUNTIME_BIN with its dependency bundle",
            runtime.display()
        );
        let runtime = runtime.canonicalize()?;
        anyhow::ensure!(
            runtime != cli,
            "CLI shim cannot substitute for the standalone Runtime fixture"
        );
        let business_cli = match (
            std::env::var_os("RSRS_TEST_STABLE_DIARY_SUITE"),
            std::env::var_os("RSRS_TEST_STABLE_CLI_BIN"),
        ) {
            (None, None) => None,
            (Some(suite), Some(binary)) if suite == "stable-diary-remote" => {
                let binary = PathBuf::from(binary).canonicalize()?;
                anyhow::ensure!(binary.is_file() && binary != cli && binary != runtime,
                    "stable business CLI must be separate from the manager and Runtime");
                Some(binary)
            }
            _ => anyhow::bail!("stable business CLI requires the explicit stable-diary-remote suite"),
        };
        let models = PathBuf::from(
            std::env::var_os("RSRS_CORE_TEST_MODEL_DIR")
                .context("supply RSRS_CORE_TEST_MODEL_DIR with the verified real CPU model fixture")?,
        )
        .canonicalize()?;
        for file in [
            "tokenizer.json",
            "onnx/model_quantized.onnx",
            "onnx/model_quantized.cpu-v1.ort",
        ] {
            anyhow::ensure!(models.join(file).is_file(), "model fixture missing {file}");
        }
        let home = tempfile::tempdir()?;
        std::fs::create_dir(home.path().join("data"))?;
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
            .local_addr()?
            .port();
        let secret = format!("A3-{}", "07".repeat(18));
        let salt = "08".repeat(16);
        let urk = [9; 32];
        let kek = crypto::derive_rsrs_kek(&secret, &salt)?;
        let (nonce, wrapped) = crypto::wrap_key(&urk, &kek)?;
        std::fs::write(
            home.path().join("data/session.json"),
            serde_json::to_vec(&json!({
                "user":"synthetic-diary", "pass":"synthetic-unused", "vault_version":4,
                "kdf_salt":salt, "wrapped_urk":format!("{}{wrapped}", crypto::RSRS_PREFIX),
                "urk_nonce":nonce
            }))?,
        )?;
        std::fs::write(
            home.path().join("data/agent.json"),
            br#"{"diary_mode":"concise"}"#,
        )?;
        Ok(Self {
            cli,
            business_cli,
            home,
            port,
            secret,
            keys: SessionKeys::from_urk(urk)?,
            child: None,
            runtime,
            models,
            runtime_owner: RefCell::new(None),
            extra_env: Vec::new(),
        })
    }

    /// Build a command confined to this profile, port, and disabled remote services.
    fn command(&self, args: &[&str]) -> Command {
        self.command_for(&self.cli, args)
    }

    fn command_for(&self, binary: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(binary);
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| {
                name.starts_with("RSRS_")
                    || name.starts_with("ONEMEMORY_")
                    || name.starts_with("RESPIRE_")
            }) {
                command.env_remove(name);
            }
        }
        command
            .args(args)
            .current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join("config"))
            .env("XDG_DATA_HOME", self.home.path().join("share"))
            .env("RSRS_DATA_DIR", self.home.path().join("data"))
            .env("RSRS_RPC_PORT", self.port.to_string())
            .env("RSRS_USER", "synthetic-diary")
            .env("RSRS_SUPER", &self.secret)
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env("RSRS_RUNTIME_BIN", &self.runtime)
            .env("RSRS_M3_DIR", &self.models)
            .env("RSRS_RPC_PARALLELISM", "2")
            .env("RSRS_LANG", "en")
            .env("TZ", "UTC")
            // Refuse background model downloads at a loopback-only destination.
            .env("RSRS_MIRROR", "http://127.0.0.1:9")
            .env("RSRS_CPU_ORT_MIRROR", "http://127.0.0.1:9");
        command.envs(self.extra_env.iter().map(|(name, value)| (*name, value)));
        command
    }

    fn business_command(&self, args: &[&str]) -> anyhow::Result<Command> {
        let Some(binary) = self.business_cli.as_deref() else {
            return Ok(self.command(args));
        };
        anyhow::ensure!(args.contains(&"--client-only")
            && !args.iter().any(|arg| *arg == "--direct" || arg.starts_with("--direct=")),
            "stable business calls must be client-only and cannot use direct execution");
        anyhow::ensure!(self.owns_runtime()?, "candidate Runtime owner changed before stable business call");
        let mut command = self.command_for(binary, args);
        command.env("RSRS_CLIENT_ONLY", "1").env("RSRS_NO_AUTOSTART", "1");
        Ok(command)
    }

    fn verify_business_owner(&self) -> anyhow::Result<()> {
        if self.business_cli.is_some() {
            anyhow::ensure!(self.owns_runtime()?, "candidate Runtime owner changed after stable business call");
        }
        Ok(())
    }

    fn business_output(&self, args: &[&str]) -> anyhow::Result<Output> {
        let output = self.business_command(args)?.output();
        self.verify_business_owner()?;
        Ok(output?)
    }

    /// Start an owned runtime and verify its process and profile before use.
    fn start(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.child.is_none(),
            "fixture already has a runtime launcher"
        );
        *self.runtime_owner.borrow_mut() = None;
        let mut command = if self.business_cli.is_some() {
            // This is the existing legacy host startup boundary. A normal
            // authorized `serve` listener intentionally requires modern scope.
            self.command_for(&self.runtime, &[
                "--runtime-internal", "--runtime-background-internal",
                "--port", &self.port.to_string(),
            ])
        } else {
            self.command(&["runtime", "run"])
        };
        self.child = Some(
            command
                .stdout(std::fs::File::create(
                    self.home.path().join("runtime.stdout"),
                )?)
                .stderr(std::fs::File::create(
                    self.home.path().join("runtime.stderr"),
                )?)
                .spawn()?,
        );
        for _ in 0..100 {
            if let Some(status) = self
                .child
                .as_mut()
                .context("synthetic runtime child missing")?
                .try_wait()?
            {
                anyhow::bail!("synthetic runtime exited: {status}");
            }
            if self.owns_runtime()? {
                if self.business_cli.is_some() {
                    self.verify_legacy_projection()?;
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        anyhow::bail!("synthetic runtime did not become ready")
    }

    /// Prove this listener projects the historical unscoped wire request.
    /// The probe is issued by the harness; subsequent business calls use the old binary.
    fn verify_legacy_projection(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.owns_runtime()?, "legacy probe requires the owned candidate");
        let id = uuid::Uuid::new_v4().to_string();
        let response: Value = ureq::post(&format!("http://127.0.0.1:{}/api/rpc", self.port))
            .timeout(Duration::from_secs(30))
            .send_json(json!({"v": 1, "id": id, "method": "cli.exec",
                "args": ["--json", "status"], "lifecycle": null}))?
            .into_json()?;
        let object = response.as_object().context("legacy probe response is not an object")?;
        anyhow::ensure!(response["v"] == 1 && response["id"] == id
            && response["ok"] == true && response["exit"] == 0
            && ["scope", "operation_id", "idempotency_key"].iter()
                .all(|key| !object.contains_key(*key)),
            "legacy probe did not receive the original unscoped projection");
        anyhow::ensure!(self.owns_runtime()?, "candidate actor changed after legacy probe");
        eprintln!("stable-diary-legacy-probe {}", json!({
            "probe_without_scope": true, "legacy_projection_verified": true,
            "same_actor_before_after": true, "candidate_process_verified": true,
        }));
        Ok(())
    }

    /// Reject port collisions instead of submitting commands to another runtime.
    fn owns_runtime(&self) -> anyhow::Result<bool> {
        let Some(child) = self.child.as_ref() else {
            return Ok(false);
        };
        let Ok(response) = ureq::get(&format!("http://127.0.0.1:{}/api/health", self.port))
            .timeout(Duration::from_millis(100))
            .call()
        else {
            return Ok(false);
        };
        let health: Value = response.into_json()?;
        if health["store_ready"] != true {
            return Ok(false);
        }
        let profile = self.home.path().join("data").canonicalize()?;
        let path_matches = |field: &str, expected: &Path| -> anyhow::Result<bool> {
            let actual = health[field]
                .as_str()
                .context("runtime health path missing")?;
            Ok(Path::new(actual).canonicalize()? == expected)
        };
        anyhow::ensure!(
            health["pid"]
                .as_u64()
                .is_some_and(|pid| pid > 0 && if self.business_cli.is_some() {
                    pid == u64::from(child.id())
                } else {
                    pid != u64::from(child.id())
                })
                && path_matches("exe", &self.runtime)?
                && path_matches("image_path", &self.runtime)?
                && path_matches("data_dir", &profile)?
                && path_matches("installation_root", &profile)?
                && health["generation"]
                    .as_u64()
                    .is_some_and(|generation| generation > 0)
                && health["account_id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty())
                && health["process_start_id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty()),
            "fixture port belongs to a different process or profile; no command submitted"
        );
        let instance = health["instance_id"]
            .as_str()
            .context("runtime instance missing")?;
        let nonce = uuid::Uuid::parse_str(instance)?;
        anyhow::ensure!(
            nonce.get_version_num() == 4 && nonce.to_string() == instance,
            "runtime launch instance is invalid"
        );
        let prefix = if cfg!(windows) {
            "windows-filetime-"
        } else if cfg!(target_os = "linux") {
            "linux-starttime-"
        } else {
            "darwin-lstart-"
        };
        if self.business_cli.is_some() {
            let process = respire_commands::net_rpc::runtime_process_identity(child.id())?;
            anyhow::ensure!(Path::new(&process.executable).canonicalize()? == self.runtime
                && health["process_start_id"] == format!("{prefix}{}", process.started_at),
                "legacy runtime does not match the directly owned process and birth");
        } else {
            let claim: Value = serde_json::from_slice(&std::fs::read(
                profile.join("runtime/autostart/launch").join(format!("launch-{instance}.claimed")),
            )?)?;
            let birth = claim["process_start_id"].as_str().context("launch claim birth missing")?;
            anyhow::ensure!(claim["pid"] == health["pid"]
                && health["process_start_id"] == format!("{prefix}{birth}"),
                "runtime does not match the consumed launch grant");
        }
        let identity = json!({
            "pid": health["pid"], "instance_id": health["instance_id"],
            "process_start_id": health["process_start_id"], "image_sha256": health["image_sha256"],
            "installation_id": health["installation_id"], "account_id": health["account_id"],
            "generation": health["generation"],
        });
        let mut owner = self.runtime_owner.borrow_mut();
        if let Some(expected) = owner.as_ref() {
            anyhow::ensure!(
                *expected == identity,
                "fixture runtime owner changed; no command submitted"
            );
        } else {
            *owner = Some(identity);
        }
        Ok(true)
    }

    /// Execute a public client-only command after rechecking runtime ownership.
    fn run(&self, args: &[&str]) -> anyhow::Result<Value> {
        anyhow::ensure!(self.owns_runtime()?, "synthetic runtime is not ready");
        let mut all = vec!["--client-only", "--json"];
        all.extend_from_slice(args);
        Self::result(self.business_output(&all)?)
    }

    /// Require a successful command and decode its public JSON envelope.
    fn result(output: Output) -> anyhow::Result<Value> {
        let value: Value = serde_json::from_slice(&output.stdout)?;
        anyhow::ensure!(
            output.status.success(),
            "synthetic command failed: {value}; {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(value)
    }

    /// Append one trivial event using the public remember command.
    fn remember(&self, content: &str) -> anyhow::Result<Value> {
        self.run(&["remember", content, "--importance", "trivial"])
    }

    /// Read the full saved entry using its public command contract.
    fn show(&self, id: &str) -> anyhow::Result<Value> {
        Ok(self.run(&["show", id])?["details"]["entry"].clone())
    }

    /// Seed before startup; assertions against a running owner stay read-only.
    /// Reopening with migrations/WAL setup races the runtime's own startup writes
    /// and can also change the data whose immutability these tests are checking.
    fn store(&self) -> anyhow::Result<LocalStore> {
        let path = self.home.path().join("data/rsrs.db");
        if self.child.is_some() {
            LocalStore::open_read_only(&path)
        } else {
            LocalStore::open(&path)
        }
    }

    /// Seed a synthetic entry whose payload author and wire owner agree.
    fn seed(&self, entry: &MemoryEntry, deleted: bool) -> anyhow::Result<StoredMemory> {
        self.seed_with_owner(entry, deleted, &entry.user)
    }

    /// Seed separate logical authors and routing owners without model downloads.
    fn seed_with_owner(
        &self,
        entry: &MemoryEntry,
        deleted: bool,
        wire_user: &str,
    ) -> anyhow::Result<StoredMemory> {
        let _defer = respire::core_sdk::defer_indexing();
        let mut stored =
            MemoryEngine::seal(&self.keys, &HashingEmbedder::default(), entry, wire_user)?;
        stored.deleted = deleted;
        anyhow::ensure!(self.store()?.put(&stored)?, "fixture seed was not stored");
        Ok(stored)
    }

    /// Verify rejected identity cannot mutate records/outbox or disclose fixture secrets.
    fn assert_author_rejection(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.owns_runtime()?, "synthetic runtime is not ready");
        let before = serde_json::to_value(self.store()?.all(true)?)?;
        let boundary = self.store()?.outgoing_boundary()?;
        let outgoing = serde_json::to_value(self.store()?.outgoing()?)?;
        let output = self
            .business_output(&[
                "--client-only",
                "--json",
                "remember",
                "rejected-private-event",
                "--importance",
                "trivial",
            ])?;
        assert!(!output.status.success());
        let value: Value = serde_json::from_slice(&output.stdout)?;
        assert!(value["errors"]
            .as_array()
            .context("missing error array")?
            .iter()
            .any(|error| error.as_str().is_some_and(
                |message| message.contains("daily track author does not match this profile")
            )));
        assert!(
            before == serde_json::to_value(self.store()?.all(true)?)?,
            "rejected append mutated rows"
        );
        assert_eq!(
            boundary,
            self.store()?.outgoing_boundary()?,
            "rejected append queued a sync operation"
        );
        assert!(
            outgoing == serde_json::to_value(self.store()?.outgoing()?)?,
            "rejected append changed pending sync bytes"
        );
        let emitted = format!(
            "{}{}{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            std::fs::read_to_string(self.home.path().join("runtime.stdout"))?,
            std::fs::read_to_string(self.home.path().join("runtime.stderr"))?
        );
        for private in [
            &self.secret,
            "foreign-private-author",
            "foreign-private-event",
            "rejected-private-event",
        ] {
            assert!(
                !emitted.contains(private),
                "rejection exposed private fixture data"
            );
        }
        for (_, private) in &self.extra_env {
            assert!(
                !emitted.contains(private),
                "rejection exposed synthetic fallback key material"
            );
        }
        Ok(())
    }

    /// Stop only the verified runtime or the exact child process we spawned.
    fn stop(&mut self) {
        let owned = self.owns_runtime().unwrap_or(false);
        if let Some(mut child) = self.child.take() {
            if owned {
                let _ = self.command(&["runtime", "stop"]).output();
            }
            for _ in 0..100 {
                if child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Drop for Fixture {
    /// Reap the fixture runtime even when a test exits early.
    fn drop(&mut self) {
        self.stop();
    }
}

/// Match the child runtime's calendar-day boundary on the current platform.
fn day() -> String {
    // Child TZ=UTC applies on Unix; Windows uses the OS local timezone.
    #[cfg(windows)]
    let now = chrono::Local::now();
    #[cfg(not(windows))]
    let now = chrono::Utc::now();
    now.format("%Y-%m-%d").to_string()
}
/// Reproduce the public daily identity namespace for synthetic authors and dates.
fn track_id(user: &str, day: &str) -> String {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("activity-track/{user}/{day}").as_bytes(),
    )
    .to_string()
}
/// Build synthetic metadata whose preservation can be checked after appends.
fn entry(id: &str, user: &str, title: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        metadata: Default::default(),
        unknown_fields: Default::default(),
        id: id.into(),
        user: user.into(),
        title: title.into(),
        content: content.into(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: Vec::new(),
        kind: respire::Kind::Context,
        tags: vec!["preserve-tag".into()],
        computer: "fixture-computer".into(),
        project: "fixture-project".into(),
        created_at: "2026-01-01T00:00:00.000Z".into(),
        updated_at: "2026-01-01T00:00:00.000Z".into(),
        emotion: 0.75,
        parent_id: "fixture-parent".into(),
        importance: "normal".into(),
        device: "fixture-device".into(),
        modified_by: "fixture-device".into(),
    }
}

/// Explicit titles identify independent entries instead of silently naming a daily track.
#[test]
fn explicit_titles_preserve_entries_and_leave_the_daily_track_unchanged() -> anyhow::Result<()> {
    for mode in ["concise", "verbose"] {
        let mut fixture = Fixture::new()?;
        std::fs::write(
            fixture.home.path().join("data/agent.json"),
            serde_json::to_vec(&json!({"diary_mode":mode}))?,
        )?;
        fixture.start()?;
        for has_track in [false, true] {
            let existing = if has_track {
                let result = fixture.remember("untitled-existing-event")?;
                let id = result["summary"]["id"]
                    .as_str()
                    .context("missing diary id")?;
                Some((id.to_owned(), fixture.show(id)?))
            } else {
                None
            };
            for importance in ["trivial", "important"] {
                let title = format!("explicit-{mode}-{has_track}-{importance}");
                let body = format!("body-{title}");
                let receipt = fixture.run(&[
                    "remember",
                    &body,
                    "--title",
                    &title,
                    "--importance",
                    importance,
                    "--force",
                ])?;
                let id = receipt["summary"]["id"]
                    .as_str()
                    .context("missing entry id")?;
                let saved = fixture.show(id)?;
                assert_eq!(receipt["details"], saved);
                assert_eq!(saved["title"], title);
                assert!(saved["content"]
                    .as_str()
                    .context("missing body")?
                    .contains(&body));
                assert!(receipt["items"]
                    .as_array()
                    .context("missing items")?
                    .iter()
                    .any(|item| item["value"] == format!("id={id}")));
                if let Some((track_id, before)) = &existing {
                    assert_ne!(id, track_id);
                    assert_eq!(fixture.show(track_id)?, *before);
                }
            }
        }
    }
    support::legacy_receipt("diary_identity::explicit_titles_preserve_entries_and_leave_the_daily_track_unchanged", "candidate_runtime")?;
    Ok(())
}

/// Every successful write action returns a public entry, while blank titles retain aggregation.
#[test]
fn remember_public_payload_covers_created_appended_and_merged() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    let created = fixture.remember("first public diary event")?;
    let id = created["summary"]["id"]
        .as_str()
        .context("missing created id")?;
    assert_eq!(created["summary"]["action"], "created");
    assert_eq!(created["details"], fixture.show(id)?);
    let appended = fixture.run(&["remember", "second public diary event", "--title", " \t "])?;
    assert_eq!(appended["summary"]["action"], "diary_appended");
    assert_eq!(appended["summary"]["id"], id);
    assert_eq!(appended["details"], fixture.show(id)?);
    let source = fixture.run(&[
        "remember",
        "merge source event",
        "--title",
        "merge source",
        "--importance",
        "important",
        "--force",
    ])?;
    let source_id = source["summary"]["id"]
        .as_str()
        .context("missing source id")?;
    let merged = fixture.run(&[
        "remember",
        "merged public event",
        "--title",
        "merged title",
        "--importance",
        "important",
        "--merge-ids",
        source_id,
    ])?;
    assert_eq!(merged["summary"]["action"], "merged");
    let merged_id = merged["summary"]["id"]
        .as_str()
        .context("missing merged id")?;
    assert_eq!(merged["details"], fixture.show(merged_id)?);
    for result in [&created, &appended, &source, &merged] {
        let details = result["details"]
            .as_object()
            .context("missing public entry")?;
        for internal in [
            "ciphertext",
            "nonce",
            "wrapped_urk",
            "embedding",
            "embedding_enc",
            "local_embedding",
            "local_artifact",
            "token",
            "password",
        ] {
            assert!(
                !details.contains_key(internal),
                "public result contains {internal}"
            );
        }
        assert_eq!(result["details"]["id"], result["summary"]["id"]);
    }
    support::legacy_receipt("diary_identity::remember_public_payload_covers_created_appended_and_merged", "candidate_runtime")?;
    Ok(())
}

/// Client-only RPC failures remain one JSON document with an actionable diagnostic.
#[test]
fn missing_entry_and_usage_failures_have_machine_diagnostics() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    for args in [
        vec!["--client-only", "--json", "show", "no-such-id"],
        vec![
            "--client-only",
            "--json",
            "remember",
            "synthetic",
            "--unknown-option",
        ],
    ] {
        let output = fixture.business_output(&args)?;
        assert!(!output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["status"], "fail");
        let errors = result["errors"].as_array().context("missing error list")?;
        assert!(!errors.is_empty());
        assert!(errors
            .iter()
            .all(|error| error.as_str().is_some_and(|s| !s.trim().is_empty())));
        if args.contains(&"--unknown-option") {
            assert_eq!(output.status.code(), Some(2));
            assert!(!errors[0]
                .as_str()
                .context("missing concise error")?
                .contains('\n'));
            assert!(result["details"]["usage"]
                .as_str()
                .context("missing usage")?
                .contains("Usage:"));
        } else {
            assert_eq!(output.status.code(), Some(1));
            assert!(errors[0]
                .as_str()
                .context("missing not-found diagnostic")?
                .contains("not found"));
        }
    }
    if let Some(binary) = support::legacy_cli()? {
        let before = serde_json::to_value(fixture.store()?.all(true)?)?;
        let owner = fixture.runtime_owner.borrow().clone();
        let rejected = fixture.command_for(&binary, &["--direct", "--json", "show", "no-such-id"])
            .output()?;
        assert!(!rejected.status.success());
        let failure: Value = serde_json::from_slice(&rejected.stdout)?;
        assert_eq!(failure["status"], "fail");
        assert!(failure["errors"].as_array().context("old direct diagnostic missing")?
            .iter().any(|error| error.as_str().is_some_and(|error|
                error.contains("the local runtime is running"))));
        assert_eq!(serde_json::to_value(fixture.store()?.all(true)?)?, before);
        assert!(fixture.owns_runtime()?);
        assert_eq!(*fixture.runtime_owner.borrow(), owner);
    }
    // --direct forwards through RPC; keep the verified standalone owner alive.
    let output = fixture
        .command(&["--direct", "--json", "show", "no-such-id"])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["status"], "fail");
    assert!(result["errors"][0]
        .as_str()
        .context("missing direct diagnostic")?
        .contains("not found"));
    support::legacy_receipt("diary_identity::missing_entry_and_usage_failures_have_machine_diagnostics", "candidate_runtime")?;
    Ok(())
}

/// Public retitling, including a blank title, must not break daily append identity.
#[test]
fn public_title_edit_and_blank_title_still_append_without_changing_metadata() -> anyhow::Result<()>
{
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    let first = fixture.remember("event-original")?;
    let id = first["summary"]["id"]
        .as_str()
        .context("synthetic response string missing")?;
    fixture.run(&[
        "update",
        id,
        "--title",
        "Renamed synthetic diary",
        "--tags",
        "keep,edited",
        "--kind",
        "context",
        "--importance",
        "important",
    ])?;
    let before = fixture.show(id)?;
    let appended = fixture.remember("event-after-title-edit")?;
    assert_eq!(appended["summary"]["id"], id);
    assert_eq!(appended["summary"]["title"], "Renamed synthetic diary");
    let after = fixture.show(id)?;
    for (field, value) in before
        .as_object()
        .context("synthetic entry is not an object")?
    {
        if !["content", "updated_at", "modified_by"].contains(&field.as_str()) {
            assert_eq!(&after[field], value, "metadata {field} changed");
        }
    }
    let content = after["content"]
        .as_str()
        .context("synthetic response string missing")?;
    assert_eq!(content.matches("event-original").count(), 1);
    assert_eq!(content.matches("event-after-title-edit").count(), 1);
    fixture.run(&["update", id, "--title", ""])?;
    fixture.remember("event-after-blank-title")?;
    let blank = fixture.show(id)?;
    assert_eq!(blank["title"], "");
    assert!(blank["content"]
        .as_str()
        .context("synthetic response string missing")?
        .contains("event-after-blank-title"));
    support::legacy_receipt("diary_identity::public_title_edit_and_blank_title_still_append_without_changing_metadata", "candidate_runtime")?;
    Ok(())
}

/// Stable and legacy tracks merge atomically without crossing author/day boundaries.
#[test]
fn canonical_identity_merges_legacy_tracks_without_touching_other_users_or_days(
) -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let day = day();
    let title = format!("\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} {day}");
    let id = track_id("synthetic-diary", &day);
    let canonical = entry(
        &id,
        "synthetic-diary",
        "Renamed canonical",
        "canonical-event",
    );
    fixture.seed_with_owner(&canonical, false, "server-routing-owner")?;
    fixture.seed_with_owner(
        &entry("legacy-today", "synthetic-diary", &title, "legacy-event"),
        false,
        "server-routing-owner",
    )?;
    let foreign = fixture.seed_with_owner(
        &entry(
            &track_id("another-user", &day),
            "another-user",
            &title,
            "foreign-event",
        ),
        false,
        "server-routing-owner",
    )?;
    let previous = fixture.seed(
        &entry(
            &track_id("synthetic-diary", "2000-01-01"),
            "synthetic-diary",
            "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2000-01-01",
            "previous-day-event",
        ),
        false,
    )?;
    fixture.start()?;
    let result = fixture.remember("fresh-event")?;
    assert_eq!(result["summary"]["id"], id);
    let saved = fixture.show(&id)?;
    assert_eq!(saved["title"], canonical.title);
    assert_eq!(saved["tags"], json!(canonical.tags));
    assert_eq!(saved["importance"], "normal");
    assert_eq!(saved["emotion"], 0.75);
    assert_eq!(saved["parent_id"], canonical.parent_id);
    assert_eq!(saved["device"], canonical.device);
    for marker in ["canonical-event", "legacy-event", "fresh-event"] {
        assert_eq!(
            saved["content"]
                .as_str()
                .context("synthetic response string missing")?
                .matches(marker)
                .count(),
            1
        );
    }
    fixture.stop();
    let rows = fixture.store()?.all(true)?;
    assert_eq!(
        rows.iter()
            .find(|row| row.id == id)
            .context("canonical row missing")?
            .user,
        "server-routing-owner"
    );
    assert!(
        rows.iter()
            .find(|row| row.id == "legacy-today")
            .context("legacy row missing")?
            .deleted
    );
    for original in [foreign, previous] {
        let after = rows
            .iter()
            .find(|row| row.id == original.id)
            .context("unrelated row missing")?;
        assert_eq!(after.ciphertext, original.ciphertext);
        assert!(!after.deleted);
    }
    support::legacy_receipt("diary_identity::canonical_identity_merges_legacy_tracks_without_touching_other_users_or_days", "candidate_runtime")?;
    Ok(())
}

/// Tombstoned content must stay deleted while legacy fallback and recreation work.
#[test]
fn deleted_stable_track_uses_legacy_fallback_and_deleted_history_is_not_resurrected(
) -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let day = day();
    let id = track_id("synthetic-diary", &day);
    let title = format!("\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} {day}");
    fixture.seed(
        &entry(
            &id,
            "synthetic-diary",
            "deleted renamed track",
            "deleted-event",
        ),
        true,
    )?;
    fixture.seed(
        &entry(
            "legacy-live",
            "synthetic-diary",
            &title,
            "legacy-live-event",
        ),
        false,
    )?;
    fixture.start()?;
    let result = fixture.remember("append-to-legacy")?;
    assert_eq!(result["summary"]["id"], "legacy-live");
    let saved = fixture.show("legacy-live")?;
    assert!(saved["content"]
        .as_str()
        .context("synthetic response string missing")?
        .contains("legacy-live-event"));
    assert!(!saved["content"]
        .as_str()
        .context("synthetic response string missing")?
        .contains("deleted-event"));
    fixture.run(&["forget", "legacy-live"])?;
    let recreated = fixture.remember("only-new-event")?;
    assert_eq!(recreated["summary"]["id"], id);
    let saved = fixture.show(&id)?;
    let content = saved["content"]
        .as_str()
        .context("synthetic response string missing")?;
    assert!(content.contains("only-new-event"));
    assert!(!content.contains("deleted-event") && !content.contains("legacy-live-event"));
    support::legacy_receipt("diary_identity::deleted_stable_track_uses_legacy_fallback_and_deleted_history_is_not_resurrected", "candidate_runtime")?;
    Ok(())
}

/// Concurrent clients must preserve every successful event exactly once.
#[test]
fn concurrent_same_day_client_commands_preserve_each_successful_addition_once() -> anyhow::Result<()>
{
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    let mut ids = Vec::new();
    for pair in 0..5 {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for index in 0..2 {
            let marker = format!("pair-{pair}-event-{index}");
            let mut command = fixture.business_command(&[
                "--client-only",
                "--json",
                "remember",
                &marker,
                "--importance",
                "trivial",
            ])?;
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                command.output()
            }));
        }
        for worker in workers {
            let output = worker
                .join()
                .map_err(|_| anyhow::anyhow!("synthetic client panicked"));
            fixture.verify_business_owner()?;
            let value = Fixture::result(output??)?;
            ids.push(
                value["summary"]["id"]
                    .as_str()
                    .context("synthetic response string missing")?
                    .to_owned(),
            );
        }
    }
    assert!(ids.iter().all(|id| id == &ids[0]));
    let saved = fixture.show(&ids[0])?;
    let content = saved["content"]
        .as_str()
        .context("synthetic response string missing")?;
    for pair in 0..5 {
        for index in 0..2 {
            assert_eq!(
                content
                    .matches(&format!("pair-{pair}-event-{index}"))
                    .count(),
                1
            );
        }
    }
    // Exercise the real admission ledger and encrypted business effects together.
    let endpoint = format!("http://127.0.0.1:{}/api/rpc", fixture.port);
    let health: Value = ureq::get(&format!("http://127.0.0.1:{}/api/health", fixture.port))
        .timeout(Duration::from_secs(5)).call()?.into_json()?;
    let scope = json!({"account_id": health["account_id"], "instance_id": health["instance_id"],
        "generation": health["generation"]});
    let original = json!({"v":1, "id":"same-key-first", "method":"cli.exec",
        "operation_id":"same-key-business-effect", "idempotency_key":"same-key-business-effect",
        "scope":scope, "args":["--json", "remember", "idempotent-rpc-marker",
            "--title", "Idempotent RPC effect", "--importance", "important", "--force"]});
    let send = |request: Value| -> anyhow::Result<(u16, Value)> {
        let response = match ureq::post(&endpoint).timeout(Duration::from_secs(120)).send_json(request) {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => return Err(error.into()),
        };
        Ok((response.status(), response.into_json()?))
    };
    let post = |request: Value| -> anyhow::Result<Value> {
        let request_id = request["id"].clone();
        let (status, reply) = send(request)?;
        assert_eq!(status, 200);
        assert_eq!(reply["v"], 1);
        assert_eq!(reply["id"], request_id);
        assert_eq!(reply["pid"], health["pid"]);
        Ok(reply)
    };
    // Use an actually completed operation as the changed parent, not a made-up ID.
    let parent_operation = "fingerprint-known-parent";
    let mut parent = original.clone();
    parent["id"] = json!("fingerprint-parent-request");
    parent["operation_id"] = json!(parent_operation);
    parent["idempotency_key"] = json!(parent_operation);
    parent["args"][2] = json!("fingerprint-parent-marker");
    parent["args"][4] = json!("Fingerprint parent effect");
    let parent = post(parent)?;
    assert_eq!(parent["ok"], true, "{parent}");
    assert_eq!(parent["operation_id"], parent_operation);
    assert!(parent["envelope"]["summary"]["id"].as_str().is_some_and(|id| !id.is_empty()));
    let before = fixture.store()?.all(true)?.len();
    let barrier = std::sync::Barrier::new(2);
    let replies = std::thread::scope(|threads| -> anyhow::Result<Vec<Value>> {
        let mut workers = Vec::new();
        for index in 0..2 {
            let mut request = original.clone();
            request["id"] = json!(format!("same-key-concurrent-{index}"));
            let post = &post;
            let barrier = &barrier;
            workers.push(threads.spawn(move || {
                barrier.wait();
                post(request)
            }));
        }
        workers.into_iter().map(|worker| worker.join()
            .map_err(|_| anyhow::anyhow!("idempotent RPC worker panicked"))?)
            .collect()
    })?;
    assert!(replies.iter().any(|reply| reply["ok"] == true));
    for reply in &replies {
        assert!(reply["ok"] == true || reply["code"] == "request_in_progress", "{reply}");
    }
    let mut replay = original.clone();
    replay["id"] = json!("same-key-completed-replay");
    let replay = post(replay)?;
    assert_eq!(replay["ok"], true, "{replay}");
    assert_eq!(replay["scope"], scope);
    let stored_id = replay["envelope"]["summary"]["id"].as_str()
        .context("idempotent business result ID missing")?;
    assert_eq!(fixture.show(stored_id)?["content"], "idempotent-rpc-marker");
    assert_eq!(fixture.store()?.all(true)?.len(), before + 1,
        "concurrent same-fingerprint requests committed more than one record");
    let mut conflict = original.clone();
    conflict["id"] = json!("same-key-changed-arguments");
    conflict["args"][2] = json!("conflicting-rpc-marker");
    let rejected = post(conflict)?;
    assert_eq!(rejected["ok"], false, "{rejected}");
    assert_eq!(rejected["code"], "idempotency_conflict");
    assert_eq!(fixture.store()?.all(true)?.len(), before + 1,
        "conflicting or replayed requests committed another record");
    assert_eq!(fixture.show(stored_id)?["content"], "idempotent-rpc-marker");
    let result = |operation: &str, id: &str| post(json!({"v":1,"id":id,
        "method":"runtime.result","scope":scope,"args":[operation]}));
    let receipt = result("same-key-business-effect", "fingerprint-original-receipt")?;
    assert_eq!(receipt["envelope"]["summary"]["state"], "completed");
    let retained = receipt["envelope"]["summary"]["response"].clone();
    let installation = PathBuf::from(health["installation_root"].as_str()
        .context("fingerprint installation root missing")?);
    let protected_files = [installation.join("embedding-profiles-v1.json"), installation.join("client.json")];
    let read_protected = || -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        protected_files.iter().map(|path| match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }).collect()
    };
    let protected_before = read_protected()?;
    let unchanged = || -> anyhow::Result<()> {
        assert_eq!(fixture.store()?.all(true)?.len(), before + 1);
        assert_eq!(fixture.show(stored_id)?["content"], "idempotent-rpc-marker");
        assert_eq!(read_protected()?, protected_before);
        assert_eq!(result("same-key-business-effect", "fingerprint-receipt-check")?
            ["envelope"]["summary"]["response"], retained);
        Ok(())
    };
    let mut changes = Vec::new();
    for (field, value, expected) in [
        ("v", json!(2), "protocol_version_mismatch"),
        // index.prepare is supported, but admission must reject before kick_index.
        ("method", json!("index.prepare"), "idempotency_conflict"),
        ("parent_operation_id", json!(parent_operation), "idempotency_conflict"),
        ("lifecycle", json!("coordinator-v1"), "idempotency_conflict"),
    ] {
        let mut request = original.clone();
        request[field] = value;
        changes.push((request, expected));
    }
    for (field, value) in [
        ("account_id", json!("different-fingerprint-account")),
        ("instance_id", json!("different-fingerprint-instance")),
        ("generation", json!(scope["generation"].as_u64().context("fingerprint generation missing")? + 1)),
    ] {
        let mut request = original.clone();
        request["scope"][field] = value;
        changes.push((request, "scope_mismatch"));
    }
    // cli.exec fingerprints the argument vector, not CLI flag semantics.
    let mut reordered = original.clone();
    reordered["args"] = json!(["--json","remember","idempotent-rpc-marker",
        "--title","Idempotent RPC effect","--force","--importance","important"]);
    changes.push((reordered, "idempotency_conflict"));
    for (index, (mut request, expected)) in changes.into_iter().enumerate() {
        request["id"] = json!(format!("fingerprint-dimension-{index}"));
        let rejected = post(request)?;
        assert_eq!(rejected["ok"], false, "{rejected}");
        assert_eq!(rejected["code"], expected);
        unchanged()?;
    }
    // Schema rejection has an HTTP error body, not a fabricated RPC envelope.
    for (index, mut malformed) in [original.clone(), original.clone()].into_iter().enumerate() {
        if index == 0 { malformed["schema_version"] = json!(1); }
        else { malformed["scope"]["generation"] = json!("not-an-integer"); }
        let (status, rejected) = send(malformed)?;
        assert_eq!(status, 400);
        assert!(rejected["error"].as_str().is_some());
        assert!(rejected.get("envelope").is_none());
        unchanged()?;
    }
    // This is failure replay: Configure rejects absent profiles before registry I/O.
    let canonical = json!({"v":1,"id":"canonical-json-first","method":"model.configure",
        "operation_id":"canonical-json-operation","idempotency_key":"canonical-json-operation",
        "scope":scope,"args":[r#"{"model_profile":null,"backend_profile":null}"#]});
    let failed = post(canonical.clone())?;
    assert_eq!(failed["ok"], false);
    assert_eq!(failed["code"], "model_profile_failed");
    unchanged()?;
    let mut equivalent = canonical.clone();
    equivalent["id"] = json!("canonical-json-reordered");
    equivalent["args"][0] = json!("{ \"backend_profile\": null, \"model_profile\": null }");
    let replayed = post(equivalent)?;
    assert_eq!(replayed["ok"], false);
    assert_eq!(replayed["code"], "model_profile_failed");
    unchanged()?;
    let canonical_receipt = result("canonical-json-operation", "canonical-json-receipt")?;
    assert_eq!(canonical_receipt["envelope"]["summary"]["state"], "failed");
    assert_eq!(canonical_receipt["envelope"]["summary"]["response"], failed);
    assert_eq!(canonical_receipt["envelope"]["summary"]["response"]["id"], "canonical-json-first",
        "normalized JSON must replay without overwriting the first receipt");
    let mut different = canonical;
    different["id"] = json!("canonical-json-structurally-different");
    different["args"][0] = json!(r#"{"model_profile":null}"#);
    let rejected = post(different)?;
    assert_eq!(rejected["ok"], false);
    assert_eq!(rejected["code"], "idempotency_conflict");
    unchanged()?;
    support::legacy_receipt("diary_identity::concurrent_same_day_client_commands_preserve_each_successful_addition_once", "candidate_runtime")?;
    Ok(())
}

/// Old appends copied the routing owner into the encrypted author without changing ID.
#[test]
fn old_owner_normalized_diary_keeps_its_author_after_public_title_edit() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let session_path = fixture.home.path().join("data/session.json");
    let mut session: Value = serde_json::from_slice(&std::fs::read(&session_path)?)?;
    session["user"] = json!("synthetic-account-owner");
    std::fs::write(session_path, serde_json::to_vec(&session)?)?;
    let day = day();
    let id = track_id("synthetic-diary", &day);
    // This is the payload produced by dev.7 after an owner-normalizing pull + append.
    let legacy = entry(
        &id,
        "synthetic-account-owner",
        &format!("\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} {day}"),
        "old-owner-event",
    );
    fixture.seed(&legacy, false)?;
    fixture.seed(
        &entry(
            "old-owner-legacy",
            "synthetic-account-owner",
            &format!("\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} {day}"),
            "old-owner-legacy-event",
        ),
        false,
    )?;
    fixture.start()?;
    fixture.run(&[
        "update",
        &id,
        "--title",
        "Renamed old owner-normalized diary",
    ])?;
    fixture.remember("new-owner-event")?;
    let saved = fixture.show(&id)?;
    assert_eq!(saved["user"], "synthetic-account-owner");
    assert_eq!(saved["title"], "Renamed old owner-normalized diary");
    let content = saved["content"]
        .as_str()
        .context("synthetic response string missing")?;
    for marker in [
        "old-owner-event",
        "old-owner-legacy-event",
        "new-owner-event",
    ] {
        assert_eq!(content.matches(marker).count(), 1);
    }
    support::legacy_receipt("diary_identity::old_owner_normalized_diary_keeps_its_author_after_public_title_edit", "candidate_runtime")?;
    Ok(())
}

/// Different payload authors cannot borrow a canonical ID or a matching wire owner.
#[test]
fn unrelated_canonical_author_fails_without_writes_or_private_output() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let day = day();
    fixture.seed_with_owner(
        &entry(
            &track_id("synthetic-diary", &day),
            "foreign-private-author",
            "Renamed foreign track",
            "foreign-private-event",
        ),
        false,
        "synthetic-diary",
    )?;
    fixture.seed(
        &entry(
            "legacy-must-survive",
            "synthetic-diary",
            &format!("\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} {day}"),
            "legacy-live-event",
        ),
        false,
    )?;
    fixture.start()?;
    fixture.assert_author_rejection()?;
    support::legacy_receipt("diary_identity::unrelated_canonical_author_fails_without_writes_or_private_output", "candidate_runtime")?;
    Ok(())
}

/// Environment fallback keys must not inherit the failed local session's owner alias.
#[test]
fn environment_key_fallback_does_not_adopt_unlocked_profile_alias() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let session_path = fixture.home.path().join("data/session.json");
    let mut session: Value = serde_json::from_slice(&std::fs::read(&session_path)?)?;
    session["user"] = json!("foreign-private-author");
    // Preserve a readable profile, but force local unlock to fail before env fallback.
    session["wrapped_urk"] = json!("rsrs:v1:00");
    std::fs::write(session_path, serde_json::to_vec(&session)?)?;
    let salt = "13".repeat(16);
    let password = "synthetic-fallback-password";
    let account_secret = "synthetic-fallback-secret";
    let kek = crypto::derive_rsrs_password_kek(password, account_secret, &salt)?;
    let (nonce, wrapped) = crypto::wrap_key(&fixture.keys.urk, &kek)?;
    fixture.extra_env = vec![
        ("RSRS_PASS", password.into()),
        ("RSRS_SECRET", account_secret.into()),
        ("RSRS_KDF_SALT", salt),
        (
            "RSRS_WRAPPED_URK",
            format!("{}{wrapped}", crypto::RSRS_PREFIX),
        ),
        ("RSRS_URK_NONCE", nonce),
    ];
    let day = day();
    let id = track_id("synthetic-diary", &day);
    fixture.seed(
        &entry(
            &id,
            "foreign-private-author",
            "Renamed unrelated profile",
            "foreign-private-event",
        ),
        false,
    )?;
    fixture.start()?;
    // A successful full read proves the environment keys can actually decrypt this vault.
    assert_eq!(fixture.show(&id)?["user"], "foreign-private-author");
    fixture.assert_author_rejection()?;
    support::legacy_receipt("diary_identity::environment_key_fallback_does_not_adopt_unlocked_profile_alias", "candidate_runtime")?;
    Ok(())
}

/// Important remember retains full bodies, synchronized fields, and outbox bytes.
#[test]
fn important_remember_pending_candidates_preserve_ciphertext_and_outbox() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let content = "synthetic orchard irrigation moisture sensor maintenance ".repeat(48);
    let mut original = entry(
        "important-candidate",
        "synthetic-diary",
        "Orchard maintenance",
        &content,
    );
    original.importance = "important".into();
    original.parent_id.clear();
    fixture.seed(&original, false)?;
    fixture.start()?;
    let before = serde_json::to_value(fixture.store()?.all(true)?)?;
    let boundary = fixture.store()?.outgoing_boundary()?;
    let outgoing = serde_json::to_value(fixture.store()?.outgoing()?)?;
    anyhow::ensure!(fixture.owns_runtime()?, "synthetic runtime is not ready");
    let output = fixture.business_output(&[
        "--client-only",
        "--json",
        "remember",
        &content,
        "--importance",
        "important",
    ])?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "pending candidates use the public pending exit code"
    );
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["errors"], serde_json::json!([]));
    assert_eq!(result["status"], "pending");
    assert_eq!(result["summary"]["written"], false);
    assert_eq!(result["summary"]["state"], "candidates");
    assert_eq!(result["summary"]["merge_count"], 1);
    assert!(result["actions"]
        .as_array()
        .context("candidate actions missing")?
        .iter()
        .any(|action| action
            .as_str()
            .is_some_and(|text| text.contains("--merge-ids \"important-candidate\""))));
    assert_eq!(fixture.show("important-candidate")?["content"], content);
    assert!(
        before == serde_json::to_value(fixture.store()?.all(true)?)?,
        "candidate lookup mutated synchronized record fields"
    );
    assert_eq!(boundary, fixture.store()?.outgoing_boundary()?);
    assert!(
        outgoing == serde_json::to_value(fixture.store()?.outgoing()?)?,
        "candidate lookup mutated outbox"
    );
    support::legacy_receipt("diary_identity::important_remember_pending_candidates_preserve_ciphertext_and_outbox", "candidate_runtime")?;
    Ok(())
}


// Hold a real provider request until the native stop assertions release it.
struct HeldClassifyProvider {
    endpoint: String,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    release: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    received: std::sync::mpsc::Receiver<()>,
    worker: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
}

impl HeldClassifyProvider {
    fn new() -> anyhow::Result<Self> {
        Self::with_response(None)
    }

    fn with_response(response: Option<Value>) -> anyhow::Result<Self> {
        use std::sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc};
        let server = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!("loopback provider bind: {error}"))?;
        let endpoint = format!("http://{}/classify", server.server_addr());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (send, received) = std::sync::mpsc::channel();
        let (count, released, stopped) = (calls.clone(), release.clone(), stop.clone());
        let worker = std::thread::spawn(move || -> anyhow::Result<()> {
            let mut held = Vec::<tiny_http::Request>::new();
            loop {
                if released.load(Ordering::Acquire) || stopped.load(Ordering::Acquire) {
                    for request in held.drain(..) {
                        if let Some(response) = response.as_ref() {
                            request.respond(tiny_http::Response::from_string(serde_json::to_string(response)?)
                                .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json")
                                    .map_err(|_| anyhow::anyhow!("provider content-type header"))?))
                                .context("send held loopback HTTP 200")?;
                        } else {
                            // Keep the existing terminal failure cases unchanged.
                            request.respond(tiny_http::Response::empty(401))
                                .context("send terminal loopback HTTP 401")?;
                        }
                    }
                }
                if stopped.load(Ordering::Acquire) { break; }
                let Some(request) = server.recv_timeout(Duration::from_millis(100))? else { continue };
                count.fetch_add(1, Ordering::AcqRel);
                anyhow::ensure!(request.method() == &tiny_http::Method::Post
                    && request.url() == "/classify", "unexpected provider request");
                anyhow::ensure!(request.headers().iter().any(|header|
                    header.field.equiv("Authorization")
                        && header.value.as_str() == "Bearer synthetic-native-stop-key"),
                    "synthetic provider authentication missing");
                held.push(request);
                let _ = send.send(());
            }
            Ok(())
        });
        Ok(Self { endpoint, calls, release, stop, received, worker: Some(worker) })
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        self.release.store(true, std::sync::atomic::Ordering::Release);
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| anyhow::anyhow!("loopback provider panicked"))??;
        }
        Ok(())
    }
}

impl Drop for HeldClassifyProvider {
    fn drop(&mut self) {
        self.release.store(true, std::sync::atomic::Ordering::Release);
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {},
                other => eprintln!("loopback provider cleanup failed: {other:?}"),
            }
        }
    }
}

fn stop_native_post(url: &str, request: &Value) -> anyhow::Result<(u16, Value)> {
    let response = match ureq::AgentBuilder::new().try_proxy_from_env(false).build()
        .post(url).timeout(Duration::from_secs(90))
        .set("X-Respire-Lifecycle", "coordinator-v1").send_json(request.clone()) {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => return Err(error.into()),
    };
    Ok((response.status(), response.into_json()?))
}

fn stop_native_worker_identity(pid: u32) -> anyhow::Result<Option<Value>> {
    #[cfg(windows)]
    {
        return Ok(respire_spawn::process_identity(pid)?.map(|identity|
            json!({"birth":identity.birth,"image":identity.executable})));
    }
    #[cfg(target_os = "linux")]
    {
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let fields: Vec<_> = stat[stat.rfind(')').context("worker stat name missing")? + 1..]
            .split_whitespace().collect();
        if fields.first() == Some(&"Z") { return Ok(None); }
        let image = match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(image) => image,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        return Ok(Some(json!({"birth":fields.get(19).context("worker birth missing")?,
            "parent":fields.get(1).context("worker parent missing")?.parse::<u32>()?,"image":image})));
    }
    #[cfg(target_os = "macos")]
    {
        let read = |field: &str| -> anyhow::Result<Option<String>> {
            let output = Command::new("ps").args(["-p", &pid.to_string(), "-o", field]).output()?;
            if !output.status.success() { return Ok(None); }
            let value = String::from_utf8(output.stdout)?.trim().to_owned();
            Ok((!value.is_empty()).then_some(value))
        };
        let Some(birth) = read("lstart=")? else { return Ok(None) };
        let Some(image) = read("comm=")? else { return Ok(None) };
        let Some(parent) = read("ppid=")? else { return Ok(None) };
        return Ok(Some(json!({"birth":birth,"parent":parent.parse::<u32>()?,"image":image})));
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    anyhow::bail!("native worker identity is unsupported on this target")
}

impl Fixture {
    fn start_standalone_for_stop(&mut self) -> anyhow::Result<Value> {
        anyhow::ensure!(self.child.is_none(), "standalone fixture already running");
        let template = self.command(&[]);
        let mut command = Command::new(&self.runtime);
        for (name, value) in template.get_envs() {
            match value { Some(value) => { command.env(name, value); }, None => { command.env_remove(name); } }
        }
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            command.env_remove(name);
        }
        let root = self.home.path().join("data");
        self.child = Some(command.args(["serve", "--host", "127.0.0.1", "--port", &self.port.to_string(),
            "--data-dir", root.to_str().context("fixture root is not UTF-8")?])
            .current_dir(self.home.path())
            .env("TYPESAFE_API_KEY", "synthetic-native-stop-key")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .stdout(std::fs::File::create(self.home.path().join("stop-runtime.stdout"))?)
            .stderr(std::fs::File::create(self.home.path().join("stop-runtime.stderr"))?).spawn()?);
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            anyhow::ensure!(self.child.as_mut().context("runtime child missing")?.try_wait()?.is_none(),
                "standalone Runtime exited before readiness");
            if let Ok(health) = self.standalone_stop_health() {
                if health["store_ready"] == true { return Ok(health); }
            }
            anyhow::ensure!(std::time::Instant::now() < deadline, "standalone Runtime readiness timed out");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn standalone_stop_health(&self) -> anyhow::Result<Value> {
        let health: Value = ureq::AgentBuilder::new().try_proxy_from_env(false).build()
            .get(&format!("http://127.0.0.1:{}/api/health", self.port))
            .timeout(Duration::from_secs(3)).call()?.into_json()?;
        let pid = self.child.as_ref().context("runtime child missing")?.id();
        anyhow::ensure!(pid != std::process::id() && health["pid"] == pid, "unexpected Runtime process");
        for field in ["image_path", "exe"] {
            anyhow::ensure!(Path::new(health[field].as_str().context("Runtime image missing")?)
                .canonicalize()? == self.runtime, "standalone Runtime image mismatch");
        }
        let root = self.home.path().join("data").canonicalize()?;
        for field in ["installation_root", "data_dir"] {
            anyhow::ensure!(Path::new(health[field].as_str().context("Runtime root missing")?)
                .canonicalize()? == root, "standalone Runtime root mismatch");
        }
        Ok(health)
    }

    fn assert_standalone_stop_lock_held(&self) -> anyhow::Result<()> {
        let owner = self.child.as_ref().context("Runtime owner missing")?.id();
        anyhow::ensure!(owner != std::process::id(), "lock check must run outside the Runtime process");
        match respire::lock::LibraryLock::acquire(&self.home.path().join("data"), Duration::from_millis(100)) {
            Ok(_) => anyhow::bail!("Runtime released its library lock before business cleanup"),
            Err(error) => anyhow::ensure!(error.to_string().starts_with("memory library still locked after "),
                "library lock check failed without proving contention: {error:#}"),
        }
        Ok(())
    }

    fn finish_standalone_stop(&mut self, health: &Value, operation: &Value, forced: bool) -> anyhow::Result<Value> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = self.child.as_mut().context("runtime child missing")?.try_wait()? { break status; }
            anyhow::ensure!(std::time::Instant::now() < deadline, "Runtime did not finish native stop");
            std::thread::sleep(Duration::from_millis(50));
        };
        self.child.take();
        assert_eq!(status.code(), Some(if forced { 1 } else { 0 }));
        let receipt: Value = serde_json::from_slice(&std::fs::read(self.home.path().join("data/runtime")
            .join(format!("stop-{}.json", health["instance_id"].as_str().context("instance missing")?)))?)?;
        assert_eq!(receipt["schema_version"], 1);
        assert_eq!(receipt["protocol_version"], 1);
        assert_eq!(receipt["operation_id"], *operation);
        for key in ["installation_id", "instance_id", "pid", "process_start_id", "image_path", "image_sha256", "runtime_version", "account_id", "generation"] {
            assert_eq!(receipt[key], health[key], "final stop identity changed: {key}");
        }
        assert_eq!(receipt["state"], if forced { "forced_timeout" } else { "drained" });
        match std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{}", self.port).parse()?, Duration::from_secs(2)) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {},
            other => anyhow::bail!("stopped listener did not refuse a fresh connection: {other:?}"),
        }
        // This harness process is distinct from the Runtime owner; use the actual file-lock API.
        let ownership = respire::lock::LibraryLock::acquire(&self.home.path().join("data"), Duration::from_secs(1))?;
        drop(ownership);
        Ok(receipt)
    }
}

struct StopWriteEvidence {
    root_id: String,
    child_id: String,
    parent_id: String,
    child: MemoryEntry,
    original_root: StoredMemory,
    original_child: StoredMemory,
    original_parent: StoredMemory,
    before_boundary: i64,
    before_outgoing: std::collections::HashSet<String>,
}

impl StopWriteEvidence {
    fn seed(fixture: &Fixture) -> anyhow::Result<Self> {
    let root_id = uuid::Uuid::new_v4().simple().to_string();
    let child_id = uuid::Uuid::new_v4().simple().to_string();
    let parent_id = uuid::Uuid::new_v4().simple().to_string();
    assert_ne!(&root_id[..8], &child_id[..8]);
    assert_ne!(&root_id[..8], &parent_id[..8]);
    assert_ne!(&child_id[..8], &parent_id[..8]);
    let mut root = entry(&root_id, "synthetic-diary", "Accepted write root", "Synthetic classification root");
    root.parent_id.clear();
    root.importance = "important".into();
    let mut child = entry(&child_id, "synthetic-diary", "Accepted write child", "Synthetic encrypted child");
    child.parent_id = root_id.clone();
    child.importance = "important".into();
    let mut parent = entry(&parent_id, "synthetic-diary", "Accepted write parent", "Synthetic encrypted parent");
    parent.parent_id = root_id.clone();
    parent.importance = "important".into();
    let original_root = fixture.seed(&root, false)?;
    let original_child = fixture.seed(&child, false)?;
    let original_parent = fixture.seed(&parent, false)?;
    let before_boundary = fixture.store()?.outgoing_boundary()?;
    let before_outgoing: std::collections::HashSet<_> = fixture.store()?.outgoing()?.into_iter()
        .map(|operation| operation.op_id).collect();

        Ok(Self { root_id, child_id, parent_id, child, original_root, original_child,
            original_parent, before_boundary, before_outgoing })
    }

    fn provider(&self) -> anyhow::Result<HeldClassifyProvider> {
        HeldClassifyProvider::with_response(Some(json!({"choices":[{"message":{"content":
            format!("{} > {}", &self.child_id[..8], &self.parent_id[..8])}}]})))
    }

    fn args(&self, endpoint: &str) -> Vec<String> {
        ["--json", "classify", "--backend", "jev", "--api-base", endpoint,
            "--auto", "--rounds", "1", "--min-kids", "2", "--segments", "1",
            "--limit", "3", "--samples", "1"].into_iter().map(str::to_owned).collect()
    }

    fn assert_result(&self, result: &Value, request: &Value) {
        for key in ["v", "id", "operation_id", "scope", "idempotency_key"] {
            assert_eq!(result[key], request[key], "accepted write identity changed: {key}");
        }
        assert_eq!(result["ok"], true);
        assert_eq!(result["exit"], 0);
        assert_eq!(result["envelope"]["command"], "classify");
        assert_eq!(result["envelope"]["status"], "ok");
        assert_eq!(result["envelope"]["details"]["applied"], 1);
        assert_eq!(result["envelope"]["details"]["ops"], json!([{"id":self.child_id,"parent":self.parent_id}]));
    }

    fn assert_committed(&self, fixture: &Fixture) -> anyhow::Result<()> {
        let root_id = self.root_id.as_str();
        let child_id = self.child_id.as_str();
        let parent_id = self.parent_id.as_str();
        let child = &self.child;
        let original_root = &self.original_root;
        let original_child = &self.original_child;
        let original_parent = &self.original_parent;
        let before_boundary = self.before_boundary;
        let before_outgoing = &self.before_outgoing;
    let after = fixture.store()?.all(true)?;
    assert_eq!(after.len(), 3);
    let written = after.iter().find(|row| row.id == child_id).context("committed child missing")?;
    assert_ne!(written.ciphertext, original_child.ciphertext);
    assert_ne!(written.nonce, original_child.nonce);
    assert_eq!(written.local_parent_id, parent_id);
    let opened = MemoryEngine::open(&fixture.keys, written)?;
    assert_eq!(opened.parent_id, parent_id);
    assert_eq!(MemoryEngine::payload_parent(&fixture.keys, written)?, parent_id);
    assert_eq!(opened.content, child.content);
    assert!(fixture.store()?.outgoing_boundary()? > before_boundary);
    let outgoing = fixture.store()?.outgoing()?;
    let added: Vec<_> = outgoing.iter().filter(|operation| !before_outgoing.contains(&operation.op_id)).collect();
    assert!(added.iter().any(|operation| operation.blob.id == child_id
        && operation.blob.ciphertext == written.ciphertext && operation.blob.nonce == written.nonce),
        "committed encrypted child is missing from the actual outbox");
    for operation in added {
        let expected = if operation.blob.id == child_id { written }
            else if operation.blob.id == root_id { &original_root }
            else if operation.blob.id == parent_id { &original_parent }
            else { anyhow::bail!("unexpected memory in the accepted-write outbox") };
        assert_eq!(operation.blob.ciphertext, expected.ciphertext);
        assert_eq!(operation.blob.nonce, expected.nonce);
        if operation.blob.id == child_id {
            assert_eq!(MemoryEngine::payload_parent(&fixture.keys, &operation.blob)?, parent_id);
        }
    }
    for original in [original_root, original_parent] {
        let unchanged = after.iter().find(|row| row.id == original.id).context("unchanged row missing")?;
        assert_eq!(unchanged.ciphertext, original.ciphertext);
        assert_eq!(unchanged.nonce, original.nonce);
        assert_eq!(unchanged.local_parent_id, original.local_parent_id);
    }

        Ok(())
    }

    fn assert_uncommitted(&self, fixture: &Fixture) -> anyhow::Result<()> {
        let rows = fixture.store()?.all(true)?;
        assert_eq!(rows.len(), 3);
        for original in [&self.original_root, &self.original_child, &self.original_parent] {
            let row = rows.iter().find(|row| row.id == original.id).context("forced fixture row missing")?;
            assert_eq!(row.ciphertext, original.ciphertext);
            assert_eq!(row.nonce, original.nonce);
            assert_eq!(row.local_parent_id, original.local_parent_id);
        }
        for operation in fixture.store()?.outgoing()? {
            let original = [&self.original_root, &self.original_child, &self.original_parent]
                .into_iter().find(|row| row.id == operation.blob.id)
                .context("forced outbox contains an unexpected memory")?;
            assert_eq!(operation.blob.ciphertext, original.ciphertext);
            assert_eq!(operation.blob.nonce, original.nonce);
        }
        Ok(())
    }
}

fn stop_native_commits_accepted_encrypted_write_after_drain() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    let mut fixture = Fixture::new()?;
    let write = StopWriteEvidence::seed(&fixture)?;
    let health = fixture.start_standalone_for_stop()?;
    assert!(health["managed_id"].is_null());
    let mut provider = write.provider()?;
    let rpc_url = format!("http://127.0.0.1:{}/api/rpc", fixture.port);
    let stop_url = format!("http://127.0.0.1:{}/api/runtime/stop", fixture.port);
    let scope = json!({"account_id":health["account_id"],"instance_id":health["instance_id"],"generation":health["generation"]});
    let business_operation = "native-stop-successful-encrypted-write";
    let request = json!({"v":1,"id":"native-stop-held-write","method":"cli.exec",
        "operation_id":business_operation,"idempotency_key":business_operation,"scope":scope,
        "args":write.args(&provider.endpoint)});
    let (url, original) = (rpc_url.clone(), request.clone());
    let business = std::thread::spawn(move || stop_native_post(&url, &original));
    provider.received.recv_timeout(Duration::from_secs(30))
        .context("real Core causal classification did not reach the held provider")?;
    let held_at = std::time::Instant::now();
    let active = fixture.standalone_stop_health()?;
    assert!(active["control"]["admitted"].as_array().context("admission list missing")?.iter()
        .any(|item| item["operation_id"] == business_operation));
    let worker_pid = u32::try_from(active["inference"]["worker_pid"].as_u64().context("Core PID missing")?)?;
    let worker_identity = stop_native_worker_identity(worker_pid)?.context("Core worker not live")?;
    assert_eq!(Path::new(worker_identity["image"].as_str().context("Core image missing")?).canonicalize()?, fixture.runtime);
    if let Some(parent) = worker_identity.get("parent") { assert_eq!(*parent, health["pid"]); }
    assert!(active["inference"]["worker_pending_calls"].as_u64().is_some_and(|count| count > 0));
    assert!(active["inference"]["worker_host_callbacks_active"].as_u64().is_some_and(|count| count > 0));
    std::thread::sleep(Duration::from_millis(4200));
    assert!(!business.is_finished());
    let business_before_stop_ms = held_at.elapsed().as_millis();
    assert!(business_before_stop_ms > 4000);
    fixture.assert_standalone_stop_lock_held()?;
    let identity = json!({"installation_id":health["installation_id"],"instance_id":health["instance_id"],
        "account_id":health["account_id"],"generation":health["generation"]});
    let (status, accepted) = stop_native_post(&stop_url, &identity)?;
    assert_eq!(status, 200);
    assert_eq!(accepted["state"], "accepted");
    assert!(accepted["deadline_ms"].is_null() && accepted["timeout_state"].is_null());
    let accepted_at = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(4200));
    let held = fixture.standalone_stop_health()?;
    assert_eq!(held["control"]["state"], "draining");
    assert_eq!(held["inference"]["worker_retired"], false);
    assert_eq!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
    assert!(!business.is_finished());
    fixture.assert_standalone_stop_lock_held()?;
    let business_held_after_stop_ms = accepted_at.elapsed().as_millis();
    assert!(business_held_after_stop_ms > 4000);
    let mut replay = request.clone();
    replay["id"] = json!("native-stop-held-write-same-key");
    let (_, pending) = stop_native_post(&rpc_url, &replay)?;
    assert_eq!(pending["code"], "request_in_progress");
    assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    provider.release.store(true, Ordering::Release);
    let (_, result) = business.join().map_err(|_| anyhow::anyhow!("accepted write client panicked"))??;
    write.assert_result(&result, &request);
    let receipt = fixture.finish_standalone_stop(&health, &accepted["operation_id"], false)?;
    assert_eq!(receipt["unfinished"], json!([]));
    assert_ne!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
    write.assert_committed(&fixture)?;
    provider.finish()?;
    assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    eprintln!("NATIVE_ACCEPTED_WRITE_RAW {}", json!({"schema":1,"evidence_class":"native-raw","gate":"not-evaluated",
        "startup_mode":"standalone","runtime_identity":health,"worker_identity":worker_identity,
        "active_health":active,"held_health":held,"business_before_stop_ms":business_before_stop_ms,
        "business_held_after_stop_ms":business_held_after_stop_ms,"accepted":accepted,
        "business_result":result,"final_receipt":receipt,"provider_http_status":200,
        "provider_requests":provider.calls.load(Ordering::Acquire),"same_key_result":pending,
        "encrypted_write_committed":true,"plaintext_parent_matches_encrypted_payload":true}));
    Ok(())
}

#[test]
fn native_stop_waits_and_explicit_force_reaps_real_core_without_replay() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    enum OwnedStopMode { Registered, Client2Owned }
    let owned_mode = match std::env::var_os("RSRS_TEST_NATIVE_OWNED_STOP") {
        None => None,
        Some(mode) if mode == "registered" => Some(OwnedStopMode::Registered),
        Some(mode) if mode == "client2-owned" => Some(OwnedStopMode::Client2Owned),
        Some(_) => anyhow::bail!("unsupported native owned-stop fixture mode"),
    };
    stop_native_commits_accepted_encrypted_write_after_drain()?;
    match owned_mode {
        Some(OwnedStopMode::Registered) => stop_native_registered_held_write()?,
        Some(OwnedStopMode::Client2Owned) => stop_native_client2_owned_held_write()?,
        None => {},
    }
    for forced in [false, true] {
        let checkpoint = |stage: &str| eprintln!("NATIVE_STOP_CHECKPOINT mode={} stage={stage}",
            if forced { "forced" } else { "normal" });
        checkpoint("start");
        let mut fixture = Fixture::new()?;
        checkpoint("fixture_ready");
        let mut memory = entry("native-stop-source", "synthetic-diary", "Native classification source", "Synthetic native stop evidence");
        memory.parent_id.clear();
        memory.importance = "important".into();
        fixture.seed(&memory, false)?;
        checkpoint("memory_seeded");
        let before = serde_json::to_value(fixture.store()?.all(true)?)?;
        let health = fixture.start_standalone_for_stop()?;
        checkpoint("runtime_ready");
        assert!(health["managed_id"].is_null(), "standalone case must not bypass a lifecycle coordinator");
        let mut provider = HeldClassifyProvider::new()?;
        let rpc_url = format!("http://127.0.0.1:{}/api/rpc", fixture.port);
        let stop_url = format!("http://127.0.0.1:{}/api/runtime/stop", fixture.port);
        let scope = json!({"account_id":health["account_id"],"instance_id":health["instance_id"],"generation":health["generation"]});
        let business_operation = format!("native-stop-classify-{forced}");
        let request = json!({"v":1,"id":"native-stop-original","method":"cli.exec",
            "operation_id":business_operation,"idempotency_key":business_operation,"scope":scope,
            "args":["--json","classify","--backend","jev","--api-base",provider.endpoint,"--limit","1","--samples","1"]});
        let (url, original) = (rpc_url.clone(), request.clone());
        let business = std::thread::spawn(move || stop_native_post(&url, &original));
        provider.received.recv_timeout(Duration::from_secs(30))
            .context("actual SDK classification did not reach the loopback provider")?;
        checkpoint("provider_received");
        let io_started = std::time::Instant::now();
        let active = fixture.standalone_stop_health()?;
        assert!(active["control"]["admitted"].as_array().context("admission list missing")?.iter()
            .any(|item| item["operation_id"] == business_operation));
        let worker = &active["inference"];
        assert!(worker["worker_pending_calls"].as_u64().is_some_and(|count| count > 0));
        assert!(worker["worker_call_deadline_secs"].as_u64().is_some_and(|seconds| seconds >= 30),
            "a short Core fault-test deadline must not substitute for explicit stop force");
        assert!(worker["worker_host_callbacks_active"].as_u64().is_some_and(|count| count > 0));
        assert_eq!(worker["worker_retired"], false);
        assert_eq!(worker["worker_reaped"], false);
        let worker_pid = u32::try_from(worker["worker_pid"].as_u64().context("actual Core worker PID missing")?)?;
        let worker_identity = stop_native_worker_identity(worker_pid)?.context("actual Core worker was not live")?;
        assert_eq!(Path::new(worker_identity["image"].as_str().context("worker OS image missing")?).canonicalize()?, fixture.runtime);
        if let Some(parent) = worker_identity.get("parent") { assert_eq!(*parent, health["pid"]); }
        fixture.assert_standalone_stop_lock_held()?;
        checkpoint("active_verified");
        std::thread::sleep(Duration::from_millis(4200));
        assert_eq!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
        assert!(!business.is_finished(), "real business completed before stop");
        let business_before_stop_ms = io_started.elapsed().as_millis();
        assert!(business_before_stop_ms > 4000);
        let identity = json!({"installation_id":health["installation_id"],"instance_id":health["instance_id"],
            "account_id":health["account_id"],"generation":health["generation"]});
        let (status, accepted) = stop_native_post(&stop_url, &identity)?;
        assert_eq!(status, 200);
        assert_eq!(accepted["state"], "accepted");
        assert!(accepted["deadline_ms"].is_null() && accepted["timeout_state"].is_null());
        let operation = accepted["operation_id"].clone();
        anyhow::ensure!(operation.as_str().is_some_and(|id| !id.is_empty()), "stop operation missing");
        checkpoint("stop_accepted");
        let accepted_at = std::time::Instant::now();
        let mut force_requests = Vec::new();
        let held_health;
        if forced {
            let mut force = identity.clone();
            force["force"] = json!(true);
            force["operation_id"] = operation.clone();
            for key in ["installation_id", "instance_id", "account_id", "generation", "operation_id"] {
                let mut stale = force.clone();
                stale[key] = if key == "generation" { json!(0) } else { json!("stale-stop-target") };
                assert_eq!(stop_native_post(&stop_url, &stale)?.0, 409);
                assert!(fixture.standalone_stop_health()?["inference"]["worker_retired"] == false);
                assert!(stop_native_post(&stop_url, &identity)?.1["deadline_ms"].is_null());
            }
            let mut missing = force.clone();
            missing.as_object_mut().context("force body missing")?.remove("operation_id");
            assert_eq!(stop_native_post(&stop_url, &missing)?.0, 409);
            assert!(stop_native_post(&stop_url, &identity)?.1["deadline_ms"].is_null());
            checkpoint("force_identities_rejected");
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            let mut previous_ms = 4000;
            let mut request_ids = std::collections::HashSet::new();
            loop {
                let (status, response) = stop_native_post(&stop_url, &force)?;
                assert_eq!(status, 200);
                assert_eq!(response["operation_id"], operation);
                assert_eq!(response["state"], "accepted");
                assert_eq!(response["timeout_state"], "forced_timeout");
                assert_ne!(response["request_id"], accepted["request_id"]);
                let remaining = response["deadline_ms"].as_u64().context("force deadline missing")?;
                assert!(remaining <= previous_ms, "repeated force extended the grace period");
                previous_ms = remaining;
                assert!(request_ids.insert(response["request_id"].as_str().context("force request ID missing")?.to_owned()));
                force_requests.push(response);
                let observed = fixture.standalone_stop_health()?;
                let retired = &observed["inference"]["retired_worker"];
                if retired["worker_reaped"] == true {
                    assert_eq!(retired["worker_pid"], worker_pid);
                    assert_eq!(retired["worker_retired"], true);
                    assert!(observed["inference"]["host_transport_callbacks_active"].as_u64().is_some_and(|count| count > 0));
                    assert_ne!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
                    held_health = observed;
                    checkpoint("worker_reaped");
                    break;
                }
                anyhow::ensure!(std::time::Instant::now() < deadline, "repeated force prevented actual worker retirement");
                std::thread::sleep(Duration::from_millis(250));
            }
        } else {
            std::thread::sleep(Duration::from_millis(4200));
            let pending = fixture.standalone_stop_health()?;
            assert_eq!(pending["control"]["state"], "draining");
            assert_eq!(pending["inference"]["worker_pid"], worker_pid);
            assert_eq!(pending["inference"]["worker_retired"], false);
            assert_eq!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
            assert!(accepted_at.elapsed() > Duration::from_secs(4));
            held_health = pending;
            checkpoint("normal_waited");
        }
        let business_held_after_stop_ms = accepted_at.elapsed().as_millis();
        assert!(!business.is_finished(), "host callback was silently cancelled");
        fixture.assert_standalone_stop_lock_held()?;
        let mut replay = request.clone();
        replay["id"] = json!("native-stop-same-key-retry");
        let (_, replayed) = stop_native_post(&rpc_url, &replay)?;
        assert_eq!(replayed["code"], "request_in_progress");
        assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        checkpoint("same_key_checked");
        provider.release.store(true, Ordering::Release);
        let (_, result) = business.join().map_err(|_| anyhow::anyhow!("native business client panicked"))??;
        assert_eq!(result["id"], request["id"]);
        assert_eq!(result["operation_id"], business_operation);
        if forced { assert_eq!(result["ok"], false); }
        checkpoint("business_completed");
        let receipt = fixture.finish_standalone_stop(&health, &operation, forced)?;
        checkpoint("runtime_stopped");
        if forced {
            let unfinished = receipt["unfinished"].as_array().context("forced unfinished list missing")?;
            assert_eq!(unfinished.iter().filter(|item| item["operation_id"] == business_operation).count(), 1);
            assert!(unfinished.iter().any(|item| item["operation_id"] == business_operation && item["result"] == "unknown"));
            assert!(unfinished.iter().all(|item| item["result"] == "unknown" || item["result"] == "aborted"));
        } else { assert_eq!(receipt["unfinished"], json!([])); }
        assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        assert_eq!(serde_json::to_value(fixture.store()?.all(true)?)?, before, "classification changed stored memory");
        checkpoint("store_unchanged");
        let restarted = fixture.start_standalone_for_stop()?;
        checkpoint("restarted");
        assert_ne!(restarted["instance_id"], health["instance_id"]);
        replay["id"] = json!("native-stop-original-scope-after-restart");
        let (_, stale) = stop_native_post(&rpc_url, &replay)?;
        assert_eq!(stale["code"], "scope_mismatch");
        assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        checkpoint("stale_rejected");
        let restart_identity = json!({"installation_id":restarted["installation_id"],"instance_id":restarted["instance_id"],
            "account_id":restarted["account_id"],"generation":restarted["generation"]});
        let (_, stopped) = stop_native_post(&stop_url, &restart_identity)?;
        let restarted_receipt = fixture.finish_standalone_stop(&restarted, &stopped["operation_id"], false)?;
        checkpoint("restart_stopped");
        provider.finish()?;
        assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        checkpoint("complete");
        eprintln!("NATIVE_STOP_RAW {}", json!({"schema":1,"evidence_class":"native-raw","gate":"not-evaluated",
            "startup_mode":"standalone","forced":forced,"passed":true,"runtime_identity":health,
            "worker_identity":worker_identity,"active_health":active,"held_health":held_health,
            "business_before_stop_ms":business_before_stop_ms,"business_held_after_stop_ms":business_held_after_stop_ms,
            "accepted":accepted,"force_requests":force_requests,"business_result":result,
            "final_receipt":receipt,"provider_http_status":401,"provider_requests":provider.calls.load(Ordering::Acquire),
            "same_key_result":replayed,"stale_scope_result":stale,"restarted_receipt":restarted_receipt}));
    }
    Ok(())
}
// Explicit isolated native acceptance only: this installs a real user service.
// It is intentionally absent from ordinary cargo-test runs and G1 certificates.
fn owned_stop_checkpoint(startup_mode: &str, case: &str, stage: &str) {
    eprintln!("OWNED_STOP_CHECKPOINT {}", json!({"startup_mode":startup_mode,"case":case,"stage":stage}));
}

fn assert_owned_stop_lock_held(root: &Path, backend_pid: u32, backend_identity: &Value) -> anyhow::Result<()> {
    anyhow::ensure!(backend_pid != std::process::id(), "lock check must run outside the backend process");
    anyhow::ensure!(stop_native_worker_identity(backend_pid)?.as_ref() == Some(backend_identity),
        "backend identity changed before library lock observation");
    match respire::lock::LibraryLock::acquire(root, Duration::from_millis(100)) {
        Ok(_) => anyhow::bail!("owned Runtime released its library lock before business cleanup"),
        Err(error) => anyhow::ensure!(error.to_string().starts_with("memory library still locked after "),
            "library lock check failed without proving contention: {error:#}"),
    }
    anyhow::ensure!(stop_native_worker_identity(backend_pid)?.as_ref() == Some(backend_identity),
        "backend identity changed during library lock observation");
    Ok(())
}

struct RegisteredStopFixture {
    fixture: Option<Fixture>,
    alias: String,
    backends: Vec<String>,
    registration_attempted: bool,
}

impl RegisteredStopFixture {
    fn fixture(&self) -> anyhow::Result<&Fixture> {
        self.fixture.as_ref().context("registered fixture is unavailable")
    }

    fn command(&self, args: &[&str]) -> anyhow::Result<Command> {
        let fixture = self.fixture()?;
        let mut command = fixture.command(args);
        // The service must unlock the checkpointed OS credential itself.
        for name in ["RSRS_SUPER", "RSRS_USER", "RSRS_PASS", "TYPESAFE_API_KEY", "DS_API_KEY"] {
            command.env_remove(name);
        }
        command.env("RSRS_BIN_DIR", fixture.home.path().join("data/bin"));
        Ok(command)
    }

    fn probe_command(&self, probe: &Path, action: &str) -> anyhow::Result<Command> {
        let template = self.command(&[])?;
        let mut command = Command::new(probe);
        command.arg(action).current_dir(self.fixture()?.home.path());
        for (name, value) in template.get_envs() {
            match value { Some(value) => { command.env(name, value); }, None => { command.env_remove(name); } }
        }
        Ok(command)
    }

    fn run(&self, args: &[&str]) -> anyhow::Result<Value> {
        let output = self.command(args)?.output()?;
        anyhow::ensure!(output.status.success(), "registered lifecycle command failed with exit code {:?}", output.status.code());
        Ok(serde_json::from_slice::<Value>(&output.stdout)?["summary"].clone())
    }

    fn health(&self) -> anyhow::Result<Value> {
        let fixture = self.fixture()?;
        let health: Value = ureq::AgentBuilder::new().try_proxy_from_env(false).build()
            .get(&format!("http://127.0.0.1:{}/api/health", fixture.port))
            .set("X-Respire-Health", "runtime-v1")
            .timeout(Duration::from_secs(3)).call()?.into_json()?;
        let root = fixture.home.path().join("data").canonicalize()?;
        let registration: Value = serde_json::from_slice(&std::fs::read(root.join("runtime/autostart/registration.json"))?)?;
        anyhow::ensure!(registration["enabled"] == true && health["managed_id"] == registration["id"]
            && health["managed_id"].as_str().is_some_and(|id| !id.is_empty()), "not a registered supervisor child");
        for field in ["installation_root", "data_dir"] {
            anyhow::ensure!(Path::new(health[field].as_str().context("registered root missing")?).canonicalize()? == root,
                "registered Runtime root mismatch");
        }
        for field in ["image_path", "exe"] {
            anyhow::ensure!(Path::new(health[field].as_str().context("registered image missing")?).canonicalize()? == fixture.runtime,
                "registered Runtime image mismatch");
        }
        Ok(health)
    }

    fn cleanup(&mut self) -> anyhow::Result<()> {
        if self.registration_attempted {
            let summary = self.run(&["--json", "runtime", "autostart", "remove", "--stop"])?;
            anyhow::ensure!(summary["enabled"] == false && summary["registered"] == false
                && summary["runtime"]["running"] == false, "registered cleanup did not remove and stop the service");
            self.registration_attempted = false;
        }
        for backend in &self.backends {
            respire::keystore::remove_imported(&self.alias, "super", backend)?;
            anyhow::ensure!(respire::keystore::read_imported(&self.alias, "super", backend).is_err(),
                "registered credential remained after cleanup");
        }
        self.backends.clear();
        Ok(())
    }
}

impl Drop for RegisteredStopFixture {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            // Preserve the root/registration if owned cleanup fails; never delete
            // paths still referenced by a real registered service or hide failure.
            if let Some(fixture) = self.fixture.take() { std::mem::forget(fixture); }
            eprintln!("REGISTERED_STOP_CLEANUP_FAILED explicit owned recovery required");
        }
    }
}

fn stop_native_registered_held_write() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    use sha2::{Digest, Sha256};
    anyhow::ensure!(std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted"),
        "real OS registration requires an ephemeral GitHub-hosted runner");
    let probe = PathBuf::from(std::env::var_os("RSRS_CLIENT2_PROBE_BIN")
        .context("registered caller-timeout requires the source-bound original Go probe")?).canonicalize()?;
    anyhow::ensure!(probe.is_file(), "original Go probe is not a file");
    let probe_digest = format!("{:x}", Sha256::digest(std::fs::read(&probe)?));
    for mode in ["normal", "caller-timeout", "explicit-force"] {
    let checkpoint = |stage| owned_stop_checkpoint("registered", mode, stage);
    checkpoint("start");
    let fixture = Fixture::new()?;
    checkpoint("fixture_created");
    anyhow::ensure!(fixture.business_cli.is_none(), "registered control requires the bound modern CLI");
    let mut owned = RegisteredStopFixture { fixture: Some(fixture),
        alias: format!("login-{}", uuid::Uuid::new_v4().simple()), backends: Vec::new(), registration_attempted: false };
    let alias = owned.alias.clone();
    let secret = owned.fixture()?.secret.clone();
    checkpoint("credential_requested");
    let backend = respire::keystore::import_credential_checkpoint(&alias, "super", &secret, |backend| {
        anyhow::ensure!(matches!(backend, "native" | "secret_service"), "registered fixture requires persistent OS credentials");
        owned.backends.push(backend.to_owned());
        Ok(())
    })?;
    anyhow::ensure!(respire::keystore::read_imported(&alias, "super", backend)? == secret,
        "registered credential checkpoint readback mismatch");
    checkpoint("credential_ready");
    let fixture = owned.fixture.as_mut().context("fixture missing")?;
    let root = fixture.home.path().join("data");
    let mut session: Value = serde_json::from_slice(&std::fs::read(root.join("session.json"))?)?;
    session["keyring_account"] = json!(alias);
    session["keyring_backend"] = json!(backend);
    std::fs::write(root.join("session.json"), serde_json::to_vec(&session)?)?;
    // Use the existing public classification file contract, with only a synthetic key.
    anyhow::ensure!(respire::keystore::load_classify_key("typesafe").is_none(), "fixture classification slot is not empty");
    std::fs::write(root.join("classify.json"), br#"{"api_key":"synthetic-native-stop-key"}"#)?;
    checkpoint("runtime_install_requested");
    support::install_runtime_fixture(&root)?;
    let selected: Value = serde_json::from_slice(&std::fs::read(root.join("runtime.json"))?)?;
    fixture.runtime = root.join("runtime").join(selected["version"].as_str().context("installed version missing")?)
        .join(if cfg!(windows) { "rsrs-runtime.exe" } else { "rsrs-runtime" }).canonicalize()?;
    std::fs::create_dir_all(root.join("bin"))?;
    std::fs::copy(&fixture.cli, root.join("bin").join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" }))?;
    checkpoint("runtime_installed");
    let write = StopWriteEvidence::seed(fixture)?;
    checkpoint("memory_seeded");
    owned.registration_attempted = true;
    checkpoint("start_requested");
    let enabled = owned.run(&["--json", "runtime", "autostart", "enable", "--now"])?;
    anyhow::ensure!(enabled["enabled"] == true && enabled["registered"] == true, "real OS registration did not complete");
    checkpoint("start_complete");
    let health = owned.health()?;
    anyhow::ensure!(health["store_ready"] == true, "registered service could not unlock its actual persistent credential");
    checkpoint("health_bound");
    let fixture = owned.fixture()?;
    let runtime_pid = u32::try_from(health["pid"].as_u64().context("runtime PID missing")?)?;
    let runtime_identity = stop_native_worker_identity(runtime_pid)?.context("registered backend is not live")?;
    let claim: Value = serde_json::from_slice(&std::fs::read(root.join("runtime/autostart/launch")
        .join(format!("launch-{}.claimed", health["instance_id"].as_str().context("instance missing")?)))?)?;
    let grant_json = claim["grant_json"].as_str().context("consumed grant JSON missing")?;
    assert_eq!(claim["schema_version"], 2);
    assert_eq!(claim["grant_sha256"], format!("{:x}", Sha256::digest(grant_json.as_bytes())));
    let grant: Value = serde_json::from_str(grant_json)?;
    let supervisor_pid = u32::try_from(grant["supervisor_pid"].as_u64().context("supervisor PID missing")?)?;
    anyhow::ensure!(supervisor_pid != runtime_pid && supervisor_pid != std::process::id(), "supervisor identity collapsed into backend/harness");
    let supervisor_identity = stop_native_worker_identity(supervisor_pid)?.context("registered supervisor is not live")?;
    let registration: Value = serde_json::from_slice(&std::fs::read(root.join("runtime/autostart/registration.json"))?)?;
    anyhow::ensure!(Path::new(supervisor_identity["image"].as_str().context("supervisor image missing")?).canonicalize()?
        == Path::new(registration["executable"].as_str().context("registration executable missing")?).canonicalize()?
        && supervisor_identity["birth"] == grant["supervisor_birth"] && claim["pid"] == health["pid"]
        && grant["managed_id"] == health["managed_id"], "registered launcher/backend claim differs from live OS identity");
    let prefix = if cfg!(windows) { "windows-filetime-" } else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
    assert_eq!(health["process_start_id"], format!("{prefix}{}", claim["process_start_id"].as_str().context("claimed birth missing")?));
    assert_eq!(runtime_identity["birth"], claim["process_start_id"]);
    anyhow::ensure!(Path::new(runtime_identity["image"].as_str().context("backend OS image missing")?).canonicalize()? == fixture.runtime,
        "registered backend OS image mismatch");
    if let Some(parent) = runtime_identity.get("parent") { assert_eq!(*parent, json!(supervisor_pid)); }
    assert_eq!(health["image_sha256"], format!("{:x}", Sha256::digest(std::fs::read(&fixture.runtime)?)));
    checkpoint("actors_bound");
    let mut provider = write.provider()?;
    let rpc_url = format!("http://127.0.0.1:{}/api/rpc", fixture.port);
    let request = json!({"v":1,"id":"registered-stop-original","method":"cli.exec",
        "operation_id":"registered-stop-classify","idempotency_key":"registered-stop-classify",
        "scope":{"account_id":health["account_id"],"instance_id":health["instance_id"],"generation":health["generation"]},
        "args":write.args(&provider.endpoint)});
    let (url, original) = (rpc_url.clone(), request.clone());
    checkpoint("provider_requested");
    let business = std::thread::spawn(move || stop_native_post(&url, &original));
    provider.received.recv_timeout(Duration::from_secs(30)).context("registered business did not reach the actual provider")?;
    checkpoint("provider_received");
    let active = owned.health()?;
    assert!(active["control"]["admitted"].as_array().context("admissions missing")?.iter()
        .any(|item| item["operation_id"] == request["operation_id"]));
    let worker_pid = u32::try_from(active["inference"]["worker_pid"].as_u64().context("Core PID missing")?)?;
    let worker_identity = stop_native_worker_identity(worker_pid)?.context("actual Core worker missing")?;
    anyhow::ensure!(Path::new(worker_identity["image"].as_str().context("Core OS image missing")?).canonicalize()? == fixture.runtime,
        "registered Core OS image mismatch");
    if let Some(parent) = worker_identity.get("parent") { assert_eq!(*parent, json!(runtime_pid)); }
    assert!(active["inference"]["worker_host_callbacks_active"].as_u64().is_some_and(|n| n > 0));
    assert!(active["inference"]["worker_call_deadline_secs"].as_u64().is_some_and(|n| n >= 30));
    checkpoint("core_bound");
    assert_owned_stop_lock_held(&root, runtime_pid, &runtime_identity)?;
    std::thread::sleep(Duration::from_millis(4200));
    assert!(!business.is_finished());
    checkpoint("lock_held_initial");
    let stop_output_path = root.join("registered-stop.stdout");
    let started_stop = std::time::Instant::now();
    checkpoint("stop_requested");
    let mut stop_command = if mode == "normal" { owned.command(&["--json", "runtime", "stop"])? }
        else { owned.probe_command(&probe, "stop")? };
    let mut stop = stop_command
        .stdout(std::fs::File::create(&stop_output_path)?)
        .stderr(std::fs::File::create(root.join("registered-stop.stderr"))?).spawn()?;
    checkpoint("stop_started");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let pending = loop {
        let observed = owned.health()?;
        if observed["control"]["state"] == "draining" { break observed; }
        anyhow::ensure!(stop.try_wait()?.is_none() && std::time::Instant::now() < deadline, "registered stop failed before drain");
        std::thread::sleep(Duration::from_millis(50));
    };
    let operation = pending["control"]["operation_id"].clone();
    anyhow::ensure!(operation.as_str().is_some_and(|id| !id.is_empty()), "registered stop operation missing");
    checkpoint("drain_observed");
    let mut caller_timeout_ms = None;
    if mode == "normal" {
        std::thread::sleep(Duration::from_millis(4200));
        assert!(stop.try_wait()?.is_none());
    } else {
        let deadline = started_stop + Duration::from_secs(45);
        loop {
            if let Some(status) = stop.try_wait()? {
                assert!(!status.success(), "old managed caller completed before the held business");
                break;
            }
            anyhow::ensure!(std::time::Instant::now() < deadline, "original managed caller did not hit its 35s deadline");
            std::thread::sleep(Duration::from_millis(100));
        }
        let output: Value = serde_json::from_slice(&std::fs::read(&stop_output_path)?)?;
        assert!(output["action_error"].as_str().context("old managed caller error missing")?
            .contains("通过 CLI 生命周期协调器停止 Runtime"));
        assert!(started_stop.elapsed() >= Duration::from_secs(35));
        caller_timeout_ms = Some(started_stop.elapsed().as_millis());
    }
    checkpoint("caller_wait_complete");
    assert!(!business.is_finished());
    assert_eq!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
    assert_eq!(stop_native_worker_identity(supervisor_pid)?.as_ref(), Some(&supervisor_identity));
    let held = owned.health()?;
    assert_eq!(held["control"]["state"], "draining");
    assert_eq!(held["inference"]["worker_retired"], false);
    let registration: Value = serde_json::from_slice(&std::fs::read(root.join("runtime/autostart/registration.json"))?)?;
    assert_eq!(registration["manually_stopped"], true);
    assert_eq!(registration["maintenance"], true);
    let mut replay = request.clone(); replay["id"] = json!("registered-stop-retry");
    let (_, same_key) = stop_native_post(&rpc_url, &replay)?;
    assert_eq!(same_key["code"], "request_in_progress");
    assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    assert_owned_stop_lock_held(&root, runtime_pid, &runtime_identity)?;
    checkpoint("lock_held_draining");
    let mut force_response = None;
    if mode == "explicit-force" {
    checkpoint("force_requested");
        let force = json!({"installation_id":health["installation_id"],"instance_id":health["instance_id"],
            "account_id":health["account_id"],"generation":health["generation"],"operation_id":operation,"force":true});
        let (status, response) = stop_native_post(&format!("http://127.0.0.1:{}/api/runtime/stop", fixture.port), &force)?;
        assert_eq!(status, 200); assert_eq!(response["operation_id"], operation);
        assert_eq!(response["timeout_state"], "forced_timeout");
        assert!(response["deadline_ms"].as_u64().is_some_and(|ms| ms <= 4000));
        force_response = Some(response);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let observed = owned.health()?;
            if observed["inference"]["retired_worker"]["worker_reaped"] == true { break; }
            anyhow::ensure!(std::time::Instant::now() < deadline, "registered force did not retire the original Core");
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_ne!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
        assert!(!business.is_finished());
        assert_owned_stop_lock_held(&root, runtime_pid, &runtime_identity)?;
        checkpoint("core_reaped");
    }
    checkpoint("provider_release_requested");
    provider.release.store(true, Ordering::Release);
    let (_, result) = business.join().map_err(|_| anyhow::anyhow!("registered business thread panicked"))??;
    assert_eq!(result["id"], request["id"]);
    assert_eq!(result["operation_id"], request["operation_id"]);
    if mode == "explicit-force" { assert_eq!(result["ok"], false); }
    else { write.assert_result(&result, &request); }
    checkpoint("business_completed");
    if mode == "normal" {
        let deadline = std::time::Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = stop.try_wait()? { anyhow::ensure!(status.success(), "registered normal stop failed"); break; }
            anyhow::ensure!(std::time::Instant::now() < deadline, "registered stop did not finish");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if stop_native_worker_identity(runtime_pid)?.as_ref() != Some(&runtime_identity)
            && stop_native_worker_identity(supervisor_pid)?.as_ref() != Some(&supervisor_identity)
            && stop_native_worker_identity(worker_pid)?.as_ref() != Some(&worker_identity) { break; }
        anyhow::ensure!(std::time::Instant::now() < deadline, "registered backend/supervisor/Core did not exit");
        std::thread::sleep(Duration::from_millis(100));
    }
    checkpoint("actors_exited");
    let receipt_path = root.join("runtime").join(format!("stop-{}.json", health["instance_id"].as_str().context("instance missing")?));
    let receipt_bytes = std::fs::read(&receipt_path)?;
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    assert_eq!(receipt["schema_version"], 1); assert_eq!(receipt["protocol_version"], 1);
    assert_eq!(receipt["operation_id"], operation);
    for key in ["installation_id", "instance_id", "pid", "process_start_id", "image_path", "image_sha256", "runtime_version", "account_id", "generation"] {
        assert_eq!(receipt[key], health[key], "registered final identity changed: {key}");
    }
    assert_eq!(receipt["state"], if mode == "explicit-force" { "forced_timeout" } else { "drained" });
    if mode == "explicit-force" {
        let unfinished = receipt["unfinished"].as_array().context("registered forced unfinished list missing")?;
        assert_eq!(unfinished.iter().filter(|item| item["operation_id"] == request["operation_id"]
            && item["result"] == "unknown").count(), 1);
    } else { assert_eq!(receipt["unfinished"], json!([])); }
    assert_ne!(stop_native_worker_identity(runtime_pid)?.as_ref(), Some(&runtime_identity));
    assert_ne!(stop_native_worker_identity(supervisor_pid)?.as_ref(), Some(&supervisor_identity));
    assert_ne!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_identity));
    checkpoint("receipt_verified");
    // Exceed both the 10s systemd/launchd delay and 60s Task Scheduler retry interval.
    let quiet = std::time::Instant::now() + Duration::from_secs(65);
    while std::time::Instant::now() < quiet {
        match std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{}", fixture.port).parse()?, Duration::from_secs(1)) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {},
            other => anyhow::bail!("registered owner resurrected or listener state unproved: {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(owned.run(&["--json", "runtime", "autostart", "status"])?["runtime"]["running"], false);
    checkpoint("quiet_period_verified");
    let lock = respire::lock::LibraryLock::acquire(&root, Duration::from_secs(1))?; drop(lock);
    if mode == "explicit-force" { write.assert_uncommitted(fixture)?; }
    else { write.assert_committed(fixture)?; }
    checkpoint("write_verified");
    let recovery = if mode != "normal" {
    checkpoint("recovery_requested");
        owned.run(&["--json", "runtime", "restart"])?;
    checkpoint("recovery_started");
        let recovered = owned.health()?;
        assert_ne!(recovered["instance_id"], health["instance_id"]);
        let recovered_pid = u32::try_from(recovered["pid"].as_u64().context("recovered registered PID missing")?)?;
        let recovered_os = stop_native_worker_identity(recovered_pid)?.context("recovered registered actor missing")?;
        let recovered_claim: Value = serde_json::from_slice(&std::fs::read(root.join("runtime/autostart/launch")
            .join(format!("launch-{}.claimed", recovered["instance_id"].as_str().context("recovered instance missing")?)))?)?;
        let recovered_grant: Value = serde_json::from_str(recovered_claim["grant_json"].as_str().context("recovered grant missing")?)?;
        let recovered_supervisor = u32::try_from(recovered_grant["supervisor_pid"].as_u64().context("recovered supervisor missing")?)?;
        let recovered_supervisor_os = stop_native_worker_identity(recovered_supervisor)?.context("recovered supervisor not live")?;
        let recovered_worker = match recovered["inference"].get("worker_pid").context("recovered registered Core observation missing")? {
            Value::Null => None,
            value => {
                let pid = u32::try_from(value.as_u64().context("recovered registered Core PID is invalid")?)?;
                let identity = stop_native_worker_identity(pid)?.context("recovered registered Core not live")?;
                anyhow::ensure!(Path::new(identity["image"].as_str().context("recovered registered Core image missing")?).canonicalize()?
                    == fixture.runtime, "recovered registered Core OS image mismatch");
                if let Some(parent) = identity.get("parent") { assert_eq!(*parent, json!(recovered_pid)); }
                Some((pid, identity))
            }
        };
    checkpoint("recovery_bound");
        replay["id"] = json!("registered-old-scope-after-explicit-recovery");
        let (_, stale) = stop_native_post(&rpc_url, &replay)?;
        assert_eq!(stale["code"], "scope_mismatch");
        assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    checkpoint("recovery_stop_requested");
        owned.run(&["--json", "runtime", "stop"])?;
        let final_recovered: Value = serde_json::from_slice(&std::fs::read(root.join("runtime")
            .join(format!("stop-{}.json", recovered["instance_id"].as_str().context("recovered instance missing")?)))?)?;
        assert_eq!(final_recovered["state"], "drained"); assert_eq!(final_recovered["unfinished"], json!([]));
        for key in ["installation_id","instance_id","pid","process_start_id","image_path","image_sha256","runtime_version","account_id","generation"] {
            assert_eq!(final_recovered[key], recovered[key], "recovered registered receipt mismatch: {key}");
        }
        assert_ne!(stop_native_worker_identity(recovered_pid)?.as_ref(), Some(&recovered_os));
        assert_ne!(stop_native_worker_identity(recovered_supervisor)?.as_ref(), Some(&recovered_supervisor_os));
        if let Some((pid, identity)) = recovered_worker.as_ref() {
            assert_ne!(stop_native_worker_identity(*pid)?.as_ref(), Some(identity));
        }
        assert_eq!(std::fs::read(&receipt_path)?, receipt_bytes, "explicit recovery rewrote the old receipt");
    checkpoint("recovery_stopped");
        Some(json!({"identity":recovered,"receipt":final_recovered,"stale_scope_result":stale}))
    } else { None };
    provider.finish()?; assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    checkpoint("cleanup_requested");
    owned.cleanup()?;
    checkpoint("cleanup_complete");
    checkpoint("complete");
    eprintln!("NATIVE_REGISTERED_STOP_RAW {}", json!({"schema":1,"evidence_class":"native-raw","gate":"not-evaluated",
        "startup_mode":"cli-supervised","case":mode,"forced":mode == "explicit-force","passed":true,"runtime_identity":health,
        "probe_sha256":probe_digest,"business_sender":"modern-harness",
        "stop_sender":if mode == "normal" { "modern-cli" } else { "original-go-client2-managed" },
        "caller_timeout_ms":caller_timeout_ms,"runtime_compatibility_timeout_claimed":false,
        "explicit_force_response":force_response,"recovery":recovery,
        "runtime_os_identity":runtime_identity,"supervisor_os_identity":supervisor_identity,"worker_os_identity":worker_identity,
        "active_health":active,"held_health":held,"business_result":result,"same_key_result":same_key,"final_receipt":receipt,
        "provider_http_status":200,"encrypted_write_committed":mode != "explicit-force",
        "forced_operation_remains_unknown":mode == "explicit-force","provider_requests":1,"quiet_after_stop_ms":65000,"credential_cleanup_verified":true}));
    }
    Ok(())
}


// Same safe keyring/installed-bundle preparation as the registered case; this
// mode starts through the original Go Manager, never the service supervisor.
fn prepare_client2_stop_fixture(case: &str) -> anyhow::Result<RegisteredStopFixture> {
    let checkpoint = |stage| owned_stop_checkpoint("client2-owned", case, stage);
    let fixture = Fixture::new()?;
    checkpoint("fixture_created");
    anyhow::ensure!(fixture.business_cli.is_none(), "Client2-owned control requires the bound modern CLI");
    let mut owned = RegisteredStopFixture { fixture: Some(fixture),
        alias: format!("login-{}", uuid::Uuid::new_v4().simple()), backends: Vec::new(), registration_attempted: false };
    let alias = owned.alias.clone();
    let secret = owned.fixture()?.secret.clone();
    checkpoint("credential_requested");
    let backend = respire::keystore::import_credential_checkpoint(&alias, "super", &secret, |backend| {
        anyhow::ensure!(matches!(backend, "native" | "secret_service"), "registered fixture requires persistent OS credentials");
        owned.backends.push(backend.to_owned());
        Ok(())
    })?;
    anyhow::ensure!(respire::keystore::read_imported(&alias, "super", backend)? == secret,
        "registered credential checkpoint readback mismatch");
    checkpoint("credential_ready");
    let fixture = owned.fixture.as_mut().context("fixture missing")?;
    let root = fixture.home.path().join("data");
    let mut session: Value = serde_json::from_slice(&std::fs::read(root.join("session.json"))?)?;
    session["keyring_account"] = json!(alias);
    session["keyring_backend"] = json!(backend);
    std::fs::write(root.join("session.json"), serde_json::to_vec(&session)?)?;
    // Use the existing public classification file contract, with only a synthetic key.
    anyhow::ensure!(respire::keystore::load_classify_key("typesafe").is_none(), "fixture classification slot is not empty");
    std::fs::write(root.join("classify.json"), br#"{"api_key":"synthetic-native-stop-key"}"#)?;
    checkpoint("runtime_install_requested");
    support::install_runtime_fixture(&root)?;
    let selected: Value = serde_json::from_slice(&std::fs::read(root.join("runtime.json"))?)?;
    fixture.runtime = root.join("runtime").join(selected["version"].as_str().context("installed version missing")?)
        .join(if cfg!(windows) { "rsrs-runtime.exe" } else { "rsrs-runtime" }).canonicalize()?;
    std::fs::create_dir_all(root.join("bin"))?;
    std::fs::copy(&fixture.cli, root.join("bin").join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" }))?;
    checkpoint("runtime_installed");
    Ok(owned)
}


struct Client2OwnedStopFixture {
    owned: Option<RegisteredStopFixture>,
    probe: PathBuf,
    observed_host: Option<Value>,
    observed_actors: Vec<(u32, Value)>,
    identity_observation_complete: bool,
    start_attempted: bool,
    completed: bool,
}

impl Client2OwnedStopFixture {
    fn owned(&self) -> anyhow::Result<&RegisteredStopFixture> {
        self.owned.as_ref().context("Client2-owned fixture missing")
    }

    fn command(&self, action: &str) -> anyhow::Result<Command> {
        let owned = self.owned()?;
        let template = owned.command(&[])?;
        let mut command = Command::new(&self.probe);
        command.arg(action).current_dir(owned.fixture()?.home.path());
        for (name, value) in template.get_envs() {
            match value { Some(value) => { command.env(name, value); }, None => { command.env_remove(name); } }
        }
        Ok(command)
    }

    fn health(&self, backend: bool) -> anyhow::Result<Value> {
        let fixture = self.owned()?.fixture()?;
        let mut request = ureq::AgentBuilder::new().try_proxy_from_env(false).build()
            .get(&format!("http://127.0.0.1:{}/api/health", fixture.port)).timeout(Duration::from_secs(3));
        if backend { request = request.set("X-Respire-Health", "runtime-v1"); }
        let health: Value = request.call()?.into_json()?;
        let root = fixture.home.path().join("data").canonicalize()?;
        anyhow::ensure!(health["server"] == "respire" && health["v"] == 1 && health["managed_id"].is_null(),
            "Client2-owned mode must not use the registered supervisor");
        for field in ["data_dir", "installation_root"] {
            anyhow::ensure!(Path::new(health[field].as_str().context("Client2-owned root missing")?).canonicalize()? == root,
                "Client2-owned scope root mismatch");
        }
        let expected = if backend { &fixture.runtime } else {
            Path::new(fixture.cli.as_path())
        };
        // Legacy host uses the original Client2-selected Runtime image even
        // though its process implements only the compatibility coordinator.
        let expected = if backend { expected.to_path_buf() } else {
            let selected: Value = serde_json::from_slice(&std::fs::read(root.join("client2/runtime.json"))?)?;
            root.join("client2/runtime").join(selected["version"].as_str().context("Client2 version missing")?)
                .join(if cfg!(windows) { "rsrs-runtime.exe" } else { "rsrs-runtime" }).canonicalize()?
        };
        anyhow::ensure!(Path::new(health["exe"].as_str().context("Client2-owned image missing")?).canonicalize()? == expected,
            "Client2-owned image mismatch");
        Ok(health)
    }

    fn cleanup(&mut self) -> anyhow::Result<()> {
        if self.completed { return Ok(()); }
        let fixture = self.owned()?.fixture()?;
        anyhow::ensure!(!self.start_attempted || self.observed_host.is_some(),
            "Client2 startup outcome is unverified; preserve root and credential for explicit recovery");
        anyhow::ensure!(!self.start_attempted || self.identity_observation_complete,
            "Client2 actor observation incomplete; preserve root and credential for explicit recovery");
        if let Some(expected) = self.observed_host.as_ref() {
            match std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{}", fixture.port).parse()?, Duration::from_secs(1)) {
                Ok(_) => {
                    let observed = self.health(false)?;
                    for key in ["pid", "exe", "installation_root", "data_dir"] {
                        anyhow::ensure!(observed[key] == expected[key], "Client2-owned cleanup target changed");
                    }
                    let output = self.command("stop")?.output()?;
                    anyhow::ensure!(output.status.success(), "original Go owned cleanup failed");
                },
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {},
                Err(error) => return Err(error.into()),
            }
        }
        for (pid, identity) in &self.observed_actors {
            anyhow::ensure!(stop_native_worker_identity(*pid)?.as_ref() != Some(identity),
                "observed Client2 host/backend/Core is still live; preserve root and credential");
        }
        self.owned.as_mut().context("owned fixture missing")?.cleanup()?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for Client2OwnedStopFixture {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            // Do not delete a possibly live root or its recovery credential.
            if let Some(owned) = self.owned.take() { std::mem::forget(owned); }
            eprintln!("CLIENT2_OWNED_STOP_CLEANUP_FAILED explicit owned recovery required");
        }
    }
}

fn stop_native_client2_owned_held_write() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    use sha2::{Digest, Sha256};
    anyhow::ensure!(std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted"),
        "Client2-owned native acceptance requires an ephemeral GitHub-hosted runner");
    let probe = PathBuf::from(std::env::var_os("RSRS_CLIENT2_PROBE_BIN")
        .context("supply the source-bound existing original Go Client2 probe executable")?).canonicalize()?;
    anyhow::ensure!(probe.is_file(), "original Client2 probe is not a file");
    // The producer must independently bind this binary to the unchanged 57bc070
    // source and the existing CLI probe fixtures; a caller-provided digest alone
    // is not a source certificate. Keep this raw report gate=not-evaluated.
    let probe_digest = format!("{:x}", Sha256::digest(std::fs::read(&probe)?));
    for mode in ["normal", "caller-timeout", "explicit-force"] {
        let checkpoint = |stage| owned_stop_checkpoint("client2-owned", mode, stage);
        checkpoint("start");
        let owned = prepare_client2_stop_fixture(mode)?;
        checkpoint("fixture_ready");
        let write = StopWriteEvidence::seed(owned.fixture()?)?;
        checkpoint("memory_seeded");
        let root = owned.fixture()?.home.path().join("data");
        let selected: Value = serde_json::from_slice(&std::fs::read(root.join("runtime.json"))?)?;
        let version = selected["version"].as_str().context("installed Runtime version missing")?;
        let version_dir = owned.fixture()?.runtime.parent().context("Runtime bundle missing")?.to_path_buf();
        let target = root.join("client2/runtime").join(version);
        let mut pending = vec![(version_dir, target.clone())];
        while let Some((source, destination)) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&source)?;
            anyhow::ensure!(!metadata.file_type().is_symlink(), "Client2 fixture bundle contains a link");
            #[cfg(windows)] {
                use std::os::windows::fs::MetadataExt;
                anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "Client2 fixture contains a reparse point");
            }
            if metadata.is_dir() {
                std::fs::create_dir_all(&destination)?;
                for entry in std::fs::read_dir(&source)? { let entry = entry?; pending.push((entry.path(), destination.join(entry.file_name()))); }
            } else {
                anyhow::ensure!(metadata.is_file(), "Client2 fixture bundle contains a non-file");
                std::fs::copy(source, destination)?;
            }
        }
        // Original InstalledRuntime is exactly version+sha256. This is the
        // original launcher fixture installation shape, not an OS registration.
        std::fs::write(root.join("client2/runtime.json"), serde_json::to_vec(&json!({"version":version,"sha256":selected["sha256"]}))?)?;
        checkpoint("bundle_staged");
        let mut client2 = Client2OwnedStopFixture { owned: Some(owned), probe: probe.clone(), observed_host: None, observed_actors: Vec::new(), identity_observation_complete: false, start_attempted: false, completed: false };
        client2.start_attempted = true;
        checkpoint("start_requested");
        let started = client2.command("start")?.output()?;
        anyhow::ensure!(started.status.success(), "original Go Manager.Start failed");
        checkpoint("start_complete");
        let startup: Value = serde_json::from_slice(&started.stdout)?;
        for key in ["health_error", "diagnostic_error", "business_error", "catalog_error", "progress_error", "variants_error"] {
            assert_eq!(startup[key], "", "original Go startup/RPC failed: {key}");
        }
        let host = client2.health(false)?;
        client2.observed_host = Some(host.clone());
        let backend = client2.health(true)?;
        checkpoint("health_bound");
        let host_pid = u32::try_from(host["pid"].as_u64().context("legacy host PID missing")?)?;
        let backend_pid = u32::try_from(backend["pid"].as_u64().context("backend PID missing")?)?;
        assert_ne!(host_pid, backend_pid);
        let host_os = stop_native_worker_identity(host_pid)?.context("actual legacy host missing")?;
        let backend_os = stop_native_worker_identity(backend_pid)?.context("actual backend missing")?;
        client2.observed_actors.extend([(host_pid, host_os.clone()), (backend_pid, backend_os.clone())]);
        assert_eq!(host["compatibility_host"], "client2-v0256");
        assert_eq!(host["backend_pid"], backend["pid"]);
        assert_eq!(host["backend_instance_id"], backend["instance_id"]);
        assert_eq!(host["backend_process_start_id"], backend["process_start_id"]);
        assert_eq!(host_os["birth"], host["host_birth"]);
        assert_eq!(Path::new(host_os["image"].as_str().context("host OS image missing")?).canonicalize()?,
            Path::new(host["exe"].as_str().context("host image missing")?).canonicalize()?);
        assert_eq!(host["host_image_sha256"], format!("{:x}", Sha256::digest(std::fs::read(host["exe"].as_str().context("host image missing")?)?)));
        assert_eq!(Path::new(backend_os["image"].as_str().context("backend OS image missing")?).canonicalize()?, client2.owned()?.fixture()?.runtime);
        let prefix = if cfg!(windows) { "windows-filetime-" } else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
        assert_eq!(backend["process_start_id"], format!("{prefix}{}", backend_os["birth"].as_str().context("backend OS birth missing")?));
        assert_eq!(backend["image_sha256"], format!("{:x}", Sha256::digest(std::fs::read(&client2.owned()?.fixture()?.runtime)?)));
        checkpoint("actors_bound");
        let mut provider = write.provider()?;
        let request = json!({"v":1,"id":uuid::Uuid::new_v4().to_string(),"method":"cli.exec",
            "operation_id":uuid::Uuid::new_v4().to_string(),"idempotency_key":uuid::Uuid::new_v4().to_string(),
            "scope":{"account_id":backend["account_id"],"instance_id":backend["instance_id"],"generation":backend["generation"]},
            "args":write.args(&provider.endpoint)});
        let rpc_url = format!("http://127.0.0.1:{}/api/rpc", client2.owned()?.fixture()?.port);
        let (url, original) = (rpc_url.clone(), request.clone());
        client2.identity_observation_complete = false;
        checkpoint("provider_requested");
        let business = std::thread::spawn(move || stop_native_post(&url, &original));
        provider.received.recv_timeout(Duration::from_secs(30)).context("actual Client2-owned SDK callback missing")?;
        checkpoint("provider_received");
        let active = client2.health(true)?;
        let worker_pid = u32::try_from(active["inference"]["worker_pid"].as_u64().context("Core worker missing")?)?;
        let worker_os = stop_native_worker_identity(worker_pid)?.context("actual Core worker missing")?;
        client2.observed_actors.push((worker_pid, worker_os.clone()));
        assert_eq!(Path::new(worker_os["image"].as_str().context("Core OS image missing")?).canonicalize()?, client2.owned()?.fixture()?.runtime);
        if let Some(parent) = worker_os.get("parent") { assert_eq!(*parent, json!(backend_pid)); }
        assert!(active["control"]["admitted"].as_array().context("admission missing")?.iter()
            .any(|item| item["operation_id"] == request["operation_id"]));
        assert!(active["inference"]["worker_host_callbacks_active"].as_u64().is_some_and(|n| n > 0));
        assert!(active["inference"]["worker_call_deadline_secs"].as_u64().is_some_and(|n| n >= 30));
        client2.identity_observation_complete = true;
        checkpoint("core_bound");
        let fixture = client2.owned()?.fixture()?;
        assert_owned_stop_lock_held(&root, backend_pid, &backend_os)?;
        std::thread::sleep(Duration::from_millis(4200)); assert!(!business.is_finished());
        checkpoint("lock_held_initial");
        let stop_output_path = root.join("original-go-stop.stdout");
        checkpoint("stop_requested");
        let mut stop = client2.command("stop")?.stdout(std::fs::File::create(&stop_output_path)?)
            .stderr(std::fs::File::create(root.join("original-go-stop.stderr"))?).spawn()?;
        checkpoint("stop_started");
        let started_stop = std::time::Instant::now();
        let deadline = started_stop + Duration::from_secs(15);
        let pending = loop {
            let health = client2.health(true)?;
            if health["control"]["state"] == "draining" { break health; }
            anyhow::ensure!(stop.try_wait()?.is_none() && std::time::Instant::now() < deadline, "original Go stop did not request drain");
            std::thread::sleep(Duration::from_millis(50));
        };
        let operation = pending["control"]["operation_id"].clone();
        anyhow::ensure!(operation.as_str().is_some_and(|id| !id.is_empty()), "original stop operation missing");
        checkpoint("drain_observed");
        let mut caller_timeout_ms = None;
        if mode == "normal" {
            std::thread::sleep(Duration::from_millis(4200)); assert!(stop.try_wait()?.is_none());
        } else {
            let deadline = started_stop + Duration::from_secs(40);
            loop {
                if let Some(status) = stop.try_wait()? {
                    assert!(!status.success(), "old caller unexpectedly completed while business was held"); break;
                }
                anyhow::ensure!(std::time::Instant::now() < deadline, "original Go caller did not return within its original timeout");
                std::thread::sleep(Duration::from_millis(100));
            }
            let stop_result: Value = serde_json::from_slice(&std::fs::read(&stop_output_path)?)?;
            assert!(stop_result["action_error"].as_str().context("old caller timeout error missing")?
                .contains("尚未退出，未强制结束进程"));
            assert!(started_stop.elapsed() >= Duration::from_secs(30));
            caller_timeout_ms = Some(started_stop.elapsed().as_millis());
        }
        checkpoint("caller_wait_complete");
        assert!(!business.is_finished());
        assert_eq!(stop_native_worker_identity(host_pid)?.as_ref(), Some(&host_os));
        assert_eq!(stop_native_worker_identity(backend_pid)?.as_ref(), Some(&backend_os));
        assert_eq!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_os));
        let after_caller = client2.health(true)?;
        assert_eq!(after_caller["control"]["state"], "draining");
        assert_eq!(after_caller["inference"]["worker_retired"], false);
        let mut replay = request.clone(); replay["id"] = json!(uuid::Uuid::new_v4().to_string());
        let (_, same_key) = stop_native_post(&rpc_url, &replay)?;
        assert_eq!(same_key["code"], "request_in_progress"); assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        assert_owned_stop_lock_held(&root, backend_pid, &backend_os)?;
        checkpoint("lock_held_draining");
        let mut force_receipt = None;
        if mode == "explicit-force" {
            // The old Stop(bool) is ownedOnly, never force. This is a separate,
            // explicit modern request tied to the original stop operation/actor.
        checkpoint("force_requested");
            let force = json!({"installation_id":backend["installation_id"],"instance_id":backend["instance_id"],
                "account_id":backend["account_id"],"generation":backend["generation"],"operation_id":operation,"force":true});
            let (status, receipt) = stop_native_post(&format!("http://127.0.0.1:{}/api/runtime/stop", fixture.port), &force)?;
            assert_eq!(status, 200); assert_eq!(receipt["operation_id"], operation);
            assert_eq!(receipt["timeout_state"], "forced_timeout");
            assert!(receipt["deadline_ms"].as_u64().is_some_and(|ms| ms <= 4000));
            force_receipt = Some(receipt);
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                let health = client2.health(true)?;
                if health["inference"]["retired_worker"]["worker_reaped"] == true { break; }
                anyhow::ensure!(std::time::Instant::now() < deadline, "explicit force did not retire the original Core worker");
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_ne!(stop_native_worker_identity(worker_pid)?.as_ref(), Some(&worker_os));
            assert!(!business.is_finished());
            assert_owned_stop_lock_held(&root, backend_pid, &backend_os)?;
            checkpoint("core_reaped");
        }
        checkpoint("provider_release_requested");
        provider.release.store(true, Ordering::Release);
        let (_, result) = business.join().map_err(|_| anyhow::anyhow!("Client2-owned modern business thread panicked"))??;
        assert_eq!(result["id"], request["id"]); assert_eq!(result["operation_id"], request["operation_id"]);
        if mode == "explicit-force" { assert_eq!(result["ok"], false); }
        else { write.assert_result(&result, &request); }
        checkpoint("business_completed");
        if mode == "normal" {
            let deadline = std::time::Instant::now() + Duration::from_secs(40);
            loop {
                if let Some(status) = stop.try_wait()? { anyhow::ensure!(status.success(), "original normal Go Stop failed"); break; }
                anyhow::ensure!(std::time::Instant::now() < deadline, "original Go Stop did not complete after business");
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(&stop_output_path)?)?["stopped"], true);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if stop_native_worker_identity(host_pid)?.as_ref() != Some(&host_os)
                && stop_native_worker_identity(backend_pid)?.as_ref() != Some(&backend_os)
                && stop_native_worker_identity(worker_pid)?.as_ref() != Some(&worker_os) { break; }
            anyhow::ensure!(std::time::Instant::now() < deadline, "Client2-owned host/backend/Core did not finish exit");
            std::thread::sleep(Duration::from_millis(100));
        }
        checkpoint("actors_exited");
        let original_receipt_path = root.join("runtime")
            .join(format!("stop-{}.json", backend["instance_id"].as_str().context("backend instance missing")?));
        let original_receipt_bytes = std::fs::read(&original_receipt_path)?;
        let final_receipt: Value = serde_json::from_slice(&original_receipt_bytes)?;
        assert_eq!(final_receipt["schema_version"], 1); assert_eq!(final_receipt["protocol_version"], 1);
        assert_eq!(final_receipt["operation_id"], operation);
        for key in ["installation_id","instance_id","pid","process_start_id","image_path","image_sha256","runtime_version","account_id","generation"] {
            assert_eq!(final_receipt[key], backend[key], "Client2-owned final receipt identity changed: {key}");
        }
        assert_eq!(final_receipt["state"], if mode == "explicit-force" { "forced_timeout" } else { "drained" });
        if mode == "explicit-force" {
            let unfinished = final_receipt["unfinished"].as_array().context("forced unfinished records missing")?;
            assert_eq!(unfinished.iter().filter(|item| item["operation_id"] == request["operation_id"] && item["result"] == "unknown").count(), 1);
        } else { assert_eq!(final_receipt["unfinished"], json!([])); }
        checkpoint("receipt_verified");
        match std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{}", fixture.port).parse()?, Duration::from_secs(1)) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {},
            other => anyhow::bail!("Client2-owned stopped listener did not refuse: {other:?}"),
        }
        let lock = respire::lock::LibraryLock::acquire(&root, Duration::from_secs(1))?; drop(lock);
        if mode == "explicit-force" { write.assert_uncommitted(fixture)?; }
        else { write.assert_committed(fixture)?; }
        checkpoint("write_verified");
        // Explicit recovery starts a new actor; querying the old fingerprint
        // cannot re-execute it or convert an old unknown result to success.
        client2.identity_observation_complete = false;
        checkpoint("recovery_requested");
        let restarted_output = client2.command("start")?.output()?;
        anyhow::ensure!(restarted_output.status.success(), "explicit original Go recovery start failed");
        checkpoint("recovery_started");
        let recovered_host = client2.health(false)?;
        let recovered = client2.health(true)?;
        assert_ne!(recovered["instance_id"], backend["instance_id"]);
        let recovered_host_pid = u32::try_from(recovered_host["pid"].as_u64().context("recovered host PID missing")?)?;
        let recovered_pid = u32::try_from(recovered["pid"].as_u64().context("recovered backend PID missing")?)?;
        let recovered_host_os = stop_native_worker_identity(recovered_host_pid)?.context("recovered host missing")?;
        let recovered_os = stop_native_worker_identity(recovered_pid)?.context("recovered backend missing")?;
        client2.observed_actors.extend([(recovered_host_pid, recovered_host_os.clone()), (recovered_pid, recovered_os.clone())]);
        assert_ne!(recovered_host_os, host_os); assert_ne!(recovered_os, backend_os);
        let recovered_worker = match recovered["inference"].get("worker_pid").context("recovered Core observation missing")? {
            Value::Null => None,
            value => {
                let pid = u32::try_from(value.as_u64().context("recovered Core PID is invalid")?)?;
                let identity = stop_native_worker_identity(pid)?.context("recovered Core worker not live")?;
                anyhow::ensure!(Path::new(identity["image"].as_str().context("recovered Core OS image missing")?).canonicalize()?
                    == client2.owned()?.fixture()?.runtime, "recovered Core OS image mismatch");
                if let Some(parent) = identity.get("parent") { assert_eq!(*parent, json!(recovered_pid)); }
                client2.observed_actors.push((pid, identity.clone()));
                Some((pid, identity))
            }
        };
        client2.observed_host = Some(recovered_host.clone());
        client2.identity_observation_complete = true;
        checkpoint("recovery_bound");
        replay["id"] = json!(uuid::Uuid::new_v4().to_string());
        let (_, stale) = stop_native_post(&rpc_url, &replay)?;
        assert_eq!(stale["code"], "scope_mismatch"); assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        checkpoint("recovery_stop_requested");
        let recovered_stop = client2.command("stop")?.output()?;
        anyhow::ensure!(recovered_stop.status.success(), "explicit recovered actor did not stop normally");
        let recovered_receipt: Value = serde_json::from_slice(&std::fs::read(root.join("runtime")
            .join(format!("stop-{}.json", recovered["instance_id"].as_str().context("recovered instance missing")?)))?)?;
        assert_eq!(recovered_receipt["state"], "drained"); assert_eq!(recovered_receipt["unfinished"], json!([]));
        for key in ["installation_id","instance_id","pid","process_start_id","image_path","image_sha256","runtime_version","account_id","generation"] {
            assert_eq!(recovered_receipt[key], recovered[key], "recovered final receipt identity changed: {key}");
        }
        assert_ne!(stop_native_worker_identity(recovered_host_pid)?.as_ref(), Some(&recovered_host_os));
        assert_ne!(stop_native_worker_identity(recovered_pid)?.as_ref(), Some(&recovered_os));
        if let Some((pid, identity)) = recovered_worker.as_ref() {
            assert_ne!(stop_native_worker_identity(*pid)?.as_ref(), Some(identity));
        }
        assert_eq!(std::fs::read(&original_receipt_path)?, original_receipt_bytes,
            "explicit recovery changed the original drained/unknown receipt");
        checkpoint("recovery_stopped");
        provider.finish()?; assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        // The listener is now closed, so owned cleanup only removes the exact
        // synthetic persistent credential; it does not send another stop.
        checkpoint("cleanup_requested");
        client2.cleanup()?;
        checkpoint("cleanup_complete");
        checkpoint("complete");
        eprintln!("NATIVE_CLIENT2_STOP_RAW {}", json!({"schema":1,"evidence_class":"native-raw","gate":"not-evaluated",
            "startup_mode":"client2-owned","case":mode,"business_sender":"modern-harness","stop_sender":"original-go-client2",
            "probe_sha256":probe_digest,"runtime_identity":backend,"legacy_host":host,
            "host_os_identity":host_os,"backend_os_identity":backend_os,"worker_os_identity":worker_os,
            "caller_timeout_ms":caller_timeout_ms,"runtime_compatibility_timeout_claimed":false,"after_caller_health":after_caller,
            "business_result":result,"same_key_result":same_key,"explicit_force_response":force_receipt,
            "final_receipt":final_receipt,"recovered_identity":recovered,"recovered_receipt":recovered_receipt,"stale_scope_result":stale,
            "provider_http_status":200,"encrypted_write_committed":mode != "explicit-force",
            "forced_operation_remains_unknown":mode == "explicit-force",
            "provider_requests":1,"credential_cleanup_verified":true,"passed":true}));
    }
    Ok(())
}

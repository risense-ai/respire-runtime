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
        let mut command = Command::new(&self.cli);
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

    /// Start an owned runtime and verify its process and profile before use.
    fn start(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.child.is_none(),
            "fixture already has a runtime launcher"
        );
        *self.runtime_owner.borrow_mut() = None;
        self.child = Some(
            self.command(&["runtime", "run"])
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
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        anyhow::bail!("synthetic runtime did not become ready")
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
                .is_some_and(|pid| pid > 0 && pid != u64::from(child.id()))
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
        let claim: Value = serde_json::from_slice(&std::fs::read(
            profile
                .join("runtime/autostart/launch")
                .join(format!("launch-{instance}.claimed")),
        )?)?;
        let birth = claim["process_start_id"]
            .as_str()
            .context("launch claim birth missing")?;
        let prefix = if cfg!(windows) {
            "windows-filetime-"
        } else if cfg!(target_os = "linux") {
            "linux-starttime-"
        } else {
            "darwin-lstart-"
        };
        anyhow::ensure!(
            claim["pid"] == health["pid"]
                && health["process_start_id"] == format!("{prefix}{birth}"),
            "runtime does not match the consumed launch grant"
        );
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
        Self::result(self.command(&all).output()?)
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
            .command(&[
                "--client-only",
                "--json",
                "remember",
                "rejected-private-event",
                "--importance",
                "trivial",
            ])
            .output()?;
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
        let output = fixture.command(&args).output()?;
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
            let mut command = fixture.command(&[
                "--client-only",
                "--json",
                "remember",
                &marker,
                "--importance",
                "trivial",
            ]);
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                command.output()
            }));
        }
        for worker in workers {
            let value = Fixture::result(
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("synthetic client panicked"))??,
            )?;
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
    fixture.assert_author_rejection()
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
    fixture.assert_author_rejection()
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
    let output = fixture
        .command(&[
            "--client-only",
            "--json",
            "remember",
            &content,
            "--importance",
            "important",
        ])
        .output()?;
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
    Ok(())
}

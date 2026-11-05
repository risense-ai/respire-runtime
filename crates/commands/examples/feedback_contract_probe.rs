//! Isolated real-model feedback contract probe. Synthetic vault only; no remote account/keyring.
//! Requires the paired SDK and an explicitly prepared model via RSRS_M3_DIR.
use anyhow::{Context, Result};
use respire::memory::engine::RecalledWithContext;
use respire::{MemoryEngine, MemoryEntry, MemoryQuery, MemoryTransport, SessionKeys};
use respire_app as respire;
use serde_json::{json, Value};

fn score(rows: &[RecalledWithContext], id: &str) -> Result<f32> {
    rows.iter()
        .find(|row| row.entry.id == id)
        .map(|row| row.score)
        .context("probe candidate unexpectedly absent")
}
fn recall(
    store: &respire::transport::local::LocalStore,
    keys: &SessionKeys,
    query: &MemoryQuery,
) -> Result<Vec<RecalledWithContext>> {
    let candidates = store.all(false)?;
    let output: Value = respire::core_sdk::execute(
        "query_business",
        json!({
            "model":"m3","snapshots":respire::memory::engine::snapshots(keys,&candidates)?,
            "query":query,"mode":"fast","provider":null,
            "query_settings":respire::feedback::query_settings(store,query,&candidates)?
        }),
    )?;
    serde_json::from_value(output["items"].clone()).map_err(Into::into)
}
struct CliProbe {
    root: std::path::PathBuf,
    exe: std::path::PathBuf,
    secret: String,
    port: u16,
}
impl CliProbe {
    fn run_program(&self, exe: &std::path::Path, args: &[&str]) -> Result<Value> {
        use std::{
            io::{Read, Seek, SeekFrom},
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut output = tempfile::tempfile()?;
        let errors = tempfile::tempfile()?;
        let mut child = Command::new(exe)
            .args(args)
            .current_dir(&self.root)
            .env("HOME", &self.root)
            .env("USERPROFILE", &self.root)
            .env("RSRS_DATA_DIR", &self.root)
            .env("RSRS_RPC_PORT", self.port.to_string())
            .env("RSRS_SUPER", &self.secret)
            .env("RSRS_ENGINE", "cpu")
            .env("RSRS_FEEDBACK", "1")
            .env("RSRS_BAD_PENALTY", "1")
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_LANG", "en")
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(errors)
            .spawn()?;
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(120) {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("isolated probe command timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        output.seek(SeekFrom::Start(0))?;
        let mut text = String::new();
        output.read_to_string(&mut text)?;
        let result: Value = serde_json::from_str(&text)
            .context("isolated command did not emit one JSON document")?;
        anyhow::ensure!(
            status.success(),
            "isolated CLI/probe failed (diagnostics retained only in the temporary fixture)"
        );
        Ok(result)
    }
    fn run(&self, args: &[&str]) -> Result<Value> {
        self.run_program(&self.exe, args)
    }
}
impl Drop for CliProbe {
    fn drop(&mut self) {
        if let Ok(status) = self.run(&["--json", "--runtime-internal", "--status"]) {
            let matches = status["summary"]["data_dir"]
                .as_str()
                .and_then(|path| std::fs::canonicalize(path).ok())
                == std::fs::canonicalize(&self.root).ok();
            if matches && status["summary"]["pid"].as_u64().is_some() {
                let _ = self.run(&["--json", "--runtime-internal", "--stop"]);
            }
        }
    }
}
fn cli_score(result: &Value, id: &str) -> Result<f32> {
    result["details"]
        .as_array()
        .context("CLI recall details")?
        .iter()
        .find(|item| item["entry"]["id"].as_str() == Some(id))
        .and_then(|item| item["score"].as_f64())
        .map(|score| score as f32)
        .context("CLI candidate absent")
}

fn cli_executable() -> Result<std::path::PathBuf> {
    let exe = std::path::PathBuf::from(
        std::env::var_os("RSRS_CLI_BIN")
            .context("supply RSRS_CLI_BIN with the exact CLI under test")?,
    ).canonicalize()?;
    anyhow::ensure!(
        exe.is_file(),
        "RSRS_CLI_BIN must select an existing CLI executable"
    );
    Ok(exe)
}

#[path = "probes/diary.rs"]
mod diary_probe;

fn main() -> Result<()> {
    anyhow::ensure!(
        respire::core_sdk::FEEDBACK_CONTRACT == 1,
        "paired real SDK with feedback contract 1 is required"
    );
    anyhow::ensure!(
        respire::env::var_os("RSRS_M3_DIR").is_some(),
        "provide the prepared real model with RSRS_M3_DIR"
    );
    anyhow::ensure!(
        respire::env::var_os("RSRS_CORE_TEST_MODE").is_none(),
        "real-model probe rejects the synthetic test provider"
    );
    // Resolve the installer-owned CPU cache before isolating the library root.
    let model_dir = std::path::PathBuf::from(
        respire::env::var_os("RSRS_M3_DIR").context("prepared model directory")?,
    );
    let ort = match respire::env::var_os("RSRS_CPU_OWNED_ORT_FILE") {
        Some(path) => std::path::PathBuf::from(path),
        None => respire::memory::bge::cpu_ort_path(&model_dir)?,
    };
    let ort = std::fs::canonicalize(ort)
        .context("prepared CPU model is missing from the original installation profile")?;
    anyhow::ensure!(
        std::fs::metadata(&ort)?.len() == respire::memory::bge::CPU_ORT_SIZE,
        "prepared CPU model size mismatch"
    );
    {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut file = std::fs::File::open(&ort)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        anyhow::ensure!(
            format!("{:x}", hash.finalize()) == respire::memory::bge::CPU_ORT_SHA256,
            "prepared CPU model hash mismatch"
        );
    }
    std::env::set_var("RSRS_CPU_OWNED_ORT_FILE", &ort);
    if std::env::args().any(|arg| arg == "--diary-only") {
        let exe = cli_executable()?;
        println!("{}", diary_probe::run(&exe)?);
        return Ok(());
    }

    let root = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", root.path());
    std::env::set_var("RSRS_NO_AUTOSYNC", "1");
    std::env::set_var("RSRS_ENGINE", "cpu");
    std::env::set_var("RSRS_RECALL_PROFILE", "legacy");
    std::env::set_var("RSRS_FEEDBACK", "0");
    std::env::set_var("RSRS_ABLATE", "");
    std::env::set_var("RSRS_MARK_SIM", "0.5");
    std::env::set_var("RSRS_BAD_PENALTY", "1");
    let store = respire::transport::local::LocalStore::open(&root.path().join("rsrs.db"))?;
    let keys = SessionKeys::from_urk([11; 32])?;
    let embedder = respire::memory::bge::BgeEmbedder::load_model("m3")?;
    let text = "Rust ownership and borrowing keep memory access safe";
    for (index, (title, body)) in [
        ("Rust memory ownership", text),
        (
            "Python exception handling",
            "Python raises and catches exceptions using try and except",
        ),
        ("\u{4e2d}\u{6587}\u{8bb0}\u{5fc6}\u{68c0}\u{7d22}", "\u{4e2d}\u{6587}\u{8bb0}\u{5fc6}\u{68c0}\u{7d22}\u{548c}\u{6570}\u{636e}\u{540c}\u{6b65}\u{4f7f}\u{7528}\u{660e}\u{786e}\u{7684}\u{5e93}\u{8fb9}\u{754c}"),
    ]
    .iter()
    .enumerate()
    {
        let now = chrono::Utc::now().to_rfc3339();
        let entry = MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            id: format!("00000000-0000-4000-8000-{index:012}"),
            user: "synthetic-probe".into(),
            title: (*title).into(),
            content: (*body).into(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            kind: respire::Kind::Context,
            tags: Vec::new(),
            computer: "fixture".into(),
            project: "probe".into(),
            created_at: now.clone(),
            updated_at: now,
            emotion: 0.0,
            parent_id: String::new(),
            importance: "normal".into(),
            device: "fixture".into(),
            modified_by: "fixture".into(),
        };
        let memory = MemoryEngine::seal(&keys, &embedder, &entry, "synthetic-probe")?;
        anyhow::ensure!(store.put(&memory)?, "fixture insertion rejected");
    }
    let query = MemoryQuery::new(text).limit(20);
    std::env::set_var("RSRS_RECALL_PROFILE", "calibrated");
    let snapshots = respire::memory::engine::snapshots(&keys, &store.all(false)?)?;
    let calibrated: Value = respire::core_sdk::execute(
        "query_business",
        json!({
            "model":"m3","snapshots":snapshots,"query":query,"mode":"fast","provider":null
        }),
    )?;
    anyhow::ensure!(
        calibrated["retrieval"]["cos_gate"] == json!(0.42f32)
            && calibrated["retrieval"]["examined"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && !calibrated["items"]
                .as_array()
                .context("calibrated items")?
                .is_empty(),
        "calibrated recall must expose actual gate diagnostics and retain a real-model hit"
    );
    std::env::set_var("RSRS_ABLATE", "kw,recency,hot,tree");
    anyhow::ensure!(
        !recall(&store, &keys, &query)?.is_empty(),
        "semantic-only ablation lost the real-model answer"
    );
    std::env::set_var("RSRS_ABLATE", "");
    std::env::set_var("RSRS_RECALL_PROFILE", "legacy");
    let baseline = recall(&store, &keys, &query)?;
    let target = baseline
        .first()
        .context("real model returned no synthetic candidate")?
        .entry
        .id
        .clone();
    let neutral = score(&baseline, &target)?;
    std::env::set_var("RSRS_FEEDBACK", "1");
    let clean = recall(&store, &keys, &query)?;
    anyhow::ensure!(
        (score(&clean, &target)? - neutral).abs() < 1e-6,
        "unmarked zero-read baseline differs"
    );
    for _ in 0..15 {
        store.bump_recall_count(&target)?;
    }
    anyhow::ensure!(
        (score(&recall(&store, &keys, &query)?, &target)? - neutral).abs() < 1e-6,
        "enabled feedback retained read heat"
    );
    std::env::set_var("RSRS_RECALL_PROFILE", "legacy");
    std::env::set_var("RSRS_FEEDBACK", "0");
    let read_hot = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (read_hot - neutral - 0.10).abs() < 1e-5,
        "legacy heat control did not exercise the original axis"
    );
    let request = uuid::Uuid::new_v4().to_string();
    store.log_query_request(&request, text, "", "", &[target.clone()], &[neutral])?;
    store.mark_query_feedback(&request, &[target.clone()], true, "human")?;
    let disabled_after = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        disabled_after == read_hot,
        "disabled experiment changed after a grade"
    );
    std::env::set_var("RSRS_FEEDBACK", "1");
    let good = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (good - neutral - 0.025).abs() < 1e-5,
        "real scorer did not consume refreshed good heat"
    );
    store.mark_query_feedback(&request, &[target.clone()], false, "human")?;
    let bad = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (bad - neutral * 0.92).abs() < 1e-5,
        "real scorer did not consume latest bad penalty"
    );
    std::env::set_var("RSRS_BAD_PENALTY", "0");
    let bad_off = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (bad_off - neutral).abs() < 1e-6,
        "bad penalty disable did not restore neutral score"
    );
    let context = respire::feedback::query_settings(
        &store,
        &MemoryQuery::new("unrelated query"),
        &store.all(false)?,
    )?;
    anyhow::ensure!(
        context["feedback"]["bad"]
            .as_object()
            .is_some_and(|map| map.is_empty()),
        "unrelated query received a penalty"
    );
    let other_project = respire::feedback::query_settings(
        &store,
        &MemoryQuery::new(text).of_project("other-project"),
        &store.all(false)?,
    )?;
    anyhow::ensure!(
        other_project["feedback"]["good"]
            .as_object()
            .is_some_and(|map| map.is_empty())
            && other_project["feedback"]["bad"]
                .as_object()
                .is_some_and(|map| map.is_empty()),
        "another project received a feedback observation"
    );
    std::env::set_var("RSRS_BAD_PENALTY", "1");
    let app = respire::service::App {
        keys: SessionKeys::from_urk([11; 32])?,
        store: respire::transport::local::LocalStore::open(&root.path().join("rsrs.db"))?,
        embedder: Box::new(embedder.clone()),
    };
    let service_rows = app.search(text, 20, None)?;
    let service_score = service_rows
        .iter()
        .find(|row| row.entry.id == target)
        .map(|row| row.score)
        .context("service candidate absent")?;
    anyhow::ensure!(
        (service_score - bad).abs() < 1e-5,
        "service search did not share query-conditioned feedback"
    );
    drop(app);
    drop(store);
    drop(embedder);
    let _: Value = respire::core_sdk::execute("engine_control", json!({"action":"reset"}))?;
    let current = std::env::current_exe()?;
    let examples = current.parent().context("example directory")?;
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let exe = cli_executable()?;
    let secret = format!("A3-{}", "14".repeat(18));
    let salt = "15".repeat(16);
    let kek = respire::memory::crypto::derive_rsrs_kek(&secret, &salt)?;
    let (nonce, wrapped) = respire::memory::crypto::wrap_key(&[11; 32], &kek)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(root.path().join("session.json"))?.write_all(&serde_json::to_vec(&json!({"user":"synthetic-probe","vault_version":4,"pass":"","kdf_salt":salt,"wrapped_urk":format!("{}{wrapped}",respire::memory::crypto::RSRS_PREFIX),"urk_nonce":nonce}))?)?;
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    let cli = CliProbe {
        root: root.path().to_owned(),
        exe,
        secret,
        port,
    };
    let first = cli.run(&["--json", "recall", text, "--limit", "20"])?;
    anyhow::ensure!(
        (cli_score(&first, &target)? - bad).abs() < 1e-5,
        "runtime recall differs from direct Core/service score"
    );
    let request = first["summary"]["query_log_id"]
        .as_str()
        .context("real runtime query identity")?;
    let _: Value = cli.run(&[
        "--json",
        "query-log",
        "mark",
        &target,
        "--good",
        "--query-log-id",
        request,
        "--source",
        "human",
    ])?;
    let refreshed = cli.run(&["--json", "recall", text, "--limit", "20"])?;
    anyhow::ensure!(
        (cli_score(&refreshed, &target)? - good).abs() < 1e-5,
        "running runtime did not refresh latest feedback"
    );
    let runtime = cli.run(&["--json", "--runtime-internal", "--status"])?;
    anyhow::ensure!(
        runtime["summary"]["pid"].as_u64().is_some(),
        "no owned runtime was exercised"
    );
    let eval = root.path().join("synthetic-eval.jsonl");
    std::fs::write(
        &eval,
        format!(
            "{}\n{}\n",
            json!({"query":text,"expect":[target]}),
            json!({"query":"unrelated query","expect":[]})
        ),
    )?;
    let saved = root.path().join("bench.json");
    let before = cli.run(&["--json", "query-log"])?;
    let _: Value = cli.run(&[
        "--json",
        "bench",
        "run",
        eval.to_str().context("UTF8 fixture path")?,
        "--topk",
        "20",
        "--save",
        saved.to_str().context("UTF8 report path")?,
    ])?;
    let report: Value = serde_json::from_slice(&std::fs::read(&saved)?)?;
    let bench_score = report["results"][0]["top1_score"]
        .as_f64()
        .context("bench score")? as f32;
    anyhow::ensure!(
        report["results"][0]["rank"] == 0 && (bench_score - good).abs() < 1e-5,
        "bench did not refresh the same scorer context"
    );
    let after = cli.run(&["--json", "query-log"])?;
    anyhow::ensure!(
        before["summary"] == after["summary"],
        "benchmark wrote query logs"
    );
    let standalone = examples.join(format!("ablation_bench{suffix}"));
    anyhow::ensure!(
        standalone.is_file(),
        "build the matching ablation_bench example"
    );
    let standalone = cli.run_program(
        &standalone,
        &[eval.to_str().context("UTF8 eval path")?, "--topk", "20"],
    )?;
    let standalone_score = standalone["results"][0]["top1_score"]
        .as_f64()
        .context("standalone bench score")? as f32;
    anyhow::ensure!(
        standalone["results"][0]["rank"] == 0 && (standalone_score - good).abs() < 1e-5,
        "standalone benchmark did not refresh scorer context"
    );
    let diary = diary_probe::run(&cli.exe)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"diary":diary,"provider":"real-m3","feedback_contract":respire::core_sdk::FEEDBACK_CONTRACT,"synthetic_entries":3,"target":target,"neutral":neutral,"legacy_read_hot":read_hot,"good":good,"bad":bad,"bad_off":bad_off,"service_score":service_score,"runtime_score":cli_score(&refreshed,&target)?,"runtime_pid":runtime["summary"]["pid"],"bench_score":bench_score,"standalone_bench_score":standalone_score,"checks":"PASS","original_benchmark_replicated":false})
        )?
    );
    Ok(())
}

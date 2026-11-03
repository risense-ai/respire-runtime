//! Real HTTP v2 + real M3 concurrency regression. Use only a disposable local
//! server/database: registers a fresh synthetic account, never an existing one.
use anyhow::{Context, Result};
use respire::core_sdk::{search::Embedder, Prepared};
use respire::memory::bge::BgeEmbedder;
use respire::transport::{
    local::LocalStore,
    remote::{RemoteConfig, RemoteTransport},
};
use respire::{MemoryEngine, MemoryEntry, MemoryTransport, SessionKeys};
use respire_app as respire;
use serde_json::{json, Value};
use std::{
    sync::{mpsc, Mutex},
    time::Duration,
};

struct PausedRealProvider {
    real: BgeEmbedder,
    prepared: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl Embedder for PausedRealProvider {
    fn model_name(&self) -> &str {
        self.real.model_name()
    }
    fn dims(&self) -> usize {
        self.real.dims()
    }
    fn prepare(&self, entry: &MemoryEntry) -> Result<Prepared> {
        let result = self.real.prepare(entry)?;
        self.prepared.send(())?;
        self.release
            .lock()
            .map_err(|_| anyhow::anyhow!("probe release lock poisoned"))?
            .recv_timeout(Duration::from_secs(120))?;
        Ok(result)
    }
}
fn read(store: &LocalStore, keys: &SessionKeys, id: &str) -> Result<MemoryEntry> {
    let stored = store
        .all(false)?
        .into_iter()
        .find(|m| m.id == id)
        .context("synthetic diary absent")?;
    MemoryEngine::open(keys, &stored)
}
fn main() -> Result<()> {
    anyhow::ensure!(
        std::env::var_os("RSRS_CORE_TEST_MODE").is_none(),
        "real-model probe rejects test inference"
    );
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 3 && args[2] == "--confirm-disposable-server",
        "pass a disposable localhost API URL and --confirm-disposable-server"
    );
    let address = args[1].trim_end_matches('/');
    let url = url::Url::parse(address)?;
    anyhow::ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some()
            && url.port() != Some(15169)
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none(),
        "disposable loopback server only"
    );
    let health: Value = ureq::get(&format!("{address}/health"))
        .call()?
        .into_json()?;
    anyhow::ensure!(health["service"] == "respire", "unexpected fixture service");
    let user = format!("diary-sync-fixture-{}", uuid::Uuid::new_v4().simple());
    let registered:Value=ureq::post(&format!("{address}/register")).send_json(json!({
        "user":user,"pass_hash":format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple())
    }))?.into_json()?;
    let remote = RemoteTransport::new(RemoteConfig {
        address: address.into(),
        token: registered["token"]
            .as_str()
            .context("synthetic registration failed")?
            .into(),
    });
    let root = tempfile::tempdir()?;
    let b_root = root.path().join("b");
    std::fs::create_dir(&b_root)?;
    std::env::set_var("RSRS_DATA_DIR", &b_root);
    let keys = SessionKeys::from_urk([81; 32])?;
    let provider = BgeEmbedder::load_model("m3")?;
    anyhow::ensure!(provider.dims() == 1024, "real M3 dimensions");
    let mut a = LocalStore::open(&root.path().join("a.db"))?;
    let b_path = b_root.join("rsrs.db");
    let mut b = LocalStore::open(&b_path)?;
    let mut entry: MemoryEntry = serde_json::from_value(json!({
        "id":uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL,format!("activity-track/{user}/2026-10-27").as_bytes()).to_string(),
        "kind":"Context","tags":[],"title":"\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-27","content":"\u{3010}09:00\u{3011}synthetic common event",
        "user":user,"computer":"synthetic-device-a","project":"sync-probe",
        "created_at":"2026-10-27T09:00:00.000Z","updated_at":"2026-10-27T09:00:00.000Z",
        "modified_by":"synthetic-device-a","importance":"trivial","parent_id":"","emotion":-1.0
    }))?;
    a.put(&MemoryEngine::seal(&keys, &provider, &entry, &user)?)?;
    respire::sync::sync_all(&keys, &a, &remote)?;
    respire::sync::sync_all(&keys, &b, &remote)?;
    let (prepared_tx, prepared_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let index_path = b_path.clone();
    let index_thread = std::thread::spawn(move || -> Result<()> {
        let store = LocalStore::open(&index_path)?;
        let keys = SessionKeys::from_urk([81; 32])?;
        let provider = PausedRealProvider {
            real: BgeEmbedder::load_model("m3")?,
            prepared: prepared_tx,
            release: Mutex::new(release_rx),
        };
        respire::diary::rebuild(&store, &keys, &provider, || Ok(()), |action| action())
    });
    prepared_rx.recv_timeout(Duration::from_secs(120))?;
    eprintln!("diary sync probe: real M3 background artifact prepared; overlapping two-device writes and HTTP sync");
    entry
        .content
        .push_str("\n\u{3010}09:16\u{3011}synthetic-confirmed-local-append");
    entry.updated_at = "2026-10-27T09:16:00.000Z".into();
    entry.modified_by = "synthetic-device-b".into();
    b.put(&MemoryEngine::seal(&keys, &provider, &entry, &user)?)?;
    let confirmed = read(&b, &keys, &entry.id)?;
    let mut earlier = entry.clone();
    earlier.content = "\u{3010}09:00\u{3011}synthetic common event\n\u{3010}09:09\u{3011}synthetic-remote-append".into();
    earlier.updated_at = "2026-10-27T09:09:00.000Z".into();
    earlier.modified_by = "synthetic-device-a".into();
    a.put(&MemoryEngine::seal(&keys, &provider, &earlier, &user)?)?;
    respire::sync::sync_all(&keys, &a, &remote)?;
    let stats = respire::sync::sync_all(&keys, &b, &remote)?;
    release_tx.send(())?;
    let old_index = index_thread
        .join()
        .map_err(|_| anyhow::anyhow!("index fixture panicked"))?;
    anyhow::ensure!(
        old_index
            .err()
            .is_some_and(|e| e.to_string().contains("source changed")),
        "stale background source was not rejected"
    );
    anyhow::ensure!(
        stats.protocol == 2 && stats.pending == 0 && stats.pushed == 0 && stats.conflicts == 1,
        "expected a real server-side CAS conflict"
    );
    for _ in 0..4 {
        b.maintain_sync_storage()?;
        b = LocalStore::open(&b_path)?;
        respire::sync::sync_all(&keys, &b, &remote)?;
        let actual = read(&b, &keys, &entry.id)?;
        anyhow::ensure!(
            actual.content == confirmed.content
                && actual.updated_at == confirmed.updated_at
                && actual.modified_by == confirmed.modified_by,
            "confirmed diary regressed after sync/restart"
        );
        respire::diary::rebuild(&b, &keys, &provider, || Ok(()), |action| action())?;
        let result =
            respire::diary::search(&b, &keys, "synthetic-confirmed-local-append", 5, 4000, true)?;
        anyhow::ensure!(
            result.semantic_ready && !result.items.is_empty(),
            "stable diary search failed after sync/index/restart"
        );
        anyhow::ensure!(
            b.sync_counts()?.0 == 0 && b.sync_counts()?.1 == 1,
            "unresolved conflict must not be hidden or resent"
        );
    }
    eprintln!("diary sync probe: append survived repeated sync, pruning, restart and real reindex; checking explicit resolution");
    let epoch = remote.capabilities()?.context("v2 capability")?.epoch;
    let head = remote
        .pull_v2(&epoch, 0, None, true)?
        .changes
        .into_iter()
        .find(|c| c.blob.id == entry.id)
        .context("remote head missing")?;
    let conflict = b
        .sync_history(Some(&entry.id))?
        .into_iter()
        .find(|c| c["status"] == "conflict_saved")
        .context("conflict history missing")?;
    let conflict_rev = conflict["rev"].as_i64().context("conflict revision")?;
    let merged = format!("{}\n\u{3010}09:09\u{3011}synthetic-remote-append", confirmed.content);
    b.queue_conflict_resolution(
        &keys,
        &epoch,
        conflict_rev,
        head.rev,
        "merge",
        Some(&merged),
    )?;
    respire::sync::sync_all(&keys, &b, &remote)?;
    respire::sync::sync_all(&keys, &a, &remote)?;
    for _ in 0..2 {
        a = LocalStore::open(&root.path().join("a.db"))?;
        b = LocalStore::open(&b_path)?;
        respire::sync::sync_all(&keys, &a, &remote)?;
        respire::sync::sync_all(&keys, &b, &remote)?;
        anyhow::ensure!(
            read(&a, &keys, &entry.id)?.content == merged
                && read(&b, &keys, &entry.id)?.content == merged,
            "explicit merge did not converge"
        );
        anyhow::ensure!(
            b.sync_counts()?.0 == 0 && b.sync_counts()?.1 == 0,
            "explicit processed resolution still pending"
        );
    }
    println!(
        "{}",
        json!({"checks":"PASS","provider":"real-m3","server_revision":health["source_revision"],
        "real_http_v2":true,"real_background_overlap":true,"stale_index_commit_rejected":true,
        "append_survived_four_sync_prune_restart_reindex_rounds":true,"explicit_merge_converged":true,
        "automatic_merge":false,"quality_benchmark":false})
    );
    Ok(())
}

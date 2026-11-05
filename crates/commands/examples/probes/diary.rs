//! Real paired-SDK diary contract checks; all records and recovery material are synthetic.
use super::*;
use respire_app::core_sdk::search::Embedder;

pub fn run(exe: &std::path::Path) -> Result<Value> {
    anyhow::ensure!(
        std::env::var_os("RSRS_CORE_TEST_MODE").is_none(),
        "real diary probe rejects mock inference"
    );
    eprintln!("diary probe: real-model source and semantic retrieval");
    let root = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", root.path());
    let keys = SessionKeys::from_urk([29; 32])?;
    let store = respire::transport::local::LocalStore::open(&root.path().join("rsrs.db"))?;
    let embedder = respire::memory::bge::BgeEmbedder::load_model("m3")?;
    anyhow::ensure!(embedder.dims() == 1024, "real model dimensions");
    let body = "Today I repaired a bicycle wheel and replaced its damaged tyre. \u{4e2d}\u{6587}\u{9a91}\u{8f66}\u{65e5}\u{8bb0} 🧠";
    let mut diary = MemoryEntry {
        metadata: Default::default(),
        unknown_fields: Default::default(),
        id: "00000000-0000-4000-8000-000000000091".into(),
        user: "synthetic-diary".into(),
        title: "Synthetic daily notes".into(),
        content: body.into(),
        kind: respire::Kind::Time,
        tags: vec![],
        computer: "fixture".into(),
        project: "probe".into(),
        created_at: "2026-10-27T10:00:00Z".into(),
        updated_at: "2026-10-27T10:00:00Z".into(),
        emotion: -1.0,
        parent_id: String::new(),
        importance: "trivial".into(),
        device: "fixture".into(),
        modified_by: "fixture".into(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: vec![],
    };
    anyhow::ensure!(
        store.put(&MemoryEngine::seal(
            &keys,
            &embedder,
            &diary,
            "synthetic-diary"
        )?)?,
        "seed diary"
    );
    let before = store.meta_get("memory_revision_v1")?;
    let fallback = respire::diary::search(&store, &keys, "bicycle", 5, 4000, true)?;
    anyhow::ensure!(
        !fallback.semantic_ready && fallback.pending_fragments > 0 && !fallback.items.is_empty(),
        "missing index must retain lexical results"
    );
    respire::diary::rebuild(&store, &keys, &embedder, || Ok(()), |action| action())?;
    anyhow::ensure!(
        before == store.meta_get("memory_revision_v1")?,
        "derived indexing mutated authoritative source"
    );
    let semantic = respire::diary::search(
        &store,
        &keys,
        "I fixed the bike and changed a flat tire",
        5,
        4000,
        true,
    )?;
    anyhow::ensure!(
        semantic.semantic_ready && semantic.pending_fragments == 0 && !semantic.items.is_empty(),
        "real semantic-only diary retrieval failed: ready={} pending={} matches={}",
        semantic.semantic_ready,
        semantic.pending_fragments,
        semantic.items.len()
    );
    anyhow::ensure!(
        respire::diary::search(
            &store,
            &keys,
            "I fixed the bike and changed a flat tire",
            5,
            4000,
            false
        )?
        .items
        .is_empty(),
        "semantic fixture accidentally has lexical overlap"
    );
    let hit = &semantic.items[0];
    anyhow::ensure!(
        hit.source_id == diary.id && hit.evidence_state == "reference",
        "provenance contract"
    );
    let old_locator = hit.fragment_id.clone();
    anyhow::ensure!(
        !respire::diary::read_fragment(&store, &keys, &diary.id, &old_locator, 1, 4000)?
            .items
            .is_empty(),
        "fragment read"
    );
    drop(store);
    drop(embedder);

    let secret = format!("A3-{}", "26".repeat(18));
    let salt = "27".repeat(16);
    let kek = respire::memory::crypto::derive_rsrs_kek(&secret, &salt)?;
    let (nonce, wrapped) = respire::memory::crypto::wrap_key(&[29; 32], &kek)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(root.path().join("session.json"))?.write_all(&serde_json::to_vec(&json!({"user":"synthetic-diary","vault_version":4,"pass":"","kdf_salt":salt,"wrapped_urk":format!("{}{wrapped}",respire::memory::crypto::RSRS_PREFIX),"urk_nonce":nonce}))?)?;
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    let cli = CliProbe {
        root: root.path().to_owned(),
        exe: exe.to_owned(),
        secret,
        port,
    };
    eprintln!("diary probe: runtime and MCP retrieval");
    let result = cli.run(&[
        "--json",
        "diary-search",
        "I fixed the bike and changed a flat tire",
    ])?;
    anyhow::ensure!(
        result["summary"]["semantic_ready"] == true
            && result["details"]["items"][0]["source_id"] == diary.id,
        "runtime semantic path"
    );
    let read = cli.run(&[
        "--json",
        "diary-fragment",
        &diary.id,
        &old_locator,
        "--neighbors",
        "1",
    ])?;
    anyhow::ensure!(
        read["details"]["items"][0]["text"] == body,
        "runtime exact read"
    );
    let mcp = mcp_call(
        &cli,
        json!({"name":"memory_diary_search","arguments":{"query":"I fixed the bike and changed a flat tire"}}),
    )?;
    anyhow::ensure!(
        mcp["result"]["isError"] == false && mcp.to_string().contains(&diary.id),
        "MCP actual runtime search"
    );
    let mcp = mcp_call(
        &cli,
        json!({"name":"memory_diary_fragment","arguments":{"source_id":diary.id,"fragment_id":old_locator}}),
    )?;
    anyhow::ensure!(
        mcp["result"]["isError"] == false && mcp.to_string().contains(&diary.id),
        "MCP actual runtime fragment"
    );
    eprintln!("diary probe: restart and readonly/off policy");
    let _ = cli.run(&["--json", "runtime", "restart"])?;
    let restarted = cli.run(&[
        "--json",
        "diary-search",
        "I fixed the bike and changed a flat tire",
    ])?;
    anyhow::ensure!(
        restarted["summary"]["semantic_ready"] == true
            && restarted["details"]["items"][0]["source_id"] == diary.id,
        "restarted runtime lost diary index"
    );
    let _ = cli.run(&["--json", "agent-config", "--set", "workspace_mode=readonly"])?;
    let readonly = cli.run(&["--json", "diary-search", "bicycle", "--mode", "lexical"])?;
    anyhow::ensure!(
        readonly["details"]["items"][0]["source_id"] == diary.id,
        "readonly must retain diary reads"
    );
    let _ = cli.run(&["--json", "agent-config", "--set", "workspace_mode=off"])?;
    let denied = mcp_call(
        &cli,
        json!({"name":"memory_diary_search","arguments":{"query":"bicycle"}}),
    )?;
    anyhow::ensure!(
        denied["result"]["isError"] == true && !denied.to_string().contains(body),
        "off mode must refuse actual MCP diary reads"
    );
    let _ = cli.run(&["--json", "agent-config", "--set", "workspace_mode=normal"])?;
    let _ = cli.run(&["--json", "runtime", "stop"])?;
    let store = respire::transport::local::LocalStore::open(&root.path().join("rsrs.db"))?;
    diary.content.push_str(" Later I cleaned the chain.");
    diary.updated_at = "2026-10-27T11:00:00Z".into();
    let embedder = respire::memory::bge::BgeEmbedder::load_model("m3")?;
    anyhow::ensure!(embedder.dims() == 1024, "real model dimensions");
    anyhow::ensure!(
        store.put(&MemoryEngine::seal(
            &keys,
            &embedder,
            &diary,
            "synthetic-diary"
        )?)?,
        "append fixture"
    );
    anyhow::ensure!(
        respire::diary::read_fragment(&store, &keys, &diary.id, &old_locator, 0, 4000).is_err(),
        "stale locator accepted"
    );
    anyhow::ensure!(
        respire::diary::needs_rebuild(&store)?,
        "append was not invalidated"
    );
    respire::diary::rebuild(&store, &keys, &embedder, || Ok(()), |action| action())?;
    anyhow::ensure!(!respire::diary::needs_rebuild(&store)?, "append rebuild");
    eprintln!("diary probe: background inference and readonly acknowledgement fence");
    // Observe real diary inference before pausing it through the normal RPC mode gate.
    diary.content = body.repeat(320);
    diary.updated_at = "2026-10-27T12:00:00Z".into();
    // Prepare the ordinary memory artifact synchronously. The runtime rebuilds
    // that index before diary fragments; including it in the observation window
    // makes this diary cancellation probe depend on unrelated full-body work.
    anyhow::ensure!(
        store.put(&MemoryEngine::seal(
            &keys,
            &embedder,
            &diary,
            "synthetic-diary"
        )?)?,
        "pending long diary"
    );
    anyhow::ensure!(
        !store.index_missing("m3")?,
        "ordinary index fixture not ready"
    );
    anyhow::ensure!(
        respire::diary::needs_rebuild(&store)?,
        "diary fixture not pending"
    );
    drop(store);
    // The restarted debug runtime verifies both pinned ~569 MB containers before
    // it can start diary inference. Give that distinct prerequisite a bounded
    // budget; keep the actual diary observation window at 120 seconds.
    let preparation_deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let status = cli.run(&["--json", "status"])?;
        if status["summary"]["model_operation"]["item"] == "diary-fragments" {
            break;
        }
        check_pending_work(
            &status,
            preparation_deadline,
            &mut deadline,
            "did not observe actual background diary work",
        )?;
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = cli.run(&["--json", "agent-config", "--set", "workspace_mode=readonly"])?;
    let derived = rusqlite::Connection::open_with_flags(
        root.path().join("diary-fragments-v1.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let snapshot = || -> Result<(i64, String)> {
        use sha2::Digest;
        let revision: i64 = derived.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let sources = derived
            .prepare("SELECT id,source FROM diary_sources ORDER BY id")?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let artifacts = derived
            .prepare(
                "SELECT id,source_id,generation,hex(artifact) FROM diary_artifacts ORDER BY id",
            )?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let digest = sha2::Sha256::digest(serde_json::to_vec(&(sources, artifacts))?);
        Ok((revision, format!("{digest:x}")))
    };
    let acknowledged = snapshot()?;
    eprintln!("diary probe: readonly acknowledged; checking durable cache and drain");
    std::thread::sleep(std::time::Duration::from_millis(300));
    anyhow::ensure!(
        snapshot()? == acknowledged,
        "derived commit after readonly acknowledgement"
    );
    let _ = cli.run(&["--json", "runtime", "stop"])?;
    anyhow::ensure!(
        snapshot()? == acknowledged,
        "derived commit while draining paused runtime"
    );
    drop(derived);
    let _ = cli.run(&[
        "--json",
        "--direct",
        "agent-config",
        "--set",
        "workspace_mode=normal",
    ])?;
    eprintln!("diary probe: different-key account profile round trip");
    let alternate = root.path().join("accounts/diary-other");
    std::fs::create_dir_all(&alternate)?;
    let other_keys = SessionKeys::from_urk([71; 32])?;
    let other_store = respire::transport::local::LocalStore::open(&alternate.join("rsrs.db"))?;
    let mut other_entry = diary.clone();
    other_entry.content = "On the weekend I baked bread with flour and yeast.".into();
    other_entry.updated_at = "2026-10-27T13:00:00Z".into();
    {
        let _deferred = respire::core_sdk::defer_indexing();
        anyhow::ensure!(
            other_store.put(&MemoryEngine::seal(
                &other_keys,
                &embedder,
                &other_entry,
                "synthetic-other"
            )?)?,
            "other-key source"
        );
    }
    drop(other_store);
    let (other_nonce, other_wrapped) = respire::memory::crypto::wrap_key(&[71; 32], &kek)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(alternate.join("session.json"))?.write_all(&serde_json::to_vec(&json!({"user":"synthetic-other","vault_version":4,"pass":"","kdf_salt":salt,"wrapped_urk":format!("{}{other_wrapped}",respire::memory::crypto::RSRS_PREFIX),"urk_nonce":other_nonce}))?)?;
    let _ = cli.run(&["--json", "account", "use", "diary-other"])?;
    let other_result = cli.run(&["--json", "diary-search", "bicycle", "--mode", "lexical"])?;
    anyhow::ensure!(
        other_result["details"]["items"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "old account's lexical text crossed profile boundary"
    );
    let mut other_hybrid = cli.run(&["--json", "diary-search", "bread"])?;
    // Profile changes enter the same model-preparation path as runtime restarts.
    let preparation_deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut reported_pending = false;
    while other_hybrid["summary"]["semantic_ready"] != true {
        let status = cli.run(&["--json", "status"])?;
        if !reported_pending {
            eprintln!(
                "diary probe: other-account pending model_operation={}, retrieval_index={}",
                status["summary"]["model_operation"], status["summary"]["retrieval_index"]
            );
            reported_pending = true;
        }
        check_pending_work(
            &status,
            preparation_deadline,
            &mut deadline,
            "other-account real semantic index never became ready",
        )?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        other_hybrid = cli.run(&["--json", "diary-search", "bread"])?;
    }
    let other_items = other_hybrid["details"]["items"]
        .as_array()
        .context("other-account hybrid result")?;
    anyhow::ensure!(
        !other_items.is_empty()
            && other_items.iter().all(|item| item["text"]
                .as_str()
                .is_some_and(|text| text.contains("bread") && !text.contains("bicycle"))),
        "hybrid returned another account's plaintext"
    );
    let _ = cli.run(&["--json", "account", "use", "main"])?;
    let original = cli.run(&["--json", "diary-search", "bicycle", "--mode", "lexical"])?;
    anyhow::ensure!(
        !original["details"]["items"]
            .as_array()
            .context("main-account result")?
            .is_empty(),
        "main account was not restored"
    );
    let _ = cli.run(&["--json", "runtime", "stop"])?;
    let store = respire::transport::local::LocalStore::open(&root.path().join("rsrs.db"))?;
    anyhow::ensure!(store.forget(&diary.id)?, "delete fixture");
    anyhow::ensure!(
        respire::diary::clear_if_empty(&store, |action| action())?,
        "last diary cleanup"
    );
    anyhow::ensure!(
        respire::diary::search(&store, &keys, "bicycle", 5, 4000, true)?
            .items
            .is_empty(),
        "deleted source reappeared"
    );
    Ok(
        json!({"provider":"real-m3","dimensions":1024,"semantic_only":true,"runtime":true,"runtime_restart":true,"readonly_read":true,"off_mcp_denied":true,"mcp_stdio":true,"missing_index_fallback":true,"append_stale_locator":true,"delete_cleanup":true,"real_background_readonly_fence":true,"different_key_hybrid_isolation":true,"profile_round_trip":true,"source_revision_unchanged_by_indexing":true,"quality_benchmark":false,"checks":"PASS"}),
    )
}

fn check_pending_work(
    status: &Value,
    preparation_deadline: std::time::Instant,
    work_deadline: &mut std::time::Instant,
    message: &str,
) -> Result<()> {
    let operation = &status["summary"]["model_operation"];
    let preparing = operation["active"] == true
        && matches!(operation["phase"].as_str(), Some("prepare" | "verify"));
    if preparing {
        anyhow::ensure!(
            std::time::Instant::now() < preparation_deadline,
            "{message}; model preparation did not finish: model_operation={}, retrieval_index={}",
            operation,
            status["summary"]["retrieval_index"]
        );
        *work_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    }
    anyhow::ensure!(
        std::time::Instant::now() < *work_deadline,
        "{message}: model_operation={}, retrieval_index={}",
        operation,
        status["summary"]["retrieval_index"]
    );
    Ok(())
}

fn mcp_call(cli: &CliProbe, params: Value) -> Result<Value> {
    use std::{
        io::{Read, Seek, SeekFrom, Write},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut input = tempfile::tempfile()?;
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":91,"method":"tools/call","params":params})
    )?;
    input.seek(SeekFrom::Start(0))?;
    let mut output = tempfile::tempfile()?;
    let mut child = Command::new(&cli.exe)
        .arg("mcp")
        .current_dir(&cli.root)
        .env("HOME", &cli.root)
        .env("USERPROFILE", &cli.root)
        .env("RSRS_DATA_DIR", &cli.root)
        .env("RSRS_RPC_PORT", cli.port.to_string())
        .env("RSRS_SUPER", &cli.secret)
        .env("RSRS_NO_AUTOSYNC", "1")
        .env("RSRS_UPDATE_CHECK", "0")
        .stdin(Stdio::from(input))
        .stdout(output.try_clone()?)
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            anyhow::ensure!(status.success(), "MCP fixture exit");
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("MCP fixture timeout");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    output.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    output.read_to_string(&mut text)?;
    serde_json::from_str(text.trim()).context("MCP must emit one response")
}

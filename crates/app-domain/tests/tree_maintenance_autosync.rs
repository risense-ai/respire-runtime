use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use respire_app_domain::memory::{MemoryEngine, SessionKeys};
use respire_app_domain::service::{self, DeepenPlan, DeepenSubRoot, SplitOp, SplitSpec};
use respire_app_domain::transport::local::LocalStore;
use respire_protocol::MemoryEntry;
use serde_json::json;

static NOTIFICATIONS: Mutex<Vec<std::result::Result<Vec<String>, String>>> =
    Mutex::new(Vec::new());

fn pending_ids(path: &Path) -> Result<Vec<String>> {
    Ok(LocalStore::open_existing(path)?
        .outgoing()?
        .into_iter()
        .map(|operation| operation.op_id)
        .collect())
}

// Observe from another SQLite connection, deliberately without running a
// transport. A missed/coalesced in-memory hint must leave all work durable.
fn observe_committed_work() {
    let receipt = service::database_path(&service::data_dir())
        .and_then(|path| pending_ids(&path))
        .map_err(|error| format!("{error:#}"));
    NOTIFICATIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(receipt);
}

#[test]
fn tree_edits_return_after_local_commit_and_only_hint_the_existing_worker() -> Result<()> {
    // This dedicated test process has only this test; it does not use the real
    // session/config or the real transport, even if the old inline path returns.
    let temp = tempfile::tempdir()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    std::env::set_var("RSRS_DATA_DIR", temp.path());
    std::env::set_var("RSRS_NO_AUTOSYNC", "0");
    std::env::set_var("RSRS_ADDR", format!("http://{}", listener.local_addr()?));
    std::env::set_var("RSRS_TOKEN", "synthetic-tree-maintenance-token");
    std::env::set_var("NO_PROXY", "*");
    std::env::set_var("no_proxy", "*");

    let path = service::database_path(temp.path())?;
    let store = LocalStore::open(&path)?;
    let keys = SessionKeys::from_urk([42; 32])?;
    let provider = respire_core_sdk::search::HashingEmbedder::default();
    let _defer = respire_core_sdk::defer_indexing();
    let root: MemoryEntry = serde_json::from_value(json!({
        "id":"fixture-root","kind":"Context","title":"Root","content":"Synthetic root",
        "tags":[],"user":"fixture","computer":"","project":"",
        "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z",
        "emotion":-1,"parent_id":""
    }))?;
    let mut member = root.clone();
    member.id = "fixture-member".into();
    member.parent_id = root.id.clone();
    for entry in [&root, &member] {
        store.put_inner(&MemoryEngine::seal(&keys, &provider, entry, &entry.user)?, false)?;
    }
    assert!(pending_ids(&path)?.is_empty());

    let spec = SplitSpec {
        summary: None,
        items: ["First", "Second"].into_iter().map(|label| SplitOp {
            title: label.into(),
            content: format!("Synthetic {label}"),
            kind: "context".into(),
            tags: Vec::new(),
            parent: String::new(),
        }).collect(),
    };
    assert!(service::autosync_active());
    assert!(respire_app_domain::sync::remote_configured());

    // Standalone library invocation has no resident notifier: local receipt
    // and durable outgoing versions still succeed without starting a worker.
    assert_eq!(service::split_exec(&keys, &provider, &store, &root, &spec)?, 2);
    let standalone = pending_ids(&path)?;
    assert_eq!(standalone.len(), 2);

    service::install_autosync_notifier(observe_committed_work);
    let plan = DeepenPlan {
        sub_roots: vec![DeepenSubRoot {
            title: "Cluster".into(),
            member_ids: vec![member.id.clone()],
            member_titles: vec![member.title.clone()],
        }],
        leftovers: Vec::new(),
    };
    assert_eq!(service::deepen_apply(&keys, &provider, &store, &root.id, &plan, &["Cluster".into()])?, (1, 1));
    let deepened = pending_ids(&path)?;
    assert_eq!(deepened.len(), 4);
    assert_eq!(service::split_exec(&keys, &provider, &store, &root, &spec)?, 2);
    let split = pending_ids(&path)?;
    assert_eq!(split.len(), 6);

    assert!(service::deepen_apply(&keys, &provider, &store, &root.id, &plan, &[]).is_err());
    assert!(service::split_exec(&keys, &provider, &store, &root, &SplitSpec {
        summary: None, items: Vec::new()
    }).is_err());
    assert_eq!(pending_ids(&path)?, split);

    // Preserve the legacy split's partial-write failure: the earlier child
    // stays queued, the original error is returned, and no success hint fires.
    let partial = SplitSpec {
        summary: None,
        items: ["context", "invalid-kind"].into_iter().map(|kind| SplitOp {
            title: "Partial fixture".into(),
            content: "Synthetic partial split".into(),
            kind: kind.into(),
            tags: Vec::new(),
            parent: String::new(),
        }).collect(),
    };
    let Err(error) = service::split_exec(&keys, &provider, &store, &root, &partial) else {
        panic!("invalid second split child unexpectedly succeeded");
    };
    assert_eq!(error.to_string(), "unsupported_metadata: unknown memory kind");
    assert_eq!(pending_ids(&path)?.len(), 7);

    std::env::set_var("RSRS_NO_AUTOSYNC", "1");
    assert_eq!(service::split_exec(&keys, &provider, &store, &root, &spec)?, 2);
    let disabled = pending_ids(&path)?;
    assert_eq!(disabled.len(), 9);
    std::env::set_var("RSRS_NO_AUTOSYNC", "0");
    std::env::set_var("RSRS_ADDR", "");
    assert!(!respire_app_domain::sync::remote_configured());
    assert_eq!(service::split_exec(&keys, &provider, &store, &root, &spec)?, 2);
    let unconfigured = pending_ids(&path)?;
    assert_eq!(unconfigured.len(), 11);
    assert_eq!(
        *NOTIFICATIONS.lock().unwrap_or_else(|error| error.into_inner()),
        vec![Ok(deepened), Ok(split)]
    );

    drop(store);
    assert_eq!(pending_ids(&path)?, unconfigured);
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
    Ok(())
}

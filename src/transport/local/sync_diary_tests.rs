//! Synthetic encrypted diaries only. No account, user library or model download.
use super::*;
use crate::{transport::MemoryTransport, MemoryEngine, MemoryEntry};
use anyhow::Context;

const ID: &str = "synthetic-daily-track";
struct Fixture {
    store: LocalStore,
    keys: SessionKeys,
    appended: MemoryEntry,
    head: StoredMemory,
    root: tempfile::TempDir,
}
fn page(rev: i64, blob: StoredMemory, status: &str, op_id: Option<String>) -> Page {
    Page {
        epoch: "e".into(),
        until: rev,
        cursor: rev,
        has_more: false,
        total: 1,
        alive: 1,
        changes: vec![Change {
            rev,
            status: status.into(),
            op_id,
            blob,
        }],
    }
}
fn visible(store: &LocalStore, keys: &SessionKeys) -> Result<MemoryEntry> {
    let stored = store
        .all(true)?
        .into_iter()
        .find(|m| m.id == ID)
        .context("synthetic diary missing")?;
    MemoryEngine::open(keys, &stored)
}
fn fixture() -> Result<Fixture> {
    let root = tempfile::tempdir()?;
    let store = LocalStore::open(&root.path().join("synthetic.db"))?;
    let keys = SessionKeys::from_urk([73; 32])?;
    let provider = crate::memory::search::HashingEmbedder::default();
    // Concise remember uses the ordinary Context default as well as explicit Time.
    let mut entry: MemoryEntry = serde_json::from_value(serde_json::json!({
        "id":ID,"kind":"Context","tags":[],"title":"活动轨迹 2026-10-27",
        "content":"【09:00】synthetic common event","user":"synthetic-account",
        "computer":"device-a","project":"synthetic","created_at":"2026-10-27T09:00:00.000Z",
        "updated_at":"2026-10-27T09:00:00.000Z","modified_by":"device-a",
        "emotion":-1.0,"parent_id":"","importance":"trivial"
    }))?;
    store.begin_sync_epoch("e")?;
    store.meta_set("sync_v2_resolution_support", "1")?;
    store.apply_page(
        &keys,
        &page(
            1,
            MemoryEngine::seal(&keys, &provider, &entry, "synthetic-account")?,
            "applied",
            None,
        ),
        false,
    )?;
    entry
        .content
        .push_str("\n【09:16】synthetic locally confirmed append");
    entry.updated_at = "2026-10-27T09:16:00.000Z".into();
    entry.modified_by = "device-b".into();
    let appended = MemoryEngine::seal(&keys, &provider, &entry, "synthetic-account")?;
    assert!(store.put(&appended)?);
    assert_eq!(visible(&store, &keys)?.content, entry.content);
    let outgoing = store.outgoing()?;
    let mut remote = entry.clone();
    remote.content =
        "【09:00】synthetic common event\n【09:09】synthetic independent remote event".into();
    remote.updated_at = "2026-10-27T09:09:00.000Z".into();
    remote.modified_by = "device-a".into();
    let head = MemoryEngine::seal(&keys, &provider, &remote, "synthetic-account")?;
    store.apply_page(&keys, &page(2, head.clone(), "applied", None), false)?;
    store.acknowledge(
        &outgoing,
        &[Receipt {
            op_id: outgoing[0].op_id.clone(),
            status: "conflict_saved".into(),
            stored_rev: 3,
            head_rev: 2,
        }],
        false,
    )?;
    // The ack alone must protect the append, even before the conflict page arrives.
    store.materialize_received(&keys)?;
    store.apply_page(
        &keys,
        &page(
            3,
            appended,
            "conflict_saved",
            Some(outgoing[0].op_id.clone()),
        ),
        false,
    )?;
    Ok(Fixture {
        store,
        keys,
        appended: entry,
        head,
        root,
    })
}
fn resolved(f: &Fixture, action: &str, head_rev: i64, restore_op_id: Option<String>) -> Result<()> {
    f.store.apply_resolution_page(&ResolutionPage {
        epoch: "e".into(),
        until: 1,
        cursor: 1,
        has_more: false,
        resolutions: vec![Resolution {
            seq: 1,
            conflict_rev: 3,
            id: ID.into(),
            action: action.into(),
            head_rev,
            restore_op_id,
            processed_at: "2026-10-27T10:00:00.000Z".into(),
        }],
    })
}
#[test]
fn conflict_receipt_does_not_replace_a_confirmed_diary_append() -> Result<()> {
    let f = fixture()?;
    f.store.materialize_received(&f.keys)?;
    let actual = visible(&f.store, &f.keys)?;
    assert_eq!(
        actual.content, f.appended.content,
        "transport receipt must not discard a confirmed diary append"
    );
    assert_eq!(actual.updated_at, f.appended.updated_at);
    assert_eq!(actual.modified_by, "device-b");
    let review = f.store.list_conflicts(&f.keys, Some(ID), false)?;
    assert_eq!(review[0]["current_scope"], "remote_canonical");
    assert_eq!(
        review[0]["current"]["value"]["entry"]["content"],
        MemoryEngine::open(&f.keys, &f.head)?.content
    );
    assert_eq!(f.store.sync_counts()?.0, 0);
    assert_eq!(
        f.store.sync_counts()?.1,
        1,
        "content conflict must remain visible"
    );
    Ok(())
}
#[test]
fn pruning_restart_and_later_head_cannot_erase_the_working_branch() -> Result<()> {
    let mut f = fixture()?;
    f.store.maintain_sync_storage()?;
    assert_eq!(
        f.store.connection.query_row(
            "SELECT count(*) FROM sync_outbox WHERE id=?1",
            [ID],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    for rev in 4..7 {
        f.store = LocalStore::open(&f.root.path().join("synthetic.db"))?;
        f.store
            .apply_page(&f.keys, &page(rev, f.head.clone(), "applied", None), false)?;
        f.store.materialize_received(&f.keys)?;
        f.store.maintain_sync_storage()?;
        assert_eq!(visible(&f.store, &f.keys)?.content, f.appended.content);
        assert_eq!(
            f.store
                .connection
                .query_row("SELECT rev FROM sync_base WHERE id=?1", [ID], |r| r
                    .get::<_, i64>(0))?,
            1
        );
        assert_eq!(
            f.store.connection.query_row(
                "SELECT rev FROM sync_remote_heads WHERE id=?1",
                [ID],
                |r| r.get::<_, i64>(0)
            )?,
            rev
        );
    }
    assert!(!f
        .store
        .set_artifact(ID, b"stale-index-artifact", &f.head.ciphertext)?);
    assert_eq!(visible(&f.store, &f.keys)?.content, f.appended.content);
    Ok(())
}
#[test]
fn explicit_diary_resolution_uses_the_inspected_head_without_forging_an_applied_base() -> Result<()>
{
    for action in ["take_incoming", "merge"] {
        let f = fixture()?;
        f.store.materialize_received(&f.keys)?;
        let merged = format!("{}\nexplicitly reviewed remote event", f.appended.content);
        let content = (action == "merge").then_some(merged.as_str());
        assert!(f
            .store
            .queue_conflict_resolution(&f.keys, "e", 3, 1, action, content)
            .is_err());
        assert!(f.store.outgoing()?.is_empty());
        f.store
            .queue_conflict_resolution(&f.keys, "e", 3, 2, action, content)?;
        let operations = f.store.outgoing()?;
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].base_rev, Some(2));
        assert!(operations[0].parent_op_id.is_none());
        assert_eq!(
            f.store
                .connection
                .query_row("SELECT rev FROM sync_base WHERE id=?1", [ID], |r| r
                    .get::<_, i64>(0))?,
            1
        );
        let expected = if action == "merge" {
            merged
        } else {
            f.appended.content.clone()
        };
        assert_eq!(
            MemoryEngine::open(&f.keys, &operations[0].blob)?.content,
            expected
        );
        if action == "take_incoming" {
            f.store
                .queue_conflict_resolution(&f.keys, "e", 3, 2, action, None)?;
        }
        assert_eq!(
            f.store.outgoing()?.len(),
            1,
            "repeating must not create another operation"
        );
        f.store.acknowledge(
            &operations,
            &[Receipt {
                op_id: operations[0].op_id.clone(),
                status: "applied".into(),
                stored_rev: 4,
                head_rev: 4,
            }],
            false,
        )?;
        f.store.apply_page(
            &f.keys,
            &page(
                4,
                operations[0].blob.clone(),
                "applied",
                Some(operations[0].op_id.clone()),
            ),
            false,
        )?;
        resolved(&f, action, 4, Some(operations[0].op_id.clone()))?;
        f.store.materialize_received(&f.keys)?;
        f.store.maintain_sync_storage()?;
        assert_eq!(visible(&f.store, &f.keys)?.content, expected);
        assert_eq!(f.store.sync_counts()?.1, 0);
    }
    Ok(())
}
#[test]
fn only_a_processed_keep_current_decision_can_release_the_live_diary_branch() -> Result<()> {
    let f = fixture()?;
    f.store
        .queue_conflict_resolution(&f.keys, "e", 3, 2, "keep_current", None)?;
    f.store.materialize_received(&f.keys)?;
    assert_eq!(visible(&f.store, &f.keys)?.content, f.appended.content);
    assert!(f.store.outgoing()?.is_empty());
    resolved(&f, "keep_current", 2, None)?;
    f.store.materialize_received(&f.keys)?;
    assert_eq!(
        visible(&f.store, &f.keys)?.content,
        MemoryEngine::open(&f.keys, &f.head)?.content
    );
    assert_eq!(f.store.sync_counts()?.1, 0);
    Ok(())
}
#[test]
fn a_remote_deletion_or_promotion_retains_its_existing_semantics() -> Result<()> {
    for deleted in [true, false] {
        let f = fixture()?;
        let mut remote = MemoryEngine::open(&f.keys, &f.head)?;
        if !deleted {
            remote.importance = "important".into();
        }
        remote.updated_at = "2026-10-27T09:20:00.000Z".into();
        let mut head = MemoryEngine::seal(
            &f.keys,
            &crate::memory::search::HashingEmbedder::default(),
            &remote,
            "synthetic-account",
        )?;
        head.deleted = deleted;
        f.store
            .apply_page(&f.keys, &page(4, head, "applied", None), false)?;
        f.store.materialize_received(&f.keys)?;
        let row = f
            .store
            .all(true)?
            .into_iter()
            .find(|m| m.id == ID)
            .context("remote result missing")?;
        assert_eq!(row.deleted, deleted);
        if !deleted {
            assert_eq!(MemoryEngine::open(&f.keys, &row)?.importance, "important");
        }
        assert_eq!(
            f.store.sync_counts()?.1,
            1,
            "distinct retained conflict must not be auto-resolved"
        );
    }
    Ok(())
}

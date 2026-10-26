// 合成密文与临时数据库，不读取真实账号、记忆或 Runtime。
fn unreadable_head(store: &LocalStore, keys: &SessionKeys) -> Result<()> {
    let mut bad = sealed(keys, "not a real record", "2026-09-19T00:00:00.004Z")?;
    let (nonce, ciphertext) = keys.encrypt_content(r#"{"content":123}"#)?;
    bad.nonce = nonce;
    bad.ciphertext = ciphertext;
    store.apply_page(
        keys,
        &Page {
            epoch: "epoch".into(),
            until: 4,
            cursor: 4,
            has_more: false,
            total: 1,
            alive: 1,
            changes: vec![Change {
                rev: 4,
                status: "applied".into(),
                op_id: None,
                blob: bad,
            }],
        },
        false,
    )?;
    Ok(())
}

fn base_rev(store: &LocalStore) -> Result<i64> {
    Ok(store
        .connection
        .query_row("SELECT rev FROM sync_base WHERE id='entry'", [], |r| {
            r.get(0)
        })?)
}

#[test]
fn sync_unreadable_head_recovery_is_atomic_and_reuses_pending_operation() -> Result<()> {
    let (_dir, store, keys) = fixture()?;
    unreadable_head(&store, &keys)?;
    assert_eq!(base_rev(&store)?, 3);
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    let first = store.outgoing()?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].base_rev, Some(4));
    assert!(first[0].parent_op_id.is_none());
    assert_eq!(first[0].blob.id, "entry");
    assert_eq!(
        MemoryEngine::open(&keys, &first[0].blob)?.content,
        "unique old edit"
    );
    assert_eq!(
        base_rev(&store)?,
        3,
        "unreadable head must not be marked locally applied"
    );
    assert!(store.outgoing_resolutions()?.is_empty());
    assert_eq!(store.processed_conflict_action("epoch", 2)?, None);
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    assert_eq!(
        serde_json::to_value(store.outgoing()?)?,
        serde_json::to_value(&first)?
    );
    assert!(store.connection.query_row::<bool, _, _>(
        "SELECT EXISTS(SELECT 1 FROM sync_inbox WHERE rev=4 AND decode_error<>'')",
        [],
        |r| r.get(0)
    )?);
    Ok(())
}

#[test]
fn sync_unreadable_head_recovery_waits_for_applied_content_and_server_resolution() -> Result<()> {
    let (_dir, store, keys) = fixture()?;
    unreadable_head(&store, &keys)?;
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    let ops = store.outgoing()?;
    store.acknowledge(
        &ops,
        &[Receipt {
            op_id: ops[0].op_id.clone(),
            status: "applied".into(),
            stored_rev: 5,
            head_rev: 5,
        }],
        false,
    )?;
    assert_eq!(store.processed_conflict_action("epoch", 2)?, None);
    store.apply_page(
        &keys,
        &Page {
            epoch: "epoch".into(),
            until: 5,
            cursor: 5,
            has_more: false,
            total: 1,
            alive: 1,
            changes: vec![Change {
                rev: 5,
                status: "applied".into(),
                op_id: Some(ops[0].op_id.clone()),
                blob: ops[0].blob.clone(),
            }],
        },
        false,
    )?;
    assert_eq!(base_rev(&store)?, 5);
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    assert!(store.outgoing()?.is_empty());
    let decisions = store.outgoing_resolutions()?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0].restore_op_id.as_deref(),
        Some(ops[0].op_id.as_str())
    );
    let reply = ResolveReply {
        results: vec![ResolutionResult {
            conflict_rev: 2,
            outcome: "processed".into(),
            resolution: Some(Resolution {
                seq: 1,
                conflict_rev: 2,
                id: "entry".into(),
                action: "take_incoming".into(),
                head_rev: 5,
                restore_op_id: Some(ops[0].op_id.clone()),
                processed_at: "now".into(),
            }),
        }],
    };
    store.acknowledge_resolutions("epoch", &decisions, &reply)?;
    store.acknowledge_resolutions("epoch", &decisions, &reply)?;
    store.maintain_sync_storage()?;
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    assert!(store.outgoing()?.is_empty());
    assert_eq!(
        store.processed_conflict_action("epoch", 2)?.as_deref(),
        Some("take_incoming")
    );
    Ok(())
}

#[test]
fn sync_unreadable_head_recovery_rejects_changed_head_epoch_and_merge() -> Result<()> {
    let (_dir, store, keys) = fixture()?;
    unreadable_head(&store, &keys)?;
    for (epoch, head, action, content) in [
        ("epoch", 3, "take_incoming", None),
        ("old-epoch", 4, "take_incoming", None),
        (
            "epoch",
            4,
            "merge",
            Some("do not silently merge an unreadable head"),
        ),
    ] {
        assert!(store
            .queue_conflict_resolution(&keys, epoch, 2, head, action, content)
            .is_err());
    }
    assert!(store.outgoing()?.is_empty());
    assert_eq!(base_rev(&store)?, 3);
    Ok(())
}

#[test]
fn sync_unreadable_head_recovery_preserves_pending_and_dirty_local_edits() -> Result<()> {
    use crate::transport::MemoryTransport;
    for dirty_only in [false, true] {
        let (_dir, store, keys) = fixture()?;
        unreadable_head(&store, &keys)?;
        if dirty_only {
            // 覆盖旧库仅 dirty 标记、尚无 outbox 的情况。
            store
                .connection
                .execute("UPDATE memories SET dirty=1 WHERE id='entry'", [])?;
        } else {
            store.put_inner(
                &sealed(&keys, "my unsubmitted edit", "2026-09-19T00:00:00.005Z")?,
                true,
            )?;
        }
        let before = serde_json::to_value(store.outgoing()?)?;
        let local = serde_json::to_value(store.all(true)?)?;
        assert!(store
            .queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)
            .unwrap_err()
            .to_string()
            .contains("pending local changes"));
        assert_eq!(serde_json::to_value(store.outgoing()?)?, before);
        assert_eq!(serde_json::to_value(store.all(true)?)?, local);
        assert_eq!(base_rev(&store)?, 3);
    }
    Ok(())
}

#[test]
fn sync_readable_unapplied_head_still_requires_sync() -> Result<()> {
    let (_dir, store, keys) = fixture()?;
    store.connection.execute("UPDATE sync_base SET rev=1", [])?;
    assert!(store
        .queue_conflict_resolution(&keys, "epoch", 2, 3, "take_incoming", None)
        .unwrap_err()
        .to_string()
        .contains("finish sync first"));
    assert!(store.outgoing()?.is_empty());
    Ok(())
}

#[test]
fn sync_unreadable_candidate_rolls_back_without_any_operation() -> Result<()> {
    let (_dir, store, keys) = fixture()?;
    unreadable_head(&store, &keys)?;
    store.connection.execute("UPDATE sync_inbox SET wire=(SELECT wire FROM sync_remote_heads WHERE id='entry') WHERE rev=2", [])?;
    assert!(store
        .queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)
        .is_err());
    assert!(store.outgoing()?.is_empty());
    assert_eq!(store.conflict_metrics()?.3, 0);
    assert_eq!(base_rev(&store)?, 3);
    Ok(())
}

#[test]
fn sync_recovery_server_race_is_not_resolved_and_retry_does_not_duplicate() -> Result<()> {
    let (_dir, store, keys) = fixture()?;
    unreadable_head(&store, &keys)?;
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    let ops = store.outgoing()?;
    // 模拟服务端 CAS 拒绝：服务端 head 已由 4 变为 5。
    assert_eq!(ops[0].base_rev, Some(4));
    store.acknowledge(
        &ops,
        &[Receipt {
            op_id: ops[0].op_id.clone(),
            status: "conflict_saved".into(),
            stored_rev: 6,
            head_rev: 5,
        }],
        false,
    )?;
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    assert!(store.outgoing()?.is_empty());
    let decisions = store.outgoing_resolutions()?;
    store.acknowledge_resolutions(
        "epoch",
        &decisions,
        &ResolveReply {
            results: vec![ResolutionResult {
                conflict_rev: 2,
                outcome: "stale".into(),
                resolution: None,
            }],
        },
    )?;
    assert_eq!(store.processed_conflict_action("epoch", 2)?, None);
    assert_eq!(base_rev(&store)?, 3);
    assert!(store
        .queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)
        .is_err());
    assert!(
        store.outgoing()?.is_empty(),
        "repeating a rejected recovery must not accumulate conflicts"
    );
    Ok(())
}

#[test]
fn sync_reset_invalidates_recovery_retry_without_recreating_operations() -> Result<()> {
    for acknowledged in [None, Some("applied"), Some("conflict_saved")] {
        let (_dir, store, keys) = fixture()?;
        unreadable_head(&store, &keys)?;
        store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
        let operations = store.outgoing()?;
        if let Some(status) = acknowledged {
            store.acknowledge(
                &operations,
                &[Receipt {
                    op_id: operations[0].op_id.clone(),
                    status: status.into(),
                    stored_rev: 5,
                    head_rev: 5,
                }],
                false,
            )?;
        }
        store.reset_sync_snapshot()?;
        store.begin_sync_epoch("epoch")?;
        store.meta_set("sync_v2_resolution_support", "1")?;
        let before = serde_json::to_value(store.outgoing()?)?;
        assert!(store
            .queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)
            .unwrap_err()
            .to_string()
            .contains("invalidated"));
        assert_eq!(serde_json::to_value(store.outgoing()?)?, before);
        assert_eq!(store.processed_conflict_action("epoch", 2)?, None);
        assert!(
            store.outgoing_resolutions()?.is_empty(),
            "reset must not resend an old recovery decision"
        );
        if acknowledged.is_some() {
            let wire: String = store.connection.query_row(
                "SELECT wire FROM sync_inbox WHERE epoch='epoch' AND rev=4",
                [],
                |r| r.get(0),
            )?;
            let bad: StoredMemory = serde_json::from_str(&wire)?;
            store.apply_page(
                &keys,
                &Page {
                    epoch: "epoch".into(),
                    until: 6,
                    cursor: 6,
                    has_more: false,
                    total: 1,
                    alive: 1,
                    changes: vec![Change {
                        rev: 6,
                        status: "applied".into(),
                        op_id: None,
                        blob: bad,
                    }],
                },
                false,
            )?;
            store.queue_conflict_resolution(&keys, "epoch", 2, 6, "take_incoming", None)?;
            let fresh = store.outgoing()?;
            assert_eq!(fresh.len(), 1);
            assert_eq!(fresh[0].base_rev, Some(6));
            assert_ne!(fresh[0].op_id, operations[0].op_id);
            let prior: String = store.connection.query_row(
                "SELECT state FROM sync_outbox WHERE op_id=?1",
                [&operations[0].op_id],
                |r| r.get(0),
            )?;
            assert_eq!(
                Some(prior.as_str()),
                acknowledged,
                "reset preserves acknowledged operation history"
            );
        }
    }
    Ok(())
}

#[test]
fn sync_unreadable_head_can_recover_on_a_fresh_client_without_an_applied_base() -> Result<()> {
    let (_dir, store, keys) = fixture()?;
    unreadable_head(&store, &keys)?;
    store.connection.execute("DELETE FROM memories", [])?;
    store.connection.execute("DELETE FROM sync_base", [])?;
    store.queue_conflict_resolution(&keys, "epoch", 2, 4, "take_incoming", None)?;
    let ops = store.outgoing()?;
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].base_rev, Some(4));
    assert_eq!(
        MemoryEngine::open(&keys, &ops[0].blob)?.content,
        "unique old edit"
    );
    let count: i64 = store
        .connection
        .query_row("SELECT count(*) FROM sync_base", [], |r| r.get(0))?;
    assert_eq!(count, 0);
    Ok(())
}

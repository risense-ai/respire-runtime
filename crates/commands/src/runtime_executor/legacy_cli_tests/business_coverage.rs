use super::{capture_run, with_isolated_profile, with_isolated_session};
use crate::sync_flow::run_sync_attempts;
use anyhow::Context;
use respire_app::MemoryTransport;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn readonly_taxonomy_dispatch_reaches_the_real_read_only_command() -> anyhow::Result<()> {
    with_isolated_profile(false, |root| {
        std::fs::write(root.join("agent.json"), br#"{"readonly":true}"#)?;
        assert!(respire_app::service::readonly_mode());
        let result = capture_run(vec!["taxonomy".into(), "--list".into()]);
        assert_eq!(result.exit, 0, "{:?}", result.envelope);
        assert!(matches!(result.envelope.status, crate::output::Status::Ok));
        assert!(result.envelope.summary["count"]
            .as_u64()
            .is_some_and(|n| n > 0));
        let write = capture_run(vec![
            "taxonomy".into(),
            "--ensure".into(),
            "synthetic".into(),
        ]);
        assert_ne!(write.exit, 0);
        assert!(!root.join("rsrs.db").exists());
        assert!(!root.join("onememory.db").exists());
        Ok(())
    })
}

#[test]
fn residual_input_errors_use_user_envelopes() -> anyhow::Result<()> {
    with_isolated_session(|root| {
        let missing = root.join("missing.json").to_string_lossy().into_owned();
        let missing_output = root
            .join("absent")
            .join("export.json")
            .to_string_lossy()
            .into_owned();
        for command in [
            vec!["restore", "deadbeef"],
            vec!["grant", "create", "--root", "deadbeef", "--label", "probe"],
            vec![
                "grant",
                "create",
                "--root",
                "00000000-0000-0000-0000-000000000000",
                "--label",
                "probe",
            ],
            vec!["import", &missing],
            vec!["bench", "run", &missing],
            vec!["share-import", &missing],
            vec!["export", &missing_output],
            vec!["backup", &missing_output],
        ] {
            let mut args = vec!["--json".to_owned()];
            args.extend(command.iter().map(|arg| (*arg).to_owned()));
            let result = capture_run(args);
            assert_eq!(result.exit, 2, "{command:?}: {:?}", result.envelope);
            assert_eq!(
                result.envelope.summary["reason"], "invalid_input",
                "{command:?}"
            );
            assert_eq!(result.envelope.details["error_type"], "user", "{command:?}");
            if matches!(command[0], "import" | "bench" | "share-import") {
                assert!(
                    result
                        .envelope
                        .errors
                        .iter()
                        .any(|error| error.contains("failed to read")),
                    "{command:?}: {:?}",
                    result.envelope.errors
                );
            }
        }
        let invalid = root.join("invalid-utf8.json");
        std::fs::write(&invalid, [0xff])?;
        let error = respire_app::input_error::read_file(&invalid, "fixture")
            .err()
            .ok_or_else(|| anyhow::anyhow!("invalid UTF-8 was accepted"))?;
        assert_eq!(crate::output_emit::command_failure(&error).1, 1);
        let existing = root.join("existing-backup.db");
        std::fs::write(&existing, b"preserve existing backup")?;
        let error = respire_app::service::backup_db(&existing)
            .err()
            .ok_or_else(|| anyhow::anyhow!("existing backup was overwritten"))?;
        assert_eq!(crate::output_emit::command_failure(&error).1, 1);
        assert_eq!(std::fs::read(&existing)?, b"preserve existing backup");
        assert!(!root.join("absent").exists());
        Ok(())
    })
}

#[test]
fn bench_runs_on_pending_resident_snapshot_without_writing_index() -> anyhow::Result<()> {
    with_isolated_session(|root| {
        let keys = crate::engine::build_session()?;
        let store = crate::engine::build_local()?;
        let entry: respire_app::MemoryEntry = serde_json::from_value(serde_json::json!({
            "id":"pending-bench","kind":"Context","tags":[],"title":"benchmark pending needle",
            "content":"benchmark pending needle","user":"test","computer":"test","project":"",
            "created_at":"2026-10-10T00:00:00Z","updated_at":"2026-10-10T00:00:00Z",
            "emotion":0,"parent_id":"","importance":"important"
        }))?;
        let stored = {
            let _defer = respire_app::core_sdk::defer_indexing();
            respire_app::MemoryEngine::seal(
                &keys,
                &respire_app::core_sdk::search::HashingEmbedder::new(1024),
                &entry,
                "test",
            )?
        };
        store.put_checked(&stored, None)?;
        let eval = root.join("eval.jsonl");
        let output = root.join("bench.json");
        std::fs::write(
            &eval,
            r#"{"query":"benchmark pending needle","expect":["pending-bench"]}"#,
        )?;
        let captured = capture_run(vec![
            "--json".into(),
            "bench".into(),
            "run".into(),
            eval.to_string_lossy().into_owned(),
            "--save".into(),
            output.to_string_lossy().into_owned(),
        ]);
        assert_eq!(captured.exit, 0, "{:?}", captured.envelope);
        let report: crate::bench::BenchReport = serde_json::from_slice(&std::fs::read(output)?)?;
        assert_eq!(
            report.params.get("index_pending").map(String::as_str),
            Some("1")
        );
        assert_eq!(report.metrics.hit1, 1.0);
        assert_eq!(report.n_entries, 1);
        let current = store.all(false)?;
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].ciphertext, stored.ciphertext);
        assert!(current[0].local_artifact.is_empty());
        respire_app::resident::clear()?;
        Ok(())
    })
}

#[test]
fn memory_revision_capture_preserves_identity_across_status_reads() -> anyhow::Result<()> {
    with_isolated_profile(false, |root| {
        let _store = respire_app::service::open_store()?;
        crate::rpc_worker::set_worker_active(true);
        let before = capture_run(vec!["memory-revision".into(), "--json".into()]);
        assert_eq!(before.exit, 0);
        assert_eq!(before.envelope.command, "memory-revision");
        assert_eq!(
            before.envelope.summary["profile"],
            root.to_string_lossy().as_ref()
        );
        let status = capture_run(vec!["status".into(), "--json".into()]);
        assert_eq!(status.exit, 0);
        assert_eq!(
            status.envelope.summary["data_dir"],
            before.envelope.summary["profile"]
        );
        let after = capture_run(vec!["memory-revision".into(), "--json".into()]);
        assert_eq!(after.exit, 0);
        assert_eq!(after.envelope.summary, before.envelope.summary);
        assert!(!root.join("session.json").exists());
        assert!(!root.join("model").exists());
        Ok(())
    })
}

#[test]
fn doctor_json_keeps_command_envelope() -> anyhow::Result<()> {
    with_isolated_session(|_| {
        respire_app::service::set_server_addr("https://example.invalid")?;
        for args in [
            vec!["--json".into(), "doctor".into()],
            vec!["--json".into(), "doctor".into(), "--remote".into()],
        ] {
            let captured = capture_run(args);
            assert_eq!(captured.envelope.command, "doctor");
            assert!(captured.envelope.summary["total"]
                .as_u64()
                .is_some_and(|count| count > 0));
            assert!(!captured.envelope.items.is_empty());
            assert_eq!(captured.envelope.summary["scope"], "runtime");
            assert_eq!(
                captured.envelope.summary["runtime_version"],
                crate::app_version::embedded()
            );
            let version = captured
                .envelope
                .items
                .iter()
                .find(|item| item.name == "Runtime version")
                .context("doctor runtime version missing")?;
            assert_eq!(version.value, crate::app_version::embedded());
            assert!(matches!(version.status, crate::output::Status::Ok));
            assert_eq!(
                captured.exit,
                crate::output_state::status_exit_code(captured.envelope.status)
            );
        }
        let operation = crate::model_progress::Operation::begin("download")?;
        let captured = capture_run(vec!["--json".into(), "doctor".into()]);
        let embedder = captured
            .envelope
            .items
            .iter()
            .find(|item| item.name == "embedder")
            .context("doctor embedder check missing")?;
        assert!(matches!(embedder.status, crate::output::Status::Warn));
        assert_eq!(crate::model_progress::status()?["phase"], "download");
        let rejected = capture_run(vec!["--json".into(), "doctor".into(), "--fix".into()]);
        assert_ne!(rejected.exit, 0, "Runtime must not accept host repair");
        assert_eq!(crate::model_progress::status()?["phase"], "download");
        drop(operation);
        Ok(())
    })
}

#[test]
fn worker_schedules_autosync_without_waiting_on_the_remote() -> anyhow::Result<()> {
    with_isolated_session(|root| {
        std::env::remove_var("RSRS_NO_AUTOSYNC");
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(sock) = conn else { break };
                std::thread::sleep(std::time::Duration::from_secs(60));
                drop(sock);
            }
        });
        std::fs::write(
            root.join("session.json"),
            format!(r#"{{"addr":"http://127.0.0.1:{port}","token":"hang"}}"#),
        )?;
        // This scheduling fixture owns its temporary store, not the in-process runtime's boot profile.
        let store = respire_app::transport::local::LocalStore::open(&root.join("onememory.db"))?;
        let keys = respire_app::SessionKeys::from_urk([9u8; 32])?;
        crate::rpc_worker::set_worker_active(true);
        let started = std::time::Instant::now();
        crate::engine::schedule_autosync(&keys, &store);
        let elapsed = started.elapsed();
        crate::rpc_worker::set_worker_active(false);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "autosync blocked the worker for {elapsed:?}"
        );
        Ok(())
    })
}

#[test]
fn retries_transport_timeout_then_succeeds() -> anyhow::Result<()> {
    let hits = AtomicUsize::new(0);
    let value = run_sync_attempts(|| {
        let n = hits.fetch_add(1, Ordering::SeqCst);
        if n < 2 {
            Err(anyhow::anyhow!("connection timed out"))
        } else {
            Ok(7)
        }
    })?;
    assert_eq!(value, 7);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    Ok(())
}

#[test]
fn protocol_error_does_not_retry() {
    let hits = AtomicUsize::new(0);
    let err = run_sync_attempts(|| {
        hits.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>(anyhow::anyhow!(
            "server sync epoch changed; local edits kept"
        ))
    })
    .unwrap_err();
    assert!(err.to_string().contains("epoch"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[test]
fn production_executor_defers_writes_and_restores_indexing_scope() -> anyhow::Result<()> {
    with_isolated_session(|root| {
        use respire_app::core_sdk::indexing_deferred;
        assert!(!indexing_deferred());
        // Call the production entry directly, not the legacy fixture wrapper.
        let written = super::super::capture_run(vec![
            "--json".into(), "remember".into(), "deferred source fixture".into(),
            "--title".into(), "deferred source fixture".into(),
            "--importance".into(), "important".into(), "--force".into(),
        ]);
        assert_eq!(written.exit, 0, "{:?}", written.envelope);
        assert_eq!(written.envelope.summary["index_state"], "pending");
        assert!(!indexing_deferred());
        let id = written.envelope.summary["id"]
            .as_str().context("remember response is missing its ID")?;
        let updated = super::super::capture_run(vec![
            "--json".into(), "update".into(), id.into(),
            "--title".into(), "updated deferred fixture".into(),
            "--content".into(), "updated deferred source".into(),
        ]);
        assert_eq!(updated.exit, 0, "{:?}", updated.envelope);
        assert_eq!(updated.envelope.summary["index_state"], "pending");
        assert!(!indexing_deferred());
        let shown = super::super::capture_run(vec![
            "--json".into(), "show".into(), id.into(),
        ]);
        assert_eq!(shown.exit, 0, "{:?}", shown.envelope);
        assert_eq!(shown.envelope.details["entry"]["content"], "updated deferred source");
        assert!(!indexing_deferred());
        let failed = super::super::capture_run(vec![
            "--json".into(), "import".into(),
            root.join("missing-import.json").to_string_lossy().into_owned(),
        ]);
        assert_ne!(failed.exit, 0);
        assert!(!indexing_deferred(), "failed write leaked its indexing scope");
        Ok(())
    })
}

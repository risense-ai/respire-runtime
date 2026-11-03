use super::with_isolated_session;
use crate::{capture_run, output::ResultEnvelope};
use anyhow::{Context, Result};
use serde_json::json;

fn command(args: &[&str], exit: i32) -> Result<ResultEnvelope> {
    let result = capture_run(
        std::iter::once("--json".to_owned())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect(),
    );
    anyhow::ensure!(
        result.exit == exit,
        "{args:?}: expected {exit}, got {}: {:?}",
        result.exit,
        result.envelope
    );
    Ok(result.envelope)
}

struct DirectGuard {
    direct: bool,
    defer: bool,
    user: Option<std::ffi::OsString>,
}
impl DirectGuard {
    fn enter() -> Self {
        let user = std::env::var_os("RSRS_USER");
        std::env::set_var("RSRS_USER", "test");
        Self {
            direct: crate::DIRECT_MODE.swap(true, std::sync::atomic::Ordering::Relaxed),
            defer: crate::DEFER_PROFILE_OUTPUT.replace(true),
            user,
        }
    }
}
impl Drop for DirectGuard {
    fn drop(&mut self) {
        crate::DIRECT_MODE.store(self.direct, std::sync::atomic::Ordering::Relaxed);
        crate::DEFER_PROFILE_OUTPUT.set(self.defer);
        match &self.user {
            Some(value) => std::env::set_var("RSRS_USER", value),
            None => std::env::remove_var("RSRS_USER"),
        }
    }
}

#[test]
fn review_due_prepare_and_date_history_use_real_store() -> Result<()> {
    with_isolated_session(|root| {
        use respire::MemoryTransport;
        let _direct = DirectGuard::enter();
        let store = crate::build_local()?;
        crate::rpc::set_worker_active(false);
        command(&["metadata", "enable"], 0)?;
        crate::rpc::set_worker_active(true);
        let _ownership =
            respire::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        let created = command(
            &[
                "remember",
                "task-only review fact",
                "--title",
                "review fixture",
                "--importance",
                "important",
                "--force",
                "--summary",
                "review summary",
                "--review-at",
                "2020-01-01T00:00:00.000Z",
            ],
            0,
        )?;
        let id = created.summary["id"].as_str().context("fixture id")?;
        let before = store.memory_revision()?;
        let due = command(&["review", "--due"], 0)?;
        assert!(
            due.details["due"]
                .as_array()
                .context("due array")?
                .iter()
                .any(|item| item["id"] == id),
            "{due:?}"
        );
        assert_eq!(
            due.summary["due_count"],
            json!(due.details["due"].as_array().map(Vec::len))
        );
        assert_eq!(due.details["memory_revision"], before);
        let draft = command(&["review", id, "--prepare"], 2)?;
        assert!(matches!(draft.status, crate::output::Status::Pending));
        assert_eq!(draft.details["entry"]["content"], "task-only review fact");
        assert_eq!(draft.details["entry"]["summary"], "review summary");
        let row = store
            .all(false)?
            .into_iter()
            .find(|row| row.id == id)
            .context("prepared row")?;
        let entry = respire::MemoryEngine::open(&crate::build_session()?, &row)?;
        assert_eq!(draft.details["entry"], serde_json::to_value(entry)?);
        assert_eq!(
            draft.details["confirm_input"]["expected_memory_revision"],
            before
        );
        assert_eq!(
            draft.details["binding"]["record_revision"],
            created.summary["record_revision"]
        );
        assert_eq!(
            draft.details["authority"]["code"],
            "verification_authority_unavailable"
        );
        assert_eq!(store.memory_revision()?, before);
        assert!(store.review_history(id, 200)?.is_empty());
        let binding = &draft.details["binding"];
        let input = &draft.details["confirm_input"];
        let recomputed: serde_json::Value = respire::core_sdk::execute(
            "memory_metadata_validate",
            json!({
                "entry":draft.details["entry"],
                "review":{"claim":input["claim"],"scope":input["scope"],
                    "evidence":input["evidence"],"method":input["method"]},
                "intent":{"owner":binding["owner"],"local_library_id":binding["local_library_id"],
                    "expected_memory_revision":binding["expected_memory_revision"],"next_review_at":input["next_review_at"]}
            }),
        )?;
        for field in ["record_revision", "claim_digest", "intent_digest"] {
            assert_eq!(binding[field], recomputed[field], "{field}");
        }
        let explicit = input.to_string();
        let checked = command(&["review", id, "--check", "--input", &explicit], 2)?;
        assert_eq!(checked.details["binding"], *binding);
        assert_eq!(checked.details["entry"], draft.details["entry"]);
        let denied = command(
            &[
                "review",
                id,
                "--confirm",
                "--input",
                &explicit,
                "--approval",
                "00000000-0000-4000-8000-000000000001",
            ],
            1,
        )?;
        assert_eq!(denied.details["code"], "verification_authority_unavailable");
        assert_eq!(denied.summary["saved"], false);
        assert_eq!(store.memory_revision()?, before);
        assert!(store.review_history(id, 200)?.is_empty());
        let scoped = command(
            &[
                "review",
                "--due",
                "--project",
                "task-project",
                "--device",
                "task-device",
                "--target-version",
                "task-version",
            ],
            0,
        )?;
        assert!(scoped.details["due"].is_array());
        let changed = command(
            &[
                "review",
                id,
                "--review-at",
                "2099-01-01T00:00:00.000Z",
                "--expected-memory-revision",
                &before,
            ],
            0,
        )?;
        assert_eq!(changed.summary["saved"], true);
        let history = command(&["review", id, "--history", "--limit", "1"], 0)?;
        assert_eq!(history.details["local_only"], true);
        assert_eq!(history.details["history"].as_array().map(Vec::len), Some(1));
        assert_eq!(history.details["history"][0]["action"], "reschedule");
        let after = store.memory_revision()?;
        let saved_history = serde_json::to_value(store.review_history(id, 200)?)?;
        for (flag, value, revision, code) in [
            (
                "--review-at",
                "2020-01-01T00:00:00.000Z",
                after.as_str(),
                "invalid_metadata",
            ),
            (
                "--review-at",
                "2099-02-01T00:00:00.000Z",
                before.as_str(),
                "review_conflict",
            ),
            ("--clear", "review_at", before.as_str(), "review_conflict"),
        ] {
            let failed = command(
                &[
                    "review",
                    id,
                    flag,
                    value,
                    "--expected-memory-revision",
                    revision,
                ],
                1,
            )?;
            assert_eq!(failed.details["code"], code);
            assert_eq!(store.memory_revision()?, after);
            assert_eq!(
                serde_json::to_value(store.review_history(id, 200)?)?,
                saved_history
            );
            let row = store
                .all(false)?
                .into_iter()
                .find(|row| row.id == id)
                .context("review row")?;
            assert_eq!(
                respire::MemoryEngine::open(&crate::build_session()?, &row)?
                    .metadata
                    .review_at
                    .as_deref(),
                Some("2099-01-01T00:00:00.000Z")
            );
        }
        let stale_draft = command(&["review", id, "--draft", "--input", &explicit], 1)?;
        assert_eq!(stale_draft.details["code"], "review_conflict");
        let cleared = command(
            &[
                "review",
                id,
                "--clear",
                "review_at",
                "--expected-memory-revision",
                &after,
            ],
            0,
        )?;
        assert_eq!(cleared.details["review_at"], serde_json::Value::Null);
        assert_eq!(
            cleared.details["record_revision"],
            created.summary["record_revision"]
        );
        let revision = store.memory_revision()?;
        let revoked = command(
            &[
                "review",
                id,
                "--revoke",
                "--reason",
                "fixture explicit revoke",
                "--expected-memory-revision",
                &revision,
            ],
            0,
        )?;
        assert_eq!(revoked.details["verification"], serde_json::Value::Null);
        let history = command(&["review", id, "--history", "--limit", "200"], 0)?;
        assert_eq!(history.details["history"].as_array().map(Vec::len), Some(3));
        assert_eq!(history.details["history"][0]["action"], "revoke");
        assert_eq!(
            history.details["history"][0]["reason"],
            "fixture explicit revoke"
        );
        assert_eq!(history.details["history"][1]["action"], "clear_review_at");
        assert_eq!(store.all(false)?.len(), 1);
        assert!(!root.join("absent-model").exists());
        assert!(!root.join("runtime/endpoint.json").exists());
        Ok(())
    })
}

#[test]
fn review_invalid_arguments_and_inputs_never_write() -> Result<()> {
    with_isolated_session(|root| {
        let _direct = DirectGuard::enter();
        let store = crate::build_local()?;
        let _ownership =
            respire::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        let before = store.memory_revision()?;
        let id = "00000000-0000-4000-8000-000000000001";
        let parser_errors: &[&[&str]] = &[
            &["review"],
            &["review", id, "--due", "--draft"],
            &["review", id, "--history", "--limit", "0"],
            &["review", id, "--history", "--limit", "201"],
            &["review", id, "--clear", "summary"],
            &[
                "review",
                id,
                "--clear",
                "review_at",
                "--review-at",
                "2099-01-01T00:00:00.000Z",
            ],
        ];
        for args in parser_errors {
            let failed = command(args, 2)?;
            assert!(matches!(failed.status, crate::output::Status::Fail));
            assert!(!failed.errors.is_empty());
        }
        let invalid: &[&[&str]] = &[
            &["review", id, "--due"],
            &["review", "--draft"],
            &["review", "short-id", "--history"],
            &["review", "--due", "--project", "*"],
            &["review", "--due", "--device", "*"],
            &["review", "--due", "--target-version", "*"],
            &["review", id, "--review-at", "tomorrow"],
            &["review", id, "--history", "--input", "{}"],
            &["review", id, "--history", "--approval", id],
            &["review", id, "--history", "--reason", "reason"],
            &[
                "review",
                id,
                "--history",
                "--expected-memory-revision",
                "revision",
            ],
            &["review", id, "--draft", "--project", "project"],
            &["review", id, "--confirm"],
            &["review", id, "--confirm", "--input", "{}"],
            &[
                "review",
                id,
                "--confirm",
                "--input",
                "{}",
                "--approval",
                "short-id",
            ],
            &["review", id, "--revoke"],
            &["review", id, "--revoke", "--reason", "   "],
            &["review", id, "--revoke", "--reason", "reason"],
            &["review", id, "--clear", "review_at"],
            &["review", id, "--review-at", "2099-01-01T00:00:00.000Z"],
            &["review", id, "--draft", "--input", "{"],
            &["review", id, "--draft", "--input", "{}"],
            &[
                "review",
                id,
                "--draft",
                "--input",
                r#"{"claim":"a","scope":{},"evidence":[],"method":"","next_review_at":null}"#,
            ],
        ];
        for args in invalid {
            let failed = command(args, 1)?;
            assert_eq!(
                failed.details["code"], "invalid_metadata",
                "{args:?}: {failed:?}"
            );
            assert_eq!(failed.summary["saved"], false);
            assert!(!failed.errors.is_empty());
            assert_eq!(store.memory_revision()?, before);
        }
        let missing = command(&["review", id, "--history"], 1)?;
        assert_eq!(missing.details["code"], "evidence_unavailable");
        assert!(store.review_history(id, 200)?.is_empty());
        let gate_off = command(
            &[
                "review",
                id,
                "--review-at",
                "2099-01-01T00:00:00.000Z",
                "--expected-memory-revision",
                &before,
            ],
            1,
        )?;
        assert_eq!(gate_off.details["code"], "feature_disabled");
        let due = command(&["review", "--due"], 0)?;
        assert_eq!(due.summary["due_count"], 0);
        assert_eq!(store.memory_revision()?, before);
        assert!(!root.join("runtime/endpoint.json").exists());
        Ok(())
    })
}

#[test]
fn review_due_decode_failure_is_not_an_empty_success() -> Result<()> {
    with_isolated_session(|root| {
        use respire::MemoryTransport;
        let _direct = DirectGuard::enter();
        let store = crate::build_local()?;
        crate::rpc::set_worker_active(false);
        command(&["metadata", "enable"], 0)?;
        crate::rpc::set_worker_active(true);
        let _ownership =
            respire::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        let created = command(
            &[
                "remember",
                "decode failure fixture",
                "--summary",
                "candidate",
                "--importance",
                "important",
                "--force",
            ],
            0,
        )?;
        let id = created.summary["id"]
            .as_str()
            .context("decode fixture id")?;
        let mut row = store
            .all(false)?
            .into_iter()
            .find(|row| row.id == id)
            .context("decode fixture row")?;
        row.updated_at = "2099-01-01T00:00:00.000Z".to_owned();
        row.ciphertext = "invalid-fixture-ciphertext".to_owned();
        assert!(store.put(&row)?);
        let before = store.memory_revision()?;
        let failed = command(&["review", "--due"], 1)?;
        assert_eq!(failed.details["code"], "review_failed");
        assert!(matches!(failed.status, crate::output::Status::Fail));
        assert_eq!(failed.summary["saved"], false);
        assert!(failed.summary.get("due_count").is_none());
        assert!(failed
            .errors
            .iter()
            .any(|error| error.contains("decode review snapshot")));
        assert_eq!(store.memory_revision()?, before);
        assert!(store.review_history(id, 200)?.is_empty());
        Ok(())
    })
}

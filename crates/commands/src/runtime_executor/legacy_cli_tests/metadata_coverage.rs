use super::capture_run;
use super::with_isolated_session;
use crate::output::ResultEnvelope;
use anyhow::{Context, Result};
use respire_app::MemoryTransport;
use serde_json::json;

fn command(args: &[&str], exit: i32) -> Result<ResultEnvelope> {
    let mut input = vec!["--json".to_owned()];
    input.extend(args.iter().map(|arg| (*arg).to_owned()));
    let result = capture_run(input);
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
}
impl DirectGuard {
    fn enter() -> Self {
        Self {
            direct: crate::engine::DIRECT_MODE.swap(true, std::sync::atomic::Ordering::Relaxed),
            defer: crate::output_state::DEFER_PROFILE_OUTPUT.replace(true),
        }
    }
}
impl Drop for DirectGuard {
    fn drop(&mut self) {
        crate::engine::DIRECT_MODE.store(self.direct, std::sync::atomic::Ordering::Relaxed);
        crate::output_state::DEFER_PROFILE_OUTPUT.set(self.defer);
    }
}

#[test]
fn metadata_lifecycle_preserves_revisions_and_merge_invariants() -> Result<()> {
    with_isolated_session(|root| {
        let _direct = DirectGuard::enter();
        let store = crate::engine::build_local()?;
        let keys = crate::engine::build_session()?;
        let status = command(&["metadata", "status"], 0)?;
        assert_eq!(status.summary["enabled"], false);
        assert_eq!(status.summary["sdk_supported"], true);
        command(
            &[
                "remember",
                "gate-off candidate",
                "--summary",
                "clue",
                "--force",
            ],
            1,
        )?;
        assert_eq!(store.count()?, 0);
        crate::rpc_worker::set_worker_active(false);
        let enabled = command(&["metadata", "enable"], 0)?;
        assert!(enabled.details["receipt"]["backup"]["id"].is_string());
        crate::rpc_worker::set_worker_active(true);
        let ownership =
            respire_app::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        let first = command(
            &[
                "remember",
                "candidate body",
                "--title",
                "candidate",
                "--importance",
                "important",
                "--force",
                "--summary",
                "\u{5019}\u{9009}\u{6458}\u{8981}",
                "--source-refs",
                "[]",
                "--valid-until",
                "2026-12-01T00:00:00.000Z",
                "--review-at",
                "2026-11-15T00:00:00.000Z",
                "--artifact",
                r#"{"path":"a.rs","repo":"fixture","commit":"abc","purpose":"candidate"}"#,
            ],
            0,
        )?;
        let id = first.summary["id"].as_str().context("candidate id")?;
        assert_eq!(first.summary["saved"], true);
        assert_eq!(first.summary["evidence_state"], "unverified");
        assert_eq!(first.summary["evidence_evaluated"], false);
        let updated = command(&["update", id, "--content", "changed body"], 0)?;
        assert_eq!(updated.summary["metadata"], first.summary["metadata"]);
        assert_ne!(
            updated.summary["record_revision"],
            first.summary["record_revision"]
        );
        let reviewed = command(
            &["update", id, "--review-at", "2026-11-20T00:00:00.000Z"],
            0,
        )?;
        assert_eq!(
            reviewed.summary["record_revision"],
            updated.summary["record_revision"]
        );
        let cleared = command(
            &[
                "update",
                id,
                "--clear-summary",
                "--clear-source-refs",
                "--clear-artifact",
                "--clear-valid-until",
                "--clear-review-at",
            ],
            0,
        )?;
        for field in ["summary", "artifact", "valid_until", "review_at"] {
            assert!(cleared.summary["metadata"][field].is_null(), "{field}");
        }
        assert_eq!(cleared.summary["metadata"]["source_refs"], json!([]));
        let legacy = command(
            &[
                "remember",
                "legacy body",
                "--title",
                "legacy",
                "--importance",
                "important",
                "--force",
            ],
            0,
        )?;
        let legacy_id = legacy.summary["id"].as_str().context("legacy id")?;
        let row = store
            .all(false)?
            .into_iter()
            .find(|row| row.id == legacy_id)
            .context("legacy row")?;
        assert_eq!(
            respire_app::MemoryEngine::open(&keys, &row)?
                .metadata
                .memory_contract,
            0
        );
        let revision = cleared.summary["record_revision"]
            .as_str()
            .context("reference revision")?;
        let optional = json!([{"id":id,"revision":revision,"required":false}]).to_string();
        let required = json!([{"id":id,"revision":revision,"required":true}]).to_string();
        let a = command(
            &[
                "remember",
                "hypothesis A",
                "--type",
                "hypothesis",
                "--title",
                "A",
                "--importance",
                "important",
                "--force",
                "--source-refs",
                &optional,
                "--summary",
                "A",
                "--artifact",
                r#"{"path":"a"}"#,
                "--valid-until",
                "2026-12-04T00:00:00.000Z",
                "--review-at",
                "2026-11-10T00:00:00.000Z",
            ],
            0,
        )?;
        let b = command(
            &[
                "remember",
                "hypothesis B",
                "--type",
                "hypothesis",
                "--title",
                "B",
                "--importance",
                "important",
                "--force",
                "--source-refs",
                &required,
                "--summary",
                "B",
                "--artifact",
                r#"{"path":"b"}"#,
                "--valid-until",
                "2026-12-02T00:00:00.000Z",
                "--review-at",
                "2026-11-11T00:00:00.000Z",
            ],
            0,
        )?;
        let merge_ids = format!(
            "{},{}",
            a.summary["id"].as_str().context("A id")?,
            b.summary["id"].as_str().context("B id")?
        );
        let before = store.memory_revision()?;
        let conflict = command(&["remember", "merged", "--merge-ids", &merge_ids], 1)?;
        assert!(conflict
            .errors
            .iter()
            .any(|error| error.contains("artifacts differ")));
        assert_eq!(store.memory_revision()?, before);
        let different_revision =
            json!([{"id":id,"revision":format!("sha256:{}", "0".repeat(64)),"required":true}])
                .to_string();
        let c = command(
            &[
                "remember",
                "hypothesis C",
                "--type",
                "hypothesis",
                "--title",
                "C",
                "--importance",
                "important",
                "--force",
                "--source-refs",
                &different_revision,
            ],
            0,
        )?;
        let conflicting_sources = format!(
            "{},{}",
            a.summary["id"].as_str().context("A id")?,
            c.summary["id"].as_str().context("C id")?
        );
        let before = store.memory_revision()?;
        command(
            &[
                "remember",
                "conflicting source revisions",
                "--merge-ids",
                &conflicting_sources,
                "--clear-artifact",
            ],
            1,
        )?;
        assert_eq!(store.memory_revision()?, before);
        let merged = command(
            &[
                "remember",
                "merged",
                "--merge-ids",
                &merge_ids,
                "--clear-artifact",
            ],
            0,
        )?;
        assert_eq!(merged.details["kind"], "Hypothesis");
        let meta = &merged.summary["metadata"];
        for field in ["summary", "verification", "artifact"] {
            assert!(meta[field].is_null());
        }
        assert_eq!(
            meta["source_refs"],
            json!([{"id":id,"revision":revision,"required":true}])
        );
        assert_eq!(meta["valid_until"], "2026-12-02T00:00:00.000Z");
        assert_eq!(meta["review_at"], "2026-11-10T00:00:00.000Z");
        let cross = format!(
            "{legacy_id},{}",
            merged.summary["id"].as_str().context("merged id")?
        );
        let before = store.memory_revision()?;
        command(
            &[
                "remember",
                "cross-kind",
                "--merge-ids",
                &cross,
                "--clear-artifact",
            ],
            1,
        )?;
        assert_eq!(store.memory_revision()?, before);
        for kind in ["reflection", "self"] {
            let created = command(
                &["remember", "separate new kind", "--type", kind, "--force"],
                0,
            )?;
            assert_eq!(created.details["content"], "separate new kind");
            assert_eq!(created.summary["memory_contract"], 1);
        }
        let cycle = json!([{"id":merged.summary["id"],"revision":merged.summary["record_revision"],"required":true}]).to_string();
        let before = store.memory_revision()?;
        command(&["update", id, "--source-refs", &cycle], 1)?;
        assert_eq!(store.memory_revision()?, before);
        drop(ownership);
        crate::rpc_worker::set_worker_active(false);
        let disabled = command(&["metadata", "disable"], 0)?;
        assert_eq!(disabled.details["metadata_retained"], true);
        assert_eq!(disabled.details["sync_isolation_retained"], true);
        let error = respire_app::metadata_gate::ensure_sync_allowed(&store)
            .err()
            .context("isolated metadata allowed sync")?;
        assert!(error.to_string().contains("isolated"));
        crate::rpc_worker::set_worker_active(true);
        let ownership =
            respire_app::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        command(&["update", id, "--content", "forbidden after disable"], 1)?;
        command(
            &["update", legacy_id, "--content", "legacy still writable"],
            0,
        )?;
        drop(ownership);
        crate::rpc_worker::set_worker_active(false);
        let path = root.join("deployment-review.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "operator":"fixture operator","upgraded_writers":"only this fixture CLI",
                "disconnected_old_clients":"no old clients","reconciled_offline_writes":"no offline writes"
            }))?,
        )?;
        let controlled = command(
            &[
                "metadata",
                "enable",
                "--mode",
                "controlled_writers",
                "--deployment-review",
                path.to_str().context("review path")?,
            ],
            0,
        )?;
        assert_eq!(
            controlled.details["deployment_assurance"],
            "operator_attestation_only"
        );
        assert_eq!(controlled.details["old_client_access_enforced"], false);
        assert!(!root.join("runtime/endpoint.json").exists());
        Ok(())
    })
}

#[test]
fn metadata_parser_rejects_invalid_semantics_without_writes() -> Result<()> {
    with_isolated_session(|_| {
        let store = crate::engine::build_local()?;
        let before = store.memory_revision()?;
        let uuid = "00000000-0000-4000-8000-000000000001";
        let revision = format!("sha256:{}", "a".repeat(64));
        let duplicate = json!([{"id":uuid,"revision":revision,"required":true},
            {"id":uuid,"revision":revision,"required":false}])
        .to_string();
        let missing = json!([{"id":uuid,"revision":revision}]).to_string();
        let oversized = "\u{5019}".repeat(121);
        let cases: Vec<Vec<&str>> = vec![
            vec!["--summary", &oversized],
            vec!["--type", "unknown"],
            vec!["--source-refs", "not-json"],
            vec!["--source-refs", &missing],
            vec!["--source-refs", &duplicate],
            vec![
                "--source-refs",
                r#"[{"id":"x","revision":"bad","required":true}]"#,
            ],
            vec![
                "--source-refs",
                r#"[{"id":"00000000-0000-4000-8000-000000000001","revision":"sha256:bad","required":true}]"#,
            ],
            vec!["--artifact", "not-json"],
            vec!["--artifact", r#"{"path":"a","execute":true}"#],
            vec!["--valid-until", "2026-12-01T00:00:00Z"],
            vec!["--review-at", "2026-13-01T00:00:00.000Z"],
            vec!["--verification", "{}"],
        ];
        for flags in cases {
            let mut args = vec!["remember", "invalid metadata", "--force"];
            args.extend(flags);
            let failure = command(&args, 2)?;
            assert_eq!(failure.summary["reason"], "invalid_input");
            assert_eq!(failure.details["error_type"], "user");
        }
        for (set, value, clear) in [
            ("--summary", "set", "--clear-summary"),
            ("--source-refs", "[]", "--clear-source-refs"),
            (
                "--valid-until",
                "2026-12-01T00:00:00.000Z",
                "--clear-valid-until",
            ),
            (
                "--review-at",
                "2026-12-01T00:00:00.000Z",
                "--clear-review-at",
            ),
            ("--artifact", r#"{"path":"a"}"#, "--clear-artifact"),
        ] {
            for verb in ["remember", "update"] {
                command(&[verb, "conflict", set, value, clear], 2)?;
            }
        }
        assert_eq!(store.memory_revision()?, before);
        assert_eq!(store.count()?, 0);
        Ok(())
    })
}

#[test]
fn metadata_configuration_requires_host_and_complete_operator_review() -> Result<()> {
    with_isolated_session(|root| {
        let _direct = DirectGuard::enter();
        let _store = crate::engine::build_local()?;
        for action in ["enable", "disable"] {
            let refused = command(&["metadata", action], 1)?;
            assert!(refused
                .errors
                .iter()
                .any(|error| error.contains("host CLI")));
        }
        crate::rpc_worker::set_worker_active(false);
        command(&["metadata", "enable", "--mode", "controlled_writers"], 1)?;
        let path = root.join("review.json");
        let path_str = path.to_str().context("review path")?;
        std::fs::write(&path, b"invalid JSON")?;
        command(
            &[
                "metadata",
                "enable",
                "--mode",
                "controlled_writers",
                "--deployment-review",
                path_str,
            ],
            1,
        )?;
        let review = json!({"operator":" ","upgraded_writers":"fixture",
            "disconnected_old_clients":"none","reconciled_offline_writes":"none"});
        std::fs::write(&path, serde_json::to_vec(&review)?)?;
        command(
            &[
                "metadata",
                "enable",
                "--mode",
                "controlled_writers",
                "--deployment-review",
                path_str,
            ],
            1,
        )?;
        let mut unknown = review;
        unknown["operator"] = json!("fixture");
        unknown["unknown"] = json!(true);
        std::fs::write(&path, serde_json::to_vec(&unknown)?)?;
        command(
            &[
                "metadata",
                "enable",
                "--mode",
                "controlled_writers",
                "--deployment-review",
                path_str,
            ],
            1,
        )?;
        command(&["metadata", "enable", "--deployment-review", path_str], 1)?;
        assert_eq!(
            command(&["metadata", "status"], 0)?.summary["enabled"],
            false
        );
        assert!(!root.join("runtime/endpoint.json").exists());
        Ok(())
    })
}

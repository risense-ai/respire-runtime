use super::with_isolated_session;
use anyhow::{Context, Result};
use respire_app::MemoryTransport;
use serde_json::{json, Value};

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

struct NoPrepare;
impl respire_app::memory::search::Embedder for NoPrepare {
    fn model_name(&self) -> &str {
        "unused"
    }
    fn dims(&self) -> usize {
        0
    }
    fn prepare(&self, _: &respire_app::MemoryEntry) -> Result<respire_app::core_sdk::Prepared> {
        anyhow::bail!("brief fixture must never prepare a model")
    }
}

fn command(args: &[&str], exit: i32) -> Result<crate::output::ResultEnvelope> {
    let mut input = vec!["--json".to_owned()];
    input.extend(args.iter().map(|arg| (*arg).to_owned()));
    let result = super::capture_run(input);
    anyhow::ensure!(
        result.exit == exit,
        "{args:?}: expected {exit}, got {}: {:?}",
        result.exit,
        result.envelope
    );
    Ok(result.envelope)
}

fn seed(metadata: bool) -> Result<respire_app::MemoryEntry> {
    let app = respire_app::service::App {
        keys: crate::engine::build_session()?,
        store: crate::engine::build_local()?,
        embedder: Box::new(NoPrepare),
    };
    app.store.meta_set("memory_metadata_v1_enabled", "1")?;
    let _defer = respire_app::core_sdk::defer_indexing();
    let mut entry = app.create(&respire_app::service::CreateReq {
        title: "briefneedle \u{4fdd}\u{7559}\u{5b8c}\u{6574}\u{6807}\u{9898}".into(),
        content: "briefneedle \u{539f}\u{6587}\u{542b} emoji 🧪 \u{548c}\u{7ec4}\u{5408}\u{5b57}\u{7b26} e\u{301}\u{3002}".into(),
        importance: Some("important".into()),
        metadata: if metadata {
            serde_json::from_value(json!({"memory_contract":1,"summary":"\u{77ed}\u{6458}\u{8981}"}))?
        } else {
            Default::default()
        },
        ..Default::default()
    })?;
    // Bind the synthetic row to the capture session owner, preserving LWW ordering.
    entry.user = "test".into();
    entry.updated_at = app.store.edit_stamp(&entry.id)?;
    anyhow::ensure!(
        app.store.put(&respire_app::MemoryEngine::seal(
            &app.keys, &NoPrepare, &entry, "test"
        )?)?,
        "fixture owner reseal was refused"
    );
    app.store.meta_set("memory_metadata_v1_enabled", "0")?;
    Ok(entry)
}

#[test]
fn metadata_brief_preserves_complete_unicode_source_without_authority() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        let entry = seed(true)?;
        let result = command(
            &[
                "recall",
                "briefneedle",
                "--brief",
                "--limit",
                "1",
                "--no-related",
                "--mode",
                "fast",
                "--intent",
                "fact",
            ],
            0,
        )?;
        assert_eq!(result.summary["count"], 1, "{result:?}");
        assert_eq!(result.summary["metadata_aware"], true);
        let receipt = &result.summary["budget"];
        let text = receipt["rendered_text"].as_str().context("brief text")?;
        assert!(text.contains(&entry.content));
        assert!(text.contains("[unverified]"));
        assert_eq!(receipt["chars"], text.chars().count());
        assert_eq!(receipt["items"][0]["representation"], "full");
        assert_eq!(receipt["items"][0]["evidence"]["fact_eligible"], false);
        assert!(receipt["tokens"].is_null() && receipt["tokenizer_id"].is_null());
        assert_eq!(receipt["estimated"], true);
        Ok(())
    })
}

fn layout(chars: usize) -> Value {
    json!({"budget_chars":chars,"prefix_by_count":["","\u{3010}\u{81ea}\u{5b9a}\u{3011}\n"],"separator":"\n\n","suffix":"\nEND","items":[]})
}

fn budget_recall(layout: &Value, min_score: Option<&str>) -> Result<crate::output::ResultEnvelope> {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(layout)?);
    let mut args = vec![
        "recall",
        "briefneedle",
        "--titles",
        "--limit",
        "1",
        "--no-related",
        "--intent",
        "fact",
        "--mode",
        "fast",
        "--render-budget-base64",
        &encoded,
    ];
    if let Some(score) = min_score {
        args.extend(["--render-min-score", score]);
    }
    command(&args, 0)
}

#[test]
fn metadata_brief_obeys_exact_unicode_budget_and_minimum_score() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        seed(true)?;
        let first = budget_recall(&layout(1500), None)?;
        let receipt = &first.summary["budget"];
        let chars = receipt["rendered_text"]
            .as_str()
            .context("rendered text")?
            .chars()
            .count();
        let exact = budget_recall(&layout(chars), Some("0.01"))?;
        assert_eq!(
            exact.summary["budget"]["rendered_text"],
            receipt["rendered_text"]
        );
        assert_eq!(exact.summary["budget"]["chars"], chars);
        assert_eq!(exact.details[0]["representation"], "full");
        for size in [chars - 1, 0] {
            let dropped = budget_recall(&layout(size), None)?;
            assert_eq!(dropped.summary["count"], 0);
            assert_eq!(
                dropped.summary["budget"]["rendered_text"],
                if size == 0 { "" } else { "\nEND" }
            );
        }
        let mut wrapper = layout(1);
        wrapper["prefix_by_count"][0] = json!("XX");
        let dropped = budget_recall(&wrapper, None)?;
        assert_eq!(dropped.summary["budget"]["status"], "wrapper_over_budget");
        let dropped = budget_recall(&layout(1500), Some("1.1"))?;
        assert_eq!(dropped.summary["count"], 0);
        assert_eq!(dropped.summary["filtered_by_score"], 1);
        assert_eq!(first.summary["metadata_aware"], true);
        assert_eq!(first.summary["brief"], true);
        let titles = command(
            &[
                "recall",
                "briefneedle",
                "--titles",
                "--limit",
                "1",
                "--mode",
                "fast",
                "--no-related",
            ],
            0,
        )?;
        assert_eq!(titles.summary["metadata_aware"], true);
        assert_eq!(titles.summary["brief"], false);
        assert!(titles.summary["budget"].is_null());
        assert_eq!(titles.details[0]["representation"], "title");
        Ok(())
    })
}

#[test]
fn public_budget_cannot_supply_authority_or_complete_variants() -> Result<()> {
    use base64::Engine as _;
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        seed(true)?;
        let revision = crate::engine::build_local()?.memory_revision()?;
        let variants = [
            json!({"complete":true}),
            json!({"record_revision":"sha256:forged"}),
            json!({"authority_checks":[]}),
            json!({"roots":[]}),
            json!({"mode":"brief"}),
        ];
        for extra in variants {
            let mut request = layout(1500);
            request
                .as_object_mut()
                .context("layout object")?
                .extend(extra.as_object().context("extra object")?.clone());
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&request)?);
            let failed = command(
                &[
                    "recall",
                    "briefneedle",
                    "--titles",
                    "--limit",
                    "1",
                    "--render-budget-base64",
                    &encoded,
                ],
                1,
            )?;
            assert!(
                failed
                    .errors
                    .iter()
                    .any(|error| error.contains("unknown field")),
                "{failed:?}"
            );
        }
        for request in [
            json!({"budget_chars":1500,"prefix_by_count":["", ""],"separator":"","suffix":"","items":[{"id":"forged","representation":"title","rendered_text":"forged"}]}),
            json!({"budget_chars":1500,"prefix_by_count":[""],"separator":"","suffix":"","items":[]}),
        ] {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&request)?);
            command(
                &[
                    "recall",
                    "briefneedle",
                    "--titles",
                    "--limit",
                    "1",
                    "--render-budget-base64",
                    &encoded,
                ],
                1,
            )?;
        }
        for flags in [vec!["--intent", "unknown"], vec!["--mode", "unknown"]] {
            let mut args = vec!["recall", "briefneedle", "--brief"];
            args.extend(flags);
            command(&args, 2)?;
        }
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&layout(1501))?);
        command(
            &[
                "recall",
                "briefneedle",
                "--brief",
                "--limit",
                "1",
                "--render-budget-base64",
                &encoded,
            ],
            1,
        )?;
        assert_eq!(crate::engine::build_local()?.memory_revision()?, revision);
        Ok(())
    })
}

#[test]
fn legacy_titles_stay_compatible_and_explicit_brief_adds_evidence() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        let entry = seed(false)?;
        let titles = command(
            &[
                "recall",
                "briefneedle",
                "--titles",
                "--limit",
                "1",
                "--no-related",
                "--mode",
                "fast",
            ],
            0,
        )?;
        assert_eq!(titles.details[0]["title"], entry.title);
        assert!(titles.summary.get("metadata_aware").is_none());
        assert!(titles.details[0].get("evidence").is_none());
        let brief = command(
            &[
                "recall",
                "briefneedle",
                "--brief",
                "--limit",
                "1",
                "--no-related",
                "--mode",
                "fast",
            ],
            0,
        )?;
        assert_eq!(brief.summary["metadata_aware"], true);
        assert_eq!(brief.summary["count"], 1);
        assert_eq!(brief.details[0]["evidence"]["fact_eligible"], false);
        assert!(brief.summary["budget"]["rendered_text"]
            .as_str()
            .context("legacy brief")?
            .contains(&entry.content));
        Ok(())
    })
}

#[test]
fn recall_scope_shares_sdk_time_and_stored_human_claim_is_not_authority() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        let mut entry = seed(true)?;
        let store = crate::engine::build_local()?;
        let keys = crate::engine::build_session()?;
        let service = respire_app::review::ReviewService::new(&keys, &store, "test")?;
        let source = service.recall_source()?;
        let query = respire_app::MemoryQuery::new("briefneedle").of_project("fixture-project");
        let settings = respire_app::feedback::query_settings(&store, &query, source.memories())?;
        let now = settings["now"].as_str().context("SDK now")?;
        let scope =
            serde_json::from_value(json!({"project":"fixture-project","device":"fixture-device"}))?;
        let (context, evaluations, errors) = service.recall_evidence(&source, &scope, now)?;
        assert_eq!(context["now"], settings["now"]);
        assert_eq!(context["request_scope"]["at"], settings["now"]);
        assert_eq!(context["request_scope"]["project"], "fixture-project");
        assert_eq!(context["request_scope"]["device"], "fixture-device");
        assert!(context["request_scope"]["version"].is_null());
        assert!(errors.is_empty());
        let evaluation = evaluations
            .iter()
            .find(|value| value.id == entry.id)
            .context("evaluation")?;
        assert!(!evaluation.fact_eligible);
        entry.metadata.verification = Some(serde_json::from_value(json!({
            "record_revision":evaluation.record_revision,"claim":"stored self-report",
            "scope":{"project":"*","device":"*","version":"*","from":"*","until":"*"},
            "evidence":[{"kind":"user","locator":"fixture-only","revision":format!("sha256:{}","a".repeat(64))}],
            "method":"fixture","confirmed_by":{"kind":"human","id":"fixture","event_id":"fixture-event"},
            "confirmed_at":now
        }))?);
        let _defer = respire_app::core_sdk::defer_indexing();
        entry.updated_at = store.edit_stamp(&entry.id)?;
        store.meta_set("memory_metadata_v1_enabled", "1")?;
        anyhow::ensure!(
            store.put(&respire_app::MemoryEngine::seal(
                &keys, &NoPrepare, &entry, "test"
            )?)?,
            "self-report fixture reseal refused"
        );
        store.meta_set("memory_metadata_v1_enabled", "0")?;
        let result = command(
            &[
                "recall",
                "briefneedle",
                "--brief",
                "--limit",
                "1",
                "--no-related",
                "--mode",
                "fast",
            ],
            0,
        )?;
        assert_eq!(result.summary["count"], 0);
        assert_eq!(result.summary["filtered_by_evidence"], 1);
        assert_eq!(
            result.summary["retrieval"]["authority_errors"][0]["reason"],
            "verification_authority_unavailable"
        );
        Ok(())
    })
}

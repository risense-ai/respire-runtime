//! Explicit user mode and provider configuration; Core returns final recall results.
#[path = "recall_metadata.rs"]
mod metadata;
pub use metadata::{brief_layout, recall_metadata, require_metadata};
use anyhow::{Context, Result};
use respire_app::memory::model::{RenderBudget, RenderBudgetReceipt, RenderItem, RecallRepresentation};
use respire_app::memory::engine::RecalledWithContext;
use respire_app::transport::MemoryTransport;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct RecallResult {
    items: Vec<RecalledWithContext>,
    mode: String,
    warning: Option<String>,
    routing: respire_app::memory::model::RecallRouting,
    retrieval: Value,
    #[serde(default)]
    budget: Option<RenderBudgetReceipt>,
    #[serde(default)]
    filtered_by_score: Option<usize>,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    procedure_pass: Option<usize>,
    #[serde(default)]
    procedure_promoted: Option<bool>,
}

/// Validate external layout input before opening a catalog or initializing a model.
pub fn decode_render_budget(encoded: Option<&str>, limit: usize, intent: &str) -> Result<Option<RenderBudget>> {
    use base64::Engine as _;
    encoded.map(|encoded| {
        let budget: RenderBudget = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD.decode(encoded)?)?;
        anyhow::ensure!(matches!(intent, "auto" | "fact" | "howto"), "unknown recall intent");
        anyhow::ensure!(budget.items.is_empty(),
            "CLI render budget items must be empty; titles come from the authorized catalog");
        anyhow::ensure!(budget.prefix_by_count.len() > limit,
            "render budget prefixes must cover zero through recall limit");
        Ok(budget)
    }).transpose()
}

pub fn require_render_budget(render_min_score: Option<f32>) -> Result<()> {
    anyhow::ensure!(render_min_score.is_none_or(f32::is_finite), "render minimum score must be finite");
    let capabilities: Value = respire_app::core_sdk::execute("capabilities", json!({}))?;
    anyhow::ensure!(capabilities["render_budget_contract"] == 1,
        "Core SDK does not support render budget contract 1; install a matching SDK");
    anyhow::ensure!(capabilities["howto_recall_contract"] == 1,
        "Core SDK does not support how-to recall contract 1; install a matching SDK");
    anyhow::ensure!(capabilities["superseded_status_contract"] == 1,
        "Core SDK does not support superseded status contract 1; install a matching SDK");
    if render_min_score.is_some() {
        anyhow::ensure!(capabilities["render_min_score_contract"] == 1,
            "Core SDK does not support render minimum score contract 1; install a matching SDK");
    }
    Ok(())
}

pub fn recall<E: respire_app::memory::search::Embedder>(
    keys: &respire_app::memory::SessionKeys,
    embedder: &E,
    candidates: &[respire_app::StoredMemory],
    query: &respire_app::MemoryQuery,
    store: &respire_app::transport::local::LocalStore,
    render_budget: Option<RenderBudget>,
    render_min_score: Option<f32>,
    intent: Option<&str>,
) -> Result<(Vec<RecalledWithContext>, String, Option<String>, respire_app::memory::model::RecallRouting, Value, Option<RenderBudgetReceipt>)> {
    let mode = respire_app::service::read_agent_config()["recall_mode"]
        .as_str()
        .unwrap_or("fast")
        .to_owned();
    recall_with_mode(keys, embedder, candidates, query, store, render_budget, render_min_score, intent, &mode)
}

pub fn recall_with_mode<E: respire_app::memory::search::Embedder>(
    keys: &respire_app::memory::SessionKeys,
    embedder: &E,
    candidates: &[respire_app::StoredMemory],
    query: &respire_app::MemoryQuery,
    store: &respire_app::transport::local::LocalStore,
    render_budget: Option<RenderBudget>,
    render_min_score: Option<f32>,
    intent: Option<&str>,
    mode: &str,
) -> Result<(Vec<RecalledWithContext>, String, Option<String>, respire_app::memory::model::RecallRouting, Value, Option<RenderBudgetReceipt>)> {
    anyhow::ensure!(matches!(mode, "fast" | "quality"), "unknown recall mode");
    let superseded = if render_budget.is_some() {
        let metadata: respire_app::memory::model::RelatedResult = respire_app::core_sdk::execute("related_business", json!({
            "model": embedder.model_name(), "snapshots": respire_app::memory::engine::snapshots(keys, candidates)?,
            "query": query, "ids": [], "pairs": [],
            "related_settings": {"enabled": false}, "all_superseded": true,
        }))?;
        metadata.superseded
    } else { Default::default() };
    let render_budget = render_budget.map(|mut budget| -> Result<RenderBudget> {
        // Resident catalogs deliberately discard ciphertext; load only authorized source records.
        let authorized: std::collections::HashSet<&str> = candidates.iter().map(|memory| memory.id.as_str()).collect();
        let records = store.all(false)?;
        budget.items = records.iter().filter(|memory| authorized.contains(memory.id.as_str())).map(|memory| {
            let entry = respire_app::memory::engine::MemoryEngine::open(keys, memory)
                .context("decrypt title for render budget")?;
            let title = if entry.title.is_empty() { "(untitled)" } else { &entry.title };
            let state = if superseded.contains_key(&entry.id) { " \u{2192}superseded" } else { "" };
            Ok(RenderItem { id: entry.id.clone(), representation: RecallRepresentation::Title,
                rendered_text: format!("- {title}\u{ff08}{}\u{ff09}{state}", entry.id) })
        }).collect::<Result<Vec<_>>>()?;
        Ok(budget)
    }).transpose()?;
    let provider = if mode == "quality" {
        configured_provider()
    } else {
        None
    };
    let mut transport = |request: &Value| -> Result<Value> {
        let backend = provider.as_ref().ok_or_else(|| anyhow::anyhow!("model provider is not configured"))?;
        crate::classify::call_api(backend, request)
    };
    let mut payload = json!({
        "model": embedder.model_name(), "snapshots": respire_app::memory::engine::snapshots(keys, candidates)?,
        "query": query, "mode": mode,
        "query_settings": respire_app::feedback::query_settings(store, query, candidates)?,
        "provider": provider.as_ref().map(|backend| json!({"name":backend.name,"model":backend.model})),
    });
    if let Some(budget) = &render_budget { payload["render_budget"] = json!(budget); }
    if let Some(min_score) = render_min_score { payload["render_min_score"] = json!(min_score); }
    if let Some(intent) = intent {
        let ids: Vec<String> = candidates.iter().map(|memory| memory.id.clone()).collect();
        let runs: std::collections::HashMap<String, Value> = store.skill_run_stats(&ids)?.into_iter()
            .map(|(id, stats)| (id, json!({"ok": stats.ok, "fail": stats.fail}))).collect();
        payload["intent"] = json!(intent);
        payload["skill_runs"] = json!(runs);
    }
    let mut result: RecallResult = respire_app::core_sdk::execute_with_transport(
        "query_business",
        payload,
        &mut transport,
    )?;
    if render_min_score.is_some() {
        let filtered = result.filtered_by_score.context("Core omitted required render score receipt")?;
        result.retrieval["filtered_by_score"] = json!(filtered);
    }
    if intent.is_some() {
        let resolved = result.intent.as_deref().context("Core omitted required intent receipt")?;
        anyhow::ensure!(matches!(resolved, "typed" | "howto" | "fact"), "invalid Core intent receipt");
        result.retrieval["intent"] = json!(resolved);
        result.retrieval["procedure_pass"] = json!(result.procedure_pass.context("Core omitted procedure count")?);
        result.retrieval["procedure_promoted"] = json!(result.procedure_promoted.context("Core omitted procedure promotion receipt")?);
    }
    if render_budget.is_some() { result.retrieval["superseded"] = json!(superseded); }
    if let Some(request) = &render_budget {
        let receipt = result.budget.as_ref().context("Core omitted required render budget receipt")?;
        let body = receipt.items.iter().map(|item| item.rendered_text.as_str()).collect::<Vec<_>>().join(&request.separator);
        let text = if receipt.status == respire_app::memory::model::RenderBudgetStatus::WrapperOverBudget {
            anyhow::ensure!(receipt.items.is_empty(), "Core returned items with an over-budget wrapper");
            String::new()
        } else {
            format!("{}{}{}", request.prefix_by_count.get(receipt.items.len()).context("invalid budget item count")?, body, request.suffix)
        };
        anyhow::ensure!(receipt.rendered_text == text && receipt.chars == text.chars().count()
            && receipt.chars <= request.budget_chars && receipt.budget_chars == request.budget_chars
            && receipt.selected_count == receipt.items.len()
            && receipt.tokens.is_none() && receipt.tokenizer_id.is_none() && receipt.estimated
            && receipt.items.iter().all(|item| request.items.iter().any(|source|
                source.id == item.id && source.representation == item.representation && source.rendered_text == item.rendered_text))
            && result.items.iter().map(|item| item.entry.id.as_str()).eq(receipt.items.iter().map(|item| item.id.as_str())),
            "Core render budget contract mismatch; dynamic block refused");
    }
    if respire_app::env::var("RSRS_DEBUG_SCORE").is_ok_and(|value| value == "1") {
        eprintln!("{}", serde_json::to_string(&result.retrieval)?);
    }
    Ok((result.items, result.mode, result.warning, result.routing, result.retrieval, result.budget))
}

fn configured_provider() -> Option<crate::classify::Backend> {
    let config = respire_app::service::read_agent_config();
    let base = config["recall_api_base"]
        .as_str()
        .map(str::to_owned)
        .or_else(respire_app::keystore::load_ds_last_base)
        .unwrap_or_else(|| crate::classify::DEFAULT_DS_BASE.to_owned());
    let slot = format!("ds@{}", respire_app::keystore::host_of(&base));
    let key = respire_app::env::var("RSRS_RECALL_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .or_else(|| respire_app::keystore::load_classify_key(&slot))?;
    let model = config["recall_model"]
        .as_str()
        .unwrap_or(crate::classify::DEFAULT_DS_MODEL);
    Some(crate::classify::Backend { name: "ds", endpoint: crate::classify::ds_endpoint(&base),
        key, model: model.to_owned(), base_shown: base })
}

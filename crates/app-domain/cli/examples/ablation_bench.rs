//! Read-only local benchmark. Set RSRS_DATA_DIR to an initialized isolated copy.
use anyhow::{Context, Result};
use clap::Parser;
use respire::{
    memory::{engine::RecalledWithContext, MemoryQuery},
    MemoryTransport,
};
use respire_app as respire;
use serde_json::{json, Value};

#[path = "../../crates/commands/src/bench.rs"]
#[allow(dead_code)]
mod bench;

#[derive(Parser)]
struct Args {
    evalset: String,
    #[arg(long, default_value_t = 5)]
    topk: usize,
    #[arg(long)]
    per_case: bool,
    #[arg(long)]
    save: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    anyhow::ensure!(args.topk > 0, "topk must be positive");
    let root = respire::env::var("RSRS_DATA_DIR")
        .context("set RSRS_DATA_DIR to an initialized isolated library copy")?;
    anyhow::ensure!(!root.trim().is_empty(), "RSRS_DATA_DIR is empty");
    let root = std::fs::canonicalize(root.trim())?;
    respire::core_sdk::set_index_root(&root)?;
    let store = respire::transport::local::LocalStore::open_read_only(
        &respire::service::database_path(&root)?,
    )?;
    let keys = respire::auth::load_local_session()?;
    let candidates = store.all(false)?;
    anyhow::ensure!(
        store.candidates_index_ready(&candidates)?,
        "library index is not ready; prepare the isolated copy before benchmarking"
    );
    let model = store.retrieval_model()?;
    let snapshots = respire::memory::engine::snapshots(&keys, &candidates)?;
    let cases = bench::parse_evalset(&std::fs::read_to_string(&args.evalset)?)?;
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let mut query = MemoryQuery::new(&case.query).limit(args.topk);
        if let Some(project) = &case.project {
            if !project.is_empty() {
                query = query.of_project(project);
            }
        }
        let output: Value = respire::core_sdk::execute(
            "query_business",
            json!({
                "model":model, "mode":"fast", "provider":null,
                "query":query, "snapshots":snapshots,
                "query_settings":respire::feedback::query_settings(&store,&query,&candidates)?,
            }),
        )?;
        let ranked: Vec<RecalledWithContext> = serde_json::from_value(output["items"].clone())?;
        let ids: Vec<String> = ranked.iter().map(|item| item.entry.id.clone()).collect();
        let result = bench::CaseResult {
            rank: bench::rank_of(&ids, &case.expect),
            ids,
            top1_score: ranked.first().map(|item| item.score),
            top1_title: ranked
                .first()
                .map(|item| item.entry.title.clone())
                .unwrap_or_default(),
            query: case.query,
            expect: case.expect,
            project: case.project,
        };
        if args.per_case {
            println!(
                "{}",
                serde_json::to_string(&json!({"case":result,"routing":output["routing"],"retrieval":output["retrieval"]}))?
            );
        }
        results.push(result);
    }
    let mut params = bench::snapshot_params()?;
    params.insert("embedding_model".into(), model);
    params.insert("recall_mode".into(), "fast".into());
    let report = bench::BenchReport {
        version: 1,
        ts: chrono::Utc::now().to_rfc3339(),
        evalset: args.evalset,
        topk: args.topk,
        n_entries: candidates.len(),
        params,
        metrics: bench::summarize(&results, args.topk),
        results,
    };
    if let Some(path) = args.save {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
    }
    if args.per_case {
        eprintln!("{}", serde_json::to_string(&report.metrics)?);
    } else {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

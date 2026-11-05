//! Synthetic source-size probe, not a semantic-quality benchmark.
use anyhow::{Context, Result};
use respire_app::{
    core_sdk::search::HashingEmbedder, diary, transport::local::LocalStore, Kind, MemoryEngine,
    MemoryEntry, MemoryTransport, SessionKeys,
};
use serde_json::json;
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let chars: usize = args.get(1).context("chars")?.parse()?;
    let days: usize = args.get(2).context("days")?.parse()?;
    anyhow::ensure!(
        (1..=2_000_000).contains(&chars)
            && (1..=400).contains(&days)
            && chars.saturating_mul(days) <= 3_000_000,
        "bounded synthetic fixture"
    );
    let root = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", root.path());
    let store = LocalStore::open(&root.path().join("rsrs.db"))?;
    let keys = SessionKeys::from_urk([39; 32])?;
    let provider = HashingEmbedder::new(8);
    for day in 0..days {
        let entry = MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            id: format!("synthetic-day-{day}"),
            kind: Kind::Time,
            tags: vec![],
            title: "Synthetic scale diary".into(),
            content: format!("{} needle", "x".repeat(chars)),
            user: "synthetic".into(),
            computer: "fixture".into(),
            project: "fixture".into(),
            created_at: "2026-10-27T09:00:00Z".into(),
            updated_at: "2026-10-27T09:00:00Z".into(),
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
            store.put(&MemoryEngine::seal(&keys, &provider, &entry, "synthetic")?)?,
            "seed"
        );
    }
    let started = std::time::Instant::now();
    let mut counts = Vec::new();
    for _ in 0..3 {
        counts.push(
            diary::search(&store, &keys, "needle", 5, 4000, false)?
                .items
                .len(),
        );
    }
    println!(
        "{}",
        json!({"synthetic":true,"semantic_quality_benchmark":false,"chars_per_day":chars,"days":days,"searches":3,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0,"counts":counts})
    );
    Ok(())
}

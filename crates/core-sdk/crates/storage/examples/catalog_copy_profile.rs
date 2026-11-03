//! Synthetic artifact attachment profile. Never opens a user profile.
use anyhow::{Context, Result};
use respire_storage::{StoredMemory, transport::{MemoryTransport, local::LocalStore}};
use serde_json::json;
use std::{io::Write, time::Instant};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let mode=args.get(1).context("seed|read")?;
    let root=std::path::Path::new(args.get(2).context("isolated directory")?);
    std::fs::create_dir_all(root)?;
    let count: usize=args.get(3).context("count")?.parse()?;
    let bytes: usize=args.get(4).context("ciphertext bytes")?.parse()?;
    let store=LocalStore::open(&root.join("synthetic.db"))?;
    if mode=="seed" {
        for start in (0..count).step_by(100) {
            let batch:Vec<_>=(start..(start+100).min(count)).map(|i| {
                let mut m=StoredMemory::new_pending(format!("fixture-{i:05}"),"synthetic".into());
                m.ciphertext="x".repeat(bytes); m.updated_at="2026-10-14T00:00:00Z".into();
                m.local_artifact=format!("synthetic opaque locator {i:05}").into_bytes(); m
            }).collect();
            store.import_batch(&batch)?;
        }
        return Ok(());
    }
    // Initialize the Core generation check before measuring the read path.
    let generation=respire_core_sdk::generation_key("m3")?;
    let rounds:usize=args.get(5).map(|v|v.parse()).transpose()?.unwrap_or(20);
    let mut timings=Vec::new();
    for _ in 0..rounds {
        let start=Instant::now(); let memories=store.all(false)?;
        timings.push(start.elapsed().as_secs_f64()*1000.);
        anyhow::ensure!(memories.len()==count,"fixture count mismatch");
        anyhow::ensure!(memories.iter().all(|m|m.ciphertext.len()==bytes && !m.local_artifact.is_empty()),"fixture mismatch");
        for (index, memory) in memories.iter().enumerate() {
            anyhow::ensure!(memory.id == format!("fixture-{index:05}") && memory.user == "synthetic"
                && memory.updated_at == "2026-10-14T00:00:00Z" && !memory.deleted
                && memory.local_artifact == format!("synthetic opaque locator {index:05}").as_bytes(),
                "fixture identity/order/artifact mismatch");
        }
        std::hint::black_box(&memories);
        drop(memories);
    }
    println!("{}",json!({"count":count,"ciphertext_bytes":bytes,"generation":generation,"latency_ms":timings,"status":std::fs::read_to_string("/proc/self/status")?,"smaps":std::fs::read_to_string("/proc/self/smaps_rollup")?}));
    std::io::stdout().flush()?; Ok(())
}

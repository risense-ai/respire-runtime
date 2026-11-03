//! Deterministic plaintext, independent synthetic-key profile for full CLI M3 profiling.
//! This only seals pending rows; the real runtime must embed every row itself.
use anyhow::{Context, Result};
use respire_app::{MemoryEngine, MemoryEntry, SessionKeys};
use respire_app::core_sdk;
use respire_app::memory::{crypto, search::HashingEmbedder};
use respire_storage::transport::local::LocalStore;
use serde_json::json;
fn main() -> Result<()> {
    let args:Vec<_>=std::env::args().collect();
    let root=std::path::PathBuf::from(args.get(1).context("new synthetic fixture directory")?);
    let count:usize=args.get(2).context("count")?.parse()?;
    anyhow::ensure!(!root.exists(), "fixture directory must not exist");
    std::fs::create_dir_all(&root)?;
    let secret=std::env::var("RSRS_TEST_SUPER").context("set local synthetic RSRS_TEST_SUPER")?;
    let salt=std::env::var("RSRS_TEST_SALT").context("set local synthetic RSRS_TEST_SALT")?; let urk:[u8;32]=std::fs::read(std::env::var("RSRS_TEST_URK_FILE").context("set local synthetic RSRS_TEST_URK_FILE")?)?.try_into().map_err(|_| anyhow::anyhow!("synthetic URK file must contain 32 bytes"))?;
    let kek=crypto::derive_rsrs_kek(&secret,&salt)?;
    let (nonce,wrapped)=crypto::wrap_key(&urk,&kek)?;
    std::fs::write(root.join("session.json"),serde_json::to_vec(&json!({"user":"synthetic-m3","pass":"","vault_version":4,"kdf_salt":salt,"wrapped_urk":format!("{}{wrapped}",crypto::RSRS_PREFIX),"urk_nonce":nonce}))?)?;
    let store=LocalStore::open(&root.join("rsrs.db"))?;
    let keys=SessionKeys::from_urk(urk)?;
    let _defer=core_sdk::defer_indexing();
    let provider=HashingEmbedder::new(1024);
    let mut lengths=Vec::new();
    for start in (0..count).step_by(100) {
        let mut batch=Vec::new();
        for i in start..(start+100).min(count) {
            let length=match i%20 {0..=9=>192,10..=15=>384,16..=18=>768,_=>1536};
            let mut body=format!("Synthetic memory number {i:05}. Topic {}. Experiment fixed seed 20261014. ",i%17);
            while body.len()<length {body.push_str("Archive retrieval benchmark garden river rust library practical observation. ");}
            body.truncate(length);lengths.push(length);
            let entry:MemoryEntry=serde_json::from_value(json!({"id":format!("m3-synthetic-{i:05}"),"kind":"Context","tags":["synthetic",format!("topic-{}",i%17)],"title":format!("Synthetic M3 fixture {i:05}"),"content":body,"user":"synthetic-m3","computer":"dot-linux-synthetic","project":"dev10-profile","created_at":"2026-10-14T00:00:00Z","updated_at":"2026-10-14T00:00:00Z","emotion":0,"parent_id":"","importance":"normal"}))?;
            batch.push(MemoryEngine::seal(&keys,&provider,&entry,"synthetic-m3")?);
        }
        store.import_batch(&batch)?;
    }
    std::fs::write(root.join("fixture-manifest.json"),serde_json::to_vec_pretty(&json!({"kind":"synthetic-only","seed":20261014,"count":count,"body_lengths":lengths,"unique_bodies":count,"user":"synthetic-m3","initial_artifacts":0,"key_origin":"locally generated synthetic test URK, never user credentials","plaintext_distribution":"50%192B,30%384B,15%768B,5%1536B; unique numeric ID and topic in every body","model_requirement":"real pinned M3 runtime must generate each artifact; never clone a prepared artifact"}))?)?;
    println!("{}",json!({"count":count,"profile":root,"status":"pending-only"}));
    Ok(())
}

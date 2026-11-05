//! One-time backfill of local plaintext metadata indexes.
//!
//! Older sync hydration omitted the local importance column. Rehydrate live
//! entries from the encrypted payload without changing ciphertext or dirty flags.
//!
//! Usage:
//!   cargo run --release -p respire_commands --example repair-locals
//!   cargo run --release -p respire_commands --example repair-locals -- --dry

use anyhow::Result;
use respire_app as respire;
use respire::auth;
use respire::memory::engine::hydrate_local;
use respire::service::open_store;
use respire::MemoryTransport;

fn main() -> Result<()> {
    let dry = std::env::args().any(|a| a == "--dry");
    let keys = auth::load_local_session()?;
    let store = open_store()?;
    let all = store.all(true)?;

    let broken: Vec<_> = all
        .iter()
        .filter(|s| !s.deleted && s.local_importance.is_empty())
        .collect();

    println!(
        "🌐 \u{7d22}\u{5f15}\u{5bf9}\u{8d26}\u{ff1a}importance \u{5217}\u{7a7a}\u{4e32} {} \u{6761}{}",
        broken.len(),
        if dry { "\u{ff08}dry \u{53ea}\u{770b}\u{4e0d}\u{52a8}\u{ff09}" } else { "" }
    );
    if broken.is_empty() {
        println!("\u{2713} \u{65e0}\u{7a7a}\u{4e32}\u{2014}\u{2014}\u{7d22}\u{5f15}\u{5217}\u{5065}\u{5168}");
        return Ok(());
    }

    let mut fixed = 0usize;
    let mut failed = 0usize;
    for s in &broken {
        let title = if s.local_title.is_empty() {
            &s.id[..8]
        } else {
            &s.local_title
        };
        let mut st = (*s).clone();
        match hydrate_local(&keys, &mut st) {
            Ok(()) => {
                if !dry {
                    store.put_synced(&st)?;
                }
                fixed += 1;
                println!(
                    "  🔧 {} {}  importance \u{2192} {}",
                    &s.id[..8],
                    title,
                    st.local_importance
                );
            }
            Err(e) => {
                failed += 1;
                println!(
                    "  \u{26a0}\u{fe0f} {} \u{89e3}\u{5bc6}\u{5931}\u{8d25}\u{ff1a}{e}",
                    &s.id[..8]
                );
            }
        }
    }
    println!(
        "{} \u{56de}\u{586b} {} \u{6761}\u{ff0c}\u{5931}\u{8d25} {failed} \u{6761}",
        if dry {
            "🔎 \u{8bd5}\u{8fd0}\u{884c}"
        } else {
            "\u{2705}"
        },
        fixed
    );
    Ok(())
}

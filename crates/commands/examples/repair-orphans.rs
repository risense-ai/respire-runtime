//! One-time repair of legacy orphan parent links.
//!
//! Older versions stored unresolved short prefixes as parent IDs. Resolve an
//! unambiguous live parent and reject cycles; otherwise promote the entry to a root.
//! Reseal changed parent links so synchronization can propagate the correction.
//!
//! Usage:
//!   cargo run --release -p respire_commands --example repair-orphans
//!   cargo run --release -p respire_commands --example repair-orphans -- --dry

use anyhow::Result;
use respire_app as respire;
use respire::auth;
use respire::memory::bge::BgeEmbedder;
use respire::memory::engine::MemoryEngine;
use respire::service::{now_stamp, open_store, resolve_prefix};
use respire::sync::{build_remote_from_env, remote_configured, sync_all};
use respire::MemoryTransport;

fn main() -> Result<()> {
    let dry = std::env::args().any(|a| a == "--dry");
    let keys = respire::auth::load_local_session()?;
    let store = open_store()?;
    let embedder = BgeEmbedder::load()?;
    let all = store.all(true)?;

    let orphans: Vec<_> = all
        .iter()
        .filter(|s| !s.deleted && !s.local_parent_id.is_empty())
        .filter(|s| !all.iter().any(|p| p.id == s.local_parent_id && !p.deleted))
        .collect();

    println!("🌐 \u{5b64}\u{513f}\u{5bf9}\u{8d26}\u{ff1a}\u{6d3b}\u{8dc3}\u{7236}\u{7f3a}\u{5931} {} \u{6761}{}", orphans.len(), if dry { "\u{ff08}dry \u{53ea}\u{770b}\u{4e0d}\u{52a8}\u{ff09}" } else { "" });
    if orphans.is_empty() {
        println!("\u{2713} \u{65e0}\u{5b64}\u{513f}\u{2014}\u{2014}\u{56e0}\u{679c}\u{6811}\u{5065}\u{5168}");
        return Ok(());
    }

    let mut reattached = 0usize;
    let mut promoted = 0usize;
    for s in &orphans {
        let title = if s.local_title.is_empty() {
            &s.id[..8]
        } else {
            &s.local_title
        };
        let entry = MemoryEngine::open(&keys, s)?;
        // Reject cycles: the target ancestor chain must not contain this entry.
        let chain = store.ancestor_chain(&s.id)?;
        let decide = match resolve_prefix(&all, &s.local_parent_id) {
            Ok(full) if full != s.id && !chain.contains(&full) => ("reattach", full),
            _ => ("promote", String::new()),
        };
        match decide {
            ("reattach", full) => {
                println!(
                    "  🔗 {} {}  \u{5047}\u{7236} {} \u{2192} \u{771f}\u{7236} {}",
                    &s.id[..8],
                    title,
                    &s.local_parent_id[..8],
                    &full[..8]
                );
                if !dry {
                    let mut e = entry;
                    e.parent_id = full;
                    e.updated_at = now_stamp();
                    let user = e.user.clone();
                    let stored = MemoryEngine::seal(&keys, &embedder, &e, &user)?;
                    store.put(&stored)?;
                }
                reattached += 1;
            }
            _ => {
                println!("  \u{2b06}\u{fe0f} {} {}  \u{7236} {} \u{771f}\u{4e0d}\u{5b58}\u{5728} \u{2192} \u{5347}\u{6839}\u{ff08}\u{81ea}\u{4e3a}\u{56e0}\u{ff09}", &s.id[..8], title, &s.local_parent_id[..8]);
                if !dry {
                    let mut e = entry;
                    e.parent_id = String::new();
                    e.updated_at = now_stamp();
                    let user = e.user.clone();
                    let stored = MemoryEngine::seal(&keys, &embedder, &e, &user)?;
                    store.put(&stored)?;
                }
                promoted += 1;
            }
        }
    }

    println!("\u{2014}\u{2014} \u{8d26}\u{5355}\u{ff1a}\u{6302}\u{771f}\u{7236} {}\u{ff0c}\u{5347}\u{6839} {}\u{ff0c}\u{5171} {}", reattached, promoted, reattached + promoted);
    if dry {
        println!("\u{ff08}dry \u{672a}\u{52a8}\u{5e93}\u{2014}\u{2014}\u{53bb}\u{6389} --dry \u{5b9e}\u{4fee}\u{ff09}");
        return Ok(());
    }
    if remote_configured() {
        match build_remote_from_env().and_then(|remote| sync_all(&keys, &store, &remote)) {
            Ok(stats) => println!("🔁 \u{5df2}\u{540c}\u{6b65}\u{ff1a}\u{62c9} {} \u{6761}\u{ff0c}\u{63a8} {} \u{6761}", stats.pulled, stats.pushed),
            Err(e) => eprintln!("\u{26a0}\u{fe0f} \u{540c}\u{6b65}\u{5931}\u{8d25}\u{ff08}\u{672c}\u{5730}\u{5df2}\u{4fee}\u{ff0c}\u{7a0d}\u{540e} rsrs sync\u{ff09}: {e}"),
        }
    }
    Ok(())
}

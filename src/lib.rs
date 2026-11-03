#![forbid(unsafe_code)]


//! respire_app_domain — engine-side application layer.
//!
//! WP-2c moved the engine-reachable modules (service, sync, resident, snapshot, diary,
//! review, embedding, read heat, metadata gate, lock, recall fusion, taxonomy, share,
//! feedback, memory, transport, auth, keystore, prompt, input_error) out of respire_app.
//! The client crate (respire_app) re-exports every module here, so existing
//! `respire_app::...` paths keep resolving unchanged.

pub use respire_core_sdk::env;
pub use respire_core_sdk as core_sdk;

#[cfg(test)]
mod test_lock;

pub mod auth;
pub mod review_approval;
pub mod review;
pub mod metadata_gate;
pub mod input_error;
pub mod lock;
pub mod service;
pub mod diary;
pub mod embedding;
pub mod snapshot;
pub mod feedback;
pub mod read_heat;
pub mod recall_fusion;
pub mod resident;
pub mod sync;
pub mod taxonomy;
pub mod transport;
pub mod keystore;
pub mod prompt;
pub mod share;

pub mod memory {
    pub use respire_core_sdk::{bge, defrag, onnx, search};
    pub use respire_crypto::{crypto, engine};
    pub use respire_crypto::{hydrate_local, reembed_embedding, MemoryEngine, SessionKeys};
    pub use respire_protocol as model;
    pub use respire_protocol::{Kind, MemoryEntry, MemoryQuery, VERSION_TAG};
}

pub use memory::{hydrate_local, MemoryEngine, SessionKeys};
pub use memory::model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};
pub use transport::MemoryTransport;

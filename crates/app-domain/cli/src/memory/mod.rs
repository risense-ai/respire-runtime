//! memory — domain facade over the shared app-core memory implementation.
//!
//! This module is about memory itself: model, crypto, engine, search.
//!
//! Boundaries:
//! - no transport/storage imports
//! - public surface is `MemoryEngine` plus pure domain types
//! - server, client, and CLI all go through this facade

pub use respire_app::memory::{bge, crypto, defrag, engine, onnx, search};
pub use respire_app::memory::{hydrate_local, reembed_embedding, MemoryEngine, SessionKeys};

pub mod model {
    pub use respire_app::memory::model::*;
}

pub use model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};

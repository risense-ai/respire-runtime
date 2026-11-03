#![forbid(unsafe_code)]


//! respire_app — client-side application layer (inject, session_import, login_transaction, migration).
//!
//! WP-2c moved the engine-side modules into the respire_app_domain crate. This crate
//! re-exports every domain module under its original name, so existing
//! `respire_app::service::...`, `respire_app::memory::...`, `respire_app::transport::...`
//! and all other engine paths keep resolving with zero caller changes.

pub use respire_core_sdk::env;
pub use respire_core_sdk as core_sdk;

#[cfg(test)]
mod test_lock;

pub mod inject;
pub mod login_transaction;
pub mod migration;
pub mod session_import;

pub use respire_app_domain::auth;
pub use respire_app_domain::diary;
pub use respire_app_domain::embedding;
pub use respire_app_domain::feedback;
pub use respire_app_domain::input_error;
pub use respire_app_domain::keystore;
pub use respire_app_domain::lock;
pub use respire_app_domain::memory;
pub use respire_app_domain::metadata_gate;
pub use respire_app_domain::prompt;
pub use respire_app_domain::read_heat;
pub use respire_app_domain::recall_fusion;
pub use respire_app_domain::resident;
pub use respire_app_domain::review;
pub use respire_app_domain::review_approval;
pub use respire_app_domain::service;
pub use respire_app_domain::share;
pub use respire_app_domain::snapshot;
pub use respire_app_domain::sync;
pub use respire_app_domain::taxonomy;
pub use respire_app_domain::transport;

pub use memory::{hydrate_local, MemoryEngine, SessionKeys};
pub use memory::model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};
pub use transport::MemoryTransport;

/// Compatibility version exported for server health responses.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

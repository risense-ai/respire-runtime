#![forbid(unsafe_code)]

//! rsrs CLI library: command surface and CLI-only modules.
//! Domain logic lives in app-core; this crate re-exports it.
//!
//! Module map:
//! + re-export app-core: auth keystore prompt share sync transport lock taxonomy service inject memory
//! + hooks / inject_tui / model_install / space / update_check / classify / bench / web
//! + re-export the shared command surface: respire_commands (cli_def gates output output_state i18n
//!   metadata review autostart classify app_version util)
//! + main: CLI entry

pub use respire_app::auth;
pub use respire_app::core_sdk;
pub use respire_app::env;
pub use respire_app::feedback;
pub use respire_commands::app_version;
pub use respire_commands::autostart;
pub use respire_commands::classify;
pub use respire_commands::cli_def;
pub use respire_commands::gates;
pub use respire_commands::hooks;
pub use respire_commands::i18n;
pub use respire_commands::metadata;
pub use respire_commands::net_rpc;
pub use respire_commands::output;
pub use respire_commands::output_state;
pub use respire_commands::review;
pub use respire_commands::rpc_worker;
pub use respire_commands::runtime_error;
pub use respire_commands::runtime_policy;
pub use respire_commands::util;
pub mod extract_tui;
pub use respire_app::inject;
pub mod inject_tui;
pub use respire_app::session_import;
pub use respire_app::keystore;
pub use respire_app::lock;
pub use respire_app::migration;
pub mod memory;
pub use respire_commands::model_install;
pub use respire_commands::model_progress;
pub use respire_app::prompt;
pub use respire_app::service;
pub use respire_app::diary;
pub use respire_app::resident;
pub use respire_app::share;
pub mod space;
pub use respire_app::sync;
pub use respire_app::taxonomy;
pub use respire_app::transport;
pub mod update_check;

pub use memory::engine::{hydrate_local, MemoryEngine, SessionKeys};
pub use memory::model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};
pub use transport::MemoryTransport;

/// Version string (used by server /health).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

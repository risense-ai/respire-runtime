#![forbid(unsafe_code)]

//! rsrs CLI library: command surface and CLI-only modules.
//! Business execution stays behind Runtime RPC.
//!
//! Module map:
//! + host UI: prompt / inject / recall_fusion
//! + inject_tui / space / update_check and pure memory protocol types
//! + re-export the shared command surface: respire_commands (cli_def gates output output_state i18n
//!   metadata review autostart classify app_version)
//! + main: CLI entry

// Both binaries compile this same host implementation. Existing host modules
// retain their crate paths; no Runtime business implementation is linked here.
extern crate self as respire;

include!("frontend.rs");

pub mod embedding;
pub use embedding::{install_runtime_embedding, RuntimeEmbedding};

pub use respire_client_host::env;
pub use respire_commands::cli_def;
pub use respire_commands::gates;
pub use respire_commands::output_state;
pub use respire_commands::review;
pub mod extract_tui;
mod host_ui;
pub use host_ui::{inject, prompt, recall_fusion};
pub mod inject_tui;
pub use respire_client_host::lock;
pub mod memory;
pub mod space;
pub mod update_check;

pub use memory::model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};

/// Version string (used by server /health).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

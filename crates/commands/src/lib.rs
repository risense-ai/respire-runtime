#![forbid(unsafe_code)]

//! Shared rsrs command surface.
//!
//! This crate hosts the pieces that both the CLI binary and the standalone
//! runtime need verbatim: the clap definitions (`cli_def`), the write/read
//! gates (`gates`), the single-source output pipeline state (`output_state`)
//! and the machine-readable output contract (`output`).
//!
//! Boundaries:
//! - depends on `respire_app` (app-core), `respire_protocol` and
//!   `respire_spawn`, never on the `respire` CLI package;
//! - the CLI binary re-exports these modules so `crate::` paths keep working;
//! - the runtime server face (`rpc_serve`, `runtime_http`, `admission`,
//!   `network`) is shared with the standalone `rsrs-runtime` binary;
//! - host-only services reach the shared code through `host_hooks`.
//!
//! Modules land with the individual extraction commits of the runtime split.

pub mod admission;
pub mod app_version;
pub mod autostart;
pub mod bench;
pub mod classify;
pub mod cli_def;
pub mod engine;
pub mod gates;
pub mod hooks;
pub mod host_hooks;
pub mod i18n;
pub mod metadata;
pub mod model_install;
pub mod model_progress;
pub mod net_rpc;
pub mod network;
pub mod output;
pub mod output_emit;
pub mod output_state;
pub mod progress;
pub mod recall_select;
pub mod review;
pub mod rpc_serve;
pub mod rpc_worker;
pub mod runtime_error;
pub mod runtime_executor;
pub mod runtime_http;
pub mod runtime_mcp;
pub mod runtime_policy;
pub mod skill;
pub mod sync_flow;
pub mod util;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod legacy_host;

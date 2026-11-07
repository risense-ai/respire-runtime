#![forbid(unsafe_code)]

//! Shared rsrs command surface.
//!
//! This crate hosts the pieces that both the CLI binary and the standalone
//! runtime need verbatim: the clap definitions (`cli_def`), the write/read
//! gates (`gates`), the single-source output pipeline state (`output_state`)
//! and the machine-readable output contract (`output`).
//!
//! Boundaries:
//! - defaults expose parsing, output, client transport and pure DTO modules;
//! - explicit `server` enables app, transport and business implementations;
//! - server dependencies stay optional; frontend consumers must not enable `server`;
//! - the CLI binary re-exports these modules so `crate::` paths keep working;
//! - the runtime server face (`rpc_serve`, `runtime_http`, `admission`,
//!   `network`) is shared with the standalone `rsrs-runtime` binary;
//! - host-only services reach the shared code through `host_hooks`.
//!
//! Modules land with the individual extraction commits of the runtime split.

pub(crate) use respire_client_host::env;

#[cfg(not(feature = "server"))]
use respire_client_host::paths as client_paths;

#[cfg(feature = "server")]
pub mod admission;
pub mod app_version;
pub mod capabilities;
pub mod autostart;
#[cfg(feature = "server")]
pub mod bench;
pub mod capture;
pub mod classify;
pub mod cli_def;
#[cfg(feature = "server")]
pub mod engine;
pub mod gates;
pub mod hooks;
pub mod host_hooks;
pub mod i18n;
pub mod metadata;
pub mod model_asset_files;
pub mod model_download;
#[cfg(feature = "server")]
pub mod model_install;
pub mod model_progress;
pub mod net_rpc;
#[cfg(feature = "server")]
pub mod network;
pub mod output;
pub mod output_emit;
pub mod output_state;
pub mod progress;
#[cfg(feature = "server")]
pub mod recall_select;
pub mod review;
pub mod rpc_client;
#[cfg(feature = "server")]
pub mod rpc_serve;
#[cfg(feature = "server")]
pub mod rpc_worker;
pub mod runtime_error;
#[cfg(feature = "server")]
pub mod runtime_http;
pub mod runtime_policy;
#[cfg(feature = "server")]
pub mod skill;
#[cfg(feature = "server")]
pub mod sync_flow;
#[cfg(feature = "server")]
pub mod util;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

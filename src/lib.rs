#![forbid(unsafe_code)]

//! Shared rsrs command surface.
//!
//! This crate hosts the pieces that both the CLI binary and the standalone
//! runtime need verbatim: the clap definitions (`cli_def`), the write/read
//! gates (`gates`), the single-source output pipeline state (`output_state`)
//! and the machine-readable output contract (`output`).
//!
//! Boundaries:
//! - depends on `respire_app` (app-core), never on the `respire` CLI package;
//! - the CLI binary re-exports these modules so `crate::` paths keep working;
//! - the runtime engine migrates here in a later split step.
//!
//! Modules land with the individual extraction commits of the runtime split.

pub mod app_version;
pub mod autostart;
pub mod classify;
pub mod cli_def;
pub mod gates;
pub mod i18n;
pub mod metadata;
pub mod output;
pub mod output_state;
pub mod review;
pub mod util;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

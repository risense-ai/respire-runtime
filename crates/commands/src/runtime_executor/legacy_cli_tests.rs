//! Business assertions migrated from the CLI's removed in-process worker fixtures.

use anyhow::Result;
use clap::Parser;

use crate::cli_def::{Cli, Command};
use crate::engine::DIRECT_MODE;
use crate::output_state::{Captured, CAPTURED, OUTPUT_EMITTED, OUTPUT_EXIT_CODE};

#[path = "legacy_cli_tests/brief_coverage.rs"]
mod brief_coverage;
#[path = "legacy_cli_tests/business_coverage.rs"]
mod business_coverage;
#[path = "legacy_cli_tests/metadata_coverage.rs"]
mod metadata_coverage;
#[path = "legacy_cli_tests/review_coverage.rs"]
mod review_coverage;
#[path = "legacy_cli_tests/diary_identity.rs"]
mod diary_identity;

fn seed_capture_session() -> Result<()> {
    const TEST_SUPER: &str = "A3-000000-000000-000000-000000-000000-000000";
    std::env::set_var("RSRS_SUPER", TEST_SUPER);
    let salt = "01".repeat(16);
    let kek = respire_app::memory::crypto::derive_rsrs_kek(TEST_SUPER, &salt)?;
    let (nonce, wrapped) = respire_app::memory::crypto::wrap_key(&[7; 32], &kek)?;
    respire_app::auth::write_session_json(&serde_json::json!({
        "user":"test", "vault_version":4, "kdf_salt":salt,
        "wrapped_urk":format!("{}{wrapped}", respire_app::memory::crypto::RSRS_PREFIX),
        "urk_nonce":nonce, "pass":"synthetic-capture-unused"
    }))?;
    Ok(())
}

fn with_isolated_profile<T>(
    session: bool,
    test: impl FnOnce(&std::path::Path) -> Result<T>,
) -> Result<T> {
    let _lock = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let root = tempfile::tempdir()?;
    struct Restore {
        env: Vec<(&'static str, Option<std::ffi::OsString>)>,
        worker: bool,
        direct: bool,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // Also release catalog leases if a migrated assertion unwinds.
            let _ = respire_app::resident::clear();
            crate::rpc_worker::set_worker_active(self.worker);
            DIRECT_MODE.store(self.direct, std::sync::atomic::Ordering::Relaxed);
            for (key, value) in &self.env {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
    let _restore = Restore {
        env: [
            "RSRS_DATA_DIR",
            "RSRS_BIN_DIR",
            "RSRS_M3_DIR",
            "RSRS_SUPER",
            "RSRS_NO_AUTOSYNC",
            "RSRS_RPC_PORT",
            "RSRS_CORE_TEST_MODE",
            "RSRS_USER",
            "RSRS_CLIENT_ONLY",
            "RSRS_ADDR",
            "RSRS_TOKEN",
        ]
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect(),
        worker: crate::rpc_worker::worker_active(),
        direct: DIRECT_MODE.load(std::sync::atomic::Ordering::Relaxed),
    };
    std::env::set_var("RSRS_DATA_DIR", root.path());
    std::env::set_var("RSRS_BIN_DIR", root.path().join("bin"));
    std::env::set_var("RSRS_M3_DIR", root.path().join("absent-model"));
    std::env::set_var("RSRS_NO_AUTOSYNC", "1");
    std::env::set_var("RSRS_RPC_PORT", "29873");
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    std::env::set_var("RSRS_CLIENT_ONLY", "0");
    std::env::remove_var("RSRS_ADDR");
    std::env::remove_var("RSRS_TOKEN");
    crate::rpc_worker::mark_worker();
    if session {
        seed_capture_session()?;
    }
    let result = test(root.path());
    respire_app::resident::clear()?;
    result
}

fn with_isolated_session<T>(test: impl FnOnce(&std::path::Path) -> Result<T>) -> Result<T> {
    with_isolated_profile(true, test)
}

fn capture_run(args: Vec<String>) -> Captured {
    let parsed =
        Cli::try_parse_from(std::iter::once("rsrs".to_owned()).chain(args.iter().cloned()));
    // Preserve the old fixture's deferred model work, not a fake business executor.
    let _deferred = parsed
        .as_ref()
        .is_ok_and(|cli| {
            matches!(
                cli.command.as_ref(),
                Some(
                    Command::Remember { .. }
                        | Command::Update { .. }
                        | Command::Import { .. }
                        | Command::Attach { .. }
                        | Command::Restore { .. }
                )
            )
        })
        .then(respire_app::core_sdk::defer_indexing);
    let direct = DIRECT_MODE.load(std::sync::atomic::Ordering::Relaxed);
    let result = if let Ok(Cli {
        command: Some(Command::Metadata { ref command }),
        ..
    }) = parsed
    {
        if !matches!(command, crate::metadata::Command::Status) {
            CAPTURED.with(|slot| *slot.borrow_mut() = None);
            OUTPUT_EMITTED.set(false);
            OUTPUT_EXIT_CODE.set(0);
            crate::output_state::set_json_mode(true);
            // This tests the existing host-only helper and its worker refusal.
            // Public Runtime admission still rejects metadata configuration.
            super::finish_execution(crate::engine::run_metadata_host(command))
        } else {
            super::capture_run(args)
        }
    } else {
        super::capture_run(args)
    };
    DIRECT_MODE.store(direct, std::sync::atomic::Ordering::Relaxed);
    result
}

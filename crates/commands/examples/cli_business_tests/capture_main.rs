//! Main capture business regressions against the exact independently built CLI.
use super::support;
use respire_commands::output_state::Captured;

static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn capture_run(args: Vec<String>) -> anyhow::Result<Captured> {
    let output = std::process::Command::new(match support::legacy_cli()? { Some(binary) => binary, None => support::cli_bin()? })
        .args(args)
        .env_remove("RSRS_RUNTIME_BIN")
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()?;
    Ok(Captured {
        exit: output.status.code().ok_or_else(|| anyhow::anyhow!("CLI capture terminated without an exit code"))?,
        envelope: serde_json::from_slice(&output.stdout)?,
    })
}

fn seed_capture_session() -> anyhow::Result<()> {
    // Fixed fixture material only; never use this session or key in production.
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

pub(crate) fn with_isolated_session<T>(
    f: impl FnOnce(&std::path::Path) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _lock = TEST_ENV_LOCK
        .lock()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let dir = tempfile::tempdir()?;
    struct Restore {
        values: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            for (key, value) in &self.values {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
    let _restore = Restore {
        values: [
            "RSRS_DATA_DIR",
            "RSRS_BIN_DIR",
            "RSRS_M3_DIR",
            "RSRS_SUPER",
            "RSRS_NO_AUTOSYNC",
            "RSRS_RPC_PORT",
            "RSRS_CORE_TEST_MODE",
        ]
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect(),
    };
    let _guard = EnvGuard {
        prev: respire_app::env::var("RSRS_DATA_DIR").ok(),
        prev_super: std::env::var_os("RSRS_SUPER"),
    };
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
    std::env::set_var("RSRS_M3_DIR", dir.path().join("absent-model"));
    std::env::set_var("RSRS_NO_AUTOSYNC", "1");
    std::env::set_var("RSRS_RPC_PORT", "29873");
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    seed_capture_session()?;
    f(dir.path())
}

struct EnvGuard {
    prev: Option<String>,
    prev_super: Option<std::ffi::OsString>,
}

#[test]
fn memory_revision_without_runtime_fails_without_local_business_fallback() -> anyhow::Result<()> {
    with_isolated_session(|root| {
        let control = capture_run(vec!["memory-revision".into(), "--json".into()])?;
        assert_eq!(control.exit, 1);
        assert!(matches!(control.envelope.status, respire_commands::output::Status::Fail));
        if support::legacy_cli()?.is_some() {
            assert!(!control.envelope.errors.is_empty());
        } else {
            assert!(control.envelope.errors.iter().any(|error| {
                error.contains("host control requires an installed managed Runtime")
            }));
        }
        assert!(!root.join("runtime").exists());
        assert!(!root.join("rsrs.db").exists());
        assert!(!root.join("onememory.db").exists());
        support::legacy_receipt("capture_main::memory_revision_without_runtime_fails_without_local_business_fallback", "host_local")?;
        Ok(())
    })
}

#[test]
fn residual_host_and_parser_errors_remain_user_errors() -> anyhow::Result<()> {
    with_isolated_session(|root| {
        for args in [vec!["--json".into(), "space".into(), "kick".into()],
            vec!["--json".into(), "agent-config".into(), "--set".into(), "workspace_mode=bogus".into()]] {
            // The fixed old test ran inside its local worker. Its released CLI
            // exposes that local validation with --direct; ordinary calls auto-start.
            let mut args = args;
            if support::legacy_cli()?.is_some() { args.insert(0, "--direct".into()); }
            let failed = capture_run(args)?;
            assert_eq!(failed.exit, 2, "{:?}", failed.envelope);
            assert_eq!(failed.envelope.summary["reason"], "invalid_input");
            assert_eq!(failed.envelope.details["error_type"], "user");
        }
        assert!(!root.join("rsrs.db").exists());
        assert!(!root.join("onememory.db").exists());
        support::legacy_receipt("capture_main::residual_host_and_parser_errors_remain_user_errors", "host_local")?;
        Ok(())
    })
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        match &self.prev_super {
            Some(value) => std::env::set_var("RSRS_SUPER", value),
            None => std::env::remove_var("RSRS_SUPER"),
        }
    }
}

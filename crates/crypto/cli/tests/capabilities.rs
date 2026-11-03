//! Static feature discovery must not touch a vault, model, runtime or network.
use serde_json::Value;
use std::process::Command;

#[test]
fn capabilities_is_typed_and_does_not_initialize_any_profile() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    for flags in [vec!["--json", "capabilities"],
        vec!["--client-only", "--json", "capabilities"],
        vec!["--direct", "--json", "capabilities"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
            .args(flags)
            .env("HOME", root.path().join("absent-home"))
            .env("USERPROFILE", root.path().join("absent-home"))
            .env("RSRS_DATA_DIR", root.path().join("absent-profile"))
            .env("RSRS_M3_DIR", root.path().join("absent-model"))
            .env("RSRS_RPC_PORT", "1")
            .env("RSRS_MIRROR", "http://127.0.0.1:1")
            .env("RSRS_MEMORY_OFF", "1")
            .output()?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.stderr.is_empty());
        let result: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["command"], "capabilities");
        assert_eq!(result["status"], "ok");
        assert_eq!(result["summary"]["schema_version"], 1);
        assert!(result["summary"]["cli_version"].is_string());
        assert_eq!(result["summary"]["capabilities"], serde_json::json!({
            "rerank":false, "model":{"install":true,"install_rerank":false,"profile_contract":1,"transport_contract":1,"methods":["model.catalog","model.configure","model.switch","model.resume","model.progress"],"selection_scope":"library"},
            "host_rpc":{"version":1,"transport":"stdio","flag":"--host-rpc-stdio",
                "methods":["auth.register","auth.login","auth.recover","auth.reset"]},
            "memory_list_metadata":true,
            "memory_metadata_flags":true,
            "memory_metadata_gate_default":false}));
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn login_help_explains_recovery_without_reviving_destructive_flags() -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
        .args(["login", "--help"]).output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for message in ["super-reset", "cannot recover a lost data key", "keygen --force", "not cloud recovery"] {
        assert!(help.contains(message), "missing recovery guidance: {message}");
    }
    for flag in ["--reset-vault", "--secret-key"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
            .args(["--json", "login", flag, "synthetic"]).output()?;
        assert_eq!(output.status.code(), Some(2));
        let result: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["summary"]["reason"], "invalid_input");
        assert!(!result["errors"][0].as_str().unwrap_or("").contains('\n'));
    }
    Ok(())
}

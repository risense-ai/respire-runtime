//! Hidden runtime help must be usable before host/profile setup, including in a sandbox.
use serde_json::Value;
use std::process::Command;

#[test]
fn runtime_help_is_static_without_a_profile_or_lifecycle_action() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    for flags in [vec!["--runtime-internal", "--help"],
        vec!["--client-only", "--runtime-internal", "-h"],
        vec!["--json", "--runtime-internal", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
            .args(&flags)
            .env("HOME", root.path().join("absent-home"))
            .env("USERPROFILE", root.path().join("absent-home"))
            .env("RSRS_DATA_DIR", root.path().join("absent-profile"))
            .env("RSRS_M3_DIR", root.path().join("absent-model"))
            .env("RSRS_RPC_PORT", "1")
            .env_remove("RSRS_JSON")
            .output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = if flags.contains(&"--json") {
            let v: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(v["command"], "runtime-help");
            assert_eq!(v["status"], "ok");
            assert_eq!(v["summary"]["lifecycle"], "host-managed");
            v["summary"]["usage"].as_str().unwrap_or("").to_owned()
        } else { String::from_utf8(output.stdout)? };
        for flag in ["--status", "--stop", "--port", "--host", "--no-open"] {
            assert!(text.contains(flag), "missing {flag}");
        }
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn help_cannot_swallow_a_stop_or_unknown_argument() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    for extra in ["--stop", "--unknown-flag"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
            .args(["--client-only", "--json", "--runtime-internal", "--help", extra])
            .env("RSRS_DATA_DIR", root.path().join("absent-profile"))
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        let v: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(v["status"], "fail");
        assert_eq!(v["summary"]["reason"], "invalid_input");
        assert!(!root.path().join("absent-profile").exists());
    }
    Ok(())
}

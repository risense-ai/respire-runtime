//! Revision probes use synthetic profiles only, without keys or model installation.
use std::path::Path;
use std::process::{Command, Output};

use respire_app::transport::local::LocalStore;
use serde_json::Value;

use super::support;
use support::install_runtime_fixture;

fn run(root: &Path, args: &[&str]) -> std::io::Result<Output> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    Command::new(match support::legacy_cli().map_err(std::io::Error::other)? { Some(binary) => binary, None => support::cli_bin()? })
        .args(args)
        .env("HOME", root.join("unused-home"))
        .env("RSRS_DATA_DIR", root)
        .env("RSRS_BIN_DIR", root.join("bin"))
        .env("RSRS_MODEL_DIR", root.join("missing-model"))
        .env("RSRS_JSON", "1")
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART")
        .env_remove("RSRS_RPC_TOKEN")
        .env_remove("RSRS_RUNTIME_BIN")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()
}

fn summary(output: Output) -> Result<Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(envelope["command"], "memory-revision");
    assert_eq!(envelope["status"], "ok");
    assert!(envelope["details"].is_null());
    let value = envelope["summary"].clone();
    assert_eq!(value["revision"].as_str().unwrap_or("").len(), 32);
    Ok(value)
}

#[test]
fn memory_revision_direct_is_model_free_and_follows_resolved_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    drop(LocalStore::open(&root.join("rsrs.db"))?);
    install_runtime_fixture(root)?;
    let initial = summary(run(root, &["--direct", "memory-revision", "--json"])?)?;
    assert_eq!(initial["profile"], root.to_string_lossy().as_ref());
    // RSRS_JSON=1 is exactly the same wire contract as the explicit flag.
    assert_eq!(
        summary(run(root, &["--direct", "memory-revision"])?)?,
        initial
    );
    if support::legacy_cli()?.is_some() {
        // In 1.0.20 only explicit direct reads are local. Ordinary reads require
        // an existing owner; this is its original contract, not a new fallback.
        let ordinary = run(root, &["memory-revision", "--json"])?;
        assert!(!ordinary.status.success());
        let failure: Value = serde_json::from_slice(&ordinary.stdout)?;
        assert_eq!(failure["status"], "fail");
        assert_eq!(summary(run(root, &["--direct", "memory-revision"])?)?, initial);
    } else {
    assert_eq!(
        summary(run(root, &["memory-revision", "--json"])?)?,
        initial
    );
    }
    let profile = root.join("accounts").join("work");
    drop(LocalStore::open(&profile.join("rsrs.db"))?);
    std::fs::write(
        root.join("client.json"),
        serde_json::to_vec(&serde_json::json!({
            "data_dir": profile.to_string_lossy()
        }))?,
    )?;
    let other = summary(run(root, &["--direct", "memory-revision"])?)?;
    assert_eq!(other["profile"], profile.to_string_lossy().as_ref());
    assert_ne!(other["revision"], initial["revision"]);
    assert_eq!(
        summary(run(root, &["--direct", "memory-revision"])?)?,
        other
    );
    std::fs::write(root.join("client.json"), "{}")?;
    assert_eq!(
        summary(run(root, &["--direct", "memory-revision"])?)?,
        initial
    );
    assert!(!root.join("runtime/endpoint.json").exists());
    assert!(!root.join("runtime/autostart").exists());
    assert!(!root.join("lock.db").exists());
    assert!(!root.join("missing-model").exists());
    assert!(!root.join("unused-home").exists());
    support::legacy_receipt("memory_revision::memory_revision_direct_is_model_free_and_follows_resolved_profile", "old_embedded")?;
    Ok(())
}

#[test]
fn memory_revision_does_not_initialize_or_autostart() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("absent-profile");
    let direct = run(&root, &["--direct", "memory-revision"])?;
    assert!(!direct.status.success());
    let envelope: Value = serde_json::from_slice(&direct.stdout)?;
    assert_eq!(envelope["status"], "fail");
    assert!(!root.exists());
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let ordinary = Command::new(match support::legacy_cli()? { Some(binary) => binary, None => support::cli_bin()? })
        .args(["memory-revision", "--json"])
        .env("HOME", dir.path().join("unused-home"))
        .env("RSRS_DATA_DIR", &root)
        .env("RSRS_BIN_DIR", root.join("bin"))
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN")
        .output()?;
    assert!(!ordinary.status.success());
    let envelope: Value = serde_json::from_slice(&ordinary.stdout)?;
    assert_eq!(envelope["status"], "fail");
    assert!(!root.exists());
    assert!(!dir.path().join("unused-home").exists());

    std::fs::create_dir(&root)?;
    drop(LocalStore::open(&root.join("rsrs.db"))?);
    let database = std::fs::read(root.join("rsrs.db"))?;
    let journal = root.join(".login-recovery.json");
    let marker = b"synthetic interrupted login must remain untouched";
    std::fs::write(&journal, marker)?;
    for args in [
        vec!["--direct", "memory-revision", "--json"],
        vec!["memory-revision", "--json"],
    ] {
        let result = run(&root, &args)?;
        if support::legacy_cli()?.is_some() {
            if args.contains(&"--direct") {
                // Stable reads the existing revision before login recovery dispatch.
                let revision = summary(result)?;
                assert_eq!(revision["profile"], root.to_string_lossy().as_ref());
            } else {
                assert_eq!(result.status.code(), Some(1));
                let envelope: Value = serde_json::from_slice(&result.stdout)?;
                assert_eq!(envelope["status"], "fail");
                assert!(envelope["errors"].to_string()
                    .contains("runtime_unavailable: host HTTP runtime is not running"));
            }
        } else {
            assert_eq!(result.status.code(), Some(1));
            let envelope: Value = serde_json::from_slice(&result.stdout)?;
            assert_eq!(envelope["command"], "cli");
            assert_eq!(envelope["status"], "fail");
            assert!(envelope["errors"]
                .to_string()
                .contains("host control requires an installed managed Runtime"));
        }
        assert_eq!(std::fs::read(root.join("rsrs.db"))?, database);
        assert_eq!(std::fs::read(&journal)?, marker);
        assert!(!root.join("runtime").exists());
        assert!(!root.join("lock.db").exists());
        assert!(!root.join("session.json").exists());
    }
    support::legacy_receipt("memory_revision::memory_revision_does_not_initialize_or_autostart", "old_embedded")?;
    Ok(())
}

#[test]
fn memory_revision_direct_respects_client_only_policy() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    let result = run(
        dir.path(),
        &["--client-only", "--direct", "memory-revision"],
    )?;
    assert!(!result.status.success());
    let envelope: Value = serde_json::from_slice(&result.stdout)?;
    assert!(envelope["errors"].to_string().contains("client_only"));
    let remote = run(dir.path(), &["--client-only", "memory-revision", "--json"])?;
    assert!(!remote.status.success());
    let envelope: Value = serde_json::from_slice(&remote.stdout)?;
    let errors = envelope["errors"].to_string();
    assert!(!errors.contains("client_only:"));
    assert!(!errors.contains("host control requires an installed managed Runtime"));
    assert!(!dir.path().join("runtime").exists());
    support::legacy_receipt("memory_revision::memory_revision_direct_respects_client_only_policy", "old_embedded")?;
    Ok(())
}

#[test]
fn memory_revision_legacy_database_and_ambiguous_names() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("onememory.db"))?);
    install_runtime_fixture(dir.path())?;
    let legacy = summary(run(dir.path(), &["--direct", "memory-revision"])?)?;
    assert_eq!(legacy["profile"], dir.path().to_string_lossy().as_ref());
    assert!(!dir.path().join("rsrs.db").exists());
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    let result = run(dir.path(), &["--direct", "memory-revision"])?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("both rsrs.db"));
    support::legacy_receipt("memory_revision::memory_revision_legacy_database_and_ambiguous_names", "old_embedded")?;
    Ok(())
}

#[test]
fn memory_revision_does_not_recover_interrupted_login() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    install_runtime_fixture(dir.path())?;
    let journal = dir.path().join(".login-recovery.json");
    let marker = b"synthetic invalid journal must remain untouched";
    std::fs::write(&journal, marker)?;
    summary(run(dir.path(), &["--direct", "memory-revision"])?)?;
    assert_eq!(std::fs::read(&journal)?, marker);
    assert!(!dir.path().join("session.json").exists());
    assert!(!dir.path().join("runtime/endpoint.json").exists());
    assert!(!dir.path().join("runtime/autostart").exists());
    support::legacy_receipt("memory_revision::memory_revision_does_not_recover_interrupted_login", "old_embedded")?;
    Ok(())
}

#[test]
fn memory_revision_preserves_legacy_environment_alias() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("onememory.db"))?);
    install_runtime_fixture(dir.path())?;
    let output = Command::new(match support::legacy_cli()? { Some(binary) => binary, None => support::cli_bin()? })
        .args(["--direct", "memory-revision", "--json"])
        .env("HOME", dir.path().join("unused-home"))
        .env_remove("RSRS_DATA_DIR")
        .env_remove("RESPIRE_DATA_DIR")
        .env("ONEMEMORY_DATA_DIR", dir.path())
        .env("RSRS_BIN_DIR", dir.path().join("bin"))
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("ONEMEMORY_CLIENT_ONLY")
        .env_remove("RESPIRE_CLIENT_ONLY")
        .env_remove("RSRS_RUNTIME_BIN")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()?;
    let value = summary(output)?;
    assert_eq!(value["profile"], dir.path().to_string_lossy().as_ref());
    assert!(!dir.path().join("rsrs.db").exists());
    support::legacy_receipt("memory_revision::memory_revision_preserves_legacy_environment_alias", "old_embedded")?;
    Ok(())
}

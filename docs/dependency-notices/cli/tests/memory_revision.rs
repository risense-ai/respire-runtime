//! Revision probes use synthetic profiles only, without keys or model installation.
use std::path::Path;
use std::process::{Command, Output};

use respire::transport::local::LocalStore;
use serde_json::Value;

fn run(root: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_rsrs"))
        .args(args)
        .env("HOME", root.join("unused-home"))
        .env("RSRS_DATA_DIR", root)
        .env("RSRS_MODEL_DIR", root.join("missing-model"))
        .env("RSRS_JSON", "1")
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART")
        .env_remove("RSRS_RPC_TOKEN")
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
    let initial = summary(run(root, &["--direct", "memory-revision", "--json"])?)?;
    assert_eq!(initial["profile"], root.to_string_lossy().as_ref());
    // RSRS_JSON=1 is exactly the same wire contract as the explicit flag.
    assert_eq!(
        summary(run(root, &["--direct", "memory-revision"])?)?,
        initial
    );
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
    assert!(!root.join("runtime").exists());
    assert!(!root.join("lock.db").exists());
    assert!(!root.join("missing-model").exists());
    assert!(!root.join("unused-home").exists());
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
    let ordinary = Command::new(env!("CARGO_BIN_EXE_rsrs"))
        .args(["memory-revision", "--json"])
        .env("HOME", dir.path().join("unused-home"))
        .env("RSRS_DATA_DIR", &root)
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN")
        .output()?;
    assert!(!ordinary.status.success());
    let envelope: Value = serde_json::from_slice(&ordinary.stdout)?;
    assert_eq!(envelope["status"], "fail");
    assert!(!root.exists());
    assert!(!dir.path().join("unused-home").exists());
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
    Ok(())
}

#[test]
fn memory_revision_legacy_database_and_ambiguous_names() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("onememory.db"))?);
    let legacy = summary(run(dir.path(), &["--direct", "memory-revision"])?)?;
    assert_eq!(legacy["profile"], dir.path().to_string_lossy().as_ref());
    assert!(!dir.path().join("rsrs.db").exists());
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    let result = run(dir.path(), &["--direct", "memory-revision"])?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("both rsrs.db"));
    Ok(())
}

#[test]
fn memory_revision_does_not_recover_interrupted_login() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    let journal = dir.path().join(".login-recovery.json");
    let marker = b"synthetic invalid journal must remain untouched";
    std::fs::write(&journal, marker)?;
    summary(run(dir.path(), &["--direct", "memory-revision"])?)?;
    assert_eq!(std::fs::read(&journal)?, marker);
    assert!(!dir.path().join("session.json").exists());
    assert!(!dir.path().join("runtime").exists());
    Ok(())
}

#[test]
fn memory_revision_preserves_legacy_environment_alias() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("onememory.db"))?);
    let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
        .args(["--direct", "memory-revision", "--json"])
        .env("HOME", dir.path().join("unused-home"))
        .env_remove("RSRS_DATA_DIR")
        .env_remove("RESPIRE_DATA_DIR")
        .env("ONEMEMORY_DATA_DIR", dir.path())
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("ONEMEMORY_CLIENT_ONLY")
        .env_remove("RESPIRE_CLIENT_ONLY")
        .output()?;
    let value = summary(output)?;
    assert_eq!(value["profile"], dir.path().to_string_lossy().as_ref());
    assert!(!dir.path().join("rsrs.db").exists());
    Ok(())
}

//! Exercise the actual shipped subprocess boundary, not a duplicated adapter.
//! Registration is confined by the Python harness to ephemeral hosted runners;
//! other environments still exercise fresh-profile foreground start and stop.
#[test]
fn native_foreground_and_opt_in_user_supervision() -> Result<(), Box<dyn std::error::Error>> {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace parent missing")?
        .join("scripts/test-runtime-autostart.py");
    let mut command = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" });
    command
        .args(["-I", "-B"])
        .arg(script)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_rsrs"));
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
    {
        command.arg("--register");
    }
    let status = command.status()?;
    assert!(
        status.success(),
        "actual native user runtime acceptance failed: {status}"
    );
    Ok(())
}

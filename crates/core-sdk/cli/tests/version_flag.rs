//! Embedded version: `--version`, `-v`, and `v`.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

fn run(args: &[&str]) -> Result<(i32, String), String> {
    let output = Command::new(bin())
        .args(args)
        .output()
        .map_err(|err| err.to_string())?;
    let code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        return Err(format!(
            "exit {code} stdout {stdout} stderr {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok((code, stdout))
}

#[test]
fn long_flag_prints_embedded_version() -> Result<(), String> {
    let (_code, stdout) = run(&["--version"])?;
    let version = env!("CARGO_PKG_VERSION");
    if !stdout.contains(version) {
        return Err(format!("--version stdout {stdout} missing {version}"));
    }
    Ok(())
}

#[test]
fn short_v_prints_embedded_version() -> Result<(), String> {
    let (_code, stdout) = run(&["-v"])?;
    let version = env!("CARGO_PKG_VERSION");
    if !stdout.contains(version) {
        return Err(format!("-v stdout {stdout} missing {version}"));
    }
    Ok(())
}

#[test]
fn subcommand_v_prints_embedded_version() -> Result<(), String> {
    let (_code, stdout) = run(&["v"])?;
    let version = env!("CARGO_PKG_VERSION");
    if !stdout.contains(version) || !stdout.contains("rsrs") {
        return Err(format!("v stdout {stdout} missing version"));
    }
    Ok(())
}

#[test]
fn subcommand_v_json_has_command_version() -> Result<(), String> {
    let (_code, stdout) = run(&["--json", "v"])?;
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|err| err.to_string())?;
    if value["command"] != "version" {
        return Err(format!("json {value}"));
    }
    if value["summary"]["version"] != env!("CARGO_PKG_VERSION") {
        return Err(format!("summary {value}"));
    }
    Ok(())
}

//! Stdio MCP protocol smoke: initialize, tools/list, ping. Does not write memories.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

#[test]
fn stdio_initialize_lists_default_safe_tools() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let mut child = Command::new(bin())
        .arg("mcp")
        .env("RSRS_DATA_DIR", dir.path())
        .env("RSRS_BIN_DIR", &bin_dir)
        .env_remove("RSRS_LANG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child.stdin.as_mut().ok_or("stdin")?;
        stdin.write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"ping"}
"#,
        )?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "mcp exit {:?} stderr {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    let mut saw_init = false;
    let mut saw_list = false;
    let mut saw_ping = false;
    let mut names = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)?;
        match value["id"].as_u64() {
            Some(1) => {
                saw_init = value["result"]["protocolVersion"] == "2025-03-26";
            }
            Some(2) => {
                saw_list = true;
                if let Some(tools) = value["result"]["tools"].as_array() {
                    names = tools
                        .iter()
                        .filter_map(|tool| tool["name"].as_str().map(ToOwned::to_owned))
                        .collect();
                }
            }
            Some(3) => saw_ping = value.get("result").is_some(),
            _ => {}
        }
    }
    if !saw_init {
        return Err(format!("initialize missing in {stdout}").into());
    }
    if !saw_ping {
        return Err("ping missing".into());
    }
    if !saw_list {
        return Err("tools/list missing".into());
    }
    for want in [
        "memory_status",
        "memory_remember",
        "memory_recall",
        "memory_list",
        "memory_show",
        "memory_update",
        "memory_attach",
        "memory_tree",
        "memory_history",
        "memory_diary",
        "memory_diary_search",
        "memory_diary_fragment",
        "memory_chain",
        "memory_query_log_mark",
        "memory_taxonomy",
    ] {
        if !names.iter().any(|name| name == want) {
            return Err(format!("missing tool {want} in {names:?}").into());
        }
    }
    assert_eq!(names.len(), 16);
    assert!(!names
        .iter()
        .any(|name| matches!(name.as_str(), "memory_forget" | "memory_restore")));
    let _ = Duration::from_millis(1);
    Ok(())
}

fn policy_child(
    settings: &[(&str, &std::ffi::OsStr)],
    input: &str,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut command = Command::new(bin());
    command
        .arg("--json")
        .arg("mcp")
        .env("RSRS_DATA_DIR", dir.path())
        .env("RSRS_BIN_DIR", dir.path().join("bin"));
    for prefix in ["RSRS", "ONEMEMORY", "RESPIRE"] {
        for suffix in ["MCP_ALLOW", "MCP_DENY", "MCP_ALLOW_TOOLS", "MCP_DENY_TOOLS"] {
            command.env_remove(format!("{prefix}_{suffix}"));
        }
    }
    for (key, value) in settings {
        command.env(key, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin")?
        .write_all(input.as_bytes())?;
    Ok(child.wait_with_output()?)
}

#[test]
fn stdio_policy_restart_compatibility_and_forced_calls() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::OsStr;
    let input=concat!("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"memory_forget\",\"arguments\":{\"id\":\"synthetic\"}}}\n");
    for settings in [
        vec![],
        vec![("RSRS_MCP_DENY_TOOLS", OsStr::new("memory_forget"))],
    ] {
        let output = policy_child(&settings, input)?;
        assert!(output.status.success());
        let frames: Vec<serde_json::Value> = String::from_utf8(output.stdout)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(frames[1]["result"]["isError"], true);
        assert!(frames[1]["result"]["content"][0]["text"]
            .as_str()
            .ok_or("text")?
            .contains("disabled"));
    }
    for key in [
        "RSRS_MCP_ALLOW",
        "ONEMEMORY_MCP_ALLOW",
        "RESPIRE_MCP_ALLOW",
        "RSRS_MCP_ALLOW_TOOLS",
        "ONEMEMORY_MCP_ALLOW_TOOLS",
        "RESPIRE_MCP_ALLOW_TOOLS",
    ] {
        let output = policy_child(
            &[(key, OsStr::new("memory_restore"))],
            &format!("{}\n", input.lines().next().ok_or("input")?),
        )?;
        assert!(output.status.success());
        let frame: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(frame["result"]["tools"].as_array().ok_or("tools")?.len(), 1);
        assert_eq!(frame["result"]["tools"][0]["name"], "memory_restore");
    }
    for value in ["", "unknown", "memory_status,"] {
        let output = policy_child(
            &[
                ("RSRS_MCP_ALLOW_TOOLS", OsStr::new(value)),
                ("ONEMEMORY_MCP_ALLOW_TOOLS", OsStr::new("memory_status")),
            ],
            input,
        )?;
        assert!(!output.status.success());
        let text = String::from_utf8(output.stdout)?;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let error: serde_json::Value = serde_json::from_str(line)?;
            assert!(
                error.get("jsonrpc").is_none(),
                "invalid config served RPC: {error}"
            );
            assert_eq!(error["status"], "fail");
        }
    }
    Ok(())
}

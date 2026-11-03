//! Settings persistence through real CLI processes, using only a fresh profile.
use anyhow::{Context, Result};
use serde_json::Value;
use std::process::{Command, Output};

#[test]
fn model_weights_persist_read_back_and_drive_the_next_load() -> Result<()> {
    let profile = tempfile::tempdir()?;
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
    let run = |args: &[&str]| -> Result<Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rsrs"));
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| ["RSRS_", "RESPIRE_", "ONEMEMORY_"]
                .iter().any(|prefix| name.starts_with(prefix))) {
                command.env_remove(name);
            }
        }
        command.args(["--json", "--direct"]).args(args).current_dir(profile.path())
            .env("HOME", profile.path()).env("USERPROFILE", profile.path())
            .env("XDG_CONFIG_HOME", profile.path().join("config"))
            .env("XDG_DATA_HOME", profile.path().join("share"))
            .env("RSRS_DATA_DIR", profile.path().join("data"))
            .env("RSRS_M3_DIR", profile.path().join("models"))
            .env("RSRS_RPC_PORT", port.to_string()).env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0").env("RSRS_LANG", "en")
            .env("RSRS_MIRROR", "http://127.0.0.1:9")
            .env("RSRS_CPU_ORT_MIRROR", "http://127.0.0.1:9");
        Ok(command.output()?)
    };
    for variant in respire::memory::onnx::MODEL_VARIANTS {
        let saved = run(&["model", "engine", "cpu", "--model", variant.name])?;
        anyhow::ensure!(saved.status.success(), "{}", String::from_utf8_lossy(&saved.stderr));
        // A new process must use the saved variant, including after an engine-only change.
        anyhow::ensure!(run(&["model", "engine", "cpu"])?.status.success());
        let read = run(&["model", "engine"])?;
        anyhow::ensure!(read.status.success(), "{}", String::from_utf8_lossy(&read.stderr));
        let value: Value = serde_json::from_slice(&read.stdout)?;
        assert_eq!(value["summary"]["model"], variant.name);
        assert_eq!(value["summary"]["variants"].as_array().context("inventory missing")?.len(),
            respire::memory::onnx::MODEL_VARIANTS.len());
    }
    let settings = profile.path().join("data/inference.json");
    let before = std::fs::read(&settings)?;
    assert!(!run(&["model", "engine", "cpu", "--model", "invalid"])?.status.success());
    assert_eq!(std::fs::read(&settings)?, before);
    std::fs::write(&settings, br#"{"engine":"cpu","model":"obsolete"}"#)?;
    anyhow::ensure!(run(&["model", "engine", "cpu", "--model", "q4f16"])?.status.success());
    assert_eq!(std::fs::read(&settings)?, before);
    assert!(!profile.path().join("models").exists(), "settings must not download models");
    // Validated loading never saves an unavailable draft or fetches dependencies.
    let failed_load = run(&["model", "load", "cpu", "--model", "fp16"])?;
    assert!(!failed_load.status.success());
    assert_eq!(std::fs::read(&settings)?, before);
    assert!(!profile.path().join("models").exists());
    assert!(!run(&["model", "install", "--model", "invalid", "--for-engine", "cpu"])?.status.success());
    assert!(!profile.path().join("models").exists(), "invalid download request must fail before fetching baseline");

    // Tiny baseline fixtures permit directory resolution, but no valid weights
    // are present and no model bytes can be executed.
    let models = profile.path().join("models");
    std::fs::create_dir_all(models.join("onnx"))?;
    std::fs::write(models.join("tokenizer.json"), b"{}")?;
    std::fs::write(models.join("onnx/model_quantized.onnx"), b"invalid synthetic weights")?;
    // Missing weights must fail without silently loading the quantized default.
    let probe = run(&["model", "probe", "--model", "m3"])?;
    assert!(!probe.status.success());
    let diagnostic = format!("{}{}", String::from_utf8_lossy(&probe.stdout), String::from_utf8_lossy(&probe.stderr));
    assert!(diagnostic.contains("q4f16"), "{diagnostic}");
    assert_eq!(std::fs::read(settings)?, before);
    assert!(!models.join("onnx/model_q4f16.onnx").exists());
    Ok(())
}

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) fn cli_bin() -> std::io::Result<PathBuf> {
    let raw = std::env::var_os("RSRS_CLI_BIN").ok_or_else(|| {
        std::io::Error::other("supply RSRS_CLI_BIN with the exact source-bound CLI executable")
    })?;
    let binary = PathBuf::from(raw).canonicalize()?;
    if !binary.is_file() {
        return Err(std::io::Error::other("RSRS_CLI_BIN is not a file"));
    }
    Ok(binary)
}

pub(super) fn runtime_bin() -> std::io::Result<PathBuf> {
    let raw = std::env::var_os("RSRS_RUNTIME_BIN").ok_or_else(|| {
        std::io::Error::other("supply RSRS_RUNTIME_BIN with a verified standalone Runtime fixture")
    })?;
    let binary = PathBuf::from(raw).canonicalize()?;
    if !binary.is_file() || binary == cli_bin()? {
        return Err(std::io::Error::other("CLI shim cannot substitute for the Runtime fixture"));
    }
    Ok(binary)
}

pub(super) fn cli_source() -> anyhow::Result<PathBuf> {
    let source = PathBuf::from(std::env::var_os("RSRS_CLI_SOURCE_DIR")
        .context("supply the exact CLI source checkout used to build RSRS_CLI_BIN")?)
        .canonicalize()?;
    let expected = std::env::var("RSRS_CLI_SOURCE_SHA")
        .context("supply the exact CLI source SHA")?;
    anyhow::ensure!(expected.len() == 40 && expected.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid CLI source SHA");
    // The native workflow verifies both checkout HEADs before it builds either side.
    anyhow::ensure!(source.join("runtime-pin.json").is_file(), "CLI source pin is missing");
    Ok(source)
}

// Candidate mode is test-only and opt-in. It accepts the unmodified receipt from
// the real offline installer, never a replacement official pin or release claim.
fn candidate_version(selected: &Value, pinned: &str, binary: &Path) -> anyhow::Result<String> {
    let path = std::env::var_os("RSRS_RUNTIME_CANDIDATE_METADATA")
        .context("candidate metadata path missing")?;
    let raw = std::fs::read_to_string(path)?;
    let metadata: Value = serde_json::from_str(&raw)?;
    let source = std::env::var("RSRS_RUNTIME_SOURCE_SHA")?;
    anyhow::ensure!(source.len() == 40 && source.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid Runtime source SHA");
    let version = metadata["runtime_version"].as_str().context("candidate version missing")?;
    anyhow::ensure!(version != pinned && metadata["schema_version"] == 2
        && metadata["candidate"]["kind"] == "unpublished-source-fixture"
        && metadata["source_commit"] == source
        && metadata["candidate"]["cli_source_sha"] == std::env::var("RSRS_CLI_SOURCE_SHA")?
        && metadata["candidate"]["cli_binary_sha256"]
            == format!("{:x}", Sha256::digest(std::fs::read(cli_bin()?)?))
        && selected["version"] == version
        && selected["release"]["metadata_json"] == raw
        && selected["release"]["metadata_sha256"] == format!("{:x}", Sha256::digest(raw.as_bytes()))
        && selected["sha256"] == metadata["binary_sha256"]
        && selected["sha256"] == format!("{:x}", Sha256::digest(std::fs::read(binary)?)),
        "candidate fixture identity differs from its source-bound offline installation");
    Ok(version.to_owned())
}

// Copy the installer receipt and inventory verbatim. Product trust validation
// still runs against the copied installation; no selection receipt is fabricated.
pub(super) fn install_runtime_fixture(root: &Path) -> anyhow::Result<()> {
    let binary = runtime_bin()?;
    let version_dir = binary.parent().context("Runtime fixture version directory missing")?;
    let source_root = version_dir.parent().and_then(Path::parent)
        .context("Runtime fixture installation root missing")?;
    let receipt = source_root.join("runtime.json");
    let selected: Value = serde_json::from_slice(&std::fs::read(&receipt)?)?;
    let pin: Value = serde_json::from_slice(&std::fs::read(cli_source()?.join("runtime-pin.json"))?)?;
    let pinned = pin["required"].as_str().context("Runtime pin required missing")?;
    let version = if std::env::var_os("RSRS_RUNTIME_CANDIDATE_METADATA").is_some() {
        candidate_version(&selected, pinned, &binary)?
    } else {
        pinned.to_owned()
    };
    anyhow::ensure!(selected["version"] == version
        && selected["release"]["metadata_json"].is_string()
        && source_root.join("runtime").join(&version) == version_dir,
        "Runtime fixture must be a verified managed installation");
    let mut pending = vec![(version_dir.to_path_buf(), root.join("runtime").join(&version))];
    while let Some((source, target)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&source)?;
        anyhow::ensure!(!metadata.file_type().is_symlink(), "Runtime fixture contains a link");
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(metadata.file_attributes() & 0x400 == 0,
                "Runtime fixture contains a reparse point");
        }
        if metadata.is_dir() {
            std::fs::create_dir_all(&target)?;
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                pending.push((entry.path(), target.join(entry.file_name())));
            }
        } else {
            anyhow::ensure!(metadata.is_file(), "Runtime fixture contains a non-file");
            std::fs::copy(source, target)?;
        }
    }
    anyhow::ensure!(std::fs::symlink_metadata(&receipt)?.is_file(), "Runtime fixture receipt missing");
    std::fs::copy(receipt, root.join("runtime.json"))?;
    stage_cli_fixture(&root.join("bin"))
}

// Completed maintenance hands the serving owner back to the default compatibility
// host. Its stable CLI must contain the same bytes as the current test sender.
pub(super) fn stage_cli_fixture(bin_directory: &Path) -> anyhow::Result<()> {
    let source = cli_bin()?;
    std::fs::create_dir_all(bin_directory)?;
    let destination = bin_directory.join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" });
    std::fs::copy(&source, &destination)?;
    anyhow::ensure!(std::fs::read(&destination)? == std::fs::read(&source)?,
        "stable CLI fixture differs from the tested binary");
    Ok(())
}

// Only the second, separately reported stable-contract pass selects this binary.
// The manager/source/installer identity above remains the current CLI throughout.
pub(super) fn legacy_cli() -> anyhow::Result<Option<PathBuf>> {
    match std::env::var("RSRS_TEST_LEGACY_STABLE_CONTRACTS") {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Ok(mode) if mode == "stable-contracts-v1" => {
            let binary = PathBuf::from(std::env::var_os("RSRS_TEST_STABLE_CLI_BIN")
                .context("verified stable contract binary missing")?).canonicalize()?;
            anyhow::ensure!(binary.is_file() && binary != cli_bin()? && binary != runtime_bin()?,
                "stable contract binary must be separate from the manager and Runtime");
            Ok(Some(binary))
        }
        _ => anyhow::bail!("invalid stable contract pass"),
    }
}

pub(super) fn legacy_receipt(case: &str, execution: &str) -> anyhow::Result<()> {
    if legacy_cli()?.is_some() {
        anyhow::ensure!(matches!(execution, "candidate_runtime" | "old_embedded" | "host_local"),
            "invalid stable contract execution role");
        eprintln!("legacy-stable-contract {}", serde_json::json!({
            "case":case,"sender":"old_cli","execution":execution,"passed":true
        }));
    }
    Ok(())
}

// These checks are deliberately Linux-only: this workflow freezes the original
// GNU x86_64 assets, rather than claiming another platform was exercised.
pub(super) fn stage_legacy_cli(root: &Path) -> anyhow::Result<PathBuf> {
    let source = legacy_cli()?.context("stable contract pass missing")?;
    let directory = root.join("bin");
    std::fs::create_dir_all(&directory)?;
    let binary = directory.join("rsrs");
    std::fs::copy(&source, &binary)?;
    let manifest = source.parent().context("stable assets directory missing")?.join("core-runtime.json");
    let bytes = std::fs::read(manifest)?;
    let core: Value = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(core["schema_version"] == 1 && core["target"] == "x86_64-unknown-linux-gnu",
        "stable embedded runtime manifest mismatch");
    // The fixed official GNU archive contains metadata/notices; its native code
    // is linked into the binary. Do not substitute candidate SDK libraries.
    for file in core["files"].as_array().context("stable GNU inventory missing")? {
        let relative = file["path"].as_str().context("stable notice path missing")?;
        anyhow::ensure!(relative.starts_with("core-notices/") && !relative.contains('\\')
            && relative.split('/').all(|part| !part.is_empty() && part != "." && part != ".."),
            "unexpected stable GNU runtime library layout");
        let original = source.parent().context("stable assets directory missing")?.join(relative);
        anyhow::ensure!(std::fs::symlink_metadata(&original)?.is_file()
            && !std::fs::symlink_metadata(&original)?.file_type().is_symlink(), "stable notice is not an ordinary file");
        let notice = std::fs::read(original)?;
        anyhow::ensure!(file["sha256"] == format!("{:x}", Sha256::digest(&notice)), "stable notice hash mismatch");
        let destination = directory.join(relative);
        std::fs::create_dir_all(destination.parent().context("stable notice parent missing")?)?;
        std::fs::write(destination, notice)?;
    }
    std::fs::write(directory.join("core-runtime.json"), bytes)?;
    anyhow::ensure!(std::fs::read(&binary)? == std::fs::read(source)?, "stable staging changed binary bytes");
    Ok(binary.canonicalize()?)
}

pub(super) fn legacy_owner(root: &Path, profile: &Path, port: u16) -> anyhow::Result<Value> {
    anyhow::ensure!(cfg!(target_os = "linux"), "stable GNU contract needs native Linux");
    let mut health: Value = ureq::get(&format!("http://127.0.0.1:{port}/api/health"))
        .timeout(std::time::Duration::from_secs(3)).call()?.into_json()?;
    let pid = u32::try_from(health["pid"].as_u64().context("stable owner PID missing")?)?;
    let binary = root.join("bin/rsrs").canonicalize()?;
    let expected = legacy_cli()?.context("stable contract binary missing")?;
    let process = std::fs::read_link(format!("/proc/{pid}/exe"))?.canonicalize()?;
    let stat=std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let birth=stat.rsplit_once(')').context("stable process stat missing")?.1
        .split_whitespace().nth(19).context("stable process birth missing")?.parse::<u64>()?;
    anyhow::ensure!(health["server"] == "respire" && health["v"] == 1
        && health["bin"] == "1.0.20" && pid > 0
        && Path::new(health["data_dir"].as_str().context("stable owner profile missing")?).canonicalize()? == profile.canonicalize()?
        && Path::new(health["exe"].as_str().context("stable owner image missing")?).canonicalize()? == binary
        && process == binary && std::fs::read(&binary)? == std::fs::read(expected)?
        && respire_commands::net_rpc::pid_listening_on(port) == Some(pid),
        "stable embedded owner identity differs from the official binary/profile/socket");
    let stat_after=std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let birth_after=stat_after.rsplit_once(')').context("stable final process stat missing")?.1
        .split_whitespace().nth(19).context("stable final process birth missing")?.parse::<u64>()?;
    anyhow::ensure!(birth==birth_after && std::fs::read_link(format!("/proc/{pid}/exe"))?.canonicalize()?==binary
        && respire_commands::net_rpc::pid_listening_on(port)==Some(pid),"stable owner changed during OS verification");
    health["test_observed_os_birth"]=serde_json::json!(birth);
    Ok(health)
}

pub(super) fn legacy_drained(profile: &Path, port: u16, pid: u32) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while respire_commands::net_rpc::process_is_running(pid)? && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::ensure!(!respire_commands::net_rpc::process_is_running(pid)?
        && !respire_commands::net_rpc::port_is_open_on(port), "stable owner did not exit and close its socket");
    let ownership = respire_app::lock::LibraryLock::acquire(profile, std::time::Duration::from_secs(2))?;
    drop(ownership);
    Ok(())
}

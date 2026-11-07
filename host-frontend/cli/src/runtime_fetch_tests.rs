//! Tests for the managed runtime fetcher: pin parsing, whitelist extraction,
//! stage verification and offline installation against fixture archives.
use super::*;

/// Lifecycle fixtures use a fully verified synthetic selection, never an
/// unproven old installation that the migration guard is supposed to preserve.
pub(crate) fn install_lifecycle_fixture() -> Result<PathBuf> {
    let version = &pinned()?.required;
    let triple = release_triple()?;
    let binary = managed_binary_path(version);
    let directory = binary.parent().context("fixture directory missing")?;
    fs::create_dir_all(directory)?;
    let payload = b"synthetic runtime; never executed";
    fs::write(&binary, payload)?;
    let resource = b"synthetic provider; never loaded";
    fs::create_dir_all(directory.join("lib"))?;
    fs::write(directory.join("lib/provider.bin"), resource)?;
    let core = serde_json::json!({"schema_version":1, "target":triple,
        "files":[{"path":"lib/provider.bin", "sha256":sha256_hex(resource)}]}).to_string();
    fs::write(directory.join(CORE_MANIFEST_FILE), &core)?;
    let name = release_binary_name(&triple);
    let metadata = serde_json::json!({
        "schema_version":2, "runtime_version":version, "tag":format!("v{version}"),
        "target_triple":triple, "archive_file":format!("rsrs-runtime-{triple}.tar.gz"),
        "archive_sha256":"0".repeat(64), "binary_file":name, "binary_sha256":sha256_hex(payload),
        "source_commit":"0".repeat(40), "compat":{"min_cli":"1.0.0", "max_cli":"*"},
        "protocol_range":{"minimum":1, "maximum":1},
        "capabilities":{"business_executor":"1", "mcp_server":"1"},
        "files":[{"path":name, "size":payload.len(), "sha256":sha256_hex(payload)},
            {"path":CORE_MANIFEST_FILE, "size":core.len(), "sha256":sha256_hex(core.as_bytes())},
            {"path":"lib/provider.bin", "size":resource.len(), "sha256":sha256_hex(resource)}],
    }).to_string();
    let parsed: BuildMetadata = serde_json::from_str(&metadata)?;
    publish_manifest(&ManagedManifest::from_release(&parsed, metadata.as_bytes())?)?;
    anyhow::ensure!(managed_runtime_path()?.as_ref() == Some(&binary));
    Ok(binary)
}

/// Serialize env-mutating tests and restore the previous environment on drop.
pub(crate) fn env_scope(keys: &[&'static str]) -> Result<impl Drop> {
    struct Restore {
        _guard: std::sync::MutexGuard<'static, ()>,
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
    Ok(Restore {
        _guard: crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow::anyhow!("test environment lock poisoned: {error}"))?,
        saved: keys
            .iter()
            .map(|key| (*key, std::env::var_os(*key)))
            .collect(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Build one ustar header block with a valid checksum field.
fn tar_header(name: &str, size: u64, typeflag: u8, mode: u32) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    let mode_text = format!("{mode:o}");
    header[100..100 + mode_text.len()].copy_from_slice(mode_text.as_bytes());
    let size_text = format!("{size:o}");
    header[124..124 + size_text.len()].copy_from_slice(size_text.as_bytes());
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let mut sum: u64 = 0;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        };
    }
    let checksum = format!("{sum:o}");
    let mut field = [0u8; 8];
    field[..checksum.len()].copy_from_slice(checksum.as_bytes());
    header[148..156].copy_from_slice(&field);
    header
}

/// Assemble a raw tar archive from (name, typeflag, mode, payload) entries.
fn tar_bytes(entries: &[(&str, u8, u32, &[u8])]) -> Vec<u8> {
    let mut raw = Vec::new();
    for (name, typeflag, mode, payload) in entries {
        raw.extend_from_slice(&tar_header(name, payload.len() as u64, *typeflag, *mode));
        raw.extend_from_slice(payload);
        let padding = (512 - (payload.len() as u64 % 512)) % 512;
        raw.extend(std::iter::repeat(0u8).take(padding as usize));
    }
    raw.extend_from_slice(&[0u8; 1024]);
    raw
}

fn gz(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(bytes)
        .context("fixture archive compression failed")?;
    encoder
        .finish()
        .context("fixture archive compression failed")
}

/// A complete, verifiable release fixture: binary + core manifest + library.
fn release_fixture(triple: &str) -> Result<(Vec<u8>, String)> {
    const BINARY: &[u8] = b"synthetic rsrs-runtime binary bytes";
    let hash = sha256_hex(BINARY);
    let manifest = serde_json::json!({
        "schema_version": 1,
        "target": triple,
        "files": [{"path": RUNTIME_BINARY, "sha256": hash}],
    });
    let raw = tar_bytes(&[
        ("./", b'5', 0o700, b""),
        ("lib/", b'5', 0o700, b""),
        ("lib/provider.json", b'0', 0o600, b"{}"),
        (
            CORE_MANIFEST_FILE,
            b'0',
            0o600,
            manifest.to_string().as_bytes(),
        ),
        (RUNTIME_BINARY, b'0', 0o755, BINARY),
    ]);
    Ok((gz(&raw)?, hash))
}

#[test]
fn pin_file_parses_and_accept_range_gates_versions() -> Result<()> {
    let pin = pinned()?;
    anyhow::ensure!(pin.required == "1.0.21-dev.15", "unexpected pin {pin:?}");
    anyhow::ensure!(pin.accept.contains("1.0.21-dev.15"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.14"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.13"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.12"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.11"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.10"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.9"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.8"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.7"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.6"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.5"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.4"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.3"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.2"));
    anyhow::ensure!(!pin.accept.contains("1.0.21-dev.1"));
    anyhow::ensure!(pin.accept.contains("1.0.21"));
    anyhow::ensure!(pin.accept.contains("1.9.9"));
    anyhow::ensure!(!pin.accept.contains("1.0.20"));
    anyhow::ensure!(!pin.accept.contains("2.0.0"));
    anyhow::ensure!(!pin.accept.contains("2.1.0-dev.1"));
    anyhow::ensure!(
        version_in_accept("1.0.21-dev.15")
            && !version_in_accept("1.0.21-dev.14")
            && !version_in_accept("1.0.21-dev.13")
            && !version_in_accept("1.0.21-dev.12")
            && !version_in_accept("1.0.21-dev.11")
            && !version_in_accept("1.0.21-dev.10")
            && !version_in_accept("1.0.21-dev.9")
            && !version_in_accept("1.0.21-dev.8")
            && !version_in_accept("1.0.21-dev.7")
            && !version_in_accept("1.0.21-dev.6")
            && !version_in_accept("1.0.21-dev.5")
            && !version_in_accept("1.0.21-dev.4")
            && !version_in_accept("1.0.21-dev.3")
            && !version_in_accept("1.0.21-dev.2")
            && !version_in_accept("0.9.0")
    );
    Ok(())
}

#[test]
fn accept_ranges_reject_malformed_bounds() -> Result<()> {
    for raw in [
        "",
        "1.2.3",
        ">=",
        "<1.0.0,>=2.0.0",
        ">=1.0.0,<=2.0.0",
        "<:>",
    ] {
        anyhow::ensure!(
            AcceptRange::parse(raw).is_err(),
            "malformed range {raw:?} was accepted"
        );
    }
    anyhow::ensure!(AcceptRange::parse("<2.0.0")?.contains("1.9.9"));
    anyhow::ensure!(!AcceptRange::parse("<2.0.0")?.contains("2.0.0"));
    anyhow::ensure!(AcceptRange::parse(">=1.0.21-dev.1")?.contains("1.0.21-dev.2"));
    Ok(())
}

#[test]
fn version_charset_rejects_separators_and_malformed_shapes() {
    for version in ["1.0.21-dev.1", "1.2.3+build.7", "2.0.0", "1.0.0-alpha-1"] {
        assert!(valid_version(version), "{version:?} should be valid");
    }
    for version in [
        "",
        "1/2",
        "a\\b",
        "C:evil",
        "1 2",
        "a\nb",
        "x@y",
        "v1.2.3",
        "1.2",
        "1.2.x",
        "=2.0.0",
        "1.2.3+",
        "1.2.3-alpha..1",
    ] {
        assert!(!valid_version(version), "{version:?} should be rejected");
    }
}

#[test]
fn entry_names_reject_traversal_and_separators() {
    for name in ["lib/x.json", "./lib/x.json", "rsrs-runtime", "a/b/c/"] {
        assert!(
            safe_entry_name(name).is_some(),
            "{name:?} should be accepted"
        );
    }
    for name in [
        "../escape",
        "a/../../escape",
        "/absolute",
        "back\\slash",
        "drive:C",
        "a//b",
        "a/./b",
        "",
        ".",
    ] {
        assert!(
            safe_entry_name(name).is_none(),
            "{name:?} should be rejected"
        );
    }
}

#[test]
fn extraction_whitelist_matches_client2_semantics() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let dir = tempfile::tempdir()?;
    let (archive, _) = release_fixture(&triple)?;
    let archive_path = dir.path().join("runtime.tar.gz");
    fs::write(&archive_path, &archive)?;
    let stage = dir.path().join("stage");
    extract_archive(&archive_path, &stage)?;
    anyhow::ensure!(stage.join(RUNTIME_BINARY).is_file());
    anyhow::ensure!(stage.join(CORE_MANIFEST_FILE).is_file());
    anyhow::ensure!(stage.join("lib/provider.json").is_file());
    // Entry names that fail the whitelist are rejected outright.
    let hostile = gz(&tar_bytes(&[("../escape", b'0', 0o600, b"x")]))?;
    fs::write(dir.path().join("hostile.tar.gz"), &hostile)?;
    anyhow::ensure!(
        extract_archive(
            &dir.path().join("hostile.tar.gz"),
            &dir.path().join("hostile")
        )
        .is_err(),
        "traversal entry was accepted"
    );
    anyhow::ensure!(!dir.path().join("escape").exists());
    for (name, typeflag) in [("C:\\bad", b'0'), ("link-target", b'2'), ("fifo", b'6')] {
        let entry = gz(&tar_bytes(&[(name, typeflag, 0o600, b"x")]))?;
        fs::write(dir.path().join("hostile2.tar.gz"), &entry)?;
        anyhow::ensure!(
            extract_archive(
                &dir.path().join("hostile2.tar.gz"),
                &dir.path().join("hostile2")
            )
            .is_err(),
            "unsafe entry {name} with flag {typeflag} was accepted"
        );
    }
    // A truncated archive never produces a usable stage.
    let truncated = gz(&tar_fixture_truncated())?;
    fs::write(dir.path().join("short.tar.gz"), &truncated)?;
    anyhow::ensure!(
        extract_archive(&dir.path().join("short.tar.gz"), &dir.path().join("short")).is_err()
    );
    Ok(())
}

fn tar_fixture_truncated() -> Vec<u8> {
    let mut raw = tar_bytes(&[("rsrs-runtime", b'0', 0o755, b"payload")]);
    raw.truncate(raw.len() - 600);
    raw
}

#[test]
fn stage_verification_enforces_manifest_and_binary_hash() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let dir = tempfile::tempdir()?;
    let (archive, binary_hash) = release_fixture(&triple)?;
    let archive_path = dir.path().join("runtime.tar.gz");
    fs::write(&archive_path, &archive)?;
    let stage = dir.path().join("stage");
    extract_archive(&archive_path, &stage)?;
    let binary = RUNTIME_BINARY.to_owned();
    let verified = verify_stage(&stage, &binary, &triple, &binary_hash)?;
    anyhow::ensure!(verified == stage.join(&binary));
    anyhow::ensure!(verify_stage(&stage, &binary, &triple, &"0".repeat(64)).is_err());
    anyhow::ensure!(verify_stage(&stage, &binary, "other-triple", &binary_hash).is_err());
    anyhow::ensure!(verify_stage(&stage, "missing-binary", &triple, &binary_hash).is_err());
    // A manifest listing a foreign path fails the whitelist.
    fs::write(
        stage.join(CORE_MANIFEST_FILE),
        serde_json::json!({
            "schema_version": 1,
            "target": triple,
            "files": [{"path": "../outside", "sha256": sha256_hex(b"x")}],
        })
        .to_string(),
    )?;
    anyhow::ensure!(verify_stage(&stage, &binary, &triple, &binary_hash).is_err());
    Ok(())
}

#[test]
fn install_placement_renames_the_full_triple_binary() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let stage = dir.path().join("stage");
    fs::create_dir_all(&stage)?;
    let full = release_binary_name("x86_64-pc-windows-msvc");
    let bare = RUNTIME_BINARY;
    anyhow::ensure!(full != bare, "platform constant must use the bare name");
    fs::write(stage.join(&full), b"binary bytes")?;
    place_managed_binary(&stage, &full)?;
    anyhow::ensure!(stage.join(bare).is_file());
    anyhow::ensure!(!stage.join(&full).exists());
    anyhow::ensure!(fs::read(stage.join(bare))? == b"binary bytes");
    fs::write(stage.join(&full), b"again")?;
    anyhow::ensure!(place_managed_binary(&stage, "../escape").is_err());
    anyhow::ensure!(place_managed_binary(&stage, "missing-binary").is_err());
    Ok(())
}

#[test]
fn offline_install_publishes_manifest_and_retains_one_rollback() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let _env = env_scope(&["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_RUNTIME_BIN", "RSRS_CORE_TEST_MODE"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
    std::env::remove_var("RSRS_RUNTIME_BIN");
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    let binary_name = release_binary_name(&triple);
    let binary_bytes = b"synthetic runtime bytes, never executed";
    let resource_bytes = b"synthetic SDK resource";
    let hash = sha256_hex(binary_bytes);
    let resource_hash = sha256_hex(resource_bytes);
    let core = serde_json::json!({
        "schema_version": 1, "target": triple,
        "files": [{"path": "lib/provider.bin", "size": resource_bytes.len(), "sha256": resource_hash}],
    }).to_string();
    let archive = gz(&tar_bytes(&[
        (&binary_name, b'0', 0o700, binary_bytes),
        (CORE_MANIFEST_FILE, b'0', 0o600, core.as_bytes()),
        ("lib/provider.bin", b'0', 0o600, resource_bytes),
    ]))?;
    let archive_path = dir.path().join("runtime.tar.gz");
    let metadata_path = dir.path().join(format!("runtime-build-{triple}.json"));
    let metadata = serde_json::json!({
        "schema_version": 2, "runtime_version": "1.0.21-dev.1", "tag": "v1.0.21-dev.1",
        "target_triple": triple, "archive_file": format!("rsrs-runtime-{triple}.tar.gz"),
        "archive_sha256": sha256_hex(&archive), "binary_file": binary_name, "binary_sha256": hash,
        "source_commit": "0".repeat(40), "compat": {"min_cli": "1.0.0", "max_cli": "*"},
        "protocol_range": {"minimum": 1, "maximum": 1},
        "capabilities": {"business_executor": "1", "mcp_server": "1"},
        "files": [
            {"path": binary_name, "size": binary_bytes.len(), "sha256": hash},
            {"path": CORE_MANIFEST_FILE, "size": core.len(), "sha256": sha256_hex(core.as_bytes())},
            {"path": "lib/provider.bin", "size": resource_bytes.len(), "sha256": resource_hash},
        ],
    });
    fs::write(&archive_path, &archive)?;
    anyhow::ensure!(
        install_from_file(&archive_path, "1.0.21-dev.1").is_err(),
        "offline metadata is mandatory"
    );
    anyhow::ensure!(read_manifest()?.is_none());
    fs::write(&metadata_path, metadata.to_string())?;
    let binary = install_from_file(&archive_path, "1.0.21-dev.1")?;
    anyhow::ensure!(binary.is_file());
    let manifest = read_manifest()?.context("manifest missing after install")?;
    anyhow::ensure!(manifest.version == "1.0.21-dev.1" && manifest.sha256 == hash);
    let proof = manifest.release.as_ref().context("release proof missing")?;
    anyhow::ensure!(proof.metadata_json == metadata.to_string());
    anyhow::ensure!(proof.metadata_sha256 == sha256_hex(metadata.to_string().as_bytes()));
    anyhow::ensure!(managed_runtime_path()?.context("managed path missing")? == binary);
    anyhow::ensure!(download_and_install(Some("1.0.21-dev.1"), None)? == binary);
    // A trusted Runtime archive is not old-host migration authorization.
    fs::create_dir(dir.path().join("bin"))?;
    let legacy = crate::mcp::stable_bin_path();
    fs::write(&legacy, b"old combined CLI")?;
    let before = fs::read(manifest_path())?;
    let error = download_and_install(Some("1.0.21-dev.1"), None)
        .err().context("verified Runtime permitted replacement of the old host")?;
    anyhow::ensure!(error.is::<LegacyRuntimeMigrationRequired>());
    anyhow::ensure!(crate::mcp::materialize_bin().is_err());
    anyhow::ensure!(fs::read(&legacy)? == b"old combined CLI");
    anyhow::ensure!(fs::read(manifest_path())? == before);
    fs::remove_file(legacy)?;
    let resource = binary
        .parent()
        .context("binary has no parent")?
        .join("lib/provider.bin");
    anyhow::ensure!(fs::read(&resource)? == resource_bytes);
    // Reuse must authenticate the original metadata, not a replacement local
    // manifest that agrees with damaged resource bytes.
    let core_path = binary
        .parent()
        .context("binary has no parent")?
        .join(CORE_MANIFEST_FILE);
    fs::write(&resource, b"damaged resource")?;
    let changed_core = serde_json::json!({
        "schema_version": 1, "target": triple,
        "files": [{"path": "lib/provider.bin", "sha256": sha256_hex(b"damaged resource")}],
    });
    fs::write(&core_path, changed_core.to_string())?;
    let error = managed_runtime_path()
        .err()
        .context("damaged resources were accepted")?;
    anyhow::ensure!(error.is::<ManagedRuntimeRepairRequired>());
    anyhow::ensure!(format!("{error:#}").contains("repair required"));
    let error = resolve_runtime_bin()
        .err()
        .context("discovery ignored managed corruption")?;
    anyhow::ensure!(error.is::<ManagedRuntimeRepairRequired>());
    anyhow::ensure!(format!("{error:#}").contains("repair required"));
    let error = download_and_install(Some("1.0.21-dev.1"), None)
        .err()
        .context("cached install ignored damaged resources")?;
    anyhow::ensure!(error.is::<ManagedRuntimeRepairRequired>());
    let before = fs::read(manifest_path())?;
    let error = download_and_install(Some("1.0.21-dev.2"), None)
        .err()
        .context("a different pin bypassed damaged resource verification")?;
    anyhow::ensure!(error.is::<ManagedRuntimeRepairRequired>());
    anyhow::ensure!(fs::read(manifest_path())? == before);
    fs::write(&core_path, &core)?;
    fs::write(&resource, resource_bytes)?;
    fs::remove_file(&resource)?;
    anyhow::ensure!(managed_runtime_path().is_err());
    fs::write(&resource, resource_bytes)?;
    let extra = resource.with_file_name("unlisted-provider.bin");
    fs::write(&extra, b"unlisted resource")?;
    anyhow::ensure!(managed_runtime_path().is_err());
    fs::remove_file(&extra)?;

    let mut changed = manifest.clone();
    changed
        .release
        .as_mut()
        .context("release proof missing")?
        .metadata_json
        .push(' ');
    publish_manifest(&changed)?;
    anyhow::ensure!(managed_runtime_path().is_err());
    changed = manifest.clone();
    changed.sha256 = "0".repeat(64);
    publish_manifest(&changed)?;
    anyhow::ensure!(managed_runtime_path().is_err());
    for (field, value) in [
        ("runtime_version", serde_json::json!("9.0.0")),
        ("target_triple", serde_json::json!("other-target")),
    ] {
        let mut rebound = metadata.clone();
        rebound[field] = value;
        changed = manifest.clone();
        let proof = changed.release.as_mut().context("release proof missing")?;
        proof.metadata_json = rebound.to_string();
        proof.metadata_sha256 = sha256_hex(proof.metadata_json.as_bytes());
        publish_manifest(&changed)?;
        anyhow::ensure!(
            managed_runtime_path().is_err(),
            "rebound {field} was accepted"
        );
    }
    let mut incomplete = metadata.clone();
    incomplete["files"]
        .as_array_mut()
        .context("release files missing")?
        .retain(|file| file["path"] != CORE_MANIFEST_FILE);
    let incomplete_metadata: BuildMetadata = serde_json::from_value(incomplete.clone())?;
    anyhow::ensure!(
        ManagedManifest::from_release(&incomplete_metadata, incomplete.to_string().as_bytes())
            .is_err(),
        "release proof must authenticate the Core manifest"
    );
    changed = manifest.clone();
    changed.release = None;
    publish_manifest(&changed)?;
    let error = resolve_runtime_bin()
        .err()
        .context("legacy selection silently fell back")?;
    anyhow::ensure!(error.is::<ManagedRuntimeRepairRequired>());
    anyhow::ensure!(format!("{error:#}").contains("repair required"));
    let error = download_and_install(Some("1.0.21-dev.1"), None)
        .err()
        .context("cached install accepted a legacy selection without proof")?;
    anyhow::ensure!(error.is::<ManagedRuntimeRepairRequired>());
    // An explicit trusted reinstall can establish proof for a legacy selection.
    let before = fs::read(manifest_path())?;
    let error = download_and_install(Some("1.0.21-dev.2"), None)
        .err()
        .context("a different pin bypassed legacy migration protection")?;
    anyhow::ensure!(error.is::<LegacyRuntimeMigrationRequired>());
    anyhow::ensure!(error.is::<ManagedRuntimeRepairRequired>());
    anyhow::ensure!(fs::read(manifest_path())? == before);
    anyhow::ensure!(fs::read(&resource)? == resource_bytes);
    anyhow::ensure!(install_from_file(&archive_path, "1.0.21-dev.1")? == binary);
    anyhow::ensure!(read_manifest()?
        .context("repaired selection missing")?
        .release
        .is_some());
    anyhow::ensure!(managed_runtime_path()?.context("repaired path missing")? == binary);
    // Failed archive, binary and resource checks must preserve the selected payload.
    for field in ["archive_sha256", "binary_sha256", "resource_sha256"] {
        let mut invalid = metadata.clone();
        if field == "resource_sha256" {
            invalid["files"][2]["sha256"] = serde_json::json!("0".repeat(64));
        } else {
            invalid[field] = serde_json::json!("0".repeat(64));
            if field == "binary_sha256" {
                invalid["files"][0]["sha256"] = invalid[field].clone();
            }
        }
        fs::write(&metadata_path, invalid.to_string())?;
        anyhow::ensure!(install_from_file(&archive_path, "1.0.21-dev.1").is_err());
        anyhow::ensure!(
            read_manifest()?
                .context("selection lost after rejected install")?
                .sha256
                == hash
        );
        anyhow::ensure!(fs::read(&resource)? == resource_bytes);
    }
    fs::write(&metadata_path, metadata.to_string())?;
    for version in ["1.0.20", "1.0.19", "1.0.21"] {
        let side = version_dir(version);
        fs::create_dir_all(&side)?;
        fs::write(side.join(RUNTIME_BINARY), b"synthetic side runtime")?;
    }
    // Reinstallation retains older payloads; cleanup is an explicit management action.
    anyhow::ensure!(install_from_file(&archive_path, "1.0.21-dev.1")? == binary);
    anyhow::ensure!(list_installed()?.len() == 4);
    let removed = clean_old()?;
    anyhow::ensure!(
        removed == vec!["1.0.20".to_owned(), "1.0.19".to_owned()],
        "unexpected removals: {removed:?}"
    );
    let listed = list_installed()?;
    anyhow::ensure!(listed.len() == 2, "unexpected inventory: {listed:?}");
    anyhow::ensure!(
        listed
            .iter()
            .find(|entry| entry.version == "1.0.21-dev.1")
            .context("current missing")?
            .current
    );
    anyhow::ensure!(clean_old()?.is_empty());
    Ok(())
}

#[test]
fn explicit_runtime_override_keeps_its_existing_trust_policy() -> Result<()> {
    let _env = env_scope(&["RSRS_DATA_DIR", "RSRS_RUNTIME_BIN"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    // An explicit selection still precedes managed discovery; no executable is run.
    fs::write(manifest_path(), b"invalid managed selection")?;
    let explicit = dir.path().join(RUNTIME_BINARY);
    fs::write(&explicit, b"synthetic explicit runtime")?;
    std::env::set_var("RSRS_RUNTIME_BIN", &explicit);
    anyhow::ensure!(resolve_runtime_bin()? == ResolvedRuntime::Ready(explicit));
    Ok(())
}

#[test]
fn automatic_install_preserves_legacy_owner_before_any_side_effects() -> Result<()> {
    let _env = env_scope(&["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_CORE_TEST_MODE"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    fs::create_dir(dir.path().join("bin"))?;
    let legacy = crate::mcp::stable_bin_path();
    let legacy_bytes = b"legacy combined CLI image; not executable";
    fs::write(&legacy, legacy_bytes)?;
    let session = dir.path().join("session.json");
    let library = dir.path().join("rsrs.db");
    fs::write(&session, b"legacy session bytes")?;
    fs::write(&library, b"legacy data bytes")?;
    let error = download_and_install(None, None)
        .err()
        .context("legacy owner triggered automatic installation")?;
    anyhow::ensure!(error.is::<LegacyRuntimeMigrationRequired>());
    anyhow::ensure!(is_progress_abort(&error));
    anyhow::ensure!(!format!("{error:#}").contains("downloads are disabled"),
        "legacy check happened after the download boundary");
    let materialize = crate::mcp::materialize_bin()
        .err()
        .context("CLI materialization overwrote the old combined service")?;
    anyhow::ensure!(materialize.contains("legacy_runtime_migration_required"));
    anyhow::ensure!(crate::autostart::coordinate_materialization().is_err());
    anyhow::ensure!(crate::autostart::restart_maintenance_locked().is_err());
    anyhow::ensure!(fs::read(&legacy)? == legacy_bytes);
    anyhow::ensure!(fs::read(&session)? == b"legacy session bytes");
    anyhow::ensure!(fs::read(&library)? == b"legacy data bytes");
    anyhow::ensure!(!runtime_dir().exists() && !manifest_path().exists());
    Ok(())
}

#[test]
fn automatic_install_allows_fresh_and_materialized_current_cli() -> Result<()> {
    let _env = env_scope(&["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_CORE_TEST_MODE"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    let required = &pinned()?.required;
    anyhow::ensure!(automatic_install_preflight(required)?.is_none());
    anyhow::ensure!(!runtime_dir().exists() && !manifest_path().exists());
    fs::write(dir.path().join("client.json"), br#"{"language":"en"}"#)?;
    anyhow::ensure!(automatic_install_preflight(required)?.is_none(),
        "fresh preferences were mistaken for an old installation");
    fs::create_dir(dir.path().join("bin"))?;
    fs::copy(std::env::current_exe()?, crate::mcp::stable_bin_path())?;
    anyhow::ensure!(automatic_install_preflight(required)?.is_none());
    let error = download_and_install(None, None)
        .err()
        .context("hermetic download was allowed")?;
    anyhow::ensure!(!error.is::<LegacyRuntimeMigrationRequired>());
    anyhow::ensure!(format!("{error:#}").contains("downloads are disabled"));
    anyhow::ensure!(!runtime_dir().exists() && !manifest_path().exists());
    Ok(())
}

#[test]
fn automatic_install_does_not_treat_missing_legacy_binary_as_fresh() -> Result<()> {
    let _env = env_scope(&["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_CORE_TEST_MODE"])?;
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    for relative in [
        "runtime/endpoint.json", "runtime/autostart/registration.json", "client.json",
        "session.json", "rsrs.db", "onememory.db",
    ] {
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
        let record = dir.path().join(relative);
        fs::create_dir_all(record.parent().context("legacy record parent missing")?)?;
        fs::write(&record, b"existing legacy state")?;
        let error = download_and_install(None, None)
            .err().context("missing binary was treated as a fresh installation")?;
        anyhow::ensure!(error.is::<LegacyRuntimeMigrationRequired>(), "missed {relative}");
        anyhow::ensure!(fs::read(&record)? == b"existing legacy state");
        anyhow::ensure!(!manifest_path().exists() && !runtime_dir().join(".install.lock").exists());
        anyhow::ensure!(!crate::mcp::stable_bin_path().exists());
    }
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
    let profile = dir.path().join("accounts/previous");
    fs::create_dir_all(&profile)?;
    fs::write(profile.join("rsrs.db"), b"old profile data")?;
    fs::write(dir.path().join("client.json"),
        serde_json::json!({"data_dir": profile}).to_string())?;
    let error = download_and_install(None, None)
        .err().context("configured legacy profile was mistaken for a fresh installation")?;
    anyhow::ensure!(error.is::<LegacyRuntimeMigrationRequired>());
    anyhow::ensure!(fs::read(profile.join("rsrs.db"))? == b"old profile data");
    anyhow::ensure!(!manifest_path().exists() && !runtime_dir().exists());
    Ok(())
}

#[test]
#[ignore = "requires the independently verified official GNU CLI v1.0.20 binary"]
fn automatic_install_preserves_official_cli_1_0_20() -> Result<()> {
    let fixture = PathBuf::from(std::env::var("RSRS_TEST_LEGACY_CLI_BIN")
        .context("set RSRS_TEST_LEGACY_CLI_BIN to the official GNU v1.0.20 binary")?);
    let expected = "c03c131c61819a5f4d132cfe328f7c1da82c2f0b21a9c87d2b8870d1541a4c3e";
    anyhow::ensure!(sha256_file(&fixture)? == expected, "wrong official legacy fixture digest");
    let _env = env_scope(&["RSRS_DATA_DIR", "RSRS_BIN_DIR", "RSRS_CORE_TEST_MODE"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_BIN_DIR", dir.path().join("bin"));
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    fs::create_dir(dir.path().join("bin"))?;
    let legacy = crate::mcp::stable_bin_path();
    fs::copy(fixture, &legacy)?;
    let error = download_and_install(None, None)
        .err()
        .context("official legacy CLI triggered automatic installation")?;
    anyhow::ensure!(error.is::<LegacyRuntimeMigrationRequired>());
    anyhow::ensure!(crate::mcp::materialize_bin().is_err());
    anyhow::ensure!(sha256_file(&legacy)? == expected);
    anyhow::ensure!(!runtime_dir().exists() && !manifest_path().exists());
    Ok(())
}

#[test]
fn release_triple_override_is_validated() -> Result<()> {
    let _env = env_scope(&["RSRS_RUNTIME_TRIPLE"])?;
    std::env::remove_var("RSRS_RUNTIME_TRIPLE");
    if cfg!(target_os = "linux") && matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
        let abi = if cfg!(target_env = "musl") { "musl" } else { "gnu" };
        anyhow::ensure!(
            release_triple()? == format!("{}-unknown-linux-{abi}", std::env::consts::ARCH)
        );
    }
    std::env::set_var("RSRS_RUNTIME_TRIPLE", "aarch64-unknown-linux-musl");
    anyhow::ensure!(release_triple()? == "aarch64-unknown-linux-musl");
    std::env::set_var("RSRS_RUNTIME_TRIPLE", "not-a-triple");
    anyhow::ensure!(release_triple().is_err());
    Ok(())
}

#[test]
fn mirror_override_builds_fallback_origins() -> Result<()> {
    let _env = env_scope(&["RSRS_MIRROR", "RSRS_DATA_DIR"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    let official = RELEASE_BASE.to_owned();
    let approved = vec![format!("{MIRROR_PREFIX}/{official}"), official.clone()];
    anyhow::ensure!(download_origins(Some(MIRROR_PREFIX))? == approved);
    anyhow::ensure!(
        download_origins(Some(MIRROR_PREFIX.trim_start_matches("https://")))? == approved
    );
    anyhow::ensure!(download_origins(Some(RELEASE_BASE))? == vec![official.clone()]);
    for origin in [
        "https://mirror.example",
        "mirror.example",
        "http://gh-proxy.com",
        "https://user:secret@gh-proxy.com",
        "https://gh-proxy.com/path",
        "https://gh-proxy.com?query=1",
        "https://gh-proxy.com#fragment",
    ] {
        anyhow::ensure!(
            download_origins(Some(origin)).is_err(),
            "unapproved origin accepted: {origin}"
        );
    }
    std::env::remove_var("RSRS_MIRROR");
    anyhow::ensure!(
        download_origins(None)? == vec![official.clone(), format!("{MIRROR_PREFIX}/{official}")]
    );
    Ok(())
}

#[test]
fn metadata_validation_rejects_cross_purpose_documents() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let base = serde_json::json!({
        "schema_version": 1,
        "runtime_version": "1.0.21-dev.1", "tag": "v1.0.21-dev.1", "triple": triple,
        "sha256": sha256_hex(b"archive"), "binary_sha256": sha256_hex(b"binary"),
        "binary_file": release_binary_name(&triple), "compat": {"min_cli": "1.0.0", "max_cli": "*"},
    });
    let metadata: BuildMetadata = serde_json::from_value(base.clone())?;
    metadata.validate("1.0.21-dev.1", &triple)?;
    anyhow::ensure!(
        ManagedManifest::from_release(&metadata, base.to_string().as_bytes()).is_err(),
        "legacy metadata must not become complete managed release proof"
    );
    let mut alias = base.clone();
    alias["archive_sha256"] = alias["sha256"].clone();
    let equal_alias: BuildMetadata = serde_json::from_value(alias.clone())?;
    equal_alias.validate("1.0.21-dev.1", &triple)?;
    alias
        .as_object_mut()
        .context("metadata is not an object")?
        .remove("sha256");
    let canonical: BuildMetadata = serde_json::from_value(alias)?;
    canonical.validate("1.0.21-dev.1", &triple)?;
    anyhow::ensure!(canonical.archive_sha256()? != canonical.binary_sha256()?);
    for (field, value) in [
        ("runtime_version", serde_json::json!("1.0.22")),
        ("tag", serde_json::json!("v1.0.22")),
        ("triple", serde_json::json!("x86_64-unknown-freebsd")),
        ("target_triple", serde_json::json!("other-target")),
        ("sha256", serde_json::json!("zz")),
        ("binary_sha256", serde_json::json!("")),
        ("binary_file", serde_json::json!("../escape")),
        ("binary_file", serde_json::json!(RUNTIME_BINARY)),
        (
            "compat",
            serde_json::json!({"min_cli":"99.0.0","max_cli":"*"}),
        ),
        (
            "compat",
            serde_json::json!({"min_cli":"1.0.0","max_cli":"no!pe"}),
        ),
    ] {
        let mut changed = base.clone();
        changed[field] = value;
        let changed: BuildMetadata = serde_json::from_value(changed)?;
        anyhow::ensure!(
            changed.validate("1.0.21-dev.1", &triple).is_err(),
            "invalid metadata accepted: {field}"
        );
    }
    let mut conflicting = base.clone();
    conflicting["archive_sha256"] = serde_json::json!(sha256_hex(b"other archive"));
    let conflicting: BuildMetadata = serde_json::from_value(conflicting)?;
    anyhow::ensure!(conflicting.validate("1.0.21-dev.1", &triple).is_err());
    let mut missing = base;
    missing
        .as_object_mut()
        .context("metadata is not an object")?
        .remove("binary_sha256");
    let missing: BuildMetadata = serde_json::from_value(missing)?;
    anyhow::ensure!(missing.validate("1.0.21-dev.1", &triple).is_err());
    Ok(())
}

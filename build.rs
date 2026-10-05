use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=RESPIRE_CORE_SDK_DIR");
    let directory = PathBuf::from(
        env::var_os("RESPIRE_CORE_SDK_DIR")
            .ok_or("prepare the Core SDK with prepare-sdk.mjs and set RESPIRE_CORE_SDK_DIR")?,
    );
    let manifest_path = directory.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    if manifest["association_contract"].as_u64() != Some(1) {
        return Err("Core SDK lacks association contract 1; rebuild and pin a matching SDK".into());
    }
    let target = env::var("TARGET")?;
    let lock_path =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("core-sdk.lock.json");
    let lock: Value = serde_json::from_slice(&fs::read(&lock_path)?)?;
    let locked_hash = lock["targets"][&target]["manifest_sha256"]
        .as_str()
        .ok_or("no validated SDK locked for this target")?;
    if hex::encode(Sha256::digest(&manifest_bytes)) != locked_hash {
        return Err("Core SDK manifest does not match the pinned lock".into());
    }
    if env::var("CARGO_CFG_PANIC")?.as_str() != "unwind" {
        return Err("Core SDK currently requires a panic=unwind host".into());
    }
    if manifest["target"].as_str() != Some(target.as_str()) {
        return Err("Core SDK target does not match Cargo TARGET".into());
    }
    let features = env::var("CARGO_CFG_TARGET_FEATURE")?;
    let static_crt = features.split(',').any(|feature| feature == "crt-static");
    if target.contains("windows-msvc") && static_crt {
        return Err("Windows Core SDK requires the dynamic CRT (-crt-static)".into());
    }
    if target.contains("musl") && !static_crt {
        return Err("musl Core SDK requires the static CRT (+crt-static)".into());
    }
    if manifest["abi_version"].as_u64() != Some(0x0001_0000) {
        return Err("Core SDK ABI version mismatch".into());
    }
    let compiler = std::process::Command::new(env::var_os("RUSTC").ok_or("missing RUSTC")?)
        .arg("-Vv")
        .output()?;
    if !compiler.status.success() {
        return Err("failed to identify Rust compiler".into());
    }
    let compiler_info = String::from_utf8(compiler.stdout)?;
    let sdk_compiler = manifest["toolchain"]
        .as_str()
        .ok_or("missing SDK toolchain")?;
    for key in ["commit-hash: ", "release: "] {
        let current = compiler_info
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or("incomplete compiler version")?;
        let built_with = sdk_compiler
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or("incomplete SDK compiler version")?;
        if current != built_with {
            return Err("SDK and host Rust toolchains do not match".into());
        }
    }
    let files = manifest["files"].as_array().ok_or("missing SDK files")?;
    let library_path = if target.contains("windows-msvc") {
        "lib/respire_core_ffi.lib"
    } else {
        "lib/librespire_core_ffi.a"
    };
    if !files
        .iter()
        .any(|file| file["path"].as_str() == Some(library_path))
    {
        return Err("SDK manifest does not include the linked library".into());
    }
    for file in files {
        let relative = file["path"].as_str().ok_or("missing SDK file path")?;
        let relative_path = std::path::Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("unsafe SDK file path".into());
        }
        let path = directory.join(relative_path);
        let actual = hex::encode(Sha256::digest(fs::read(&path)?));
        if file["sha256"].as_str() != Some(actual.as_str()) {
            return Err(format!("SDK checksum mismatch: {relative}").into());
        }
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!("cargo:rerun-if-changed={}", lock_path.display());
    // Cargo does not stage SDK runtime dependencies next to executables.
    // OUT_DIR is <profile>/build/<package>/out; tests also run in <profile>/deps.
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    let profile = out
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .ok_or("unexpected Cargo output directory")?;
    for file in files {
        let relative = file["path"].as_str().ok_or("missing SDK file path")?;
        if let Some(name) = relative.strip_prefix("runtime/") {
            if name.contains('/') {
                return Err("runtime libraries must be flat".into());
            }
            for destination in [profile.to_path_buf(), profile.join("deps")] {
                fs::create_dir_all(&destination)?;
                fs::copy(directory.join(relative), destination.join(name))?;
            }
        }
    }
    println!(
        "cargo:rustc-link-search=native={}",
        directory.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=respire_core_ffi");
    if target.contains("apple-darwin")
        && manifest["native_libraries"]
            .as_array()
            .ok_or("missing native libraries")?
            .iter()
            .any(|library| library.as_str() == Some("clang_rt.osx"))
    {
        let clang = std::process::Command::new("clang")
            .arg("--print-resource-dir")
            .output()?;
        if !clang.status.success() {
            return Err("clang failed to identify its runtime directory".into());
        }
        let resources = String::from_utf8(clang.stdout)?;
        let runtime = PathBuf::from(resources.trim()).join("lib/darwin");
        if !runtime.join("libclang_rt.osx.a").is_file() {
            return Err("Apple clang runtime libclang_rt.osx.a is not installed".into());
        }
        println!("cargo:rustc-link-search=native={}", runtime.display());
    }
    for library in manifest["native_libraries"]
        .as_array()
        .ok_or("missing native libraries")?
    {
        let library = library.as_str().ok_or("invalid native library")?;
        println!("cargo:rustc-link-lib={library}");
    }
    Ok(())
}

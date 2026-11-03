use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Cursor, Read},
    path::PathBuf,
};

pub fn prepare() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=host-winml-build.rs");
    println!("cargo:rerun-if-changed=notices/WinML-2.4.89-license.txt");
    if env::var("CARGO_CFG_TARGET_OS")? != "windows" {
        return Ok(());
    }
    let arch = match env::var("CARGO_CFG_TARGET_ARCH")?.as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported Windows ML architecture: {other}").into()),
    };
    let out = PathBuf::from(env::var("OUT_DIR")?);
    let package = out.join("winml-2.4.89.nupkg");
    let bytes = if package.is_file() {
        fs::read(&package)?
    } else {
        let mut bytes = Vec::new();
        ureq::get("https://api.nuget.org/v3-flatcontainer/microsoft.windows.ai.machinelearning/2.4.89/microsoft.windows.ai.machinelearning.2.4.89.nupkg")
            .timeout(std::time::Duration::from_secs(300))
            .call()?.into_reader().read_to_end(&mut bytes)?;
        bytes
    };
    if format!("{:x}", Sha256::digest(&bytes))
        != "5c68ecfb947223267abf159a023f5192ad42725e4e9cc995e7c1470dd54dff63"
    {
        return Err("Windows ML package SHA256 mismatch".into());
    }
    fs::write(package, &bytes)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    for (entry, name) in [
        (
            format!("runtimes/win-{arch}/native/Microsoft.Windows.AI.MachineLearning.dll"),
            "winml.dll",
        ),
        ("license.txt".into(), "winml-license.txt"),
    ] {
        let mut file = archive.by_name(&entry)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if name == "winml-license.txt" {
            let notice = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
                .join("notices/WinML-2.4.89-license.txt");
            if fs::read(notice)? != bytes {
                return Err(
                    "Windows ML packaged license differs from the verified NuGet license".into(),
                );
            }
        }
        fs::write(out.join(name), bytes)?;
    }
    Ok(())
}

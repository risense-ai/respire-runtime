//! Pinned variant file staging and publication without app or Core dependencies.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model_download::{download_with_fallback, remove_download_parts, DownloadTimeouts};

/// HuggingFace repo (where the ONNX actually lives, not the BAAI source repo).
pub const MODEL_REPO: &str = "Xenova/bge-m3";
/// Verified revision (this commit's tokenizer/onnx hashes match the local read-only model).
pub const MODEL_REVISION: &str = "4de13258303883538bd53b696b452bf8099f0858";

/// Execute a plan received through authenticated Runtime control, never an arbitrary URL list.
/// The caller owns and serializes the local roots; roots must not come from the remote plan.
/// This proves files only;
/// Runtime must subsequently invalidate its validation cache and prove fresh backend loading.
pub fn prepare_model_assets(
    plan: &respire_protocol::AssetsStatus,
    allowed_roots: &[PathBuf],
) -> Result<()> {
    let sources: Vec<_> = plan.assets.iter()
        .map(|asset| vec![asset.suggested_source.clone()]).collect();
    prepare_model_assets_with_sources(plan, allowed_roots, &sources).map(|_| ())
}

/// Sources come from local mirror policy; the Runtime plan still supplies fixed pins.
pub fn prepare_model_assets_with_sources(
    plan: &respire_protocol::AssetsStatus,
    allowed_roots: &[PathBuf],
    sources: &[Vec<String>],
) -> Result<bool> {
    use respire_protocol::AssetState;
    anyhow::ensure!(sources.len() == plan.assets.len()
        && sources.iter().all(|list| !list.is_empty()
            && list.iter().all(|source| !source.is_empty())),
        "every model asset requires local download sources");
    anyhow::ensure!(
        !plan.complete
            && plan.backend_load.is_none()
            && !plan.assets.is_empty()
            && plan.missing == plan.assets,
        "expected a file installation plan, not readiness status"
    );
    anyhow::ensure!(
        !allowed_roots.is_empty(),
        "trusted local model roots are required"
    );
    for root in allowed_roots {
        check_model_path(root)?;
    }
    let mut pending = Vec::new();
    let mut claimed = std::collections::BTreeSet::new();
    // Validate the entire plan before creating directories or transferring any bytes.
    for (asset, asset_sources) in plan.assets.iter().zip(sources) {
        anyhow::ensure!(
            asset.state == AssetState::Missing
                && asset.reason.is_none()
                && asset.actual_size.is_none()
                && asset.actual_sha256.is_none(),
            "asset {} requires Runtime preparation: {}",
            asset.name,
            asset.reason.as_deref().unwrap_or("invalid plan state")
        );
        anyhow::ensure!(
            matches!(
                asset.name.as_str(),
                "bge-m3-tokenizer"
                    | "bge-m3-baseline"
                    | "bge-m3-model"
                    | "bge-m3-cpu-ort"
                    | "profile-tokenizer"
                    | "profile-weights"
            ),
            "unsupported model preparation resource {}",
            asset.name
        );
        let hash = asset
            .sha256
            .as_deref()
            .context("model asset SHA-256 missing")?;
        anyhow::ensure!(
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "model asset requires a fixed SHA-256"
        );
        anyhow::ensure!(
            asset.expected_size.is_some_and(|size| size > 0),
            "model asset size missing"
        );
        let target = PathBuf::from(asset.path.as_deref().context("model asset path missing")?);
        check_model_path(&target)?;
        let relative = allowed_roots
            .iter()
            .find_map(|root| target.strip_prefix(root).ok())
            .context("model destination is outside trusted local roots")?;
        anyhow::ensure!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "model destination must be a relative file below a trusted root"
        );
        let filename = target
            .file_name()
            .and_then(|name| name.to_str())
            .context("model file name missing")?;
        anyhow::ensure!(
            filename
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                && !filename.starts_with('.'),
            "invalid model file name"
        );
        check_plan_source(asset, filename)?;
        let staged = target.with_file_name(format!(".{hash}-{filename}.partial"));
        let parts = staged.with_extension("onnx.parts");
        for path in [&target, &staged, &parts] {
            check_model_path(path)?;
            let key = path
                .to_str()
                .context("model path is not Unicode")?
                .to_owned();
            #[cfg(windows)]
            let key = key.to_ascii_lowercase();
            anyhow::ensure!(claimed.insert(key), "model plan has overlapping paths");
        }
        for index in 0..4 {
            check_model_path(&parts.join(index.to_string()))?;
        }
        pending.push((target, staged, asset, asset_sources));
    }
    let _operation = crate::model_progress::Operation::begin_download()?;
    let mut skipped = true;
    for (target, staged, asset, asset_sources) in &pending {
        let hash = asset
            .sha256
            .as_deref()
            .context("model asset SHA-256 missing")?;
        if crate::model_download::file_valid(target, hash, asset.expected_size)? {
            continue;
        }
        skipped = false;
        crate::model_progress::check()?;
        let parent = staged.parent().context("model staging parent missing")?;
        std::fs::create_dir_all(parent)?;
        check_model_path(staged)?;
        if !crate::model_download::file_valid(staged, hash, asset.expected_size)? {
            let parts = staged.with_extension("onnx.parts");
            check_model_path(&parts)?;
            for index in 0..4 {
                check_model_path(&parts.join(index.to_string()))?;
            }
            download_with_fallback(
                asset_sources,
                staged,
                hash,
                matches!(
                    target.extension().and_then(|ext| ext.to_str()),
                    Some("onnx" | "ort" | "safetensors")
                ),
                DownloadTimeouts::default(),
                asset.expected_size,
            )?;
        }
        anyhow::ensure!(
            crate::model_download::file_valid(staged, hash, asset.expected_size)?,
            "prepared model asset failed size or SHA-256 validation"
        );
    }
    // Never publish the first replacement until every required download verifies.
    for (target, staged, asset, _) in &pending {
        crate::model_progress::check()?;
        check_model_path(target)?;
        check_model_path(staged)?;
        let hash = asset
            .sha256
            .as_deref()
            .context("model asset SHA-256 missing")?;
        if crate::model_download::file_valid(target, hash, asset.expected_size)? {
            check_model_path(&staged.with_extension("onnx.parts"))?;
            remove_download_parts(staged)?;
            match std::fs::remove_file(staged) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            continue;
        }
        anyhow::ensure!(
            crate::model_download::file_valid(staged, hash, asset.expected_size)?,
            "staged model asset changed before publication"
        );
        check_model_path(&staged.with_extension("onnx.parts"))?;
        remove_download_parts(staged)?;
        replace_file(staged, target)?;
    }
    for (target, _, asset, _) in &pending {
        anyhow::ensure!(
            crate::model_download::file_valid(
                target,
                asset
                    .sha256
                    .as_deref()
                    .context("model asset SHA-256 missing")?,
                asset.expected_size
            )?,
            "model file preparation is incomplete"
        );
    }
    Ok(skipped)
}

fn check_plan_source(asset: &respire_protocol::AssetRequirement, filename: &str) -> Result<()> {
    // Accept only these canonical official layouts. Do not enable the server-only URL dependency
    // or turn profile metadata into a general-purpose URL download surface.
    let source = &asset.suggested_source;
    let cpu = asset.name == "bge-m3-cpu-ort";
    let prefix = if cpu {
        "https://github.com/risense-ai/respire-cli/releases/download/"
    } else {
        "https://huggingface.co/"
    };
    let relative = source
        .strip_prefix(prefix)
        .context("model source must use its official HTTPS origin")?;
    let path: Vec<_> = relative.split('/').collect();
    anyhow::ensure!(
        path.iter().all(|part| !part.is_empty()
            && *part != "."
            && *part != ".."
            && part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))),
        "model source must be canonical, without credentials, query, fragment or encoded paths"
    );
    let version = asset
        .version
        .as_deref()
        .context("model source revision missing")?;
    if cpu {
        anyhow::ensure!(
            !version.is_empty() && path.len() == 2 && path[1] == filename,
            "CPU container must use its official pinned release"
        );
    } else {
        anyhow::ensure!(
            path.len() >= 5
                && path[2] == "resolve"
                && path[3] == version
                && path.last().copied() == Some(filename)
                && version.len() == 40
                && version.bytes().all(|c| c.is_ascii_hexdigit()),
            "model source requires its official immutable revision and matching file name"
        );
    }
    Ok(())
}

fn check_model_path(path: &Path) -> Result<()> {
    use std::path::Component;
    anyhow::ensure!(
        path.is_absolute() && path.to_str().is_some(),
        "model path must be absolute Unicode"
    );
    let mut prefix = PathBuf::new();
    for component in path.components() {
        anyhow::ensure!(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "model paths must not contain dot components"
        );
        if let Component::Normal(name) = component {
            let name = name
                .to_str()
                .context("model path component is not Unicode")?;
            anyhow::ensure!(
                !name.contains([':', '\\']) && !name.ends_with(['.', ' ']),
                "ambiguous model path component"
            );
        }
        prefix.push(component.as_os_str());
        // A Windows drive/UNC prefix is not a path until its root component is appended.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&prefix) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "model paths must not follow symlinks"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "model paths must not follow reparse points"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Publish the baseline as a batch; selection and final loader readiness stay with the caller.
pub(super) fn install_baseline_into(
    files: &[(&str, &str, Option<u64>)],
    dest: &Path,
    origins: &[String],
) -> Result<bool> {
    std::fs::create_dir_all(&dest)?;
    // A pinned revision allows cancellation, restart and mirror changes to reuse
    // partial bytes without exposing an incomplete file to the model loader.
    let tmp = dest.join(format!(".download-{MODEL_REVISION}"));
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let mut skipped = true;
    for &(name, sha, expected_size) in files {
        if crate::model_download::file_valid(&dest.join(name), sha, expected_size)? {
            continue;
        }
        if crate::model_download::file_valid(&tmp.join(name), sha, expected_size)? {
            skipped = false;
            continue;
        }
        let sources = origins
            .iter()
            .map(|origin| file_url(origin, name))
            .collect::<Vec<_>>();
        download_with_fallback(
            &sources,
            &tmp.join(name),
            sha,
            name.ends_with(".onnx"),
            DownloadTimeouts::default(),
            expected_size,
        )?;
        skipped = false;
    }
    // Publish only after every required replacement has passed the pinned checksum.
    std::fs::create_dir_all(dest.join("onnx"))?;
    for &(name, _, _) in files {
        if tmp.join(name).is_file() {
            replace_file(&tmp.join(name), &dest.join(name))?;
        }
    }
    std::fs::remove_dir_all(&tmp)?;
    Ok(skipped)
}

/// Return only after publication, so the caller can invalidate SDK validation before notices.
pub(super) fn install_cpu_container_into(
    partial: &Path,
    dest: &Path,
    sources: &[String],
    expected: &str,
    size: u64,
    expected_size: Option<u64>,
) -> Result<Option<String>> {
    let downloaded_from = if !crate::model_download::file_valid(partial, expected, expected_size)? {
        Some(download_with_fallback(
            sources,
            partial,
            expected,
            true,
            DownloadTimeouts::default(),
            expected_size,
        )?)
    } else {
        None
    };
    anyhow::ensure!(
        partial.metadata()?.len() == size,
        "CPU model size mismatch"
    );
    remove_download_parts(partial)?;
    replace_file(partial, dest)?;
    Ok(downloaded_from)
}

pub(super) fn install_variant_into(
    variant_name: &str,
    file: &str,
    expected: &str,
    variant_size: u64,
    expected_size: Option<u64>,
    dest: &Path,
    origins: &[String],
) -> Result<()> {
    std::fs::create_dir_all(&dest)?;
    let tmp = variant_staging_dir(&dest);
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let dest_path = dest.join(file);
    let tmp_path = tmp.join(file);
    if !variant_file_valid(&dest_path, expected, variant_size, expected_size)? {
        // A verified leftover from an earlier attempt is published without
        // re-downloading; only an unverified destination downloads.
        if !variant_file_valid(&tmp_path, expected, variant_size, expected_size)? {
            let sources = origins
                .iter()
                .map(|origin| file_url(origin, file))
                .collect::<Vec<_>>();
            download_with_fallback(
                &sources,
                &tmp_path,
                expected,
                true,
                DownloadTimeouts::default(),
                expected_size,
            )?;
        }
        std::fs::create_dir_all(dest.join("onnx"))?;
        anyhow::ensure!(
            variant_file_valid(&tmp_path, expected, variant_size, expected_size)?,
            "downloaded variant size or checksum mismatch"
        );
        replace_file(&tmp_path, &dest_path)?;
    }
    anyhow::ensure!(
        variant_file_valid(&dest_path, expected, variant_size, expected_size)?,
        "BGE-M3 {} install is incomplete",
        variant_name
    );
    Ok(())
}

pub(super) fn file_url(origin: &str, rel: &str) -> String {
    format!(
        "{}/{}/resolve/{}/{}",
        origin.trim_end_matches('/'),
        MODEL_REPO,
        MODEL_REVISION,
        rel
    )
}

pub(super) fn replace_file(from: &Path, to: &Path) -> Result<()> {
    // Rename replaces the destination without deleting it first if publication fails.
    std::fs::rename(from, to).with_context(|| format!("failed to place {}", to.display()))
}

fn variant_staging_dir(dest: &Path) -> PathBuf {
    dest.join(format!(".variants-{MODEL_REVISION}"))
}

fn variant_file_valid(
    path: &Path,
    expected: &str,
    variant_size: u64,
    expected_size: Option<u64>,
) -> Result<bool> {
    if !path.is_file() || path.metadata()?.len() != variant_size {
        return Ok(false);
    }
    crate::model_download::file_valid(path, expected, expected_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn verified_variant_survives_base_cleanup_and_publishes_without_network() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let name = "fp16";
        let file = "onnx/model_fp16.onnx";
        let size = 3;
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let staging = variant_staging_dir(dir.path());
        std::fs::create_dir_all(staging.join("onnx"))?;
        std::fs::write(staging.join("onnx/model_fp16.onnx"), b"abc")?;
        let base_staging = dir.path().join(format!(".download-{MODEL_REVISION}"));
        std::fs::create_dir_all(&base_staging)?;
        std::fs::remove_dir_all(base_staging)?;
        install_variant_into(name, file, sha256, size, None, dir.path(), &[])?;
        install_variant_into(name, file, sha256, size, None, dir.path(), &[])?;
        let destination = dir.path().join(file);
        assert!(replace_file(&dir.path().join("missing-staged-model"), &destination).is_err());
        assert_eq!(std::fs::read(&destination)?, b"abc");
        let replacement = dir.path().join("verified-staged-model");
        std::fs::write(&replacement, b"abc")?;
        replace_file(&replacement, &destination)?;
        assert!(!replacement.exists());
        assert_eq!(
            std::fs::read(dir.path().join("onnx/model_fp16.onnx"))?,
            b"abc"
        );
        assert!(!staging.join("onnx/model_fp16.onnx").exists());

        use respire_protocol::{AssetRequirement, AssetState, AssetsStatus};
        // Canonicalize the fixture root, not a plan-supplied path: macOS temp roots may be links.
        let root = dir.path().canonicalize()?;
        let asset = AssetRequirement {
            name: "bge-m3-model".to_owned(),
            version: Some(MODEL_REVISION.to_owned()),
            sha256: Some(sha256.to_owned()),
            suggested_source: file_url("https://huggingface.co", file),
            state: AssetState::Missing,
            path: Some(
                root.join(file)
                    .to_str()
                    .context("fixture path is not Unicode")?
                    .to_owned(),
            ),
            expected_size: Some(size),
            actual_size: None,
            actual_sha256: None,
            reason: None,
        };
        let plan = AssetsStatus::installation_plan(vec![asset.clone()]);
        assert!(!plan.complete);
        assert!(plan.backend_load.is_none());
        assert_eq!(plan.missing, plan.assets);
        for sources in [vec![], vec![vec![]], vec![vec![String::new()]]] {
            assert!(prepare_model_assets_with_sources(&plan, std::slice::from_ref(&root), &sources)
                .is_err());
        }
        // The real official artifact cannot match this three-byte pin: downloading would fail.
        prepare_model_assets(&plan, std::slice::from_ref(&root))?;
        assert!(prepare_model_assets_with_sources(&plan, std::slice::from_ref(&root),
            &[vec!["https://local-mirror.invalid/unused-verified-file".to_owned()]])?);
        assert_eq!(std::fs::read(root.join(file))?, b"abc");

        for (case, expected_error) in [
            ("outside", "outside trusted local roots"),
            ("duplicate", "overlapping paths"),
            ("http", "official HTTPS origin"),
            ("sha", "fixed SHA-256"),
            ("sha-nonhex", "fixed SHA-256"),
            ("missing-size", "size missing"),
            ("zero-size", "size missing"),
        ] {
            let destination = root.join(format!("rejected-{case}"));
            let mut rejected = asset.clone();
            rejected.path = Some(
                destination
                    .join(file)
                    .to_str()
                    .context("fixture path is not Unicode")?
                    .to_owned(),
            );
            let allowed = if case == "outside" {
                root.join("allowed")
            } else {
                destination.clone()
            };
            match case {
                "http" => {
                    rejected.suggested_source =
                        rejected.suggested_source.replacen("https://", "http://", 1)
                }
                "sha" => rejected.sha256 = Some("not-a-sha256".to_owned()),
                "sha-nonhex" => rejected.sha256 = Some("z".repeat(64)),
                "missing-size" => rejected.expected_size = None,
                "zero-size" => rejected.expected_size = Some(0),
                _ => {}
            }
            let assets = if case == "duplicate" {
                vec![rejected.clone(), rejected]
            } else {
                vec![rejected]
            };
            let error = prepare_model_assets(&AssetsStatus::installation_plan(assets), &[allowed])
                .err()
                .ok_or_else(|| anyhow!("invalid {case} plan was accepted"))?;
            assert!(
                error.to_string().contains(expected_error),
                "{case}: {error:#}"
            );
            assert!(
                !destination.exists(),
                "{case} rejection must precede directory creation"
            );
        }
        // Keep all built-in profile source layouts executable; no network is used here.
        for (repo, revision, weights) in [
            ("Xenova/bge-m3", MODEL_REVISION, "onnx/model_quantized.onnx"),
            (
                "Xenova/bge-small-zh-v1.5",
                "75c43b069aac4d136ba6bc1122f995fedcfd2781",
                "onnx/model_quantized.onnx",
            ),
            (
                "mlx-community/bge-m3-mlx-fp16",
                "a37eddded9a6a1273a87fb8b0da0d1cdbd98aeec",
                "model.safetensors",
            ),
        ] {
            for resource in ["tokenizer.json", weights] {
                let mut builtin = asset.clone();
                builtin.name = if resource == "tokenizer.json" {
                    "profile-tokenizer"
                } else {
                    "profile-weights"
                }
                .to_owned();
                builtin.version = Some(revision.to_owned());
                builtin.suggested_source =
                    format!("https://huggingface.co/{repo}/resolve/{revision}/{resource}");
                let filename = resource
                    .rsplit('/')
                    .next()
                    .context("fixture file name missing")?;
                check_plan_source(&builtin, filename)?;
            }
        }
        assert_eq!(std::fs::read(root.join(file))?, b"abc");
        Ok(())
    }
}

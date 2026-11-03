//! Explicit synthetic benchmark; never reads an account, library or transcript.
use anyhow::{Context, Result};
use respire_core_sdk::Core;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    time::{Duration, Instant},
};
struct StopObserver(Arc<AtomicBool>);
impl Drop for StopObserver {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn verified(path: &Path, expected: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("read fixture {}", path.display()))?;
    anyhow::ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == expected,
        "fixture checksum mismatch"
    );
    Ok(bytes)
}
fn threads() -> Option<usize> {
    std::fs::read_dir("/proc/self/task")
        .ok()
        .map(|entries| entries.count())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let root = Path::new(args.get(1).context("provide verified model directory")?);
    let legacy = args.iter().any(|arg| arg == "--legacy");
    let (name, hash) = if legacy {
        (
            "model_quantized.onnx",
            "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
        )
    } else {
        (
            "model_quantized.cpu-v1.ort",
            "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff",
        )
    };
    let model = verified(&root.join("onnx").join(name), hash)?;
    let tokenizer = verified(
        &root.join("tokenizer.json"),
        "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
    )?;
    let content = "Synthetic indexing fixture: the lunar research station stores calibration decisions and validates retrieval results. ".repeat(70);
    let mut reports = Vec::new();
    let mut baseline_threads = None;
    for background in [1usize, 4] {
        let mut core = Core::new()?;
        anyhow::ensure!(
            core.capabilities()?["inference_thread_contract"] == 1,
            "SDK lacks thread isolation contract"
        );
        let mut config = json!({"model":"m3","asset_id":hash,"engine":"cpu","execution_timeout_secs":120,
            "session_options_id":format!("synthetic-thread-probe-{background}"),
            "cpu_owned_ort_experiment":!legacy});
        // The baseline uses the unchanged request shape from older callers.
        if background != 1 {
            config["background_intra_threads"] = json!(background);
        }
        if legacy {
            core.load_model(config.clone(), &model, &tokenizer)?;
        } else {
            let mut upload = core.begin_model_input(model.len())?;
            for chunk in model.chunks(1 << 20) {
                upload.append(chunk)?;
            }
            upload.commit(config.clone(), &tokenizer)?;
        }
        let status = core.call("engine_control", json!({"action":"inference_status"}))?;
        anyhow::ensure!(
            status["intra_threads"] == json!({"foreground":1,"background":background}),
            "loaded native policy mismatch"
        );
        let mut wrong = config.clone();
        wrong["reuse_current"] = json!(true);
        wrong["background_intra_threads"] = json!(if background == 1 { 4 } else { 1 });
        anyhow::ensure!(
            core.load_model(wrong, &[], &[]).is_err(),
            "cached model reused across thread policies"
        );
        let warm = core.call("prepare", json!({"model":"m3","content":content}))?;
        anyhow::ensure!(
            warm["artifact"]
                .as_str()
                .is_some_and(|artifact| !artifact.is_empty()),
            "background warmup failed"
        );
        let native_threads = threads();
        if background == 1 {
            baseline_threads = native_threads;
        }
        if let (Some(baseline), Some(actual)) = (baseline_threads, native_threads) {
            anyhow::ensure!(
                actual >= baseline + background - 1,
                "native ORT thread pool did not reflect background configuration"
            );
        }
        let (index_seconds, foreground_seconds, overlap) = std::thread::scope(
            |scope| -> Result<_> {
                let barrier = Arc::new(Barrier::new(3));
                let stopped = Arc::new(AtomicBool::new(false));
                let _stop_observer = StopObserver(Arc::clone(&stopped));
                let origin = Instant::now();
                let foreground_barrier = Arc::clone(&barrier);
                let mut reuse = config.clone();
                reuse["reuse_current"] = json!(true);
                let foreground = scope.spawn(move || -> Result<Vec<Value>> {
                foreground_barrier.wait();
                let mut handle = Core::new()?;
                handle.load_model(reuse, &[], &[])?;
                let mut times = Vec::new();
                for _ in 0..3 {
                    let started = Instant::now();
                    let result = handle.call("model_probe", json!({"model":"m3","text":"synthetic foreground query"}))?;
                    anyhow::ensure!(result["ready"] == true && result["dimensions"] == 1024, "foreground inference failed");
                    times.push(json!({"started_seconds":started.duration_since(origin).as_secs_f64(),
                        "finished_seconds":origin.elapsed().as_secs_f64(),"elapsed_seconds":started.elapsed().as_secs_f64()}));
                }
                Ok(times)
            });
                let observer_barrier = Arc::clone(&barrier);
                let observer_stopped = Arc::clone(&stopped);
                let observer = scope.spawn(move || -> Result<Vec<f64>> {
                    observer_barrier.wait();
                    let mut handle = Core::new()?;
                    let mut overlap = Vec::new();
                    while !observer_stopped.load(Ordering::Acquire) {
                        let status =
                            handle.call("engine_control", json!({"action":"inference_status"}))?;
                        if status["foreground"]["active"] == true
                            && status["background"]["active"] == true
                            && overlap.len() < 100
                        {
                            overlap.push(origin.elapsed().as_secs_f64());
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Ok(overlap)
                });
                barrier.wait();
                let mut index = Vec::new();
                for _ in 0..3 {
                    let started = Instant::now();
                    let prepared = core.call("prepare", json!({"model":"m3","content":content}))?;
                    anyhow::ensure!(
                        prepared["artifact"]
                            .as_str()
                            .is_some_and(|artifact| !artifact.is_empty()),
                        "index inference failed"
                    );
                    index.push(json!({"started_seconds":started.duration_since(origin).as_secs_f64(),
                    "finished_seconds":origin.elapsed().as_secs_f64(),"elapsed_seconds":started.elapsed().as_secs_f64()}));
                }
                let foreground = foreground
                    .join()
                    .map_err(|_| anyhow::anyhow!("foreground probe panicked"))??;
                stopped.store(true, Ordering::Release);
                let overlap = observer
                    .join()
                    .map_err(|_| anyhow::anyhow!("overlap observer panicked"))??;
                anyhow::ensure!(
                    !overlap.is_empty(),
                    "no simultaneous native foreground/background activity observed"
                );
                Ok((index, foreground, overlap))
            },
        )?;
        reports.push(json!({"mode":if legacy { "legacy-onnx" } else { "streamed-owned-ort" },
            "foreground_threads":1,"background_threads":background,"native_process_threads":native_threads,
            "background_prepare_seconds":index_seconds,"concurrent_foreground_probe_seconds":foreground_seconds,
            "simultaneous_native_activity_seconds":overlap,
            "cache_policy_mismatch_rejected":true,"legacy_request_defaults_checked":background == 1}));
        core.call("engine_control", json!({"action":"reset"}))?;
    }
    println!("{}", serde_json::to_string_pretty(&Value::Array(reports))?);
    Ok(())
}

//! Foreground supervisor started by the sign-in registration. It owns and
//! restarts the separate `rsrs-runtime` child process; the runtime binary
//! itself never registers, restarts or updates anything.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::{lifecycle, read_registration, Registration};

/// Delay between a failed child attempt and the next start.
const RESTART_DELAY: Duration = Duration::from_secs(60);
/// Child uptime after which the consecutive-failure counter resets.
const STABLE_UPTIME_RESET: Duration = Duration::from_secs(120);
/// Consecutive short-lived failures that trip the circuit breaker.
const MAX_CONSECUTIVE_FAILURES: u8 = 3;

/// Registration entry point (`rsrs runtime supervise --data-dir <root>`).
/// Resolves the managed runtime, spawns `rsrs-runtime serve --supervised` and
/// keeps it alive with a bounded retry budget.
pub(crate) fn supervise(data_dir: &Path) -> Result<()> {
    let root = data_dir
        .canonicalize()
        .with_context(|| format!("invalid --data-dir {}", data_dir.display()))?;
    let config = read_registration(&root)?.context(
        "no startup registration for this installation; enable runtime autostart first",
    )?;
    lifecycle::owned(&config)?;
    // Align this process with the registration environment before resolving
    // the runtime, exactly like the managed foreground run does.
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| {
            key.starts_with("RSRS_")
                || key.starts_with("ONEMEMORY_")
                || key.starts_with("RESPIRE_")
        }) {
            std::env::remove_var(key);
        }
    }
    for (key, value) in &config.environment {
        std::env::set_var(key, value);
    }
    std::env::set_var("RSRS_DATA_DIR", &root);
    // The registered task is the foreground owner. A kill-on-close job keeps a
    // dead supervisor from orphaning the runtime child (Windows 8+ nested jobs
    // preserve the enclosing Task Scheduler job).
    #[cfg(windows)]
    respire_spawn::confine_supervisor_tree()
        .context("cannot establish owned supervisor process tree")?;
    // Unix delivery forwards the signal to the child and exits without
    // counting the shutdown against the retry budget.
    #[cfg(unix)]
    let stopped = {
        let stopped = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
        stopped
    };
    #[cfg(not(unix))]
    let stopped = Arc::new(AtomicBool::new(false));
    let mut failures: u8 = 0;
    loop {
        if !supervise_may_run(&root, &config)? {
            return Ok(());
        }
        let started = Instant::now();
        let plan = match resolve_child_plan() {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!("runtime resolution failed: {error:#}");
                if !failure_backoff(&config, &root, &mut failures, Duration::ZERO)? {
                    return Ok(());
                }
                continue;
            }
        };
        lifecycle::record_supervise_event(&config, "starting");
        let outcome = match plan {
            ChildPlan::Runtime(binary) => {
                let arguments: Vec<std::ffi::OsString> = vec![
                    std::ffi::OsString::from("serve"),
                    std::ffi::OsString::from("--data-dir"),
                    root.clone().into_os_string(),
                    std::ffi::OsString::from("--supervised"),
                ];
                respire_spawn::spawn_binary_with_boot_token(
                    &binary,
                    &arguments,
                    lifecycle::current_boot_token().as_deref(),
                )
                .map(|mut child| wait_child(&mut child, &stopped))
            }
            ChildPlan::Shim => {
                // Split-transition shim: offline hosts and isolated test
                // environments cannot fetch the pinned runtime. Run this same
                // binary through the managed foreground entry in a child; it
                // serves in-process, reports the managed identity and keeps
                // the supervised ownership contract intact.
                let mut command = std::process::Command::new(&config.executable);
                command
                    .args(["runtime", "run", "--managed", &config.id, "--installation-root"])
                    .arg(&root);
                #[cfg(windows)]
                command.arg("--supervised-child");
                command
                    .env_remove("RSRS_RUNTIME_BOOT_TOKEN")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                respire_spawn::spawn_host_control(&mut command)
                    .map(|mut child| wait_child(&mut child, &stopped))
            }
        };
        let uptime = started.elapsed();
        match outcome {
            // Signalled shutdown: the supervisor exits without retrying.
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(status))) if status.success() => {
                lifecycle::record_supervise_event(&config, "exit_ok");
                return Ok(());
            }
            Ok(Ok(Some(_))) => {
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
            Ok(Err(error)) => {
                eprintln!("runtime child supervision failed: {error:#}");
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
            Err(error) => {
                eprintln!("runtime child could not be started: {error:#}");
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
        }
    }
}

/// Wait for the child, honoring a signal flag. `Ok(None)` means the supervisor
/// was signalled and the child has been stopped.
fn wait_child(
    child: &mut std::process::Child,
    stopped: &AtomicBool,
) -> Result<Option<std::process::ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if stopped.load(Ordering::Acquire) {
            let _ = child.kill();
            child.wait().context("cannot reap the stopped runtime child")?;
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// How the supervisor starts the next runtime child.
enum ChildPlan {
    /// A resolved `rsrs-runtime` executable spawned with serve arguments.
    Runtime(PathBuf),
    /// This CLI exe serving in-process through the managed foreground entry
    /// (offline/test fallback during the split transition).
    Shim,
}

/// Resolve the managed runtime binary, migrating away from a legacy combined
/// layout by installing the pinned release on the fly; hosts that cannot
/// fetch it fall back to the in-process shim child.
fn resolve_child_plan() -> Result<ChildPlan> {
    let resolved = crate::runtime_fetch::resolve_runtime_bin();
    if let Ok(crate::runtime_fetch::ResolvedRuntime::LegacyCombined(legacy)) = &resolved {
        eprintln!(
            "legacy combined runtime found at {}; installing the pinned managed runtime",
            legacy.display()
        );
    }
    match resolved {
        Ok(crate::runtime_fetch::ResolvedRuntime::Ready(binary)) => Ok(ChildPlan::Runtime(binary)),
        _ => match crate::runtime_fetch::download_and_install(None, None) {
            Ok(binary) => Ok(ChildPlan::Runtime(binary)),
            Err(_) => Ok(ChildPlan::Shim),
        },
    }
}

/// Record the failure, keep the restart budget bounded and sleep out the retry
/// delay while still honoring disablement. `Ok(false)` stops the supervisor.
fn failure_backoff(
    config: &Registration,
    root: &Path,
    failures: &mut u8,
    uptime: Duration,
) -> Result<bool> {
    lifecycle::record_supervise_event(config, "exit_error");
    if !supervise_may_run(root, config)? {
        return Ok(false);
    }
    if !supervise_retry(failures, uptime) {
        lifecycle::record_supervise_event(config, "crash_limit");
        return Ok(false);
    }
    let deadline = Instant::now() + RESTART_DELAY;
    while Instant::now() < deadline {
        if !supervise_may_run(root, config)? {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(true)
}

/// Continue only while the registration still exists unchanged, enabled and
/// not manually stopped. Identity changes fail loudly instead of silently
/// abandoning a runtime we no longer own.
fn supervise_may_run(root: &Path, expected: &Registration) -> Result<bool> {
    let Some(current) = read_registration(root)? else {
        return Ok(false);
    };
    anyhow::ensure!(
        current.id == expected.id
            && current.owner == expected.owner
            && current.executable == expected.executable,
        "supervised registration identity changed"
    );
    Ok(current.enabled && !current.manually_stopped)
}

/// Bounded retry budget: three consecutive short-lived failures trip the
/// circuit breaker; stable uptime resets the counter.
fn supervise_retry(failures: &mut u8, uptime: Duration) -> bool {
    if uptime >= STABLE_UPTIME_RESET {
        *failures = 0;
    }
    *failures = failures.saturating_add(1);
    *failures < MAX_CONSECUTIVE_FAILURES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_retries_are_bounded_and_reset_only_after_stability() {
        let mut failures = 0;
        assert!(supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(!supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(supervise_retry(&mut failures, Duration::from_secs(120)));
        assert_eq!(failures, 1);
    }
}

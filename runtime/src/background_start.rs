//! Compatibility lifecycle for the unmodified Client2 host command.
//! The explicit background child installs the fixed-scope legacy-host lane.
//! Its loopback/Host/Origin boundary is not authentication of a Client2 process.
use std::io::{BufRead, BufReader, Read};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use respire_commands::net_rpc::{self, Health};

const READY_LIMIT: u64 = 64 * 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn is_unavailable(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<respire_commands::runtime_error::RuntimeError>(),
        Some(respire_commands::runtime_error::RuntimeError::Unavailable)
    )
}

fn read_ready_value(reader: impl Read) -> Result<serde_json::Value> {
    let mut reader = BufReader::new(reader.take(READY_LIMIT + 1));
    let mut frame = Vec::new();
    reader.read_until(b'\n', &mut frame)?;
    anyhow::ensure!(
        frame.len() <= READY_LIMIT as usize && frame.last() == Some(&b'\n'),
        "background Runtime returned an incomplete or oversized readiness frame"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&frame).context("background Runtime readiness is not JSON")?;
    anyhow::ensure!(
        value["startup_complete"] == true,
        "Runtime has not completed configured-mode startup"
    );
    Ok(value)
}

fn read_ready(reader: impl Read) -> Result<Health> {
    serde_json::from_value(read_ready_value(reader)?).context("background Runtime readiness is not a health frame")
}

#[cfg(any(test, target_os = "macos"))]
fn verify_observed_child(value: &serde_json::Value, observer_pid: u32) -> Result<()> {
    let pid = value["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok());
    anyhow::ensure!(observer_pid > 0 && value["exit_observer_pid"] == observer_pid
        && value["startup_complete"] == true && pid.is_some_and(|pid| pid > 0 && pid != observer_pid),
        "private readiness does not identify this observer and its Runtime child");
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn observe_exit() -> Result<i32> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let args: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(args.len() == 3 && args[1] == "--port", "invalid exit observer arguments");
    let port: u16 = args[2].parse()?;
    anyhow::ensure!(port > 0, "invalid exit observer port");
    std::env::set_var("RSRS_RPC_PORT", port.to_string());
    let expected = crate::startup_identity::background_start_context(port)?;
    expected.verify_current()?;
    let mut command = Command::new(expected.image_path());
    command.args(["--runtime-internal", "--runtime-background-internal", "--port", &port.to_string()])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = respire_spawn::spawn_host_control(&mut command)?;
    let reader = child.stdout.take().context("owned Runtime readiness pipe missing")?;
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || { let _ = tx.send(read_ready_value(reader)); });
    let mut value = rx.recv_timeout(READY_TIMEOUT)
        .with_context(|| format!("Runtime readiness uncertain for owned child {}; inspect before retry", child.id()))??;
    let ready: Health = serde_json::from_value(value.clone())?;
    anyhow::ensure!(ready.pid == child.id(), "readiness does not identify the observer's owned child");
    expected.verify(&ready)?;
    value["exit_observer_pid"] = serde_json::json!(std::process::id());
    verify_observed_child(&value, std::process::id())?;
    let published = (|| -> Result<()> {
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(&mut stdout, &value)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        Ok(())
    })();
    // Preserve the actual child's wait status through unchanged Client2's
    // 30-second poll window. Its Darwin API accepts zombies but returns EIO
    // for an already-reaped, zero-length kinfo_proc record.
    while net_rpc::instance_is_running(&ready)? {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(35));
    let status = child.wait()?;
    published?;
    anyhow::ensure!(status.success(), "observed Runtime exited unsuccessfully");
    Ok(0)
}

pub(crate) fn start(flags: &crate::Flags) -> Result<i32> {
    let (_, state) = start_inner(flags)?;
    crate::print_envelope("start", true, 0, None, Some(state));
    Ok(0)
}

pub(crate) fn start_quiet(flags: &crate::Flags) -> Result<Health> {
    start_inner(flags).map(|(health, _)| health)
}

fn start_inner(flags: &crate::Flags) -> Result<(Health, &'static str)> {
    anyhow::ensure!(
        flags.host == "127.0.0.1",
        "background startup currently requires the existing 127.0.0.1 client endpoint"
    );
    let port = flags.port.unwrap_or_else(net_rpc::rpc_port);
    let expected = crate::startup_identity::background_start_context(port)?;
    // Serialize the check/spawn/readiness interval across short-lived host
    // commands. The serving child never takes this launcher-only guard.
    let _launch = respire_app::lock::LibraryLock::acquire(
        &respire_app::service::main_data_dir().join("runtime/background-start"),
        Duration::from_secs(10),
    )
    .context("another background startup still owns the launch interval")?;
    expected.verify_current()?;
    match net_rpc::health() {
        Ok(health) => {
            expected.verify_existing(&health)?;
            // Health can be available while the library/queues are still being
            // initialized. An idempotent start must not convert that into ready.
            let response = ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(2))
                .build()
                .get(&format!("http://127.0.0.1:{port}/api/health"))
                .call()?;
            let mut raw = Vec::new();
            response
                .into_reader()
                .take(READY_LIMIT + 1)
                .read_to_end(&mut raw)?;
            raw.push(b'\n');
            let current = read_ready(&raw[..])?;
            anyhow::ensure!(
                current.pid == health.pid
                    && current.instance_id == health.instance_id
                    && current.process_start_id == health.process_start_id,
                "Runtime changed during repeated start"
            );
            expected.verify_existing(&current)?;
            return Ok((current, "already_running"));
        }
        Err(error) if is_unavailable(&error) => {}
        Err(error) => {
            return Err(error).context("endpoint ownership is uncertain; startup refused")
        }
    }
    #[cfg(not(target_os = "macos"))]
    let args = [
        "--runtime-internal",
        "--runtime-background-internal",
        "--port",
        &port.to_string(),
    ]
    .map(std::ffi::OsString::from);
    #[cfg(target_os = "macos")]
    let args = ["--runtime-exit-observer-internal", "--port", &port.to_string()]
        .map(std::ffi::OsString::from);
    let mut child = respire_spawn::spawn_binary_with_readiness(expected.image_path(), &args)
        .context("cannot spawn the selected Runtime image")?;
    let pid = child.id();
    let output = child
        .stdout
        .take()
        .context("background Runtime readiness pipe is missing")?;
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("runtime-start-readiness".into())
        .spawn(move || {
            let _ = tx.send(read_ready_value(output));
        })?;
    // An uncertain readiness outcome must not cause a second launch, ownership
    // transfer, forced termination, or a fabricated success. Leave any live
    // child for an identity-checked status/stop, and report the exact spawned PID.
    let value = rx
        .recv_timeout(READY_TIMEOUT)
        .with_context(|| {
            format!(
                "Runtime startup is unconfirmed for spawned PID {pid}; inspect status before retry"
            )
        })?
        .with_context(|| format!("Runtime startup failed for spawned PID {pid}"))?;
    let ready: Health = serde_json::from_value(value.clone())?;
    anyhow::ensure!(
        child.try_wait()?.is_none(),
        "background Runtime exited during startup"
    );
    #[cfg(not(target_os = "macos"))]
    anyhow::ensure!(
        ready.pid == pid,
        "readiness does not identify the spawned Runtime child"
    );
    #[cfg(target_os = "macos")]
    verify_observed_child(&value, pid)?;
    expected.verify(&ready)?;
    let live = net_rpc::health().context("initialized Runtime is not reachable")?;
    anyhow::ensure!(
        live.pid == ready.pid
            && live.instance_id == ready.instance_id
            && live.process_start_id == ready.process_start_id,
        "Runtime listener changed after private readiness"
    );
    expected.verify(&live)?;
    Ok((live, "started"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_readiness_requires_the_owned_parent_and_distinct_child() -> Result<()> {
        let value = serde_json::json!({"startup_complete":true, "pid":123, "exit_observer_pid":456});
        verify_observed_child(&value, 456)?;
        for (key, wrong) in [("pid", serde_json::json!(0)), ("pid", serde_json::json!(456)),
            ("pid", serde_json::json!(u64::MAX)), ("exit_observer_pid", serde_json::json!(789)),
            ("startup_complete", serde_json::json!(false))] {
            let mut altered = value.clone();
            altered[key] = wrong;
            assert!(verify_observed_child(&altered, 456).is_err(), "{key}");
        }
        assert!(verify_observed_child(&value, 0).is_err());
        Ok(())
    }

    #[test]
    fn rejects_incomplete_or_oversized_readiness() {
        assert!(read_ready(&b"{}"[..]).is_err());
        assert!(read_ready(&vec![b' '; READY_LIMIT as usize + 1][..]).is_err());
        assert!(read_ready(&b"{\"status\":\"ok\"}\n"[..]).is_err());
    }

    #[test]
    fn accepts_only_the_existing_health_shape() -> Result<()> {
        let frame = b"{\"server\":\"respire\",\"bin\":\"test\",\"pid\":42,\"v\":1,\"startup_complete\":true}\n";
        let health = read_ready(&frame[..])?;
        assert_eq!(health.pid, 42);
        // Parsing alone is never authority: start additionally checks the owned
        // child, exact scope/image, OS process identity and live endpoint.
        Ok(())
    }
}

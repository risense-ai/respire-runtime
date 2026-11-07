//! Shared exact-owner loopback drain and grant-authorized replacement startup.
//! Extracted from CLI rpc::{drain_occupant,wait_daemon_ready}; never force an
//! existing owner. A just-spawned child remains owned by its Child handle.
use crate::{LaunchContext, VerifiedRuntime};
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::net_rpc::{self, Health};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn endpoint_path() -> PathBuf {
    respire_client_host::paths::main_data_dir().join("runtime/endpoint.json")
}

pub fn probe_runtime() -> Result<Option<Health>> {
    match net_rpc::health() {
        Ok(health) => Ok(Some(health)),
        Err(error)
            if matches!(
                error.downcast_ref::<respire_commands::runtime_error::RuntimeError>(),
                Some(respire_commands::runtime_error::RuntimeError::Unavailable)
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn endpoint_pid() -> Result<Option<u32>> {
    let path = respire_client_host::config::normalize_control_path(&endpoint_path())?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(bytes.len() <= 65536, "runtime endpoint record is too large");
    let data: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(data
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok()))
}

pub fn drain_runtime(health: &Health) -> Result<()> {
    let pid = health.pid;
    let (root, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(
        Path::new(&health.installation_root).canonicalize()? == root.canonicalize()?
            && Path::new(&health.data_dir).canonicalize()? == profile.canonicalize()?,
        "runtime restart blocked: owner roots do not match this installation"
    );
    let birth = crate::launch::process_birth(pid)?.context("runtime process already exited")?;
    anyhow::ensure!(
        start_matches(&birth, &health.process_start_id),
        "runtime process birth differs from health"
    );
    let accepted = net_rpc::request_stop_for(health, Duration::from_secs(120))?;
    let operation_id = accepted;
    let deadline = Instant::now() + Duration::from_secs(60);
    while crate::launch::process_birth(pid)?.as_deref() == Some(birth.as_str()) {
        anyhow::ensure!(
            Instant::now() < deadline,
            "runtime drain is still pending; no process was forced to exit"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    net_rpc::final_stop_receipt(health, Some(&operation_id))?;
    net_rpc::wait_until_down()?;
    let released = LibraryLock::acquire(&profile, Duration::from_secs(15))
        .context("stopped runtime has not released its library lock")?;
    if endpoint_path().try_exists()? {
        anyhow::ensure!(
            endpoint_pid()? == Some(pid) && crate::launch::process_birth(pid)?.is_none(),
            "runtime endpoint owner changed after drain; record was not removed"
        );
        std::fs::remove_file(endpoint_path())?;
    }
    drop(released);
    Ok(())
}

fn start_matches(birth: &str, observed: &str) -> bool {
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    !birth.is_empty() && observed.strip_prefix(prefix) == Some(birth)
}

/// A successful return proves this owned child's identity and ready store. The
/// maintenance owner separately verifies the account receipt before completion.
pub fn start_account_runtime(context: &LaunchContext, image: &VerifiedRuntime) -> Result<()> {
    anyhow::ensure!(
        image.port() == net_rpc::rpc_port(),
        "selected Runtime port differs from host transport"
    );
    let (mut child, instance_id) = crate::spawn_serving(context, image)?;
    let result = (|| -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            anyhow::ensure!(
                child.try_wait()?.is_none(),
                "owned account Runtime exited before readiness"
            );
            let Some(health) = probe_runtime()? else {
                continue;
            };
            if !health.store_ready {
                continue;
            }
            let birth =
                crate::launch::process_birth(child.id())?.context("starting Runtime exited")?;
            let process = net_rpc::runtime_process_identity(child.id())?;
            anyhow::ensure!(
                health.pid == child.id()
                    && start_matches(&birth, &health.process_start_id)
                    && health.v == crate::PROTOCOL_V
                    && health.generation > 0
                    && !health.account_id.is_empty()
                    && health.instance_id == instance_id
                    && health.runtime_version == image.version()
                    && Path::new(&health.image_path).canonicalize()? == image.path()
                    && Path::new(&process.executable).canonicalize()? == image.path()
                    && health.image_sha256.eq_ignore_ascii_case(image.sha256())
                    && Path::new(&health.installation_root).canonicalize()?
                        == context.installation_root()
                    && Path::new(&health.data_dir).canonicalize()? == context.profile(),
                "Runtime owner changed during account startup"
            );
            net_rpc::request_scope(&health)?;
            anyhow::ensure!(
                net_rpc::runtime_process_identity(child.id())? == process,
                "Runtime process changed during account startup verification"
            );
            image.revalidate()?;
            return Ok(());
        }
        anyhow::bail!("owned account Runtime did not become ready; query the original operation")
    })();
    if result.is_err() && child.try_wait()?.is_none() {
        child
            .kill()
            .context("failed to stop owned unready Runtime")?;
        child
            .wait()
            .context("failed to reap owned unready Runtime")?;
    }
    result
}

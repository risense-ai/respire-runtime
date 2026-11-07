//! Bounded inherited transport for one owned private-control helper.
//!
//! Extracted from respire-cli 25ef33a23c87b0c00f1430c23d2c5b6c629ec13d,
//! `cli/src/autostart/launch_authorization.rs::exchange_control` and cleanup.
//! The caller supplies coordinator-verified authority and validates the typed
//! result. Transport success is not business completion. Never retry an exchange
//! after a timeout, malformed result, or unconfirmed child exit.
use anyhow::{Context, Result};
use respire_commands::output::ResultEnvelope;
use respire_protocol::{
    HostControlLaunchGrant, RpcRequest, RpcResponse, HOST_CONTROL_MAX_FRAME_BYTES,
};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub(crate) fn exchange_control(
    binary: &Path,
    grant: &HostControlLaunchGrant,
    request: &RpcRequest,
    deadline: Instant,
    validate: impl FnOnce(RpcResponse<ResultEnvelope>, u32) -> Result<ResultEnvelope>,
) -> Result<ResultEnvelope> {
    let mut frames = Vec::new();
    for bytes in [serde_json::to_vec(grant)?, serde_json::to_vec(request)?] {
        append_request_frame(&mut frames, &bytes)?;
    }
    anyhow::ensure!(Instant::now() < deadline, "host control deadline exceeded");
    let mut command = Command::new(&binary);
    command
        .arg("--host-control-internal")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("RSRS_RUNTIME_BOOT_TOKEN");
    let mut child = respire_spawn::spawn_control_helper(&mut command)
        .context("cannot start owned host control Runtime")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let (input_sender, input_receiver) = std::sync::mpsc::channel();
    let mut worker = None;
    let outcome = (|| -> Result<ResultEnvelope> {
        let mut input = child
            .stdin
            .take()
            .context("missing host control input pipe")?;
        let mut output = child
            .stdout
            .take()
            .context("missing host control output pipe")?;
        worker = Some(
            std::thread::Builder::new()
                .name("host-control-io".into())
                .spawn(move || {
                    let response = (|| -> Result<RpcResponse<ResultEnvelope>> {
                        let written = input.write_all(&frames).and_then(|()| input.flush());
                        // Return the writer before blocking on stdout so the owner can revoke it.
                        input_sender.send(input).map_err(|_| {
                            anyhow::anyhow!("host control input owner was released")
                        })?;
                        written.context("host control request write failed")?;
                        read_response(&mut output)
                    })();
                    let _ = sender.send(response);
                })?,
        );
        let response = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .context("host control response deadline or channel failure")?;
        anyhow::ensure!(
            Instant::now() < deadline,
            "host control response deadline exceeded"
        );
        let response = response?;
        let expected_exit = response.exit;
        let envelope = validate(response, child.id())?;
        loop {
            anyhow::ensure!(
                Instant::now() < deadline,
                "host control exit deadline exceeded"
            );
            if let Some(status) = child.try_wait()? {
                anyhow::ensure!(
                    status.code() == Some(expected_exit),
                    "host control Runtime exit does not match its response"
                );
                return Ok(envelope);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    let cleanup = if outcome.is_err() {
        stop_control_child(&mut child)
    } else {
        Ok(())
    };
    // Keep stdin until exit confirmation; on failure release it to revoke the channel.
    drop(input_receiver);
    drop(receiver);
    cleanup?;
    if let Some(worker) = worker {
        let until = Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() {
            anyhow::ensure!(
                Instant::now() < until,
                "cleanup_failed owned_pid={}: host control I/O worker did not finish",
                child.id()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        worker.join().map_err(|_| {
            anyhow::anyhow!(
                "cleanup_failed owned_pid={}: host control I/O worker panicked",
                child.id()
            )
        })?;
    }
    outcome
}

fn stop_control_child(child: &mut Child) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(2);
    let kill_error = child.kill().err();
    loop {
        if control_exit_confirmed(
            child.id(),
            child.try_wait().map(|status| status.is_some()),
            Instant::now() >= until,
            kill_error.as_ref(),
        )? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn control_exit_confirmed(
    pid: u32,
    observation: std::io::Result<bool>,
    expired: bool,
    kill_error: Option<&std::io::Error>,
) -> Result<bool> {
    let reason = match observation {
        // try_wait(Some) has reaped the owned child, even if kill lost an exit race.
        Ok(true) => return Ok(true),
        Ok(false) if !expired => return Ok(false),
        Ok(false) => "exit confirmation deadline exceeded".to_owned(),
        Err(error) => format!("exit confirmation failed: {error}"),
    };
    match kill_error {
        Some(error) => {
            anyhow::bail!("cleanup_failed owned_pid={pid}: {reason}; kill failed: {error}")
        }
        None => anyhow::bail!("cleanup_failed owned_pid={pid}: {reason}"),
    }
}

fn append_request_frame(frames: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= HOST_CONTROL_MAX_FRAME_BYTES,
        "host control request frame exceeds the protocol limit"
    );
    frames.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    frames.extend_from_slice(bytes);
    Ok(())
}

fn read_response(output: &mut impl Read) -> Result<RpcResponse<ResultEnvelope>> {
    let mut length = [0u8; 4];
    output
        .read_exact(&mut length)
        .context("missing host control response frame")?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(
        length > 0 && length <= HOST_CONTROL_MAX_FRAME_BYTES,
        "invalid host control response frame size"
    );
    let mut bytes = vec![0u8; length];
    output
        .read_exact(&mut bytes)
        .context("incomplete host control response frame")?;
    let response = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid host control response JSON"))?;
    let mut extra = [0u8; 1];
    anyhow::ensure!(
        output.read(&mut extra)? == 0,
        "extra host control response bytes"
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_frames_are_length_prefixed_and_bounded() -> Result<()> {
        let mut frames = Vec::new();
        append_request_frame(&mut frames, b"grant")?;
        append_request_frame(&mut frames, b"request")?;
        assert_eq!(frames, b"\0\0\0\x05grant\0\0\0\x07request");
        let before = frames.clone();
        assert!(append_request_frame(&mut frames, b"").is_err());
        assert!(
            append_request_frame(&mut frames, &vec![0; HOST_CONTROL_MAX_FRAME_BYTES + 1]).is_err()
        );
        assert_eq!(frames, before);
        append_request_frame(&mut Vec::new(), &vec![0; HOST_CONTROL_MAX_FRAME_BYTES])?;
        Ok(())
    }

    #[test]
    fn response_requires_one_complete_bounded_json_frame_and_eof() -> Result<()> {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "v": crate::PROTOCOL_V,
            "id": "synthetic-response", "bin": "rsrs-runtime", "pid": 4242,
            "ok": true, "exit": 0,
        }))?;
        let mut frame = Vec::new();
        append_request_frame(&mut frame, &bytes)?;
        assert_eq!(
            read_response(&mut Cursor::new(&frame))?.id,
            "synthetic-response"
        );
        assert!(read_response(&mut Cursor::new(&frame[..3])).is_err());
        assert!(read_response(&mut Cursor::new(&frame[..frame.len() - 1])).is_err());
        assert!(read_response(&mut Cursor::new([0u8; 4])).is_err());
        assert!(read_response(&mut Cursor::new(
            u32::try_from(HOST_CONTROL_MAX_FRAME_BYTES + 1)?.to_be_bytes()
        ))
        .is_err());
        let mut trailing = frame;
        trailing.push(0);
        assert!(read_response(&mut Cursor::new(trailing)).is_err());
        let mut invalid_json = Vec::new();
        append_request_frame(&mut invalid_json, b"private-invalid-json")?;
        let error = read_response(&mut Cursor::new(invalid_json))
            .err()
            .context("invalid JSON must fail")?
            .to_string();
        assert_eq!(error, "invalid host control response JSON");
        Ok(())
    }

    #[test]
    fn cleanup_requires_reaped_exit_even_after_a_kill_race() -> Result<()> {
        let pid = 4242;
        assert!(!control_exit_confirmed(pid, Ok(false), false, None)?);
        assert!(control_exit_confirmed(pid, Ok(true), false, None)?);
        let kill_error = std::io::Error::other("fixture kill failed");
        assert!(control_exit_confirmed(
            pid,
            Ok(true),
            true,
            Some(&kill_error)
        )?);
        let timeout = control_exit_confirmed(pid, Ok(false), true, Some(&kill_error))
            .err()
            .context("cleanup deadline must fail closed")?
            .to_string();
        assert!(timeout.contains("cleanup_failed owned_pid=4242"));
        assert!(timeout.contains("exit confirmation deadline exceeded"));
        assert!(timeout.contains("fixture kill failed"));
        let observation_error = control_exit_confirmed(
            pid,
            Err(std::io::Error::other("fixture observation failed")),
            false,
            None,
        )
        .err()
        .context("cleanup observation error must fail closed")?
        .to_string();
        assert!(observation_error.contains("cleanup_failed owned_pid=4242"));
        assert!(observation_error.contains("fixture observation failed"));
        Ok(())
    }
}

//! Verified, resumable model downloads without app or Core dependencies.
//! Source selection and pinned artifact metadata stay with the installer.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::model_progress;

pub(super) fn file_valid(path: &Path, expected: &str, expected_size: Option<u64>) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    if let Some(size) = expected_size {
        if path.metadata()?.len() != size {
            return Ok(false);
        }
    }
    let actual = sha256_file(path)?;
    Ok(actual.eq_ignore_ascii_case(expected))
}

pub(super) fn sha256_file(path: &Path) -> Result<String> {
    let item = path.file_name().unwrap_or_default().to_string_lossy();
    let total = path.metadata()?.len();
    let mut checked = 0;
    model_progress::update("verify", &item, 0, Some(total))?;
    let mut file =
        File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        checked += n as u64;
        model_progress::update("verify", &item, checked, Some(total))?;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Bound stalled network operations, not the lifetime of a progressing download.
#[derive(Clone, Copy)]
pub struct DownloadTimeouts {
    connect: std::time::Duration,
    read: std::time::Duration,
    write: std::time::Duration,
}

impl Default for DownloadTimeouts {
    fn default() -> Self {
        use std::time::Duration;
        Self {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(30),
            write: Duration::from_secs(10),
        }
    }
}

/// Every source must provide the same pinned artifact. Network/checksum errors
/// advance to the next source; cancellation and local filesystem failures do not.
/// A single explicit source therefore never silently falls back to another host.
pub fn download_with_fallback(
    sources: &[String],
    dest: &Path,
    expected: &str,
    parallel: bool,
    timeouts: DownloadTimeouts,
    expected_size: Option<u64>,
) -> Result<String> {
    let mut failures = Vec::new();
    for url in sources {
        model_progress::check()?;
        let result = if parallel && !dest.exists() {
            download_parallel_with_timeouts(
                url,
                dest,
                expected,
                16 * 1024 * 1024,
                timeouts,
                expected_size,
            )
            .and_then(|used| {
                if used {
                    Ok(())
                } else {
                    download_verified_with_timeouts(url, dest, expected, timeouts, expected_size)
                }
            })
        } else {
            download_verified_with_timeouts(url, dest, expected, timeouts, expected_size)
        };
        match result {
            Ok(()) => {
                // A no-Range fallback may have finished a prior segmented transfer.
                remove_download_parts(dest)?;
                return Ok(url.clone());
            }
            Err(error) => {
                model_progress::check()?;
                if error.downcast_ref::<std::io::Error>().is_some() {
                    return Err(error);
                }
                failures.push(format!("{url}: {error:#}"));
            }
        }
    }
    anyhow::bail!("BGE-M3 download failed: {}", failures.join("; "))
}

#[cfg(test)]
pub(super) fn download_verified(
    url: &str,
    dest: &Path,
    expected: &str,
    expected_size: Option<u64>,
) -> Result<()> {
    download_verified_with_timeouts(
        url,
        dest,
        expected,
        DownloadTimeouts::default(),
        expected_size,
    )
}

fn download_verified_with_timeouts(
    url: &str,
    dest: &Path,
    expected: &str,
    timeouts: DownloadTimeouts,
    expected_size: Option<u64>,
) -> Result<()> {
    download_verified_bounded(url, dest, expected, timeouts, expected_size)
}

fn download_verified_bounded(
    url: &str,
    dest: &Path,
    expected: &str,
    timeouts: DownloadTimeouts,
    expected_size: Option<u64>,
) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if dest.is_file()
        && expected_size
            .is_some_and(|size| dest.metadata().map(|m| m.len() > size).unwrap_or(false))
    {
        std::fs::remove_file(dest)?;
    }
    let offset = if dest.is_file() {
        dest.metadata()?.len()
    } else {
        0
    };
    let resp = match download_response(url, dest, offset, timeouts) {
        Ok(response) => response,
        Err(error)
            if offset > 0
                && error
                    .downcast_ref::<ureq::Error>()
                    .is_some_and(|error| matches!(error, ureq::Error::Status(416, _))) =>
        {
            std::fs::remove_file(dest)?;
            download_response(url, dest, 0, timeouts)?
        }
        Err(error) => return Err(error),
    };
    let resumed = resp.status() == 206;
    let total = if resumed {
        let range = resp
            .header("Content-Range")
            .ok_or_else(|| anyhow!("partial response has no Content-Range"))?;
        let (start, total) = parse_content_range(range)?;
        anyhow::ensure!(
            start == offset,
            "partial response starts at {start}, expected {offset}"
        );
        Some(total)
    } else {
        anyhow::ensure!(
            resp.status() == 200,
            "unexpected download status {}",
            resp.status()
        );
        resp.header("Content-Length")
            .and_then(|v| v.parse::<u64>().ok())
    };
    if let (Some(pinned), Some(reported)) = (expected_size, total) {
        anyhow::ensure!(
            pinned == reported,
            "model size mismatch: response {reported}, expected {pinned}"
        );
    }
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    let mut reader = resp.into_reader();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(resumed)
        .truncate(!resumed)
        .open(dest)
        .with_context(|| format!("failed to write {}", dest.display()))?;
    let mut buf = [0u8; 64 * 1024];
    let mut written: u64 = if resumed { offset } else { 0 };
    loop {
        model_progress::update("download", &item, written, total)?;
        let n = read_download(&mut reader, &mut buf, url)?;
        if n == 0 {
            break;
        }
        if let Some(limit) = expected_size {
            anyhow::ensure!(
                written <= limit && n as u64 <= limit - written,
                "model response exceeds pinned size {limit}"
            );
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("failed to write {}", dest.display()))?;
        written += n as u64;
    }
    file.flush()
        .with_context(|| format!("failed to write {}", dest.display()))?;
    drop(file);
    if let Some(total) = total {
        anyhow::ensure!(
            written == total,
            "download incomplete: {written}/{total} bytes; partial file retained"
        );
    }
    if let Some(expected) = expected_size {
        anyhow::ensure!(
            written == expected,
            "model size mismatch: {written}/{expected}"
        );
    }
    model_progress::update("verify", &item, written, Some(written))?;
    let actual = sha256_file(dest)?;
    if !actual.eq_ignore_ascii_case(expected) {
        // A saved prefix can be corrupt. Retry this source once from byte zero;
        // the fresh request cannot enter this branch with a nonzero offset.
        if resumed && offset > 0 {
            std::fs::remove_file(dest)?;
            return download_verified_bounded(url, dest, expected, timeouts, expected_size);
        }
        // Unknown-length EOF may be a truncated response. Preserve resumable bytes.
        if total.is_some() {
            std::fs::remove_file(dest)?;
        }
        anyhow::bail!(
            "checksum failed: {} SHA256={actual} (expected {expected})",
            dest.display()
        );
    }
    Ok(())
}

fn parse_content_range(value: &str) -> Result<(u64, u64)> {
    let value = value
        .strip_prefix("bytes ")
        .ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (range, total) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let start = start.parse::<u64>()?;
    let end = end.parse::<u64>()?;
    let total = total.parse::<u64>()?;
    anyhow::ensure!(start <= end && end < total, "invalid Content-Range bounds");
    Ok((start, total))
}

fn download_parts_path(dest: &Path) -> PathBuf {
    // Preserve the existing partial-directory name across installer upgrades.
    dest.with_extension("onnx.parts")
}

pub(super) fn remove_download_parts(dest: &Path) -> Result<()> {
    match std::fs::remove_dir_all(download_parts_path(dest)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to remove completed model segments"),
    }
}

/// Four persistent ranges. Only the coordinator updates task state; workers
/// receive cancellation through a shared flag and retain their partial files.
#[cfg(test)]
fn download_parallel(
    url: &str,
    dest: &Path,
    expected: &str,
    minimum: u64,
    expected_size: Option<u64>,
) -> Result<bool> {
    download_parallel_with_timeouts(
        url,
        dest,
        expected,
        minimum,
        DownloadTimeouts::default(),
        expected_size,
    )
}

fn download_parallel_with_timeouts(
    url: &str,
    dest: &Path,
    expected: &str,
    minimum: u64,
    timeouts: DownloadTimeouts,
    expected_size: Option<u64>,
) -> Result<bool> {
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    };
    use std::time::Duration;
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, 0, None)?;
    let response = download_agent(timeouts)
        .get(url)
        .set("Accept-Encoding", "identity")
        .set("Range", "bytes=0-0")
        .call()
        .with_context(|| format!("download probe failed ({url})"))?;
    model_progress::check()?;
    if response.status() == 200 {
        return Ok(false);
    }
    anyhow::ensure!(response.status() == 206, "unexpected range probe status");
    let range = response
        .header("Content-Range")
        .ok_or_else(|| anyhow!("range probe has no Content-Range"))?;
    let (start, total) = parse_content_range(range)?;
    anyhow::ensure!(start == 0, "range probe starts at {start}");
    if let Some(pinned) = expected_size {
        anyhow::ensure!(
            total == pinned,
            "model size mismatch: response {total}, expected {pinned}"
        );
    }
    drop(response);
    if total < minimum || total < 4 {
        return Ok(false);
    }
    let parts = download_parts_path(dest);
    std::fs::create_dir_all(&parts)?;
    for index in 0..4 {
        let path = parts.join(index.to_string());
        let length = total * (index + 1) / 4 - total * index / 4;
        if path.is_file() && path.metadata()?.len() > length {
            // Stale or corrupt segment lengths cannot be safely resumed.
            std::fs::remove_dir_all(&parts)?;
            std::fs::create_dir_all(&parts)?;
            break;
        }
    }
    let counts: [AtomicU64; 4] = std::array::from_fn(|_| AtomicU64::new(0));
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::channel();
    let result = std::thread::scope(|scope| -> Result<()> {
        for (index, count) in counts.iter().enumerate() {
            let begin = total * index as u64 / 4;
            let end = total * (index + 1) as u64 / 4;
            let path = parts.join(index.to_string());
            let sender = sender.clone();
            let stop = &stop;
            scope.spawn(move || {
                let result = download_part(url, &path, begin, end, total, count, stop, timeouts);
                let failed = result.is_err();
                let _ = sender.send(result);
                if failed {
                    stop.store(true, Ordering::Relaxed);
                }
            });
        }
        drop(sender);
        let mut finished = 0;
        let mut failure = None;
        while finished < 4 {
            let done = counts
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .sum();
            if let Err(error) = model_progress::update("download", &item, done, Some(total)) {
                stop.store(true, Ordering::Relaxed);
                if failure.is_none() {
                    failure = Some(error);
                }
            }
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(result) => {
                    finished += 1;
                    if let Err(error) = result {
                        // A concurrent network failure must not hide a disk failure
                        // reported by another worker and turn it into a failover.
                        if failure.is_none() || error.downcast_ref::<std::io::Error>().is_some() {
                            failure = Some(error);
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("download workers disconnected")
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    });
    result?;
    let mut merged = File::create(dest)?;
    for index in 0..4 {
        model_progress::check()?;
        std::io::copy(&mut File::open(parts.join(index.to_string()))?, &mut merged)?;
    }
    merged.flush()?;
    drop(merged);
    if !file_valid(dest, expected, expected_size)? {
        std::fs::remove_file(dest)?;
        std::fs::remove_dir_all(&parts)?;
        // A corrupt saved prefix must not exhaust the final healthy source.
        // Discard every segment and retry that source once from byte zero.
        download_verified_with_timeouts(url, dest, expected, timeouts, expected_size)?;
        return Ok(true);
    }
    std::fs::remove_dir_all(parts)?;
    Ok(true)
}

fn download_part(
    url: &str,
    path: &Path,
    begin: u64,
    end: u64,
    total: u64,
    count: &std::sync::atomic::AtomicU64,
    stop: &std::sync::atomic::AtomicBool,
    timeouts: DownloadTimeouts,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    let length = end - begin;
    let mut offset = if path.is_file() {
        path.metadata()?.len()
    } else {
        0
    };
    anyhow::ensure!(offset <= length, "saved download segment is too long");
    count.store(offset, Ordering::Relaxed);
    if offset == length {
        return Ok(());
    }
    anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
    let start = begin + offset;
    let response = download_agent(timeouts)
        .get(url)
        .set("Accept-Encoding", "identity")
        .set("Range", &format!("bytes={start}-{}", end - 1))
        .call()
        .with_context(|| format!("segment download failed ({url})"))?;
    anyhow::ensure!(
        response.status() == 206,
        "source did not honor the segment range"
    );
    let expected_range = format!("bytes {start}-{}/{total}", end - 1);
    anyhow::ensure!(
        response.header("Content-Range") == Some(expected_range.as_str()),
        "source returned an incorrect segment range"
    );
    let mut reader = response.into_reader();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    while offset < length {
        anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
        let limit = buffer.len().min((length - offset) as usize);
        let received = reader
            .read(&mut buffer[..limit])
            .map_err(|error| anyhow!("segment interrupted ({url}): {error}"))?;
        anyhow::ensure!(
            received > 0,
            "segment download incomplete; partial bytes retained"
        );
        file.write_all(&buffer[..received])?;
        offset += received as u64;
        count.store(offset, Ordering::Relaxed);
    }
    file.flush()?;
    Ok(())
}

fn download_agent(timeouts: DownloadTimeouts) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeouts.connect)
        .timeout_read(timeouts.read)
        .timeout_write(timeouts.write)
        .build()
}

fn download_response(
    url: &str,
    dest: &Path,
    offset: u64,
    timeouts: DownloadTimeouts,
) -> Result<ureq::Response> {
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, offset, None)?;
    // Headers and body reads share the same bounded idle wait. No total deadline
    // cuts off a large model while bytes are still arriving.
    let request = download_agent(timeouts)
        .get(url)
        .set("Accept-Encoding", "identity");
    let request = if offset > 0 {
        request.set("Range", &format!("bytes={offset}-"))
    } else {
        request
    };
    let response = request.call();
    model_progress::check()?;
    response.with_context(|| format!("download failed ({url})"))
}

fn read_download(reader: &mut impl Read, buf: &mut [u8], url: &str) -> Result<usize> {
    let result = reader.read(buf);
    model_progress::check()?;
    result.map_err(|error| anyhow!("download interrupted ({url}): {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn bounded_download_rejects_headers_stream_overflow_and_short_eof() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        for (headers, body, valid) in [
            ("Content-Length: 4\r\n", "abcd", false),
            (
                "Transfer-Encoding: chunked\r\n",
                "4\r\nabcd\r\n0\r\n\r\n",
                false,
            ),
            ("", "ab", false),
            ("Content-Length: 3\r\n", "abc", true),
        ] {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join("model");
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let url = format!("http://{}/model", listener.local_addr()?);
            let response = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{headers}\r\n{body}");
            let worker = std::thread::spawn(move || -> Result<()> {
                let (mut socket, _) = listener.accept()?;
                socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    anyhow::ensure!(socket.read(&mut byte)? == 1, "request ended early");
                    request.push(byte[0]);
                }
                socket.write_all(response.as_bytes())?;
                Ok(())
            });
            let result =
                download_verified_bounded(&url, &target, expected, fast_timeouts(), Some(3));
            worker.join().map_err(|_| anyhow!("server panicked"))??;
            assert_eq!(result.is_ok(), valid, "unexpected result: {result:?}");
            if target.exists() {
                assert!(target.metadata()?.len() <= 3);
            }
        }
        Ok(())
    }

    fn fast_timeouts() -> DownloadTimeouts {
        use std::time::Duration;
        DownloadTimeouts {
            connect: Duration::from_millis(500),
            read: Duration::from_millis(200),
            write: Duration::from_millis(500),
        }
    }

    /// Hold the connection open until the test releases it, so advancing to the
    /// next source proves the client timeout fired rather than the server's EOF.
    fn stalled_source(
        body: Option<(&[u8], usize)>,
    ) -> Result<(
        String,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<Result<()>>,
    )> {
        use std::time::Duration;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/model", listener.local_addr()?);
        let body = body.map(|(prefix, total)| (prefix.to_vec(), total));
        let (release, wait) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || -> Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                anyhow::ensure!(
                    socket.read(&mut byte)? == 1,
                    "request closed before headers"
                );
                request.push(byte[0]);
            }
            if let Some((prefix, total)) = body {
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
                )?;
                socket.write_all(&prefix)?;
                socket.flush()?;
            }
            wait.recv_timeout(Duration::from_secs(10))?;
            Ok(())
        });
        Ok((url, release, server))
    }

    fn responding_source(
        body: &[u8],
        offset: usize,
    ) -> Result<(String, std::thread::JoinHandle<Result<()>>)> {
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let body = body.to_vec();
        let worker = std::thread::spawn(move || -> Result<()> {
            let request = server
                .recv_timeout(std::time::Duration::from_secs(5))?
                .ok_or_else(|| anyhow!("fallback source not requested"))?;
            let range = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("Range"));
            let response = if offset > 0 {
                assert_eq!(
                    range.map(|header| header.value.as_str()),
                    Some(format!("bytes={offset}-").as_str())
                );
                tiny_http::Response::from_data(body[offset..].to_vec())
                    .with_status_code(206)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            "Content-Range",
                            format!("bytes {offset}-{}/{}", body.len() - 1, body.len()),
                        )
                        .map_err(|_| anyhow!("invalid test header"))?,
                    )
            } else {
                assert!(range.is_none());
                tiny_http::Response::from_data(body)
            };
            request.respond(response)?;
            Ok(())
        });
        Ok((url, worker))
    }

    #[test]
    fn stalled_headers_and_body_fail_over_and_resume_without_waiting_for_eof() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body = b"pinned artifact from healthy fallback";
        let expected = hex::encode(Sha256::digest(body));
        for offset in [0, 7] {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join("model.ort");
            let prefix = if offset == 0 {
                None
            } else {
                Some((&body[..offset], body.len()))
            };
            let (first, release, stalled) = stalled_source(prefix)?;
            let (second, healthy) = responding_source(body, offset)?;
            let started = std::time::Instant::now();
            let result = download_with_fallback(
                &[first, second.clone()],
                &target,
                &expected,
                false,
                fast_timeouts(),
                None,
            );
            let elapsed = started.elapsed();
            release.send(())?;
            stalled
                .join()
                .map_err(|_| anyhow!("stalled source panicked"))??;
            healthy
                .join()
                .map_err(|_| anyhow!("healthy source panicked"))??;
            assert_eq!(result?, second);
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "fallback was not bounded: {elapsed:?}"
            );
            assert_eq!(std::fs::read(target)?, body);
        }
        Ok(())
    }

    #[test]
    fn stalled_range_probe_fails_over_without_publishing_unverified_bytes() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let parts = download_parts_path(&target);
        std::fs::create_dir_all(&parts)?;
        std::fs::write(
            parts.join("0"),
            b"saved segment from an interrupted range source",
        )?;
        let body = b"healthy model";
        let expected = hex::encode(Sha256::digest(body));
        let (first, release, stalled) = stalled_source(None)?;
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let second = format!("http://{}/model", server.server_addr());
        let healthy = std::thread::spawn(move || -> Result<()> {
            let probe = server
                .recv_timeout(std::time::Duration::from_secs(5))?
                .ok_or_else(|| anyhow!("probe missing"))?;
            assert!(probe
                .headers()
                .iter()
                .any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=0-0"));
            probe.respond(tiny_http::Response::from_data(body.to_vec()))?;
            let request = server
                .recv_timeout(std::time::Duration::from_secs(5))?
                .ok_or_else(|| anyhow!("full request missing"))?;
            request.respond(tiny_http::Response::from_data(body.to_vec()))?;
            Ok(())
        });
        let result = download_with_fallback(
            &[first, second.clone()],
            &target,
            &expected,
            true,
            fast_timeouts(),
            None,
        );
        release.send(())?;
        stalled
            .join()
            .map_err(|_| anyhow!("stalled source panicked"))??;
        healthy
            .join()
            .map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(result?, second);
        assert_eq!(std::fs::read(target)?, body);
        assert!(
            !parts.exists(),
            "no-Range fallback left unused CPU segments behind"
        );
        Ok(())
    }

    #[test]
    fn progressing_transfer_outlives_the_per_read_timeout() -> Result<()> {
        use std::time::Duration;
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let body = b"abcdefgh";
        let expected = hex::encode(Sha256::digest(body));
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/model", listener.local_addr()?);
        let worker = std::thread::spawn(move || -> Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_nodelay(true)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                anyhow::ensure!(
                    socket.read(&mut byte)? == 1,
                    "request closed before headers"
                );
                request.push(byte[0]);
            }
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            for byte in body {
                socket.write_all(&[*byte])?;
                socket.flush()?;
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        });
        let timeouts = DownloadTimeouts {
            read: Duration::from_millis(500),
            ..fast_timeouts()
        };
        let started = std::time::Instant::now();
        download_with_fallback(&[url], &target, &expected, false, timeouts, None)?;
        assert!(started.elapsed() > timeouts.read);
        worker
            .join()
            .map_err(|_| anyhow!("progressing source panicked"))??;
        assert_eq!(std::fs::read(target)?, body);
        Ok(())
    }

    #[test]
    fn corrupt_source_is_rejected_before_clean_fallback() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let expected = hex::encode(Sha256::digest(b"trusted model"));
        let (first, corrupt) = responding_source(b"corrupt model", 0)?;
        let (second, healthy) = responding_source(b"trusted model", 0)?;
        assert_eq!(
            download_with_fallback(
                &[first, second.clone()],
                &target,
                &expected,
                false,
                fast_timeouts(),
                None
            )?,
            second
        );
        corrupt
            .join()
            .map_err(|_| anyhow!("corrupt source panicked"))??;
        healthy
            .join()
            .map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(std::fs::read(target)?, b"trusted model");
        Ok(())
    }

    #[test]
    fn failed_source_releases_operation_slot_and_can_retry() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model.ort");
        let body = b"verified retry";
        let expected = hex::encode(Sha256::digest(body));
        let (first, release, stalled) = stalled_source(None)?;
        let failed = {
            let _operation = model_progress::Operation::begin_download()?;
            let result =
                download_with_fallback(&[first], &target, &expected, false, fast_timeouts(), None);
            assert_eq!(model_progress::status()?["active"], true);
            result
        };
        release.send(())?;
        stalled
            .join()
            .map_err(|_| anyhow!("stalled source panicked"))??;
        assert!(failed.is_err());
        assert!(!target.exists());
        assert_eq!(model_progress::status()?["active"], false);
        let (second, healthy) = responding_source(body, 0)?;
        {
            let _operation = model_progress::Operation::begin_download()?;
            download_with_fallback(&[second], &target, &expected, false, fast_timeouts(), None)?;
        }
        healthy
            .join()
            .map_err(|_| anyhow!("healthy source panicked"))??;
        assert_eq!(model_progress::status()?["active"], false);
        assert_eq!(std::fs::read(target)?, body);
        Ok(())
    }

    #[test]
    fn local_disk_failure_is_not_retried_as_a_mirror_outage() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let parent = dir.path().join("not-a-directory");
        std::fs::write(&parent, b"keep")?;
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let error = download_with_fallback(
            &[url.clone(), url],
            &parent.join("model.ort"),
            "unused",
            false,
            fast_timeouts(),
            None,
        )
        .unwrap_err();
        assert!(
            error.downcast_ref::<std::io::Error>().is_some(),
            "disk failure identity lost: {error:#}"
        );
        assert!(server
            .recv_timeout(std::time::Duration::from_millis(10))?
            .is_none());
        assert_eq!(std::fs::read(parent)?, b"keep");
        Ok(())
    }

    #[test]
    fn partial_download_resumes_across_sources_and_ignoring_range_restarts_safely() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body = b"pinned model contents";
        let expected = hex::encode(Sha256::digest(body));
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial.bin");
        for supports_range in [true, false] {
            std::fs::write(&target, &body[..7])?;
            let server =
                tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
            let url = format!("http://{}/model", server.server_addr());
            let worker = std::thread::spawn(move || -> Result<()> {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(10))?
                    .ok_or_else(|| anyhow!("download not requested"))?;
                assert!(request.headers().iter().any(
                    |header| header.field.equiv("Range") && header.value.as_str() == "bytes=7-"
                ));
                let response = if supports_range {
                    tiny_http::Response::from_data(body[7..].to_vec())
                        .with_status_code(206)
                        .with_header(
                            tiny_http::Header::from_bytes(
                                "Content-Range",
                                format!("bytes 7-{}/{}", body.len() - 1, body.len()),
                            )
                            .map_err(|_| anyhow!("invalid test header"))?,
                        )
                } else {
                    tiny_http::Response::from_data(body.to_vec())
                };
                request.respond(response)?;
                Ok(())
            });
            download_verified(&url, &target, &expected, None)?;
            worker.join().map_err(|_| anyhow!("server panicked"))??;
            assert_eq!(std::fs::read(&target)?, body);
        }
        assert!(parse_content_range("bytes 8-9/9").is_err());
        assert!(parse_content_range("bytes 8-7/10").is_err());
        Ok(())
    }

    #[test]
    fn four_parallel_ranges_resume_saved_segments_and_verify_the_merged_file() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body: Vec<u8> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
        let expected = hex::encode(Sha256::digest(&body));
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model_quantized.onnx");
        let parts = target.with_extension("onnx.parts");
        std::fs::create_dir(&parts)?;
        for index in 0..4 {
            let begin = body.len() * index / 4;
            std::fs::write(parts.join(index.to_string()), &body[begin..begin + 3])?;
        }
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let source = body.clone();
        let worker = std::thread::spawn(move || -> Result<()> {
            let header = |value: String| {
                tiny_http::Header::from_bytes("Content-Range", value)
                    .map_err(|_| anyhow!("invalid test header"))
            };
            let probe = server
                .recv_timeout(std::time::Duration::from_secs(10))?
                .ok_or_else(|| anyhow!("probe missing"))?;
            probe.respond(
                tiny_http::Response::from_data(vec![source[0]])
                    .with_status_code(206)
                    .with_header(header(format!("bytes 0-0/{}", source.len()))?),
            )?;
            // Hold all four responses until all requests arrive. A sequential
            // implementation times out here instead of passing this test.
            let mut requests = Vec::new();
            for _ in 0..4 {
                requests.push(
                    server
                        .recv_timeout(std::time::Duration::from_secs(10))?
                        .ok_or_else(|| anyhow!("four concurrent requests did not arrive"))?,
                );
            }
            for request in requests {
                let range = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Range"))
                    .ok_or_else(|| anyhow!("segment Range missing"))?
                    .value
                    .as_str();
                let (start, end) = range
                    .strip_prefix("bytes=")
                    .and_then(|value| value.split_once('-'))
                    .ok_or_else(|| anyhow!("bad range"))?;
                let start = start.parse::<usize>()?;
                let end = end.parse::<usize>()?;
                assert_eq!(start % (source.len() / 4), 3);
                request.respond(
                    tiny_http::Response::from_data(source[start..=end].to_vec())
                        .with_status_code(206)
                        .with_header(header(format!("bytes {start}-{end}/{}", source.len()))?),
                )?;
            }
            Ok(())
        });
        assert!(download_parallel(&url, &target, &expected, 0, None)?);
        worker.join().map_err(|_| anyhow!("source panicked"))??;
        assert_eq!(std::fs::read(target)?, body);
        assert!(!parts.exists());
        Ok(())
    }

    #[test]
    fn corrupt_or_overlong_parallel_segments_restart_cleanly_on_the_same_source() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let body: Vec<u8> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
        let expected = hex::encode(Sha256::digest(&body));
        for overlong in [false, true] {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join("model.ort");
            let parts = download_parts_path(&target);
            std::fs::create_dir(&parts)?;
            for index in 0..4 {
                let bad_length = if overlong { body.len() / 4 + 1 } else { 3 };
                std::fs::write(parts.join(index.to_string()), vec![255; bad_length])?;
            }
            let server =
                tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
            let url = format!("http://{}/model", server.server_addr());
            let source = body.clone();
            let worker = std::thread::spawn(move || -> Result<()> {
                let header = |value: String| {
                    tiny_http::Header::from_bytes("Content-Range", value)
                        .map_err(|_| anyhow!("invalid test header"))
                };
                let next = || {
                    server
                        .recv_timeout(std::time::Duration::from_secs(5))?
                        .ok_or_else(|| anyhow!("download request missing"))
                };
                next()?.respond(
                    tiny_http::Response::from_data(vec![source[0]])
                        .with_status_code(206)
                        .with_header(header(format!("bytes 0-0/{}", source.len()))?),
                )?;
                for _ in 0..4 {
                    let request = next()?;
                    let range = request
                        .headers()
                        .iter()
                        .find(|header| header.field.equiv("Range"))
                        .ok_or_else(|| anyhow!("segment Range missing"))?
                        .value
                        .as_str();
                    let (start, end) = range
                        .strip_prefix("bytes=")
                        .and_then(|value| value.split_once('-'))
                        .ok_or_else(|| anyhow!("bad range"))?;
                    let start = start.parse::<usize>()?;
                    let end = end.parse::<usize>()?;
                    assert_eq!(start % (source.len() / 4), if overlong { 0 } else { 3 });
                    request.respond(
                        tiny_http::Response::from_data(source[start..=end].to_vec())
                            .with_status_code(206)
                            .with_header(header(format!("bytes {start}-{end}/{}", source.len()))?),
                    )?;
                }
                if !overlong {
                    let fresh = next()?;
                    assert!(!fresh
                        .headers()
                        .iter()
                        .any(|header| header.field.equiv("Range")));
                    fresh.respond(tiny_http::Response::from_data(source))?;
                }
                Ok(())
            });
            assert!(download_parallel_with_timeouts(
                &url,
                &target,
                &expected,
                0,
                fast_timeouts(),
                None
            )?);
            worker
                .join()
                .map_err(|_| anyhow!("range source panicked"))??;
            assert_eq!(std::fs::read(target)?, body);
            assert!(!parts.exists());
        }
        Ok(())
    }

    #[test]
    fn unknown_length_partial_is_retained_and_resumed_after_checksum_failure() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial");
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let handler =
            std::thread::spawn(move || -> Result<()> {
                let request = server.recv()?;
                request.respond(tiny_http::Response::new(
                    tiny_http::StatusCode(200),
                    vec![],
                    std::io::Cursor::new(b"abc"),
                    None,
                    None,
                ))?;
                let request = server.recv()?;
                assert!(request.headers().iter().any(
                    |header| header.field.equiv("Range") && header.value.as_str() == "bytes=3-"
                ));
                let range = tiny_http::Header::from_bytes("Content-Range", "bytes 3-5/6")
                    .map_err(|_| anyhow!("range header"))?;
                request.respond(
                    tiny_http::Response::from_string("def")
                        .with_status_code(206)
                        .with_header(range),
                )?;
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(10))?
                    .ok_or_else(|| anyhow!("corrupt-prefix resume request missing"))?;
                assert!(request.headers().iter().any(
                    |header| header.field.equiv("Range") && header.value.as_str() == "bytes=3-"
                ));
                let range = tiny_http::Header::from_bytes("Content-Range", "bytes 3-5/6")
                    .map_err(|_| anyhow!("range header"))?;
                request.respond(
                    tiny_http::Response::from_string("def")
                        .with_status_code(206)
                        .with_header(range),
                )?;
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(10))?
                    .ok_or_else(|| anyhow!("fresh request after corrupt prefix missing"))?;
                assert!(!request
                    .headers()
                    .iter()
                    .any(|header| header.field.equiv("Range")));
                request.respond(tiny_http::Response::from_string("abcdef"))?;
                Ok(())
            });
        let expected = hex::encode(Sha256::digest(b"abcdef"));
        assert!(download_verified(&url, &target, &expected, None).is_err());
        assert_eq!(std::fs::read(&target)?, b"abc");
        download_verified(&url, &target, &expected, None)?;
        assert_eq!(std::fs::read(&target)?, b"abcdef");
        std::fs::write(&target, b"bad")?;
        download_verified(&url, &target, &expected, None)?;
        handler
            .join()
            .map_err(|_| anyhow!("test server panicked"))??;
        assert_eq!(std::fs::read(target)?, b"abcdef");
        Ok(())
    }
}

/// Download sources all serve the same pinned BGE-M3 files.
pub const MIRRORS: &[&str] = &[
    "auto",
    "https://hf-mirror.com",
    "https://hf-mirror.net",
    "https://huggingface.co",
];

pub fn validate_mirror(value: &str) -> Result<()> {
    if value == "auto" {
        return Ok(());
    }
    origin_from_mirror(value).map(|_| ())
}

pub(crate) fn origin_from_mirror(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("--mirror must not be empty");
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let Some((scheme, rest)) = with_scheme.split_once("://") else {
        anyhow::bail!("--mirror is invalid: {raw}");
    };
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("--mirror only supports http/https");
    }
    let hostport = match rest.split('/').next() {
        Some(h) if !h.is_empty() => h.trim(),
        _ => anyhow::bail!("--mirror is missing a host"),
    };
    anyhow::ensure!(
        !hostport.contains(['@', '?', '#']) && !hostport.chars().any(char::is_whitespace),
        "mirror must be a host without credentials, query or fragment"
    );
    Ok(format!("{scheme}://{hostport}"))
}

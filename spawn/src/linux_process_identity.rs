//! Bounded termination of one checked Linux process through a stable pidfd.
//! This does not terminate descendants or provide full forced recovery.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// Field 22 of /proc/PID/stat, in clock ticks since boot.
    pub birth: u64,
    /// The OS path returned by /proc/PID/exe, without lossy UTF-8 conversion.
    pub executable: PathBuf,
}

fn syscall_error(operation: &str, error: io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(libc::ENOSYS) => io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{operation} is unavailable; stable-reference termination refused: {error}"),
        ),
        Some(libc::EPERM) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{operation} denied; permissions will not be changed: {error}"),
        ),
        _ => error,
    }
}

fn checked_pid(pid: u32) -> io::Result<libc::pid_t> {
    match libc::pid_t::try_from(pid) {
        Ok(value) if value > 0 && pid != std::process::id() => Ok(value),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid runtime PID or refusing to terminate the current process",
        )),
    }
}

pub(crate) fn open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a positive PID and zero flags, with no pointers.
    // libc syscall numbers cover x86_64/aarch64 on both GNU and musl.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0 as libc::c_uint) };
    if fd < 0 {
        return Err(syscall_error("pidfd_open", io::Error::last_os_error()));
    }
    // SAFETY: successful pidfd_open returns a new, uniquely owned CLOEXEC fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

fn poll_exited(process: &OwnedFd, timeout_ms: libc::c_int) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: process.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized, writable pollfd with a live owned descriptor.
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        return Ok(false);
    }
    if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(io::Error::other("runtime pidfd poll failed"));
    }
    if descriptor.revents & libc::POLLIN != 0 {
        return Ok(true);
    }
    Err(io::Error::other("unexpected runtime pidfd poll events"))
}

fn stat_birth(stat: &[u8], pid: u32) -> io::Result<u64> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid runtime procfs identity",
        )
    };
    // comm may contain spaces, ')' and non-UTF-8 bytes. Fields after its last
    // delimiter are ASCII; field 22 is index 19 when starting at field 3.
    if !stat.starts_with(format!("{pid} (").as_bytes()) {
        return Err(invalid());
    }
    let end = stat
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(invalid)?;
    let mut fields = stat[end + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let state = fields.next().ok_or_else(invalid)?;
    if state.len() != 1 || !b"RSDTtKWPI".contains(&state[0]) {
        return Err(invalid());
    }
    let birth = fields.nth(18).ok_or_else(invalid)?;
    if birth.is_empty() || !birth.iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    std::str::from_utf8(birth)
        .map_err(|_| invalid())?
        .parse()
        .map_err(|_| invalid())
}

fn verify(process: &OwnedFd, pid: u32, expected: &ProcessIdentity) -> io::Result<()> {
    // A live pidfd alone does not pin numeric /proc paths. Require the same PID
    // namespace and check pidfd liveness after reading, before sending anything.
    stat_birth(&std::fs::read("/proc/self/stat")?, std::process::id())?;
    if poll_exited(process, 0)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "runtime already exited",
        ));
    }
    let directory = PathBuf::from(format!("/proc/{pid}"));
    let current = ProcessIdentity {
        birth: stat_birth(&std::fs::read(directory.join("stat"))?, pid)?,
        executable: std::fs::read_link(directory.join("exe"))?,
    };
    if &current != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime process identity changed",
        ));
    }
    if poll_exited(process, 0)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "runtime exited during identity verification",
        ));
    }
    Ok(())
}

fn wait_for_exit(process: &OwnedFd, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime exit was not confirmed before the pidfd deadline",
            ));
        }
        let milliseconds = remaining.as_millis().clamp(1, libc::c_int::MAX as u128);
        match poll_exited(process, milliseconds as libc::c_int) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Terminate only the instance matching the caller's previously verified birth
/// and OS image. Success means this pidfd reported exit, not descendant cleanup.
/// Unsupported kernels and denied syscalls fail closed without a PID fallback.
/// A pidfd pins process lifetime; it does not prevent a concurrent exec.
pub fn terminate_runtime(pid: u32, expected: &ProcessIdentity) -> io::Result<()> {
    let process = open(checked_pid(pid)?)?;
    verify(&process, pid, expected)?;
    // SAFETY: the owned pidfd binds SIGKILL to the checked process instance;
    // null siginfo and zero flags request ordinary signal delivery.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            process.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0 as libc::c_uint,
        )
    };
    if result < 0 {
        return Err(syscall_error(
            "pidfd_send_signal",
            io::Error::last_os_error(),
        ));
    }
    wait_for_exit(&process, EXIT_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_stat(pid: u32, name: &[u8], state: &str, birth: &str) -> Vec<u8> {
        let mut stat = format!("{pid} (").into_bytes();
        stat.extend_from_slice(name);
        stat.extend_from_slice(format!(") {state} {} {birth} 0\n", ["0"; 18].join(" ")).as_bytes());
        stat
    }

    #[test]
    fn proc_stat_checks_pid_state_and_birth_without_decoding_comm() -> io::Result<()> {
        let valid = fixture_stat(42, b"name ) with \xff", "S", "123456");
        assert_eq!(stat_birth(&valid, 42)?, 123456);
        assert!(stat_birth(&valid, 43).is_err());
        for state in ["Z", "X", "x", "?", "SS"] {
            assert!(stat_birth(&fixture_stat(42, b"name", state, "1"), 42).is_err());
        }
        for birth in ["bad", "-1", "+1", "18446744073709551616"] {
            assert!(stat_birth(&fixture_stat(42, b"name", "S", birth), 42).is_err());
        }
        assert!(stat_birth(b"42 (truncated", 42).is_err());
        assert!(stat_birth(b"42 (name) S 0", 42).is_err());
        Ok(())
    }

    #[test]
    fn invalid_pids_and_unsupported_or_denied_syscalls_fail_closed() {
        for pid in [0, u32::MAX, std::process::id()] {
            assert!(checked_pid(pid).is_err());
        }
        for operation in ["pidfd_open", "pidfd_send_signal"] {
            assert_eq!(
                syscall_error(operation, io::Error::from_raw_os_error(libc::ENOSYS)).kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                syscall_error(operation, io::Error::from_raw_os_error(libc::EPERM)).kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    struct Child(std::process::Child);

    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn owned_child_mismatch_timeout_and_confirmed_single_process_exit() -> io::Result<()> {
        let mut child = Child(std::process::Command::new("/bin/sleep").arg("30").spawn()?);
        let pid = child.0.id();
        let directory = PathBuf::from(format!("/proc/{pid}"));
        let process = open(checked_pid(pid)?)?;
        let expected = ProcessIdentity {
            birth: stat_birth(&std::fs::read(directory.join("stat"))?, pid)?,
            executable: std::fs::read_link(directory.join("exe"))?,
        };
        let wrong_birth = ProcessIdentity {
            birth: expected.birth ^ 1,
            executable: expected.executable.clone(),
        };
        assert_eq!(
            terminate_runtime(pid, &wrong_birth)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let wrong_image = ProcessIdentity {
            birth: expected.birth,
            executable: PathBuf::from("/not-the-runtime"),
        };
        assert_eq!(
            terminate_runtime(pid, &wrong_image)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(child.0.try_wait()?.is_none());
        assert_eq!(
            wait_for_exit(&process, Duration::from_millis(10))
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(child.0.try_wait()?.is_none());
        terminate_runtime(pid, &expected)?;
        assert!(poll_exited(&process, 0)?);
        assert!(verify(&process, pid, &expected).is_err());
        child.0.wait()?;
        Ok(())
    }
}

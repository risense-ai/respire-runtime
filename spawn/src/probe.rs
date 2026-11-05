//! Private native probe ownership. No runtime or account discovery is performed.
use std::{io, process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio}};

pub struct ProbeChild {
    child: Child,
    #[cfg(target_os = "linux")]
    process: std::os::fd::OwnedFd,
}

impl ProbeChild {
    pub fn id(&self) -> u32 { self.child.id() }
    pub fn take_stdin(&mut self) -> Option<ChildStdin> { self.child.stdin.take() }
    pub fn take_stdout(&mut self) -> Option<ChildStdout> { self.child.stdout.take() }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> { self.child.try_wait() }

    pub fn kill(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the retained pidfd addresses only this process instance.
            let result = unsafe { libc::syscall(libc::SYS_pidfd_send_signal,
                self.process.as_raw_fd(), libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0) };
            if result < 0 { return Err(io::Error::last_os_error()); }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Windows retains a process handle. On macOS only this Child owns wait/reap;
            // an unreaped child retains its PID until try_wait confirms its exit.
            self.child.kill()
        }
    }
}

/// Callers must retain the piped stdin writer until confirmed exit. The early
/// helper calls watch_probe_parent before doing native work on Unix.
pub fn spawn_probe_helper(command: &mut Command) -> io::Result<ProbeChild> {
    #[cfg(windows)]
    crate::confine_supervisor_tree()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = std::process::id() as libc::pid_t;
        // SAFETY: only async-signal-safe kernel operations run between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
    }
    command.stdin(Stdio::piped());
    let child = crate::spawn_host_control(command)?;
    #[cfg(target_os = "linux")]
    let process = match crate::linux_process_identity::open(child.id() as libc::pid_t) {
        Ok(process) => process,
        Err(error) => {
            let mut child = child;
            // Still uniquely owned and unreaped: this fallback cannot address a reused PID.
            let _ = child.kill();
            let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if matches!(child.try_wait(), Ok(Some(_))) { return Err(error); }
                if std::time::Instant::now() >= until {
                    eprintln!("probe pidfd setup failed and child exit was not confirmed: {error}");
                    std::process::exit(2);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    };
    Ok(ProbeChild { child, #[cfg(target_os = "linux")] process })
}

/// On Unix, EOF, pipe failure or any extra byte revokes the request. The watcher
/// never acquires a model lock or runs native destructors while exiting.
pub fn watch_probe_parent() -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Read;
        std::thread::Builder::new().name("probe-parent-pipe".into()).spawn(|| {
            let mut input = std::io::stdin();
            let mut byte = [0u8; 1];
            loop {
                match input.read(&mut byte) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    _ => {
                        // SAFETY: immediate process exit intentionally skips potentially stuck teardown.
                        unsafe { libc::_exit(2) }
                    }
                }
            }
        })?;
    }
    Ok(())
}

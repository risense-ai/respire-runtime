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

/// Spawn a one-shot control child without changing the caller's Job membership.
/// Retain Child and its stdin writer until exit is confirmed; on cancellation,
/// close stdin, kill this owned child if needed, and confirm exit before returning.
pub fn spawn_control_helper(command: &mut Command) -> io::Result<Child> {
    command
        .env_remove("RSRS_RUNTIME_BOOT_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::spawn_host_control(command)
}

/// After the two control frames, EOF, any extra byte or pipe error revokes the
/// read-only child on every platform. No Rust/native teardown may delay exit.
pub fn watch_control_parent() -> io::Result<()> {
    use std::io::Read;
    std::thread::Builder::new().name("control-parent-pipe".into()).spawn(|| {
        let mut input = std::io::stdin();
        let mut byte = [0u8; 1];
        loop {
            match input.read(&mut byte) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                _ => {
                    #[cfg(unix)]
                    // SAFETY: this private helper only reads; exit skips native teardown.
                    unsafe { libc::_exit(2) }
                    #[cfg(windows)]
                    {
                        use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
                        // SAFETY: terminate only this helper, never a caller-supplied PID.
                        unsafe { TerminateProcess(GetCurrentProcess(), 2); }
                        // Fail closed even if the OS unexpectedly rejects self-termination.
                        std::process::abort();
                    }
                    #[cfg(not(any(unix, windows)))]
                    std::process::abort();
                }
            }
        }
    })?;
    Ok(())
}

/// Require pipe stdio and the actual OS parent, not a caller-asserted PID.
/// The caller must use spawn_control_helper and retain its stdin until exit.
pub fn verify_control_parent(expected_pid: u32) -> io::Result<()> {
    if expected_pid == 0 || expected_pid == std::process::id() {
        return Err(io::Error::other("invalid host control parent"));
    }
    #[cfg(unix)]
    {
        // SAFETY: getppid has no pointer arguments or side effects.
        if unsafe { libc::getppid() } as u32 != expected_pid {
            return Err(io::Error::other("host control parent does not match grant"));
        }
        for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: stat is writable and only read after successful fstat.
            if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fstat initialized the entire structure on success.
            if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO {
                return Err(io::Error::other("host control requires inherited pipe stdio"));
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
        use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, PROCESS_BASIC_INFORMATION};
        let mut info = PROCESS_BASIC_INFORMATION::default();
        let mut written = 0u32;
        // SAFETY: query only this process; the typed output is live and writable.
        let status = unsafe {
            NtQueryInformationProcess(
                GetCurrentProcess(), ProcessBasicInformation,
                (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32, &mut written,
            )
        };
        if status < 0 || written as usize != std::mem::size_of_val(&info) {
            return Err(io::Error::other("host control parent identity unavailable"));
        }
        if info.InheritedFromUniqueProcessId != expected_pid as usize {
            return Err(io::Error::other("host control parent does not match grant"));
        }
        for handle in [std::io::stdin().as_raw_handle(), std::io::stdout().as_raw_handle()] {
            // SAFETY: borrowed standard handles remain owned by this process.
            if unsafe { GetFileType(handle.cast()) } != FILE_TYPE_PIPE {
                return Err(io::Error::other("host control requires inherited pipe stdio"));
            }
        }
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    Err(io::Error::other("host control is unsupported on this platform"))
}

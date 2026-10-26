//! Start `rsrs --runtime-internal` without keeping the caller's stdout pipe open.
//!
//! On Windows, `CreateProcess` with `bInheritHandles = TRUE` copies every
//! inheritable handle, not only the stdio slots. A piped parent then never
//! sees EOF. The inherit bit is cleared only for the duration of the spawn.

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

pub mod durable;
mod confinement;
pub use confinement::is_restricted;

#[cfg(windows)]
mod supervisor_job;
#[cfg(windows)]
pub use supervisor_job::confine_supervisor_tree;

#[cfg(windows)]
mod process_identity;
#[cfg(windows)]
pub use process_identity::{process_birth, process_identity, runtime_process_identity, terminate_runtime, ProcessIdentity};

#[cfg(windows)]
mod winml;
#[cfg(windows)]
pub use winml::{install_accelerators, replace_provider_manifest};

/// Short-lived host service-manager clients must not retain the calling CLI's
/// unrelated inheritable output handles on Windows or open a console window.
pub fn spawn_host_control(command: &mut Command) -> io::Result<std::process::Child> {
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW, same user/token.
        return without_inherited_stdio(|| command.spawn());
    }
    #[cfg(not(windows))] { command.spawn() }
}

pub fn spawn_runtime(exe: &Path) -> io::Result<std::process::Child> {
    spawn_runtime_with_boot_token(exe, None)
}

/// A non-secret maintenance operation identifier lets the replacement child
/// prove it belongs to the host's still-fenced startup, before accepting work.
pub fn spawn_runtime_with_boot_token(exe: &Path, token: Option<&str>) -> io::Result<std::process::Child> {
    let mut command = Command::new(exe);
    command.env_remove("RSRS_RUNTIME_BOOT_TOKEN");
    if let Some(token) = token { command.env("RSRS_RUNTIME_BOOT_TOKEN", token); }
    command
        .arg("--runtime-internal")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
        return without_inherited_stdio(|| command.spawn());
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::process::CommandExt;
        // A new session so the runtime is not signaled when the short-lived client exits.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }
}

#[cfg(windows)]
fn without_inherited_stdio<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let saved = [
        prepare(io::stdin())?,
        prepare(io::stdout())?,
        prepare(io::stderr())?,
    ];
    let result = f();
    for slot in saved {
        restore(slot);
    }
    result
}

#[cfg(windows)]
struct Saved {
    handle: windows_sys::Win32::Foundation::HANDLE,
    flags: u32,
}

#[cfg(windows)]
fn prepare(pipe: impl std::os::windows::io::AsRawHandle) -> io::Result<Option<Saved>> {
    use windows_sys::Win32::Foundation::{
        GetHandleInformation, SetHandleInformation, HANDLE_FLAG_INHERIT,
    };
    let handle = pipe.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut flags = 0u32;
    let known = unsafe { GetHandleInformation(handle, &mut flags) };
    if known == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(6) {
            return Ok(None);
        }
        return Err(err);
    }
    if flags & HANDLE_FLAG_INHERIT == 0 {
        return Ok(None);
    }
    let cleared = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    if cleared == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(Saved { handle, flags }))
}

#[cfg(windows)]
fn restore(slot: Option<Saved>) {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    if let Some(slot) = slot {
        if slot.flags & HANDLE_FLAG_INHERIT != 0 {
            let _ = unsafe {
                SetHandleInformation(slot.handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            };
        }
    }
}

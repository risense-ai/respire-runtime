//! Windows creation identity without WMI, command-line inspection or extra access.
use std::io;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the successful OpenProcess handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub fn process_birth(pid: u32) -> io::Result<Option<u64>> {
    // SAFETY: no pointers are supplied and only query-limited access is requested.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let process = Process(handle);
    let empty = || FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (empty(), empty(), empty(), empty());
    // SAFETY: the handle remains owned/live and every pointer refers to a valid
    // distinct writable FILETIME for the duration of the call.
    if unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut status = 0_u32;
    // SAFETY: the handle remains live; status is a valid writable u32.
    if unsafe { GetExitCodeProcess(process.0, &mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if status != 259 {
        return Ok(None);
    } // STILL_ACTIVE
    Ok(Some(
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn current_process_birth_is_stable_and_dead_child_is_not_live() -> std::io::Result<()> {
        let birth = super::process_birth(std::process::id())?;
        assert!(birth.is_some());
        assert_eq!(super::process_birth(std::process::id())?, birth);
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "exit", "0"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let pid = child.id();
        child.wait()?;
        assert!(super::process_birth(pid)?.is_none());
        Ok(())
    }
}

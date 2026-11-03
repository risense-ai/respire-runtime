//! OS sandbox detection. Policy and user-facing errors live in the CLI.

use std::io;

#[cfg(not(windows))]
pub fn is_restricted() -> io::Result<bool> {
    // Unix sandbox integrations explicitly select client-only mode.
    Ok(false)
}

#[cfg(windows)]
pub fn is_restricted() -> io::Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError};
    use windows_sys::Win32::Security::{IsTokenRestricted, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // The handle is owned here and closed on both success and failure.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        SetLastError(0);
        let restricted = IsTokenRestricted(token) != 0;
        let error = GetLastError();
        CloseHandle(token);
        if !restricted && error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(restricted)
    }
}

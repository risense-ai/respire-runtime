//! Query-limited Windows process identity, including suspended runtimes.
//! No WMI, VM_READ handles, privilege adjustment or argument logging.
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

const MAX_ARGUMENT_BYTES: usize = 128 * 1024;

struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the successful OpenProcess handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn open_with_rights(pid: u32, terminate: bool) -> io::Result<Option<Process>> {
    // SAFETY: inspection is query-limited. Only explicit recovery requests
    // the termination right; no inheritance or privilege adjustment is used.
    let rights = PROCESS_QUERY_LIMITED_INFORMATION | if terminate { PROCESS_TERMINATE } else { 0 };
    let handle = unsafe { OpenProcess(rights, 0, pid) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    Ok(Some(Process(handle)))
}

fn open(pid: u32) -> io::Result<Option<Process>> {
    open_with_rights(pid, false)
}

fn birth(process: &Process) -> io::Result<Option<u64>> {
    let empty = || FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (empty(), empty(), empty(), empty());
    // SAFETY: the owned handle and distinct writable FILETIMEs remain live.
    if unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut status = 0;
    // SAFETY: status is writable and the handle remains owned/live.
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

pub fn process_birth(pid: u32) -> io::Result<Option<u64>> {
    match open(pid)? {
        Some(process) => birth(&process),
        None => Ok(None),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub birth: u64,
    pub executable: PathBuf,
}

fn image(process: &Process) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    // SAFETY: the query-limited handle is live and the full buffer is writable.
    if unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if length == 0 || length as usize > buffer.len() {
        return Err(io::Error::other("invalid process image length"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length as usize],
    )))
}

fn invalid_arguments() -> io::Error {
    io::Error::other("Windows process arguments could not be verified")
}

fn decode_arguments(storage: &[usize], written: usize) -> io::Result<Vec<u16>> {
    let capacity = std::mem::size_of_val(storage);
    let header_size = std::mem::size_of::<UNICODE_STRING>();
    if written < header_size || written > capacity || capacity > MAX_ARGUMENT_BYTES {
        return Err(invalid_arguments());
    }
    // SAFETY: usize storage provides pointer alignment; the entire header is
    // initialized and within the checked allocation. All field bit patterns are valid.
    let header = unsafe { storage.as_ptr().cast::<UNICODE_STRING>().read() };
    let length = usize::from(header.Length);
    let base = storage.as_ptr() as usize;
    let offset = (header.Buffer as usize)
        .checked_sub(base)
        .ok_or_else(invalid_arguments)?;
    let end = offset.checked_add(length).ok_or_else(invalid_arguments)?;
    if length == 0
        || length % 2 != 0
        || header.MaximumLength < header.Length
        || offset < header_size
        || offset % std::mem::align_of::<u16>() != 0
        || end > written
    {
        return Err(invalid_arguments());
    }
    // SAFETY: derive the pointer from our own allocation, not from unchecked
    // remote memory. Alignment, initialized extent and UTF-16 byte length were checked.
    let words = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
            length / 2,
        )
    };
    if words.contains(&0) {
        return Err(invalid_arguments());
    }
    let mut command = words.to_vec();
    command.push(0);
    Ok(command)
}

fn query_error(stage: &str, status: i32) -> io::Error {
    io::Error::other(format!(
        "Windows native process argument query failed at {stage} (NTSTATUS 0x{:08X})",
        status as u32
    ))
}

fn command_line(process: &Process) -> io::Result<Vec<u16>> {
    let resize = |status| {
        [
            STATUS_BUFFER_OVERFLOW,
            STATUS_BUFFER_TOO_SMALL,
            STATUS_INFO_LENGTH_MISMATCH,
        ]
        .contains(&status)
    };
    for _ in 0..3 {
        let mut needed = 0u32;
        // SAFETY: null/zero is the NT size query; only needed is writable.
        let status = unsafe {
            NtQueryInformationProcess(
                process.0,
                ProcessCommandLineInformation,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if !resize(status) {
            return Err(query_error("size", status));
        }
        if needed as usize > MAX_ARGUMENT_BYTES
            || (needed as usize) < std::mem::size_of::<UNICODE_STRING>()
        {
            return Err(invalid_arguments());
        }
        let mut storage = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let mut written = std::mem::size_of_val(storage.as_slice()) as u32;
        // SAFETY: the live query-limited handle and aligned, initialized owned
        // output allocation satisfy the API. No remote pointer is dereferenced.
        let status = unsafe {
            NtQueryInformationProcess(
                process.0,
                ProcessCommandLineInformation,
                storage.as_mut_ptr().cast(),
                written,
                &mut written,
            )
        };
        if resize(status) {
            continue;
        } // command line changed between the two queries
        if status < 0 {
            return Err(query_error("read", status));
        }
        return decode_arguments(&storage, written as usize);
    }
    Err(invalid_arguments())
}

struct Arguments {
    pointer: *mut *mut u16,
    count: usize,
}
impl Drop for Arguments {
    fn drop(&mut self) {
        // SAFETY: CommandLineToArgvW returns this single LocalAlloc allocation.
        unsafe {
            LocalFree(self.pointer.cast());
        }
    }
}
impl Arguments {
    fn is(&self, index: usize, expected: &str) -> bool {
        if index >= self.count {
            return false;
        }
        // SAFETY: Shell32 guarantees count valid pointers to terminated strings.
        let word = unsafe { *self.pointer.add(index) };
        if word.is_null() {
            return false;
        }
        let mut offset = 0;
        for unit in expected.encode_utf16() {
            // SAFETY: stop at the terminator before any subsequent read; all
            // comparisons are fixed role literals, never returned/logged arguments.
            let actual = unsafe { *word.add(offset) };
            if actual == 0 || actual != unit {
                return false;
            }
            offset += 1;
        }
        // SAFETY: the previous loop never advanced past a terminator.
        unsafe { *word.add(offset) == 0 }
    }
}

fn runtime_role(command: &[u16]) -> io::Result<bool> {
    if command.last() != Some(&0) || command[..command.len() - 1].contains(&0) {
        return Err(invalid_arguments());
    }
    let mut count = 0;
    // SAFETY: the owned input is terminated and remains live through the call.
    let pointer = unsafe { CommandLineToArgvW(command.as_ptr(), &mut count) };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let arguments = Arguments {
        pointer,
        count: count.max(0) as usize,
    };
    if count <= 0 || count > 32768 {
        return Err(invalid_arguments());
    }
    let has = |value| (1..arguments.count).any(|index| arguments.is(index, value));
    let mut first = 1;
    while arguments.is(first, "--json") || arguments.is(first, "--direct") {
        first += 1;
    }
    Ok(has("--runtime-internal")
        || (has("web") && has("--internal"))
        || (arguments.is(first, "runtime") && arguments.is(first + 1, "run")))
}

fn inspect(pid: u32, require_runtime: bool) -> io::Result<Option<ProcessIdentity>> {
    let Some(process) = open(pid)? else {
        return Ok(None);
    };
    let Some(created) = birth(&process)? else {
        return Ok(None);
    };
    let executable = image(&process)?;
    if require_runtime && !runtime_role(&command_line(&process)?)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process arguments do not identify a runtime",
        ));
    }
    if birth(&process)? != Some(created) {
        return Err(io::Error::other(
            "process exited during identity inspection",
        ));
    }
    Ok(Some(ProcessIdentity {
        birth: created,
        executable,
    }))
}

pub fn process_identity(pid: u32) -> io::Result<Option<ProcessIdentity>> {
    inspect(pid, false)
}
pub fn runtime_process_identity(pid: u32) -> io::Result<Option<ProcessIdentity>> {
    inspect(pid, true)
}

/// Bind the destructive operation to the same kernel process handle that was
/// checked. A PID reused after inspection can never redirect termination.
pub fn terminate_runtime(pid: u32, expected: &ProcessIdentity) -> io::Result<()> {
    let process =
        open_with_rights(pid, true)?.ok_or_else(|| io::Error::other("runtime already exited"))?;
    let current = ProcessIdentity {
        birth: birth(&process)?.ok_or_else(|| io::Error::other("runtime already exited"))?,
        executable: image(&process)?,
    };
    if &current != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime process identity changed",
        ));
    }
    if !runtime_role(&command_line(&process)?)? || birth(&process)? != Some(expected.birth) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime process role or lifetime changed",
        ));
    }
    // SAFETY: the handle belongs to the exact checked instance and has only
    // query plus the termination right already required for explicit recovery.
    if unsafe { TerminateProcess(process.0, 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_process_birth_is_stable_and_dead_child_is_not_live() -> io::Result<()> {
        let identity = process_identity(std::process::id())?
            .ok_or_else(|| io::Error::other("self identity missing"))?;
        assert_eq!(process_birth(std::process::id())?, Some(identity.birth));
        assert_eq!(
            identity.executable.canonicalize()?,
            std::env::current_exe()?.canonicalize()?
        );
        assert!(
            runtime_process_identity(std::process::id()).is_err(),
            "a test process must not impersonate a runtime"
        );
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "exit", "0"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let pid = child.id();
        child.wait()?;
        assert!(process_birth(pid)?.is_none());
        Ok(())
    }
    #[test]
    fn identity_mismatch_and_unknown_role_never_terminate_owned_child() -> io::Result<()> {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "set /p marker="])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let identity =
            process_identity(child.id())?.ok_or_else(|| io::Error::other("fixture missing"))?;
        let wrong_birth = ProcessIdentity {
            birth: identity.birth.saturating_add(1),
            executable: identity.executable.clone(),
        };
        assert!(terminate_runtime(child.id(), &wrong_birth).is_err());
        assert!(child.try_wait()?.is_none());
        let wrong_image = ProcessIdentity {
            birth: identity.birth,
            executable: identity.executable.with_extension("foreign"),
        };
        assert!(terminate_runtime(child.id(), &wrong_image).is_err());
        assert!(child.try_wait()?.is_none());
        assert!(terminate_runtime(child.id(), &identity).is_err());
        assert!(
            child.try_wait()?.is_none(),
            "a matching PID/image alone cannot establish runtime role"
        );
        child.kill()?;
        child.wait()?;
        Ok(())
    }

    #[test]
    fn role_parsing_preserves_quoted_paths_and_rejects_other_commands() -> io::Result<()> {
        for (command, expected) in [
            (r#""C:\space path\rsrs.exe" --runtime-internal"#, true),
            (
                r#""C:\中文\rsrs.exe" --json --direct runtime run --managed example"#,
                true,
            ),
            (r#""C:\rsrs.exe" web --internal"#, true),
            (r#""C:\rsrs.exe" runtime status"#, false),
            (r#""C:\rsrs.exe" login --interactive"#, false),
            (r#""C:\rsrs.exe" --runtime-internal-suffix"#, false),
            (r#""C:\rsrs.exe" remember "runtime run""#, false),
        ] {
            let words: Vec<_> = command.encode_utf16().chain(Some(0)).collect();
            assert_eq!(runtime_role(&words)?, expected);
        }
        Ok(())
    }
    #[test]
    fn native_query_buffer_rejects_invalid_extents_before_reading() -> io::Result<()> {
        let words: Vec<_> = "rsrs --runtime-internal".encode_utf16().collect();
        let header = std::mem::size_of::<UNICODE_STRING>();
        let bytes = header + words.len() * 2;
        let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let base = storage.as_mut_ptr().cast::<u8>();
        // SAFETY: the synthetic header and UTF-16 data fit the aligned owned allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                words.as_ptr(),
                base.add(header).cast::<u16>(),
                words.len(),
            );
            base.cast::<UNICODE_STRING>().write(UNICODE_STRING {
                Length: (words.len() * 2) as u16,
                MaximumLength: (words.len() * 2) as u16,
                Buffer: base.add(header).cast(),
            });
        }
        assert!(runtime_role(&decode_arguments(&storage, bytes)?)?);
        assert!(decode_arguments(&storage, header - 1).is_err());
        assert!(decode_arguments(&storage, MAX_ARGUMENT_BYTES + 1).is_err());
        // SAFETY: mutations address only the same valid synthetic header.
        unsafe {
            (*base.cast::<UNICODE_STRING>()).Length = 3;
        }
        assert!(decode_arguments(&storage, bytes).is_err());
        unsafe {
            (*base.cast::<UNICODE_STRING>()).Length = (words.len() * 2) as u16;
            (*base.cast::<UNICODE_STRING>()).Buffer = base.wrapping_add(bytes + 2).cast();
        }
        assert!(decode_arguments(&storage, bytes).is_err());
        unsafe {
            (*base.cast::<UNICODE_STRING>()).Buffer = std::ptr::null_mut();
        }
        assert!(decode_arguments(&storage, bytes).is_err());
        Ok(())
    }
}

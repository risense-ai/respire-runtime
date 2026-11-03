//! A parent-owned, non-inheritable job kills only its own process tree on exit.
use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::sync::Mutex;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

// Static ownership deliberately lasts until process termination, including
// abnormal termination. Dropping the last handle while still running would
// terminate this parent too. Children must never inherit a duplicate handle.
static LIFETIME_JOB: Mutex<Option<OwnedHandle>> = Mutex::new(None);

pub fn confine_supervisor_tree() -> io::Result<()> {
    let mut slot = LIFETIME_JOB.lock().map_err(|_| io::Error::other("supervisor job lock poisoned"))?;
    if slot.is_some() { return Ok(()); }
    // SAFETY: null attributes create a non-inheritable unnamed job; no pointer
    // supplied here refers to application memory.
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if handle.is_null() { return Err(io::Error::last_os_error()); }
    // SAFETY: CreateJobObject returned a uniquely owned real handle.
    let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
    // SAFETY: all-zero limits are valid; only kill-on-close is enabled below.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: handle is live, and the typed structure/size describe the entire
    // readable buffer for this synchronous API call.
    if unsafe { SetInformationJobObject(handle, JobObjectExtendedLimitInformation,
        &limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const std::ffi::c_void, std::mem::size_of_val(&limits) as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: only the calling process is assigned. Windows 8+ nested jobs
    // preserve the enclosing Task Scheduler job; no breakaway/elevation is set.
    if unsafe { AssignProcessToJobObject(handle, GetCurrentProcess()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    *slot = Some(owned);
    Ok(())
}

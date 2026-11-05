//! Process image lookup; pointers never escape the synchronous native probe.
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::Context;
use std::path::PathBuf;
#[cfg(windows)]
use std::path::Path;

pub(super) fn runtime_version(api: usize, version: u32, create: usize, run: usize) -> Result<String> {
    // SAFETY: the already-linked ORT API base owns this versioned table and its version string.
    let base = unsafe { ort_sys::OrtGetApiBase() };
    anyhow::ensure!(!base.is_null(), "loaded ORT API base missing");
    let table = unsafe { ((*base).GetApi)(version) };
    anyhow::ensure!(!table.is_null() && table as usize == api, "observed API does not match the loaded ORT versioned table");
    anyhow::ensure!(unsafe { (*table).CreateSessionFromArray } as usize == create
        && unsafe { (*table).Run } as usize == run, "observed runtime functions differ from the loaded ORT API");
    let version = unsafe { ((*base).GetVersionString)() };
    anyhow::ensure!(!version.is_null(), "loaded ORT version string missing");
    Ok(unsafe { std::ffi::CStr::from_ptr(version) }.to_str()?.to_owned())
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleExW(flags: u32, address: *const u16, module: *mut *mut std::ffi::c_void) -> i32;
    fn GetModuleFileNameW(module: *mut std::ffi::c_void, path: *mut u16, size: u32) -> u32;
}

#[cfg(windows)]
fn module_name(module: *mut std::ffi::c_void) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut path = vec![0u16; 32768];
    // SAFETY: the OS module handle is live and the buffer covers the advertised length.
    let count = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
    anyhow::ensure!(count > 0 && count < path.len(), "cannot resolve loaded probe module");
    Ok(std::ffi::OsString::from_wide(&path[..count]).into())
}

#[cfg(windows)]
pub(super) fn module_path(address: usize) -> Result<PathBuf> {
    let mut module = std::ptr::null_mut();
    // SAFETY: FROM_ADDRESS interprets the value as a code address without dereferencing it.
    let found = unsafe { GetModuleHandleExW(0x4 | 0x2, address as *const u16, &mut module) };
    anyhow::ensure!(found != 0, "probe code address is not in a loaded module");
    module_name(module)
}

#[cfg(target_os = "linux")]
pub(super) fn module_path(address: usize) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    // /proc also covers static musl executables, where dladdr cannot identify code.
    let maps = std::fs::read_to_string("/proc/self/maps").context("read loaded process images")?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next().context("invalid process mapping")?;
        let (start, end) = range.split_once('-').context("invalid process mapping range")?;
        if !(usize::from_str_radix(start, 16)?..usize::from_str_radix(end, 16)?).contains(&address) { continue; }
        let permissions = fields.next().context("missing process mapping permissions")?;
        anyhow::ensure!(permissions.contains('x'), "probe function is not in executable memory");
        let inode = fields.nth(2).context("missing process mapping inode")?.parse::<u64>()?;
        let path = PathBuf::from(&line[line.find('/').context("probe code has no backing image")?..]);
        anyhow::ensure!(std::fs::metadata(&path)?.ino() == inode, "loaded probe image was replaced");
        return Ok(path);
    }
    anyhow::bail!("probe code address is not in a loaded image")
}

#[cfg(target_os = "macos")]
pub(super) fn module_path(address: usize) -> Result<PathBuf> {
    use std::ffi::{c_char, c_void, CStr};
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct DlInfo { name: *const c_char, base: *mut c_void, symbol: *const c_char, symbol_address: *mut c_void }
    extern "C" { fn dladdr(address: *const c_void, info: *mut DlInfo) -> i32; }
    let mut info = DlInfo { name: std::ptr::null(), base: std::ptr::null_mut(), symbol: std::ptr::null(), symbol_address: std::ptr::null_mut() };
    // SAFETY: dladdr only queries the image containing an address and writes the supplied struct.
    let found = unsafe { dladdr(address as *const c_void, &mut info) };
    anyhow::ensure!(found != 0 && !info.name.is_null(), "cannot resolve loaded probe image");
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(unsafe { CStr::from_ptr(info.name) }.to_bytes())))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(super) fn module_path(_: usize) -> Result<PathBuf> { anyhow::bail!("backend module lookup unsupported on this OS") }

#[cfg(windows)]
pub(super) struct LoadedLibrary { pub library: libloading::Library }

#[cfg(windows)]
pub(super) fn load_library(path: &Path) -> Result<LoadedLibrary> {
    // SAFETY: the caller checked this absolute file against its compiled trusted pin.
    let library = unsafe { libloading::os::windows::Library::load_with_flags(path, 0x100 | 0x1000) }?;
    let handle = library.into_raw();
    // Restore ownership before any fallible operation, so failure cannot leak the reference.
    let library = unsafe { libloading::os::windows::Library::from_raw(handle) };
    let actual = std::fs::canonicalize(module_name(handle as *mut std::ffi::c_void)?)?;
    anyhow::ensure!(actual == std::fs::canonicalize(path)?, "Windows loaded a module outside its pinned location");
    Ok(LoadedLibrary { library: library.into() })
}

#[cfg(windows)]
pub(super) fn symbol_path(library: &LoadedLibrary, name: &[u8]) -> Result<PathBuf> {
    // SAFETY: this symbol is only located, never invoked with an invented signature.
    let symbol = unsafe { library.library.get::<unsafe extern "system" fn()>(name) }?;
    module_path(*symbol as usize)
}

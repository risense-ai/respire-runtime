//! Host-only Windows ML installation through Microsoft's public C catalog ABI.
use libloading::{Library, Symbol};
use std::{collections::BTreeMap, ffi::{c_char, c_void, CStr, CString}, io, path::{Path, PathBuf}, ptr};

type Handle = *mut c_void;
type Release = unsafe extern "system" fn(Handle);
#[repr(C)]
struct Info {
    name: *const c_char, version: *const c_char, family: *const c_char,
    library: *const c_char, root: *const c_char, state: i32, certification: i32,
}
type Callback = unsafe extern "system" fn(Handle, *const Info, *mut c_void) -> i32;

/// Replace the host's provider manifest without deleting its previous copy first.
pub fn replace_provider_manifest(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn check(status: i32, operation: &str) -> io::Result<()> {
    if status < 0 {
        return Err(io::Error::other(format!("Windows ML {operation}: HRESULT 0x{:08X}", status as u32)));
    }
    Ok(())
}

struct Catalog { library: Library, handle: Handle, release: Release }
impl Drop for Catalog {
    fn drop(&mut self) {
        // The catalog is released before unloading its DLL.
        unsafe { (self.release)(self.handle) };
    }
}

pub fn install_accelerators(dll: &Path) -> io::Result<BTreeMap<String, PathBuf>> {
    if !dll.is_absolute() || !dll.is_file() {
        return Err(io::Error::other("Windows ML catalog must be an existing absolute DLL path"));
    }
    // Signatures match Microsoft's pinned catalog C ABI. All handles, callback
    // input and allocated path buffers stay valid until their synchronous calls end.
    let catalog = unsafe {
        let library = Library::new(dll).map_err(io::Error::other)?;
        let create: Symbol<unsafe extern "system" fn(*mut Handle) -> i32> =
            library.get(b"WinMLEpCatalogCreate\0").map_err(io::Error::other)?;
        let release = *library.get::<Release>(b"WinMLEpCatalogRelease\0").map_err(io::Error::other)?;
        let mut handle = ptr::null_mut();
        check(create(&mut handle), "create catalog")?;
        if handle.is_null() { return Err(io::Error::other("Windows ML returned a null catalog")); }
        Catalog { library, handle, release }
    };
    unsafe extern "system" fn collect(_: Handle, info: *const Info, context: *mut c_void) -> i32 {
        if !info.is_null() {
            let info = unsafe { &*info };
            if !info.name.is_null() {
                let providers = unsafe { &mut *context.cast::<Vec<String>>() };
                providers.push(unsafe { CStr::from_ptr(info.name) }.to_string_lossy().into_owned());
            }
        }
        1
    }
    let mut names = Vec::<String>::new();
    unsafe {
        let enumerate: Symbol<unsafe extern "system" fn(Handle, Callback, *mut c_void) -> i32> =
            catalog.library.get(b"WinMLEpCatalogEnumProviders\0").map_err(io::Error::other)?;
        check(enumerate(catalog.handle, collect, ptr::from_mut(&mut names).cast()), "enumerate providers")?;
    }
    let mut paths = BTreeMap::new();
    for name in names {
        if !matches!(name.as_str(), "OpenVINOExecutionProvider" | "QNNExecutionProvider" | "VitisAIExecutionProvider") { continue; }
        let encoded = CString::new(name.as_str()).map_err(io::Error::other)?;
        let path = unsafe {
            let find: Symbol<unsafe extern "system" fn(Handle, *const c_char, *const c_char, *mut Handle) -> i32> =
                catalog.library.get(b"WinMLEpCatalogFindProvider\0").map_err(io::Error::other)?;
            let ensure: Symbol<unsafe extern "system" fn(Handle) -> i32> =
                catalog.library.get(b"WinMLEpEnsureReady\0").map_err(io::Error::other)?;
            let mut provider = ptr::null_mut();
            check(find(catalog.handle, encoded.as_ptr(), ptr::null(), &mut provider), "find provider")?;
            if provider.is_null() { return Err(io::Error::other("Windows ML provider not found")); }
            check(ensure(provider), "install provider")?;
            let size: Symbol<unsafe extern "system" fn(Handle, *mut usize) -> i32> =
                catalog.library.get(b"WinMLEpGetLibraryPathSize\0").map_err(io::Error::other)?;
            let get: Symbol<unsafe extern "system" fn(Handle, usize, *mut c_char, *mut usize) -> i32> =
                catalog.library.get(b"WinMLEpGetLibraryPath\0").map_err(io::Error::other)?;
            let mut len = 0;
            check(size(provider, &mut len), "provider path size")?;
            let mut bytes = vec![0u8; len];
            check(get(provider, len, bytes.as_mut_ptr().cast(), ptr::null_mut()), "provider path")?;
            PathBuf::from(CStr::from_bytes_until_nul(&bytes).map_err(io::Error::other)?.to_str().map_err(io::Error::other)?)
        };
        if !path.is_absolute() || !path.is_file() { return Err(io::Error::other("Windows ML installed provider DLL is missing")); }
        paths.insert(name, path);
    }
    Ok(paths)
}

//! Small Windows ML C ABI boundary. The inference crates remain unsafe-free.
//! ABI: Microsoft.Windows.AI.MachineLearning 2.4.89, WinMLEpCatalog.h.

use anyhow::{anyhow, Context, Result};
use libloading::{Library, Symbol};
use std::{
    ffi::{c_char, c_void, CStr},
    path::{Path, PathBuf},
    ptr,
};

pub const DLL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/winml.dll"));
pub const LICENSE: &str = include_str!(concat!(env!("OUT_DIR"), "/winml-license.txt"));

#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String,
    pub path: Option<PathBuf>,
    pub ready: bool,
}

#[repr(C)]
struct Info {
    name: *const c_char,
    version: *const c_char,
    family: *const c_char,
    library: *const c_char,
    root: *const c_char,
    state: i32,
    certification: i32,
}
type Handle = *mut c_void;
type Callback = unsafe extern "system" fn(Handle, *const Info, *mut c_void) -> i32;
type Release = unsafe extern "system" fn(Handle);

pub struct Catalog {
    library: Library,
    handle: Handle,
    release: Release,
}

fn check(hr: i32, operation: &str) -> Result<()> {
    if hr < 0 {
        return Err(anyhow!(
            "Windows ML {operation}: HRESULT 0x{:08X}",
            hr as u32
        ));
    }
    Ok(())
}

impl Catalog {
    pub fn open(path: &Path) -> Result<Self> {
        // SAFETY: absolute path points to the pinned Microsoft DLL; signatures
        // match its published C header. Library outlives all calls and handles.
        unsafe {
            let library = Library::new(path).context("load Windows ML catalog")?;
            let create: Symbol<unsafe extern "system" fn(*mut Handle) -> i32> =
                library.get(b"WinMLEpCatalogCreate\0")?;
            let release = *library.get::<Release>(b"WinMLEpCatalogRelease\0")?;
            let mut handle = ptr::null_mut();
            check(create(&mut handle), "create catalog")?;
            Ok(Self {
                library,
                handle,
                release,
            })
        }
    }

    pub fn providers(&self) -> Result<Vec<Provider>> {
        // SAFETY: callback borrows a live Vec only during the synchronous enum.
        unsafe extern "system" fn collect(
            _: Handle,
            info: *const Info,
            context: *mut c_void,
        ) -> i32 {
            if info.is_null() {
                return 1;
            }
            let info = unsafe { &*info };
            let rows = unsafe { &mut *context.cast::<Vec<Provider>>() };
            if !info.name.is_null() {
                rows.push(Provider {
                    name: unsafe { CStr::from_ptr(info.name) }
                        .to_string_lossy()
                        .into_owned(),
                    path: if info.library.is_null() {
                        None
                    } else {
                        let text = unsafe { CStr::from_ptr(info.library) }.to_string_lossy();
                        if text.is_empty() {
                            None
                        } else {
                            Some(PathBuf::from(text.as_ref()))
                        }
                    },
                    ready: info.state == 0,
                });
            }
            1
        }
        let mut rows = Vec::<Provider>::new();
        unsafe {
            let enumerate: Symbol<unsafe extern "system" fn(Handle, Callback, *mut c_void) -> i32> =
                self.library.get(b"WinMLEpCatalogEnumProviders\0")?;
            check(
                enumerate(
                    self.handle,
                    collect,
                    (&mut rows as *mut Vec<Provider>).cast(),
                ),
                "enumerate providers",
            )?;
        }
        Ok(rows)
    }
}

impl Drop for Catalog {
    fn drop(&mut self) {
        // SAFETY: exactly one owner releases the catalog before unloading DLL.
        unsafe { (self.release)(self.handle) };
    }
}

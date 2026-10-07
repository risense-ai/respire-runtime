#![deny(unsafe_code)]


//! Safe ownership wrapper. No private Rust engine crate is a dependency.

pub mod env;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{marker::PhantomData, rc::Rc};

mod business;
pub use business::*;

pub const ABI_VERSION: u32 = 0x0001_0001;

/// Confined to its owner thread; calls cannot race destruction or one another.
pub struct Core {
    handle: ffi::Handle,
    next_request: u64,
    poisoned: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Core {
    pub fn new() -> Result<Self> {
        let version = ffi::abi_version();
        if version != ABI_VERSION {
            bail!("Core ABI mismatch: {version:#x}");
        }
        Ok(Self {
            handle: ffi::Handle::create(b"{}")?,
            next_request: 0,
            poisoned: false,
            _thread_bound: PhantomData,
        })
    }

    pub fn call(&mut self, operation: &str, payload: Value) -> Result<Value> {
        self.call_inner(operation, payload, None)
    }

    /// Host performs external requests. Credentials must remain in the closure.
    pub fn call_with_transport(&mut self, operation: &str, payload: Value,
        transport: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<Value> {
        self.call_inner(operation, payload, Some(transport))
    }

    fn call_inner(&mut self, operation: &str, payload: Value,
        transport: Option<&mut dyn FnMut(&Value) -> Result<Value>>) -> Result<Value> {
        if self.poisoned {
            bail!("Core handle is poisoned; recreate it");
        }
        self.next_request = self
            .next_request
            .checked_add(1)
            .context("request counter exhausted")?;
        let request_id = self.next_request.to_string();
        let request = serde_json::to_vec(&json!({
            "schema_version": 1, "request_id": request_id,
            "operation": operation, "payload": payload,
        }))?;
        let (code, bytes) = match transport {
            Some(transport) => self.handle.call_with_transport(&request, transport)?,
            None => self.handle.call(&request)?,
        };
        if code == 7 {
            self.poisoned = true;
        }
        let response: Value =
            serde_json::from_slice(&bytes).context("invalid Core response JSON")?;
        if code != 0 {
            bail!("Core error {code}: {}", response["error"]["message"]);
        }
        if response["schema_version"].as_u64() != Some(1)
            || response["request_id"].as_str() != Some(request_id.as_str())
        {
            bail!("Core response schema or request ID mismatch");
        }
        response
            .get("result")
            .cloned()
            .context("Core response missing result")
    }

    pub fn capabilities(&mut self) -> Result<Value> {
        self.call("capabilities", Value::Null)
    }
}

#[allow(unsafe_code)]
mod ffi {
    use super::*;
    use std::{ffi::c_void, ptr, slice};

    #[repr(C)]
    struct Buffer {
        data: *mut u8,
        len: usize,
    }

    impl Buffer {
        fn empty() -> Self {
            Self {
                data: ptr::null_mut(),
                len: 0,
            }
        }
        fn bytes(&self) -> Result<Vec<u8>> {
            if self.len == 0 {
                return Ok(Vec::new());
            }
            if self.data.is_null() || self.len > isize::MAX as usize {
                bail!("invalid Core output buffer");
            }
            // The ABI guarantees readable bytes until the matching Core free.
            Ok(unsafe { slice::from_raw_parts(self.data, self.len) }.to_vec())
        }
    }

    impl Drop for Buffer {
        fn drop(&mut self) {
            // Only Core-created buffers enter this wrapper; free also clears it.
            unsafe {
                rs_core_buffer_free(self);
            }
        }
    }

    extern "C" {
        fn rs_core_abi_version() -> u32;
        fn rs_core_create(
            config: *const u8,
            len: usize,
            core: *mut *mut c_void,
            error: *mut Buffer,
        ) -> i32;
        fn rs_core_call(
            core: *mut c_void,
            input: *const u8,
            len: usize,
            output: *mut Buffer,
        ) -> i32;
        fn rs_core_buffer_free(buffer: *mut Buffer);
        fn rs_core_call_with_transport(
            core: *mut c_void, input: *const u8, len: usize, context: *mut c_void,
            request: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut HostBuffer) -> i32,
            release: unsafe extern "C" fn(*mut c_void, *mut HostBuffer),
            output: *mut Buffer,
        ) -> i32;
        fn rs_core_destroy(core: *mut c_void);
    }

    pub(super) fn abi_version() -> u32 {
        unsafe { rs_core_abi_version() }
    }

    pub(super) struct Handle {
        pointer: ptr::NonNull<c_void>,
    }

    // Host allocations must never enter Buffer, whose Drop uses the Core allocator.
    #[repr(C)]
    struct HostBuffer { data: *mut u8, len: usize }

    struct TransportContext<'a> {
        callback: &'a mut dyn FnMut(&Value) -> Result<Value>,
        response: Vec<u8>,
    }

    unsafe extern "C" fn host_request(context: *mut c_void, input: *const u8,
        len: usize, output: *mut HostBuffer) -> i32 {
        let context = unsafe { &mut *context.cast::<TransportContext<'_>>() };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Vec<u8>> {
            anyhow::ensure!(!input.is_null() && len <= isize::MAX as usize, "invalid host request buffer");
            let request: Value = serde_json::from_slice(unsafe { slice::from_raw_parts(input, len) })?;
            serde_json::to_vec(&(context.callback)(&request)?).map_err(Into::into)
        }));
        let (status, bytes) = match result {
            Ok(Ok(bytes)) => (0, bytes),
            Ok(Err(error)) => (6, json!({"error":error.to_string()}).to_string().into_bytes()),
            Err(_) => (7, Vec::new()),
        };
        context.response = bytes;
        unsafe { ptr::write(output, HostBuffer { data: context.response.as_mut_ptr(), len: context.response.len() }) };
        status
    }

    unsafe extern "C" fn host_release(context: *mut c_void, output: *mut HostBuffer) {
        let context = unsafe { &mut *context.cast::<TransportContext<'_>>() };
        context.response.clear();
        unsafe { ptr::write(output, HostBuffer { data: ptr::null_mut(), len: 0 }) };
    }

    impl Handle {
        pub(super) fn create(config: &[u8]) -> Result<Self> {
            let mut pointer = ptr::null_mut();
            let mut error = Buffer::empty();
            let code =
                unsafe { rs_core_create(config.as_ptr(), config.len(), &mut pointer, &mut error) };
            if code != 0 {
                bail!(
                    "Core creation error {code}: {}",
                    String::from_utf8_lossy(&error.bytes()?)
                );
            }
            Ok(Self {
                pointer: ptr::NonNull::new(pointer).context("Core returned a null handle")?,
            })
        }

        pub(super) fn call(&mut self, input: &[u8]) -> Result<(i32, Vec<u8>)> {
            let mut output = Buffer::empty();
            // &mut self provides exclusive access; Core is not Send or Sync.
            let code = unsafe {
                rs_core_call(
                    self.pointer.as_ptr(),
                    input.as_ptr(),
                    input.len(),
                    &mut output,
                )
            };
            Ok((code, output.bytes()?))
        }

        pub(super) fn call_with_transport(&mut self, input: &[u8],
            callback: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<(i32, Vec<u8>)> {
            let mut context = TransportContext { callback, response: Vec::new() };
            let mut output = Buffer::empty();
            let code = unsafe { rs_core_call_with_transport(self.pointer.as_ptr(), input.as_ptr(),
                input.len(), ptr::from_mut(&mut context).cast(), host_request, host_release, &mut output) };
            Ok((code, output.bytes()?))
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                rs_core_destroy(self.pointer.as_ptr());
            }
        }
    }
}

#![deny(unsafe_code)]


//! Safe ownership wrapper. No private Rust engine crate is a dependency.

pub mod env;
mod host;
#[cfg(windows)]
#[allow(unsafe_code)]
mod host_winml;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{marker::PhantomData, rc::Rc};

mod business;
pub use business::*;
mod resident;
pub use resident::{ResidentLease, ResidentScope, resident_scope_active, BackgroundIndexScope, defer_indexing, indexing_deferred};

pub const ABI_VERSION: u32 = 0x0001_0002;

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
            handle: ffi::Handle::create(&serde_json::to_vec(&json!({"test_mode":
                env::var("RSRS_CORE_TEST_MODE").as_deref() == Ok("1")}))?)?,
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

    /// Borrow model buffers for this synchronous call. Core retains its own session.
    pub fn load_model(&mut self, config: Value, model: &[u8], tokenizer: &[u8]) -> Result<Value> {
        anyhow::ensure!(!self.poisoned, "Core handle is poisoned; recreate it");
        let (code, bytes) = self.handle.load_model(&serde_json::to_vec(&config)?, model, tokenizer)?;
        if code == 7 { self.poisoned = true; }
        let response: Value = serde_json::from_slice(&bytes).context("invalid Core model response")?;
        anyhow::ensure!(code == 0, "Core error {code}: {}", response["error"]["message"]);
        response.get("result").cloned().context("Core model response missing result")
    }

    #[cfg(windows)]
    fn register_providers(&mut self) -> Result<Vec<String>> {
        let providers = onnx::host_providers()?;
        let (code, bytes, diagnostics) = self.handle.register_providers(providers)?;
        let response: Value = serde_json::from_slice(&bytes).context("invalid Core provider response")?;
        anyhow::ensure!(code == 0, "Core provider registration error {code}: {}", response["error"]["message"]);
        Ok(diagnostics)
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
        fn rs_core_model_load(core: *mut c_void, config: *const u8, config_len: usize,
            model: *const u8, model_len: usize, tokenizer: *const u8, tokenizer_len: usize,
            output: *mut Buffer) -> i32;
        fn rs_core_model_load_with_host(core: *mut c_void, config: *const u8, config_len: usize,
            model: *const u8, model_len: usize, tokenizer: *const u8, tokenizer_len: usize,
            context: *mut c_void,
            configure: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void, *mut c_void, *const c_void) -> i32,
            output: *mut Buffer) -> i32;
        #[cfg(windows)]
        fn rs_core_register_providers(core: *mut c_void, context: *mut c_void,
            configure: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void) -> i32,
            output: *mut Buffer) -> i32;
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

        pub(super) fn load_model(&mut self, config: &[u8], model: &[u8], tokenizer: &[u8]) -> Result<(i32, Vec<u8>)> {
            let mut output = Buffer::empty();
            let config_value: Value = serde_json::from_slice(config)?;
            let device_options = cfg!(windows) && config_value["engine"].as_str() != Some("cpu");
            let mut options = SessionOptionsContext { profiling:crate::env::var_os("RSRS_ORT_PROFILE").map(std::path::PathBuf::from),
                device_options, cache:crate::onnx::host_cache_dir(), error:None };
            // Borrowed slices and host option callback remain alive through this call.
            let code = if options.profiling.is_some() || options.device_options {
                unsafe { rs_core_model_load_with_host(self.pointer.as_ptr(), config.as_ptr(), config.len(),
                    model.as_ptr(), model.len(), tokenizer.as_ptr(), tokenizer.len(),
                    ptr::from_mut(&mut options).cast(), configure_session_options, &mut output) }
            } else {
                unsafe { rs_core_model_load(self.pointer.as_ptr(), config.as_ptr(), config.len(),
                    model.as_ptr(), model.len(), tokenizer.as_ptr(), tokenizer.len(), &mut output) }
            };
            if let Some(error) = options.error { return Err(error); }
            Ok((code, output.bytes()?))
        }

        #[cfg(windows)]
        pub(super) fn register_providers(&mut self, providers: Vec<crate::host_winml::Provider>) -> Result<(i32, Vec<u8>, Vec<String>)> {
            let mut context = ProviderContext { providers, error:None, diagnostics:Vec::new() };
            let mut output = Buffer::empty();
            // The callback and provider paths live until this synchronous call returns.
            let code = unsafe { rs_core_register_providers(self.pointer.as_ptr(), ptr::from_mut(&mut context).cast(), register_host_providers, &mut output) };
            if let Some(error) = context.error { return Err(error); }
            Ok((code, output.bytes()?, context.diagnostics))
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

    struct SessionOptionsContext { profiling: Option<std::path::PathBuf>, device_options:bool,
        cache:std::path::PathBuf, error: Option<anyhow::Error> }

    unsafe extern "C" fn configure_session_options(context: *mut c_void, options: *mut c_void, api: *const c_void,
        environment: *mut c_void, device: *const c_void) -> i32 {
        let context = unsafe { &mut *context.cast::<SessionOptionsContext>() };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            anyhow::ensure!(!options.is_null() && !api.is_null(), "invalid Core native session options");
            let api = unsafe { &*api.cast::<ort_sys::OrtApi>() };
            if !device.is_null() {
                anyhow::ensure!(!environment.is_null(), "invalid Core native environment");
                let name = unsafe { (api.EpDevice_EpName)(device.cast()) };
                anyhow::ensure!(!name.is_null(), "missing Core selected provider name");
                let openvino = unsafe { std::ffi::CStr::from_ptr(name) }.to_bytes() == b"OpenVINOExecutionProvider";
                let cache_key = std::ffi::CString::new("cache_dir")?;
                if openvino { std::fs::create_dir_all(&context.cache)?; }
                let cache_path = std::ffi::CString::new(context.cache.to_string_lossy().as_bytes())?;
                let keys = [cache_key.as_ptr()];
                let values = [cache_path.as_ptr()];
                let selected = [device.cast::<ort_sys::OrtEpDevice>()];
                let status = unsafe { (api.SessionOptionsAppendExecutionProvider_V2)(options.cast(), environment.cast(),
                    selected.as_ptr(), 1, if openvino { keys.as_ptr() } else { ptr::null() },
                    if openvino { values.as_ptr() } else { ptr::null() }, usize::from(openvino)) };
                if !status.0.is_null() {
                    let message = unsafe { std::ffi::CStr::from_ptr((api.GetErrorMessage)(status.0)) }.to_string_lossy().into_owned();
                    unsafe { (api.ReleaseStatus)(status.0) };
                    anyhow::bail!("configure host selected provider: {message}");
                }
            }
            if let Some(path) = &context.profiling {
                #[cfg(windows)]
                let encoded: Vec<u16> = {
                    use std::os::windows::ffi::OsStrExt;
                    path.as_os_str().encode_wide().chain(Some(0)).collect()
                };
                #[cfg(not(windows))]
                let encoded = {
                    use std::os::unix::ffi::OsStrExt;
                    std::ffi::CString::new(path.as_os_str().as_bytes())?
                };
                let status = unsafe { (api.EnableProfiling)(options.cast(), encoded.as_ptr()) };
                if !status.0.is_null() {
                    let message = unsafe { std::ffi::CStr::from_ptr((api.GetErrorMessage)(status.0)) }.to_string_lossy().into_owned();
                    unsafe { (api.ReleaseStatus)(status.0) };
                    anyhow::bail!("configure host profiling: {message}");
                }
            }
            Ok(())
        }));
        match result {
            Ok(Ok(())) => 0,
            Ok(Err(error)) => { context.error = Some(error); 6 },
            Err(_) => { context.error = Some(anyhow::anyhow!("host session configuration panicked")); 7 },
        }
    }

    #[cfg(windows)]
    struct ProviderContext { providers: Vec<crate::host_winml::Provider>, error: Option<anyhow::Error>, diagnostics:Vec<String> }

    #[cfg(windows)]
    unsafe extern "C" fn register_host_providers(context: *mut c_void, environment: *mut c_void, api: *const c_void) -> i32 {
        let context = unsafe { &mut *context.cast::<ProviderContext>() };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            anyhow::ensure!(!environment.is_null() && !api.is_null(), "invalid Core native environment");
            let api = unsafe { &*api.cast::<ort_sys::OrtApi>() };
            static REGISTERED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
            let mut registered = REGISTERED.lock().map_err(|_| anyhow::anyhow!("host provider registry poisoned"))?;
            for provider in &context.providers {
                if !provider.ready || registered.contains(&provider.name) { continue; }
                let Some(path) = &provider.path else { continue; };
                use std::os::windows::ffi::OsStrExt;
                let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
                let name = std::ffi::CString::new(provider.name.as_str())?;
                let status = unsafe { (api.RegisterExecutionProviderLibrary)(environment.cast(), name.as_ptr(), path.as_ptr()) };
                if !status.0.is_null() {
                    let message = unsafe { std::ffi::CStr::from_ptr((api.GetErrorMessage)(status.0)) }.to_string_lossy().into_owned();
                    unsafe { (api.ReleaseStatus)(status.0) };
                    context.diagnostics.push(format!("register {}: {message}", provider.name));
                    continue;
                }
                registered.push(provider.name.clone());
            }
            Ok(())
        }));
        match result {
            Ok(Ok(())) => 0,
            Ok(Err(error)) => { context.error = Some(error); 6 },
            Err(_) => { context.error = Some(anyhow::anyhow!("host provider registration panicked")); 7 },
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

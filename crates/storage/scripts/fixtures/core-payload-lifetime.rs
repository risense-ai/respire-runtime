// Synthetic test-only FFI boundary. No model, filesystem, network, or credentials.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static WATCH: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicBool = AtomicBool::new(false);
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct TrackingAllocator;
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 { System.alloc(layout) }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH.compare_exchange(ptr as usize, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            FREED.store(true, Ordering::SeqCst);
        }
        System.dealloc(ptr, layout);
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

mod ffi {
    use super::*;
    #[derive(Default)]
    pub struct Handle { pub plain: usize, pub transport: usize }
    impl Handle {
        fn inspect(input: &[u8]) -> Result<Value> {
            // The original payload allocation must already be gone on FFI entry.
            anyhow::ensure!(FREED.load(Ordering::SeqCst), "payload still live at FFI entry");
            let request: Value = serde_json::from_slice(input)?;
            anyhow::ensure!(request["schema_version"] == 1);
            anyhow::ensure!(request["payload"]["blob"].as_str().is_some_and(|s|
                s.len() == 1024 * 1024 && s.bytes().all(|byte| byte == b'A')));
            anyhow::ensure!(request["payload"]["nested"] == json!([null, true, "\u{4f60}\u{597d}\n\"\\", {"k": 42}]));
            Ok(request)
        }
        fn response(request: &Value) -> Result<(i32, Vec<u8>)> {
            let operation = request["operation"].as_str().context("operation")?;
            if operation == "ffi_error" { bail!("synthetic FFI failure"); }
            if operation == "invalid_json" { return Ok((0, b"{".to_vec())); }
            let code = if operation == "poison" { 7 } else if operation == "business_error" { 6 } else { 0 };
            let id = if operation == "wrong_id" { json!("bad") } else { request["request_id"].clone() };
            Ok((code, serde_json::to_vec(&json!({"schema_version":1, "request_id":id,
                "result":{"ok":true,"id":request["request_id"]},
                "error":{"message":"synthetic error"}}))?))
        }
        pub fn call(&mut self, input: &[u8]) -> Result<(i32, Vec<u8>)> {
            self.plain += 1;
            Self::response(&Self::inspect(input)?)
        }
        pub fn call_with_transport(&mut self, input: &[u8], callback: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<(i32, Vec<u8>)> {
            self.transport += 1;
            let request = Self::inspect(input)?;
            callback(&request)?;
            // Request Vec must remain readable after the callback, too.
            anyhow::ensure!(serde_json::from_slice::<Value>(input)? == request);
            Self::response(&request)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn core() -> Core { Core { handle:ffi::Handle::default(), next_request:0, poisoned:false, native_feedback_contract:None, native_read_heat_contract:None } }
    fn payload() -> Value {
        let blob = "A".repeat(1024 * 1024);
        FREED.store(false, Ordering::SeqCst);
        WATCH.store(blob.as_ptr() as usize, Ordering::SeqCst);
        let mut fields = serde_json::Map::new();
        fields.insert("blob".into(), Value::String(blob));
        fields.insert("nested".into(), json!([null, true, "\u{4f60}\u{597d}\n\"\\", {"k":42}]));
        Value::Object(fields)
    }
    fn serial() -> Result<std::sync::MutexGuard<'static, ()>> { SERIAL.lock().map_err(|_| anyhow::anyhow!("test mutex poisoned")) }
    #[test]
    fn actual_call_inner_plain_frees_payload_before_ffi() -> Result<()> {
        let _guard = serial()?;
        let mut c = core();
        for expected_id in ["1", "2"] {
            assert_eq!(c.call("ok", payload())?, json!({"ok":true,"id":expected_id}));
        }
        assert_eq!((c.handle.plain, c.handle.transport), (2, 0));
        Ok(())
    }
    #[test]
    fn actual_call_inner_transport_frees_payload_before_ffi() -> Result<()> {
        let _guard = serial()?;
        let mut c = core();
        let mut callbacks = 0;
        let result = c.call_with_transport("ok", payload(), &mut |request| {
            callbacks += 1;
            anyhow::ensure!(FREED.load(Ordering::SeqCst));
            anyhow::ensure!(request["request_id"] == "1");
            Ok(json!({"synthetic":true}))
        })?;
        assert_eq!(result, json!({"ok":true,"id":"1"}));
        assert_eq!((c.handle.plain, c.handle.transport, callbacks), (0, 1, 1));
        Ok(())
    }
    #[test]
    fn actual_call_inner_preserves_error_paths_and_poisoning() -> Result<()> {
        let _guard = serial()?;
        for operation in ["ffi_error", "invalid_json", "wrong_id", "business_error", "poison"] {
            for transport in [false, true] {
                let mut c = core();
                let result = if transport { c.call_with_transport(operation, payload(), &mut |_| Ok(Value::Null)) }
                    else { c.call(operation, payload()) };
                let message = result.err().context("expected error")?.to_string();
                let expected = match operation {
                    "ffi_error" => "synthetic FFI failure",
                    "invalid_json" => "invalid Core response JSON",
                    "wrong_id" => "Core response schema or request ID mismatch",
                    "business_error" => "Core error 6: \"synthetic error\"",
                    _ => "Core error 7: \"synthetic error\"",
                };
                assert_eq!(message, expected);
                assert_eq!(c.poisoned, operation == "poison");
                if c.poisoned {
                    assert!(c.call("ok", payload()).is_err());
                    assert_eq!(c.handle.plain + c.handle.transport, 1);
                    assert!(FREED.load(Ordering::SeqCst));
                }
            }
        }
        Ok(())
    }
    #[test]
    fn actual_call_inner_preserves_callback_failure() -> Result<()> {
        let _guard = serial()?;
        let mut c = core();
        let result = c.call_with_transport("ok", payload(), &mut |_| bail!("synthetic callback failure"));
        assert_eq!(result.err().context("expected error")?.to_string(), "synthetic callback failure");
        assert!(!c.poisoned);
        Ok(())
    }
    #[test]
    fn actual_call_inner_counter_exhaustion_drops_payload_without_ffi() -> Result<()> {
        let _guard = serial()?;
        let mut c = core();
        c.next_request = u64::MAX;
        assert!(c.call("ok", payload()).is_err());
        assert_eq!(c.handle.plain + c.handle.transport, 0);
        assert!(FREED.load(Ordering::SeqCst));
        Ok(())
    }
}

//! Isolation for the existing instruction-file tests; no credential-store access.

use std::sync::MutexGuard;

pub struct Isolate {
    _lock: MutexGuard<'static, ()>,
    prev: Option<String>,
    _dir: tempfile::TempDir,
}

impl Isolate {
    pub fn new() -> std::io::Result<Self> {
        let lock = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let prev = std::env::var("RSRS_DATA_DIR").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        Ok(Self {
            _lock: lock,
            prev,
            _dir: dir,
        })
    }
}

impl Drop for Isolate {
    fn drop(&mut self) {
        match &self.prev {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
    }
}

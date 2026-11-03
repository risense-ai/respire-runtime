//! One lock for tests that touch process environment or client.json.
//!
//! auth, service, inject, and sync used to take different mutexes, or none.
//! Parallel tests then wrote the real ~/.rsrs/client.json.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, Once};

static LOCK: Mutex<()> = Mutex::new(());

pub fn guard() -> MutexGuard<'static, ()> {
    // DATA_DIR does not isolate the operating system credential store.
    // Existing auth fixtures must never write or read the user's keyring.
    static KEYRING: Once = Once::new();
    KEYRING.call_once(|| {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    });
    LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

/// Hold the lock, point RSRS_DATA_DIR at a private root, restore it on drop.
pub struct Isolate {
    _lock: MutexGuard<'static, ()>,
    prev: Option<String>,
    dir: tempfile::TempDir,
}

impl Isolate {
    pub fn new() -> std::io::Result<Self> {
        let lock = guard();
        let prev = std::env::var("RSRS_DATA_DIR").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        Ok(Self {
            _lock: lock,
            prev,
            dir,
        })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
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

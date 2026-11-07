//! lock — process-wide mutex for the local library (multi-session protection)
//!
//! A SQLite lock db (`lock.db`) lives in the data directory. The process holds
//! `BEGIN EXCLUSIVE` until exit. Later arrivals poll on SQLITE_BUSY; SQLite
//! releases the lock when the holder exits or crashes. No deadlock, no stale
//! lock files. Every rsrs subcommand acquires this lock in main.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;
use rusqlite::{Connection, ErrorCode};

pub struct LibraryLock {
    _conn: Connection,
}

impl LibraryLock {
    /// Verify that this live ownership guard belongs to the requested library.
    pub fn protects(&self, dir: &Path) -> Result<bool> {
        let held = self
            ._conn
            .path()
            .ok_or_else(|| anyhow::anyhow!("library lock has no persistent path"))?;
        Ok(std::fs::canonicalize(held)? == std::fs::canonicalize(dir.join("lock.db"))?)
    }

    /// Take the library lock and hold it until this object (this process) ends.
    /// While occupied, print wait messages on stderr (do not pollute json stdout)
    /// and retry every 300ms. Give up after max_wait so a stuck holder cannot block forever.
    pub fn acquire(dir: &Path, max_wait: Duration) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("failed to create data dir ({}): {e}", dir.display()))?;
        let path = dir.join("lock.db");
        let conn = Connection::open(&path)
            .map_err(|e| anyhow::anyhow!("failed to open lock db ({}): {e}", path.display()))?;
        let _ = conn.busy_timeout(Duration::from_millis(200));
        let began = Instant::now();
        let mut reported_first = false;
        let mut next_report = Duration::from_secs(10);
        loop {
            match conn.execute_batch("BEGIN EXCLUSIVE;") {
                Ok(_) => return Ok(Self { _conn: conn }),
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == ErrorCode::DatabaseBusy || e.code == ErrorCode::DatabaseLocked =>
                {
                    let waited = began.elapsed();
                    if waited >= max_wait {
                        anyhow::bail!(
                            "memory library still locked after {}s \u{2014} check the holding process or retry later",
                            waited.as_secs()
                        );
                    }
                    if waited >= next_report {
                        eprintln!(
                            "still waiting for another session to release the library ({}s)",
                            waited.as_secs()
                        );
                        next_report += Duration::from_secs(10);
                    } else if !reported_first {
                        eprintln!("memory library is locked by another session; waiting (lock.db exclusive, released when the holder exits)");
                        reported_first = true;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn acquire_and_timeout() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let held = LibraryLock::acquire(dir.path(), Duration::from_secs(2))?;
        let err = LibraryLock::acquire(dir.path(), Duration::from_millis(400));
        assert!(err.is_err(), "second locker must time out");
        drop(held);
        let _again = LibraryLock::acquire(dir.path(), Duration::from_secs(2))?;
        Ok(())
    }
}

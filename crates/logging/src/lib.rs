//! Dependency-free file logging for the respire CLI and the resident runtime.
//!
//! The runtime is detached with all three stdio handles pointed at null
//! (`respire_spawn::spawn_binary_with_boot_token`), so every `eprintln!` on a
//! serving path is silently discarded. This crate gives both binaries a tiny
//! append-only log file instead:
//!
//! - Off by default until `init` installs a sink; every record call before
//!   that is a no-op, so unit tests never write files.
//! - The record level defaults to [`Level::Error`]; `RSRS_LOG` raises or
//!   lowers it (`off|error|warn|info|debug`, case-insensitive, invalid values
//!   keep the default). Human diagnostics stay on stderr per the README
//!   contract; this file is only a persistent tail for support.
//! - Best effort by design: write or rotation failures are swallowed and
//!   never panic, never block business paths.
//! - Separate CLI/runtime files under the data root. The mutex serializes
//!   threads in one process; rotation across processes is best effort.
//!
//! The caller resolves the log directory (CLI: `respire_client_host::paths`,
//! runtime: `respire_app::service`) and passes the full file path to
//! [`init`]; this crate stays free of workspace business dependencies.

use std::any::Any;
use std::fmt::Arguments;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Records at or above the configured level are written; [`Level::Off`]
/// disables the sink entirely.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Off = 4,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
            Level::Off => "OFF",
        }
    }
}

/// Parsed from `RSRS_LOG` (`off|error|warn|info|debug`); anything missing or
/// unrecognised keeps [`Level::Error`].
pub fn parse_level(raw: &str) -> Option<Level> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" => Some(Level::Off),
        "error" => Some(Level::Error),
        "warn" => Some(Level::Warn),
        "info" => Some(Level::Info),
        "debug" => Some(Level::Debug),
        _ => None,
    }
}

fn level_from_env() -> Level {
    std::env::var("RSRS_LOG")
        .ok()
        .and_then(|raw| parse_level(&raw))
        .unwrap_or(Level::Error)
}

/// Rotated file cap; the previous log survives one generation as `<name>.1`.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

pub struct LoggingConfig {
    pub path: PathBuf,
    pub level: Level,
    pub max_bytes: u64,
}

impl LoggingConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            level: level_from_env(),
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

struct Sink {
    file: Option<File>,
    path: PathBuf,
    level: Level,
    max_bytes: u64,
    written: u64,
}

impl Sink {
    fn accepts(&self, level: Level) -> bool {
        self.level != Level::Off && level != Level::Off && level >= self.level
    }
}

static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();

/// Install the process-wide sink. A later call replaces the sink; a failure
/// (unreadable directory, unopenable file) leaves the previous state intact
/// and every record call stays a no-op, so callers may ignore the result.
pub fn init(config: LoggingConfig) -> Result<(), String> {
    if let Some(parent) = config.path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create log directory failed: {error}"))?;
        }
    }
    let written = fs::metadata(&config.path)
        .map(|meta| meta.len())
        .unwrap_or(0);
    let mut sink = Sink {
        file: None,
        path: config.path,
        level: config.level,
        max_bytes: config.max_bytes.max(1),
        written,
    };
    if sink.written > sink.max_bytes {
        rotate(&mut sink);
    }
    if sink.file.is_none() {
        sink.file = Some(open_log(&sink.path)?);
    }
    let mutex = SINK.get_or_init(|| Mutex::new(None));
    match mutex.lock() {
        Ok(mut slot) => *slot = Some(sink),
        Err(poisoned) => *poisoned.into_inner() = Some(sink),
    }
    Ok(())
}

pub fn error(args: Arguments<'_>) {
    write_record(Level::Error, args);
}

pub fn warn(args: Arguments<'_>) {
    write_record(Level::Warn, args);
}

pub fn info(args: Arguments<'_>) {
    write_record(Level::Info, args);
}

pub fn debug(args: Arguments<'_>) {
    write_record(Level::Debug, args);
}

/// Persist the panic event and its code location, never the arbitrary payload.
/// Production callers pass only PanicHookInfo::location, not request input.
pub fn log_panic(_payload: &(dyn Any + Send), location: &str) {
    error(format_args!("panic at {location}"));
}

fn write_record(level: Level, args: Arguments<'_>) {
    let Some(mutex) = SINK.get() else {
        return;
    };
    let Ok(mut slot) = mutex.lock().map_err(|poisoned| poisoned.into_inner()) else {
        return;
    };
    let Some(sink) = slot.as_mut() else {
        return;
    };
    if !sink.accepts(level) {
        return;
    }
    let line = format!("{} {} {}\n", timestamp(), level.label(), args);
    if sink.written + line.len() as u64 > sink.max_bytes {
        rotate(sink);
    }
    if sink.file.is_none() {
        // Self-heal after a failed rotation reopen; records dropped in
        // between stay dropped.
        sink.file = open_log(&sink.path).ok();
    }
    let Some(file) = sink.file.as_mut() else {
        return;
    };
    if file.write_all(line.as_bytes()).is_ok() {
        sink.written += line.len() as u64;
    }
}

/// Rename the current log to `<name>.1` and reopen a fresh file. Every step
/// is best effort: if the rename or reopen fails the sink keeps writing to
/// whatever handle it holds.
fn rotate(sink: &mut Sink) {
    let previous = sink.file.take();
    drop(previous);
    let mut rotated = sink.path.clone().into_os_string();
    rotated.push(".1");
    let rotated = PathBuf::from(rotated);
    // rename(2) over an existing file works on unix but fails on Windows.
    let _ = fs::remove_file(&rotated);
    if fs::rename(&sink.path, &rotated).is_ok() {
        sink.file = open_log(&sink.path).ok();
        sink.written = 0;
    } else {
        sink.file = open_log(&sink.path).ok();
        if sink.file.is_none() {
            return;
        }
    }
}

#[cfg(unix)]
fn open_log(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("open log file failed: {error}"))
}

#[cfg(not(unix))]
fn open_log(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("open log file failed: {error}"))
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ`; the civil-from-days conversion is the
/// standard Howard Hinnant algorithm, kept here so the logging crate itself
/// stays dependency-free and the line format stays canonical.
fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let remain = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remain / 3_600,
        (remain % 3_600) / 60,
        remain % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shift = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_shift + 2) / 5 + 1) as u32;
    let month = if month_shift < 10 {
        month_shift + 3
    } else {
        month_shift - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod logging_tests;

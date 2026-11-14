use super::*;

// init installs a process-global sink, so every test in this crate holds the
// same mutex to stay deterministic under a parallel local `cargo test`; CI
// already runs the workspace single-threaded.
static TEST_LOCK: Mutex<()> = Mutex::new(());
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn level_from_file(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn line_count(text: &str) -> usize {
    text.lines().count()
}

fn init_at(
    dir: &std::path::Path,
    name: &str,
    level: Level,
    max_bytes: u64,
) -> TestResult<std::path::PathBuf> {
    let path = dir.join(name);
    init(LoggingConfig {
        path: path.clone(),
        level,
        max_bytes,
    })?;
    Ok(path)
}

#[test]
fn default_level_only_writes_errors() -> TestResult {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = tempfile::tempdir()?;
    let path = init_at(dir.path(), "levels.log", Level::Error, DEFAULT_MAX_BYTES)?;
    error(format_args!("first failure: {:#}", "root cause"));
    warn(format_args!("warn suppressed"));
    info(format_args!("info suppressed"));
    debug(format_args!("debug suppressed"));
    let text = level_from_file(&path);
    assert!(text.contains(" ERROR first failure: root cause"), "{text}");
    assert_eq!(line_count(&text), 1, "{text}");
    Ok(())
}

#[test]
fn rsrs_log_levels_parse() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (raw, expected) in [
        ("off", Level::Off),
        ("ERROR", Level::Error),
        ("Warn", Level::Warn),
        ("info", Level::Info),
        ("debug", Level::Debug),
        ("  info  ", Level::Info),
    ] {
        assert_eq!(parse_level(raw), Some(expected), "raw={raw:?}");
    }
    // Invalid values yield None; the env fallback keeps Level::Error.
    assert_eq!(parse_level("bogus"), None);
    assert_eq!(parse_level(""), None);
    assert_eq!(parse_level("trace"), None);
}

#[test]
fn rsrs_log_env_controls_level() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = std::env::var("RSRS_LOG").ok();
    std::env::set_var("RSRS_LOG", "warn");
    assert_eq!(LoggingConfig::new(PathBuf::from("x")).level, Level::Warn);
    std::env::set_var("RSRS_LOG", "not-a-level");
    assert_eq!(LoggingConfig::new(PathBuf::from("x")).level, Level::Error);
    std::env::remove_var("RSRS_LOG");
    assert_eq!(LoggingConfig::new(PathBuf::from("x")).level, Level::Error);
    match previous {
        Some(value) => std::env::set_var("RSRS_LOG", value),
        None => std::env::remove_var("RSRS_LOG"),
    }
}

#[test]
fn off_level_writes_nothing() -> TestResult {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = tempfile::tempdir()?;
    let path = init_at(dir.path(), "off.log", Level::Off, DEFAULT_MAX_BYTES)?;
    error(format_args!("must not land"));
    assert_eq!(level_from_file(&path), "");
    Ok(())
}

#[test]
fn rotation_keeps_one_generation() -> TestResult {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = tempfile::tempdir()?;
    let path = init_at(dir.path(), "rotate.log", Level::Error, 128)?;
    for index in 0..8 {
        error(format_args!(
            "failure {index} with some padding text to exceed the cap quickly"
        ));
    }
    let rotated = PathBuf::from(std::format!("{}.1", path.display()));
    let rotated_text = std::fs::read_to_string(&rotated).unwrap_or_default();
    let current = level_from_file(&path);
    assert!(!rotated_text.is_empty(), "rotated generation should exist");
    // One generation kept: the rotated file holds the last records that
    // overflowed the cap, the fresh file holds the most recent ones.
    assert!(rotated_text.contains("failure 6"), "{rotated_text}");
    assert!(!rotated_text.contains("failure 7"), "{rotated_text}");
    assert!(current.contains("failure 7"), "{current}");
    assert!(line_count(&current) < 8, "cap must rotate: {current}");
    // The sink keeps working after rotation.
    error(format_args!("post-rotation failure"));
    assert!(level_from_file(&path).contains("post-rotation failure"));
    Ok(())
}

#[test]
fn concurrent_writers_all_land() -> TestResult {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = tempfile::tempdir()?;
    let path = init_at(dir.path(), "threads.log", Level::Error, DEFAULT_MAX_BYTES)?;
    let handles: Vec<_> = (0..4)
        .map(|worker| {
            std::thread::spawn(move || {
                for index in 0..20 {
                    error(format_args!("worker {worker} failure {index}"));
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().map_err(|_| "writer thread panicked")?;
    }
    let text = level_from_file(&path);
    assert_eq!(line_count(&text), 80, "{text}");
    Ok(())
}

#[test]
fn timestamp_shape_is_iso8601_utc() {
    let stamp = timestamp();
    let bytes = stamp.as_bytes();
    assert_eq!(stamp.len(), 20, "{stamp}");
    assert_eq!(bytes[4], b'-', "{stamp}");
    assert_eq!(bytes[7], b'-', "{stamp}");
    assert_eq!(bytes[10], b'T', "{stamp}");
    assert_eq!(bytes[13], b':', "{stamp}");
    assert_eq!(bytes[16], b':', "{stamp}");
    assert_eq!(bytes[19], b'Z', "{stamp}");
}

#[test]
fn civil_from_days_matches_known_dates() {
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(civil_from_days(20_765), (2026, 11, 8)); // 2026-11-08 UTC
    assert_eq!(civil_from_days(-1), (1969, 12, 31));
}

#[cfg(unix)]
#[test]
fn unix_file_mode_is_owner_only() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = tempfile::tempdir()?;
    let path = init_at(dir.path(), "perms.log", Level::Error, DEFAULT_MAX_BYTES)?;
    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "log file must stay owner-only");
    Ok(())
}

#[test]
fn failed_init_leaves_records_as_noop() -> TestResult {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // A regular file used as a parent directory fails create_dir_all on
    // every platform, so the failure is deterministic in CI and locally.
    let base = tempfile::tempdir()?;
    let blocker = base.path().join("blocker");
    std::fs::write(&blocker, b"x")?;
    let missing_parent = blocker.join("nested.log");
    let result = init(LoggingConfig {
        path: missing_parent,
        level: Level::Error,
        max_bytes: DEFAULT_MAX_BYTES,
    });
    assert!(result.is_err(), "an impossible path must fail init");
    // A failed init leaves the sink state untouched, so the next record call
    // must not panic whether or not an earlier init installed a sink.
    error(format_args!("after failed init"));
    warn(format_args!("still a noop"));
    Ok(())
}

#[test]
fn panic_payload_formats() -> TestResult {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = tempfile::tempdir()?;
    let path = init_at(dir.path(), "panic.log", Level::Error, DEFAULT_MAX_BYTES)?;
    log_panic(&"explicit str panic", "cli::frontend");
    log_panic(&(String::from("owned string panic")), "runtime::serve");
    log_panic(&(7u32), "somewhere");
    let text = level_from_file(&path);
    assert_eq!(line_count(&text), 3, "{text}");
    for location in ["cli::frontend", "runtime::serve", "somewhere"] {
        assert!(
            text.contains(&format!(" ERROR panic at {location}")),
            "{text}"
        );
    }
    for private in ["explicit str panic", "owned string panic"] {
        assert!(!text.contains(private), "panic payload persisted");
    }
    Ok(())
}

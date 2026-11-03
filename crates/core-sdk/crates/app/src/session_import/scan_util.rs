//! Shared helpers for session scanners: file discovery, JSON/JSONL reads,
//! timestamp parsing and small text extraction.
//!
//! Deliberately dependency-free (no glob/tokio): the scanners need only
//! bounded directory walks and simple `*` name matching. Every helper is
//! best-effort and never panics on malformed input or missing files.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Datelike, Duration, SecondsFormat, TimeZone, Utc};
use serde_json::Value;

/// Maximum files a single platform scan considers (newest first), mirroring the
/// reference finder's `MAX_PLATFORM_FILES`.
pub const MAX_PLATFORM_FILES: usize = 2000;

/// User home directory.
pub fn home() -> Option<PathBuf> {
    dirs::home_dir().filter(|p| !p.as_os_str().is_empty())
}

/// A path from an environment variable, ignoring empty values.
pub fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Keep existing, de-duplicated paths in input order.
pub fn existing(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        if path.as_os_str().is_empty() {
            continue;
        }
        if path.exists() && seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

/// Read a file as lossy UTF-8 text (non-UTF-8 bytes are replaced, never fail).
pub fn read_text(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Parse a file as JSON; `None` on any IO or syntax error.
pub fn read_json(path: &Path) -> Option<Value> {
    read_text(path).and_then(|text| serde_json::from_str(&text).ok())
}

/// Parse each line of a file as a JSON object, skipping non-object/blank lines.
pub fn iter_jsonl(path: &Path) -> Vec<Value> {
    let Some(text) = read_text(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.is_object())
        .collect()
}

/// File modification time as an ISO-8601 UTC string.
pub fn file_mtime_iso(path: &Path) -> Option<String> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let datetime: DateTime<Utc> = modified.into();
    Some(datetime.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Modification time as seconds since epoch (0.0 when unavailable).
pub fn mtime_seconds(path: &Path) -> f64 {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Keep the `limit` newest paths by modification time (stable for ties).
pub fn recent(paths: Vec<PathBuf>, limit: usize) -> Vec<PathBuf> {
    let mut keyed: Vec<(f64, PathBuf)> = paths
        .into_iter()
        .map(|path| (mtime_seconds(&path), path))
        .collect();
    keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    keyed.truncate(limit);
    keyed.into_iter().map(|(_, path)| path).collect()
}

/// Whether a file name matches a `*`-wildcard pattern (single path segment).
pub fn match_name(name: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return name == pattern;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let first = parts[0];
    let last = parts[parts.len() - 1];
    if !name.starts_with(first) {
        return false;
    }
    let mut idx = first.len();
    if name.len() < idx {
        return false;
    }
    for part in &parts[1..parts.len().saturating_sub(1)] {
        if part.is_empty() {
            continue;
        }
        match name[idx..].find(part) {
            Some(pos) => idx += pos + part.len(),
            None => return false,
        }
    }
    if last.is_empty() {
        return true;
    }
    name.len() >= idx + last.len() && name[idx..].ends_with(last)
}

/// Files directly inside `dir` whose name matches `pattern`.
pub fn files_in(dir: &Path, pattern: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| match_name(n, pattern))
        })
        .collect()
}

/// Files at or below `dir` (up to `max_depth` extra levels) matching `pattern`.
pub fn files_below(dir: &Path, max_depth: usize, pattern: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((current, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if match_name(name, pattern) {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Parse an ISO-8601-ish timestamp into UTC (Z, offset, or naive treated as UTC).
pub fn parse_stamp(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(parsed.with_timezone(&Utc));
    }
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    None
}

fn iso(datetime: DateTime<Utc>) -> String {
    datetime.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Unix seconds (float) to ISO-8601.
pub fn unix_seconds(value: f64) -> Option<String> {
    let secs = value.trunc() as i64;
    let nanos = (value.fract().abs() * 1_000_000_000.0) as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos).map(iso)
}

/// Unix milliseconds to ISO-8601.
pub fn unix_millis(value: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp_millis(value).map(iso)
}

/// Resolve a date bound keyword (`today`/`yesterday`/`7d`/`YYYY`/`YYYY-MM`/`YYYY-MM-DD`).
pub fn date_bound(value: &str, end: bool) -> Option<DateTime<Utc>> {
    let text = value.trim().to_ascii_lowercase();
    if text.is_empty() {
        return None;
    }
    let now = Utc::now();
    let midnight = now.date_naive().and_hms_opt(0, 0, 0)?;
    let base: DateTime<Utc> = if text == "today" {
        Utc.from_utc_datetime(&midnight)
    } else if text == "yesterday" {
        Utc.from_utc_datetime(&midnight.checked_sub_signed(Duration::try_days(1)?)?)
    } else if let Some(days) = text.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        if days < 0 {
            return None;
        }
        Utc.from_utc_datetime(&midnight.checked_sub_signed(Duration::try_days(days)?)?)
    } else {
        let parts: Vec<&str> = text.split('-').collect();
        if parts.is_empty()
            || parts.len() > 3
            || parts.iter().any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return None;
        }
        let year = parts[0].parse::<i32>().ok()?;
        let month = parts.get(1).map_or(Ok(1), |part| part.parse::<u32>()).ok()?;
        let day = parts.get(2).map_or(Ok(1), |part| part.parse::<u32>()).ok()?;
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single()?
    };
    if !end {
        return Some(base);
    }
    let segment_count = text.split('-').count();
    if text == "today" || text == "yesterday" || text.ends_with('d') || segment_count == 3 {
        return base.checked_add_signed(Duration::try_days(1)?);
    }
    if segment_count == 2 {
        return Utc
            .with_ymd_and_hms(base.year() + (base.month() / 12) as i32, (base.month() % 12) + 1, 1, 0, 0, 0)
            .single();
    }
    Utc.with_ymd_and_hms(base.year() + 1, 1, 1, 0, 0, 0).single()
}

/// Session id fallback derived from a file stem and a marker.
pub fn stem_id(path: &Path, marker: &str) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let after = stem.split(marker).last().unwrap_or(stem);
    after.rsplit('_').next().unwrap_or(after).to_owned()
}

/// JSON object view of a value.
pub fn as_map(value: &Value) -> Option<&serde_json::Map<String, Value>> {
    value.as_object()
}

/// String view of a value.
pub fn jtext(value: &Value) -> Option<String> {
    value.as_str().map(ToOwned::to_owned)
}

/// Extract display text from a string or an array of `{text|content}` parts.
pub fn content_text(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_owned();
    }
    if let Some(items) = value.as_array() {
        let parts: Vec<String> = items
            .iter()
            .filter_map(|item| {
                item.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("content").and_then(Value::as_str))
                    .map(ToOwned::to_owned)
            })
            .filter(|part| !part.is_empty())
            .collect();
        return parts.join("\n");
    }
    String::new()
}

/// Compose `nickname (role)` when both are present, else whichever exists.
pub fn nick_role(nickname: Option<&str>, role: Option<&str>) -> Option<String> {
    match (nickname.map(str::trim).filter(|s| !s.is_empty()), role.map(str::trim).filter(|s| !s.is_empty())) {
        (Some(nick), Some(role)) => Some(format!("{nick} ({role})")),
        (Some(nick), None) => Some(nick.to_owned()),
        (None, Some(role)) => Some(role.to_owned()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_name_supports_prefix_suffix_infix() {
        assert!(match_name("state_5.sqlite", "state_*.sqlite"));
        assert!(match_name("rollout-abc.jsonl", "rollout-*.jsonl"));
        assert!(match_name("any.jsonl", "*.jsonl"));
        assert!(match_name("exact.json", "exact.json"));
        assert!(!match_name("state_5.sqlite", "other_*.sqlite"));
        assert!(!match_name("agent-1.jsonl", "rollout-*.jsonl"));
        assert!(match_name("agent-7.jsonl", "agent-*.jsonl"));
    }

    #[test]
    fn date_bound_handles_keywords_and_parts() -> Result<(), Box<dyn std::error::Error>> {
        assert!(date_bound("2026-10-01", false).is_some());
        let end = date_bound("2026-10", true).ok_or("end bound")?;
        assert_eq!(end.month(), 11);
        let month_only = date_bound("2026-10", false).ok_or("month bound")?;
        assert_eq!(month_only.month(), 10);
        assert!(date_bound("7d", false).is_some());
        assert!(date_bound("", false).is_none());
        assert!(date_bound("-5d", false).is_none());
        assert!(date_bound("2026-1x-01", false).is_none());
        assert!(date_bound("2026-13-01", false).is_none());
        Ok(())
    }

    #[test]
    fn unix_and_content_helpers() -> Result<(), Box<dyn std::error::Error>> {
        assert!(unix_millis(1_700_000_000_000).ok_or("millis")?.starts_with("2023-11-14"));
        assert!(unix_seconds(1_700_000_000.0).ok_or("seconds")?.starts_with("2023-11-14"));
        let parts = serde_json::json!([{"text": "a"}, {"text": "b"}, {"type": "tool"}]);
        assert_eq!(content_text(&parts), "a\nb");
        assert_eq!(nick_role(Some("Tesla"), Some("explorer")), Some("Tesla (explorer)".into()));
        assert_eq!(nick_role(None, Some("writer")), Some("writer".into()));
        assert_eq!(nick_role(None, None), None);
        Ok(())
    }
}

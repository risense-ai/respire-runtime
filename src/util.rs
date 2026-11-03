//! Small shared helpers used by command rendering, listing and labels.

use anyhow::Result;


pub fn now_stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn current_user() -> String {
    respire_app::env::var("RSRS_USER").unwrap_or_else(|_| "local".to_owned())

/// Local-timezone YYYY-MM-DD (parse failure falls back to the first 10 chars of the original).
pub fn local_day_of(s: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| {
            dt.with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|_| s.chars().take(10).collect())
}

/// Device label: `device` first, `computer` as fallback; both empty -> "unknown device (old data)" -
/// so an AI does not miss the empty field and copy commands across machines.
pub fn dev_label(device: &str, computer: &str) -> String {
    if !device.trim().is_empty() {
        device.trim().to_owned()
    } else if !computer.trim().is_empty() {
        computer.trim().to_owned()
    } else {
        "unknown device (old data, do not copy commands across machines)".to_owned()
    }
}

/// Time lower bound for list (§3.8 tidy intake). --since takes an explicit time (RFC3339 or YYYY-MM-DD,
/// the latter from 00:00 UTC that day); --since-resort reads maintenance.json resort_at
/// (written when resort --go resets, i.e. "last tidy time"). Both together take the later one.
/// Missing resort_at (never tidied) -> 1970 epoch, i.e. no filter.
pub fn list_since_bound(since: Option<&str>, since_resort: bool) -> Result<String> {
    let explicit = since.map(respire_app::service::normalize_since).transpose()?;
    let from_resort = if since_resort {
        respire_app::service::resort_at()
    } else {
        None
    };
    Ok(respire_app::service::later_bound(explicit, from_resort))
}

pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

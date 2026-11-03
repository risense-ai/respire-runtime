use anyhow::{Context, Result};
use std::time::Duration;

/// Host policy is immutable for a worker lifetime; only the background lane uses it.
pub(crate) fn background_threads(value: Option<&str>, cores: usize) -> Result<usize> {
    match value {
        Some(value) => Ok(value
            .trim()
            .parse::<usize>()
            .context("RSRS_INTRA_THREADS must be a nonnegative integer")?
            .clamp(1, 16)),
        None => Ok(cores.saturating_sub(1).clamp(1, 16)),
    }
}

pub(crate) fn call_limit(value: Option<&str>, fallback: Duration) -> Duration {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn background_threads_are_bounded_without_changing_foreground_configuration() -> Result<()> {
        for (cores, expected) in [(0, 1), (1, 1), (2, 1), (6, 5), (17, 16), (64, 16)] {
            assert_eq!(background_threads(None, cores)?, expected);
        }
        for (value, expected) in [("0", 1), ("1", 1), (" 4 ", 4), ("16", 16), ("64", 16)] {
            assert_eq!(background_threads(Some(value), 6)?, expected);
        }
        for invalid in ["", "invalid", "-1", "1.5"] {
            assert!(background_threads(Some(invalid), 6).is_err());
        }
        std::thread::scope(|scope| -> Result<()> {
            let checks: Vec<_> = [1usize, 4, 16]
                .into_iter()
                .map(|threads| {
                    scope.spawn(move || -> Result<()> {
                        for _ in 0..100 {
                            assert_eq!(
                                background_threads(Some(&threads.to_string()), 64)?,
                                threads
                            );
                        }
                        Ok(())
                    })
                })
                .collect();
            for check in checks {
                check
                    .join()
                    .map_err(|_| anyhow::anyhow!("thread policy test panicked"))??;
            }
            Ok(())
        })
    }

    #[test]
    fn maintenance_deadline_override_and_fallback() {
        let fallback = Duration::from_secs(365);
        assert_eq!(
            call_limit(Some(" 7200 "), fallback),
            Duration::from_secs(7200)
        );
        for value in [None, Some("0"), Some("-1"), Some("invalid"), Some("")] {
            assert_eq!(call_limit(value, fallback), fallback);
        }
    }
}

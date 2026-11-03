//! Unicode scalar offsets for bounded records inside a daily diary.
//! This module does not read or write memories and has no model dependency.

pub const CHUNK_CHARS: usize = 800;

fn starts_record(line: &str) -> bool {
    let text = line.trim_start();
    let inner = text
        .strip_prefix('\u{3010}')
        .and_then(|s| s.split_once('\u{3011}').map(|p| p.0))
        .or_else(|| {
            text.strip_prefix('[')
                .and_then(|s| s.split_once(']').map(|p| p.0))
        });
    inner.is_some_and(|value| {
        let b = value.as_bytes();
        b.len() == 5
            && b[2] == b':'
            && b[0..2].iter().all(u8::is_ascii_digit)
            && b[3..5].iter().all(u8::is_ascii_digit)
            && &value[0..2] < "24"
            && &value[3..5] < "60"
    })
}

/// Half-open Unicode scalar ranges; never byte offsets or UTF-16 positions.
pub fn ranges(content: &str) -> Vec<(usize, usize)> {
    let mut boundaries = vec![0];
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        if offset > 0 && starts_record(line) {
            boundaries.push(offset);
        }
        offset += line.chars().count();
    }
    boundaries.push(offset);
    let chars: Vec<char> = content.chars().collect();
    let mut result = Vec::new();
    for pair in boundaries.windows(2) {
        let (mut start, end) = (pair[0], pair[1]);
        while start < end {
            let mut stop = (start + CHUNK_CHARS).min(end);
            if stop < end {
                // Prefer a paragraph boundary, but retain a hard upper bound.
                if let Some(n) = chars[start + CHUNK_CHARS / 2..stop]
                    .iter()
                    .rposition(|c| *c == '\n')
                {
                    stop = start + CHUNK_CHARS / 2 + n + 1;
                }
            }
            if chars[start..stop].iter().any(|c| !c.is_whitespace()) {
                result.push((start, stop));
            }
            if stop == end {
                break;
            }
            start = stop.saturating_sub(80).max(start + 1);
        }
    }
    result
}

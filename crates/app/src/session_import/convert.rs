//! Convert a normalized [`Session`] into a protocol `MemoryEntry`.
//!
//! New bodies use the canonical `【Cause】【Action】【Result】` headings.
//! Existing memory bodies are not migrated by this formatter. Credentials embedded in transcripts
//! are scrubbed best-effort before storage (agent policy requires inspecting
//! content before writing; this is a safety net, not a scanner guarantee).

use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::memory::model::{Kind, MemoryEntry};

use super::Session;

/// Conversion knobs chosen by the CLI (`extract` flags).
#[derive(Debug, Clone)]
pub struct ConvertOptions {
    pub kind: Kind,
    /// `important` (reusable) or `trivial` (diary).
    pub importance: String,
    /// Optional causal parent for every imported memory.
    pub parent: String,
    pub user: String,
    /// Device tag (`host/os`).
    pub device: String,
    /// Explicit project override; empty → derived from the session cwd.
    pub project: String,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            kind: Kind::Context,
            importance: "important".to_owned(),
            parent: String::new(),
            user: "local".to_owned(),
            device: String::new(),
            project: String::new(),
        }
    }
}

/// Build one `MemoryEntry` from a session.
pub fn session_entry(session: &Session, opts: &ConvertOptions) -> MemoryEntry {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let created_at = session
        .created_at
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| now.clone());
    let updated_at = session
        .updated_at
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| created_at.clone());
    MemoryEntry {
        metadata: Default::default(),
        unknown_fields: Default::default(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: Vec::new(),
        id: session_id(&session.key()),
        kind: opts.kind,
        tags: vec!["session-import".to_owned(), session.platform.clone()],
        title: scrub(&derive_title(session)),
        content: build_body(session),
        user: opts.user.clone(),
        computer: opts.device.clone(),
        project: project_of(session, &opts.project),
        created_at,
        // These SQLite sources have no reliable per-session modification stamp:
        // WAL commits can leave the main file mtime unchanged. Their cursor uses
        // content instead, and a fresh import needs a fresh LWW write stamp.
        updated_at: if session.uses_content_cursor() {
            now
        } else {
            updated_at
        },
        emotion: -1.0,
        parent_id: opts.parent.clone(),
        importance: opts.importance.clone(),
        device: opts.device.clone(),
        modified_by: opts.device.clone(),
    }
}

/// Human-readable platform label.
fn platform_label(platform: &str) -> String {
    match platform {
        "codex" => "Codex".into(),
        "opencode" => "OpenCode".into(),
        "claude" => "Claude Code".into(),
        "senpi" => "Senpi".into(),
        "oh-my-pi" => "oh-my-pi".into(),
        "gajae-code" => "gajae-code".into(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => other.to_owned(),
            }
        }
    }
}

/// Session title: `<Platform> session <first request>` (concise, event-shaped).
pub fn derive_title(session: &Session) -> String {
    let platform = platform_label(&session.platform);
    let snippet = first_line(&scrub(&session.first_user_message));
    if snippet.is_empty() {
        format!("{platform} session {}", short_id(&session.id))
    } else {
        format!("{platform} session {snippet}")
    }
}

/// Assemble the English scaffold; user-supplied text keeps its original language.
pub fn build_body(session: &Session) -> String {
    let cwd = session.cwd.as_deref().unwrap_or("unknown");
    let model = match (session.provider.as_deref(), session.model.as_deref()) {
        (Some(provider), Some(model)) => format!("{provider}/{model}"),
        (Some(provider), None) => provider.to_owned(),
        (None, Some(model)) => model.to_owned(),
        (None, None) => "unknown".to_owned(),
    };
    let created = session.created_at.as_deref().unwrap_or("unknown");
    let updated = session.updated_at.as_deref().unwrap_or(created);

    let mut body = String::new();
    body.push_str(&format!(
        "\u{3010}Cause\u{3011}{} session {}. Started {}; working directory {}; model {}.",
        platform_label(&session.platform),
        short_id(&session.id),
        scrub(created),
        scrub(&cwd),
        scrub(&model)
    ));

    let first_raw = session.first_user_message.trim();
    let first = truncate_chars(&scrub(first_raw), 600);
    body.push_str("\n\u{3010}Action\u{3011}");
    if first.is_empty() {
        body.push_str("(no user message recorded)");
    } else {
        body.push_str(&first);
    }
    let last_raw = session.last_user_message.trim();
    if !last_raw.is_empty() && last_raw != first_raw {
        body.push_str(&format!(
            "\nLast request: {}",
            truncate_chars(&scrub(last_raw), 400)
        ));
    }

    body.push_str(&format!("\n\u{3010}Result\u{3011}Session updated at {}.", scrub(updated)));
    if let Some(line) = usage_line(&session.usage) {
        body.push(' ');
        body.push_str(&line);
    }
    if let Some(agent) = session.agent.as_deref().filter(|s| !s.is_empty()) {
        body.push_str(&format!(" Executed by subagent `{}`", scrub(agent)));
        if let Some(parent) = session.parent_id.as_deref().filter(|s| !s.is_empty()) {
            body.push_str(&format!(" (parent session {})", short_id(parent)));
        }
        body.push('.');
    }
    body
}

fn usage_line(usage: &serde_json::Map<String, Value>) -> Option<String> {
    if usage.is_empty() {
        return None;
    }
    let number = |key: &str| -> Option<f64> { usage.get(key).and_then(Value::as_f64) };
    let mut parts = Vec::new();
    let total = number("totalTokens").or_else(|| number("total_tokens"));
    if let Some(total) = total {
        parts.push(format!("tokens {total:.0}"));
    } else {
        if let Some(input) = number("input") {
            parts.push(format!("input {input:.0}"));
        }
        if let Some(output) = number("output") {
            parts.push(format!("output {output:.0}"));
        }
    }
    if let Some(cost) = number("cost_total") {
        parts.push(format!("cost {cost:.4}"));
    }
    if let Some(count) = number("message_count") {
        parts.push(format!("messages {count:.0}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("{}.", parts.join("; ")))
    }
}

/// Resolve the project label: explicit override, else the cwd basename.
fn project_of(session: &Session, explicit: &str) -> String {
    if !explicit.trim().is_empty() {
        return scrub(explicit.trim());
    }
    session
        .cwd
        .as_deref()
        .and_then(|cwd| cwd.trim_end_matches(['/', '\\']).rsplit(['/', '\\']).next())
        .filter(|name| !name.is_empty())
        .map(scrub)
        .unwrap_or_default()
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| truncate_chars(&collapse_ws(line), 40))
        .unwrap_or_default()
}

fn collapse_ws(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_owned()
    } else {
        let mut out: String = text.chars().take(max).collect();
        out.push('\u{2026}');
        out
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Stable memory id for a session (UUIDv5-shaped from `platform:id`), so
/// re-importing the same session maps to the same row instead of a duplicate.
fn session_id(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Best-effort credential scrub: PEM blocks, `key=value` secrets and known
/// token prefixes are redacted so plaintext secrets are not stored.
pub fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_pem = false;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if line.contains("-----BEGIN") && lower.contains("private key") {
            in_pem = true;
            out.push_str("[REDACTED PRIVATE KEY]");
            out.push('\n');
            continue;
        }
        if in_pem {
            if line.contains("-----END") && lower.contains("private key") {
                in_pem = false;
            }
            continue;
        }
        out.push_str(&redact_line(line));
        out.push('\n');
    }
    if !text.ends_with('\n') {
        out.pop();
    }
    out
}

const SECRET_KEYS: [&str; 17] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "authorization",
    "bearer",
    "credential",
    "client_secret",
    "\u{5bc6}\u{7801}",
    "\u{53e3}\u{4ee4}",
    "\u{5bc6}\u{94a5}",
    "\u{4ee4}\u{724c}",
    "\u{51ed}\u{8bc1}",
];

fn redact_line(line: &str) -> String {
    let masked = redact_key_value(line).unwrap_or_else(|| line.to_owned());
    let masked = redact_bearer(&masked);
    redact_prefixed_tokens(&masked)
}

/// Mask the value when a secret keyword is followed (after spaces/tabs and an
/// optional opening quote) by `=`/`:` (ASCII or full-width), or when the keyword
/// is a `--flag` whose value is whitespace-separated (`--password hunter2`). Prose
/// that merely mentions "token" or a timestamp is not truncated.
fn redact_key_value(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let mut best: Option<usize> = None;
    for key in SECRET_KEYS {
        let mut from = 0;
        while let Some(relative) = lower[from..].find(key) {
            let pos = from + relative;
            let after = &line[pos + key.len()..];
            let trimmed = after.trim_start_matches([' ', '\t', '"', '\'']);
            let separator = trimmed
                .chars()
                .next()
                .filter(|c| matches!(*c, '=' | ':' | '\u{ff1a}'));
            let index = if let Some(separator) = separator {
                line.len() - (trimmed.len() - separator.len_utf8())
            } else if line[..pos].ends_with("--") {
                // CLI flag form `--password <value>`: value is whitespace-separated.
                let gap = after.len() - after.trim_start_matches([' ', '\t']).len();
                if gap == 0 {
                    from = pos + key.len();
                    continue;
                }
                pos + key.len()
            } else {
                from = pos + key.len();
                continue;
            };
            best = Some(best.map_or(index, |current| current.min(index)));
            from = pos + key.len();
        }
    }
    best.map(|index| {
        let (head, _) = line.split_at(index);
        format!("{head} ***")
    })
}

/// Mask the token in `Bearer <token>` even without a `=`/`:` separator.
fn redact_bearer(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(pos) = rest.to_ascii_lowercase().find("bearer") {
        let end = pos + "bearer".len();
        result.push_str(&rest[..end]);
        rest = &rest[end..];
        let space = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let token = &rest[space..];
        let token_len = token
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | ',' | ';' | ')' | ']'))
            .unwrap_or(token.len());
        if space > 0 && token_len >= 8 {
            result.push_str(&rest[..space]);
            result.push_str("***");
            rest = &rest[space + token_len..];
        }
    }
    result.push_str(rest);
    result
}

const TOKEN_PREFIXES: [&str; 14] = [
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
    "eyJ",
];

fn redact_prefixed_tokens(line: &str) -> String {
    let mut result = String::new();
    let mut rest = line;
    loop {
        let mut earliest: Option<(usize, &str)> = None;
        for prefix in TOKEN_PREFIXES {
            if let Some(idx) = rest.find(prefix) {
                if earliest.map_or(true, |(best, _)| idx < best) {
                    earliest = Some((idx, prefix));
                }
            }
        }
        let Some((idx, prefix)) = earliest else {
            result.push_str(rest);
            break;
        };
        result.push_str(&rest[..idx]);
        let after = &rest[idx..];
        let run: String = after[prefix.len()..]
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric()
                    || *c == '-'
                    || *c == '_'
                    || (prefix == "eyJ" && *c == '.')
            })
            .collect();
        if run.len() >= 8 {
            result.push_str(prefix);
            result.push_str("***");
        } else {
            result.push_str(prefix);
            result.push_str(&run);
        }
        rest = &after[prefix.len() + run.len()..];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Session {
        Session {
            platform: "codex".into(),
            id: "0199abcd-1234".into(),
            path: "path".into(),
            cwd: Some("/home/u/respire".into()),
            created_at: Some("2026-10-01T00:00:00Z".into()),
            updated_at: Some("2026-10-01T02:00:00Z".into()),
            provider: Some("openai".into()),
            model: Some("gpt-5".into()),
            first_user_message: "add an extract command".into(),
            last_user_message: "ship it".into(),
            usage: [("total_tokens".to_owned(), serde_json::json!(1234))]
                .into_iter()
                .collect(),
            parent_id: None,
            agent: None,
        }
    }

    #[test]
    fn english_scaffold_preserves_chinese_user_data_and_input_version() {
        let mut session = sample();
        session.platform = "hermes".into();
        session.first_user_message = "\u{4fdd}\u{7559}\u{7528}\u{6237}\u{4e2d}\u{6587}\u{4e0e}\u{3010}\u{524d}\u{56e0}\u{3011}\u{539f}\u{59cb}\u{5f15}\u{7528}".into();
        session.last_user_message = "\u{4fdd}\u{7559}\u{6df7}\u{5408}\u{3010}Result\u{3011}\u{539f}\u{6587}".into();
        let fingerprint = session.content_fingerprint();
        let entry = session_entry(&session, &ConvertOptions::default());
        assert_eq!(fingerprint, session.content_fingerprint());
        assert_eq!(entry.id, session_id(&session.key()));
        assert_eq!(entry.title, "Hermes session \u{4fdd}\u{7559}\u{7528}\u{6237}\u{4e2d}\u{6587}\u{4e0e}\u{3010}\u{524d}\u{56e0}\u{3011}\u{539f}\u{59cb}\u{5f15}\u{7528}");
        assert!(entry.content.starts_with("\u{3010}Cause\u{3011}Hermes session"));
        assert!(entry.content.contains("\n\u{3010}Action\u{3011}\u{4fdd}\u{7559}\u{7528}\u{6237}\u{4e2d}\u{6587}\u{4e0e}\u{3010}\u{524d}\u{56e0}\u{3011}\u{539f}\u{59cb}\u{5f15}\u{7528}"));
        assert!(entry.content.contains("\nLast request: \u{4fdd}\u{7559}\u{6df7}\u{5408}\u{3010}Result\u{3011}\u{539f}\u{6587}"));
        assert!(entry.content.contains("\n\u{3010}Result\u{3011}Session updated at"));
        assert_eq!(entry.importance, "important");
        assert_eq!(scrub("\u{8bf4}\u{660e}\u{4e2d}\u{6587}\u{4fdd}\u{6301}\u{ff1b}\u{5bc6}\u{7801}\u{ff1a}fixture-secret"), "\u{8bf4}\u{660e}\u{4e2d}\u{6587}\u{4fdd}\u{6301}\u{ff1b}\u{5bc6}\u{7801}\u{ff1a} ***");
    }

    #[test]
    fn builds_entry_with_three_markers_and_metadata() {
        let entry = session_entry(&sample(), &ConvertOptions::default());
        assert!(entry.content.contains("\u{3010}Cause\u{3011}"));
        assert!(entry.content.contains("\u{3010}Action\u{3011}"));
        assert!(entry.content.contains("\u{3010}Result\u{3011}"));
        assert_eq!(entry.project, "respire");
        assert_eq!(entry.importance, "important");
        assert!(entry.title.starts_with("Codex session"));
        assert_eq!(
            entry.tags,
            vec!["session-import".to_owned(), "codex".to_owned()]
        );
    }

    #[test]
    fn scrub_redacts_secrets_and_pem() {
        let raw = "password=hunter2\nAuthorization: Bearer abcdef\ntoken=ghp_ABCDEFGHIJKLMNOP\nAKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        let clean = scrub(raw);
        assert!(!clean.contains("hunter2"));
        assert!(!clean.contains("ghp_ABCDEFGHIJKLMNOP"));
        assert!(!clean.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!clean.contains("MIIabc"));
        assert!(clean.contains("[REDACTED PRIVATE KEY]"));
    }

    #[test]
    fn title_falls_back_to_id() {
        let mut s = sample();
        s.first_user_message = String::new();
        assert_eq!(derive_title(&s), format!("Codex session {}", "0199abcd"));
    }

    #[test]
    fn redact_only_when_keyword_adjoins_separator() {
        assert_eq!(
            scrub("\u{4f1a}\u{8bdd}\u{66f4}\u{65b0}\u{4e8e} 2026-10-01T02:03:00Z"),
            "\u{4f1a}\u{8bdd}\u{66f4}\u{65b0}\u{4e8e} 2026-10-01T02:03:00Z"
        );
        assert_eq!(
            scrub("fix the token refresh bug: now"),
            "fix the token refresh bug: now"
        );
        assert!(scrub("token=abcd1234").contains("***"));
        assert!(scrub("api_key: abcd1234").contains("***"));
        assert!(scrub("\u{5bc6}\u{7801}\u{ff1a}hunter2").contains("***"));
    }

    #[test]
    fn redact_masks_quoted_json_and_flag_values() {
        let object = scrub(r#"{"password": "hunter2"}"#);
        assert!(!object.contains("hunter2"));
        assert!(object.contains("***"));

        let pair = scrub(r#""secret":"abcdefgh123""#);
        assert!(!pair.contains("abcdefgh123"));
        assert!(pair.contains("***"));

        let flag = scrub("mysql -u root --password hunter2");
        assert!(!flag.contains("hunter2"));
        assert!(flag.contains("***"));
    }

    #[test]
    fn scrub_masks_bearer_without_separator() {
        let masked = scrub("curl -H 'Authorization: Bearer abcdefghijklmnop'");
        assert!(!masked.contains("abcdefghijklmnop"));
        let bare = scrub("Bearer abcdefghijklmnop");
        assert!(!bare.contains("abcdefghijklmnop"));
    }

    #[test]
    fn private_key_detection_is_strict() {
        let prose = "Let's begin by rotating the private key for the service";
        assert_eq!(scrub(prose), prose);
        let block = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert!(scrub(block).contains("[REDACTED PRIVATE KEY]"));
    }

    #[test]
    fn stable_id_is_deterministic_and_title_is_scrubbed() {
        let a = session_entry(&sample(), &ConvertOptions::default());
        let b = session_entry(&sample(), &ConvertOptions::default());
        assert_eq!(a.id, b.id);

        let mut s = sample();
        s.first_user_message = "password=hunter2 now continue".into();
        let entry = session_entry(&s, &ConvertOptions::default());
        assert!(!entry.title.contains("hunter2"));
    }

    #[test]
    fn mixed_and_repeated_credentials_are_scrubbed_in_every_projection() {
        let secrets = [
            "ghp_SYNTHETIC1234567890",
            "sk-SYNTHETIC1234567890",
            "SYNTHETIC_BEARER_A",
            "SYNTHETIC_BEARER_B",
            "fixture-password",
        ];
        let lines = [
            format!("{} password={}", secrets[0], secrets[4]),
            format!("{} {} password={}", secrets[0], secrets[1], secrets[4]),
            format!("Bearer {} Bearer {}", secrets[2], secrets[3]),
            format!(
                r#"{{"a":"Bearer {}","b":"Bearer {}"}}"#,
                secrets[2], secrets[3]
            ),
            format!("Bearer short; bearer {}; BEARER {}", secrets[2], secrets[3]),
            format!(
                r#"{{"note":"{}", "password":"{}", "other":"{}"}}"#,
                secrets[0], secrets[4], secrets[1]
            ),
            format!(
                "Bearer {} {} --password {}",
                secrets[2], secrets[0], secrets[4]
            ),
            format!(
                "{}\nBearer {}\npassword={}",
                secrets[0], secrets[2], secrets[4]
            ),
        ];
        for line in lines {
            let mut session = sample();
            session.first_user_message = line.clone();
            session.last_user_message = line.clone();
            let entry = session_entry(&session, &ConvertOptions::default());
            for output in [
                scrub(&line),
                entry.title,
                entry.content,
                session.to_json().to_string(),
            ] {
                for secret in secrets {
                    assert!(!output.contains(secret), "credential leaked from {line:?}");
                }
            }
        }
        let prose = "fix the token refresh bug: now; discuss bearer";
        assert_eq!(scrub(prose), prose);
        let jwt = "eyJSYNTHETIC_HEADER.SYNTHETIC_PAYLOAD.SYNTHETIC_SIGNATURE";
        let scrubbed = scrub(&format!("{jwt} {}", secrets[0]));
        assert!(!scrubbed.contains("SYNTHETIC_PAYLOAD"));
        assert!(!scrubbed.contains("SYNTHETIC_SIGNATURE"));
    }

    #[test]
    fn content_versioned_sqlite_import_gets_fresh_write_timestamp() -> anyhow::Result<()> {
        let mut session = sample();
        session.platform = "hermes".into();
        session.updated_at = Some("2020-01-01T00:00:00.000Z".into());
        let entry = session_entry(&session, &ConvertOptions::default());
        let imported = super::super::scan_util::parse_stamp(&entry.updated_at)
            .ok_or_else(|| anyhow::anyhow!("invalid import timestamp"))?;
        let source = super::super::scan_util::parse_stamp("2020-01-01T00:00:00.000Z")
            .ok_or_else(|| anyhow::anyhow!("invalid fixture timestamp"))?;
        assert!(imported > source);
        assert!(
            entry.content.contains("2020-01-01"),
            "source time remains in body"
        );
        Ok(())
    }
}

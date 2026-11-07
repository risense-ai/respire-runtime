//! space - spaces (virtual accounts) and membership (shared across accounts).
//!
//! Model (locked 2026-09-20): **a space is an account**. An owner account can hang several
//! virtual accounts; each is a space with its own super key and data dir (reuses account_dir).
//! "Join" = a member builds that space's profile on their machine from an invite, then switches freely.
//!
//! Isolation: (1) independent data_dir (2) independent session.json (token/URK/super key)
//! (3) independent store file.
//!
//! **Zero server change**: a space account is just a user on the server; members hold an
//! independent session token for that user (`sessions` already supports many sessions per user,
//! `db.rs:192`); sync uses the existing per-user partition. The owner mints a member session
//! with existing `POST /api/self/sessions` and ships it in the invite; the member fetches vault
//! (`GET /api/self/vault`) for key material. **The super password never goes through the server**.
//! Kick = revoke that session (`DELETE /api/self/sessions/{id}/revoke`); the kicked member fails immediately.
//!
//! Security boundary (do not blur): kick only blocks future access; it does not claw back
//! already-decrypted history. If a member exported the super password before leaving, they
//! can still unwrap all history. Real revoke needs a super-password rotation and a full
//! re-encrypt of the space - not this round.

use anyhow::Result;
use serde_json::json;

use respire_client_host::config;

/// Invite-code prefix (easy to recognize; room to change the format later).
pub const INVITE_PREFIX: &str = "1mem-invite:";

/// File in the space profile listing issued sessions (owner revoke = kick).
pub const SESSIONS_FILE: &str = "space_sessions.json";
/// File in the space profile marking "created on this machine" (owner identity).
pub const OWNER_FILE: &str = "space_owner.json";

/// Space-name check: reuse the account-profile whitelist (letters/digits/-/_).
/// Note: do not reject `main` - `main` is a valid switch target (back to the primary profile);
/// only `create` forbids occupying that name.
pub fn validate_space_name(name: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty() {
        return Err(
            respire_client_host::input_error::InputError("space name must not be empty".into()).into(),
        );
    }
    if n.len() > 40 {
        return Err(respire_client_host::input_error::InputError(
            "space name too long (<=40 bytes)".into(),
        )
        .into());
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(respire_client_host::input_error::InputError(format!(
            "space name allows only letters/digits/-/_, got \"{name}\""
        ))
        .into());
    }
    Ok(())
}

/// Decode an invite -> payload.
pub fn parse_invite(code: &str) -> Result<serde_json::Value> {
    let raw = code.trim();
    let hexed = raw.strip_prefix(INVITE_PREFIX).unwrap_or(raw);
    if hexed.is_empty() || hexed.len() % 2 != 0 {
        return Err(respire_client_host::input_error::InputError(
            "invite code format is wrong (odd length)".into(),
        )
        .into());
    }
    let cs: Vec<char> = hexed.chars().collect();
    let mut bytes = Vec::with_capacity(cs.len() / 2);
    for pair in cs.chunks(2) {
        let s: String = pair.iter().collect();
        bytes.push(u8::from_str_radix(&s, 16).map_err(|_| {
            respire_client_host::input_error::InputError("invite code contains illegal characters".into())
        })?);
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        respire_client_host::input_error::InputError("invite code is not valid text".into())
    })?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| respire_client_host::input_error::InputError("invite code failed to parse".into()))?;
    for k in ["space", "addr", "user", "token", "super"] {
        if v[k].as_str().unwrap_or("").trim().is_empty() {
            return Err(respire_client_host::input_error::InputError(format!(
                "invite code missing field \"{k}\" - the code may be truncated"
            ))
            .into());
        }
    }
    Ok(v)
}

/// Validate user input before a host stops its current runtime.
pub fn validate_join(code: &str) -> Result<serde_json::Value> {
    let value = parse_invite(code)?;
    let name = value["space"].as_str().unwrap_or("").trim();
    validate_space_name(name)?;
    if account_dir(name)?.exists() {
        return Err(respire_client_host::input_error::InputError(format!(
            "this machine already has space \"{name}\"; choose another space or remove the old profile explicitly"
        )).into());
    }
    Ok(value)
}

fn account_dir(name: &str) -> Result<std::path::PathBuf> {
    validate_space_name(name)?;
    let (root, _) = config::control_roots()?;
    let directory = if name.trim() == "main" {
        root
    } else {
        root.join("accounts").join(name.trim())
    };
    config::normalize_control_path(&directory)
}

/// List member sessions this space has issued (owner view, for kick).
pub fn space_members(name: Option<&str>) -> Result<serde_json::Value> {
    let (root, current) = config::control_roots()?;
    let dir = match name {
        Some(n) if !n.trim().is_empty() => {
            validate_space_name(n)?;
            account_dir(n.trim())?
        }
        _ => current,
    };
    let rows = read_sessions(&dir)?;
    let space = dir.strip_prefix(root.join("accounts")).ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "main".to_owned());
    Ok(json!({ "space": space, "members": rows }))
}

fn read_sessions(dir: &std::path::Path) -> Result<Vec<serde_json::Value>> {
    let path = config::normalize_control_path(&dir.join(SESSIONS_FILE))?;
    Ok(std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn space_name_validation() {
        assert!(validate_space_name("work").is_ok());
        assert!(validate_space_name("dept-x_1").is_ok());
        assert!(
            validate_space_name("main").is_ok(),
            "main is a valid switch target; create forbids it separately"
        );
        assert!(validate_space_name("").is_err());
        assert!(validate_space_name("\u{6709}\u{4e2d}\u{6587}").is_err());
        assert!(
            validate_space_name("a/b").is_err(),
            "path traversal is forbidden"
        );
        assert!(validate_space_name("../etc").is_err());
    }

    #[test]
    fn invite_roundtrip() -> Result<()> {
        let payload = json!({
            "space": "team-a",
            "addr": "https://example.com",
            "user": "team-a",
            "token": "deadbeef",
            "session_id": "sid-1",
            "super": "A3-abc-def",
        });
        let hexed: String = serde_json::to_string(&payload)?
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        let code = format!("{INVITE_PREFIX}{hexed}");
        let back = parse_invite(&code)?;
        assert_eq!(back["space"], "team-a");
        assert_eq!(back["user"], "team-a");
        assert_eq!(back["super"], "A3-abc-def");
        assert_eq!(back["session_id"], "sid-1");
        Ok(())
    }

    #[test]
    fn invite_rejects_bad_input() -> Result<()> {
        assert!(parse_invite("1mem-invite:zz").is_err(), "illegal hex");
        assert!(parse_invite("1mem-invite:6162").is_err(), "not JSON");
        assert!(parse_invite("1mem-invite:").is_err(), "empty code");
        // missing fields
        let p = json!({"space":"a","addr":"b","user":"c"});
        let hexed: String = serde_json::to_string(&p)?
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            parse_invite(&format!("{INVITE_PREFIX}{hexed}")).is_err(),
            "missing token/super must be rejected"
        );
        Ok(())
    }

}

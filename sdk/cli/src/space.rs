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

use anyhow::{anyhow, Result};
use serde_json::json;

use crate::service::{account_dir, account_remove, account_use, accounts_root, data_dir};

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
        return Err(respire_app::input_error::InputError("space name must not be empty".into()).into());
    }
    if n.len() > 40 {
        return Err(respire_app::input_error::InputError("space name too long (<=40 bytes)".into()).into());
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(respire_app::input_error::InputError(format!(
            "space name allows only letters/digits/-/_, got \"{name}\""
        )).into());
    }
    Ok(())
}

/// List every space profile on this machine (primary + each dir under accounts/).
///
/// Do not depend on `account_list`'s existence filter - a space profile must list even
/// before register, so every directory under accounts/ counts as a space.
pub fn space_list() -> Result<serde_json::Value> {
    let current = data_dir();
    // "primary" = the space-profile root (`RSRS_DATA_DIR` or its default), **not** current -
    // current may already be a space profile after a switch. Treating current as main makes
    // the main row always "current" and the real profile look inactive (2026-09-20: GUI showed
    // "current: main   teamA").
    let main_dir = crate::service::main_data_dir();
    let mut out = vec![space_row("main", &main_dir, &current)];
    if let Ok(rd) = std::fs::read_dir(accounts_root()) {
        let mut names: Vec<std::ffi::OsString> =
            rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        names.sort();
        for n in names {
            let dir = accounts_root().join(&n);
            if !dir.is_dir() {
                continue;
            }
            out.push(space_row(&n.to_string_lossy(), &dir, &current));
        }
    }
    Ok(json!({ "spaces": out, "current_dir": current.to_string_lossy() }))
}

fn space_row(name: &str, dir: &std::path::Path, current: &std::path::Path) -> serde_json::Value {
    json!({
        "name": name,
        "dir": dir.to_string_lossy(),
        "user": crate::service::session_user_of_dir(dir),
        "current": dir == current,
        "owner": dir.join(OWNER_FILE).exists(),
        "is_main": name == "main",
        "members": read_sessions(dir).len(),
    })
}

/// Create a space: new profile and switch into it (not signed in). Returns `{name, dir, hint}`.
pub fn space_create(name: &str) -> Result<serde_json::Value> {
    respire_app::service::require_profile_change_host()?;
    validate_space_name(name)?;
    let n = name.trim();
    if n == "main" {
        return Err(respire_app::input_error::InputError(
            "\"main\" is reserved for the primary profile; pick another space name"
                .into()
        ).into());
    }
    if account_dir(n)?.exists() {
        return Err(respire_app::input_error::InputError(format!(
            "space \"{n}\" already exists - pick another name, or run rsrs space use {n}"
        )).into());
    }
    let v = account_use(n)?;
    let dir = std::path::Path::new(v["dir"].as_str().unwrap_or("")).to_path_buf();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(OWNER_FILE), json!({ "name": n }).to_string())?;
    Ok(json!({
        "name": n,
        "dir": dir.to_string_lossy(),
        "hint": "space created and switched in - next rsrs register for this space, then space invite to mint an invite code",
    }))
}

/// Mint an invite: sign a new member session and pack it with the server address and super password.
///
/// `readonly` = a read-only member (recall only, no writes). Read-only is a **session** property;
/// the server rejects writes by token; this machine also records readonly in agent.json (belt and braces).
///
/// **There is only one super password** - the invite is that key; pass it on a trusted channel.
pub fn space_invite(note: Option<&str>, readonly: bool) -> Result<serde_json::Value> {
    let dir = data_dir();
    let session = read_session(&dir)?;
    let user = session["user"].as_str().unwrap_or("").trim().to_owned();
    if user.is_empty() {
        return Err(anyhow!(
            "this profile has no account yet - register/login before minting an invite"
        ));
    }
    let addr = session["addr"]
        .as_str()
        .unwrap_or("")
        .trim()
        .trim_end_matches('/')
        .to_owned();
    if addr.is_empty() {
        return Err(anyhow!(
            "this profile has no server address - login/register first"
        ));
    }
    let token = session["token"].as_str().unwrap_or("").trim().to_owned();
    if token.is_empty() {
        return Err(anyhow!("this profile has no token - login/register first"));
    }
    let super_pass = crate::keystore::load_super(&user).ok_or_else(|| {
        anyhow!("cannot load this space's super password (not in the keyring and RSRS_SUPER is unset) - login --super <code> to store it")
    })?;
    let name = space_name_of(&dir).unwrap_or_else(|| user.clone());

    // Sign a member session on the existing endpoint (many sessions per user; the server already supports it)
    let device = format!("member-{}", note.unwrap_or("invited").trim());
    let (member_token, member_sid) = create_member_session(&addr, &token, &device, readonly)?;

    // Persist on the owner side, so kick can find the session later
    let mut rows = read_sessions(&dir);
    rows.push(json!({
        "session_id": member_sid,
        "device_name": device,
        "readonly": readonly,
        "issued_at": chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }));
    write_sessions(&dir, &rows)?;

    let payload = json!({
        "space": name,
        "addr": addr,
        "user": user,
        "token": member_token,
        "session_id": member_sid,
        "super": super_pass,
        "readonly": readonly,
    });
    let body = serde_json::to_string(&payload)?;
    let hexed: String = body.bytes().map(|b| format!("{b:02x}")).collect();
    Ok(json!({
        "space": name,
        "session_id": member_sid,
        "readonly": readonly,
        "code": format!("{INVITE_PREFIX}{hexed}"),
    }))
}

/// Decode an invite -> payload.
pub fn parse_invite(code: &str) -> Result<serde_json::Value> {
    let raw = code.trim();
    let hexed = raw.strip_prefix(INVITE_PREFIX).unwrap_or(raw);
    if hexed.is_empty() || hexed.len() % 2 != 0 {
        return Err(respire_app::input_error::InputError("invite code format is wrong (odd length)".into()).into());
    }
    let cs: Vec<char> = hexed.chars().collect();
    let mut bytes = Vec::with_capacity(cs.len() / 2);
    for pair in cs.chunks(2) {
        let s: String = pair.iter().collect();
        bytes.push(
            u8::from_str_radix(&s, 16)
                .map_err(|_| respire_app::input_error::InputError("invite code contains illegal characters".into()))?,
        );
    }
    let text = String::from_utf8(bytes).map_err(|_| respire_app::input_error::InputError("invite code is not valid text".into()))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| respire_app::input_error::InputError("invite code failed to parse".into()))?;
    for k in ["space", "addr", "user", "token", "super"] {
        if v[k].as_str().unwrap_or("").trim().is_empty() {
            return Err(respire_app::input_error::InputError(format!(
                "invite code missing field \"{k}\" - the code may be truncated"
            )).into());
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
        return Err(respire_app::input_error::InputError(format!(
            "this machine already has space \"{name}\"; choose another space or remove the old profile explicitly"
        )).into());
    }
    Ok(value)
}

/// Join a space: decode invite -> create profile -> fetch vault with the member token -> write session -> super password into the keyring.
pub fn space_join(code: &str) -> Result<serde_json::Value> {
    respire_app::service::require_profile_change_host()?;
    let v = validate_join(code)?;
    let name = v["space"].as_str().unwrap_or("").trim().to_owned();
    let dir = account_dir(&name)?;
    let addr = v["addr"]
        .as_str()
        .unwrap_or("")
        .trim()
        .trim_end_matches('/')
        .to_owned();
    let user = v["user"].as_str().unwrap_or("").trim().to_owned();
    let token = v["token"].as_str().unwrap_or("").trim().to_owned();
    let session_id = v["session_id"].as_str().unwrap_or("").trim().to_owned();
    let super_pass = v["super"].as_str().unwrap_or("").trim().to_owned();

    // Prove the code: fetch vault with the member token (endpoint requires auth; a dead token fails)
    let vault = fetch_vault(&addr, &token)?;
    std::fs::create_dir_all(&dir)?;

    let session = json!({
        "addr": addr,
        "user": user,
        "token": token,
        "session_id": session_id,
        "kdf_salt": vault["kdf_salt"],
        "wrapped_urk": vault["wrapped_urk"],
        "urk_nonce": vault["urk_nonce"],
        "vault_version": vault["version"].as_i64().unwrap_or(4),
    });
    std::fs::write(
        dir.join("session.json"),
        serde_json::to_string_pretty(&session)?,
    )?;
    // Read-only member: set readonly in local agent.json (write commands blocked); the server also enforces at session level.
    // readonly_team=true marks the source - a personal readonly has no such key and can be lifted; team readonly cannot (H2).
    let readonly = v["readonly"].as_bool().unwrap_or(false);
    if readonly {
        std::fs::write(
            dir.join("agent.json"),
            serde_json::to_vec_pretty(&json!({ "readonly": true, "readonly_team": true }))?,
        )?;
    }
    let mut keyring = true;
    if let Err(e) = crate::keystore::save_super(&user, &super_pass) {
        keyring = false;
        eprintln!("WARN {e}");
    }
    Ok(json!({
        "space": name,
        "dir": dir.to_string_lossy(),
        "user": user,
        "addr": addr,
        "readonly": readonly,
        "keyring": keyring,
        "hint": if readonly {
            format!("joined space \"{name}\" (**read-only** - recall only, no writes) - rsrs space use {name} to switch")
        } else {
            format!("joined space \"{name}\" - rsrs space use {name} to switch")
        },
    }))
}

/// Switch space (reuses account_use).
///
/// Differs from `account use` (fixed 2026-09-21): `space use` **only switches into an existing space**;
/// a typo errors instead of silently creating an empty profile. Why: `space use nosuch` used to
/// create_dir_all an empty dir and print "this profile has no account", so the user walked into
/// an empty profile without knowing. Create stays on `space create` (says "create") and `account use`
/// (generic profile switch).
pub fn space_use(name: &str) -> Result<serde_json::Value> {
    respire_app::service::require_profile_change_host()?;
    validate_space_name(name)?;
    let n = name.trim();
    if n != "main" && !account_dir(n)?.exists() {
        return Err(respire_app::input_error::InputError(format!(
            "space \"{n}\" does not exist - rsrs space list to see current spaces; \
             to create one, run rsrs space create {n}"
        )).into());
    }
    account_use(n)
}

/// Delete a space profile (store and keys are unrecoverable). Reuses account_remove's guard (cannot delete the current profile).
pub fn space_remove(name: &str) -> Result<()> {
    respire_app::service::require_profile_change_host()?;
    validate_space_name(name)?;
    account_remove(name.trim())
}

/// List member sessions this space has issued (owner view, for kick).
pub fn space_members(name: Option<&str>) -> Result<serde_json::Value> {
    let dir = match name {
        Some(n) if !n.trim().is_empty() => {
            validate_space_name(n)?;
            account_dir(n.trim())?
        }
        _ => data_dir(),
    };
    let rows = read_sessions(&dir);
    let space = space_name_of(&dir).unwrap_or_else(|| "main".to_owned());
    Ok(json!({ "space": space, "members": rows }))
}

/// Kick: revoke a member session (`--session <id>`), or every member session (`--all`).
///
/// Uses existing `DELETE /api/self/sessions/{id}/revoke` - the owner calls it with this space's token;
/// the kicked member loses access immediately. Also dropped from the local log.
pub fn space_kick(session_id: Option<&str>, all: bool) -> Result<serde_json::Value> {
    let dir = data_dir();
    let session = read_session(&dir)?;
    let addr = session["addr"]
        .as_str()
        .unwrap_or("")
        .trim()
        .trim_end_matches('/')
        .to_owned();
    let token = session["token"].as_str().unwrap_or("").trim().to_owned();
    if addr.is_empty() || token.is_empty() {
        return Err(anyhow!(
            "this profile is not signed in - login/register first"
        ));
    }
    let rows = read_sessions(&dir);
    if rows.is_empty() {
        return Err(anyhow!(
            "this space has never issued a member session (or the local log was cleared)"
        ));
    }
    let targets: Vec<&serde_json::Value> = if all {
        rows.iter().collect()
    } else {
        let sid = session_id
            .ok_or_else(|| anyhow!("need --session <id> or --all"))?
            .trim();
        let hit: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| r["session_id"].as_str().map(|s| s == sid).unwrap_or(false))
            .collect();
        if hit.is_empty() {
            return Err(anyhow!("this space has no member session: {sid}"));
        }
        hit
    };
    let mut revoked = Vec::new();
    let mut failed = Vec::new();
    for r in &targets {
        let sid = r["session_id"].as_str().unwrap_or("");
        match revoke_session(&addr, &token, sid) {
            Ok(true) => revoked.push(sid.to_owned()),
            Ok(false) => failed.push(format!(
                "{sid} (server has no such session; it may already be revoked)"
            )),
            Err(e) => failed.push(format!("{sid} ({e})")),
        }
    }
    // Drop successful revokes from the local log
    let left: Vec<serde_json::Value> = rows
        .into_iter()
        .filter(|r| {
            let sid = r["session_id"].as_str().unwrap_or("");
            !revoked.iter().any(|x| x == sid)
        })
        .collect();
    write_sessions(&dir, &left)?;
    Ok(json!({ "revoked": revoked, "failed": failed, "remaining": left.len() }))
}

// -- internals --

fn read_session(dir: &std::path::Path) -> Result<serde_json::Value> {
    let t = std::fs::read_to_string(dir.join("session.json"))
        .map_err(|_| anyhow!("this profile has no session.json - not signed in yet"))?;
    Ok(serde_json::from_str(&t)?)
}

/// Space name: the profile name (non-main is the directory name).
fn space_name_of(dir: &std::path::Path) -> Option<String> {
    dir.strip_prefix(accounts_root())
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_sessions(dir: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.join(SESSIONS_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

fn write_sessions(dir: &std::path::Path, rows: &[serde_json::Value]) -> Result<()> {
    std::fs::write(
        dir.join(SESSIONS_FILE),
        serde_json::to_string_pretty(&rows)?,
    )?;
    Ok(())
}

/// Sign a member session: `POST /api/self/sessions` (existing endpoint; zero server change).
fn create_member_session(
    addr: &str,
    token: &str,
    device: &str,
    readonly: bool,
) -> Result<(String, String)> {
    let base = addr.trim().trim_end_matches('/');
    let resp = ureq::post(&format!("{base}/api/self/sessions"))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(json!({ "device_name": device, "readonly": readonly }))
        .map_err(|e| match e {
            ureq::Error::Status(401, _) => anyhow!("this space token is expired - login again"),
            ureq::Error::Status(403, _) => anyhow!(
                "this session cannot issue member sessions (read-only sessions cannot issue)"
            ),
            other => anyhow!("failed to issue a member session: {other}"),
        })?;
    let v: serde_json::Value = resp
        .into_json()
        .map_err(|e| anyhow!("failed to parse response: {e}"))?;
    let t = v["token"]
        .as_str()
        .ok_or_else(|| anyhow!("server did not return a token"))?
        .to_owned();
    let id = v["session_id"].as_str().unwrap_or("").to_owned();
    Ok((t, id))
}

/// Revoke a session: `POST /api/self/sessions/{id}/revoke` (existing endpoint; POST, not DELETE).
fn revoke_session(addr: &str, token: &str, session_id: &str) -> Result<bool> {
    let base = addr.trim().trim_end_matches('/');
    let url = format!("{base}/api/self/sessions/{session_id}/revoke");
    match ureq::post(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(json!({}))
    {
        Ok(resp) => {
            let v: serde_json::Value = resp.into_json().unwrap_or_else(|_| json!({}));
            Ok(v["revoked"].as_bool().unwrap_or(false))
        }
        Err(ureq::Error::Status(401, _)) => Err(anyhow!("this space token is expired")),
        Err(ureq::Error::Status(404, _)) => Ok(false),
        Err(e) => Err(anyhow!("failed to revoke session: {e}")),
    }
}

/// Fetch vault (`GET /api/self/vault`, needs a token). Members use this to get key material on join.
fn fetch_vault(addr: &str, token: &str) -> Result<serde_json::Value> {
    let base = addr.trim().trim_end_matches('/');
    let resp = ureq::get(&format!("{base}/api/self/vault"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(401, _) => anyhow!(
                "session token in the invite is invalid - the member may already have been kicked"
            ),
            ureq::Error::Status(404, _) => {
                anyhow!("this space has no vault on the server - registration may be incomplete")
            }
            other => anyhow!("failed to fetch vault: {other}"),
        })?;
    let v: serde_json::Value = resp
        .into_json()
        .map_err(|e| anyhow!("failed to parse response: {e}"))?;
    Ok(v)
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

    #[test]
    fn space_create_list_use_remove() -> Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let saved = std::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        assert!(space_create("main").is_err());
        let created = space_create("team_a")?;
        assert_eq!(created["name"], "team_a");
        let listed = space_list()?;
        let spaces = listed["spaces"].as_array().cloned().unwrap_or_default();
        assert!(spaces.iter().any(|s| s["name"] == "team_a"));
        assert!(space_use("missing").is_err());
        let used = space_use("main")?;
        assert_eq!(used["name"], "main");
        space_use("team_a")?;
        assert!(
            space_remove("team_a").is_err(),
            "cannot remove current space"
        );
        space_use("main")?;
        space_remove("team_a")?;
        match saved {
            Some(v) => std::env::set_var("RSRS_DATA_DIR", v),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        Ok(())
    }
}

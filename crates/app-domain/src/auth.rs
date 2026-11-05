//! auth — authentication and session (shared by CLI and the web console)
//!
//! Read/write session.json, unlock, register, login. Register = key material + server-issued token;
//! login = verify existing key material and fill in a token. Crypto domain is separate from auth:
//!   unlocking the local library uses session pass (KEK chain); server auth uses PBKDF2(pass, deterministic auth_salt).

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use crate::memory::crypto;
use crate::memory::SessionKeys;

pub fn session_file() -> Result<PathBuf> {
    Ok(crate::service::data_dir().join("session.json"))
}

pub fn read_session_json() -> Result<serde_json::Value> {
    let path = session_file()?;
    let text = std::fs::read_to_string(&path).map_err(|_| anyhow!("no local session"))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn write_session_json(data: &serde_json::Value) -> Result<PathBuf> {
    let path = session_file()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(data)?)?;
    Ok(path)
}

/// Session device name (server sessions.device_name): same hostname source as device_tag,
/// so the two do not disagree (old impl had no syscall fallback and was always "CLI" on mac — fixed 2026-09-20).
fn device_name() -> String {
    crate::service::host_name().unwrap_or_else(|| "CLI".to_owned())
}

/// Manage independent network sessions; never send decryption keys to the server.
pub fn sessions(revoke: Option<&str>) -> Result<serde_json::Value> {
    let mut data = read_session_json()?;
    let addr = data["addr"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("cloud address is not configured"))?;
    let token = data["token"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("no cloud token; log in first"))?;
    let base = addr.trim_end_matches('/');
    let response = if let Some(id) = revoke {
        let id = uuid::Uuid::parse_str(id).map_err(|_| anyhow!("session id must be a full UUID"))?;
        ureq::post(&format!("{base}/api/self/sessions/{id}/revoke"))
            .set("Authorization", &format!("Bearer {token}")).send_json(serde_json::json!({}))?
    } else {
        ureq::get(&format!("{base}/api/self/sessions"))
            .set("Authorization", &format!("Bearer {token}")).call()?
    };
    let reply: serde_json::Value = response.into_json()?;
    if revoke.is_some() && reply["revoked"].as_bool() == Some(true)
        && reply["session_id"] == data["session_id"] {
        if let Some(fields) = data.as_object_mut() {
            fields.remove("token");
            fields.remove("session_id");
        }
        write_session_json(&data)?;
    }
    Ok(reply)
}

/// Log out. Default: clear token/session_id to drop the cloud (keep addr, identity, key material —
/// login without --addr reconnects). --full: delete session.json (forget local identity; reconnect with the five-piece kit or register).
pub fn logout(full: bool) -> Result<()> {
    let path = session_file()?;
    if full {
        let user = read_session_json()
            .ok()
            .and_then(|d| d["user"].as_str().map(|s| s.to_owned()))
            .unwrap_or_default();
        crate::keystore::delete_super(&user);
        crate::keystore::delete_login_pass(&user);
        match std::fs::remove_file(&path) {
            Ok(_) => println!("forgot local identity: {} deleted (reconnect with register or the five-piece kit)", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("no session ({} does not exist)", path.display()),
            Err(e) => return Err(anyhow::anyhow!("clear failed: {e}")),
        }
        return Ok(());
    }
    match read_session_json() {
        Err(_) => println!("no session ({} does not exist)", path.display()),
        Ok(mut data) => {
            if let Some(o) = data.as_object_mut() {
                o.remove("token");
                o.remove("session_id");
            }
            write_session_json(&data)?;
            println!("cloud session logged out: token cleared (addr/identity/key material kept; login without --addr reconnects; local library still works)");
        }
    }
    Ok(())
}

/// Unlock session keys from local session.json.
pub fn load_local_session() -> Result<SessionKeys> {
    load_local_session_with_owner().map(|(keys, _)| keys)
}

/// Unlock keys and retain the profile-owner alias from the same file snapshot.
/// This is local configuration identity, not proof of remote account authentication.
pub fn load_local_session_with_owner() -> Result<(SessionKeys, Option<String>)> {
    unlock_local_session_snapshot(&read_session_json()?)
}

/// Keep key material and owner inseparable even if the profile changes after reading.
fn unlock_local_session_snapshot(data: &serde_json::Value) -> Result<(SessionKeys, Option<String>)> {
    let user = data["user"].as_str().unwrap_or("").to_owned();
    let explicit_pass = if data["vault_version"] == 1 {
        crate::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty())
    } else { None };
    let pass = explicit_pass.or_else(|| data["pass"].as_str().map(ToOwned::to_owned))
        .or_else(|| crate::keystore::load_login_pass(&user)).unwrap_or_default();
    let keys = unlock_session_keys(data, &pass, None, &user)?;
    let owner = if user.trim().is_empty() { None } else { Some(user) };
    Ok((keys, owner))
}

/// Try to unlock the local session; no session → Ok(None) (unregistered; web can guide register).
pub fn try_session() -> Result<Option<SessionKeys>> {
    match load_local_session() {
        Ok(keys) => Ok(Some(keys)),
        Err(_) => Ok(None),
    }
}

pub fn wrap_with_v4(super_pass: &str, urk: &[u8; 32]) -> Result<(String, String, String)> {
    let kdf_salt = crypto::random_hex(16);
    let kek = crypto::derive_kek_v4(super_pass, &kdf_salt)?;
    let (urk_nonce, wrapped_urk) = crypto::wrap_key(urk, &kek)?;
    Ok((kdf_salt, wrapped_urk, urk_nonce))
}

pub fn wrap_with_rsrs(super_pass: &str, urk: &[u8; 32]) -> Result<(String, String, String)> {
    let salt = crypto::random_hex(16);
    let kek = crypto::derive_rsrs_kek(super_pass, &salt)?;
    let (nonce, wrapped) = crypto::wrap_key(urk, &kek)?;
    Ok((salt, format!("{}{wrapped}", crypto::RSRS_PREFIX), nonce))
}

/// v4 key material: generate a super password (A3- recovery code) and a fresh URK.
pub fn new_vault_v4() -> Result<(String, [u8; 32], String, String, String)> {
    let super_pass = crypto::generate_secret_key();
    let urk = crypto::generate_key();
    let (kdf_salt, wrapped_urk, urk_nonce) = wrap_with_rsrs(&super_pass, &urk)?;
    Ok((super_pass, urk, kdf_salt, wrapped_urk, urk_nonce))
}

/// Write v4 material into session: super password goes only to the OS keyring (headless warns and uses RSRS_SUPER); never plaintext on disk.
fn apply_vault_v4(
    data: &mut serde_json::Value,
    user: &str,
    super_pass: &str,
    kdf_salt: String,
    wrapped_urk: String,
    urk_nonce: String,
) -> Result<()> {
    data["kdf_salt"] = serde_json::Value::String(kdf_salt);
    data["wrapped_urk"] = serde_json::Value::String(wrapped_urk);
    data["urk_nonce"] = serde_json::Value::String(urk_nonce);
    data["vault_version"] = serde_json::json!(4);
    // Super password and login password never go to disk
    data.as_object_mut().map(|o| {
        o.remove("secret_key");
        o.remove("super");
        o.remove("pass");
    });
    match crate::keystore::save_super(user, super_pass) {
        Ok(()) => {}
        Err(e) => eprintln!("warning: {e}; this session can still pass --super <super-password>"),
    }
    Ok(())
}

fn put_vault(addr: &str, token: &str, data: &serde_json::Value) -> Result<()> {
    let base = addr.trim().trim_end_matches('/');
    ureq::post(&format!("{base}/api/self/vault"))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({
            "kdf_salt": data["kdf_salt"],
            "wrapped_urk": data["wrapped_urk"],
            "urk_nonce": data["urk_nonce"],
            "version": data["vault_version"].as_i64().unwrap_or(3),
        }))
        .map_err(|e| anyhow!("failed to upload key wrap: {e}"))?;
    Ok(())
}

fn fetch_vault(addr: &str, token: &str) -> Result<Option<serde_json::Value>> {
    let base = addr.trim().trim_end_matches('/');
    match ureq::get(&format!("{base}/api/self/vault"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(resp) => resp
            .into_json()
            .map(Some)
            .map_err(|e| anyhow!("failed to parse vault response: {e}")),
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(anyhow!("failed to fetch key wrap: {e}")),
    }
}

/// Live memory count for this user on the server (overwrite protection / prompts).
fn fetch_count(addr: &str, token: &str) -> Result<i64> {
    let base = addr.trim().trim_end_matches('/');
    match ureq::get(&format!("{base}/count"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(resp) => Ok(resp.into_json::<serde_json::Value>()?["count"].as_i64().unwrap_or(0)),
        Err(ureq::Error::Status(404, _)) => Ok(0),
        Err(e) => Err(anyhow!("failed to fetch memory count: {e}")),
    }
}

/// Generate key material (local offline): wrap URK with a random key, store in the OS keyring, never plaintext in session.
///
/// Offline mode has no cloud backup: the keyring is the only copy, so the write must round-trip —
/// the old `save_super(...).ok()` swallowed errors and left the user with a library that could never open.
pub fn keygen() -> Result<(PathBuf, String)> {
    let (super_pass, _urk, kdf_salt, wrapped_urk, urk_nonce) = new_vault_v4()?;
    crate::keystore::save_super("local", &super_pass).map_err(|e| {
        anyhow!(
            "local keyring write failed ({e}) \u{2014} offline mode stores the key only here; \
             a failed write builds a library that cannot be opened. \
             Install a keyring (gnome-keyring / KWallet) and retry, \
             or set RSRS_SUPER on later commands as a bypass"
        )
    })?;
    if crate::keystore::load_super("local").is_none() {
        anyhow::bail!("keyring write did not round-trip \u{2014} offline mode cannot continue; check the keyring service and retry");
    }
    let path = write_session_json(&serde_json::json!({
        "kdf_salt": kdf_salt,
        "wrapped_urk": wrapped_urk,
        "urk_nonce": urk_nonce,
        "vault_version": 4,
    }))?;
    Ok((path, super_pass))
}

pub fn unlock_session_keys(
    data: &serde_json::Value,
    login_pass: &str,
    super_arg: Option<&str>,
    user: &str,
) -> Result<crate::memory::SessionKeys> {
    let wrapped = data["wrapped_urk"].as_str().ok_or_else(|| anyhow!("session missing wrapped_urk"))?;
    let nonce = data["urk_nonce"].as_str().ok_or_else(|| anyhow!("session missing urk_nonce"))?;
    let salt = data["kdf_salt"].as_str().ok_or_else(|| anyhow!("session missing kdf_salt"))?;
    let keys = match data["vault_version"].as_i64() {
        // v4: super password as the single factor — source: --super > OS keyring/env > leftover session field
        Some(v) if v >= 4 => {
            let super_pass = super_arg
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned())
                .or_else(|| crate::keystore::load_super(user))
                .or_else(|| data["secret_key"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_owned()))
                .ok_or_else(|| {
                    anyhow!(
                        "super password required: --super <super-password> (A3-\u{2026}, system-generated recovery code). \
                         none in the local keyring \u{2014} on a new machine export from the old device with `rsrs keys-export` and retry"
                    )
                })?;
            crate::memory::SessionKeys::unlock_v4(&super_pass, salt, wrapped, nonce)
        }
        // v3: original super password + Secret Key, retained during normal login.
        Some(3) => {
            let stored_super = if super_arg.is_none() && data["super"].as_str().is_none() {
                crate::keystore::load_super(user)
            } else { None };
            let super_pass = super_arg
                .or_else(|| data["super"].as_str())
                .or(stored_super.as_deref())
                .ok_or_else(|| anyhow!("super password required"))?;
            let secret_key = data["secret_key"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("Secret Key required"))?;
            crate::memory::SessionKeys::unlock_vault(super_pass, secret_key, salt, wrapped, nonce)
        }
        // v2: super password (passphrase) only
        Some(2) => {
            let stored_super = if super_arg.is_none() && data["super"].as_str().is_none() {
                crate::keystore::load_super(user)
            } else { None };
            let super_pass = super_arg
                .or_else(|| data["super"].as_str())
                .or(stored_super.as_deref())
                .ok_or_else(|| anyhow!("super password required"))?;
            crate::memory::SessionKeys::unlock_super(super_pass, salt, wrapped, nonce)
        }
        // v1: original login password + Account Secret, retained during normal login.
        _ => crate::memory::SessionKeys::unlock(
            login_pass,
            data["secret"].as_str().ok_or_else(|| anyhow!("session missing secret"))?,
            salt,
            wrapped,
            nonce,
        ),
    }?;
    if data["crypto_namespace"].as_str() == Some(crypto::RSRS_PREFIX) {
        crate::memory::SessionKeys::from_urk(keys.urk)
    } else {
        Ok(keys)
    }
}

/// Current profile already belongs to a different user: switch to that user's
/// profile and return its session. An empty profile stays put, so the first
/// register in an isolated data dir still writes there.
fn session_for_other_user(user: &str) -> Result<serde_json::Value> {
    let data = read_session_json().unwrap_or_else(|_| serde_json::json!({}));
    let cur_user = data["user"].as_str().unwrap_or("").to_owned();
    if cur_user.is_empty() || cur_user == user {
        return Ok(data);
    }
    crate::service::require_profile_change_host()?;
    let main_user = crate::service::session_user_of_dir(&crate::service::main_data_dir());
    if main_user == user {
        crate::service::set_data_dir("")?;
    } else {
        let dir = crate::service::account_dir(user)?;
        std::fs::create_dir_all(&dir)?;
        crate::service::set_data_dir(&dir.to_string_lossy())?;
    }
    eprintln!(
        "switching profile for `{user}` (account `{cur_user}` stays in its own data dir)"
    );
    Ok(read_session_json().unwrap_or_else(|_| serde_json::json!({})))
}

/// Super password for a vault that already exists (keygen, or the same profile).
/// `--super` wins, then `super:<user>`, then the keygen slot `super:local`, then a leftover session field.
fn existing_super(data: &serde_json::Value, passed: &str, user: &str) -> Result<String> {
    if !passed.is_empty() {
        return Ok(passed.to_owned());
    }
    if let Some(found) = crate::keystore::load_super(user) {
        return Ok(found);
    }
    if user != "local" {
        if let Some(found) = crate::keystore::load_super("local") {
            return Ok(found);
        }
    }
    data["secret_key"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow!(
                "super password required: --super <super-password> (A3-\u{2026}, system-generated recovery code). \
                 none in the local keyring \u{2014} on a new machine export from the old device with `rsrs keys-export` and retry"
            )
        })
}

/// Register: login password is auth only; super password (v4 single factor) wraps URK and uploads the vault.
/// A brand-new profile generates the super password. An existing keygen vault uses `--super`, then the keyring.
pub fn register(addr: &str, user: &str, pass: &str, super_pass_arg: &str) -> Result<Option<String>> {
    let mut data = session_for_other_user(user)?;
    let issued: Option<String>;
    if data["wrapped_urk"].as_str().filter(|s| !s.is_empty()).is_some() {
        // keygen (or this same profile) already wrapped the URK. Bind it to this username.
        data["user"] = serde_json::Value::String(user.to_owned());
        let super_pass = existing_super(&data, super_pass_arg, user)?;
        unlock_session_keys(&data, data["pass"].as_str().unwrap_or(pass), Some(&super_pass), user)?;
        crate::keystore::save_super(user, &super_pass)?;
        issued = Some(super_pass);
    } else {
        let (super_pass, _urk, kdf_salt, wrapped_urk, urk_nonce) = new_vault_v4()?;
        apply_vault_v4(&mut data, user, &super_pass, kdf_salt, wrapped_urk, urk_nonce)?;
        issued = Some(super_pass);
    }
    let auth_salt = server_authentication_salt(addr, user)?;
    let pass_hash = crypto::derive_pass_hash(pass, &auth_salt)?;

    let resp = match ureq::post(&format!("{}/register", addr.trim().trim_end_matches('/')))
        .send_json(serde_json::json!({
            "user": user,
            "pass_hash": pass_hash,
            "salt": auth_salt,
            "device_name": device_name(),
        })) {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _r)) if code == 409 => {
            return Err(anyhow::anyhow!(
                "user \"{user}\" is already registered on this server \u{2014} use rsrs login --interactive --user {user} --pass <password>",
            ));
        }
        Err(e) => return Err(anyhow::anyhow!("register request failed: {e}")),
    };
    let reply: serde_json::Value = resp.into_json().map_err(|e| anyhow::anyhow!("failed to parse response: {e}"))?;
    let token = reply["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("register failed: {}", reply.get("error").and_then(|e| e.as_str()).unwrap_or("unknown")))?
        .to_owned();
    if let Err(e) = crate::keystore::save_login_pass(user, pass) {
        eprintln!("warning: login password not stored in keyring: {e}");
    }

    data["auth_salt"] = serde_json::Value::String(auth_salt);
    data["user"] = serde_json::Value::String(user.to_owned());
    data["addr"] = serde_json::Value::String(addr.trim().trim_end_matches('/').to_owned());
    data["token"] = serde_json::Value::String(token.clone());
    data["session_id"] = reply.get("session_id").cloned().unwrap_or(serde_json::Value::Null);
    data.as_object_mut().map(|o| o.remove("pass"));
    write_session_json(&data)?;
    put_vault(addr, &token, &data)?;
    Ok(issued)
}

/// Login: send the login password to the server → fetch cloud vault and reconcile with local material → unlock using the cloud as source of truth.
/// v3/v2 accounts auto-upgrade to v4 after a successful login (URK unchanged, data stays).
/// Returns a newly issued super password (copy it down now); None if one already exists.
pub fn login(
    addr: &str,
    user: &str,
    pass: &str,
    super_pass: Option<&str>,
    secret_key: Option<&str>,
    reset_vault: bool,
) -> Result<Option<String>> {
    let mut authenticated = serde_json::json!({});
    authenticate_session(&mut authenticated, addr, user, pass)?;
    let mut data = read_session_json().unwrap_or_else(|_| serde_json::json!({}));
    if let Some(s) = secret_key.filter(|s| !s.is_empty()) {
        data["secret_key"] = serde_json::Value::String(s.to_owned());
    }

    // 0. Multi-account on one machine: if the login user differs from the current profile owner
    // (including offline with no owner), auto-create and switch — library/keys/session move with the
    // profile; the old profile stays in place (no need to logout --full to wipe material).
    let cur_user = data["user"].as_str().unwrap_or("").to_owned();
    if !cur_user.is_empty() && cur_user != user {
        data = session_for_other_user(user)?;
        if let Some(s) = secret_key.filter(|s| !s.is_empty()) {
            data["secret_key"] = serde_json::Value::String(s.to_owned());
        }
    } else if cur_user != user {
        crate::service::require_profile_change_host()?;
        let main_user = crate::service::session_user_of_dir(&crate::service::main_data_dir());
        if main_user == user {
            crate::service::set_data_dir("")?;
        } else {
            let dir = crate::service::account_dir(user)?;
            std::fs::create_dir_all(&dir)?;
            crate::service::set_data_dir(&dir.to_string_lossy())?;
        }
        data = read_session_json().unwrap_or_else(|_| serde_json::json!({}));
        if let Some(s) = secret_key.filter(|s| !s.is_empty()) {
            data["secret_key"] = serde_json::Value::String(s.to_owned());
        }
    }
    let has_wrap = data["wrapped_urk"].as_str().filter(|s| !s.is_empty()).is_some();

    // 1. Auth first: send the login password to the server. On failure local material is untouched —
    // the old impl unlocked locally first and died on "local key unlock failed" when material was
    // stale, never reaching the cloud or asking for the super password (reported 2026-09-16 on a new device).
    for field in ["user", "addr", "token", "session_id", "auth_salt", "pass"] {
        data[field] = authenticated[field].clone();
    }
    if let Err(e) = crate::keystore::save_login_pass(user, pass) {
        eprintln!("warning: login password not stored in keyring: {e}");
    }
    let token = data["token"].as_str().ok_or_else(|| anyhow!("login did not return a token"))?.to_owned();

    // 2. Fetch cloud vault and reconcile with local material
    let vault = fetch_vault(addr, &token)?;
    match vault {
        Some(vault) if has_wrap && vault_matches(&vault, &data) => {
            // Ordinary login verifies the existing key without migrating it.
            unlock_session_keys(&data, pass, super_pass, user).context(
                "local key unlock failed \u{2014} the keyring code does not match this account: pass the correct code with --super, or export from the old machine with keys-export",
            )?;
            // On unlock success, write back to the keyring: this branch never did that before —
            // a machine with full local material but an empty keyring had to pass --super/env every time
            // (reported 2026-09-18 on fslong-hasee; doctor said "nothing in the keyring").
            if let Some(s) = super_pass.filter(|s| !s.is_empty()) {
                if let Err(e) = crate::keystore::save_super(user, s) {
                    eprintln!("warning: super password not stored in keyring: {e}; this session can use RSRS_SUPER");
                }
            }
            write_session_json(&data)?;
            return Ok(None);
        }
        Some(vault) => {
            // Cloud vault does not match local material (rotated code / reissued / local keygen) or there is no local material:
            // **cloud wins** — login means attach to that account's library.
            // Overwrite guard: local memories encrypted with the current local key become undecryptable if we switch keys.
            if has_wrap && !reset_vault {
                use crate::transport::MemoryTransport as _;
                let alive = crate::service::open_store().and_then(|s| s.count()).unwrap_or(0);
                if alive > 0 {
                    anyhow::bail!(
                        "local library already has {alive} memories encrypted with the current local key, which does not match cloud account \"{user}\". \
                         switching now would make them undecryptable. export first: rsrs export <file>; \
                         to drop local memories and use the cloud key, add --reset-vault"
                    );
                }
            }
            // Super password source: --super > interactive (TTY) > local keyring
            let super_pass = obtain_super(user, super_pass)?;
            return unlock_cloud_vault(&mut data, addr, user, &token, &vault, &super_pass, secret_key);
        }
        None => {
            // Overwrite guard: server has data but no vault — those rows were encrypted with another key.
            // Minting a new URK and put_vault would lock them forever (hit 2026-09-16).
            let count = fetch_count(addr, &token)?;
            if count > 0 && !reset_vault {
                anyhow::bail!(
                    "server already has {count} encrypted memories but no key wrap \u{2014} they were encrypted on an earlier device with another key. \
                     export the key from the old device then login: old machine `rsrs keys-export`, this machine \
                     login --super <super-password> --secret-key <A3-\u{2026}>. \
                     to drop the old data and start from this machine, add --reset-vault"
                );
            }
            let (super_pass, _urk, kdf_salt, wrapped_urk, urk_nonce) = new_vault_v4()?;
            apply_vault_v4(&mut data, user, &super_pass, kdf_salt, wrapped_urk, urk_nonce)?;
            put_vault(addr, &token, &data)?;
            write_session_json(&data)?;
            return Ok(Some(super_pass));
        }
    }
}

/// Whether cloud vault material and local session material are the same key.
fn vault_matches(vault: &serde_json::Value, data: &serde_json::Value) -> bool {
    vault["wrapped_urk"] == data["wrapped_urk"]
        && vault["kdf_salt"] == data["kdf_salt"]
        && vault["urk_nonce"] == data["urk_nonce"]
}

/// Super password source order: --super > interactive (TTY) > local keyring.
/// Interactive comes before the keyring: when the user is logging in, use the code they type —
/// the keyring may still hold an old code (after rotation/reissue) and would only yield "decrypt failed".
fn obtain_super(user: &str, super_arg: Option<&str>) -> Result<String> {
    if let Some(s) = super_arg.filter(|s| !s.is_empty()) {
        return Ok(s.to_owned());
    }
    if crate::prompt::interactive() {
        return crate::prompt::ask_secret("super password (A3-\u{2026}, used to decrypt memories; if missing, export first on the old machine with rsrs keys-export): ");
    }
    crate::keystore::load_super(user).ok_or_else(|| {
        anyhow!(
            "super password required: --super <A3-\u{2026}> (system-generated recovery code; the login password only authenticates to the server and cannot unwrap memories). \
             no super password? export from the old machine with `rsrs keys-export`; a headless server can set RSRS_SUPER"
        )
    })
}

/// Unlock the cloud vault with the super password (v4 single factor / v3 two-factor / v2 old passphrase) and write the local session.
/// Login preserves the cloud format and original user factors. Migration is explicit.
fn unlock_cloud_vault(
    data: &mut serde_json::Value,
    _addr: &str,
    user: &str,
    _token: &str,
    vault: &serde_json::Value,
    super_pass: &str,
    secret_key: Option<&str>,
) -> Result<Option<String>> {
    let salt = vault["kdf_salt"].as_str().ok_or_else(|| anyhow!("vault missing kdf_salt"))?;
    let wrapped = vault["wrapped_urk"].as_str().ok_or_else(|| anyhow!("vault missing wrapped_urk"))?;
    let nonce = vault["urk_nonce"].as_str().ok_or_else(|| anyhow!("vault missing urk_nonce"))?;
    let version = vault["version"].as_i64().unwrap_or(2);
    if version >= 4 {
        // v4: super password as the single factor. Keyring may hold an old code — on unlock failure in a TTY, ask again.
        match crate::memory::SessionKeys::unlock_v4(super_pass, salt, wrapped, nonce) {
            Ok(_) => {
                apply_vault_v4(data, user, super_pass, salt.to_owned(), wrapped.to_owned(), nonce.to_owned())?;
                write_session_json(data)?;
                Ok(None)
            }
            Err(e) if crate::prompt::interactive() => {
                eprintln!("warning: this code cannot unwrap cloud memories ({e:#}) \u{2014} re-enter");
                let retry = crate::prompt::ask_secret("super password: ")?;
                crate::memory::SessionKeys::unlock_v4(&retry, salt, wrapped, nonce)?;
                apply_vault_v4(data, user, &retry, salt.to_owned(), wrapped.to_owned(), nonce.to_owned())?;
                write_session_json(data)?;
                Ok(None)
            }
            Err(e) => Err(anyhow!("super password cannot unwrap cloud memories ({e:#}) \u{2014} verify with keys-export on the old machine and retry")),
        }
    } else if version == 3 {
        // Read v3 without replacing its passphrase with its Secret Key.
        let legacy_secret = secret_key
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .or_else(|| data["secret_key"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_owned()))
            .ok_or_else(|| {
                anyhow!(
                    "this account is still v3 two-factor: need --super <old passphrase> --secret-key <A3-\u{2026}>. \
                     export the original material with `rsrs keys-export`; migrate explicitly to change the format"
                )
            })?;
        crate::memory::SessionKeys::unlock_vault(super_pass, &legacy_secret, salt, wrapped, nonce)
            .map_err(|e| anyhow!("v3 key unlock failed ({e}) \u{2014} retry with material from keys-export on the old machine"))?;
        data["kdf_salt"] = serde_json::json!(salt);
        data["wrapped_urk"] = serde_json::json!(wrapped);
        data["urk_nonce"] = serde_json::json!(nonce);
        data["vault_version"] = serde_json::json!(3);
        data["secret_key"] = serde_json::json!(legacy_secret);
        crate::keystore::save_super(user, super_pass)?;
        write_session_json(data)?;
        Ok(None)
    } else if version == 2 {
        crate::memory::SessionKeys::unlock_super(super_pass, salt, wrapped, nonce)?;
        data["kdf_salt"] = serde_json::json!(salt);
        data["wrapped_urk"] = serde_json::json!(wrapped);
        data["urk_nonce"] = serde_json::json!(nonce);
        data["vault_version"] = serde_json::json!(2);
        crate::keystore::save_super(user, super_pass)?;
        write_session_json(data)?;
        Ok(None)
    } else {
        anyhow::bail!("unsupported legacy vault version; original keys were preserved")
    }
}

/// Reset super password: current code (keyring/--super/input) unwraps URK → mint a new code → rewrap v4 → upload.
/// URK unchanged, data stays. Requires login (token). Returns the new super password.
pub fn super_reset(addr: Option<&str>, super_arg: Option<&str>) -> Result<String> {
    let mut data = read_session_json()?;
    let user = data["user"].as_str().unwrap_or("").to_owned();
    let token = data["token"].as_str().unwrap_or("").to_owned();
    anyhow::ensure!(!token.is_empty(), "not logged in \u{2014} run rsrs login before resetting the super password");
    let addr = match addr.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(a) => a.to_owned(),
        None => data["addr"].as_str().unwrap_or(crate::service::DEFAULT_SERVER_ADDR).to_owned(),
    };
    let keys = unlock_session_keys(&data, data["pass"].as_str().unwrap_or(""), super_arg, &user)
        .context("unlock failed \u{2014} current super password required (or one stored in the local keyring)")?;
    let new_super = crypto::generate_secret_key();
    let (kdf_salt, wrapped_urk, urk_nonce) = if data["wrapped_urk"].as_str().is_some_and(|value| value.starts_with(crypto::RSRS_PREFIX))
        || data["crypto_namespace"].as_str() == Some(crypto::RSRS_PREFIX) {
        wrap_with_rsrs(&new_super, &keys.urk)?
    } else {
        wrap_with_v4(&new_super, &keys.urk)?
    };
    data["secret_key"] = serde_json::Value::String(new_super.clone());
    data["kdf_salt"] = serde_json::Value::String(kdf_salt);
    data["wrapped_urk"] = serde_json::Value::String(wrapped_urk);
    data["urk_nonce"] = serde_json::Value::String(urk_nonce);
    data["vault_version"] = serde_json::json!(4);
    data.as_object_mut().map(|o| o.remove("super"));
    put_vault(&addr, &token, &data)?;
    write_session_json(&data)?;
    crate::keystore::save_super(&user, &new_super).ok();
    Ok(new_super)
}

/// Mutate the in-memory candidate session only; do not overwrite saved material on network or unlock failure.
pub fn password_authorization(addr: &str, user: &str, pass: &str) -> Result<serde_json::Value> {
    password_authorization_with_totp(addr,user,pass,None)
}

pub fn password_authorization_with_totp(addr: &str, user: &str, pass: &str, totp:Option<&str>) -> Result<serde_json::Value> {
    let mut authorization = serde_json::json!({});
    authenticate_session_with_totp(&mut authorization, addr, user, pass,totp)?;
    Ok(authorization)
}

fn server_authentication_salt(addr: &str, user: &str) -> Result<String> {
    let salt_response = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
        .get(&format!("{}/auth/salt", addr.trim().trim_end_matches('/'))).query("user", user).call();
    let salt = match salt_response {
        Ok(response) => response.into_json::<serde_json::Value>()?["salt"].as_str()
            .filter(|salt| !salt.is_empty()).context("server did not return an authentication salt")?.to_owned(),
        Err(ureq::Error::Status(404, _)) => crypto::derive_legacy_auth_salt(user)?,
        Err(error) => return Err(anyhow!("authentication salt request failed: {error}")),
    };
    Ok(salt)
}

fn authenticate_session(data: &mut serde_json::Value, addr: &str, user: &str, pass: &str) -> Result<()> {
    authenticate_session_with_totp(data,addr,user,pass,None)
}

fn authenticate_session_with_totp(data: &mut serde_json::Value, addr: &str, user: &str, pass: &str, totp:Option<&str>) -> Result<()> {
    let auth_salt = server_authentication_salt(addr, user)?;
    let pass_hash = crypto::derive_pass_hash(pass, &auth_salt)?;

    let resp = ureq::post(&format!("{}/login", addr.trim().trim_end_matches('/')))
        .send_json(serde_json::json!({
            "user": user,
            "pass_hash": pass_hash,
            "device_name": device_name(),
        }))
        .map_err(|e| anyhow::anyhow!("login request failed: {e}"))?;
    let mut reply: serde_json::Value = resp.into_json().map_err(|e| anyhow::anyhow!("failed to parse response: {e}"))?;
    if reply["totp_required"].as_bool() == Some(true) {
        if totp.is_none() && !crate::prompt::interactive() {
            anyhow::bail!("TOTP verification requires an interactive terminal or browser authorization");
        }
        let ticket = reply["ticket"].as_str().ok_or_else(|| anyhow!("TOTP challenge did not return a ticket"))?;
        let code = match totp {Some(code)=>code.to_owned(),None=>crate::prompt::ask_secret("TOTP code (6 digits): ")?};
        let code = code.trim();
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            anyhow::bail!("TOTP code must contain 6 digits");
        }
        let response = ureq::post(&format!("{}/login/totp", addr.trim().trim_end_matches('/')))
            .send_json(serde_json::json!({"ticket":ticket,"code":code,"device_name":device_name()}))
            .map_err(|error| anyhow!("TOTP verification failed: {error}"))?;
        reply = response.into_json().map_err(|error| anyhow!("failed to parse TOTP response: {error}"))?;
    }
    let token = reply["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("login failed: {}", reply.get("error").and_then(|e| e.as_str()).unwrap_or("unknown")))?
        .to_owned();

    // Fill addr/token/user (keep key material)
    data["user"] = serde_json::Value::String(user.to_owned());
    data["addr"] = serde_json::Value::String(addr.trim().trim_end_matches('/').to_owned());
    data["token"] = serde_json::Value::String(token);
    data["session_id"] = reply.get("session_id").cloned().unwrap_or(serde_json::Value::Null);
    data["auth_salt"] = serde_json::Value::String(auth_salt);
    data["pass"] = serde_json::Value::String(pass.to_owned());
    Ok(())
}

/// Five-piece kit attach (manual decrypt path on another machine): unlock verifies → write the full local session (then login fills the token).
/// Any wrong item (password/secret/salt/wrap) is refused — a write is always a valid session.
#[allow(clippy::too_many_arguments)]
pub fn fivekeys_login(
    addr: &str,
    user: &str,
    pass: &str,
    secret: &str,
    kdf_salt: &str,
    wrapped_urk: &str,
    urk_nonce: &str,
    super_pass: &str,
) -> Result<()> {
    crate::service::check_runtime_user(user)?;
    // A different account must not overwrite the profile that is already open.
    let previous = session_for_other_user(user)?;
    let mut data = if !super_pass.is_empty() {
        let trimmed_addr = addr.trim().trim_end_matches('/').to_owned();
        // Current accounts wrap with v4 (derive_kek_v4). unlock_super is the older
        // passphrase KDF and cannot open a v4 wrap even when the super password is right.
        match crate::memory::SessionKeys::unlock_v4(super_pass, kdf_salt, wrapped_urk, urk_nonce) {
            Ok(_) => {
                let mut data = serde_json::json!({
                    "user": user,
                    "addr": trimmed_addr,
                });
                if let Some(alias) = previous.get("keyring_account") {
                    data["keyring_account"] = alias.clone();
                }
                apply_vault_v4(
                    &mut data,
                    user,
                    super_pass,
                    kdf_salt.to_owned(),
                    wrapped_urk.to_owned(),
                    urk_nonce.to_owned(),
                )?;
                data
            }
            Err(v4_err) => {
                crate::memory::SessionKeys::unlock_super(super_pass, kdf_salt, wrapped_urk, urk_nonce)
                    .map_err(|_| v4_err)
                    .context("super password cannot unwrap the wrap")?;
                serde_json::json!({
                    "pass": pass,
                    "super": super_pass,
                    "kdf_salt": kdf_salt,
                    "wrapped_urk": wrapped_urk,
                    "urk_nonce": urk_nonce,
                    "vault_version": 2,
                    "user": user,
                    "addr": trimmed_addr,
                })
            }
        }
    } else {
        crate::memory::SessionKeys::unlock(pass, secret, kdf_salt, wrapped_urk, urk_nonce)
            .context("five-piece kit verification failed \u{2014} each item must match keygen/register output from the first device")?;
        serde_json::json!({
            "pass": pass,
            "secret": secret,
            "kdf_salt": kdf_salt,
            "wrapped_urk": wrapped_urk,
            "urk_nonce": urk_nonce,
            "user": user,
            "addr": addr.trim().trim_end_matches('/'),
        })
    };
    if let Some(alias) = previous.get("keyring_account") {
        data["keyring_account"] = alias.clone();
    }
    if !addr.trim().is_empty() {
        authenticate_session(&mut data, addr, user, pass)?;
    }
    write_session_json(&data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::crypto;

    fn lock_dir() -> std::sync::MutexGuard<'static, ()> {
        crate::test_lock::guard()
    }

    #[test]
    fn auth_salt_deterministic() -> Result<()> {
        assert_eq!(crypto::derive_auth_salt("Alice")?, crypto::derive_auth_salt("alice")?);
        assert_ne!(crypto::derive_auth_salt("Alice")?, crypto::derive_auth_salt("Bob")?);
        Ok(())
    }

    #[test]
    fn wrap_v3_cannot_unlock_with_super_alone() -> Result<()> {
        let super_pass = crypto::generate_secret_key();
        let urk = crypto::generate_key();
        let (salt, wrapped, nonce) = wrap_with_v4(&super_pass, &urk)?;
        let (secret, salt3, wrapped3, nonce3) = {
            let sk = crypto::generate_secret_key();
            let kdf_salt = crypto::random_hex(16);
            let kek = crypto::derive_vault_kek("master-pass", &sk, &kdf_salt)?;
            let (n, w) = crypto::wrap_key(&urk, &kek)?;
            (sk, kdf_salt, w, n)
        };
        crate::memory::SessionKeys::unlock_vault("master-pass", &secret, &salt3, &wrapped3, &nonce3)?;
        assert!(crate::memory::SessionKeys::unlock_vault(
            "wrong-pass",
            &secret,
            &salt3,
            &wrapped3,
            &nonce3
        )
        .is_err());
        assert!(crate::memory::SessionKeys::unlock_super("master-pass", &salt3, &wrapped3, &nonce3).is_err());
        // v4 roundtrip: correct super password unlocks, wrong key does not
        crate::memory::SessionKeys::unlock_v4(&super_pass, &salt, &wrapped, &nonce)?;
        assert!(crate::memory::SessionKeys::unlock_v4("A3-000000-000000-000000-000000-000000-000000", &salt, &wrapped, &nonce).is_err());
        assert_ne!(super_pass, "master-pass");
        let _ = salt3;
        Ok(())
    }

    #[test]
    fn unlock_session_keys_v3_and_v2() -> Result<()> {
        let _guard = lock_dir();
        let super_pass = crypto::generate_secret_key();
        let urk = crypto::generate_key();
        let (salt, wrapped, nonce) = wrap_with_v4(&super_pass, &urk)?;
        let v4 = serde_json::json!({
            "wrapped_urk": wrapped,
            "urk_nonce": nonce,
            "kdf_salt": salt,
            "vault_version": 4,
            "secret_key": super_pass,
        });
        unlock_session_keys(&v4, "login-pass", None, "u")?;
        assert!(unlock_session_keys(&v4, "login-pass", Some("A3-000000-000000-000000-000000-000000-000000"), "u").is_err());

        let (secret, salt, wrapped, nonce) = {
            let sk = crypto::generate_secret_key();
            let kdf_salt = crypto::random_hex(16);
            let kek = crypto::derive_vault_kek("master-pass", &sk, &kdf_salt)?;
            let urk = crypto::generate_key();
            let (n, w) = crypto::wrap_key(&urk, &kek)?;
            (sk, kdf_salt, w, n)
        };
        let v3 = serde_json::json!({
            "wrapped_urk": wrapped,
            "urk_nonce": nonce,
            "kdf_salt": salt,
            "vault_version": 3,
            "super": "master-pass",
            "secret_key": secret,
        });
        unlock_session_keys(&v3, "login-pass", None, "u")?;
        assert!(unlock_session_keys(&v3, "login-pass", Some("wrong-pass"), "u").is_err());

        let salt2 = crypto::random_hex(16);
        let kek = crypto::derive_super_kek("master-pass", &salt2)?;
        let urk = crypto::generate_key();
        let (nonce2, wrapped2) = crypto::wrap_key(&urk, &kek)?;
        let v2 = serde_json::json!({
            "wrapped_urk": wrapped2,
            "urk_nonce": nonce2,
            "kdf_salt": salt2,
            "vault_version": 2,
            "super": "master-pass",
        });
        unlock_session_keys(&v2, "login-pass", None, "u")?;
        assert!(unlock_session_keys(&v2, "login-pass", Some("wrong-pass"), "u").is_err());
        Ok(())
    }

    /// A replaced session file cannot supply an alias for previously read key material.
    #[test]
    fn local_session_owner_and_keys_share_one_snapshot() -> Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        assert!(load_local_session_with_owner().is_err());
        let salt = crypto::random_hex(16);
        let kek = crypto::derive_super_kek("synthetic-super", &salt)?;
        let first_urk = [11; 32];
        let (nonce, wrapped) = crypto::wrap_key(&first_urk, &kek)?;
        let first = serde_json::json!({"user":"snapshot-owner", "pass":"unused",
            "super":"synthetic-super", "vault_version":2, "kdf_salt":salt,
            "wrapped_urk":wrapped, "urk_nonce":nonce});
        write_session_json(&first)?;
        let snapshot = read_session_json()?;
        let second_urk = [12; 32];
        let (nonce, wrapped) = crypto::wrap_key(&second_urk, &kek)?;
        let mut second = first.clone();
        second["user"] = serde_json::json!("replacement-owner");
        second["wrapped_urk"] = serde_json::json!(wrapped);
        second["urk_nonce"] = serde_json::json!(nonce);
        write_session_json(&second)?;
        let (keys, owner) = unlock_local_session_snapshot(&snapshot)?;
        assert!(keys.urk == first_urk);
        assert_eq!(owner.as_deref(), Some("snapshot-owner"));
        let (keys, owner) = load_local_session_with_owner()?;
        assert!(keys.urk == second_urk);
        assert_eq!(owner.as_deref(), Some("replacement-owner"));
        for user in [serde_json::Value::Null, serde_json::json!(""), serde_json::json!(" ")] {
            second["user"] = user;
            write_session_json(&second)?;
            let (keys, owner) = load_local_session_with_owner()?;
            assert!(keys.urk == second_urk && owner.is_none());
            assert!(load_local_session()?.urk == second_urk);
        }
        Ok(())
    }

    #[test]
    fn session_roundtrip_isolated_home() -> Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let secret = crypto::generate_account_secret();
        let kdf_salt = crypto::random_hex(16);
        let kek = crypto::derive_kek("pass", &secret, &kdf_salt)?;
        let urk = crypto::generate_key();
        let (nonce, wrapped) = crypto::wrap_key(&urk, &kek)?;
        write_session_json(&serde_json::json!({
            "pass": "pass", "secret": secret, "kdf_salt": kdf_salt,
            "wrapped_urk": wrapped, "urk_nonce": nonce,
        }))?;
        assert!(load_local_session().is_ok());
        Ok(())
    }

    #[test]
    fn fivekeys_super_opens_v4_and_keeps_old_wrap() -> Result<()> {
        let _guard = lock_dir();
        let dir = tempfile::tempdir()?;
        let saved = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let result = (|| -> Result<()> {
            let super_pass = crypto::generate_secret_key();
            let urk = crypto::generate_key();
            let (salt, wrapped, nonce) = wrap_with_v4(&super_pass, &urk)?;
            fivekeys_login(
                "",
                "fivekeys-v4-test",
                "login-pass-123",
                "",
                &salt,
                &wrapped,
                &nonce,
                &super_pass,
            )?;
            let session = read_session_json()?;
            if session["vault_version"].as_i64() != Some(4) {
                anyhow::bail!("v4 fivekeys wrote vault_version {}", session["vault_version"]);
            }
            crate::memory::SessionKeys::unlock_v4(&super_pass, &salt, &wrapped, &nonce)?;
            if fivekeys_login(
                "",
                "fivekeys-v4-test",
                "login-pass-123",
                "",
                &salt,
                &wrapped,
                &nonce,
                "not-the-super",
            )
            .is_ok()
            {
                anyhow::bail!("wrong super password was accepted for a v4 wrap");
            }

            let old_pass = "old-super-passphrase";
            let old_urk = crypto::generate_key();
            let old_salt = crypto::random_hex(16);
            let kek = crypto::derive_super_kek(old_pass, &old_salt)?;
            let (old_nonce, old_wrapped) = crypto::wrap_key(&old_urk, &kek)?;
            fivekeys_login(
                "",
                "fivekeys-v2-test",
                "login-pass-123",
                "",
                &old_salt,
                &old_wrapped,
                &old_nonce,
                old_pass,
            )?;
            let old = read_session_json()?;
            if old["vault_version"].as_i64() != Some(2) {
                anyhow::bail!("old fivekeys wrote vault_version {}", old["vault_version"]);
            }
            let root: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
                dir.path().join("session.json"),
            )?)?;
            if root["user"].as_str() != Some("fivekeys-v4-test") || root["vault_version"].as_i64() != Some(4) {
                anyhow::bail!("fivekeys for another user overwrote the open profile");
            }
            Ok(())
        })();
        match saved {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        result
    }

    #[test]
    fn register_other_user_does_not_unlock_the_open_vault() -> Result<()> {
        let _guard = lock_dir();
        let dir = tempfile::tempdir()?;
        let saved = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let result = (|| -> Result<()> {
            let super_pass = crypto::generate_secret_key();
            let urk = crypto::generate_key();
            let (salt, wrapped, nonce) = wrap_with_v4(&super_pass, &urk)?;
            write_session_json(&serde_json::json!({
                "user": "mainuser",
                "vault_version": 4,
                "kdf_salt": salt,
                "wrapped_urk": wrapped,
                "urk_nonce": nonce,
            }))?;
            let err = register(
                "http://127.0.0.1:1",
                "otheruser",
                "password12",
                "",
            )
            .expect_err("register against a closed port must fail after switching profiles");
            let msg = format!("{err:#}");
            if msg.contains("none in the local keyring") {
                anyhow::bail!("register tried to unlock the open vault: {msg}");
            }
            let root: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
                dir.path().join("session.json"),
            )?)?;
            if root["user"] != "mainuser" || root["wrapped_urk"] != wrapped {
                anyhow::bail!("open profile was rewritten");
            }
            let current = crate::service::data_dir();
            let expected = dir.path().join("accounts").join("otheruser");
            if current != expected {
                anyhow::bail!("new account profile is {}, want {}", current.display(), expected.display());
            }
            Ok(())
        })();
        match saved {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        result
    }

    #[test]
    fn register_after_keygen_accepts_the_issued_super() -> Result<()> {
        let _guard = lock_dir();
        let dir = tempfile::tempdir()?;
        let saved = crate::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let result = (|| -> Result<()> {
            let super_pass = crypto::generate_secret_key();
            let urk = crypto::generate_key();
            let (salt, wrapped, nonce) = wrap_with_v4(&super_pass, &urk)?;
            write_session_json(&serde_json::json!({
                "vault_version": 4,
                "kdf_salt": salt,
                "wrapped_urk": wrapped,
                "urk_nonce": nonce,
            }))?;
            let opened = register("http://127.0.0.1:1", "keygenuser", "password12", &super_pass)
                .expect_err("closed port");
            let opened_msg = format!("{opened:#}");
            if opened_msg.contains("none in the local keyring") {
                anyhow::bail!("correct A3 was ignored: {opened_msg}");
            }
            let wrong = register(
                "http://127.0.0.1:1",
                "keygenuser",
                "password12",
                "A3-000000-000000-000000-000000-000000-000000",
            )
            .expect_err("wrong A3");
            let wrong_msg = format!("{wrong:#}");
            if wrong_msg.contains("none in the local keyring") {
                anyhow::bail!("placeholder A3 was treated as a missing key: {wrong_msg}");
            }
            let omitted = register("http://127.0.0.1:1", "keygenuser", "password12", "")
                .expect_err("omitted super");
            let omitted_msg = format!("{omitted:#}");
            let keyring_has_it = crate::keystore::load_super("keygenuser").is_some()
                || crate::keystore::load_super("local").is_some();
            if keyring_has_it && omitted_msg.contains("none in the local keyring") {
                anyhow::bail!("keyring already holds the keygen code but register did not use it: {omitted_msg}");
            }
            if !keyring_has_it && !omitted_msg.contains("none in the local keyring") {
                anyhow::bail!("missing super and empty keyring should say so: {omitted_msg}");
            }
            let root: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
                dir.path().join("session.json"),
            )?)?;
            if root["user"].as_str().unwrap_or("").is_empty() == false {
                anyhow::bail!("failed register wrote a user into the keygen profile");
            }
            if root["wrapped_urk"].as_str() != Some(wrapped.as_str()) {
                anyhow::bail!(
                    "failed register rewrote the keygen wrap file={} expect={}",
                    root["wrapped_urk"].as_str().unwrap_or("").chars().take(12).collect::<String>(),
                    wrapped.chars().take(12).collect::<String>()
                );
            }
            Ok(())
        })();
        match saved {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        result
    }
}

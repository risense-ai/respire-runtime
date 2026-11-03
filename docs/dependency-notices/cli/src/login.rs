//! Host-owned login: browser or password/TOTP authorization, then verified profile commit.
use std::cell::RefCell;
use std::time::{Duration, Instant};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};

pub(crate) fn origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).context("login server must be an absolute origin")?;
    let local = matches!(url.host(), Some(url::Host::Domain("localhost")))
        || matches!(url.host(), Some(url::Host::Ipv4(address)) if address.is_loopback())
        || matches!(url.host(), Some(url::Host::Ipv6(address)) if address.is_loopback());
    ensure!(url.scheme() == "https" || (url.scheme() == "http" && local), "login requires HTTPS, except loopback fixtures");
    ensure!(url.username().is_empty() && url.password().is_none() && url.path() == "/" && url.query().is_none() && url.fragment().is_none(), "login origin must not include credentials, paths, queries or fragments");
    Ok(url.origin().ascii_serialization())
}

fn login_origin(explicit: Option<&str>, stored: Option<&str>) -> Result<String> {
    let nonempty = |value: &str| !value.trim().is_empty();
    let (value, source) = if let Some(value) = explicit.filter(|value| nonempty(value)) {
        (value, "--addr")
    } else if let Some(value) = stored.filter(|value| nonempty(value)) {
        (value, "stored session.json addr")
    } else {
        (respire::service::DEFAULT_SERVER_ADDR, "default login server")
    };
    origin(value).with_context(|| format!(
        "invalid login server from {source}; supply --addr <https-origin> (official service: --addr https://api.rsrs.rs); RSRS_ADDR and client.json are not consulted for login"
    ))
}

fn browser_authorization(addr: &str, user: Option<&str>, dashboard: Option<&str>, no_open: bool) -> Result<Value> {
    let dashboard = match dashboard {
        Some(value) => origin(value).context("invalid OAuth dashboard from --dashboard; supply an HTTPS origin")?,
        None if addr == "https://api.rsrs.rs" => "https://dash.rsrs.rs".to_owned(),
        None if addr == "https://api.dev.rsrs.rs" || addr == "https://api-dev.rsrs.rs" => "https://dash.dev.rsrs.rs".to_owned(),
        None if respire::prompt::interactive() => origin(&respire::prompt::ask("dashboard origin: ")?).context("invalid OAuth dashboard from terminal input; supply an HTTPS origin")?,
        None => anyhow::bail!("custom login servers require --dashboard <dashboard-origin>"),
    };
    let agent = ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(30)).build();
    let device = respire::service::host_name().unwrap_or_else(|| "CLI".to_owned());
    let grant: Value = agent.post(&format!("{addr}/oauth/device/code")).send_form(&[
        ("client_id", "respire-cli"), ("device_name", &device), ("expected_user", user.unwrap_or_default()),
    ]).context("browser authorization request failed")?.into_json()?;
    let device_code = grant["device_code"].as_str().context("authorization response missing device_code")?;
    let code = grant["user_code"].as_str().context("authorization response missing user_code")?;
    ensure!(code.len() == 12 && code.bytes().all(|byte| byte.is_ascii_hexdigit()), "authorization response has an invalid user code");
    let expires = grant["expires_in"].as_u64().filter(|seconds| *seconds > 0 && *seconds <= 600).context("authorization response has an invalid expiry")?;
    let mut interval = grant["interval"].as_u64().filter(|seconds| *seconds > 0 && *seconds <= 30).context("authorization response has an invalid polling interval")?;
    let url = format!("{dashboard}/#/authorize?code={code}");
    ensure!(grant["verification_uri_complete"].as_str() == Some(url.as_str()), "server dashboard differs from the expected dashboard; configure RSRS_DASHBOARD_URL on the server or --dashboard in the CLI");
    eprintln!("Authorize CLI: {url}\nCheck code: {code}");
    if !no_open { crate::web::open_browser(&url)?; }
    let deadline = Instant::now() + Duration::from_secs(expires);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(interval));
        let response = match agent.post(&format!("{addr}/oauth/token")).send_form(&[
            ("client_id", "respire-cli"), ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", device_code),
        ]) { Ok(response) => response, Err(ureq::Error::Status(400, response)) => response, Err(error) => return Err(anyhow!("browser authorization polling failed: {error}")) };
        let reply: Value = response.into_json()?;
        if reply["access_token"].as_str().is_some_and(|token| !token.is_empty()) {
            ensure!(reply["token_type"].as_str().is_some_and(|kind| kind.eq_ignore_ascii_case("bearer")), "unsupported authorization token type");
            return Ok(json!({"user":reply["user"],"token":reply["access_token"],"session_id":reply["session_id"]}));
        }
        match reply["error"].as_str() {
            Some("authorization_pending") => {},
            Some("slow_down") => interval += 5,
            Some("access_denied") => anyhow::bail!("browser authorization was denied; original account was preserved"),
            Some("expired_token" | "invalid_grant") => anyhow::bail!("browser authorization expired or was consumed; original account was preserved"),
            _ => anyhow::bail!("invalid browser authorization response"),
        }
    }
    Err(anyhow!("browser authorization timed out; original account was preserved"))
}

pub(crate) fn run(addr: Option<&str>, user: Option<&str>, pass: Option<&str>, super_password: Option<&str>, interactive: bool, oauth: bool, dashboard: Option<&str>, no_open: bool, migrate_local: bool) -> Result<()> {
    crate::runtime_policy::require_host("account authorization and profile switching")?;
    ensure!(!crate::rpc::worker_active(), "login must run in the host terminal, not runtime RPC");
    crate::rpc::recover_interrupted_login()?;
    let last = respire::auth::read_session_json().ok().and_then(|session| session["addr"].as_str().map(ToOwned::to_owned));
    let selected_addr = if interactive && addr.is_none() && respire::prompt::interactive() {
        let selected = respire::prompt::ask("server HTTPS origin (Enter = current/public): ")?;
        (!selected.trim().is_empty()).then(|| selected.trim().to_owned())
    } else { None };
    let addr = login_origin(addr.or(selected_addr.as_deref()), last.as_deref())?;
    let password_mode = if interactive && !oauth && pass.is_none() && respire::prompt::interactive() {
        let choice = respire::prompt::ask("login method: 1 OAuth (default), 2 password/TOTP: ")?;
        ensure!(matches!(choice.trim(), "" | "1" | "2"), "select login method 1 or 2");
        choice.trim() == "2"
    } else { interactive && !oauth };
    ensure!(!password_mode || (dashboard.is_none() && !no_open), "--dashboard and --no-open apply to OAuth login");
    let mut authorization = if password_mode {
        let user = match user {
            Some(user) => user.to_owned(),
            None if respire::prompt::interactive() => respire::prompt::ask("username: ")?,
            None => anyhow::bail!("interactive login requires a terminal or --user"),
        };
        let password = match pass {
            Some(pass) => pass.to_owned(),
            None if respire::prompt::interactive() => respire::prompt::ask_secret("login password: ")?,
            None => anyhow::bail!("interactive login requires a terminal or --pass"),
        };
        respire::auth::password_authorization_with_totp(&addr, user.trim(), &password,crate::host_rpc::totp_code().as_deref())?
    } else { browser_authorization(&addr, user, dashboard, no_open)? };
    let vault = respire_app::login_transaction::PreparedLogin::fetch_vault(&addr, &authorization)?;
    ensure!(!vault.is_null(), "account has no cloud vault; explicitly migrate the original local library before login");
    let super_password = if vault["version"] == 1 {
        ensure!(super_password.is_none(), "v1 requires the original login password and Account Secret, not --super");
        let user = authorization["user"].as_str().context("authorization did not return a user")?;
        let directory = respire_app::login_transaction::login_directory(&addr, user)?;
        let local: Value = match std::fs::read(directory.join("session.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("target account session is invalid")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
            Err(error) => return Err(error.into()),
        };
        let password = authorization["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned)
            .or_else(|| pass.filter(|value| !value.is_empty()).map(str::to_owned))
            .or_else(|| respire::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty()))
            .or_else(|| local["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned))
            .or_else(|| respire::keystore::load_login_pass(local["keyring_account"].as_str().unwrap_or(user)));
        authorization["pass"] = json!(match password {
            Some(value) => value,
            None if respire::prompt::interactive() => respire::prompt::ask_secret("original v1 login password: ")?,
            None => anyhow::bail!("v1 recovery requires the original login password; original account was preserved"),
        });
        let secret = local["secret"].as_str().filter(|value| !value.is_empty()).map(str::to_owned);
        authorization["secret"] = json!(match secret {
            Some(value) => value,
            None if respire::prompt::interactive() => respire::prompt::ask_secret("original v1 Account Secret: ")?,
            None => anyhow::bail!("v1 recovery requires interactive Account Secret input; original account was preserved"),
        });
        String::new()
    } else {
        match super_password {
            Some(value) if !value.is_empty() => value.to_owned(),
            _ if respire::prompt::interactive() => respire::prompt::ask_secret("super password (A3-\u{2026}): ")?,
            _ => anyhow::bail!("authorization succeeded; enter the super password in an interactive terminal or supply --super; original account was preserved"),
        }
    };
    let source = respire::service::data_dir();
    let prepared = respire_app::login_transaction::PreparedLogin::prepare_with_vault(&addr, &authorization, super_password, vault, None)?;
    let different = source != prepared.directory;
    let source_has_data = respire::service::database_path(&source)?.is_file();
    ensure!(!migrate_local || different, "source and destination are the same account; no migration is needed");
    let copy = if migrate_local { true }
        else if interactive && different && source_has_data && respire::prompt::interactive() {
            respire::prompt::ask("Merge selected local memories into this server account (skip identical bodies; keep existing records)? [y/N]: ")?
                .trim().eq_ignore_ascii_case("y")
        } else { false };
    let snapshot = if copy {
        ensure!(!respire::service::off_mode(), "memory service is disabled; restore normal service before migration");
        respire::service::ensure_writable()?;
        let source_secret = if respire::prompt::interactive() {
            respire::prompt::ask_secret("original local super password (v1: login password; Enter = saved credentials): ")?
        } else { String::new() };
        Some(respire_app::login_transaction::local_snapshot(
            (!source_secret.is_empty()).then_some(source_secret.as_str()))?)
    } else { None };
    commit_verified(&addr, &authorization, prepared, "login", snapshot.as_deref())
}

fn commit_verified(addr: &str, authorization: &Value, prepared: respire_app::login_transaction::PreparedLogin, command: &str, snapshot: Option<&str>) -> Result<()> {
    let prepared = RefCell::new(prepared);
    let imported = RefCell::new(None);
    crate::rpc::change_profile_with_verification(|| {
        prepared.borrow_mut().commit()?;
        if let Some(snapshot) = snapshot {
            let mut entries: Vec<respire::memory::model::MemoryEntry> = serde_json::from_str(snapshot)?;
            for entry in &mut entries { entry.user = prepared.borrow().user.clone(); }
            ensure!(!respire::service::off_mode(), "target memory service is disabled; source library was preserved");
            respire::service::ensure_writable()?;
            let _deferred = respire::core_sdk::defer_indexing();
            let target = respire::service::App::open()?;
            let before = target.sync().context("target synchronization failed before copying; source library was preserved")?;
            ensure!(before.converged, "target library has not converged; resolve sync before migrating; source library was preserved");
            drop(target);
            *imported.borrow_mut() = Some(respire::service::import_json_text(&serde_json::to_string(&entries)?)?);
        }
        Ok(())
    }, || prepared.borrow_mut().rollback(), || {
        let actual = crate::rpc::query_existing_json(vec!["account".to_owned(), "list".to_owned()])?;
        ensure!(actual["status"] == "ok", "runtime account verification failed");
        let accounts = actual["details"]["accounts"].as_array().context("runtime account list missing accounts")?;
        let current = accounts.iter().find(|account| account["current"].as_bool() == Some(true)).context("runtime did not report a selected account")?;
        let expected = prepared.borrow();
        let current_directory = current["dir"].as_str().context("runtime did not report the selected directory")?;
        ensure!(current["user"].as_str() == Some(expected.user.as_str())
            && std::path::Path::new(current_directory) == expected.directory.as_path(),
            "runtime account or directory differs from the authorized account");
        expected.finish_migration(addr, authorization)?;
        expected.complete()?;
        Ok(())
    })?;
    let sync = if snapshot.is_some() {
        Some(match crate::rpc::query_existing_json(vec!["sync".to_owned()]) {
            Ok(result) => result,
            Err(error) => json!({"status":"pending","errors":[format!("{error:#}")]}),
        })
    } else { None };
    let status = if sync.as_ref().is_some_and(|result| result["status"] != "ok") {
        crate::output::Status::Warn
    } else { crate::output::Status::Ok };
    let committed = prepared.borrow();
    crate::emit_result(crate::output::ResultEnvelope::new(
        command, status,
        json!({"ok":true,"user":committed.user,"addr":addr,"dir":committed.directory.to_string_lossy(),"super_issued":committed.migration_super_password(),"import":*imported.borrow(),"sync":sync}), Vec::new(),
    ))
}

pub(crate) fn migrate_vault(addr: Option<&str>, user: Option<&str>, pass: Option<&str>, legacy_super: Option<&str>, secret_key: Option<&str>, new_super: Option<&str>) -> Result<()> {
    crate::runtime_policy::require_host("explicit legacy vault migration")?;
    ensure!(!crate::rpc::worker_active(), "vault migration requires the host terminal");
    crate::rpc::recover_interrupted_login()?;
    let local = respire::auth::read_session_json()?;
    let addr = origin(addr.or(local["addr"].as_str()).context("legacy server address required")?)?;
    let user = user.or(local["user"].as_str()).filter(|value| !value.is_empty()).context("select the legacy account first")?;
    let password = match pass {
        Some(value) => value.to_owned(),
        None if respire::prompt::interactive() => respire::prompt::ask_secret("login password: ")?,
        None => anyhow::bail!("migration requires --pass or an interactive terminal"),
    };
    let authorization = respire::auth::password_authorization(&addr, user, &password)?;
    let prepared = respire_app::login_transaction::PreparedLogin::prepare_migration(&addr, &authorization, &password, legacy_super, secret_key, new_super)?;
    if let Some(code) = prepared.migration_super_password() {
        eprintln!("Keep this recovery code before migration: {code}");
    }
    commit_verified(&addr, &authorization, prepared, "migrate", None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_origin_preserves_precedence_and_empty_fallback() -> Result<()> {
        for empty in [None, Some(""), Some(" \t\n")] {
            assert_eq!(login_origin(empty, empty)?, respire::service::DEFAULT_SERVER_ADDR);
            assert_eq!(login_origin(empty, Some("https://self-hosted.invalid"))?, "https://self-hosted.invalid");
        }
        assert_eq!(login_origin(Some("https://explicit.invalid"), Some("http://stored.invalid"))?, "https://explicit.invalid");
        for local in ["http://localhost:1234", "http://127.0.0.1:1234", "http://127.2.3.4:1234", "http://[::1]:1234"] {
            assert_eq!(login_origin(None, Some(local))?, local);
        }
        Ok(())
    }

    #[test]
    fn login_origin_rejects_unsafe_addresses_without_echoing_them() -> Result<()> {
        for unsafe_addr in ["http://remote.invalid", "http://192.168.1.1", "http://localhost.invalid", "http://[::2]", "ftp://localhost", "https://name:synthetic-secret@remote.invalid", "https://remote.invalid/path?synthetic-secret#fragment", "synthetic-secret"] {
            for (explicit, stored, source) in [(Some(unsafe_addr), None, "--addr"), (None, Some(unsafe_addr), "stored session.json addr")] {
                let error = match login_origin(explicit, stored) { Err(error) => format!("{error:#}"), Ok(_) => anyhow::bail!("unsafe login origin was accepted") };
                assert!(error.contains(source), "{error}");
                assert!(error.contains("--addr https://api.rsrs.rs"), "{error}");
                assert!(!error.contains(unsafe_addr), "{error}");
                assert!(!error.contains("synthetic-secret"), "{error}");
            }
        }
        Ok(())
    }
}

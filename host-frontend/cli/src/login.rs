//! Client login prompts and OAuth HTTP; Runtime owns account transactions and migration.
use anyhow::{anyhow, ensure, Context, Result};
use respire_protocol::host_control::{
    HostAuthAccountOutcome, HostAuthAccountResult, HostAuthAuthorization, HostAuthLoginContinuation,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

pub(crate) fn origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).context("login server must be an absolute origin")?;
    let local = matches!(url.host(), Some(url::Host::Domain("localhost")))
        || matches!(url.host(), Some(url::Host::Ipv4(address)) if address.is_loopback())
        || matches!(url.host(), Some(url::Host::Ipv6(address)) if address.is_loopback());
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "login requires HTTPS, except loopback fixtures"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "login origin must not include credentials, paths, queries or fragments"
    );
    Ok(url.origin().ascii_serialization())
}

fn selected_session() -> Result<Value> {
    let (_, profile) = respire_client_host::config::control_roots()?;
    respire_client_host::identity::read_session_json(&profile.join("session.json"))?
        .context("no local session")
}

fn login_origin(explicit: Option<&str>, stored: Option<&str>) -> Result<String> {
    let nonempty = |value: &str| !value.trim().is_empty();
    let (value, source) = if let Some(value) = explicit.filter(|value| nonempty(value)) {
        (value, "--addr")
    } else if let Some(value) = stored.filter(|value| nonempty(value)) {
        (value, "stored session.json addr")
    } else {
        (
            crate::client_config::DEFAULT_SERVER_ADDR,
            "default login server",
        )
    };
    origin(value).with_context(|| format!(
        "invalid login server from {source}; supply --addr <https-origin> (official service: --addr https://api.rsrs.rs); RSRS_ADDR and client.json are not consulted for login"
    ))
}

fn browser_authorization(
    addr: &str,
    user: Option<&str>,
    dashboard: Option<&str>,
    no_open: bool,
) -> Result<(String, HostAuthAuthorization)> {
    let dashboard = match dashboard {
        Some(value) => origin(value)
            .context("invalid OAuth dashboard from --dashboard; supply an HTTPS origin")?,
        None if addr == "https://api.rsrs.rs" => "https://dash.rsrs.rs".to_owned(),
        None if addr == "https://api.dev.rsrs.rs" || addr == "https://api-dev.rsrs.rs" => {
            "https://dash.dev.rsrs.rs".to_owned()
        }
        None if respire::prompt::interactive() => {
            origin(&respire::prompt::ask("dashboard origin: ")?)
                .context("invalid OAuth dashboard from terminal input; supply an HTTPS origin")?
        }
        None => anyhow::bail!("custom login servers require --dashboard <dashboard-origin>"),
    };
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(30))
        .build();
    let device = respire_client_host::env::host_name().unwrap_or_else(|| "CLI".to_owned());
    let grant: Value = agent
        .post(&format!("{addr}/oauth/device/code"))
        .send_form(&[
            ("client_id", "respire-cli"),
            ("device_name", &device),
            ("expected_user", user.unwrap_or_default()),
        ])
        .context("browser authorization request failed")?
        .into_json()?;
    let device_code = grant["device_code"]
        .as_str()
        .context("authorization response missing device_code")?;
    let code = grant["user_code"]
        .as_str()
        .context("authorization response missing user_code")?;
    ensure!(
        code.len() == 12 && code.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "authorization response has an invalid user code"
    );
    let expires = grant["expires_in"]
        .as_u64()
        .filter(|seconds| *seconds > 0 && *seconds <= 600)
        .context("authorization response has an invalid expiry")?;
    let mut interval = grant["interval"]
        .as_u64()
        .filter(|seconds| *seconds > 0 && *seconds <= 30)
        .context("authorization response has an invalid polling interval")?;
    let url = format!("{dashboard}/#/authorize?code={code}");
    ensure!(grant["verification_uri_complete"].as_str() == Some(url.as_str()), "server dashboard differs from the expected dashboard; configure RSRS_DASHBOARD_URL on the server or --dashboard in the CLI");
    eprintln!("Authorize CLI: {url}\nCheck code: {code}");
    if !no_open {
        crate::web::open_browser(&url)?;
    }
    let deadline = Instant::now() + Duration::from_secs(expires);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(interval));
        let response = match agent.post(&format!("{addr}/oauth/token")).send_form(&[
            ("client_id", "respire-cli"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ]) {
            Ok(response) => response,
            Err(ureq::Error::Status(400, response)) => response,
            Err(error) => return Err(anyhow!("browser authorization polling failed: {error}")),
        };
        let reply: Value = response.into_json()?;
        if reply["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
        {
            ensure!(
                reply["token_type"]
                    .as_str()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer")),
                "unsupported authorization token type"
            );
            let user = reply["user"]
                .as_str()
                .filter(|value| !value.is_empty())
                .context("authorization did not return a user")?
                .to_owned();
            let token = reply["access_token"]
                .as_str()
                .context("authorization did not return a token")?
                .to_owned();
            let session_id = match reply.get("session_id") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) => Some(value.clone()),
                Some(_) => anyhow::bail!("authorization returned an invalid session ID"),
            };
            return Ok((user, HostAuthAuthorization::Browser { token, session_id }));
        }
        match reply["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some("access_denied") => {
                anyhow::bail!("browser authorization was denied; original account was preserved")
            }
            Some("expired_token" | "invalid_grant") => anyhow::bail!(
                "browser authorization expired or was consumed; original account was preserved"
            ),
            _ => anyhow::bail!("invalid browser authorization response"),
        }
    }
    Err(anyhow!(
        "browser authorization timed out; original account was preserved"
    ))
}

/// Collect client input without opening a store, reading keyring material or authenticating a password.
fn prepare_authorization(
    addr: &str,
    user: Option<&str>,
    pass: Option<&str>,
    interactive: bool,
    oauth: bool,
    dashboard: Option<&str>,
    no_open: bool,
) -> Result<(String, HostAuthAuthorization)> {
    let password_mode = if interactive && !oauth && pass.is_none() && respire::prompt::interactive()
    {
        let choice = respire::prompt::ask("login method: 1 OAuth (default), 2 password/TOTP: ")?;
        ensure!(
            matches!(choice.trim(), "" | "1" | "2"),
            "select login method 1 or 2"
        );
        choice.trim() == "2"
    } else {
        interactive && !oauth
    };
    ensure!(
        !password_mode || (dashboard.is_none() && !no_open),
        "--dashboard and --no-open apply to OAuth login"
    );
    if !password_mode {
        return browser_authorization(addr, user, dashboard, no_open);
    }
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
    Ok((user.trim().to_owned(), HostAuthAuthorization::Password {
        password,
        totp: crate::host_rpc::totp_code(),
    }))
}

pub(crate) fn run(
    addr: Option<&str>,
    user: Option<&str>,
    pass: Option<&str>,
    super_password: Option<&str>,
    interactive: bool,
    oauth: bool,
    dashboard: Option<&str>,
    no_open: bool,
    migrate_local: bool,
) -> Result<()> {
    crate::runtime_policy::require_host("account authorization and profile switching")?;
    crate::autostart::check_direct_access()?;
    let last = selected_session()
        .ok()
        .and_then(|session| session["addr"].as_str().map(ToOwned::to_owned));
    let selected_addr = if interactive && addr.is_none() && respire::prompt::interactive() {
        let selected = respire::prompt::ask("server HTTPS origin (Enter = current/public): ")?;
        (!selected.trim().is_empty()).then(|| selected.trim().to_owned())
    } else {
        None
    };
    let addr = login_origin(addr.or(selected_addr.as_deref()), last.as_deref())?;
    let (user, authorization) = prepare_authorization(
        &addr, user, pass, interactive, oauth, dashboard, no_open,
    )?;
    let legacy_password = match &authorization {
        HostAuthAuthorization::Password { password, .. } if !password.is_empty() => Some(password.clone()),
        _ => pass.filter(|value| !value.is_empty()).map(str::to_owned)
            .or_else(|| respire_client_host::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty())),
    };
    let input = HostAuthLoginContinuation {
        legacy_password,
        migrate_local,
        offer_local_merge: interactive && !migrate_local && respire::prompt::interactive(),
        ..Default::default()
    };
    run_account_control("login", &addr, &user, authorization, super_password, input)
}

/// Format the verified transaction result without accessing its profile or keys.
fn emit_login_result(command: &str, summary: Value) -> Result<()> {
    let status = if summary.get("sync")
        .filter(|result| !result.is_null())
        .is_some_and(|result| result["status"] != "ok")
    {
        crate::output::Status::Warn
    } else {
        crate::output::Status::Ok
    };
    crate::emit_result(crate::output::ResultEnvelope::new(
        command, status, summary, Vec::new(),
    ))
}

fn source_secret_input() -> Result<Option<String>> {
    let value = respire::prompt::ask_secret(
        "original local super password (v1: login password; Enter = saved credentials): ",
    )?;
    Ok((!value.is_empty()).then_some(value))
}

fn supply_login_inputs(
    required: &[String],
    authorization: &mut HostAuthAuthorization,
    super_password: &mut String,
    input: &mut HostAuthLoginContinuation,
    supplied: &mut BTreeSet<String>,
) -> Result<()> {
    ensure!(!required.is_empty(), "Runtime requested no login input");
    let mut requested = BTreeSet::new();
    for field in required {
        ensure!(matches!(field.as_str(),
            "totp" | "legacy_password" | "account_secret" | "super_password" | "merge_local" | "source_secret")
            && requested.insert(field.as_str()) && !supplied.contains(field),
            "Runtime requested unsupported, repeated or already supplied login input");
    }
    ensure!(respire::prompt::interactive(),
        "login requires an interactive terminal for additional input; original operation was retained");
    // Resolve the admitted offer before asking for source-library credentials.
    if requested.contains("merge_local") {
        ensure!(input.offer_local_merge && !input.migrate_local && !input.migrate_vault
            && input.merge_local.is_none(), "Runtime requested an unbound local merge confirmation");
        let answer = respire::prompt::ask(
            "Merge selected local memories into this server account (skip identical bodies; keep existing records)? [y/N]: ",
        )?;
        input.merge_local = Some(answer.trim().eq_ignore_ascii_case("y"));
        supplied.insert("merge_local".to_owned());
        if input.merge_local == Some(true) && !requested.contains("source_secret") {
            input.source_secret = source_secret_input()?;
            supplied.insert("source_secret".to_owned());
        }
    }
    for field in required {
        match field.as_str() {
            "totp" => {
                let HostAuthAuthorization::Password { totp, .. } = authorization else {
                    anyhow::bail!("Runtime requested password TOTP for browser authorization");
                };
                let code = respire::prompt::ask_secret("TOTP code (6 digits): ")?;
                let code = code.trim();
                ensure!(code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
                    "TOTP code must contain 6 digits");
                *totp = Some(code.to_owned());
            }
            "legacy_password" => {
                let value = respire::prompt::ask_secret("original v1 login password: ")?;
                ensure!(!value.is_empty(), "original login password is required");
                input.legacy_password = Some(value);
            }
            "account_secret" => {
                let value = respire::prompt::ask_secret("original v1 Account Secret: ")?;
                ensure!(!value.is_empty(), "original Account Secret is required");
                input.account_secret = Some(value);
            }
            "super_password" => {
                let value = respire::prompt::ask_secret("super password (A3-…): ")?;
                ensure!(!value.is_empty(), "super password is required");
                *super_password = value;
            }
            "source_secret" => {
                ensure!(input.migrate_local || input.merge_local == Some(true),
                    "Runtime requested source credentials without local migration");
                input.source_secret = source_secret_input()?;
            }
            "merge_local" => {}
            _ => anyhow::bail!("unsupported login input"),
        }
        supplied.insert(field.clone());
    }
    Ok(())
}

fn run_account_control(
    command: &str,
    addr: &str,
    user: &str,
    mut authorization: HostAuthAuthorization,
    super_password: Option<&str>,
    mut input: HostAuthLoginContinuation,
) -> Result<()> {
    let explicit_super_password = super_password.is_some();
    let mut super_password = super_password.unwrap_or_default().to_owned();
    let mut resume: Option<HostAuthAccountResult> = None;
    let mut continuation = None;
    let mut supplied = BTreeSet::new();
    if !super_password.is_empty() {
        supplied.insert("super_password".to_owned());
    }
    if input.legacy_password.as_ref().is_some_and(|value| !value.is_empty()) {
        supplied.insert("legacy_password".to_owned());
    }
    if matches!(&authorization, HostAuthAuthorization::Password { totp: Some(_), .. }) {
        supplied.insert("totp".to_owned());
    }
    if input.migrate_local && respire::prompt::interactive() {
        input.source_secret = source_secret_input()?;
        supplied.insert("source_secret".to_owned());
    }
    loop {
        let request_authorization = match &authorization {
            HostAuthAuthorization::Password { password, totp } =>
                HostAuthAuthorization::Password { password: password.clone(), totp: totp.clone() },
            HostAuthAuthorization::Browser { token, session_id } =>
                HostAuthAuthorization::Browser { token: token.clone(), session_id: session_id.clone() },
        };
        let request_input = HostAuthLoginContinuation {
            legacy_password: input.legacy_password.clone(),
            account_secret: input.account_secret.clone(),
            source_secret: input.source_secret.clone(),
            secret_key: input.secret_key.clone(),
            new_super: input.new_super.clone(),
            migrate_local: input.migrate_local,
            migrate_vault: input.migrate_vault,
            offer_local_merge: input.offer_local_merge,
            merge_local: input.merge_local,
        };
        let envelope = crate::autostart::control_login_step(
            addr, user, request_authorization,
            (explicit_super_password || !super_password.is_empty()).then_some(super_password.as_str()),
            request_input, resume.as_ref(), &mut continuation,
        )?;
        let receipt: HostAuthAccountResult = serde_json::from_value(envelope.summary)
            .map_err(|_| anyhow!("invalid login control receipt"))?;
        if let Some(previous) = resume.as_ref() {
            ensure!(receipt.operation_id == previous.operation_id
                && receipt.source_profile == previous.source_profile,
                "login continuation returned a different operation or source profile");
        }
        match receipt.outcome {
            HostAuthAccountOutcome::AwaitingInput => {
                ensure!(matches!(envelope.status, crate::output::Status::Pending),
                    "login input request has an invalid status");
                let status = receipt.login.as_ref().context("login input request is missing")?;
                ensure!(status.user == user && status.addr == addr,
                    "login input request belongs to a different account");
                supply_login_inputs(&status.required_inputs, &mut authorization,
                    &mut super_password, &mut input, &mut supplied)
                    .with_context(|| format!(
                        "login input pending; operation_id={} source_profile={}; query the original operation before restarting login",
                        receipt.operation_id, receipt.source_profile.display()
                    ))?;
                resume = Some(receipt);
            }
            HostAuthAccountOutcome::Committed => {
                ensure!(matches!(envelope.status, crate::output::Status::Ok),
                    "committed login has an invalid status");
                let status = receipt.login.as_ref().context("committed login result is missing")?;
                let directory = receipt.target_profile.as_ref().context("login target is missing")?;
                ensure!(status.required_inputs.is_empty() && status.user == user
                    && status.addr == addr && status.dir.as_ref() == Some(directory),
                    "committed login result differs from the verified account");
                let imported = status.import.as_ref().map(|value| {
                    value.get("report").context("Runtime import result is missing its report")
                }).transpose()?;
                return emit_login_result(command, json!({
                    "ok": true, "user": status.user, "addr": status.addr,
                    "dir": directory.to_string_lossy(), "super_issued": status.super_issued,
                    "import": imported, "sync": status.sync,
                }));
            }
            HostAuthAccountOutcome::RolledBack => anyhow::bail!(
                "account operation rolled back; operation_id={} source_profile={}; original account was preserved",
                receipt.operation_id, receipt.source_profile.display()
            ),
            HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Unknown => {
                return Err(crate::autostart::AccountOutcomeUnknown {
                    operation_id: receipt.operation_id,
                    source_profile: receipt.source_profile,
                    register: false,
                }.into());
            }
        }
    }
}

pub(crate) fn migrate_vault(
    addr: Option<&str>,
    user: Option<&str>,
    pass: Option<&str>,
    legacy_super: Option<&str>,
    secret_key: Option<&str>,
    new_super: Option<&str>,
) -> Result<()> {
    crate::runtime_policy::require_host("explicit legacy vault migration")?;
    crate::autostart::check_direct_access()?;
    let local = selected_session()?;
    let addr = origin(
        addr.or(local["addr"].as_str())
            .context("legacy server address required")?,
    )?;
    let user = user.or(local["user"].as_str())
        .filter(|value| !value.is_empty())
        .context("select the legacy account first")?;
    let password = match pass {
        Some(value) => value.to_owned(),
        None if respire::prompt::interactive() => respire::prompt::ask_secret("login password: ")?,
        None => anyhow::bail!("migration requires --pass or an interactive terminal"),
    };
    let authorization = HostAuthAuthorization::Password {
        password: password.clone(),
        totp: crate::host_rpc::totp_code(),
    };
    let input = HostAuthLoginContinuation {
        legacy_password: Some(password),
        secret_key: secret_key.map(str::to_owned),
        new_super: new_super.map(str::to_owned),
        migrate_vault: true,
        ..Default::default()
    };
    run_account_control("migrate", &addr, user, authorization, legacy_super, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_origin_preserves_precedence_and_empty_fallback() -> Result<()> {
        for empty in [None, Some(""), Some(" \t\n")] {
            assert_eq!(
                login_origin(empty, empty)?,
                crate::client_config::DEFAULT_SERVER_ADDR
            );
            assert_eq!(
                login_origin(empty, Some("https://self-hosted.invalid"))?,
                "https://self-hosted.invalid"
            );
        }
        assert_eq!(
            login_origin(
                Some("https://explicit.invalid"),
                Some("http://stored.invalid")
            )?,
            "https://explicit.invalid"
        );
        for local in [
            "http://localhost:1234",
            "http://127.0.0.1:1234",
            "http://127.2.3.4:1234",
            "http://[::1]:1234",
        ] {
            assert_eq!(login_origin(None, Some(local))?, local);
        }
        Ok(())
    }

    #[test]
    fn login_origin_rejects_unsafe_addresses_without_echoing_them() -> Result<()> {
        for unsafe_addr in [
            "http://remote.invalid",
            "http://192.168.1.1",
            "http://localhost.invalid",
            "http://[::2]",
            "ftp://localhost",
            "https://name:synthetic-secret@remote.invalid",
            "https://remote.invalid/path?synthetic-secret#fragment",
            "synthetic-secret",
        ] {
            for (explicit, stored, source) in [
                (Some(unsafe_addr), None, "--addr"),
                (None, Some(unsafe_addr), "stored session.json addr"),
            ] {
                let error = match login_origin(explicit, stored) {
                    Err(error) => format!("{error:#}"),
                    Ok(_) => anyhow::bail!("unsafe login origin was accepted"),
                };
                assert!(error.contains(source), "{error}");
                assert!(error.contains("--addr https://api.rsrs.rs"), "{error}");
                assert!(!error.contains(unsafe_addr), "{error}");
                assert!(!error.contains("synthetic-secret"), "{error}");
            }
        }
        Ok(())
    }
}

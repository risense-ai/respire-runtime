//! One-shot host RPC survives the memory Runtime's profile transition.
//! Credentials arrive only on stdin; normal Runtime RPC retains its host gates.
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};

thread_local! {static TOTP:std::cell::RefCell<Option<String>>=const {std::cell::RefCell::new(None)};}
pub(crate) fn totp_code() -> Option<String> {
    TOTP.with(|value| value.borrow().clone())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    v: u8,
    id: String,
    method: String,
    params: BTreeMap<String, String>,
}

fn arguments(request: &Request) -> Result<Vec<String>> {
    ensure!(request.v == 1, "unsupported host RPC version");
    ensure!(
        !request.id.is_empty()
            && request.id.len() <= 96
            && request
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)),
        "invalid host RPC request ID"
    );
    let (command, fields, required): (&str, &[(&str, &str)], &[&str]) =
        match request.method.as_str() {
            "auth.register" => (
                "register",
                &[("addr", "addr"), ("user", "user"), ("password", "pass")],
                &["user", "password"],
            ),
            "auth.login" => (
                "login",
                &[
                    ("addr", "addr"),
                    ("user", "user"),
                    ("password", "pass"),
                    ("super", "super"),
                ],
                &["user", "password"],
            ),
            "auth.recover" => (
                concat!("five", "keys"),
                &[
                    ("addr", "addr"),
                    ("user", "user"),
                    ("password", "pass"),
                    ("secret", "secret"),
                    ("super", "super"),
                    ("kdf_salt", "kdf-salt"),
                    ("wrapped_urk", "wrapped-urk"),
                    ("urk_nonce", "urk-nonce"),
                ],
                &["kdf_salt", "wrapped_urk", "urk_nonce"],
            ),
            "auth.reset" => ("super-reset", &[("super", "super")], &[]),
            _ => bail!("unknown host RPC method"),
        };
    for key in request.params.keys() {
        ensure!(
            fields.iter().any(|(name, _)| name == key)
                || (key == "totp" && request.method == "auth.login"),
            "unknown authentication field"
        );
    }
    if let Some(addr) = request.params.get("addr").filter(|value| !value.is_empty()) {
        crate::login::origin(addr).context("invalid authentication server origin")?;
    }
    if request.method == "auth.recover" {
        let present = |key: &str| request.params.get(key).is_some_and(|value| !value.is_empty());
        ensure!(present("super") || (present("password") && present("secret")),
            "recovery requires a super password or the legacy password and Account Secret");
    }
    if let Some(code) = request.params.get("totp") {
        ensure!(
            code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
            "TOTP code must contain 6 digits"
        );
    }
    for key in required {
        ensure!(
            request.params.get(*key).is_some_and(|v| !v.is_empty()),
            "missing authentication field: {key}"
        );
    }
    let mut args = vec!["--json".to_owned(), command.to_owned()];
    if request.method == "auth.login" {
        args.push("--interactive".to_owned());
    }
    if request.method == "auth.recover" && !request.params.contains_key("password") {
        args.push("--pass=".to_owned());
    }
    for (key, flag) in fields {
        if let Some(value) = request.params.get(*key) {
            ensure!(
                value.len() <= 16384 && !value.contains('\0'),
                "invalid authentication field"
            );
            args.push(format!("--{flag}={value}"));
        }
    }
    Ok(args)
}

fn scrub(value: &mut Value, secrets: &[&str]) {
    match value {
        Value::String(text) => {
            for secret in secrets {
                if !secret.is_empty() {
                    *text = text.replace(secret, "[redacted]");
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                scrub(value, secrets);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                scrub(value, secrets);
            }
        }
        _ => {}
    }
}

pub(crate) fn serve() -> Result<i32> {
    crate::runtime_policy::require_host("authentication RPC")?;
    ensure!(
        std::env::args_os()
            .skip(1)
            .all(|arg| arg == "--json" || arg == "--host-rpc-stdio" || arg == "--client-only"),
        "host RPC accepts no command-line payload"
    );
    let mut bytes = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "host RPC request exceeds 64 KiB");
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid host RPC JSON request"))?;
    let captured = match arguments(&request).and_then(|args| {
        crate::prepare_command_runtime()?;
        Ok(args)
    }) {
        Ok(args) => {
            // Preserve existing host lifecycle, access gates and profile transactions.
            crate::HOST_RPC_OUTPUT.set(true);
            TOTP.with(|value| *value.borrow_mut() = request.params.get("totp").cloned());
            let result = crate::capture_run(args);
            TOTP.with(|value| *value.borrow_mut() = None);
            crate::HOST_RPC_OUTPUT.set(false);
            result
        }
        Err(error) => {
            let (envelope, exit) = crate::command_failure(&error);
            crate::Captured { exit, envelope }
        }
    };
    let mut envelope = serde_json::to_value(captured.envelope)?;
    let secrets: Vec<&str> = request
        .params
        .iter()
        .filter(|(key, _)| {
            matches!(
                key.as_str(),
                "password" | "super" | "secret" | "wrapped_urk" | "totp"
            )
        })
        .map(|(_, v)| v.as_str())
        .collect();
    if envelope["status"] == "fail" {
        scrub(&mut envelope, &secrets);
    } else if let Some(errors) = envelope.get_mut("errors") {
        scrub(errors, &secrets);
    }
    let response = json!({"v":1,"id":request.id,"ok":captured.exit==0,"exit":captured.exit,"envelope":envelope});
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).context("write host RPC reply")?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(captured.exit)
}

//! Local classification settings; never opens a model or contacts a provider.

use anyhow::{bail, ensure, Context, Result};
use std::io::{self, IsTerminal};

fn backend_name(value: Option<&str>) -> Result<String> {
    let backend = value
        .map(str::to_owned)
        .or_else(respire::keystore::load_classify_backend)
        .unwrap_or_else(|| "jev".to_owned());
    ensure!(
        backend == "jev" || backend == "ds",
        "backend must be jev or ds"
    );
    Ok(backend)
}

fn ds_base(value: Option<&str>) -> Result<String> {
    let base = value
        .map(str::to_owned)
        .or_else(respire::keystore::load_ds_last_base)
        .unwrap_or_else(|| crate::classify::DEFAULT_DS_BASE.to_owned());
    let base = base.trim().trim_end_matches('/');
    let host = respire::keystore::host_of(base);
    ensure!(
        (base.starts_with("https://") || base.starts_with("http://"))
            && !host.is_empty()
            && !base.chars().any(char::is_whitespace)
            && !base.contains(['@', '?', '#']),
        "API base must be an HTTP(S) URL without credentials, query, or fragment"
    );
    Ok(base.to_owned())
}

/// Return public settings and key availability, never the credential value.
pub(crate) fn status(backend: Option<&str>, api_base: Option<&str>) -> Result<serde_json::Value> {
    let backend = backend_name(backend)?;
    let (base, model, slot) = if backend == "ds" {
        let base = ds_base(api_base)?;
        let host = respire::keystore::host_of(&base);
        let model = respire::keystore::load_ds_model(&host)
            .unwrap_or_else(|| crate::classify::DEFAULT_DS_MODEL.to_owned());
        (base, model, format!("ds@{host}"))
    } else {
        ensure!(
            api_base.is_none(),
            "jev uses a fixed endpoint; API base is only configurable for ds"
        );
        (
            crate::classify::DEFAULT_API_BASE.to_owned(),
            crate::classify::DEFAULT_MODEL.to_owned(),
            "typesafe".to_owned(),
        )
    };
    Ok(serde_json::json!({
        "backend": backend,
        "api_base": base,
        "model": model,
        "has_key": respire::keystore::load_classify_key(&slot).is_some(),
    }))
}

/// Save provider settings through the existing OS keystore. Key input uses a
/// redirected stdin line so terminal echo and command-line history cannot expose it.
pub(crate) fn configure(
    backend: &str,
    api_base: Option<&str>,
    model: Option<&str>,
    key_stdin: bool,
) -> Result<serde_json::Value> {
    let backend = backend_name(Some(backend))?;
    let base = if backend == "ds" {
        ds_base(api_base)?
    } else {
        ensure!(
            api_base.is_none() && model.is_none(),
            "jev endpoint and model are fixed"
        );
        crate::classify::DEFAULT_API_BASE.to_owned()
    };
    let host = respire::keystore::host_of(&base);
    let slot = if backend == "ds" {
        format!("ds@{host}")
    } else {
        "typesafe".to_owned()
    };
    let model = model.map(str::trim);
    ensure!(
        model.is_none_or(|value| !value.is_empty()),
        "model must not be empty"
    );
    if key_stdin {
        ensure!(
            !io::stdin().is_terminal(),
            "--key-stdin requires redirected input; do not paste a key into an echoed terminal"
        );
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("failed to read provider key from stdin")?;
        let key = input.trim();
        ensure!(!key.is_empty(), "provider key stdin is empty");
        respire::keystore::save_classify_key(&slot, key)?;
        ensure!(
            respire::keystore::load_classify_key(&slot).as_deref() == Some(key),
            "provider key was not readable after saving"
        );
    }
    if backend == "ds" {
        respire::keystore::save_ds_last_base(&base);
        ensure!(
            respire::keystore::load_ds_last_base().as_deref() == Some(base.as_str()),
            "provider endpoint was not saved"
        );
        if let Some(model) = model {
            respire::keystore::save_ds_model(&host, model);
            ensure!(
                respire::keystore::load_ds_model(&host).as_deref() == Some(model),
                "provider model was not saved"
            );
        }
    }
    respire::keystore::save_classify_backend(&backend);
    if respire::keystore::load_classify_backend().as_deref() != Some(backend.as_str()) {
        bail!("classification backend was not saved");
    }
    status(
        Some(&backend),
        if backend == "ds" { Some(&base) } else { None },
    )
}

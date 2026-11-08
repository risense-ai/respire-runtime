//! Real CLI account/space calls with Runtime-owned business fixtures and decryption.
use super::support;
use std::process::{Command, Output};
use std::time::Duration;

fn runtime_bin() -> std::io::Result<std::path::PathBuf> {
    support::runtime_bin()
}

fn isolated_command(models: Option<&std::path::Path>) -> std::io::Result<Command> {
    let mut command = Command::new(match support::legacy_cli().map_err(std::io::Error::other)? { Some(binary)=>binary, None=>support::cli_bin()? });
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| {
            name.starts_with("RSRS_") || name.starts_with("ONEMEMORY_") || name.starts_with("RESPIRE_")
        }) {
            command.env_remove(name);
        }
    }
    command.env_remove("GH_TOKEN").env_remove("GITHUB_TOKEN");
    if let Some(models) = models {
        command.env("RSRS_M3_DIR", models).env("RSRS_ENGINE", "cpu");
    }
    Ok(command)
}

fn runtime_health(port: u16, stage: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let url = format!("http://127.0.0.1:{port}/api/health");
    let health: serde_json::Value = ureq::get(&url).set("X-Respire-Health", "runtime-v1")
        .timeout(Duration::from_secs(5)).call()?.into_json()?;
    if std::env::var("RSRS_TEST_EXPECT_CLIENT2_HOST").as_deref() == Ok("1") {
        let legacy: serde_json::Value = ureq::get(&url)
            .timeout(Duration::from_secs(5)).call()?.into_json()?;
        use sha2::{Digest, Sha256};
        let root = health["installation_root"].as_str().ok_or("Runtime installation root missing")?;
        let expected = std::path::Path::new(root).join("bin")
            .join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" }).canonicalize()?;
        let same_cli = Sha256::digest(std::fs::read(&expected)?)
            == Sha256::digest(std::fs::read(support::cli_bin()?)?);
        let pid = u32::try_from(legacy["pid"].as_u64().ok_or("legacy host PID missing")?)?;
        let actual_image: std::path::PathBuf = {
            #[cfg(target_os = "linux")]
            { std::fs::read_link(format!("/proc/{pid}/exe"))?.canonicalize()? }
            #[cfg(not(target_os = "linux"))]
            { return Err("this opt-in account host fixture requires native Linux".into()); }
        };
        let live = respire_commands::net_rpc::process_is_running(pid)?;
        let valid = same_cli && live && actual_image == expected
            && legacy["compatibility_host"] == "client2-v0256"
            && legacy["backend_instance_id"] == health["instance_id"]
            && legacy["pid"] != health["pid"]
            && legacy["data_dir"] == health["data_dir"]
            && legacy["installation_root"] == health["installation_root"]
            && legacy["exe"].as_str().is_some_and(|path| std::path::Path::new(path)
                .canonicalize().is_ok_and(|path| path == expected));
        eprintln!("client2-account-host {}", serde_json::json!({"stage":stage, "passed":valid}));
        if !valid {
            return Err("legacy Client2 host identity was not preserved across profile maintenance".into());
        }
    }
    Ok(health)
}

#[test]
fn space_create_list_use_remove() -> Result<(), Box<dyn std::error::Error>> {
    if support::legacy_cli()?.is_some() {
        return legacy_space_contract("account::space_create_list_use_remove");
    }
    use serde_json::Value;

    let home = tempfile::tempdir()?;
    let root = home.path().join(".rsrs");
    std::fs::create_dir(&root)?;
    if support::legacy_cli()?.is_some() {
        support::stage_legacy_cli(&root)?;
    } else {
        support::install_runtime_fixture(&root)?;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let invoke = |args: &[&str]| -> std::io::Result<Output> {
        isolated_command(None)?
            .arg("--json")
            .args(args)
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("RSRS_DATA_DIR", &root)
            .env("RSRS_BIN_DIR", root.join("bin"))
            .env("RSRS_M3_DIR", root.join("absent-model"))
            .env("RSRS_RPC_PORT", port.to_string())
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env_remove("RSRS_RUNTIME_BIN")
            .output()
    };
    let success = |args: &[&str]| -> Result<Value, Box<dyn std::error::Error>> {
        let output = invoke(args)?;
        assert!(
            output.status.success(),
            "space command {args:?} failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    };

    assert!(!invoke(&["space", "create", "main"])?.status.success());
    let created = success(&["space", "create", "team_a"])?;
    assert_eq!(created["summary"]["name"], "team_a");
    let listed = success(&["space", "list"])?;
    let spaces = listed["details"]["spaces"]
        .as_array()
        .ok_or("space listing must contain its profile array")?;
    assert!(spaces.iter().any(|space| space["name"] == "team_a"));
    assert!(!invoke(&["space", "use", "missing"])?.status.success());
    let used = success(&["space", "use", "main"])?;
    assert_eq!(used["summary"]["name"], "main");
    success(&["space", "use", "team_a"])?;
    assert!(
        !invoke(&["space", "remove", "team_a", "--yes"])?.status.success(),
        "cannot remove current space"
    );
    success(&["space", "use", "main"])?;
    success(&["space", "remove", "team_a", "--yes"])?;
    Ok(())
}

#[test]
fn spaces_coordinate_with_the_owned_runtime() -> Result<(), Box<dyn std::error::Error>> {
    if support::legacy_cli()?.is_some() {
        return legacy_space_contract("account::spaces_coordinate_with_the_owned_runtime");
    }
    use serde_json::{json, Value};
    let home = tempfile::tempdir()?;
    let library = home.path().join(".rsrs");
    std::fs::create_dir(&library)?;
    if support::legacy_cli()?.is_some() {
        support::stage_legacy_cli(&library)?;
    } else {
        support::install_runtime_fixture(&library)?;
    }
    let source_runtime = runtime_bin()?;
    let version = source_runtime.parent().and_then(std::path::Path::file_name)
        .ok_or("Runtime fixture version directory missing")?;
    let installed_runtime = library.join("runtime").join(version)
        .join(source_runtime.file_name().ok_or("Runtime fixture file name missing")?);
    let config = library.join("client.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "data_dir":library,"api_base":"https://fixture.invalid","custom":"preserve"
        }))?,
    )?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let invoke = |args: &[&str], expected: i32| -> Result<Value, Box<dyn std::error::Error>> {
        let output = isolated_command(None)?
            .arg("--json")
            .args(args)
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("RSRS_DATA_DIR", &library)
            .env("RSRS_RPC_PORT", port.to_string())
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env_remove("RSRS_RPC_URL")
            .env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART")
            .env_remove("RSRS_RUNTIME_WORKER")
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let value: Value = serde_json::from_str(stdout.trim())?;
        // Headless systems can join successfully without an available OS keyring.
        let keyring_warning = expected == 0
            && args.first() == Some(&"space")
            && args.get(1) == Some(&"join")
            && output.status.code() == Some(2)
            && value["status"] == "warn"
            && value["details"]["keyring"] == false;
        if output.status.code() != Some(expected) && !keyring_warning {
            eprintln!("account-response-evidence {}", json!({
                "stage": "space_command", "reason_code": value["summary"]["reason"],
                "error_type": value["details"]["error_type"]
            }));
            return Err(format!(
                "owned space command {args:?} exited {:?}: {stdout} {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(value)
    };
    let health = |profile: &std::path::Path, stage: &str| -> Result<u64, Box<dyn std::error::Error>> {
        let status = runtime_health(port, "space-profile")
            .map_err(|error| format!("owned space health stage={stage}: {error}"))?;
        let executable = status["exe"].as_str().ok_or("Runtime executable missing")?;
        if status["data_dir"].as_str().map(std::path::Path::new) != Some(profile)
            || std::path::Path::new(executable).canonicalize()? != installed_runtime.canonicalize()?
        {
            return Err(format!("runtime profile readback failed: {status}").into());
        }
        // Exercise request scope without autostart masking a missed restart.
        invoke(&["--client-only", "status"], 0)?;
        status["pid"]
            .as_u64()
            .ok_or_else(|| "runtime PID missing".into())
    };
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        // Start the copied pinned managed installation, not a shared Runtime override.
        invoke(&["runtime", "start"], 0)?;
        invoke(&["status"], 0)?;
        let original_pid = health(&library, "initial-status")?;
        invoke(&["space", "list"], 0)?;
        assert_eq!(
            health(&library, "after-list")?,
            original_pid,
            "listing host profiles must preserve the owned runtime"
        );
        let before = std::fs::read(&config)?;
        for args in [
            vec!["space", "join", "BADCODE"],
            vec!["space", "join", "--code", "BADCODE"],
        ] {
            let rejected = invoke(&args, 2)?;
            assert_eq!(rejected["summary"]["reason"], "invalid_input");
            assert_eq!(rejected["details"]["error_type"], "user");
            assert_eq!(
                health(&library, "after-invalid-invite")?,
                original_pid,
                "bad invite must not stop the current runtime"
            );
            assert_eq!(std::fs::read(&config)?, before);
        }
        for readonly in [false, true] {
            let server =
                tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
            let name = if readonly {
                "joined-readonly"
            } else {
                "joined-writable"
            };
            let user = format!("join-fixture-{}", uuid::Uuid::new_v4());
            let super_password = respire_app::memory::crypto::generate_secret_key();
            let salt = respire_app::memory::crypto::random_hex(16);
            let kek = respire_app::memory::crypto::derive_kek_v4(&super_password, &salt)?;
            let (nonce, wrapped) = respire_app::memory::crypto::wrap_key(&[42_u8; 32], &kek)?;
            let vault = json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
            let member_token = uuid::Uuid::new_v4().to_string();
            let payload = json!({"space":name,"addr":format!("http://{}",server.server_addr()),"user":user,"token":member_token,"super":super_password,"readonly":readonly});
            let code = format!(
                "1mem-invite:{}",
                serde_json::to_vec(&payload)?
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let expected_user = user.clone();
            let expected_authorization = format!("Bearer {member_token}");
            let worker = std::thread::spawn(move || -> Result<(), String> {
                for (path, body) in [("/api/self", json!({"user":expected_user})), ("/api/self/vault", vault)] {
                    let request = server
                        .recv_timeout(Duration::from_secs(20))
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| format!("join never fetched {path}"))?;
                    if request.method() != &tiny_http::Method::Get || request.url() != path
                        || !request.headers().iter().any(|header| {
                            header.field.equiv("Authorization")
                                && header.value.as_str() == expected_authorization.as_str()
                        })
                    {
                        return Err(format!("join did not authenticate its ordered GET {path}"));
                    }
                    request.respond(tiny_http::Response::from_string(body.to_string()))
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            });
            let joined = invoke(&["space", "join", &code], if readonly { 2 } else { 0 });
            let served = worker.join().map_err(|_| "join fixture panicked".to_owned())
                .and_then(|result| result).map_err(|error| format!("join server: {error}"));
            respire_app::keystore::delete_super(&user);
            let joined = match (joined, served) {
                (Ok(joined), Ok(())) => joined,
                (Err(error), Ok(())) => return Err(error),
                (Ok(_), Err(error)) => return Err(error.into()),
                (Err(error), Err(server)) => return Err(format!("{error}; {server}").into()),
            };
            assert_eq!(
                joined["status"],
                if readonly || joined["details"]["keyring"] == false {
                    "warn"
                } else {
                    "ok"
                }
            );
            assert_eq!(joined["details"]["readonly"], readonly);
            assert_eq!(std::fs::read(&config)?, before);
            assert_ne!(health(&library, if readonly { "after-readonly-join" } else { "after-writable-join" })?, original_pid);
            let target = library.join("accounts").join(name);
            let session: Value =
                serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
            assert_eq!(session["user"], user);
            if readonly {
                let agent: Value =
                    serde_json::from_slice(&std::fs::read(target.join("agent.json"))?)?;
                assert_eq!(agent["readonly_team"], true);
            }
            let pid = health(&library, "before-duplicate-join")?;
            invoke(&["space", "join", "--code", &code], 2)?;
            assert_eq!(
                health(&library, "after-duplicate-join")?,
                pid,
                "existing target must fail before stopping the runtime"
            );
        }
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
        let payload = json!({"space":"rejected-join","addr":format!("http://{}",server.server_addr()),"user":"fixture-rejected","token":"revoked-token","super":"synthetic-super"});
        let code = format!(
            "1mem-invite:{}",
            serde_json::to_vec(&payload)?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let worker = std::thread::spawn(move || -> Result<(), String> {
            let request = server
                .recv_timeout(Duration::from_secs(20))
                .map_err(|error| error.to_string())?
                .ok_or("rejected join never fetched the vault")?;
            request
                .respond(tiny_http::Response::empty(401))
                .map_err(|error| error.to_string())
        });
        let rejected = invoke(&["space", "join", &code], 1);
        let served = worker.join().map_err(|_| "rejected join fixture panicked".to_owned())
            .and_then(|result| result).map_err(|error| format!("join server: {error}"));
        let rejected = match (rejected, served) {
            (Ok(rejected), Ok(())) => rejected,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error.into()),
            (Err(error), Err(server)) => return Err(format!("{error}; {server}").into()),
        };
        assert_eq!(rejected["details"]["error_type"], "runtime");
        assert_eq!(std::fs::read(&config)?, before);
        assert!(!library.join("accounts/rejected-join").exists());
        let _before_create_pid = u32::try_from(health(&library, "after-rejected-join")?)?;
        #[cfg(windows)]
        let before_create_birth = respire_spawn::process_birth(_before_create_pid)?
            .ok_or("space create owner birth missing")?;
        let read_optional_session = |path: &std::path::Path| -> std::io::Result<Option<Vec<u8>>> {
            match std::fs::read(path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        };
        let original_session = read_optional_session(&library.join("session.json"))?;
        let joined_writable = library.join("accounts/joined-writable");
        let joined_session = std::fs::read(joined_writable.join("session.json"))?;
        let mut original_config: Value = serde_json::from_slice(&std::fs::read(&config)?)?;
        original_config.as_object_mut().ok_or("space config must be an object")?.remove("data_dir");
        invoke(&["space", "create", "probe"], 0)?;
        let probe = library.join("accounts/probe");
        assert!(probe.join("space_owner.json").is_file());
        let assert_idle_probe = || -> Result<(), Box<dyn std::error::Error>> {
            let mut selected: Value = serde_json::from_slice(&std::fs::read(&config)?)?;
            let directory = selected["data_dir"].as_str().ok_or("space selected directory missing")?;
            if std::path::Path::new(directory).canonicalize()? != probe.canonicalize()? {
                return Err("empty space was not selected".into());
            }
            selected.as_object_mut().ok_or("space config must be an object")?.remove("data_dir");
            if selected != original_config {
                return Err("empty space changed unrelated configuration".into());
            }
            respire_app::login_transaction::verify_auth_identity(
                &library, &probe, &respire_protocol::HostAuthIdentity::Absent,
            )?;
            #[cfg(windows)]
            if respire_spawn::process_birth(_before_create_pid)? == Some(before_create_birth) {
                return Err("empty space retained the previous Runtime owner".into());
            }
            if probe.join("session.json").try_exists()?
                || read_optional_session(&library.join("session.json"))? != original_session
                || std::fs::read(joined_writable.join("session.json"))? != joined_session
                || std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200),
                ).is_ok()
                || library.join("runtime/endpoint.json").try_exists()?
            {
                return Err("empty space did not preserve idle ownership and session boundaries".into());
            }
            Ok(())
        };
        assert_idle_probe()?;
        let before = std::fs::read(&config)?;
        let blocked = invoke(&["space", "remove", "probe"], 2)?;
        assert_eq!(blocked["summary"]["reason"], "invalid_input");
        assert_eq!(std::fs::read(&config)?, before);
        let blocked = invoke(&["space", "remove", "probe", "--yes"], 2)?;
        assert_eq!(blocked["details"]["error_type"], "user");
        assert!(probe.is_dir());
        assert_idle_probe()?;
        invoke(&["space", "use", "joined-writable"], 0)?;
        invoke(&["runtime", "start"], 0)?;
        let resumed_pid = health(&joined_writable, "after-idle-create-return-authenticated")?;
        assert_ne!(resumed_pid, original_pid);
        use sha2::{Digest, Sha256};
        let joined: Value = serde_json::from_slice(&joined_session)?;
        let joined_account = format!("{:x}", Sha256::digest(
            joined["user"].as_str().ok_or("joined account missing")?.as_bytes(),
        ));
        respire_app::login_transaction::verify_auth_identity(&library, &joined_writable,
            &respire_protocol::HostAuthIdentity::Bound {
                account_id: joined_account.clone(),
                session_sha256: format!("{:x}", Sha256::digest(&joined_session)),
            })?;
        let resumed = runtime_health(port, "space-profile")?;
        if resumed["pid"] != resumed_pid || resumed["account_id"] != joined_account {
            return Err("resumed space health differs from its authenticated session".into());
        }
        invoke(&["space", "use", "main"], 0)?;
        health(&library, "after-use-main")?;
        let before = std::fs::read(&config)?;
        invoke(&["space", "use", "missing"], 2)?;
        assert_eq!(std::fs::read(&config)?, before);
        health(&library, "after-use-missing")?;
        invoke(&["space", "remove", "probe", "--yes"], 0)?;
        assert!(!probe.exists());
        health(&library, "after-remove")?;
        let preserved: Value = serde_json::from_slice(&std::fs::read(&config)?)?;
        assert_eq!(preserved["api_base"], "https://fixture.invalid");
        assert_eq!(preserved["custom"], "preserve");
        Ok(())
    })();
    let cleanup = invoke(&["--runtime-internal", "--stop"], 0);
    result?;
    cleanup?;
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    Ok(())
}

fn authorization_failure_evidence(root: &std::path::Path, source: &std::path::Path, output: &Output) {
    use serde_json::{json, Value};

    fn allowed(value: &Value, choices: &[&str]) -> Value {
        match value.as_str().filter(|value| choices.contains(value)) {
            Some(value) => json!(value),
            None if value.is_null() => Value::Null,
            None => json!("redacted"),
        }
    }

    fn operation_id(value: &Value) -> Option<String> {
        let text = value.as_str()?;
        let id = uuid::Uuid::parse_str(text).ok()?;
        (id.get_version_num() == 4 && id.to_string() == text).then(|| id.to_string())
    }

    let response: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    let mut evidence = json!({
        "schema_version": 1, "event": "authorization_failure_evidence",
        "reason_code": allowed(&response["summary"]["reason"], &["account_outcome_unknown", "runtime_error"]),
        "error_type": allowed(&response["details"]["error_type"], &["outcome_unknown", "runtime"]),
        "operation_id": operation_id(&response["details"]["operation_id"]),
        "runtime_log_reason_code": "not_captured_by_fixture",
    });
    let journal = match std::fs::read(root.join(".login-recovery.json")) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) => value,
            Err(_) => {
                evidence["journal_reason_code"] = json!("invalid_json");
                eprintln!("{evidence}");
                return;
            }
        },
        Err(error) => {
            evidence["journal_reason_code"] = json!(match error.kind() {
                std::io::ErrorKind::NotFound => "not_found",
                std::io::ErrorKind::PermissionDenied => "permission_denied",
                _ => "io_error",
            });
            evidence["journal_os_error_code"] = json!(error.raw_os_error());
            eprintln!("{evidence}");
            return;
        }
    };
    let active = &journal["active"];
    let id = operation_id(&response["details"]["operation_id"]);
    evidence["operation_id"] = json!(id);
    evidence["journal_reason_code"] = json!("read");
    evidence["journal_schema_v2"] = json!(journal["schema_version"] == 2);
    evidence["active_present"] = json!(active.is_object());
    evidence["active_matches_operation"] = json!(id.is_some() && operation_id(&active["operation_id"]) == id);
    let records: Vec<&Value> = journal["operations"].as_array().into_iter().flatten()
        .filter(|record| id.is_some() && operation_id(&record["operation_id"]) == id).collect();
    evidence["matching_records"] = json!(records.len());
    if let [record] = records.as_slice() {
        let account = &record["account"];
        let login = &account["login"];
        evidence["phase"] = allowed(&record["phase"], &["admitted", "login_input", "remote_pending",
            "remote_unknown", "authorized", "prepared", "awaiting_verification", "rolling_back", "committed", "rolled_back"]);
        evidence["backend"] = allowed(&record["backend"], &["native", "secret_service", "kernel"]);
        evidence["root_matches_fixture"] = json!(root.canonicalize().ok().is_some_and(|path|
            record["root"].as_str().map(std::path::Path::new) == Some(path.as_path())));
        evidence["source_matches_fixture"] = json!(source.canonicalize().ok().is_some_and(|path|
            record["profile"].as_str().map(std::path::Path::new) == Some(path.as_path())));
        for field in ["candidate", "candidate_sha256"] {
            evidence[format!("{field}_present")] = json!(!record[field].is_null());
        }
        for field in ["authorization", "vault", "target"] {
            evidence[format!("{field}_present")] = json!(!account[field].is_null());
        }
        for field in ["published_vault", "vault_pending"] {
            evidence[field] = json!(account[field].as_bool());
        }
        for field in ["import_started", "sync_started", "publication_pending", "publication_done", "vault_done", "password_done"] {
            evidence[field] = json!(login[field].as_bool());
        }
        evidence["owns_config"] = json!(active["owns_config"].as_bool());
        for field in ["backends", "pass_backends", "totp_backends"] {
            evidence[field] = json!(active[field].as_array().map(|values| values.iter()
                .map(|value| allowed(value, &["native", "secret_service", "kernel"])).collect::<Vec<_>>()));
        }
    }
    // Never serialize journal material, response text, credentials or arbitrary errors.
    eprintln!("{evidence}");
}

/// Exercise the shipped client against an isolated authorization server, including
/// failures before commit and the host/runtime account verification after commit.
#[test]
fn authorization_preserves_and_commits_profiles() -> Result<(), Box<dyn std::error::Error>> {
    const AUTHORIZATION_TOKEN: &str = "synthetic-grant-token";
    use respire_app::memory::{crypto, SessionKeys};
    use respire_app::transport::{local::LocalStore, MemoryTransport};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    let models = std::path::PathBuf::from(
        std::env::var_os("RSRS_CORE_TEST_MODEL_DIR")
            .ok_or("supply RSRS_CORE_TEST_MODEL_DIR with the verified real CPU model fixture")?,
    )
    .canonicalize()?;
    for file in [
        "tokenizer.json",
        "onnx/model_quantized.onnx",
        "onnx/model_quantized.cpu-v1.ort",
    ] {
        if !models.join(file).is_file() {
            return Err(format!("model fixture missing {file} at {}", models.display()).into());
        }
    }
    let home = tempfile::tempdir()?;
    let root = home.path().join(".rsrs");
    let original = root.join("accounts/original");
    std::fs::create_dir_all(&original)?;
    if support::legacy_cli()?.is_some() {
        support::stage_legacy_cli(&root)?;
    } else {
        support::install_runtime_fixture(&root)?;
    }
    let session_bytes = br#"{"user":"original","addr":"https://previous.invalid"}"#;
    std::fs::write(original.join("session.json"), session_bytes)?;
    let config_bytes = serde_json::to_vec(
        &json!({"data_dir":original,"api_base":"https://previous.invalid","addr":"http://config.invalid","custom":"preserve"}),
    )?;
    std::fs::write(root.join("client.json"), &config_bytes)?;
    let super_password = crypto::generate_secret_key();
    let salt = crypto::random_hex(16);
    let urk = [42_u8; 32];
    let (nonce, wrapped) = crypto::wrap_key(&urk, &crypto::derive_kek_v4(&super_password, &salt)?)?;
    let cloud = Arc::new(Mutex::new(
        json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce}),
    ));
    let mode = Arc::new(Mutex::new("authorized".to_owned()));
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let remote_blobs = Arc::new(Mutex::new(Vec::<Value>::new()));
    let server =
        Arc::new(tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?);
    let addr = format!("http://{}", server.server_addr());
    let runtime_port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let running = Arc::new(AtomicBool::new(true));
    let worker_server = server.clone();
    let worker_running = running.clone();
    let worker_cloud = cloud.clone();
    let worker_mode = mode.clone();
    let worker_requests = requests.clone();
    let worker_addr = addr.clone();
    let initial_auth_salt = crypto::derive_legacy_auth_salt("authorized")?;
    let current_auth_salt = crypto::derive_auth_salt("authorized")?;
    let authentication_salt = Arc::new(Mutex::new(initial_auth_salt));
    let worker_authentication_salt = authentication_salt.clone();
    let worker_blobs = remote_blobs.clone();
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let mut sync_pulls = 0;
        while worker_running.load(Ordering::SeqCst) {
            let Some(mut request) = worker_server
                .recv_timeout(Duration::from_millis(50))
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            let path = request.url().to_owned();
            worker_requests
                .lock()
                .map_err(|error| error.to_string())?
                .push(path.clone());
            let mode = worker_mode
                .lock()
                .map_err(|error| error.to_string())?
                .clone();
            let mut status = 200;
            let reply = match path.as_str() {
                path if path.starts_with("/auth/salt?user=authorized") => {
                    json!({"salt":worker_authentication_salt.lock().map_err(|error| error.to_string())?.clone()})
                }
                "/api/self/password" => {
                    if !request.headers().iter().any(|header| {
                        header.field.equiv("Authorization")
                            && header.value.as_str() == format!("Bearer {AUTHORIZATION_TOKEN}")
                    }) {
                        return Err("password namespace update missing authorization".to_owned());
                    }
                    let value: Value = serde_json::from_reader(request.as_reader())
                        .map_err(|error| error.to_string())?;
                    if value["salt"] != current_auth_salt
                        || value["pass_hash"]
                            != crypto::derive_pass_hash("fixture-password", &current_auth_salt)
                                .map_err(|error| error.to_string())?
                    {
                        return Err("migration changed the original login password".to_owned());
                    }
                    *worker_authentication_salt
                        .lock()
                        .map_err(|error| error.to_string())? = current_auth_salt.clone();
                    json!({"ok":true})
                }
                "/oauth/device/code" => {
                    json!({"device_code":"synthetic-device-code","user_code":"ABCDEF123456","expires_in":60,"interval":1,"verification_uri_complete":format!("{worker_addr}/#/authorize?code=ABCDEF123456")})
                }
                "/oauth/token" if mode != "authorized" && mode != "sync_unavailable" => {
                    status = 400;
                    json!({"error":mode})
                }
                "/oauth/token" => {
                    json!({"access_token":AUTHORIZATION_TOKEN,"token_type":"Bearer","user":"authorized","session_id":"fixture"})
                }
                "/login" if mode == "totp" => {
                    json!({"totp_required":true,"ticket":"synthetic-ticket"})
                }
                "/login" => {
                    json!({"token":AUTHORIZATION_TOKEN,"user":"authorized","session_id":"fixture"})
                }
                "/api/self/vault" => {
                    if !request.headers().iter().any(|header| {
                        header.field.equiv("Authorization")
                            && header.value.as_str() == format!("Bearer {AUTHORIZATION_TOKEN}")
                    }) {
                        return Err("vault request missing authorization".to_owned());
                    }
                    if request.method() == &tiny_http::Method::Post {
                        let value: Value = serde_json::from_reader(request.as_reader())
                            .map_err(|error| error.to_string())?;
                        *worker_cloud.lock().map_err(|error| error.to_string())? = value;
                        json!({"ok":true})
                    } else {
                        worker_cloud
                            .lock()
                            .map_err(|error| error.to_string())?
                            .clone()
                    }
                }
                "/sync/capabilities" => {
                    status = if mode == "sync_unavailable" { 503 } else { 404 };
                    json!({"error":"legacy sync fixture"})
                }
                path if path == "/pull" || path.starts_with("/pull?") => {
                    sync_pulls += 1;
                    if sync_pulls == 2 {
                        status = 503;
                        json!({"error":"synthetic outage after preflight"})
                    } else {
                        let blobs = worker_blobs
                            .lock()
                            .map_err(|error| error.to_string())?
                            .clone();
                        let alive = blobs.iter().filter(|blob| blob["deleted"] != true).count();
                        json!({"cursor":blobs.len(),"total":blobs.len(),"alive":alive,"blobs":blobs})
                    }
                }
                "/push/batch" => {
                    let value: Value = serde_json::from_reader(request.as_reader())
                        .map_err(|error| error.to_string())?;
                    let items = value["items"].as_array().ok_or("missing push items")?;
                    let mut blobs = worker_blobs.lock().map_err(|error| error.to_string())?;
                    for item in items {
                        let mut blob = item.clone();
                        blob["user"] = json!("authorized");
                        if let Some(index) = blobs.iter().position(|old| old["id"] == blob["id"]) {
                            blobs[index] = blob;
                        } else {
                            blobs.push(blob);
                        }
                    }
                    json!({"replaced":vec![true;items.len()]})
                }
                _ => return Err(format!("unexpected authorization request: {path}")),
            };
            request
                .respond(
                    tiny_http::Response::from_string(reply.to_string()).with_status_code(status),
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    let use_checkpointed_credentials = std::cell::Cell::new(false);
    let migration_super = std::cell::Cell::new(None::<&str>);
    let source_alias = format!("login-{}", uuid::Uuid::new_v4().simple());
    let mut source_backends = Vec::new();
    let execute = |args: &[&str]| -> std::io::Result<Output> {
        let mut command = isolated_command(Some(&models))?;
        // Login uses its arguments; checkpointed source/target sessions use their own credentials.
        if args.contains(&"login") || use_checkpointed_credentials.get() {
            command.env_remove("RSRS_SUPER");
        } else {
            command.env("RSRS_SUPER", migration_super.get().unwrap_or(&super_password));
        }
        let output = command
            .args(args)
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("RSRS_DATA_DIR", &root)
            .env("RSRS_ADDR", "http://environment.invalid")
            .env("RSRS_RPC_PORT", runtime_port.to_string())
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART")
            .env_remove("RSRS_RUNTIME_WORKER")
            .env_remove("RSRS_RPC_TOKEN")
            .env_remove("RSRS_LANG")
            .output()?;
        // The test harness retains these synthetic replies when any later assertion fails.
        eprintln!(
            "authorization fixture: status={}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    };
    let recover_account = |output: &Output, required: Option<&str>| -> Result<(), Box<dyn std::error::Error>> {
        use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult};
        assert!(!output.status.success());
        let failure: Value = serde_json::from_slice(&output.stdout)?;
        eprintln!("account-response-evidence {}", serde_json::json!({
            "stage": if required.is_some() { "required_input" } else { "wrong_super" },
            "reason_code": failure["summary"]["reason"],
            "error_type": failure["details"]["error_type"]
        }));
        let operation = if required.is_some() {
            assert_eq!(failure["summary"]["reason"], "runtime_error");
            failure["errors"].as_array().ok_or("login errors missing")?
                .iter().filter_map(Value::as_str)
                .find_map(|error| error.split_once("login input pending; operation_id=")
                    .and_then(|(_, tail)| tail.split_whitespace().next()))
                .ok_or("login did not retain an AwaitingInput operation")?
        } else {
            assert_eq!(failure["summary"]["reason"], "account_outcome_unknown");
            failure["details"]["operation_id"].as_str().ok_or("original account operation missing")?
        };
        let id = uuid::Uuid::parse_str(operation)?;
        assert_eq!(id.get_version_num(), 4);
        assert_eq!(id.to_string(), operation);
        let source = original.canonicalize()?;
        let source_arg = source.to_str().ok_or("source profile is not UTF-8")?;
        let before = requests.lock().map_err(|error| error.to_string())?.clone();
        // Observe the original O without resending login or supplying new factors.
        let queried = execute(&["--json", "runtime", "account-result", "--operation-id",
            operation, "--source-profile", source_arg])?;
        let envelope: Value = serde_json::from_slice(&queried.stdout)?;
        if let Some(required) = required {
            assert_eq!(envelope["command"], "auth-account");
            assert_eq!(envelope["status"], "pending");
            let receipt: HostAuthAccountResult = serde_json::from_value(envelope["summary"].clone())?;
            assert_eq!(receipt.operation_id, operation);
            assert_eq!(receipt.source_profile, source);
            assert_eq!(receipt.outcome, HostAuthAccountOutcome::AwaitingInput);
            assert_eq!(receipt.login.ok_or("login input status missing")?.required_inputs, [required]);
        } else {
            assert!(!queried.status.success());
            for response in [&failure, &envelope] {
                assert_eq!(response["summary"]["reason"], "account_outcome_unknown");
                assert_eq!(response["details"]["error_type"], "outcome_unknown");
                assert_eq!(response["details"]["operation_id"], operation);
                assert_eq!(response["details"]["source_profile"], source_arg);
                assert_eq!(response["details"]["register"], false);
                assert_eq!(response["details"]["replayed"], false);
                assert_eq!(response["details"]["result_command"], "runtime account-result");
            }
        }
        // Explicit compensation, not a login retry: Runtime rejects RemotePending,
        // RemoteUnknown, committed operations and pending/published remote effects.
        let rolled_back = execute(&["--json", "runtime", "account-rollback", "--operation-id",
            operation, "--source-profile", source_arg, "--confirm"])?;
        let envelope: Value = serde_json::from_slice(&rolled_back.stdout)?;
        assert_eq!(envelope["command"], "auth-account");
        let receipt: HostAuthAccountResult = serde_json::from_value(envelope["summary"].clone())?;
        assert_eq!(receipt.operation_id, operation);
        assert_eq!(receipt.source_profile, source);
        assert_eq!(receipt.outcome, HostAuthAccountOutcome::RolledBack);
        assert_eq!(*requests.lock().map_err(|error| error.to_string())?, before,
            "original-operation recovery repeated authorization or vault requests");
        assert_eq!(std::fs::read(root.join("client.json"))?, config_bytes);
        assert_eq!(std::fs::read(original.join("session.json"))?, session_bytes);
        // Reconnected rollback deliberately retains Paused; restart is explicit recovery.
        let restarted = execute(&["--json", "runtime", "restart"])?;
        assert!(restarted.status.success(), "original account did not resume after rollback");
        let envelope: Value = serde_json::from_slice(&restarted.stdout)?;
        assert_eq!(envelope["summary"]["state"], "ready");
        assert_eq!(std::fs::canonicalize(envelope["summary"]["data_dir"].as_str()
            .ok_or("restarted profile missing")?)?, source);
        assert_eq!(std::fs::read(root.join("client.json"))?, config_bytes);
        assert_eq!(std::fs::read(original.join("session.json"))?, session_bytes);
        Ok(())
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), Box<dyn std::error::Error>> {
        if support::legacy_cli()?.is_some() {
            let guard=super::snapshot_lifecycle::Fixture::new()?;
            let protected=guard.protected_state()?;
            *mode.lock().map_err(|error|error.to_string())?="access_denied".to_owned();
            let denied=execute(&["--json","login","--oauth","--addr",&addr,
                "--dashboard",&addr,"--no-open"])?;
            assert!(!denied.status.success());
            assert!(std::fs::read(root.join("client.json"))?==config_bytes);
            assert!(std::fs::read(original.join("session.json"))?==session_bytes);
            assert!(!requests.lock().map_err(|error|error.to_string())?.is_empty());
            *mode.lock().map_err(|error|error.to_string())?="authorized".to_owned();
            let wrong=crypto::generate_secret_key();
            let rejected=execute(&["--json","login","--oauth","--addr",&addr,
                "--dashboard",&addr,"--no-open","--super",&wrong])?;
            assert!(!rejected.status.success());
            assert!(std::fs::read(root.join("client.json"))?==config_bytes);
            assert!(std::fs::read(original.join("session.json"))?==session_bytes);
            *mode.lock().map_err(|error|error.to_string())?="totp".to_owned();
            let totp=execute(&["--json","login","--interactive","--addr",&addr,
                "--user","authorized","--pass=fixture-password","--super",&super_password])?;
            assert!(!totp.status.success());
            assert!(std::fs::read(root.join("client.json"))?==config_bytes);
            assert!(std::fs::read(original.join("session.json"))?==session_bytes);
            *mode.lock().map_err(|error|error.to_string())?="authorized".to_owned();
            let login=execute(&["--json","login","--oauth","--addr",&addr,
                "--dashboard",&addr,"--no-open","--super",&super_password])?;
            assert!(login.status.success(),"old authorized login failed");
            let selected:Value=serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
            let target=std::path::PathBuf::from(selected["data_dir"].as_str().ok_or("old committed profile missing")?);
            assert!(target.starts_with(&root));
            assert_eq!(selected["custom"],"preserve");
            assert_eq!(selected["api_base"],"https://previous.invalid");
            let saved:Value=serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
            assert_eq!(saved["user"],"authorized");
            assert!(saved.get("super").is_none()&&saved.get("pass").is_none());
            let owner=support::legacy_owner(&root,&target,runtime_port)?;
            assert!(respire_app::lock::LibraryLock::acquire(&target,Duration::from_millis(80)).is_err());
            let written=execute(&["--json","remember","old authorized private body","--force"])?;
            assert!(written.status.success());
            let written:Value=serde_json::from_slice(&written.stdout)?;
            let id=written["summary"]["id"].as_str().ok_or("old authorized memory ID missing")?;
            let shown=execute(&["--json","show",id])?;
            assert!(shown.status.success());
            let shown:Value=serde_json::from_slice(&shown.stdout)?;
            assert_eq!(shown["details"]["entry"]["content"],"old authorized private body");
            let retained=serde_json::to_value(LocalStore::open(&target.join("rsrs.db"))?.all(true)?)?;
            let retained_config=std::fs::read(root.join("client.json"))?;
            assert!(!execute(&["--json","account","use","not-an-existing-account"])? .status.success());
            assert!(std::fs::read(root.join("client.json"))?==retained_config);
            assert_eq!(serde_json::to_value(LocalStore::open(&target.join("rsrs.db"))?.all(true)?)?,retained);
            support::legacy_owner(&root,&target,runtime_port)?;
            let pid=u32::try_from(owner["pid"].as_u64().ok_or("old auth PID missing")?)?;
            // Failure recovery may legitimately replace this old owner. Reverify
            // the current PID instead of sending any signal to the saved PID.
            let current=support::legacy_owner(&root,&target,runtime_port)?;
            let current_pid=u32::try_from(current["pid"].as_u64().ok_or("old auth current PID missing")?)?;
            assert!(execute(&["--runtime-internal","--stop"])?.status.success());
            support::legacy_drained(&target,runtime_port,current_pid)?;
            assert!(!respire_commands::net_rpc::process_is_running(pid)?);
            assert!(execute(&["--json","logout","--full"])?.status.success());
            assert!(!target.join("session.json").exists());
            let recovered=execute(&["--json","login","--oauth","--addr",&addr,
                "--dashboard",&addr,"--no-open","--super",&super_password])?;
            assert!(recovered.status.success());
            let selected:Value=serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
            assert_eq!(selected["data_dir"].as_str(),target.to_str());
            assert_eq!(serde_json::to_value(LocalStore::open(&target.join("rsrs.db"))?.all(true)?)?,retained);
            support::legacy_owner(&root,&target,runtime_port)?;

            // Reuse the original mock vault and real v2 namespace conversion.
            // New account-result/rollback receipts are deliberately not invoked.
            assert!(execute(&["--runtime-internal","--stop"])?.status.success());
            assert!(execute(&["--json","logout","--full"])?.status.success());
            let legacy_super="synthetic-legacy-passphrase";
            migration_super.set(Some(legacy_super));
            let salt=crypto::random_hex(16);
            let (nonce,wrapped)=crypto::wrap_key(&urk,&crypto::derive_super_kek(legacy_super,&salt)?)?;
            let mut legacy=json!({"user":"authorized","addr":addr,"vault_version":2,
                "kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
            *cloud.lock().map_err(|error|error.to_string())?=json!({"version":2,
                "kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
            std::fs::write(target.join("session.json"),serde_json::to_vec(&legacy)?)?;
            let config=std::fs::read(root.join("client.json"))?;
            let incomplete=execute(&["--json","migrate","--vault","--pass=fixture-password","--super",legacy_super])?;
            assert!(!incomplete.status.success());
            assert!(std::fs::read(target.join("session.json"))?==serde_json::to_vec(&legacy)?);
            assert!(std::fs::read(root.join("client.json"))?==config);
            legacy["crypto_namespace"]=json!(crypto::RSRS_PREFIX);
            legacy["wrapped_urk"]=json!(format!("{}{wrapped}",crypto::RSRS_PREFIX));
            std::fs::write(target.join("session.json"),serde_json::to_vec(&legacy)?)?;
            let migrated=execute(&["--json","migrate","--vault","--pass=fixture-password",
                "--super",legacy_super,"--new-super",legacy_super])?;
            assert!(migrated.status.success());
            let current=cloud.lock().map_err(|error|error.to_string())?.clone();
            let keys=SessionKeys::unlock_super(legacy_super,current["kdf_salt"].as_str().ok_or("old migrated salt missing")?,
                current["wrapped_urk"].as_str().ok_or("old migrated wrap missing")?,
                current["urk_nonce"].as_str().ok_or("old migrated nonce missing")?)?;
            assert!(keys.urk==urk);
            assert_eq!(current["version"],2);
            assert!(current["wrapped_urk"].as_str().is_some_and(|value|value.starts_with(crypto::RSRS_PREFIX)));
            assert!(std::fs::read(original.join("session.json"))?==session_bytes);
            assert_eq!(guard.protected_state()?,protected);
            assert!(execute(&["--json","logout","--full"])?.status.success());
            if respire_commands::net_rpc::port_is_open_on(runtime_port) {
                let selected:Value=serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
                let profile=selected["data_dir"].as_str().map(std::path::PathBuf::from)
                    .map_or_else(||root.clone(),|path|path);
                let owner=support::legacy_owner(&root,&profile,runtime_port)?;
                let pid=u32::try_from(owner["pid"].as_u64().ok_or("old final auth PID missing")?)?;
                assert!(execute(&["--runtime-internal","--stop"])?.status.success());
                support::legacy_drained(&profile,runtime_port,pid)?;
            }
            support::legacy_receipt("account::authorization_preserves_and_commits_profiles","old_embedded")?;
            return Ok(());
        }
        let stale_session = br#"{"user":"original","addr":"http://legacy.invalid"}"#;
        std::fs::write(original.join("session.json"), stale_session)?;
        for args in [
            vec!["--json", "login", "--oauth", "--no-open"],
            vec![
                "--json",
                "login",
                "--interactive",
                "--user",
                "fixture",
                "--pass",
                "fixture-password",
            ],
            vec![
                "--json",
                "login",
                "--oauth",
                "--addr",
                "http://explicit.invalid",
                "--no-open",
            ],
            vec![
                "--json",
                "login",
                "--oauth",
                "--addr",
                &addr,
                "--dashboard",
                "http://name:fixture-secret@dashboard.invalid/?fixture-secret",
                "--no-open",
            ],
        ] {
            let output = execute(&args)?;
            assert_eq!(output.status.code(), Some(1));
            let reply: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(reply["summary"]["reason"], "runtime_error");
            let text = reply.to_string();
            assert!(
                text.contains("login requires HTTPS, except loopback fixtures"),
                "{text}"
            );
            let source = if args.contains(&"--dashboard") {
                "OAuth dashboard from --dashboard"
            } else if args.contains(&"--addr") {
                "login server from --addr"
            } else {
                "stored session.json addr"
            };
            assert!(text.contains(source), "{text}");
            assert!(!text.contains("fixture-secret"), "{text}");
            assert!(requests
                .lock()
                .map_err(|error| error.to_string())?
                .is_empty());
            assert_eq!(std::fs::read(root.join("client.json"))?, config_bytes);
            assert_eq!(std::fs::read(original.join("session.json"))?, stale_session);
        }
        for stored in [
            json!({"user":"original"}),
            json!({"user":"original","addr":""}),
            json!({"user":"original","addr":" \t"}),
            json!({"user":"original","addr":"https://self-hosted.invalid"}),
        ] {
            let bytes = serde_json::to_vec(&stored)?;
            std::fs::write(original.join("session.json"), &bytes)?;
            // Dashboard validation stops before networking, proving login origin
            // resolution succeeded without contacting the official/custom server.
            let output = execute(&[
                "--json",
                "login",
                "--oauth",
                "--dashboard",
                "http://dashboard.invalid",
                "--no-open",
            ])?;
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stdout)
                .contains("OAuth dashboard from --dashboard"));
            assert!(requests
                .lock()
                .map_err(|error| error.to_string())?
                .is_empty());
            assert_eq!(std::fs::read(original.join("session.json"))?, bytes);
            assert_eq!(std::fs::read(root.join("client.json"))?, config_bytes);
        }
        std::fs::write(original.join("session.json"), stale_session)?;
        // An explicit loopback origin can override a stale server without changing
        // the account when authorization is denied. Other address settings are ignored.
        *mode.lock().map_err(|error| error.to_string())? = "access_denied".to_owned();
        let output = execute(&[
            "--json",
            "login",
            "--oauth",
            "--addr",
            &addr,
            "--dashboard",
            &addr,
            "--no-open",
        ])?;
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("browser authorization was denied")
        );
        assert_eq!(
            *requests.lock().map_err(|error| error.to_string())?,
            vec!["/oauth/device/code", "/oauth/token"]
        );
        assert_eq!(std::fs::read(root.join("client.json"))?, config_bytes);
        assert_eq!(std::fs::read(original.join("session.json"))?, stale_session);
        // The stored loopback fixture also works without --addr.
        let loopback_session = serde_json::to_vec(&json!({"user":"original", "addr":addr}))?;
        std::fs::write(original.join("session.json"), &loopback_session)?;
        let output = execute(&[
            "--json",
            "login",
            "--oauth",
            "--dashboard",
            &addr,
            "--no-open",
        ])?;
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("browser authorization was denied")
        );
        assert_eq!(
            std::fs::read(original.join("session.json"))?,
            loopback_session
        );
        assert_eq!(std::fs::read(root.join("client.json"))?, config_bytes);
        std::fs::write(original.join("session.json"), session_bytes)?;
        for reply in [
            "access_denied",
            "expired_token",
            "invalid_grant",
            "unexpected_error",
        ] {
            *mode.lock().map_err(|error| error.to_string())? = reply.to_owned();
            let output = execute(&[
                "login",
                "--oauth",
                "--addr",
                &addr,
                "--dashboard",
                &addr,
                "--no-open",
                "--super",
                &super_password,
            ])?;
            if output.status.success() {
                return Err(format!("OAuth failure {reply} was accepted").into());
            }
            if std::fs::read(root.join("client.json"))? != config_bytes
                || std::fs::read(original.join("session.json"))? != session_bytes
            {
                return Err("rejected authorization changed the original account".into());
            }
        }
        *mode.lock().map_err(|error| error.to_string())? = "authorized".to_owned();
        for args in [
            vec![
                "--json",
                "login",
                "--oauth",
                "--addr",
                &addr,
                "--dashboard",
                &addr,
                "--no-open",
                // Explicit empty input prevents fallback to an old target keyring entry.
                "--super=",
            ],
            vec![
                "--json",
                "login",
                "--interactive",
                "--addr",
                &addr,
                "--user",
                "authorized",
                "--pass=fixture-password",
                "--super=wrong-super",
            ],
        ] {
            let output = execute(&args)?;
            if output.status.success() {
                return Err("missing or incorrect super password was accepted".into());
            }
            if std::fs::read(root.join("client.json"))? != config_bytes
                || std::fs::read(original.join("session.json"))? != session_bytes
            {
                return Err("failed vault verification changed the original account".into());
            }
            if args.contains(&"--super=") {
                recover_account(&output, Some("super_password"))?;
            } else {
                recover_account(&output, None)?;
            }
        }
        *mode.lock().map_err(|error| error.to_string())? = "totp".to_owned();
        let totp = execute(&[
            "--json",
            "login",
            "--interactive",
            "--addr",
            &addr,
            "--user",
            "authorized",
            "--pass=fixture-password",
            "--super",
            &super_password,
        ])?;
        if totp.status.success() || std::fs::read(root.join("client.json"))? != config_bytes {
            return Err("headless TOTP changed the account before authorization".into());
        }
        recover_account(&totp, Some("totp"))?;
        *mode.lock().map_err(|error| error.to_string())? = "authorized".to_owned();
        let before_login: Value = serde_json::from_slice(
            &std::fs::read(root.join(".login-recovery.json"))?,
        )?;
        let prior_operations: Vec<String> = before_login["operations"]
            .as_array().ok_or("account receipt history missing before login")?
            .iter().map(|record| record["operation_id"].as_str()
                .map(str::to_owned).ok_or("prior account operation ID missing"))
            .collect::<Result<_, _>>()?;
        let authorized = execute(&[
            "--json",
            "login",
            "--oauth",
            "--addr",
            &addr,
            "--dashboard",
            &addr,
            "--no-open",
            "--super",
            &super_password,
        ])?;
        if !authorized.status.success() {
            authorization_failure_evidence(&root, &original, &authorized);
            return Err(format!(
                "authorized OAuth login failed: {} {}",
                String::from_utf8_lossy(&authorized.stdout),
                String::from_utf8_lossy(&authorized.stderr)
            )
            .into());
        }
        let envelope: Value = serde_json::from_slice(&authorized.stdout)?;
        if envelope["status"] != "ok" || envelope["summary"]["user"] != "authorized" {
            return Err("OAuth login did not report the verified account".into());
        }
        let selected: Value = serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
        let target = std::path::PathBuf::from(
            selected["data_dir"]
                .as_str()
                .ok_or("selected directory missing")?,
        );
        if !target.starts_with(&root)
            || selected["custom"] != "preserve"
            || selected["api_base"] != "https://previous.invalid"
        {
            return Err("login changed unrelated API preferences or escaped the fixture".into());
        }
        let saved_bytes = std::fs::read(target.join("session.json"))?;
        let saved: Value = serde_json::from_slice(&saved_bytes)?;
        if saved["user"] != "authorized"
            || saved.get("super").is_some()
            || saved.get("pass").is_some()
        {
            return Err("headless login persisted an unexpected credential".into());
        }
        // Private auth retains a credential reference bound to this new committed receipt.
        // Compare private bytes in memory; failures must not print credential material.
        use sha2::{Digest, Sha256};
        let journal: Value = serde_json::from_slice(
            &std::fs::read(root.join(".login-recovery.json"))?,
        )?;
        let new_operations: Vec<_> = journal["operations"].as_array()
            .ok_or("account receipt history missing after login")?
            .iter().filter(|record| record["operation_id"].as_str()
                .is_some_and(|id| !prior_operations.iter().any(|prior| prior == id)))
            .collect();
        if journal["schema_version"] != 2 || !journal["active"].is_null()
            || new_operations.len() != 1 {
            return Err("login did not retain exactly one completed new operation".into());
        }
        let record = new_operations[0];
        let operation_id = record["operation_id"].as_str().ok_or("login operation ID missing")?;
        let parsed = uuid::Uuid::parse_str(operation_id)?;
        let alias = record["alias"].as_str().filter(|value| !value.is_empty())
            .ok_or("login credential reference missing")?;
        let backend = record["backend"].as_str().ok_or("login credential backend missing")?;
        let candidate: Vec<u8> = serde_json::from_value(record["candidate"].clone())?;
        let session_sha256 = format!("{:x}", Sha256::digest(&saved_bytes));
        if parsed.get_version_num() != 4 || parsed.to_string() != operation_id
            || record["idempotency_key"] != operation_id || record["phase"] != "committed"
            || record["account"]["register"] != false
            || record["account"]["user"] != "authorized" || record["account"]["addr"] != addr
            || std::path::Path::new(record["root"].as_str().ok_or("login receipt root missing")?).canonicalize()? != root.canonicalize()?
            || std::path::Path::new(record["profile"].as_str().ok_or("login receipt source missing")?).canonicalize()? != original.canonicalize()?
            || std::path::Path::new(record["account"]["target"].as_str().ok_or("login receipt target missing")?).canonicalize()? != target.canonicalize()?
            || saved["keyring_account"] != alias || saved["keyring_backend"] != backend
            || !matches!(backend, "native" | "secret_service")
            || candidate != saved_bytes || record["candidate_sha256"] != session_sha256
        {
            return Err("login session does not match its committed credential receipt".into());
        }
        let stopped = execute(&["--runtime-internal", "--stop"])?;
        if !stopped.status.success() {
            return Err("could not stop the isolated OAuth runtime".into());
        }

        // Seed an encrypted cloud-only record, absent from this target's local store.
        assert!(execute(&[
            "--json",
            "remember",
            "Synthetic cloud peer body",
            "--title",
            "Cloud peer",
            "--importance",
            "important",
            "--force"
        ])?
        .status
        .success());
        let peer_store = LocalStore::open(&target.join("rsrs.db"))?;
        let peers = peer_store.all(false)?;
        let peer = peers.first().ok_or("cloud fixture row missing")?;
        remote_blobs
            .lock()
            .map_err(|error| error.to_string())?
            .push(serde_json::to_value(peer)?);
        drop(peer_store);
        assert!(execute(&["--runtime-internal", "--stop"])?.status.success());
        for name in ["rsrs.db", "rsrs.db-wal", "rsrs.db-shm"] {
            let path = target.join(name);
            if path.is_file() {
                std::fs::remove_file(path)?;
            }
        }

        // The source owns its recovery code; target --super is never a source factor.
        let source_urk = [43_u8; 32];
        let source_secret = crypto::generate_secret_key();
        if source_secret == super_password {
            return Err("source and target fixture credentials must be distinct".into());
        }
        let source_backend = respire_app::keystore::import_credential_checkpoint(
            &source_alias, "super", &source_secret, |backend| {
                anyhow::ensure!(matches!(backend, "native" | "secret_service"),
                    "source fixture requires persistent credentials");
                source_backends.push(backend.to_owned());
                Ok(())
            },
        )?;
        let checkpoint = respire_app::keystore::read_imported(
            &source_alias, "super", source_backend,
        )?;
        if checkpoint != source_secret {
            return Err("source credential checkpoint readback mismatch".into());
        }
        let source_salt = crypto::random_hex(16);
        let (source_nonce, source_wrap) = crypto::wrap_key(
            &source_urk,
            &crypto::derive_kek_v4(&source_secret, &source_salt)?,
        )?;
        let source_session = serde_json::to_vec(
            &json!({"user":"original","addr":"https://previous.invalid",
            "keyring_account":source_alias,"keyring_backend":source_backend,
            "vault_version":4,"kdf_salt":source_salt,"wrapped_urk":source_wrap,"urk_nonce":source_nonce}),
        )?;
        std::fs::write(original.join("session.json"), &source_session)?;
        use_checkpointed_credentials.set(true);
        let selected = execute(&["--json", "account", "use", "original"])?;
        assert!(
            selected.status.success(),
            "{}",
            String::from_utf8_lossy(&selected.stdout)
        );
        let created = execute(&[
            "--json",
            "remember",
            "Synthetic cross-server transfer body",
            "--title",
            "Transfer fixture",
            "--importance",
            "important",
            "--force",
        ])?;
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stdout)
        );
        assert!(execute(&[
            "--json",
            "remember",
            "Synthetic cloud peer body",
            "--title",
            "Source peer",
            "--importance",
            "important",
            "--force"
        ])?
        .status
        .success());
        let transfer = [
            "--json",
            "login",
            "--oauth",
            "--addr",
            &addr,
            "--dashboard",
            &addr,
            "--no-open",
            "--super",
            &super_password,
            "--migrate-local",
        ];
        let source_config = std::fs::read(root.join("client.json"))?;
        let target_session = std::fs::read(target.join("session.json"))?;
        let before_import: Value = serde_json::from_slice(
            &std::fs::read(root.join(".login-recovery.json"))?,
        )?;
        let prior_imports = before_import["operations"].as_array()
            .ok_or("account history missing before import")?;
        let target_empty = || -> Result<bool, Box<dyn std::error::Error>> {
            let path = target.join("rsrs.db");
            if !path.try_exists()? { return Ok(true); }
            let database = rusqlite::Connection::open_with_flags(path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW)?;
            Ok(database.query_row("SELECT NOT EXISTS(SELECT 1 FROM memories)
                AND NOT EXISTS(SELECT 1 FROM sync_outbox)
                AND NOT EXISTS(SELECT 1 FROM sync_resolution_outbox)", [], |row| row.get(0))?)
        };
        if before_import["schema_version"] != 2 || !before_import["active"].is_null()
            || !target_empty()? {
            return Err("import rejection fixture requires its original empty target/outbox".into());
        }
        *mode.lock().map_err(|error| error.to_string())? = "sync_unavailable".to_owned();
        let rejected = execute(&transfer)?;
        assert_eq!(rejected.status.code(), Some(1));
        let after_import: Value = serde_json::from_slice(
            &std::fs::read(root.join(".login-recovery.json"))?,
        )?;
        let operations = after_import["operations"].as_array()
            .ok_or("account history missing after rejected import")?;
        if after_import["schema_version"] != 2 || !after_import["active"].is_null()
            || operations.len() != prior_imports.len() + 1
            || operations.get(..prior_imports.len()) != Some(prior_imports.as_slice()) {
            return Err("rejected import did not retain one new terminal operation and its history".into());
        }
        let record = &operations[prior_imports.len()];
        let operation_id = record["operation_id"].as_str().ok_or("import operation ID missing")?;
        let parsed = uuid::Uuid::parse_str(operation_id)?;
        let bound_root: std::path::PathBuf = serde_json::from_value(record["root"].clone())?;
        let bound_source: std::path::PathBuf = serde_json::from_value(record["profile"].clone())?;
        let identity = respire_protocol::HostAuthIdentity::Bound {
            account_id: format!("{:x}", Sha256::digest(b"original")),
            session_sha256: format!("{:x}", Sha256::digest(&source_session)),
        };
        let base = format!("{:x}", Sha256::digest(serde_json::to_vec(&json!({
            "schema_version":1,"register":false,"root":bound_root,"source":bound_source,
            "identity":identity,"addr":addr,"user":"authorized",
        }))?));
        let fingerprint = format!("{:x}", Sha256::digest(
            serde_json::to_vec(&(&base, (true, false, false)))?,
        ));
        let login = &record["account"]["login"];
        if parsed.get_version_num() != 4 || parsed.to_string() != operation_id
            || prior_imports.iter().any(|prior| prior["operation_id"] == operation_id)
            || record["idempotency_key"] != operation_id || record["fingerprint"] != fingerprint
            || record["phase"] != "rolled_back" || bound_root != root.canonicalize()?
            || bound_source != original.canonicalize()?
            || record["original_sha256"] != format!("{:x}", Sha256::digest(&source_session))
            || record["account"]["register"] != false || record["account"]["user"] != "authorized"
            || record["account"]["addr"] != addr
            || record["account"]["source_identity"] != serde_json::to_value(&identity)?
            || std::path::Path::new(record["account"]["target"].as_str()
                .ok_or("import receipt target missing")?).canonicalize()? != target.canonicalize()?
            || login["migrate_local"] != true || login["migrate_vault"] != false
            || login["offer_local_merge"] != false || login["import_started"] != false
            || login.get("import") != Some(&Value::Null)
            || login["sync_started"] != true
            || login["sync"] != json!({"status":"failed","reason":"target_sync_failed_before_copying"})
            || !target_empty()? || std::fs::read(target.join("session.json"))? != target_session {
            return Err("rejected import did not prove bound rollback before copying source data".into());
        }
        assert_eq!(std::fs::read(root.join("client.json"))?, source_config);
        assert_eq!(
            std::fs::read(original.join("session.json"))?,
            source_session
        );
        *mode.lock().map_err(|error| error.to_string())? = "authorized".to_owned();
        let prior_copy_operations = operations;
        let source_rows = serde_json::to_value(LocalStore::open(&original.join("rsrs.db"))?.all(true)?)?;
        let copied = execute(&transfer)?;
        assert_eq!(
            copied.status.code(),
            Some(2),
            "{} {}",
            String::from_utf8_lossy(&copied.stdout),
            String::from_utf8_lossy(&copied.stderr)
        );
        let copied: Value = serde_json::from_slice(&copied.stdout)?;
        assert_eq!(copied["status"], "warn");
        assert_eq!(copied["summary"]["ok"], true);
        assert_eq!(copied["summary"]["user"], "authorized");
        assert_eq!(copied["summary"]["addr"], addr);
        assert_eq!(copied["summary"]["import"]["imported"], 1, "{copied}");
        assert_eq!(
            copied["summary"]["import"]["duplicates"], 1,
            "cloud-only duplicate was not pulled before import"
        );
        assert_eq!(copied["summary"]["import"]["skipped"], 1);
        let pending_sync = json!({"status":"pending","reason":"post_import_sync_failed"});
        assert_eq!(copied["summary"]["sync"], pending_sync);
        // Import is durable before post-sync; a sync warning is not an unknown login.
        let copy_journal: Value = serde_json::from_slice(
            &std::fs::read(root.join(".login-recovery.json"))?,
        )?;
        let copy_operations = copy_journal["operations"].as_array()
            .ok_or("account history missing after committed import")?;
        if copy_journal["schema_version"] != 2 || !copy_journal["active"].is_null()
            || copy_operations.len() != prior_copy_operations.len() + 1
            || copy_operations.get(..prior_copy_operations.len()) != Some(prior_copy_operations.as_slice()) {
            return Err("import warning did not retain one new terminal operation and its history".into());
        }
        let copy_record = &copy_operations[prior_copy_operations.len()];
        let copy_id = copy_record["operation_id"].as_str().ok_or("committed import ID missing")?;
        let parsed = uuid::Uuid::parse_str(copy_id)?;
        let copy_login = &copy_record["account"]["login"];
        let candidate: Vec<u8> = serde_json::from_value(copy_record["candidate"].clone())?;
        let copied_session_bytes = std::fs::read(target.join("session.json"))?;
        let copied_session: Value = serde_json::from_slice(&copied_session_bytes)?;
        let alias = copy_record["alias"].as_str().filter(|value| !value.is_empty())
            .ok_or("committed import credential reference missing")?;
        let backend = copy_record["backend"].as_str().ok_or("committed import backend missing")?;
        if parsed.get_version_num() != 4 || parsed.to_string() != copy_id
            || prior_copy_operations.iter().any(|prior| prior["operation_id"] == copy_id)
            || copy_record["idempotency_key"] != copy_id || copy_record["fingerprint"] != fingerprint
            || copy_record["phase"] != "committed" || copy_record["root"] != record["root"]
            || copy_record["profile"] != record["profile"]
            || copy_record["original_sha256"] != format!("{:x}", Sha256::digest(&source_session))
            || copy_record["account"]["source_identity"] != serde_json::to_value(&identity)?
            || copy_record["account"]["register"] != false || copy_record["account"]["user"] != "authorized"
            || copy_record["account"]["addr"] != addr
            || std::path::Path::new(copy_record["account"]["target"].as_str()
                .ok_or("committed import target missing")?).canonicalize()? != target.canonicalize()?
            || copy_login["migrate_local"] != true || copy_login["migrate_vault"] != false
            || copy_login["offer_local_merge"] != false || copy_login["import_started"] != true
            || copy_login["sync_started"] != true || copy_login["import"]["recovered"] != false
            || copy_login["import"]["report"] != copied["summary"]["import"] || copy_login["sync"] != pending_sync
            || candidate != copied_session_bytes
            || copy_record["candidate_sha256"] != format!("{:x}", Sha256::digest(&copied_session_bytes))
            || copied_session["user"] != "authorized" || copied_session["addr"] != addr
            || copied_session["keyring_account"] != alias || copied_session["keyring_backend"] != backend
            || !matches!(backend, "native" | "secret_service")
            || copied_session.get("super").is_some() || copied_session.get("pass").is_some() {
            return Err("import warning does not match its committed candidate, owner and durable result".into());
        }
        let mut copy_config: Value = serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
        let source_config_value: Value = serde_json::from_slice(&source_config)?;
        if std::path::Path::new(copy_config["data_dir"].as_str().ok_or("import selection missing")?).canonicalize()?
                != target.canonicalize()?
            || std::path::Path::new(copied["summary"]["dir"].as_str().ok_or("import response directory missing")?).canonicalize()?
                != target.canonicalize()? {
            return Err("committed import did not select its bound target".into());
        }
        copy_config["data_dir"] = source_config_value["data_dir"].clone();
        if copy_config != source_config_value || std::fs::read(original.join("session.json"))? != source_session
            || serde_json::to_value(LocalStore::open(&original.join("rsrs.db"))?.all(true)?)? != source_rows {
            return Err("committed import changed source data/session or unrelated configuration".into());
        }
        let owner = runtime_health(runtime_port, "import-target")?;
        let official = runtime_bin()?;
        let installed = root.join("runtime")
            .join(official.parent().and_then(std::path::Path::file_name).ok_or("official Runtime version missing")?)
            .join(official.file_name().ok_or("official Runtime filename missing")?).canonicalize()?;
        if owner["store_ready"] != true || owner["account_id"] != format!("{:x}", Sha256::digest(b"authorized"))
            || std::path::Path::new(owner["data_dir"].as_str().ok_or("import owner profile missing")?).canonicalize()? != target.canonicalize()?
            || std::path::Path::new(owner["exe"].as_str().ok_or("import owner image missing")?).canonicalize()? != installed
            || owner["image_sha256"] != format!("{:x}", Sha256::digest(std::fs::read(&installed)?))
            || !owner["pid"].as_u64().is_some_and(|pid| pid > 0)
            || !owner["instance_id"].as_str().is_some_and(|id| !id.is_empty())
            || !owner["generation"].is_u64() {
            return Err("import warning lost its ready managed target owner".into());
        }
        assert!(execute(&["--json", "--client-only", "status"])?.status.success(),
            "committed import failed the existing scoped owner verification");
        let db = LocalStore::open(&target.join("rsrs.db"))?;
        let rows = db.all(false)?;
        assert_eq!(rows.len(), 2);
        let cloud_snapshot = cloud.lock().map_err(|error| error.to_string())?.clone();
        let keys = SessionKeys::unlock_v4(
            &super_password,
            cloud_snapshot["kdf_salt"]
                .as_str()
                .ok_or("missing cloud salt")?,
            cloud_snapshot["wrapped_urk"]
                .as_str()
                .ok_or("missing cloud wrap")?,
            cloud_snapshot["urk_nonce"]
                .as_str()
                .ok_or("missing cloud nonce")?,
        )?;
        let entries = rows
            .iter()
            .map(|row| respire_app::memory::MemoryEngine::open(&keys, row))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(entries
            .iter()
            .any(|entry| entry.content == "Synthetic cross-server transfer body"));
        assert!(entries
            .iter()
            .any(|entry| entry.id == peer.id && entry.content == "Synthetic cloud peer body"));
        drop(db);
        assert!(execute(&["--json", "account", "use", "original"])?
            .status
            .success());
        let retry = execute(&transfer)?;
        assert!(
            retry.status.success(),
            "{}",
            String::from_utf8_lossy(&retry.stdout)
        );
        let retry: Value = serde_json::from_slice(&retry.stdout)?;
        assert_eq!(retry["summary"]["import"]["imported"], 0, "{retry}");
        assert_eq!(retry["summary"]["import"]["duplicates"], 2);
        assert_eq!(
            remote_blobs
                .lock()
                .map_err(|error| error.to_string())?
                .len(),
            2
        );
        assert_eq!(
            std::fs::read(original.join("session.json"))?,
            source_session
        );
        let retained_session = std::fs::read(target.join("session.json"))?;
        let retained_config = std::fs::read(root.join("client.json"))?;
        // Inspect only local checkpoints; account-result can resume an unfinished operation.
        let journal = || -> Result<Value, Box<dyn std::error::Error>> {
            Ok(serde_json::from_slice(&std::fs::read(root.join(".login-recovery.json"))?)?)
        };
        let local_rows = || -> Result<Value, Box<dyn std::error::Error>> {
            Ok(serde_json::to_value(LocalStore::open(&target.join("rsrs.db"))?.all(true)?)?)
        };
        let checkpoint = |before: &Value, session: &[u8], config: &[u8], data: &Value,
            migrating: bool, phase: &str| -> Result<Value, Box<dyn std::error::Error>> {
            let after = journal()?;
            let prior = before["operations"].as_array().ok_or("prior account history missing")?;
            let operations = after["operations"].as_array().ok_or("account history missing")?;
            if before["schema_version"] != 2 || !before["active"].is_null()
                || after["schema_version"] != 2 || operations.len() != prior.len() + 1
                || operations.get(..prior.len()) != Some(prior.as_slice()) {
                return Err("rejected account operation did not retain exactly one new receipt".into());
            }
            let record = &operations[prior.len()];
            let id = record["operation_id"].as_str().ok_or("rejected operation ID missing")?;
            let parsed = uuid::Uuid::parse_str(id)?;
            let source = target.canonicalize()?;
            let identity = respire_protocol::HostAuthIdentity::Bound {
                account_id: format!("{:x}", Sha256::digest(b"authorized")),
                session_sha256: format!("{:x}", Sha256::digest(session)),
            };
            let base = format!("{:x}", Sha256::digest(serde_json::to_vec(&json!({
                "schema_version":1,"register":false,"root":root.canonicalize()?,
                "source":source,"identity":identity,"addr":addr,"user":"authorized",
            }))?));
            let fingerprint = format!("{:x}", Sha256::digest(serde_json::to_vec(
                &(&base, (false, migrating, false)))?));
            let account = &record["account"];
            let login = &account["login"];
            if parsed.get_version_num() != 4 || parsed.to_string() != id
                || prior.iter().any(|old| old["operation_id"] == id)
                || record["idempotency_key"] != id || record["fingerprint"] != fingerprint
                || record["root"] != serde_json::to_value(root.canonicalize()?)?
                || record["profile"] != serde_json::to_value(&source)?
                || record["original_sha256"] != format!("{:x}", Sha256::digest(session))
                || record["phase"] != phase
                || !record["alias"].as_str().is_some_and(|alias| alias.starts_with("login-") && alias.len() > 6)
                || record["candidate"] != Value::Null || record["candidate_sha256"] != Value::Null
                || record["backend"] != Value::Null || account["target"] != Value::Null
                || account["register"] != false || account["user"] != "authorized" || account["addr"] != addr
                || account["source_identity"] != serde_json::to_value(identity)?
                || !account["authorization"].is_object()
                || account["published_vault"] != false || account["vault_pending"] != false
                || login["migrate_local"] != false || login["migrate_vault"] != migrating
                || login["offer_local_merge"] != false || login["required_inputs"] != json!([])
                || login["snapshot"] != Value::Null || login["import_started"] != false
                || login["sync_started"] != false || login["import"] != Value::Null || login["sync"] != Value::Null
                || login["publication_pending"] != false || login["publication_done"] != false
                || login["vault_done"] != false || login["password_done"] != false
                || std::fs::read(target.join("session.json"))? != session
                || std::fs::read(root.join("client.json"))? != config || local_rows()? != *data {
                return Err("rejected account operation changed its binding, checkpoint or local material".into());
            }
            if phase == "authorized" {
                let active = &after["active"];
                let original: Vec<u8> = serde_json::from_value(active["original"].clone())?;
                if active["operation_id"] != id || active["alias"] != record["alias"]
                    || active["directory"] != serde_json::to_value(source)? || original != session
                    || active["directory_existed"] != true || active["owns_config"] != false
                    || active["config"] != Value::Null || active["backends"] != json!([])
                    || active["pass_backends"] != json!([]) || active["totp_backends"] != json!([]) {
                    return Err("rejected account operation does not own an untouched recovery checkpoint".into());
                }
            } else if phase != "rolled_back" || !after["active"].is_null() {
                return Err("automatic account rejection did not durably clear active recovery".into());
            }
            Ok(record.clone())
        };
        let rollback_rejected = |output: &Output, before: &Value, session: &[u8], config: &[u8], data: &Value|
            -> Result<(), Box<dyn std::error::Error>> {
            use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult};
            assert!(!output.status.success());
            let record = checkpoint(before, session, config, data, true, "authorized")?;
            let operation = record["operation_id"].as_str().ok_or("rollback operation missing")?;
            let failure: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(failure["summary"]["reason"], "account_outcome_unknown");
            assert_eq!(failure["details"]["operation_id"], operation);
            assert_eq!(failure["details"]["source_profile"], serde_json::to_value(target.canonicalize()?)?);
            assert_eq!(failure["details"]["register"], false);
            let requests_before = requests.lock().map_err(|error| error.to_string())?.clone();
            let cloud_before = cloud.lock().map_err(|error| error.to_string())?.clone();
            let source = target.canonicalize()?;
            let source_arg = source.to_str().ok_or("rollback source is not UTF-8")?;
            let output = execute(&["--json", "runtime", "account-rollback", "--operation-id",
                operation, "--source-profile", source_arg, "--confirm"])?;
            let envelope: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(envelope["command"], "auth-account");
            let receipt: HostAuthAccountResult = serde_json::from_value(envelope["summary"].clone())?;
            assert_eq!(receipt.operation_id, operation);
            assert_eq!(receipt.source_profile, source);
            assert_eq!(receipt.outcome, HostAuthAccountOutcome::RolledBack);
            let mut expected = record;
            expected["phase"] = json!("rolled_back");
            if checkpoint(before, session, config, data, true, "rolled_back")? != expected {
                return Err("explicit rollback changed original operation evidence".into());
            }
            assert_eq!(*requests.lock().map_err(|error| error.to_string())?, requests_before,
                "rollback repeated authentication, vault publication or import requests");
            if *cloud.lock().map_err(|error| error.to_string())? != cloud_before {
                return Err("explicit rollback changed the remote vault".into());
            }
            Ok(())
        };
        let restart_migration = |session: &[u8], config: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
            let restarted = execute(&["--json", "runtime", "restart"])?;
            assert!(restarted.status.success(), "migration source did not resume after explicit rollback");
            let envelope: Value = serde_json::from_slice(&restarted.stdout)?;
            assert_eq!(envelope["summary"]["state"], "ready");
            assert_eq!(std::fs::canonicalize(envelope["summary"]["data_dir"].as_str()
                .ok_or("restarted migration source missing")?)?, target.canonicalize()?);
            assert!(execute(&["--json", "--client-only", "status"])?.status.success(),
                "restarted migration source failed scoped owner verification");
            let health = runtime_health(runtime_port, "restart-target")?;
            assert_eq!(health["store_ready"], true);
            assert_eq!(health["account_id"], format!("{:x}", Sha256::digest(b"authorized")));
            assert_eq!(std::fs::canonicalize(health["data_dir"].as_str()
                .ok_or("restarted owner profile missing")?)?, target.canonicalize()?);
            assert_eq!(std::fs::read(target.join("session.json"))?, session);
            assert_eq!(std::fs::read(root.join("client.json"))?, config);
            Ok(())
        };
        let mismatch_before = journal()?;
        let mismatch_rows = local_rows()?;
        let mismatch_salt = crypto::random_hex(16);
        let (mismatch_nonce, mismatch_wrap) = crypto::wrap_key(
            &[44_u8; 32],
            &crypto::derive_kek_v4(&super_password, &mismatch_salt)?,
        )?;
        *cloud.lock().map_err(|error| error.to_string())? = json!({"version":4,"kdf_salt":mismatch_salt,"wrapped_urk":mismatch_wrap,"urk_nonce":mismatch_nonce});
        let rejected = execute(&[
            "--json",
            "login",
            "--oauth",
            "--addr",
            &addr,
            "--dashboard",
            &addr,
            "--no-open",
            "--super",
            &super_password,
        ])?;
        assert_eq!(
            rejected.status.code(),
            Some(1),
            "same-identity key mismatch was accepted"
        );
        let rejected_record = checkpoint(&mismatch_before, &retained_session, &retained_config,
            &mismatch_rows, false, "rolled_back")?;
        let rejected_envelope: Value = serde_json::from_slice(&rejected.stdout)?;
        assert_eq!(rejected_envelope["summary"]["reason"], "runtime_error");
        let rejected_id = rejected_record["operation_id"].as_str().ok_or("automatic rollback operation missing")?;
        assert!(rejected_envelope["errors"].as_array().ok_or("automatic rollback error missing")?
            .iter().filter_map(Value::as_str).any(|message| message.contains(
                &format!("account operation rolled back; operation_id={rejected_id} "))),
            "key mismatch did not report its automatic original-operation rollback");
        assert_eq!(
            std::fs::read(target.join("session.json"))?,
            retained_session
        );
        assert_eq!(std::fs::read(root.join("client.json"))?, retained_config);
        *cloud.lock().map_err(|error| error.to_string())? = cloud_snapshot;
        assert!(execute(&["--json", "logout", "--full"])?.status.success());
        assert!(!target.join("session.json").exists());
        let recovered = execute(&[
            "--json",
            "login",
            "--oauth",
            "--addr",
            &addr,
            "--dashboard",
            &addr,
            "--no-open",
            "--super",
            &super_password,
        ])?;
        assert!(
            recovered.status.success(),
            "{}",
            String::from_utf8_lossy(&recovered.stdout)
        );
        let recovered: Value = serde_json::from_slice(&recovered.stdout)?;
        assert_eq!(
            recovered["summary"]["dir"].as_str(),
            target.to_str(),
            "full logout selected a fresh library"
        );
        for row in &rows {
            let read = execute(&["--json", "show", &row.id])?;
            assert!(
                read.status.success(),
                "full logout lost local record: {}",
                String::from_utf8_lossy(&read.stdout)
            );
        }
        for row in &rows {
            assert!(execute(&["--json", "purge", &row.id])?.status.success());
        }
        remote_blobs
            .lock()
            .map_err(|error| error.to_string())?
            .clear();
        assert!(execute(&["--runtime-internal", "--stop"])?.status.success());
        std::fs::write(original.join("session.json"), session_bytes)?;
        use_checkpointed_credentials.set(false);

        let legacy_super = "synthetic-legacy-passphrase";
        migration_super.set(Some(legacy_super));
        let salt = crypto::random_hex(16);
        let (nonce, wrapped) =
            crypto::wrap_key(&urk, &crypto::derive_super_kek(legacy_super, &salt)?)?;
        let mut legacy = json!({"user":"authorized","addr":addr,"vault_version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        std::fs::write(target.join("session.json"), serde_json::to_vec(&legacy)?)?;
        *cloud.lock().map_err(|error| error.to_string())? =
            json!({"version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        let incomplete_before = journal()?;
        let incomplete_session = std::fs::read(target.join("session.json"))?;
        let migration_config = std::fs::read(root.join("client.json"))?;
        let migration_rows = local_rows()?;
        let incomplete = execute(&[
            "--json",
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
        ])?;
        if incomplete.status.success()
            || std::fs::read(target.join("session.json"))? != serde_json::to_vec(&legacy)?
        {
            return Err("vault-only operation bypassed full library migration".into());
        }
        rollback_rejected(&incomplete, &incomplete_before, &incomplete_session, &migration_config, &migration_rows)?;
        // The real public library conversion is covered by migration_readiness_tests.
        // This authorization fixture begins with its verified v2 namespace wrap.
        legacy["crypto_namespace"] = json!(crypto::RSRS_PREFIX);
        legacy["wrapped_urk"] = json!(format!("{}{wrapped}", crypto::RSRS_PREFIX));
        std::fs::write(target.join("session.json"), serde_json::to_vec(&legacy)?)?;
        restart_migration(&serde_json::to_vec(&legacy)?, &migration_config)?;
        let migrated = execute(&[
            "--json",
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
            "--new-super",
            legacy_super,
        ])?;
        if !migrated.status.success() {
            return Err(format!(
                "explicit vault migration failed: {} {}",
                String::from_utf8_lossy(&migrated.stdout),
                String::from_utf8_lossy(&migrated.stderr)
            )
            .into());
        }
        let current = cloud.lock().map_err(|error| error.to_string())?.clone();
        let keys = SessionKeys::unlock_super(
            legacy_super,
            current["kdf_salt"].as_str().ok_or("salt missing")?,
            current["wrapped_urk"].as_str().ok_or("wrap missing")?,
            current["urk_nonce"].as_str().ok_or("nonce missing")?,
        )?;
        if current["version"] != 2
            || keys.urk != urk
            || !current["wrapped_urk"]
                .as_str()
                .is_some_and(|value| value.starts_with(crypto::RSRS_PREFIX))
        {
            return Err("migration replaced the existing memory key".into());
        }
        let stopped = execute(&["--runtime-internal", "--stop"])?;
        if !stopped.status.success() {
            return Err("could not stop the isolated migration runtime".into());
        }
        // Reproduce a committed cloud wrap with a locally rolled-back legacy
        // session: retry must prove the same URK, never overwrite the cloud key.
        let legacy_bytes = serde_json::to_vec(&legacy)?;
        std::fs::write(target.join("session.json"), &legacy_bytes)?;
        let wrong_before = journal()?;
        let wrong_config = std::fs::read(root.join("client.json"))?;
        let wrong_rows = local_rows()?;
        let wrong = execute(&[
            "--json",
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
            "--new-super=wrong-recovery-code",
        ])?;
        if wrong.status.success() || std::fs::read(target.join("session.json"))? != legacy_bytes {
            return Err("migration resume accepted an incorrect recovery code".into());
        }
        rollback_rejected(&wrong, &wrong_before, &legacy_bytes, &wrong_config, &wrong_rows)?;
        restart_migration(&legacy_bytes, &wrong_config)?;
        let resumed = execute(&[
            "--json",
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
            "--new-super",
            legacy_super,
        ])?;
        if !resumed.status.success() {
            return Err(format!(
                "migration resume failed: {} {}",
                String::from_utf8_lossy(&resumed.stdout),
                String::from_utf8_lossy(&resumed.stderr)
            )
            .into());
        }
        let saved: Value = serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
        if saved["vault_version"] != 2
            || *cloud.lock().map_err(|error| error.to_string())? != current
        {
            return Err(
                "migration resume did not commit locally or republished the cloud vault".into(),
            );
        }
        if std::fs::read(original.join("session.json"))? != session_bytes {
            return Err("migration modified the unrelated original account".into());
        }
        let paths = requests.lock().map_err(|error| error.to_string())?;
        if !paths.iter().any(|path| path == "/oauth/token")
            || !paths.iter().any(|path| path == "/api/self/vault")
        {
            return Err("authorization did not exercise polling and vault verification".into());
        }
        Ok(())
    }));
    let stopped = execute(&["--runtime-internal", "--stop"]);
    running.store(false, Ordering::SeqCst);
    let served = worker
        .join()
        .map_err(|_| "authorization fixture thread panicked");
    let mut source_cleanup_failed = false;
    for backend in &source_backends {
        if respire_app::keystore::remove_imported(&source_alias, "super", backend).is_err() {
            source_cleanup_failed = true;
        }
    }
    if source_cleanup_failed {
        eprintln!("source fixture credential cleanup failed; original fixture result retained");
    }
    let result = match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    result?;
    if source_cleanup_failed {
        return Err("source fixture credential cleanup failed".into());
    }
    stopped?;
    served?.map_err(Into::into)
}

fn legacy_space_contract(case: &str) -> Result<(), Box<dyn std::error::Error>> {
    use serde_json::{json,Value};
    use respire_app::transport::MemoryTransport;
    let guard=super::snapshot_lifecycle::Fixture::new()?;
    let protected=guard.protected_state()?;
    let home=tempfile::tempdir()?;
    let root=home.path().join(".rsrs");
    std::fs::create_dir(&root)?;
    support::stage_legacy_cli(&root)?;
    let port=std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let invoke=|args:&[&str]| -> Result<(Output,Value),Box<dyn std::error::Error>> {
        let output=isolated_command(None)?.arg("--json").args(args)
            .current_dir(home.path()).env("HOME",home.path()).env("USERPROFILE",home.path())
            .env("RSRS_DATA_DIR",&root).env("RSRS_BIN_DIR",root.join("bin"))
            .env("RSRS_RPC_PORT",port.to_string()).env("RSRS_NO_AUTOSYNC","1")
            .env("RSRS_UPDATE_CHECK","0").env("RSRS_CORE_TEST_MODE","1")
            .env("RSRS_MIRROR","http://127.0.0.1:9").output()?;
        let value=serde_json::from_slice(&output.stdout)?;
        Ok((output,value))
    };
    let outcome=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(),Box<dyn std::error::Error>> {
        assert!(!invoke(&["space","create","main"])?.0.status.success());
        let (created,value)=invoke(&["space","create","legacy-team"])?;
        assert!(created.status.success());
        assert_eq!(value["summary"]["name"],"legacy-team");
        let selected:Value=serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
        let team=std::path::PathBuf::from(selected["data_dir"].as_str().ok_or("old team profile missing")?);
        assert!(team.starts_with(&root));
        let owner=support::legacy_owner(&root,&team,port)?;
        let pid=u32::try_from(owner["pid"].as_u64().ok_or("old team PID missing")?)?;
        assert!(invoke(&["--runtime-internal","--stop"])?.0.status.success());
        support::legacy_drained(&team,port,pid)?;
        guard.copy_test_rows(&team)?;
        assert!(invoke(&["runtime","start"])?.0.status.success());
        support::legacy_owner(&root,&team,port)?;
        assert!(respire_app::lock::LibraryLock::acquire(&team,Duration::from_millis(80)).is_err());
        let (listed,spaces)=invoke(&["space","list"])?;
        assert!(listed.status.success());
        assert!(spaces["details"]["spaces"].as_array().ok_or("old space list missing")?
            .iter().any(|space|space["name"]=="legacy-team"));
        let config=std::fs::read(root.join("client.json"))?;
        std::fs::write(team.join("keep.txt"),b"old team data must survive refused operations")?;
        let saved=serde_json::to_value(respire_app::transport::local::LocalStore::open(&team.join("rsrs.db"))?.all(true)?)?;
        for args in [&["space","use","missing"][..],&["space","remove","legacy-team","--yes"][..]] {
            assert!(!invoke(args)?.0.status.success());
            assert!(std::fs::read(root.join("client.json"))?==config);
            assert_eq!(std::fs::read(team.join("keep.txt"))?,b"old team data must survive refused operations");
            assert_eq!(serde_json::to_value(respire_app::transport::local::LocalStore::open(&team.join("rsrs.db"))?.all(true)?)?,saved);
            support::legacy_owner(&root,&team,port)?;
        }
        assert!(invoke(&["space","use","main"])?.0.status.success());
        support::legacy_owner(&root,&root,port)?;
        assert!(invoke(&["space","use","legacy-team"])?.0.status.success());
        support::legacy_owner(&root,&team,port)?;
        assert!(std::fs::read(team.join("keep.txt"))?==b"old team data must survive refused operations");
        assert!(invoke(&["space","use","main"])?.0.status.success());
        assert!(invoke(&["space","remove","legacy-team","--yes"])?.0.status.success());
        let (_,listed)=invoke(&["space","list"])?;
        assert!(!listed["details"]["spaces"].as_array().ok_or("old final space list missing")?
            .iter().any(|space|space["name"]=="legacy-team"));
        if case=="account::spaces_coordinate_with_the_owned_runtime" {
            let before=std::fs::read(root.join("client.json"))?;
            for readonly in [false,true] {
                // Same ordered self/vault mock protocol as the original case.
                let server=tiny_http::Server::http("127.0.0.1:0").map_err(|error|error.to_string())?;
                let name=if readonly {"legacy-joined-readonly"} else {"legacy-joined-writable"};
                let user=format!("old-join-{}",uuid::Uuid::new_v4());
                let secret=respire_app::memory::crypto::generate_secret_key();
                let salt=respire_app::memory::crypto::random_hex(16);
                let kek=respire_app::memory::crypto::derive_kek_v4(&secret,&salt)?;
                let (nonce,wrapped)=respire_app::memory::crypto::wrap_key(&[42_u8;32],&kek)?;
                let vault=json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
                let token=uuid::Uuid::new_v4().to_string();
                let payload=json!({"space":name,"addr":format!("http://{}",server.server_addr()),
                    "user":user,"token":token,"super":secret,"readonly":readonly});
                let code=format!("1mem-invite:{}",serde_json::to_vec(&payload)?.iter()
                    .map(|byte|format!("{byte:02x}")).collect::<String>());
                let expected_user=user.clone();
                let authorization=format!("Bearer {token}");
                let worker=std::thread::spawn(move || -> Result<(),String> {
                    for (path,body) in [("/api/self",json!({"user":expected_user})),("/api/self/vault",vault)] {
                        let request=server.recv_timeout(Duration::from_secs(20)).map_err(|_|"old join receive failed")?
                            .ok_or("old join did not fetch the ordered vault fixture")?;
                        if request.method()!=&tiny_http::Method::Get || request.url()!=path
                            || !request.headers().iter().any(|header|header.field.equiv("Authorization")
                                &&header.value.as_str()==authorization) {
                            return Err("old join did not authenticate its ordered GET".into());
                        }
                        request.respond(tiny_http::Response::from_string(body.to_string()))
                            .map_err(|_|"old join response failed")?;
                    }
                    Ok(())
                });
                let joined=invoke(&["space","join",&code]);
                let served=worker.join().map_err(|_|"old join fixture panicked");
                respire_app::keystore::delete_super(&user);
                // Join the worker even when the client failed; retain both errors.
                let (output,joined)=match(joined,served) {
                    (Ok(joined),Ok(Ok(())))=>joined,
                    (Err(error),Ok(Ok(())))=>return Err(error),
                    (Ok(_),Ok(Err(error)))=>return Err(error.into()),
                    (Err(error),Ok(Err(server)))=>return Err(format!("{error}; {server}").into()),
                    (Ok(_),Err(error))=>return Err(error.into()),
                    (Err(error),Err(server))=>return Err(format!("{error}; {server}").into()),
                };
                assert!(output.status.success() || (output.status.code()==Some(2)&&joined["status"]=="warn"));
                assert_eq!(joined["details"]["readonly"],readonly);
                assert!(std::fs::read(root.join("client.json"))?==before);
                let target=root.join("accounts").join(name);
                let session:Value=serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
                assert_eq!(session["user"],user);
                if readonly {
                    let agent:Value=serde_json::from_slice(&std::fs::read(target.join("agent.json"))?)?;
                    assert_eq!(agent["readonly_team"],true);
                }
                let owner=support::legacy_owner(&root,&root,port)?;
                assert!(!invoke(&["space","join","--code",&code])?.0.status.success());
                assert_eq!(support::legacy_owner(&root,&root,port)?["pid"],owner["pid"]);
            }
        }
        assert_eq!(guard.protected_state()?,protected);
        Ok(())
    }));
    let cleanup=(|| -> Result<(),Box<dyn std::error::Error>> {
        if respire_commands::net_rpc::port_is_open_on(port) {
            let config:Value=serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
            let profile=config["data_dir"].as_str().map(std::path::PathBuf::from).map_or_else(||root.clone(),|path|path);
            let owner=support::legacy_owner(&root,&profile,port)?;
            let pid=u32::try_from(owner["pid"].as_u64().ok_or("old space cleanup PID missing")?)?;
            assert!(invoke(&["--runtime-internal","--stop"])?.0.status.success());
            support::legacy_drained(&profile,port,pid)?;
        }
        assert_eq!(guard.protected_state()?,protected);
        Ok(())
    })();
    let result=match outcome {Ok(result)=>result,Err(panic)=>std::panic::resume_unwind(panic)};
    result?;
    cleanup?;
    support::legacy_receipt(case,"old_embedded")?;
    Ok(())
}

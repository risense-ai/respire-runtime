//! Real CLI account/space calls with Runtime-owned business fixtures and decryption.
use super::support;
use std::process::{Command, Output};
use std::time::Duration;

fn runtime_bin() -> std::io::Result<std::path::PathBuf> {
    support::runtime_bin()
}

fn isolated_command(models: Option<&std::path::Path>) -> std::io::Result<Command> {
    let mut command = Command::new(support::cli_bin()?);
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

#[test]
fn space_create_list_use_remove() -> Result<(), Box<dyn std::error::Error>> {
    use serde_json::Value;

    let home = tempfile::tempdir()?;
    let root = home.path().join(".rsrs");
    std::fs::create_dir(&root)?;
    support::install_runtime_fixture(&root)?;
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
    use serde_json::{json, Value};
    let home = tempfile::tempdir()?;
    let library = home.path().join(".rsrs");
    std::fs::create_dir(&library)?;
    support::install_runtime_fixture(&library)?;
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
        let status: Value = ureq::get(&format!("http://127.0.0.1:{port}/api/health"))
            .timeout(Duration::from_secs(5))
            .call().map_err(|error| format!("owned space health stage={stage}: {error}"))?
            .into_json()?;
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
            let served = worker.join().map_err(|_| "join fixture panicked")?;
            respire_app::keystore::delete_super(&user);
            served.map_err(|error| format!("join server: {error}"))?;
            let joined = joined?;
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
        worker
            .join()
            .map_err(|_| "rejected join fixture panicked")?
            .map_err(|error| format!("join server: {error}"))?;
        assert_eq!(rejected?["details"]["error_type"], "runtime");
        assert_eq!(std::fs::read(&config)?, before);
        assert!(!library.join("accounts/rejected-join").exists());
        health(&library, "after-rejected-join")?;
        invoke(&["space", "create", "probe"], 0)?;
        let probe = library.join("accounts/probe");
        assert!(probe.join("space_owner.json").is_file());
        assert_ne!(health(&probe, "after-create")?, original_pid);
        let before = std::fs::read(&config)?;
        let blocked = invoke(&["space", "remove", "probe"], 2)?;
        assert_eq!(blocked["summary"]["reason"], "invalid_input");
        assert_eq!(std::fs::read(&config)?, before);
        let blocked = invoke(&["space", "remove", "probe", "--yes"], 2)?;
        assert_eq!(blocked["details"]["error_type"], "user");
        assert!(probe.is_dir());
        health(&probe, "after-blocked-remove")?;
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
    support::install_runtime_fixture(&root)?;
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
    let execute = |args: &[&str]| -> std::io::Result<Output> {
        let mut command = isolated_command(Some(&models))?;
        // Login factors come only from its arguments, never the harness unlock key.
        if args.contains(&"login") {
            command.env_remove("RSRS_SUPER");
        } else {
            command.env("RSRS_SUPER", &super_password);
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
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
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
        let saved: Value = serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
        if saved["user"] != "authorized"
            || saved.get("super").is_some()
            || saved.get("keyring_account").is_some()
        {
            return Err("headless login persisted an unexpected credential".into());
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

        // A different server's source uses another URK, even with the same recovery code.
        let source_urk = [43_u8; 32];
        let source_salt = crypto::random_hex(16);
        let (source_nonce, source_wrap) = crypto::wrap_key(
            &source_urk,
            &crypto::derive_kek_v4(&super_password, &source_salt)?,
        )?;
        let source_session = serde_json::to_vec(
            &json!({"user":"original","addr":"https://previous.invalid",
            "vault_version":4,"kdf_salt":source_salt,"wrapped_urk":source_wrap,"urk_nonce":source_nonce}),
        )?;
        std::fs::write(original.join("session.json"), &source_session)?;
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
        *mode.lock().map_err(|error| error.to_string())? = "sync_unavailable".to_owned();
        let rejected = execute(&transfer)?;
        assert_eq!(rejected.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&rejected.stdout).contains("before copying"));
        assert_eq!(std::fs::read(root.join("client.json"))?, source_config);
        assert_eq!(
            std::fs::read(original.join("session.json"))?,
            source_session
        );
        *mode.lock().map_err(|error| error.to_string())? = "authorized".to_owned();
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
        assert_eq!(copied["summary"]["import"]["imported"], 1, "{copied}");
        assert_eq!(
            copied["summary"]["import"]["duplicates"], 1,
            "cloud-only duplicate was not pulled before import"
        );
        assert_eq!(copied["summary"]["sync"]["status"], "fail");
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
        assert!(String::from_utf8_lossy(&rejected.stdout).contains("different key material"));
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

        let legacy_super = "synthetic-legacy-passphrase";
        let salt = crypto::random_hex(16);
        let (nonce, wrapped) =
            crypto::wrap_key(&urk, &crypto::derive_super_kek(legacy_super, &salt)?)?;
        let mut legacy = json!({"user":"authorized","addr":addr,"vault_version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        std::fs::write(target.join("session.json"), serde_json::to_vec(&legacy)?)?;
        *cloud.lock().map_err(|error| error.to_string())? =
            json!({"version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        let incomplete = execute(&[
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
        // The real public library conversion is covered by migration_readiness_tests.
        // This authorization fixture begins with its verified v2 namespace wrap.
        legacy["crypto_namespace"] = json!(crypto::RSRS_PREFIX);
        legacy["wrapped_urk"] = json!(format!("{}{wrapped}", crypto::RSRS_PREFIX));
        std::fs::write(target.join("session.json"), serde_json::to_vec(&legacy)?)?;
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
        let wrong = execute(&[
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
    })();
    let stopped = execute(&["--runtime-internal", "--stop"]);
    running.store(false, Ordering::SeqCst);
    let served = worker
        .join()
        .map_err(|_| "authorization fixture thread panicked")?;
    result?;
    stopped?;
    served.map_err(Into::into)
}

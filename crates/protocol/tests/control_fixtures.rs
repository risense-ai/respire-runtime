use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

mod private_host_control {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/runtime-control/consumers/private_host_control.rs"));
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/runtime-control/consumers/space_control.rs"));
}

#[test]
fn host_control_dto_roundtrip_rejects_unknown_fields() -> Result<()> {
    use respire_protocol::{HostControlOperation, HostControlParams, RpcRequest, HOST_CONTROL_SCHEMA_V};

    let wire = json!({
        "schema_version": HOST_CONTROL_SCHEMA_V,
        "binding": {
            "installation_root": "fixture-root",
            "profile": "fixture-profile",
            "launch_id": "12345678-1234-4234-8234-123456789abc",
            "expected_account_id": null,
        },
    });
    let params: HostControlParams = serde_json::from_value(wire.clone())?;
    assert_eq!(serde_json::to_value(&params)?, wire);
    assert!(params.binding.expected_account_id.is_none());
    let operation = HostControlOperation::MemoryRevision;
    assert_eq!(serde_json::to_value(operation)?, json!("memory_revision"));
    assert_eq!(serde_json::from_value::<HostControlOperation>(json!("memory_revision"))?, operation);
    assert!(serde_json::from_value::<HostControlOperation>(json!("exec")).is_err());
    let request: RpcRequest = serde_json::from_value(json!({
        "v": 1,
        "id": "12345678-1234-4234-8234-123456789abc",
        "method": operation.method(),
        "args": [serde_json::to_string(&params)?],
    }))?;
    let roundtrip: RpcRequest = serde_json::from_slice(&serde_json::to_vec(&request)?)?;
    assert!(roundtrip.scope.is_none());
    assert_eq!(roundtrip.method, "control.memory_revision");
    assert_eq!(roundtrip.args, request.args);
    let mut unknown = wire.clone();
    unknown["argv"] = json!(["--direct"]);
    assert!(serde_json::from_value::<HostControlParams>(unknown).is_err());
    let mut unknown = wire;
    unknown["binding"]["generation"] = json!(0);
    assert!(serde_json::from_value::<HostControlParams>(unknown).is_err());
    use respire_protocol::{HostAuthIdentity, HostAuthKeygenParams, HOST_AUTH_SCHEMA_V};
    let mut auth = json!({
        "schema_version": HOST_AUTH_SCHEMA_V,
        "binding": serde_json::to_value(&params.binding)?,
        "identity": {"kind":"absent"},
        "force": false,
    });
    let parsed: HostAuthKeygenParams = serde_json::from_value(auth.clone())?;
    assert_eq!(serde_json::to_value(parsed)?, auth);
    auth["identity"] = json!({"kind":"unbound","operation_id":"12345678-1234-4234-8234-123456789abc","session_sha256":"a".repeat(64)});
    let parsed: HostAuthKeygenParams = serde_json::from_value(auth.clone())?;
    assert!(matches!(&parsed.identity, HostAuthIdentity::Unbound { .. }));
    assert_eq!(serde_json::to_value(parsed)?, auth);
    auth["identity"]["generation"] = json!(0);
    assert!(serde_json::from_value::<HostAuthKeygenParams>(auth).is_err());
    assert!(serde_json::from_value::<HostAuthIdentity>(json!({"kind":"anonymous"})).is_err());
    use respire_protocol::host_control::{HostAuthRegisterParams, HostAuthLoginParams, HostAuthAccountParams};
    let register = json!({"schema_version":1,"binding":params.binding,"identity":{"kind":"absent"},
        "addr":"https://example.invalid","user":"roundtrip-user","password":"private-pipe-only","super_password":null});
    let parsed: HostAuthRegisterParams = serde_json::from_value(register.clone())?;
    assert_eq!(serde_json::to_value(parsed)?, register);
    let mut unknown = register.clone();
    unknown["argv"] = json!(["keygen"]);
    assert!(serde_json::from_value::<HostAuthRegisterParams>(unknown).is_err());
    let mut login = register;
    let object = login.as_object_mut().context("login parameters are an object")?;
    object.remove("password");
    object.insert("authorization".into(), json!({"kind":"password","password":"private-pipe-only","totp":null}));
    object.insert("super_password".into(), json!("recovery-code"));
    let parsed: HostAuthLoginParams = serde_json::from_value(login.clone())?;
    assert_eq!(serde_json::to_value(parsed)?, login);
    login["authorization"]["exec"] = json!(true);
    assert!(serde_json::from_value::<HostAuthLoginParams>(login).is_err());
    let query = json!({"schema_version":1,"binding":params.binding,"identity":{"kind":"absent"}});
    let parsed: HostAuthAccountParams = serde_json::from_value(query.clone())?;
    assert_eq!(serde_json::to_value(parsed)?, query);
    let mut unknown = query;
    unknown["verified"] = json!(true);
    assert!(serde_json::from_value::<HostAuthAccountParams>(unknown).is_err());
    Ok(())
}

fn contract_root() -> Result<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR is set")?;
    Ok(Path::new(&manifest_dir)
        .join("../../contracts/runtime-control")
        .canonicalize()
        .context("runtime control contract exists")?)
}

fn read_fixture(name: &str) -> Result<Value> {
    let path = contract_root()?.join("fixtures").join(name);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read fixture {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse fixture {}", path.display()))
}

fn require_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing string field {key}"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_release_metadata(fixture: &Value) -> Result<()> {
    let payload = fixture
        .get("payload")
        .and_then(Value::as_object)
        .context("metadata payload must be an object")?;
    let version = payload
        .get("schema_version")
        .and_then(Value::as_u64)
        .context("schema_version must be an integer")?;
    let runtime_version = require_string(&fixture["payload"], "runtime_version")?;
    let tag = require_string(&fixture["payload"], "tag")?;
    if tag.strip_prefix('v') != Some(runtime_version) {
        bail!("tag and runtime_version disagree");
    }

    let target = payload
        .get("target_triple")
        .and_then(Value::as_str)
        .or_else(|| payload.get("triple").and_then(Value::as_str))
        .context("target_triple or legacy triple is required")?;
    if target.is_empty() {
        bail!("target cannot be empty");
    }

    let archive = payload
        .get("archive_sha256")
        .and_then(Value::as_str)
        .or_else(|| payload.get("sha256").and_then(Value::as_str))
        .context("archive_sha256 or legacy sha256 is required")?;
    if !valid_sha256(archive) {
        bail!("archive digest is invalid");
    }

    let binary = payload.get("binary_sha256").and_then(Value::as_str);
    if version >= 2 {
        let binary = binary.context("schema 2 requires binary_sha256")?;
        if !valid_sha256(binary) {
            bail!("binary digest is invalid");
        }
    }

    let legacy_archive = payload.get("sha256").and_then(Value::as_str);
    let legacy_target = payload.get("triple").and_then(Value::as_str);
    if let Some(value) = legacy_archive {
        if value != archive {
            bail!("legacy archive alias conflicts with canonical value");
        }
    }
    if let Some(value) = legacy_target {
        if value != target {
            bail!("legacy target alias conflicts with canonical value");
        }
    }
    Ok(())
}

fn validate_identity(fixture: &Value, complete: bool) -> Result<()> {
    let payload = fixture["payload"].as_object().context("identity object")?;
    if !complete {
        assert_eq!(fixture["error_code"], "identity_incomplete");
        assert!(payload.get("instance_id").is_none_or(Value::is_null));
        return Ok(());
    }
    for key in [
        "installation_root",
        "installation_id",
        "instance_id",
        "pid",
        "process_start_id",
        "image_path",
        "image_sha256",
        "runtime_version",
        "account_id",
        "generation",
        "protocol_range",
        "capabilities",
        "store_ready",
        "state",
    ] {
        if !payload.contains_key(key) {
            bail!("health identity requires {key}");
        }
    }
    Ok(())
}

fn validate_stop(fixture: &Value, valid: bool) -> Result<()> {
    let payload = fixture["payload"].as_object().context("stop object")?;
    for key in ["request_id", "operation_id", "state"] {
        if !payload.contains_key(key) {
            bail!("stop state requires {key}");
        }
    }
    let drained_unfinished = payload.get("state").and_then(Value::as_str) == Some("drained")
        && payload
            .get("unfinished")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
    if !valid {
        assert_eq!(fixture["error_code"], "ambiguous_stop_result");
        assert!(drained_unfinished);
        return Ok(());
    }
    anyhow::ensure!(
        !drained_unfinished,
        "drained cannot contain unfinished operations"
    );
    Ok(())
}

fn validate_operation(fixture: &Value) -> Result<()> {
    let payload = fixture["payload"].as_object().context("operation object")?;
    for key in ["request_id", "operation_id", "method", "result", "scope"] {
        if !payload.contains_key(key) {
            bail!("operation result requires {key}");
        }
    }
    let scope: respire_protocol::RuntimeRequestScope =
        serde_json::from_value(fixture["payload"]["scope"].clone())?;
    anyhow::ensure!(
        !scope.account_id.trim().is_empty()
            && !scope.instance_id.trim().is_empty()
            && scope.generation > 0,
        "operation receipt requires a complete scope"
    );
    if fixture.get("expected").and_then(Value::as_str) == Some("reject") {
        if require_string(&fixture, "error_code")? != "idempotency_conflict" {
            bail!("unexpected operation rejection");
        }
        if !payload.contains_key("idempotency_key") {
            bail!("idempotency conflict requires the key");
        }
    }
    Ok(())
}

fn validate_roots(fixture: &Value) -> Result<()> {
    let installation = require_string(&fixture["payload"], "installation_root")?;
    for key in [
        "device_config_root",
        "account_data_root",
        "asset_root",
        "log_root",
    ] {
        let value = require_string(&fixture["payload"], key)?;
        if fixture.get("expected").and_then(Value::as_str) == Some("accept")
            && !value.starts_with(installation)
        {
            bail!("accepted legacy isolation must keep all roots under installation root");
        }
    }
    Ok(())
}

fn validate_route(fixture: &Value) -> Result<()> {
    let payload = fixture["payload"].as_object().context("route object")?;
    let operation = payload
        .get("operation")
        .and_then(Value::as_str)
        .context("route operation")?;
    let executor = payload
        .get("executor")
        .and_then(Value::as_str)
        .context("route executor")?;
    if operation.starts_with("auth.") && operation != "auth.status" && executor != "cli" {
        bail!("identity operations route to CLI");
    }
    Ok(())
}

#[test]
fn manifest_lists_the_frozen_fixture_sets() -> Result<()> {
    let path = contract_root()?.join("manifest.json");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).context("read manifest")?)?;
    let positive = manifest["fixtures"]["positive"]
        .as_array()
        .context("positive fixtures")?;
    let negative = manifest["fixtures"]["negative"]
        .as_array()
        .context("negative fixtures")?;
    assert_eq!(positive.len(), 89);
    assert_eq!(negative.len(), 287);
    assert_eq!(manifest["contract"], "runtime-control");
    assert_eq!(manifest["release_metadata_schema_version"], 2);
    private_host_control::space_contract_fixtures()?;
    Ok(())
}

#[test]
fn backend_load_success_matches_the_sanitized_sdk_shape() -> Result<()> {
    use respire_protocol::{AssetsStatus, BackendLoadEvidence, BackendLoadState};
    let fixture = read_fixture("positive/assets-loaded.json")?;
    let status: AssetsStatus = serde_json::from_value(fixture["payload"].clone())?;
    assert!(status.complete && status.missing.is_empty());
    let load = status.backend_load.context("backend load result")?;
    assert_eq!(load.state, BackendLoadState::Loaded);
    let evidence: BackendLoadEvidence = load.evidence.context("sanitized SDK evidence")?;
    assert!(evidence.ready && evidence.fresh_session && evidence.inference_completed);
    assert!(!evidence.runtime.version.is_empty());
    assert_eq!(serde_json::to_value(&evidence)?, fixture["payload"]["backend_load"]["evidence"]);
    for name in ["positive/assets-legacy-incomplete.json", "positive/assets-not-run.json",
        "positive/assets-failed.json"] {
        let fixture = read_fixture(name)?;
        let status: AssetsStatus = serde_json::from_value(fixture["payload"].clone())?;
        assert!(!status.complete);
    }
    for name in ["negative/assets-raw-address.json", "negative/assets-unknown-state.json"] {
        let fixture = read_fixture(name)?;
        assert!(serde_json::from_value::<AssetsStatus>(fixture["payload"].clone()).is_err());
    }
    Ok(())
}

#[test]
fn shared_fixtures_enforce_stage_one_semantics() -> Result<()> {
    for name in [
        "positive/release-metadata-v2.json",
        "positive/release-metadata-v1.json",
    ] {
        validate_release_metadata(&read_fixture(name)?)?;
    }

    validate_identity(&read_fixture("positive/health-identity.json")?, true)?;
    validate_identity(
        &read_fixture("negative/health-identity-pid-only.json")?,
        false,
    )?;
    validate_stop(&read_fixture("positive/stop-draining.json")?, true)?;
    validate_stop(&read_fixture("negative/stop-ambiguous-ok.json")?, false)?;
    validate_operation(&read_fixture("positive/operation-result-completed.json")?)?;
    validate_operation(&read_fixture("negative/idempotency-conflict.json")?)?;
    validate_roots(&read_fixture("positive/root-layout.json")?)?;
    validate_roots(&read_fixture(
        "negative/root-layout-legacy-as-data-only.json",
    )?)?;
    validate_route(&read_fixture("positive/bootstrap-route.json")?)?;
    Ok(())
}

#[test]
fn scoped_business_requests_match_shared_admission_fixtures() -> Result<()> {
    use respire_protocol::RuntimeRequestScope;
    fn failure(payload: &Value, current: &RuntimeRequestScope) -> Option<&'static str> {
        let Ok(request) = serde_json::from_value::<respire_protocol::RpcRequest>(payload.clone()) else {
            return Some("rpc_body_invalid");
        };
        let Some(scope) = request.scope else {
            return Some("scope_required");
        };
        if scope.account_id.trim().is_empty() || scope.instance_id.trim().is_empty()
            || scope.generation == 0 || &scope != current
        {
            return Some("scope_mismatch");
        }
        None
    }
    let health = read_fixture("positive/health-identity.json")?;
    let current: RuntimeRequestScope = serde_json::from_value(json!({
        "account_id": health["payload"]["account_id"],
        "instance_id": health["payload"]["instance_id"],
        "generation": health["payload"]["generation"],
    }))?;
    let manifest: Value = serde_json::from_slice(&std::fs::read(contract_root()?.join("manifest.json"))?)?;
    for group in ["positive", "negative"] {
        for name in manifest["fixtures"][group].as_array().context("fixture group")? {
            let name = name.as_str().context("fixture path")?;
            let fixture = read_fixture(name.strip_prefix("fixtures/").context("fixture prefix")?)?;
            if fixture["fixture_type"] == "business_rpc_response" {
                let expected = if fixture["expected"] == "accept" { None } else { fixture["error_code"].as_str() };
                assert_eq!(response_failure(&fixture["payload"]), expected, "{name}");
                continue;
            }
            if fixture["fixture_type"] != "business_rpc_request" { continue; }
            let expected = if fixture["expected"] == "accept" {
                None
            } else { fixture["error_code"].as_str() };
            assert_eq!(failure(&fixture["payload"], &current), expected, "{name}");
        }
    }
    let submission = read_fixture("positive/business-rpc-scoped.json")?;
    let request: respire_protocol::RpcRequest = serde_json::from_value(submission["payload"].clone())?;
    assert_eq!(serde_json::to_value(request)?, submission["payload"]);
    let completed = read_fixture("positive/rpc-response-completed.json")?;
    let response: respire_protocol::RpcResponse<Value> =
        serde_json::from_value(completed["payload"]["response"].clone())?;
    assert_eq!(serde_json::to_value(response)?, completed["payload"]["response"]);
    let query = read_fixture("positive/runtime-result-scoped.json")?;
    assert_ne!(submission["payload"]["id"], query["payload"]["id"]);
    assert_eq!(query["payload"]["args"][0], submission["payload"]["operation_id"]);
    assert_eq!(query["payload"]["scope"], submission["payload"]["scope"]);
    assert_eq!(current.generation, health["payload"]["generation"].as_u64().context("wire generation")?);
    Ok(())
}

#[test]
fn business_request_scope_uses_the_health_wire_identity() -> Result<()> {
    use respire_protocol::RuntimeRequestScope;
    let health = read_fixture("positive/health-identity.json")?;
    let wire = json!({
        "account_id": health["payload"]["account_id"],
        "instance_id": health["payload"]["instance_id"],
        "generation": health["payload"]["generation"],
    });
    let scope: RuntimeRequestScope = serde_json::from_value(wire.clone())?;
    assert!(!scope.account_id.is_empty());
    assert!(!scope.instance_id.is_empty());
    assert!(scope.generation > 0);
    assert_eq!(serde_json::to_value(scope)?, wire);
    for key in ["account_id", "instance_id", "generation"] {
        let mut missing = wire.clone();
        missing.as_object_mut().context("scope object")?.remove(key);
        assert!(serde_json::from_value::<RuntimeRequestScope>(missing).is_err());
        let mut null = wire.clone();
        null[key] = Value::Null;
        assert!(serde_json::from_value::<RuntimeRequestScope>(null).is_err());
    }
    let mut unknown = wire.clone();
    unknown["unexpected"] = json!(true);
    assert!(serde_json::from_value::<RuntimeRequestScope>(unknown).is_err());
    let mut wrong_generation = wire;
    wrong_generation["generation"] = json!("1");
    assert!(serde_json::from_value::<RuntimeRequestScope>(wrong_generation).is_err());
    Ok(())
}

#[test]
fn final_stop_receipt_round_trips_the_producer_wire_type() -> Result<()> {
    use respire_protocol::{RuntimeStopOutcome, RuntimeStopReceipt};
    for (name, outcome) in [
        ("positive/stop-final-forced-timeout.json", RuntimeStopOutcome::ForcedTimeout),
        ("positive/stop-final-compatibility-timeout.json", RuntimeStopOutcome::CompatibilityTimeout),
    ] {
        let fixture = read_fixture(name)?;
        let receipt: RuntimeStopReceipt = serde_json::from_value(fixture["payload"].clone())?;
        assert_eq!(receipt.state, outcome);
        assert_ne!(receipt.state, RuntimeStopOutcome::Drained);
        assert!(!receipt.unfinished.is_empty());
        assert!(receipt.unfinished.iter().all(|operation|
            !operation.operation_id.is_empty() && matches!(operation.result, respire_protocol::RuntimeUnfinishedOutcome::Aborted | respire_protocol::RuntimeUnfinishedOutcome::Unknown)));
        assert_eq!(serde_json::to_value(receipt)?, fixture["payload"]);
    }
    let fabricated = read_fixture("negative/stop-final-fabricated-completion.json")?;
    assert_eq!(fabricated["error_code"], "stop_outcome_invalid");
    assert_eq!(fabricated["payload"]["unfinished"][0]["result"], "completed");
    assert!(serde_json::from_value::<respire_protocol::RuntimeStopReceipt>(
        fabricated["payload"].clone()
    ).is_err());
    let fixture = read_fixture("positive/stop-final-drained.json")?;
    let receipt: RuntimeStopReceipt = serde_json::from_value(fixture["payload"].clone())?;
    assert_eq!(receipt.schema_version, 1);
    assert_eq!(receipt.state, RuntimeStopOutcome::Drained);
    assert!(receipt.unfinished.is_empty());
    assert_eq!(serde_json::to_value(&receipt)?, fixture["payload"]);
    let identity = read_fixture("positive/health-identity.json")?;
    let wire = serde_json::to_value(receipt)?;
    for key in [
        "installation_id",
        "instance_id",
        "pid",
        "process_start_id",
        "image_path",
        "image_sha256",
        "runtime_version",
        "account_id",
        "generation",
    ] {
        assert_eq!(
            wire[key], identity["payload"][key],
            "identity mismatch: {key}"
        );
    }
    Ok(())
}

#[test]
fn negative_release_fixtures_have_detectable_violations() -> Result<()> {
    let conflicting = read_fixture("negative/release-metadata-conflicting-hash.json")?;
    assert_eq!(conflicting["error_code"], "metadata_alias_conflict");
    assert_ne!(
        conflicting["payload"]["archive_sha256"],
        conflicting["payload"]["sha256"]
    );
    assert_ne!(
        conflicting["payload"]["target_triple"],
        conflicting["payload"]["triple"]
    );

    let missing = read_fixture("negative/release-metadata-missing-binary-hash.json")?;
    assert_eq!(missing["error_code"], "missing_binary_sha256");
    assert!(missing["payload"].get("binary_sha256").is_none());

    let wrong_target = read_fixture("negative/release-metadata-wrong-target.json")?;
    assert_eq!(wrong_target["error_code"], "target_mismatch");
    let target = wrong_target["payload"]["target_triple"]
        .as_str()
        .context("wrong-target fixture names its target")?;
    let archive_name = wrong_target["payload"]["archive_file"]
        .as_str()
        .context("wrong-target fixture names its archive")?;
    assert!(!archive_name.contains(target));
    Ok(())
}


// Fixture-only counterpart of the read-only CLI response checker.
fn response_failure(payload: &Value) -> Option<&'static str> {
    let request = &payload["request"];
    let response = &payload["response"];
    if response["v"].as_u64() != Some(1) || response["id"] != request["id"]
        || response["code"] == "protocol_version_mismatch"
    {
        return Some("response_header_mismatch");
    }
    let Some(exit) = response["exit"].as_u64() else { return Some("response_status_mismatch"); };
    if response["ok"].as_bool() != Some(exit == 0) { return Some("response_status_mismatch"); }
    for (key, error) in [("operation_id", "response_operation_mismatch"),
        ("idempotency_key", "response_key_mismatch")]
    {
        if response.get(key).is_some_and(|value| value != &request[key]) { return Some(error); }
    }
    if matches!(response["code"].as_str(), Some("scope_required" | "scope_mismatch")) {
        if exit == 0 || response.get("envelope").filter(|value| !value.is_null())
            .is_some_and(|envelope| envelope["status"] != "fail")
        { return Some("response_status_mismatch"); }
        if let Some(scope) = response.get("scope").filter(|value| !value.is_null()) {
            if serde_json::from_value::<respire_protocol::RuntimeRequestScope>(scope.clone()).is_err() {
                return Some("response_scope_mismatch");
            }
        }
        return None;
    }
    let receipt = if request["method"] == "runtime.result" { &response["envelope"]["summary"] } else { response };
    if receipt["operation_id"] != request["operation_id"] { return Some("response_operation_mismatch"); }
    if serde_json::from_value::<respire_protocol::RuntimeRequestScope>(receipt["scope"].clone()).is_err()
        || receipt["scope"] != request["scope"]
    { return Some("response_scope_mismatch"); }
    if receipt.get("idempotency_key").is_some_and(|key| key != &request["idempotency_key"]) {
        return Some("response_key_mismatch");
    }
    if request["method"] == "runtime.result" {
        if receipt["request_id"] != request["id"] { return Some("response_result_request_mismatch"); }
        if response.get("scope").is_some_and(|scope| scope != &receipt["scope"]) {
            return Some("response_scope_mismatch");
        }
    }
    if let Some(cached) = payload.get("cached_response") {
        let mut replay = response.clone();
        replay["id"] = cached["id"].clone();
        if &replay != cached { return Some("response_replay_mismatch"); }
    }
    None
}

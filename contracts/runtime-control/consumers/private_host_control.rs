// Included by the existing CLI and protocol integration-test suites, not a runner.
use anyhow::{Context, Result};
use serde_json::Value;

fn pattern_matches(value: &str, pattern: &str) -> bool {
    let lower_hex = |text: &str| text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    match pattern {
        "^[0-9a-f]{64}$" | "^[a-f0-9]{64}$" => value.len() == 64 && lower_hex(value),
        "^[A-Za-z0-9][A-Za-z0-9_.-]*$" => value.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "^0[xX][0-9a-fA-F]+$" => value.len() > 2 && (value.starts_with("0x") || value.starts_with("0X"))
            && value[2..].bytes().all(|b| b.is_ascii_hexdigit()),
        "^[A-Za-z][A-Za-z0-9_]*$" => value.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "^[a-z][a-z0-9_]*$" => value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "^Npu: " => value.starts_with("Npu: "),
        "^(CPU|Host|Gpu: DmlExecutionProvider|Npu: [A-Za-z][A-Za-z0-9_]*)$" =>
            matches!(value, "CPU" | "Host" | "Gpu: DmlExecutionProvider")
                || value.strip_prefix("Npu: ").is_some_and(|provider| pattern_matches(provider, "^[A-Za-z][A-Za-z0-9_]*$")),
        "^(m3|[a-f0-9]{64})$" => value == "m3" || value.len() == 64 && lower_hex(value),
        "^[0-9a-f]{32}$" => value.len() == 32 && lower_hex(value),
        "^[A-Za-z0-9_.-]+$" => !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" => {
            let parts: Vec<_> = value.split('-').collect();
            parts.len() == 5 && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| p.len() == n && lower_hex(p))
                && parts[2].starts_with('4') && matches!(parts[3].as_bytes().first(), Some(b'8' | b'9' | b'a' | b'b'))
        }
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$" => {
            let parts: Vec<_> = value.split('-').collect();
            parts.len() == 5 && parts.iter().zip([8, 4, 4, 4, 12]).all(|(part, n)|
                part.len() == n && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        }
        _ => false,
    }
}

fn schema_valid(value: &Value, schema: &Value, definitions: &Value) -> bool {
    if let Some(reference) = schema["$ref"].as_str() {
        return reference.strip_prefix("#/$defs/").is_some_and(|key| schema_valid(value, &definitions[key], definitions));
    }
    if schema["allOf"].as_array().is_some_and(|children| children.iter().any(|child| !schema_valid(value, child, definitions))) { return false; }
    if schema.get("not").is_some_and(|child| schema_valid(value, child, definitions)) { return false; }
    if let Some(condition) = schema.get("if") {
        let branch = if schema_valid(value, condition, definitions) { "then" } else { "else" };
        if schema.get(branch).is_some_and(|child| !schema_valid(value, child, definitions)) { return false; }
    }
    for (name, exact) in [("anyOf", false), ("oneOf", true)] {
        if let Some(children) = schema[name].as_array() {
            let count = children.iter().filter(|child| schema_valid(value, child, definitions)).count();
            if count == 0 || exact && count != 1 { return false; }
        }
    }
    if schema.get("const").is_some_and(|expected| value != expected) { return false; }
    if schema["enum"].as_array().is_some_and(|values| !values.contains(value)) { return false; }
    let valid_type = match schema["type"].as_str() {
        Some("null") => value.is_null(), Some("object") => value.is_object(),
        Some("array") => value.is_array(), Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(), Some("integer") => value.as_u64().is_some(),
        None => true, _ => false,
    };
    if !valid_type { return false; }
    if let Some(text) = value.as_str() {
        if schema["minLength"].as_u64().is_some_and(|n| (text.chars().count() as u64) < n)
            || schema["maxLength"].as_u64().is_some_and(|n| text.chars().count() as u64 > n)
            || schema["pattern"].as_str().is_some_and(|pattern| !pattern_matches(text, pattern)) { return false; }
    }
    if let Some(number) = value.as_u64() {
        if schema["minimum"].as_u64().is_some_and(|n| number < n)
            || schema["maximum"].as_u64().is_some_and(|n| number > n) { return false; }
    }
    if let Some(object) = value.as_object() {
        if schema["required"].as_array().is_some_and(|keys| keys.iter().any(|key|
            key.as_str().is_none_or(|key| !object.contains_key(key)))) { return false; }
        for (key, child) in object {
            if let Some(rule) = schema["properties"].get(key) {
                if !schema_valid(child, rule, definitions) { return false; }
            } else if schema["additionalProperties"] == false { return false; }
        }
    }
    if let Some(array) = value.as_array() {
        if schema["uniqueItems"] == true && array.iter().enumerate().any(|(i, item)| array[..i].contains(item)) { return false; }
        if schema["minItems"].as_u64().is_some_and(|n| (array.len() as u64) < n)
            || schema["maxItems"].as_u64().is_some_and(|n| array.len() as u64 > n) { return false; }
        if let Some(rule) = schema.get("items") {
            if array.iter().any(|item| !schema_valid(item, rule, definitions)) { return false; }
        }
    }
    true
}

// Node recomputes byte revisions; Rust binds the digest anchors and calls the real intent implementation.
fn config_fixture_failure(params: &Value, context: &Value) -> Option<&'static str> {
    if context.is_null() { return Some("config_context_mismatch"); }
    if context["candidate_config"] != context["reviewed_candidate_config"] { return Some("config_revision_mismatch"); }
    for key in ["original_config", "original_revision", "candidate_revision"] {
        if params[key] != context[key] { return Some("config_revision_mismatch"); }
    }
    if params["target_profile"] != params["binding"]["profile"]
        || params["source_profile"] != context["source_profile"] || params["target_profile"] != context["target_profile"]
        || params["source_identity"] != context["source_identity"] || params["identity"] != context["target_identity"] {
        return Some("config_context_mismatch");
    }
    let original: Value = match params["original_config"].as_str() {
        Some(text) => match serde_json::from_str(text) { Ok(value) => value, Err(_) => return Some("config_intent_mismatch") },
        None => serde_json::json!({}),
    };
    let candidate: Value = match context["candidate_config"].as_str().and_then(|text| serde_json::from_str(text).ok()) {
        Some(value) => value, None => return Some("config_intent_mismatch"),
    };
    let intent: respire_protocol::config_control::ConfigChangeIntent = match serde_json::from_value(params["intent"].clone()) {
        Ok(value) => value, Err(_) => return Some("config_intent_mismatch"),
    };
    if intent.apply(&original).ok().as_ref() != Some(&candidate) { return Some("config_intent_mismatch"); }
    None
}

fn fixed_write_model_failure(payload: &Value, params: &Value, kind: &str, schema: &Value) -> Option<&'static str> {
    if !matches!(kind, "identityWriteResult" | "keyResult" | "modelMaintenanceReceipt") { return None; }
    let definitions = &schema["$defs"];
    let result = &payload["result"];
    let binding = &params["binding"];
    if kind != "modelMaintenanceReceipt" {
        let context = &payload["write_context"];
        if !schema_valid(context, &definitions["writeContext"], definitions)
            || context["installation_root"] != binding["installation_root"] || context["profile"] != binding["profile"]
            || context["source_identity"] != params["source_identity"] || context["operation"] != params["operation"]
            || context["operation_id"] != payload["request"]["operation_id"] || context["idempotency_key"] != payload["request"]["idempotency_key"] {
            return Some("write_context_mismatch");
        }
        // Node and Go recompute SHA-256; Rust binds the declared complete intent and digest anchor.
        if result["fingerprint"] != context["fingerprint"] { return Some("host_fingerprint_mismatch"); }
        if result["operation"] != params["operation"] { return Some("write_context_mismatch"); }
        let before = &params["identity"];
        let after = &result["identity"];
        let account = if before["kind"] == "bound" { &before["account_id"] } else { &Value::Null };
        if binding["expected_account_id"] != *account { return Some("write_identity_mismatch"); }
        let full = kind == "identityWriteResult" && params["operation"]["kind"] == "logout" && params["operation"]["full"] == true;
        let changed = if after["kind"] == "absent" { before["kind"] != "absent" && !full }
            else { before["kind"] != after["kind"] || if after["kind"] == "bound" {
                before["account_id"] != after["account_id"]
            } else { before["operation_id"] != after["operation_id"] } };
        if changed { return Some("write_identity_mismatch"); }
        if kind == "identityWriteResult" {
            let revoke = &result["revoke"];
            let revoke_id = revoke["session_id"].as_str().map(str::to_ascii_lowercase);
            let requested_id = params["operation"]["session_id"].as_str().map(str::to_ascii_lowercase);
            if result["path"] != format!("{}/session.json", binding["profile"].as_str()?)
                || result["session_sha256"] != after["session_sha256"]
                || full && result["outcome"] == "committed" && after["kind"] != "absent"
                || params["operation"]["kind"] == "logout" && !revoke.is_null()
                || params["operation"]["kind"] == "session_revoke" && ((!revoke.is_null() && revoke_id != requested_id)
                    || result["outcome"] == "committed" && revoke.is_null()) { return Some("write_identity_mismatch"); }
        } else {
            let committed = result["outcome"] == "committed";
            if result["source_profile"] != binding["profile"] || !result["target_profile"].is_null() && result["target_profile"] != binding["profile"]
                || committed && (result["target_profile"] != binding["profile"] || after["kind"] != "bound"
                    || result["account_id"] != after["account_id"] || result["session_sha256"] != after["session_sha256"]
                    || result["super_password"].as_str().is_none_or(str::is_empty))
                || !committed && ["super_password", "account_id", "session_sha256"].iter().any(|key| !result[key].is_null())
                || (result["outcome"] == "awaiting_input") != result["required_inputs"].as_array().is_some_and(|items| !items.is_empty()) {
                return Some("write_identity_mismatch");
            }
        }
    } else {
        let plan = &result["plan"];
        if params["phase"] != "plan" && params["expected"] != plan["review"] { return Some("model_review_mismatch"); }
        if plan["kind"] != params["kind"] || result["phase"] != params["phase"]
            || result["verified"] != (params["phase"] != "plan") || result["config_applied"] != (params["phase"] == "apply")
            || params["kind"] == "reset_cpu" && (plan["cpu_candidate_sha256"].is_null()
                || ["preparation", "catalog", "uninstall_directory"].iter().any(|key| !plan[key].is_null()))
            || params["kind"] == "uninstall_m3" && (plan["uninstall_directory"].is_null()
                || ["cpu_candidate_sha256", "preparation", "catalog"].iter().any(|key| !plan[key].is_null()))
            || params["kind"] == "install_engines" && (!plan["uninstall_directory"].is_null() || !plan["cpu_candidate_sha256"].is_null()
                || plan["preparation"].is_null() != plan["catalog"].is_null() || !plan["catalog"].is_null()
                && plan["catalog"]["destination"] != format!("{}/engines/winml-2.4.89/Microsoft.Windows.AI.MachineLearning.dll", binding["installation_root"].as_str()?)) {
            return Some("model_receipt_mismatch");
        }
    }
    let model = kind == "modelMaintenanceReceipt";
    let envelope = &payload[if model { "public_response" } else { "private_response" }];
    let rule = if model { "modelMaintenanceEnvelope" } else if kind == "keyResult" { "keyEnvelope" } else { "identityWriteEnvelope" };
    let status = if model { "ok" } else if result["outcome"] == "unknown" { "fail" }
        else if matches!(result["outcome"].as_str(), Some("pending" | "awaiting_input")) { "pending" } else { "ok" };
    if !schema_valid(envelope, &definitions[rule], definitions) || envelope["status"] != status
        || envelope[if model { "details" } else { "summary" }] != *result
        || model && envelope["summary"] != serde_json::json!({"kind":params["kind"],"phase":params["phase"],"verified":result["verified"]}) {
        return Some("host_result_invalid");
    }
    for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
        let items = envelope["items"].as_array()?;
        let matching: Vec<_> = items.iter().filter(|item| item["name"] == name).collect();
        if matching.len() != 1 || matching[0]["status"] != status || matching[0]["value"] != value { return Some("host_result_invalid"); }
    }
    None
}

fn failure(payload: &Value, schema: &Value) -> Option<&'static str> {
    if payload["channel"] != "inherited_pipe" { return Some("private_channel_required"); }
    let definitions = &schema["$defs"];
    if !schema_valid(payload, &definitions["case"], definitions) { return Some("host_request_invalid"); }
    let request = &payload["request"];
    let method = request["method"].as_str()?;
    let spec = &schema["x-methods"][method];
    if matches!(spec["result"].as_str(), Some("secretResult" | "keysExportResult" | "identityWriteResult" | "keyResult"))
        && payload.get("public_response").is_some() { return Some("private_secret_exposure"); }
    let mutable = spec["mutable"] == true;
    if mutable && (request["operation_id"].is_null() || request["idempotency_key"].is_null()) { return Some("host_operation_required"); }
    if !mutable && (!request["operation_id"].is_null() || !request["idempotency_key"].is_null()) { return Some("host_request_invalid"); }
    let params: Value = match request["args"][0].as_str().and_then(|text| serde_json::from_str(text).ok()) {
        Some(params) => params, None => return Some("host_params_invalid"),
    };
    if !schema_valid(&params, &definitions[spec["params"].as_str()?], definitions) { return Some("host_params_invalid"); }
    if spec["params"] == "identityWriteParams" && method != "control.identity.write_result"
        && (method == "control.identity.logout") != (params["operation"]["kind"] == "logout") { return Some("host_params_invalid"); }
    if spec["params"] == "modelMaintenanceParams" && ((params["phase"] == "plan") != params["expected"].is_null()
        || params["phase"] == "apply" && params["kind"] != "reset_cpu"
        || params["phase"] == "verify" && params["kind"] == "reset_cpu") { return Some("host_params_invalid"); }
    if spec["params"] == "modelParams" && if method == "control.model_install_plan" {
        !params["selection_sha256"].is_null()
    } else { params["selection_sha256"].is_null() } { return Some("host_params_invalid"); }
    let snapshot = method == "control.snapshot_maintenance";
    let verified = method == "control.auth.account_complete" || snapshot && matches!(params["action"].as_str(), Some("commit" | "release"));
    if payload["maintenance_phase"] != if verified { "Verified" } else { "Paused" } { return Some("maintenance_phase_mismatch"); }
    if !payload["original_operation_id"].is_null() && payload["original_operation_id"] != request["operation_id"] { return Some("host_operation_mismatch"); }
    if snapshot {
        if params["operation_id"] != request["operation_id"] { return Some("host_operation_mismatch"); }
        // Node independently recomputes the SHA-256 tuple; Rust binds the frozen anchor.
        if params["request_fingerprint"] != payload["original_fingerprint"] { return Some("host_fingerprint_mismatch"); }
    }
    if spec["params"] == "configParams" {
        if let Some(error) = config_fixture_failure(&params, &payload["config_context"]) { return Some(error); }
    }
    let Some(result) = payload.get("result") else {
        return if payload["finish_maintenance"] == true { Some("maintenance_not_terminal") } else { None };
    };
    let kind = spec["result"].as_str()?;
    if !schema_valid(result, &definitions[kind], definitions) { return Some("host_result_invalid"); }
    if mutable && result["operation_id"] != request["operation_id"] { return Some("host_operation_mismatch"); }
    if let Some(error) = fixed_write_model_failure(payload, &params, kind, schema) { return Some(error); }
    if matches!(kind, "identityResult" | "configReceipt") {
        let envelope = &payload["private_response"];
        let envelope_kind = if kind == "identityResult" { "identityEnvelope" } else { "configEnvelope" };
        let result_field = if kind == "identityResult" { "details" } else { "summary" };
        if !schema_valid(envelope, &definitions[envelope_kind], definitions) || envelope[result_field] != *result {
            return Some("host_result_invalid");
        }
        for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
            let Some(items) = envelope["items"].as_array() else { return Some("host_result_invalid"); };
            let matching: Vec<_> = items.iter().filter(|item| item["name"] == name).collect();
            if matching.len() != 1 || matching[0]["status"] != status || matching[0]["value"] != value { return Some("host_result_invalid"); }
        }
        if kind == "configReceipt" {
            for (receipt, parameter) in [("original_revision", "original_revision"), ("candidate_revision", "candidate_revision"),
                ("source_profile", "source_profile"), ("target_profile", "target_profile"),
                ("source_identity", "source_identity"), ("target_identity", "identity")] {
                if result[receipt] != params[parameter] { return Some("config_receipt_mismatch"); }
            }
            let a: respire_protocol::config_control::ConfigChangeIntent = match serde_json::from_value(result["intent"].clone()) {
                Ok(value) => value, Err(_) => return Some("config_receipt_mismatch"),
            };
            let b: respire_protocol::config_control::ConfigChangeIntent = match serde_json::from_value(params["intent"].clone()) {
                Ok(value) => value, Err(_) => return Some("config_receipt_mismatch"),
            };
            if a != b { return Some("config_receipt_mismatch"); }
        }
    }

    if kind == "modelPlan" && result["assets"]["assets"] != result["assets"]["missing"] { return Some("host_result_invalid"); }
    if matches!(kind, "modelPlan" | "modelVerify") {
        if kind == "modelVerify" && result["selection_sha256"] != params["selection_sha256"] { return Some("host_selection_mismatch"); }
        let envelope = &payload["public_response"];
        let command = if kind == "modelPlan" { "model-install-plan" } else { "model-install-verify" };
        if !schema_valid(envelope, &definitions["modelEnvelope"], definitions)
            || envelope["command"] != command || envelope["details"] != *result
            || envelope["summary"]["complete"] != result["assets"]["complete"] { return Some("host_result_invalid"); }
        for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
            let Some(items) = envelope["items"].as_array() else { return Some("host_result_invalid"); };
            let matching: Vec<_> = items.iter().filter(|item| item["name"] == name).collect();
            if matching.len() != 1 || matching[0]["status"] != status || matching[0]["value"] != value { return Some("host_result_invalid"); }
        }
        if let Some(evidence) = result["assets"]["backend_load"].get("evidence") {
            if evidence["selected"].as_str().and_then(|selected| selected.strip_prefix("Npu: "))
                .is_some_and(|provider| evidence["provider"] != provider) { return Some("host_result_invalid"); }
            if let Some(modules) = evidence["modules"].as_array() {
                if modules.iter().enumerate().any(|(i, module)| modules[..i].iter().any(|previous| previous["id"] == module["id"])) { return Some("host_result_invalid"); }
            }
        }
    }
    let outcome = result["outcome"].as_str();
    if kind == "accountResult" {
        if matches!(outcome, Some("awaiting_verification" | "committed"))
            && ["target_profile", "account_id", "session_sha256"].iter().any(|key| result[key].is_null()) { return Some("host_result_invalid"); }
        if outcome == Some("rolled_back") && ["account_id", "session_sha256", "super_password"].iter().any(|key| !result[key].is_null()) { return Some("host_result_invalid"); }
    }
    if snapshot {
        if result["request_fingerprint"] != params["request_fingerprint"] || result["snapshot_id"] != params["snapshot_id"] { return Some("host_fingerprint_mismatch"); }
        if let Some(history) = payload["history"].as_array() {
            for previous in history {
                if previous["operation_id"] != request["operation_id"] { continue; }
                if previous["request_fingerprint"] != params["request_fingerprint"] || previous["snapshot_id"] != params["snapshot_id"]
                    || matches!(previous["state"].as_str(), Some("released" | "rolled_back")) && previous["state"] != result["state"]
                    || previous["state"] == "verified" && !matches!(result["state"].as_str(), Some("verified" | "released")) { return Some("terminal_history_conflict"); }
            }
        }
    }
    let terminal = kind == "accountResult" && matches!(outcome, Some("committed" | "rolled_back"))
        || snapshot && matches!(result["state"].as_str(), Some("released" | "rolled_back"));
    if payload["finish_maintenance"] == true && !terminal { return Some("maintenance_not_terminal"); }
    None
}

fn producer_types(payload: &Value) -> Result<()> {
    use respire_protocol::host_control::*;
    let request: respire_protocol::RpcRequest = serde_json::from_value(payload["request"].clone())?;
    let params: Value = serde_json::from_str(request.args.first().context("one host argument")?)?;
    match request.method.as_str() {
        HOST_AUTH_KEYGEN_METHOD | HOST_AUTH_RESULT_METHOD => { serde_json::from_value::<HostAuthKeygenParams>(params)?; }
        HOST_AUTH_REGISTER_METHOD => { serde_json::from_value::<HostAuthRegisterParams>(params)?; }
        HOST_AUTH_LOGIN_METHOD => {
            let parsed: HostAuthLoginParams = serde_json::from_value(params.clone())?;
            let wire = serde_json::to_value(&parsed)?;
            if let Some(value) = params.get("super_password").filter(|value| !value.is_null()) {
                assert_eq!(parsed.super_password.as_deref(), Some(value.as_str().context("super password string")?));
                assert_eq!(&wire["super_password"], value);
            } else {
                assert!(parsed.super_password.is_none());
                assert!(wire.get("super_password").is_none());
            }
            if let Some(continuation) = params.get("continuation").filter(|value| !value.is_null()) {
                assert!(parsed.continuation.is_some());
                for (key, value) in continuation.as_object().context("continuation object")? {
                    assert_eq!(&wire["continuation"][key], value);
                }
            } else { assert!(parsed.continuation.is_none()); }
        }
        HOST_AUTH_ACCOUNT_RESULT_METHOD | HOST_AUTH_ACCOUNT_COMPLETE_METHOD | HOST_AUTH_ACCOUNT_ROLLBACK_METHOD => { serde_json::from_value::<HostAuthAccountParams>(params)?; }
        "control.model_install_plan" | "control.model_install_verify" => { serde_json::from_value::<respire_protocol::HostModelParams>(params)?; }
        "control.snapshot_maintenance" => { serde_json::from_value::<respire_protocol::maintenance_control::MaintenanceControlParams>(params)?; }
        "control.secret.read" => { serde_json::from_value::<respire_protocol::secret_control::HostSecretReadParams>(params)?; }
        "control.keys_export.read" => { serde_json::from_value::<respire_protocol::secret_control::HostKeysExportReadParams>(params)?; }
        "control.identity.session_list" => { serde_json::from_value::<respire_protocol::identity_control::HostIdentitySessionListParams>(params)?; }
        "control.config_validate" => { serde_json::from_value::<respire_protocol::config_control::ConfigValidateParams>(params)?; }
        "control.identity.logout" | "control.identity.session_revoke" | "control.identity.write_result" => {
            serde_json::from_value::<respire_protocol::identity_write_control::HostIdentityWriteParams>(params)?;
        }
        "control.key.super_reset" | "control.key.result" | "control.key.rollback" => {
            serde_json::from_value::<respire_protocol::key_control::HostKeyParams>(params)?;
        }
        "control.model_maintenance" => {
            serde_json::from_value::<respire_protocol::model_maintenance::ModelMaintenanceParams>(params)?;
        }
        _ => anyhow::bail!("unsupported frozen method"),
    }
    if let Some(result) = payload.get("result") {
        match request.method.as_str() {
            HOST_AUTH_KEYGEN_METHOD | HOST_AUTH_RESULT_METHOD => { serde_json::from_value::<HostAuthResult>(result.clone())?; }
            "control.model_install_plan" => {
                let plan: respire_protocol::ModelPreparation = serde_json::from_value(result.clone())?;
                assert!(!plan.assets.complete && plan.assets.backend_load.is_none() && plan.assets.assets == plan.assets.missing);
            }
            "control.model_install_verify" => { serde_json::from_value::<respire_protocol::ModelPreparation>(result.clone())?; }
            "control.snapshot_maintenance" => { serde_json::from_value::<respire_protocol::maintenance_control::MaintenanceControlResult>(result.clone())?; }
            "control.secret.read" => { serde_json::from_value::<respire_protocol::secret_control::HostSecretReadResult>(result.clone())?; }
            "control.keys_export.read" => { serde_json::from_value::<respire_protocol::secret_control::HostKeysExportReadResult>(result.clone())?; }
            "control.identity.session_list" => { serde_json::from_value::<respire_protocol::identity_control::HostIdentitySessionListResult>(result.clone())?; }
            "control.config_validate" => { serde_json::from_value::<respire_protocol::config_control::ConfigValidationReceipt>(result.clone())?; }
            "control.identity.logout" | "control.identity.session_revoke" | "control.identity.write_result" => {
                serde_json::from_value::<respire_protocol::identity_write_control::HostIdentityWriteResult>(result.clone())?;
            }
            "control.key.super_reset" | "control.key.result" | "control.key.rollback" => {
                serde_json::from_value::<respire_protocol::key_control::HostKeyResult>(result.clone())?;
            }
            "control.model_maintenance" => {
                serde_json::from_value::<respire_protocol::model_maintenance::ModelMaintenanceReceipt>(result.clone())?;
            }
            _ => {
                let parsed: HostAuthAccountResult = serde_json::from_value(result.clone())?;
                if result["outcome"] == "awaiting_input" {
                    assert_eq!(parsed.outcome, HostAuthAccountOutcome::AwaitingInput);
                    assert!(!parsed.login.context("awaiting input status")?.required_inputs.is_empty());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn frozen_private_host_control_fixtures() -> Result<()> {
    let root = super::contract_root()?;
    let schema: Value = serde_json::from_slice(&std::fs::read(root.join("schema/private-host-control.schema.json"))?)?;
    let manifest: Value = serde_json::from_slice(&std::fs::read(root.join("manifest.json"))?)?;
    let mut count = 0;
    for group in ["positive", "negative"] {
        for path in manifest["fixtures"][group].as_array().context("fixture group")? {
            let path = path.as_str().context("fixture path")?;
            let fixture: Value = serde_json::from_slice(&std::fs::read(root.join(path))?)?;
            if fixture["fixture_type"] != "private_host_control" { continue; }
            let expected = if fixture["expected"] == "accept" { None } else { fixture["error_code"].as_str() };
            assert_eq!(failure(&fixture["payload"], &schema), expected, "{path}");
            if expected.is_none() { producer_types(&fixture["payload"])?; }
            if matches!(path.rsplit('/').next(), Some("host-auth-login-super-type.json"
                | "host-auth-continuation-unknown.json" | "host-auth-continuation-type.json"
                | "host-auth-login-status-unknown.json" | "host-secret-unknown.json"
                | "host-keys-export-out.json" | "host-secret-result-unknown.json"
                | "host-identity-argv.json" | "host-identity-unknown.json" | "host-identity-result-unknown.json"
                | "host-config-argv.json" | "host-config-unknown.json" | "host-config-intent-unknown.json"
                | "host-config-receipt-unknown.json"
                | "host-identity-write-argv.json" | "host-identity-write-params-unknown.json" | "host-identity-write-result-unknown.json"
                | "host-key-write-argv.json" | "host-key-write-params-unknown.json" | "host-key-write-result-unknown.json"
                | "host-key-write-input-type.json" | "host-key-write-input-unknown.json"
                | "host-model-maintenance-argv.json" | "host-model-maintenance-params-unknown.json"
                | "host-model-maintenance-result-unknown.json" | "host-model-maintenance-secret.json")) {
                assert!(producer_types(&fixture["payload"]).is_err(), "{path}: DTO must reject invalid fields");
            }
            count += 1;
        }
    }
    assert_eq!(count, 204);
    Ok(())
}

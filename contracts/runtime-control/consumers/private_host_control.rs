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
        "^[A-Za-z0-9_-]+$" => !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
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
            if result["verification_required"] == true || result["source_profile"] != binding["profile"] || !result["target_profile"].is_null() && result["target_profile"] != binding["profile"]
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

fn key_migration_failure(payload: &Value, params: &Value, kind: &str, schema: &Value) -> Option<&'static str> {
    let definitions = &schema["$defs"];
    let (request, result, binding) = (&payload["request"], &payload["result"], &params["binding"]);
    if kind == "keyResult" && params["operation"]["kind"] == "fivekeys" {
        let (context, write) = (&payload["key_context"], &payload["write_context"]);
        if !schema_valid(context, &definitions["keyContext"], definitions)
            || !schema_valid(write, &definitions["writeContext"], definitions)
            || write["installation_root"] != binding["installation_root"] || write["source_identity"] != params["source_identity"]
            || write["operation"] != params["operation"] || write["operation_id"] != request["operation_id"]
            || write["idempotency_key"] != request["idempotency_key"] || binding["profile"] != context["launch_profile"]
            || params["identity"] != context["launch_identity"] { return Some("write_context_mismatch"); }
        // Node/Go hash the producer preimage; this serde-only consumer binds its frozen anchor.
        if write["fingerprint"] != result["fingerprint"] { return Some("host_fingerprint_mismatch"); }
        let account = if params["identity"]["kind"] == "bound" { &params["identity"]["account_id"] } else { &Value::Null };
        if result["operation"] != params["operation"] || result["source_profile"] != write["profile"]
            || result["identity"] != context["selected_identity"] || binding["expected_account_id"] != *account {
            return Some("write_identity_mismatch");
        }
        let inputs = result["required_inputs"].as_array()?;
        if !result["super_password"].is_null() || inputs.iter().any(|field|
            !matches!(field.as_str(), Some("password" | "super_password" | "account_secret" | "totp"))) {
            return Some("private_secret_exposure");
        }
        let applied = result["verification_required"] == true || result["outcome"] == "committed";
        if applied {
            if result["target_profile"] != context["target_profile"] || context["selected_profile"] != context["target_profile"]
                || result["identity"] != context["target_identity"] || result["identity"]["kind"] != "bound"
                || result["account_id"] != context["target_identity"]["account_id"]
                || result["session_sha256"] != result["identity"]["session_sha256"] || !inputs.is_empty()
                || if result["verification_required"] == true { result["outcome"] != "pending" } else { result["outcome"] != "committed" }
                || result["outcome"] == "committed" && context["verified"] != true
                || binding["profile"] != write["profile"] && binding["profile"] != context["target_profile"] {
                return Some("write_identity_mismatch");
            }
        } else if !result["account_id"].is_null() || !result["session_sha256"].is_null()
            || result["identity"] != params["source_identity"] || context["selected_profile"] != write["profile"]
            || (result["outcome"] == "awaiting_input") != !inputs.is_empty() { return Some("write_identity_mismatch"); }
        if request["method"] == "control.key.complete" && (!applied || result["outcome"] != "committed" || result["verification_required"] == true || context["verified"] != true
            || binding["profile"] != context["target_profile"] || params["identity"] != context["target_identity"]
            || !params["input"].is_null()) { return Some("key_completion_mismatch"); }
        if context["input_state"] == "initial" && request["method"] == "control.key.fivekeys" && params["input"]["password"].is_null()
            && !(result["outcome"] == "awaiting_input" && inputs.iter().any(|field| field == "password")) { return Some("key_input_mismatch"); }
        if context["input_state"] == "continuation" && (payload["original_operation_id"] != request["operation_id"]
            || !params["input"]["totp"].is_string()) { return Some("key_input_mismatch"); }
    } else if kind == "migrationResult" {
        let (original, context) = (&params["original"], &payload["migration_context"]);
        if !schema_valid(context, &definitions["migrationContext"], definitions) { return Some("migration_context_mismatch"); }
        if original["operation_id"] != request["operation_id"] || original["key"] != request["idempotency_key"]
            || original["key"] != original["operation_id"] { return Some("host_operation_mismatch"); }
        if original["installation_root"] != binding["installation_root"] || original["profile"] != binding["profile"]
            || original["identity"] != params["identity"] || result["identity"] != original["identity"]
            || binding["expected_account_id"] != if original["identity"]["kind"] == "bound" { original["identity"]["account_id"].clone() } else { Value::Null }
            || original["source_id"] != context["source_id"] || original["account"] != context["account"] {
            return Some("migration_context_mismatch");
        }
        let operation: respire_protocol::migration_control::HostMigrationOperation = match serde_json::from_value(original.clone()) {
            Ok(value) => value, Err(_) => return Some("host_params_invalid"),
        };
        if original["fingerprint"] != result["fingerprint"] || operation.fingerprint_bytes().ok().as_deref()
            != context["fingerprint_preimage"].as_str().map(str::as_bytes) { return Some("host_fingerprint_mismatch"); }
        let destination = format!("{}/accounts/{}", original["installation_root"].as_str()?, original["account"].as_str()?);
        let marker = &context["marker"];
        if result["outcome"] == "completed" {
            if context["publication"] != "bound" || marker["control"] != *original || marker["schema"] != 2
                || marker["complete"] != true || marker["namespace_migrated"] != true || marker["original_preserved"] != true
                || marker["source_identity"] != original["source_id"] || marker["source"] != context["source"]
                || marker["destination"] != destination || marker["control_result"] != result["details"]
                || result["details"] != serde_json::json!({"state":"migrated","account":original["account"],"dir":destination,
                    "source":context["source"],"original_preserved":true}) { return Some("migration_marker_mismatch"); }
        } else if result["outcome"] == "already_migrated" {
            if request["method"] != "control.migration.profile" || context["publication"] != "legacy_unbound"
                || !marker["control"].is_null() || marker["complete"] != true || marker["source_identity"] != original["source_id"]
                || result["details"]["state"] != "already_migrated" || result["details"]["dir"] != marker["destination"] {
                return Some("migration_marker_mismatch");
            }
        } else if !result["details"].is_null() || context["publication"] == "bound" { return Some("migration_marker_mismatch"); }
    } else { return None; }
    let envelope = &payload["private_response"];
    let rule = if kind == "migrationResult" { "migrationEnvelope" } else { "keyEnvelope" };
    let status = match result["outcome"].as_str() { Some("unknown") => "fail", Some("pending" | "awaiting_input") => "pending", _ => "ok" };
    if !schema_valid(envelope, &definitions[rule], definitions) || envelope["status"] != status
        || envelope["summary"] != *result { return Some("host_result_invalid"); }
    for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
        let items: Vec<_> = envelope["items"].as_array()?.iter().filter(|item| item["name"] == name).collect();
        if items.len() != 1 || items[0]["status"] != status || items[0]["value"] != value { return Some("host_result_invalid"); }
    }
    if !payload["progress"].is_null() || !payload["ledger"].is_null() { return Some("private_secret_exposure"); }
    None
}

// Contexts describe fixture inputs; they are never production grants or journals.
fn profile_recovery_failure(payload: &Value, params: &Value, kind: &str, schema: &Value) -> Option<&'static str> {
    let profile = kind == "profileResult";
    if !profile && kind != "recoveryResult" { return None; }
    let definitions = &schema["$defs"];
    let context = &payload[if profile { "profile_context" } else { "recovery_context" }];
    if !schema_valid(context, &definitions[if profile { "profileContext" } else { "recoveryContext" }], definitions) {
        return Some("profile_recovery_context_mismatch");
    }
    let (request, result, binding, authority) = (&payload["request"], &payload["result"], &params["binding"], &context["authority"]);
    let status_read = request["method"] == "control.auth.recovery_status";
    if authority["installation_root"] != binding["installation_root"] || authority["profile"] != binding["profile"]
        || authority["launch_id"] != binding["launch_id"]
        || authority["identity"] != params["identity"]
        || binding["expected_account_id"] != if params["identity"]["kind"] == "bound" { params["identity"]["account_id"].clone() } else { Value::Null } {
        return Some("profile_recovery_binding_mismatch");
    }
    if authority["grant_maintenance"] != if status_read { "none" } else { "Paused" }
        || authority["owns_auth"] != !status_read || authority["serving_authorized"] != false
        || ["parent_verified", "binding_verified_before"].iter().any(|key| authority[key] != true)
        || (profile || status_read) && authority["binding_verified_after"] != true {
        return Some("profile_recovery_authority_mismatch");
    }
    if !payload["history"].is_null() || !payload["original_fingerprint"].is_null()
        || !profile && !payload["original_operation_id"].is_null()
        || !payload[if profile { "recovery_context" } else { "profile_context" }].is_null() {
        return Some("host_request_invalid");
    }
    if profile {
        let original = &params["original"];
        if original["operation_id"] != request["operation_id"] || original["key"] != request["idempotency_key"]
            || original["key"] != original["operation_id"] { return Some("host_operation_mismatch"); }
        if original["installation_root"] != binding["installation_root"] || original["profile"] != binding["profile"]
            || original["identity"] != params["identity"] || result["identity"] != original["identity"] {
            return Some("profile_recovery_binding_mismatch");
        }
        let operation: respire_protocol::profile_maintenance::HostProfileRemoveOperation = match serde_json::from_value(original.clone()) {
            Ok(value) => value, Err(_) => return Some("host_params_invalid"),
        };
        if original["fingerprint"] != result["fingerprint"] || operation.fingerprint_bytes().ok().as_deref()
            != context["fingerprint_preimage"].as_str().map(str::as_bytes) { return Some("host_fingerprint_mismatch"); }
        let records = context["records"].as_array()?;
        if context["entry_count"].as_u64()? < records.len() as u64
            || records.iter().enumerate().any(|(index, entry)| records[..index].iter().any(|previous|
                previous["original"]["operation_id"] == entry["original"]["operation_id"]
                    || previous["original"]["key"] == entry["original"]["key"])) { return Some("profile_history_conflict"); }
        let previous = records.iter().find(|entry| entry["original"]["operation_id"] == original["operation_id"]
            || entry["original"]["key"] == original["key"]);
        let expected = if let Some(previous) = previous {
            if previous["original"] != *original { return Some("profile_history_conflict"); }
            if context["delete_attempted"] != false { return Some("profile_replay_forbidden"); }
            if previous["phase"] == "committed" { "committed" } else { "unknown" }
        } else if request["method"] == "control.profile.result" {
            if context["delete_attempted"] != false { return Some("profile_replay_forbidden"); }
            "unknown"
        } else {
            if context["entry_count"] == 4096 || context["active"] == true { return Some("profile_admission_blocked"); }
            if context["snapshot_clear"] != true { return Some("profile_snapshot_pending"); }
            let target = format!("{}/accounts/{}", original["installation_root"].as_str()?, original["name"].as_str()?);
            if context["target_path"] != target || context["target_path"] == original["profile"]
                || context["target_identity"] != original["target_identity"] { return Some("profile_target_mismatch"); }
            // Failed effects return an error, not a fabricated typed Unknown receipt.
            if context["delete_attempted"] != true { return Some("profile_receipt_mismatch"); }
            "committed"
        };
        if result["outcome"] != expected { return Some("profile_receipt_mismatch"); }
    } else if status_read {
        if result["state"] != context["journal_state"] || result["recovered"] != false || context["recovery_attempted"] != false {
            return Some("legacy_recovery_mismatch");
        }
    } else {
        if context["journal_state"] == "operation_pending" { return Some("legacy_recovery_forbidden"); }
        let recovered = context["journal_state"] == "legacy_pending";
        if result["state"] != "clear" || result["recovered"] != recovered || context["recovery_attempted"] != recovered {
            return Some("legacy_recovery_mismatch");
        }
    }
    let envelope = &payload["private_response"];
    let status = if profile && result["outcome"] == "unknown" { "fail" } else { "ok" };
    if !schema_valid(envelope, &definitions[if profile { "profileEnvelope" } else { "recoveryEnvelope" }], definitions)
        || envelope["summary"] != *result || envelope["status"] != status { return Some("host_result_invalid"); }
    for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
        let items: Vec<_> = envelope["items"].as_array()?.iter().filter(|item| item["name"] == name).collect();
        if items.len() != 1 || items[0]["status"] != status || items[0]["value"] != value { return Some("host_result_invalid"); }
    }
    let response = &payload["private_rpc_response"];
    let unknown = profile && result["outcome"] == "unknown";
    if !schema_valid(response, &definitions["profileRecoveryResponse"], definitions)
        || response["id"] != request["id"] || response["operation_id"] != request["operation_id"]
        || response["idempotency_key"] != request["idempotency_key"] || response["envelope"] != *envelope
        || response["ok"] != !unknown || response["exit"] != if unknown { 2 } else { 0 }
        || response["code"] != if unknown { serde_json::json!("profile_remove_outcome_unknown") } else { Value::Null } {
        return Some("host_result_invalid");
    }
    None
}

// Fixture authority anchors never create a grant or execute a product.
fn settings_authority_failure(payload: &Value, binding: &Value, context: &Value, identity: &Value, read: bool) -> Option<&'static str> {
    let a = &context["authority"];
    let snapshot = payload["request"]["method"] == "control.snapshot.preflight";
    if a["installation_root"] != binding["installation_root"] || a["profile"] != binding["profile"]
        || a["launch_id"] != binding["launch_id"]
        || binding["expected_account_id"] != if snapshot { Value::Null } else { identity["account_id"].clone() } {
        return Some("settings_binding_mismatch");
    }
    if a["identity"] != *identity || a["serving_authorized"] != false
        || ["parent_verified", "binding_verified_before", "binding_verified_after", "grant_verified", "registration_verified"]
            .iter().any(|key| a[key] != true)
        || a["grant_maintenance"] != if payload["maintenance_phase"] == "Idle" { serde_json::json!("none") } else { payload["maintenance_phase"].clone() }
        || if read { !matches!(payload["maintenance_phase"].as_str(), Some("Idle" | "Starting" | "Verified")) }
            else { payload["maintenance_phase"] != "Paused" } { return Some("settings_authority_mismatch"); }
    None
}

fn offline_read_failure(payload: &Value, schema: &Value) -> Option<&'static str> {
    let (request, result, c, d) = (&payload["request"], &payload["result"], &payload["offline_context"], &schema["$defs"]);
    if payload.get("public_response").is_some() { return Some("private_secret_exposure"); }
    if ["history", "original_operation_id", "original_fingerprint", "config_context", "write_context", "key_context",
        "migration_context", "profile_context", "recovery_context", "metadata_context", "progress", "ledger"].iter().any(|key| payload.get(key).is_some())
        || !request["operation_id"].is_null() || !request["idempotency_key"].is_null() { return Some("host_request_invalid"); }
    let params: Value = match request["args"][0].as_str().and_then(|text| serde_json::from_str(text).ok()) {
        Some(value) => value, None => return Some("host_params_invalid"),
    };
    if !schema_valid(&params, &d["offlineReadParams"], d) { return Some("host_params_invalid"); }
    if !schema_valid(c, &d["offlineReadContext"], d) { return Some("settings_context_mismatch"); }
    if let Some(error) = settings_authority_failure(payload, &params["binding"], c, &c["authority"]["identity"], true) { return Some(error); }
    let snapshot = request["method"] == "control.snapshot.preflight";
    let metadata = request["method"] == "control.metadata.status";
    if if snapshot { c["snapshot_clear"] != true } else { c["auth_recovery_pending"] != false } { return Some("offline_read_blocked"); }
    if c["mutated"] != false { return Some("offline_read_mutation"); }
    if payload["finish_maintenance"] == true { return Some("maintenance_not_terminal"); }
    if !schema_valid(result, &d["offlineEnvelope"], d) || *result != payload["private_response"]
        || result["command"] != if snapshot { "snapshot-preflight" } else if metadata { "metadata" } else { "agent-config" }
        || !schema_valid(&result["summary"], &d[if snapshot { "snapshotPreflightSummary" } else if metadata { "metadataStatusSummary" } else { "agentReadSummary" }], d)
        || if metadata { !schema_valid(&result["details"], &d["metadataStatusDetails"], d)
            || result["summary"]["enabled"] != result["details"]["enabled"] || result["summary"]["mode"] != result["details"]["mode"] }
            else { !result["details"].is_null() } { return Some("host_result_invalid"); }
    for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
        let items: Vec<_> = result["items"].as_array()?.iter().filter(|item| item["name"] == name).collect();
        if items.len() != 1 || items[0]["status"] != status || items[0]["value"] != value { return Some("host_result_invalid"); }
    }
    let r = &payload["private_rpc_response"];
    if r.is_null() || r["id"] != request["id"] || !r["operation_id"].is_null() || !r["idempotency_key"].is_null()
        || r["envelope"] != *result || r["ok"] != true || r["exit"] != 0 || !r["code"].is_null() || !r["data_dir"].is_null() { return Some("host_result_invalid"); }
    None
}

fn settings_write_response_failure(payload: &Value, schema: &Value, envelope_kind: &str, code: &str, profile: Value) -> Option<&'static str> {
    let (request, result, e, r, d) = (&payload["request"], &payload["result"], &payload["private_response"],
        &payload["private_rpc_response"], &schema["$defs"]);
    let unknown = result["outcome"] == "unknown";
    if !schema_valid(e, &d[envelope_kind], d) || e["summary"] != *result
        || e["status"] != if unknown { "fail" } else { "ok" } { return Some("host_result_invalid"); }
    for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
        let items: Vec<_> = e["items"].as_array()?.iter().filter(|item| item["name"] == name).collect();
        if items.len() != 1 || items[0]["status"] != status || items[0]["value"] != value { return Some("host_result_invalid"); }
    }
    if !schema_valid(r, &d["settingsResponse"], d) || r["id"] != request["id"] || r["operation_id"] != request["operation_id"]
        || r["idempotency_key"] != request["idempotency_key"] || r["envelope"] != *e || r["ok"] != !unknown
        || r["exit"] != if unknown { 2 } else { 0 } || r["code"] != if unknown { serde_json::json!(code) } else { Value::Null }
        || r["data_dir"] != profile { return Some("host_result_invalid"); }
    if payload["finish_maintenance"] == true && unknown { return Some("maintenance_not_terminal"); }
    None
}

fn metadata_failure(payload: &Value, schema: &Value) -> Option<&'static str> {
    let (request, result, c, d) = (&payload["request"], &payload["result"], &payload["metadata_context"], &schema["$defs"]);
    if payload.get("public_response").is_some() { return Some("private_secret_exposure"); }
    if ["history", "original_operation_id", "original_fingerprint", "config_context", "write_context", "key_context",
        "migration_context", "profile_context", "recovery_context", "offline_context", "progress", "ledger"]
        .iter().any(|key| payload.get(key).is_some()) { return Some("host_request_invalid"); }
    if request["operation_id"].is_null() || request["idempotency_key"].is_null() { return Some("host_operation_required"); }
    let params: Value = match request["args"][0].as_str().and_then(|text| serde_json::from_str(text).ok()) {
        Some(value) => value, None => return Some("host_params_invalid"),
    };
    if !schema_valid(&params, &d["metadataParams"], d) { return Some("host_params_invalid"); }
    let o = &params["original"];
    let original: respire_protocol::metadata_control::HostMetadataOperation = match serde_json::from_value(o.clone()) {
        Ok(value) => value, Err(_) => return Some("host_params_invalid"),
    };
    let query = request["method"] == "control.metadata.result";
    if original.intent.validate().is_err() || !query && request["method"] != format!("control.metadata.{}", o["intent"]["kind"].as_str()?) {
        return Some("host_params_invalid");
    }
    if o["operation_id"] != request["operation_id"] || o["key"] != o["operation_id"] || o["key"] != request["idempotency_key"] {
        return Some("host_operation_mismatch");
    }
    if o["installation_root"] != params["binding"]["installation_root"] || o["profile"] != params["binding"]["profile"]
        || o["identity"] != params["identity"] { return Some("settings_binding_mismatch"); }
    if !schema_valid(c, &d["metadataContext"], d) { return Some("settings_context_mismatch"); }
    if let Some(error) = settings_authority_failure(payload, &params["binding"], c, &params["identity"], false) { return Some(error); }
    // Node recomputes SHA-256; Rust checks the typed preimage and frozen digest anchor.
    if o["fingerprint"] != c["fingerprint"] || original.fingerprint_bytes().ok().as_deref()
        != c["fingerprint_preimage"].as_str().map(str::as_bytes) { return Some("host_fingerprint_mismatch"); }
    if c["auth_recovery_pending"] != false || c["snapshot_clear"] != true || c["writable"] != true
        || c["memory_off"] != false || c["locks_owned"] != true { return Some("metadata_admission_blocked"); }
    if !schema_valid(result, &d["metadataResult"], d) || result["original"] != *o { return Some("host_result_invalid"); }
    let (before, after) = (&c["receipt_before"], &c["receipt_after"]);
    if !before.is_null() {
        if before["original"] != *o || before["outcome"] != "committed" || before != after { return Some("metadata_history_conflict"); }
        if c["effect_attempted"] != false { return Some("metadata_replay_forbidden"); }
        if result != before { return Some("metadata_receipt_mismatch"); }
    } else if query {
        if c["effect_attempted"] != false || !after.is_null() { return Some("metadata_replay_forbidden"); }
        if result["outcome"] != "unknown" || !result["details"].is_null() { return Some("metadata_receipt_mismatch"); }
    } else if c["effect_attempted"] != true || after.is_null() || after["outcome"] != "committed" || after != result {
        return Some("metadata_receipt_mismatch");
    }
    if result["outcome"] == "committed" && if o["intent"]["kind"] == "disable" {
        result["details"]["enabled"] != false || result["details"]["sync_isolation_retained"] != true
    } else {
        result["details"]["deployment_assurance"] != "operator_attestation_only" || result["details"]["old_client_access_enforced"] != false
            || result["details"]["deployment_review"] != o["intent"]["deployment_review"] || result["details"]["receipt"]["enabled"] != true
            || result["details"]["receipt"]["deployment"]["mode"] != o["intent"]["mode"]
    } { return Some("metadata_receipt_mismatch"); }
    settings_write_response_failure(payload, schema, "metadataEnvelope", "metadata_outcome_unknown", Value::Null)
}

fn failure(payload: &Value, schema: &Value) -> Option<&'static str> {
    if payload["channel"] != "inherited_pipe" { return Some("private_channel_required"); }
    let definitions = &schema["$defs"];
    if !schema_valid(payload, &definitions["case"], definitions) { return Some("host_request_invalid"); }
    let request = &payload["request"];
    let method = request["method"].as_str()?;
    let spec = &schema["x-methods"][method];
    if spec["params"] == "offlineReadParams" { return offline_read_failure(payload, schema); }
    if spec["params"] == "metadataParams" { return metadata_failure(payload, schema); }
    if ["offline_context", "metadata_context"].iter().any(|key| payload.get(key).is_some()) { return Some("host_request_invalid"); }
    if !matches!(spec["result"].as_str(), Some("profileResult" | "recoveryResult"))
        && ["profile_context", "recovery_context", "private_rpc_response"].iter().any(|key| payload.get(key).is_some()) {
        return Some("host_request_invalid");
    }
    if matches!(spec["result"].as_str(), Some("secretResult" | "keysExportResult" | "identityWriteResult" | "keyResult" | "migrationResult" | "profileResult" | "recoveryResult"))
        && payload.get("public_response").is_some() { return Some("private_secret_exposure"); }
    let mutable = spec["mutable"] == true;
    if mutable && (request["operation_id"].is_null() || request["idempotency_key"].is_null()) { return Some("host_operation_required"); }
    if !mutable && (!request["operation_id"].is_null() || !request["idempotency_key"].is_null()) { return Some("host_request_invalid"); }
    let params: Value = match request["args"][0].as_str().and_then(|text| serde_json::from_str(text).ok()) {
        Some(params) => params, None => return Some("host_params_invalid"),
    };
    if !schema_valid(&params, &definitions[spec["params"].as_str()?], definitions) { return Some("host_params_invalid"); }
    if matches!(spec["result"].as_str(), Some("profileResult" | "recoveryResult"))
        && ["config_context", "write_context", "key_context", "migration_context"].iter().any(|key| payload.get(key).is_some()) {
        return Some("host_request_invalid");
    }
    if (payload.get("progress").is_some() || payload.get("ledger").is_some()) && spec["result"] != "migrationResult"
        && !(spec["result"] == "keyResult" && params["operation"]["kind"] == "fivekeys") { return Some("host_request_invalid"); }
    if spec["params"] == "keyParams" && (method == "control.key.super_reset" && params["operation"]["kind"] != "super_reset"
        || matches!(method, "control.key.fivekeys" | "control.key.complete") && params["operation"]["kind"] != "fivekeys") { return Some("host_params_invalid"); }
    if spec["params"] == "identityWriteParams" && method != "control.identity.write_result"
        && (method == "control.identity.logout") != (params["operation"]["kind"] == "logout") { return Some("host_params_invalid"); }
    if spec["params"] == "modelMaintenanceParams" && ((params["phase"] == "plan") != params["expected"].is_null()
        || params["phase"] == "apply" && params["kind"] != "reset_cpu"
        || params["phase"] == "verify" && params["kind"] == "reset_cpu") { return Some("host_params_invalid"); }
    if spec["params"] == "modelParams" && if method == "control.model_install_plan" {
        !params["selection_sha256"].is_null()
    } else { params["selection_sha256"].is_null() } { return Some("host_params_invalid"); }
    let snapshot = method == "control.snapshot_maintenance";
    let verified = matches!(method, "control.auth.account_complete" | "control.key.complete") || snapshot && matches!(params["action"].as_str(), Some("commit" | "release"));
    if payload["maintenance_phase"] != if method == "control.auth.recovery_status" { "Idle" } else if verified { "Verified" } else { "Paused" } { return Some("maintenance_phase_mismatch"); }
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
        if matches!(spec["result"].as_str(), Some("profileResult" | "recoveryResult")) { return Some("host_result_invalid"); }
        return if payload["finish_maintenance"] == true { Some("maintenance_not_terminal") } else { None };
    };
    let kind = spec["result"].as_str()?;
    if !schema_valid(result, &definitions[kind], definitions) { return Some("host_result_invalid"); }
    if mutable && result["operation_id"] != request["operation_id"] { return Some("host_operation_mismatch"); }
    if let Some(error) = profile_recovery_failure(payload, &params, kind, schema) { return Some(error); }
    let extension = kind == "migrationResult" || kind == "keyResult" && params["operation"]["kind"] == "fivekeys";
    if let Some(error) = if extension { key_migration_failure(payload, &params, kind, schema) }
        else { fixed_write_model_failure(payload, &params, kind, schema) } { return Some(error); }
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
    let terminal = kind == "profileResult" && outcome == Some("committed")
        || kind == "recoveryResult" && method == "control.auth.recover_legacy" && result["state"] == "clear"
        || kind == "accountResult" && matches!(outcome, Some("committed" | "rolled_back"))
        || extension && if kind == "migrationResult" { matches!(outcome, Some("completed" | "already_migrated")) }
            else { matches!(outcome, Some("committed" | "rolled_back")) && result["verification_required"] != true }
        || snapshot && matches!(result["state"].as_str(), Some("released" | "rolled_back"));
    if payload["finish_maintenance"] == true && !terminal { return Some("maintenance_not_terminal"); }
    None
}

fn producer_types(payload: &Value) -> Result<()> {
    use respire_protocol::host_control::*;
    let request: respire_protocol::RpcRequest = serde_json::from_value(payload["request"].clone())?;
    let params: Value = serde_json::from_str(request.args.first().context("one host argument")?)?;
    if matches!(request.method.as_str(), HOST_LOGIN_RECOVERY_STATUS_METHOD | HOST_LOGIN_RECOVERY_METHOD
        | "control.profile.remove" | "control.profile.result") {
        let parsed: respire_protocol::RpcResponse<Value> = serde_json::from_value(payload["private_rpc_response"].clone())?;
        assert_eq!(serde_json::to_value(parsed)?, payload["private_rpc_response"]);
    }
    if matches!(request.method.as_str(), "control.metadata.status" | "control.agent_config.read" | "control.snapshot.preflight") {
        let parsed: respire_protocol::metadata_control::HostMetadataReadParams = serde_json::from_value(params.clone())?;
        assert_eq!(serde_json::to_value(parsed)?, params);
        let parsed: respire_protocol::RpcResponse<Value> = serde_json::from_value(payload["private_rpc_response"].clone())?;
        assert_eq!(serde_json::to_value(parsed)?, payload["private_rpc_response"]);
        return Ok(());
    }
    if matches!(request.method.as_str(), "control.metadata.enable" | "control.metadata.disable" | "control.metadata.result") {
        let parsed: respire_protocol::metadata_control::HostMetadataParams = serde_json::from_value(params.clone())?;
        assert_eq!(serde_json::to_value(parsed)?, params);
        let result: respire_protocol::metadata_control::HostMetadataResult = serde_json::from_value(payload["result"].clone())?;
        assert_eq!(serde_json::to_value(result)?, payload["result"]);
        let response: respire_protocol::RpcResponse<Value> = serde_json::from_value(payload["private_rpc_response"].clone())?;
        assert_eq!(serde_json::to_value(response)?, payload["private_rpc_response"]);
        return Ok(());
    }
    match request.method.as_str() {
        HOST_AUTH_KEYGEN_METHOD | HOST_AUTH_RESULT_METHOD => { serde_json::from_value::<HostAuthKeygenParams>(params)?; }
        HOST_LOGIN_RECOVERY_STATUS_METHOD | HOST_LOGIN_RECOVERY_METHOD => {
            let parsed: HostLoginRecoveryParams = serde_json::from_value(params.clone())?;
            assert_eq!(serde_json::to_value(parsed)?, params);
        }
        "control.profile.remove" | "control.profile.result" => {
            let parsed: respire_protocol::profile_maintenance::HostProfileRemoveParams = serde_json::from_value(params.clone())?;
            assert_eq!(serde_json::to_value(parsed)?, params);
        }
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
        "control.key.super_reset" | "control.key.fivekeys" | "control.key.complete" | "control.key.result" | "control.key.rollback" => {
            let parsed: respire_protocol::key_control::HostKeyParams = serde_json::from_value(params.clone())?;
            if let Some(input) = params.get("input").filter(|value| !value.is_null()) {
                let input = &input["password"];
                assert_eq!(parsed.input.as_ref().and_then(|value| value.password.as_deref()), input.as_str());
            }
        }
        "control.migration.profile" | "control.migration.result" => {
            serde_json::from_value::<respire_protocol::migration_control::HostMigrationParams>(params)?;
        }
        "control.model_maintenance" => {
            serde_json::from_value::<respire_protocol::model_maintenance::ModelMaintenanceParams>(params)?;
        }
        _ => anyhow::bail!("unsupported frozen method"),
    }
    if let Some(result) = payload.get("result") {
        match request.method.as_str() {
            HOST_AUTH_KEYGEN_METHOD | HOST_AUTH_RESULT_METHOD => { serde_json::from_value::<HostAuthResult>(result.clone())?; }
            HOST_LOGIN_RECOVERY_STATUS_METHOD | HOST_LOGIN_RECOVERY_METHOD => {
                let parsed: HostLoginRecoveryResult = serde_json::from_value(result.clone())?;
                assert_eq!(serde_json::to_value(parsed)?, *result);
            }
            "control.profile.remove" | "control.profile.result" => {
                let parsed: respire_protocol::profile_maintenance::HostProfileRemoveResult = serde_json::from_value(result.clone())?;
                assert_eq!(serde_json::to_value(parsed)?, *result);
            }
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
            "control.key.super_reset" | "control.key.fivekeys" | "control.key.complete" | "control.key.result" | "control.key.rollback" => {
                serde_json::from_value::<respire_protocol::key_control::HostKeyResult>(result.clone())?;
            }
            "control.migration.profile" | "control.migration.result" => {
                serde_json::from_value::<respire_protocol::migration_control::HostMigrationResult>(result.clone())?;
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
    let extension = &manifest["extensions"]["profile_recovery"];
    assert_eq!(extension["schema"], "schema/private-host-control.schema.json");
    assert_eq!(extension["consumer"], "consumers/private_host_control.rs");
    let mut count = 0;
    let mut extension_count = 0;
    for group in ["positive", "negative"] {
        let original_paths = manifest["fixtures"][group].as_array().context("fixture group")?;
        let new_paths = extension["fixtures"][group].as_array().context("profile/recovery fixture group")?;
        assert_eq!(new_paths.len(), if group == "positive" { 21 } else { 132 });
        for (index, path) in original_paths.iter().chain(new_paths).enumerate() {
            let path = path.as_str().context("fixture path")?;
            let fixture: Value = serde_json::from_slice(&std::fs::read(root.join(path))?)?;
            if index >= original_paths.len() {
                assert_eq!(fixture["fixture_type"], "private_host_control");
                assert_eq!(fixture["expected"], if group == "positive" { "accept" } else { "reject" });
            }
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
                | "host-fivekeys-input-unknown.json" | "host-fivekeys-input-totp-type.json"
                | "host-fivekeys-input-secret-type.json" | "host-fivekeys-operation-unknown.json"
                | "host-fivekeys-result-unknown.json" | "host-fivekeys-params-unknown.json"
                | "host-migration-params-unknown.json" | "host-migration-original-unknown.json" | "host-migration-result-unknown.json"
                | "host-profile-argv.json" | "host-profile-params-unknown.json" | "host-profile-result-unknown.json"
                | "host-profile-original-unknown.json" | "host-recovery-argv.json" | "host-recovery-params-unknown.json"
                | "host-recovery-result-unknown.json" | "host-recovery-status-identity-unknown.json"
                | "host-recovery-status-result-type.json" | "host-recovery-legacy-identity-unknown.json"
                | "host-recovery-legacy-result-type.json"
                | "host-model-maintenance-argv.json" | "host-model-maintenance-params-unknown.json"
                | "host-model-maintenance-result-unknown.json" | "host-model-maintenance-secret.json")) {
                assert!(producer_types(&fixture["payload"]).is_err(), "{path}: DTO must reject invalid fields");
            }
            if index < original_paths.len() { count += 1; } else { extension_count += 1; }
        }
    }
    assert_eq!(count, 303);
    assert_eq!(extension_count, 153);
    for (extension_name, positive_count, negative_count) in [("settings", 7, 26), ("metadata", 7, 18)] {
        let extension = &manifest["extensions"][extension_name];
        assert_eq!(extension["schema"], "schema/private-host-control.schema.json");
        assert_eq!(extension["consumer"], "consumers/private_host_control.rs");
        for (group, count) in [("positive", positive_count), ("negative", negative_count)] {
            let paths = extension["fixtures"][group].as_array().context("settings fixture group")?;
            assert_eq!(paths.len(), count);
            for path in paths {
                let path = path.as_str().context("settings fixture path")?;
                let fixture: Value = serde_json::from_slice(&std::fs::read(root.join(path))?)?;
                let expected = if group == "positive" { None } else { fixture["error_code"].as_str() };
                assert_eq!(failure(&fixture["payload"], &schema), expected, "{path}");
                if group == "positive" { producer_types(&fixture["payload"])?; }
                if path.ends_with("/host-metadata-params-unknown.json") { assert!(producer_types(&fixture["payload"]).is_err()); }
            }
        }
    }
    Ok(())
}

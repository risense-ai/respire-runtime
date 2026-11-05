// Included beside the frozen host consumer so both use the same schema evaluator.
fn space_failure(p: &serde_json::Value, schema: &serde_json::Value) -> Option<&'static str> {
    use serde_json::{json, Value};
    let valid = |v: &Value, name: &str| schema_valid(v, &schema["$defs"][name], &schema["$defs"]);
    if p["channel"] != "inherited_pipe" { return Some("private_channel_required"); }
    if p.get("public_response").is_some() { return Some("private_secret_exposure"); }
    let q = &p["request"];
    if !valid(q, "request") { return Some("space_request_invalid"); }
    let a: Value = match q["args"][0].as_str().and_then(|s| serde_json::from_str(s).ok()) {
        Some(a) => a, None => return Some("space_params_invalid"),
    };
    if !valid(&a, "params") { return Some("space_params_invalid"); }
    let op = &a["operation"];
    let method = format!("control.space.{}", op["kind"].as_str()?);
    if q["method"] != "control.space.result" && q["method"] != method { return Some("space_method_mismatch"); }
    let r = &p["result"];
    let c = &p["space_context"];
    if !valid(r, "result") { return Some("space_result_invalid"); }
    for name in ["ledger", "progress"] {
        if p.get(name).is_some_and(|v| !valid(v, "publicState")) { return Some("private_secret_exposure"); }
    }
    if p["maintenance_phase"] != "Paused" { return Some("maintenance_phase_mismatch"); }
    if !valid(c, "context") || c["installation_root"] != a["binding"]["installation_root"] || c["profile"] != a["binding"]["profile"]
        || c["source_identity"] != a["source_identity"] || c["operation"] != *op
        || c["operation_id"] != q["operation_id"] || c["idempotency_key"] != q["idempotency_key"] {
        return Some("space_context_mismatch");
    }
    if r["operation_id"] != q["operation_id"] || r["operation"] != *op { return Some("space_operation_mismatch"); }
    let preimage = json!({"schema_version":1,"method":"control.space","root":c["installation_root"],
        "profile":c["profile"],"source_identity":a["source_identity"],"operation":op});
    // Node and Go recompute SHA-256. Here the bound preimage and digest anchors are checked without a new dependency.
    let parsed: Option<Value> = c["fingerprint_preimage"].as_str().and_then(|s| serde_json::from_str(s).ok());
    if parsed.as_ref() != Some(&preimage) || r["fingerprint"] != c["fingerprint"] { return Some("space_fingerprint_mismatch"); }
    if r["profile"] != c["profile"] || c["selected_profile"] != c["profile"] || r["identity"] != a["source_identity"]
        || a["identity"] != a["source_identity"] || a["binding"]["expected_account_id"] != a["source_identity"]["account_id"] {
        return Some("space_identity_mismatch");
    }
    let outcome = match c["journal_phase"].as_str()? {
        "admitted" | "authorized" => "pending", "remote_pending" | "remote_unknown" => "unknown",
        "committed" => "committed", "rolled_back" => "rejected", _ => return Some("space_outcome_mismatch"),
    };
    if r["outcome"] != outcome || ["ledger", "progress"].iter().any(|k| p.get(k).is_some_and(|v| v["outcome"] != r["outcome"])) {
        return Some("space_outcome_mismatch");
    }
    for name in ["ledger", "progress"] {
        if let Some(state) = p.get(name) {
            for key in ["operation_id", "idempotency_key", "fingerprint"] {
                let expected = if key == "fingerprint" { &c[key] } else { &q[key] };
                if state.get(key).is_some_and(|v| v != expected) { return Some("space_context_mismatch"); }
            }
        }
    }
    let kick = r["kick"].as_array()?;
    match op["kind"].as_str()? {
        "join" => {
            let target = format!("{}/accounts/{}", c["installation_root"].as_str()?, op["space"].as_str()?);
            if !r["invite_code"].is_null() || !r["session_id"].is_null() || !kick.is_empty() || !r["remaining"].is_null()
                || r["target_profile"] != c["target_profile"] || r["target_account_id"] != c["target_account_id"]
                || r["target_session_sha256"] != c["target_session_sha256"] || r["target_profile"] != target
                || outcome == "committed" && (c["readonly_team"] != op["readonly"] || r["target_account_id"].is_null() || r["target_session_sha256"].is_null())
                || outcome != "committed" && (!r["target_account_id"].is_null() || !r["target_session_sha256"].is_null()) {
                return Some("space_join_mismatch");
            }
            if !a["invite_code"].is_null() {
                let code = space_invite(&a["invite_code"]);
                if code.as_ref().is_none_or(|code| ["space", "addr", "user", "readonly"].iter().any(|k| code[k] != op[k])) {
                    return Some("space_join_mismatch");
                }
            }
        }
        "kick" => {
            let targets = c["kick_targets"].as_array()?;
            if kick.len() != targets.len() || kick.iter().zip(targets).any(|(item, id)| item["session_id"] != *id)
                || op["all"] == false && (kick.len() != 1 || kick[0]["session_id"] != op["session_id"])
                || op["all"] == true && r["remaining"].as_u64() != Some(kick.iter().filter(|i| i["state"] != "revoked").count() as u64)
                || outcome == "committed" && kick.iter().any(|i| matches!(i["state"].as_str(), Some("queued" | "remote_pending" | "unknown")))
                || ["invite_code", "session_id", "target_profile", "target_account_id", "target_session_sha256"].iter().any(|k| !r[k].is_null()) {
                return Some("space_kick_mismatch");
            }
            if q["method"] == "control.space.result" && !c["remote_posts"].as_array()?.is_empty() { return Some("space_remote_replay"); }
            for (old, item) in c["previous_kick"].as_array()?.iter().zip(kick) {
                if old["session_id"] != item["session_id"] || old["state"] == "revoked" && item["state"] != "revoked"
                    || matches!(old["state"].as_str(), Some("remote_pending" | "unknown")) && item["state"] != "unknown" {
                    return Some("space_remote_replay");
                }
            }
        }
        "invite" => {
            if !kick.is_empty() || ["target_profile", "target_account_id", "target_session_sha256"].iter().any(|k| !r[k].is_null()) { return Some("space_result_invalid"); }
            if outcome == "committed" {
                if space_invite(&r["invite_code"]).as_ref().is_none_or(|code| code["session_id"] != r["session_id"]
                    || code["control_operation_id"] != q["operation_id"] || code["control_fingerprint"] != r["fingerprint"] || code["readonly"] != op["readonly"]) {
                    return Some("space_result_invalid");
                }
            } else if !r["invite_code"].is_null() || !r["session_id"].is_null() { return Some("space_result_invalid"); }
        }
        _ => return Some("space_params_invalid"),
    }
    let e = &p["private_response"];
    let status = match outcome { "pending" => "pending", "committed" => "ok", _ => "fail" };
    if !valid(e, "envelope") || e["summary"] != *r || e["status"] != status { return Some("space_result_invalid"); }
    for (name, status, value) in [("control_ready", "ok", "true"), ("store_ready", "skip", "false")] {
        let items: Vec<_> = e["items"].as_array()?.iter().filter(|i| i["name"] == name).collect();
        if items.len() != 1 || items[0]["status"] != status || items[0]["value"] != value { return Some("space_result_invalid"); }
    }
    if p["finish_maintenance"] == true && !matches!(outcome, "committed" | "rejected") { return Some("maintenance_not_terminal"); }
    None
}

fn space_invite(value: &serde_json::Value) -> Option<serde_json::Value> {
    let text = value.as_str()?.strip_prefix("1mem-invite:")?;
    if text.len() % 2 != 0 || !text.is_ascii() { return None; }
    let bytes: Option<Vec<_>> = (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect();
    serde_json::from_slice(&bytes?).ok()
}

pub(super) fn space_contract_fixtures() -> anyhow::Result<()> {
    use anyhow::Context;
    use serde_json::Value;
    use respire_protocol::space_control::{HostSpaceParams, HostSpaceResult,
        HOST_SPACE_INVITE_METHOD, HOST_SPACE_JOIN_METHOD, HOST_SPACE_KICK_METHOD, HOST_SPACE_RESULT_METHOD};
    let root = super::contract_root()?;
    let manifest: Value = serde_json::from_slice(&std::fs::read(root.join("manifest.json"))?)?;
    let extension = &manifest["extensions"]["space"];
    let schema: Value = serde_json::from_slice(&std::fs::read(root.join(extension["schema"].as_str().context("space schema")?))?)?;
    assert_eq!(schema["x-methods"], serde_json::json!([
        HOST_SPACE_INVITE_METHOD, HOST_SPACE_JOIN_METHOD, HOST_SPACE_KICK_METHOD, HOST_SPACE_RESULT_METHOD]));
    for (group, count) in [("positive", 7), ("negative", 24)] {
        let paths = extension["fixtures"][group].as_array().context("space fixture list")?;
        assert_eq!(paths.len(), count);
        for path in paths {
            let path = path.as_str().context("space fixture path")?;
            let f: Value = serde_json::from_slice(&std::fs::read(root.join(path))?)?;
            let expected = if group == "positive" { None } else { Some(f["error_code"].as_str().context("space rejection")?) };
            assert_eq!(space_failure(&f["payload"], &schema), expected, "{path}");
            let params = f["payload"]["request"]["args"][0].as_str().context("space args")?;
            if expected.is_none() {
                assert!(schema_valid(&f, &schema, &schema["$defs"]), "{path}");
                let _: respire_protocol::RpcRequest = serde_json::from_value(f["payload"]["request"].clone())?;
                let a: HostSpaceParams = serde_json::from_str(params)?;
                assert_eq!(serde_json::to_value(a)?, serde_json::from_str::<Value>(params)?);
                let r: HostSpaceResult = serde_json::from_value(f["payload"]["result"].clone())?;
                assert_eq!(serde_json::to_value(r)?, f["payload"]["result"]);
            } else if matches!(path.rsplit('/').next(), Some("space-params-unknown.json" | "space-operation-unknown.json")) {
                assert!(serde_json::from_str::<HostSpaceParams>(params).is_err(), "{path}: strict DTO");
            } else if path.ends_with("space-result-unknown.json") {
                assert!(serde_json::from_value::<HostSpaceResult>(f["payload"]["result"].clone()).is_err(), "{path}: strict result");
            }
        }
    }
    Ok(())
}

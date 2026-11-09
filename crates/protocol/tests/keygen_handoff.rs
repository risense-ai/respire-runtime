use respire_protocol::host_control::{
    HostAuthKeygenParams, HostAuthResult, HostKeygenHandoffReceipt,
    HOST_AUTH_KEYGEN_COMPLETE_METHOD, HOST_AUTH_KEYGEN_METHOD, HOST_AUTH_RESULT_METHOD,
};
use respire_protocol::RpcRequest;
use serde_json::json;

fn handoff_receipt_fixture() -> serde_json::Value {
    json!({"schema_version":1,"operation_id":"00000000-0000-4000-8000-000000000001",
        "session_sha256":"a".repeat(64),"path":"/fixture/profile/session.json",
        "runtime":{"pid":42,"process_start_id":"fixture-birth","instance_id":"fixture-instance",
            "generation":1,"image_path":"/fixture/runtime","image_sha256":"b".repeat(64),
            "installation_root":"/fixture","installation_id":"fixture-installation",
            "profile":"/fixture/profile","account_id":"c".repeat(64)}})
}

#[test]
fn keygen_handoff_is_independent_and_rejects_secret_or_claimed_authority_fields() -> anyhow::Result<()> {
    assert_eq!(HOST_AUTH_KEYGEN_COMPLETE_METHOD, "control.auth.keygen_complete");
    let receipt = handoff_receipt_fixture();
    let decoded: HostKeygenHandoffReceipt = serde_json::from_value(receipt.clone())?;
    assert_eq!(serde_json::to_value(decoded)?, receipt);
    for field in ["super_password", "outcome", "verified", "raw_error"] {
        let mut malicious = receipt.clone();
        malicious[field] = json!("SYNTHETIC_SECRET_MUST_NOT_ENTER_HANDOFF");
        assert!(serde_json::from_value::<HostKeygenHandoffReceipt>(malicious).is_err());
    }
    let mut nested = receipt.clone();
    nested["runtime"]["token"] = json!("SYNTHETIC_SECRET");
    assert!(serde_json::from_value::<HostKeygenHandoffReceipt>(nested).is_err());
    let params = json!({"schema_version":1,"force":false,
        "binding":{"installation_root":"/fixture","profile":"/fixture/profile",
            "launch_id":"fixture-launch","expected_account_id":null},
        "identity":{"kind":"unbound","operation_id":"00000000-0000-4000-8000-000000000001",
            "session_sha256":"a".repeat(64)}});
    let _: HostAuthKeygenParams = serde_json::from_value(params.clone())?;
    let mut claimed = params;
    claimed["verified"] = json!(true);
    assert!(serde_json::from_value::<HostAuthKeygenParams>(claimed).is_err());
    Ok(())
}

#[test]
fn legacy_keygen_and_result_requests_keep_their_json_shapes() -> anyhow::Result<()> {
    assert_eq!(HOST_AUTH_KEYGEN_METHOD, "control.auth.keygen");
    assert_eq!(HOST_AUTH_RESULT_METHOD, "control.auth.result");
    for method in [HOST_AUTH_KEYGEN_METHOD, HOST_AUTH_RESULT_METHOD] {
        assert_ne!(method, HOST_AUTH_KEYGEN_COMPLETE_METHOD);
        for identity in [
            json!({"kind":"absent"}),
            json!({"kind":"unbound","operation_id":"00000000-0000-4000-8000-000000000001",
                "session_sha256":"a".repeat(64)}),
            json!({"kind":"bound","account_id":"c".repeat(64),"session_sha256":"a".repeat(64)}),
        ] {
            let params = json!({"schema_version":1,"force":false,
                "binding":{"installation_root":"/fixture","profile":"/fixture/profile",
                    "launch_id":"fixture-launch","expected_account_id":null},
                "identity":identity});
            let decoded: HostAuthKeygenParams = serde_json::from_value(params.clone())?;
            assert_eq!(serde_json::to_value(decoded)?, params);
            let request = json!({"v":1,"id":"00000000-0000-4000-8000-000000000002",
                "operation_id":"00000000-0000-4000-8000-000000000001",
                "idempotency_key":"fixture-original","method":method,"args":[params.to_string()]});
            let decoded: RpcRequest = serde_json::from_value(request.clone())?;
            assert_eq!(serde_json::to_value(decoded)?, request);
            let mut claimed = request;
            claimed["capabilities"] = json!({"offline_keygen_handoff":"1"});
            assert!(serde_json::from_value::<RpcRequest>(claimed).is_err());
            for field in ["verified", "runtime", "capabilities"] {
                let mut claimed = params.clone();
                claimed[field] = json!(true);
                assert!(serde_json::from_value::<HostAuthKeygenParams>(claimed).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn legacy_auth_results_keep_exact_json_and_cannot_become_handoff_receipts() -> anyhow::Result<()> {
    let receipt = handoff_receipt_fixture();
    assert!(serde_json::from_value::<HostAuthResult>(receipt.clone()).is_err());
    for wire in [
        r#"{"operation_id":"fixture-original","outcome":"committed","session_sha256":"fixture-session","path":"/fixture/profile/session.json","super_password":"SYNTHETIC_PRIVATE_PIPE_ONLY"}"#,
        r#"{"operation_id":"fixture-original","outcome":"rolled_back","session_sha256":null,"path":"/fixture/profile/session.json"}"#,
        r#"{"operation_id":"fixture-original","outcome":"unknown","session_sha256":null,"path":"/fixture/profile/session.json"}"#,
    ] {
        let decoded: HostAuthResult = serde_json::from_str(wire)?;
        assert_eq!(serde_json::to_string(&decoded)?, wire);
        let legacy: serde_json::Value = serde_json::from_str(wire)?;
        assert!(serde_json::from_value::<HostKeygenHandoffReceipt>(legacy.clone()).is_err());
        let mut mixed = legacy.clone();
        mixed["runtime"] = receipt["runtime"].clone();
        assert!(serde_json::from_value::<HostAuthResult>(mixed).is_err());
        for outcome in ["finished", "handed_off", "verified"] {
            let mut changed = legacy.clone();
            changed["outcome"] = json!(outcome);
            assert!(serde_json::from_value::<HostAuthResult>(changed).is_err());
        }
    }
    Ok(())
}

#[test]
fn handoff_receipt_rejects_missing_or_null_identity_evidence() -> anyhow::Result<()> {
    let receipt = handoff_receipt_fixture();
    for field in ["schema_version", "operation_id", "session_sha256", "path", "runtime"] {
        let mut missing = receipt.clone();
        let object = missing.as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("handoff fixture must be an object"))?;
        object.remove(field);
        assert!(serde_json::from_value::<HostKeygenHandoffReceipt>(missing).is_err());
        let mut null = receipt.clone();
        null[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<HostKeygenHandoffReceipt>(null).is_err());
    }
    for field in ["pid", "process_start_id", "instance_id", "generation", "image_path",
        "image_sha256", "installation_root", "installation_id", "profile", "account_id"] {
        let mut missing = receipt.clone();
        let runtime = missing["runtime"].as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime fixture must be an object"))?;
        runtime.remove(field);
        assert!(serde_json::from_value::<HostKeygenHandoffReceipt>(missing).is_err());
        let mut null = receipt.clone();
        null["runtime"][field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<HostKeygenHandoffReceipt>(null).is_err());
    }
    Ok(())
}

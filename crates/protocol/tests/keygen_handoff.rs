use respire_protocol::host_control::{HostAuthKeygenParams, HostKeygenHandoffReceipt,
    HOST_AUTH_KEYGEN_COMPLETE_METHOD};
use serde_json::json;

#[test]
fn keygen_handoff_is_independent_and_rejects_secret_or_claimed_authority_fields() -> anyhow::Result<()> {
    assert_eq!(HOST_AUTH_KEYGEN_COMPLETE_METHOD, "control.auth.keygen_complete");
    let receipt = json!({"schema_version":1,"operation_id":"00000000-0000-4000-8000-000000000001",
        "session_sha256":"a".repeat(64),"path":"/fixture/profile/session.json",
        "runtime":{"pid":42,"process_start_id":"fixture-birth","instance_id":"fixture-instance",
            "generation":1,"image_path":"/fixture/runtime","image_sha256":"b".repeat(64),
            "installation_root":"/fixture","installation_id":"fixture-installation",
            "profile":"/fixture/profile","account_id":"c".repeat(64)}});
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

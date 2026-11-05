use super::*;

#[test]
fn only_npu_requires_a_working_windows_ml_catalog() -> Result<()> {
    use crate::onnx::Engine;
    for engine in [Engine::Cpu, Engine::Gpu] {
        let errors = register_selected_catalog(engine, || anyhow::bail!("catalog unavailable"))?;
        assert!(errors.is_empty());
    }
    assert!(
        register_selected_catalog(Engine::Npu, || anyhow::bail!("catalog unavailable")).is_err()
    );
    assert_eq!(
        register_selected_catalog(Engine::Npu, || Ok(vec!["optional provider".into()]))?,
        vec!["optional provider".to_owned()]
    );
    let observation = json!({"status":"loaded","ready":true,"fresh_session":true,"inference_completed":true,
        "runtime":{"kind":"onnxruntime","api_version":27,"build_info":"test build","api_address":"private-api-address",
            "symbols":{"Run":"private-function-address"}},
        "device_address":"private-device-address","host_identity":{"verified":true,"resources_verified":true,
            "provider":"CPUExecutionProvider","modules":[{"id":"ort","sha256":"a".repeat(64),
                "symbols":{"Run":"private-function-address"}}]}});
    let summary = crate::backend_probe::sanitized(&observation, &json!({"sdk_version":"fixture"}))?;
    let encoded = serde_json::to_string(&summary)?;
    for private in ["private-api-address", "private-function-address", "private-device-address", "api_address", "symbols"] {
        assert!(!encoded.contains(private), "public probe summary leaked a native address");
    }
    assert_eq!(summary["modules"][0]["id"], "ort");
    assert_eq!(summary["runtime"]["build_info_sha256"], digest(b"test build"));
    let mut stale = observation;
    stale["fresh_session"] = json!(false);
    assert!(crate::backend_probe::sanitized(&stale, &json!({})).is_err());
    assert!(crate::backend_probe::require_contract(&json!({"phase":"idle"})).is_err());
    assert!(crate::backend_probe::require_contract(&json!({"backend_load_probe_contract":1})).is_err());
    crate::backend_probe::require_contract(&json!({"backend_load_probe_contract":1,"operations":["backend_load_probe"]}))?;
    let gate = crate::model_selection::probe_gate()?;
    assert!(crate::model_selection::probe_gate().is_err(), "recursive probe must fail instead of waiting on its own native loader");
    drop(gate);
    Ok(())
}

#[test]
fn missing_custom_cpu_model_preserves_io_error_and_correct_recovery() -> Result<()> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let missing = std::env::temp_dir().join(format!(
        "respire-missing-model-{}-{nonce}",
        std::process::id()
    ));
    assert!(!missing.exists());
    for custom in [false, true] {
        let failure = model_file_metadata(&missing, custom, "fp16")
            .err()
            .ok_or_else(|| anyhow::anyhow!("missing model unexpectedly available"))?;
        let io = failure
            .downcast_ref::<std::io::Error>()
            .ok_or_else(|| anyhow::anyhow!("original IO error missing"))?;
        assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            failure
                .to_string()
                .contains("correct or unset RSRS_CPU_OWNED_ORT_FILE"),
            custom
        );
        assert_eq!(
            failure.to_string().contains("run rsrs model install-m3"),
            !custom
        );
        assert_eq!(failure.to_string().contains("--model fp16"), !custom);
    }
    Ok(())
}

#[test]
fn model_reads_are_bounded_and_fallback_diagnostics_do_not_accumulate() -> Result<()> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "respire-model-bounds-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root)?;
    let file = root.join("model");
    std::fs::write(&file, b"abc")?;
    assert_eq!(read_model_bytes(&file, 3)?, b"abc");
    assert!(read_model_bytes(&file, 2).is_err());
    assert!(read_model_bytes(&file, 4).is_err());
    let errors = vec!["provider unavailable".to_owned()];
    let expected = vec![
        "provider unavailable".to_owned(),
        "using quantized".to_owned(),
    ];
    for _ in 0..3 {
        assert_eq!(model_diagnostics("using quantized", &errors), expected);
    }
    assert_eq!(model_diagnostics("", &errors), errors);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
#[ignore = "requires pinned model fixtures; injects legacy native-options callback only"]
fn legacy_failed_second_session_reloads_the_prior_configuration_without_restart() -> Result<()> {
    recover_after_options_failure(2)
}

#[test]
#[ignore = "requires pinned model fixtures; injects legacy native-options callback only"]
fn legacy_failed_first_session_reloads_the_prior_configuration_without_restart() -> Result<()> {
    recover_after_options_failure(1)
}

fn recover_after_options_failure(failure_at: usize) -> Result<()> {
    anyhow::ensure!(
        std::env::var_os("RSRS_CORE_TEST_MODEL_DIR").is_some(),
        "explicit pinned model fixture required for legacy native-options recovery test"
    );
    // Stream commit bypasses this callback; owned non-stream loads reject it.
    // Keep this fixture explicitly legacy without changing product defaults or
    // leaking the override into later owned/stream tests, including on panic.
    struct LegacyMode(Option<std::ffi::OsString>);
    impl Drop for LegacyMode {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("RSRS_CPU_OWNED_ORT_EXPERIMENT", value),
                None => std::env::remove_var("RSRS_CPU_OWNED_ORT_EXPERIMENT"),
            }
        }
    }
    let _legacy = LegacyMode(std::env::var_os("RSRS_CPU_OWNED_ORT_EXPERIMENT"));
    std::env::set_var("RSRS_CPU_OWNED_ORT_EXPERIMENT", "0");
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            crate::ffi::set_test_option_failure(None);
            let _ = reset_model_cache();
        }
    }
    let _cleanup = Cleanup;
    reset_model_cache()?;
    let mut core = crate::Core::new()?;
    initialize_model(&mut core)?;
    assert_eq!(
        core.call(
            "model_probe",
            json!({"model":"m3","text":"model A before failed replacement"})
        )?["ready"],
        true
    );
    crate::ffi::set_test_option_failure(Some(failure_at));
    let failed = initialize_model(&mut core);
    assert!(failed.is_err());
    assert_eq!(
        crate::ffi::test_option_callback_count(),
        failure_at,
        "the requested native session callback must be reached"
    );
    crate::ffi::set_test_option_failure(None);
    // This is the real Host cache path: the previous stamp must not repeatedly
    // request reuse of a canonical group that replacement already retired.
    initialize_model(&mut core)?;
    assert_eq!(
        core.call(
            "model_probe",
            json!({"model":"m3","text":"model A recovered without restart"})
        )?["ready"],
        true
    );
    // Also recover when another handle resets Core without clearing this Host stamp.
    core.call("engine_control", json!({"action":"reset"}))?;
    initialize_model(&mut core)?;
    assert_eq!(
        core.call(
            "model_probe",
            json!({"model":"m3","text":"stale cached reuse recovered"})
        )?["ready"],
        true
    );
    core.call("engine_control", json!({"action":"reset"}))?;
    Ok(())
}

#[test]
fn user_variants_take_precedence_over_packaged_baselines() {
    use std::path::PathBuf;
    let user = PathBuf::from("user-model");
    let packaged = PathBuf::from("packaged-model");
    let legacy = PathBuf::from("legacy-model");
    let candidates = crate::bge::model_directory_candidates(
        user.clone(),
        vec![legacy.clone()],
        Some(packaged.clone()),
        false,
    );
    let isolated = crate::bge::model_directory_candidates(
        user.clone(), vec![legacy.clone()], Some(packaged.clone()), true,
    );
    assert_eq!(isolated, vec![user.clone()]);
    assert_eq!(&candidates[..3], &[user, legacy, packaged]);
    assert_eq!(
        candidates.last(),
        Some(&PathBuf::from("/usr/lib/respire/models/bge-m3"))
    );
}

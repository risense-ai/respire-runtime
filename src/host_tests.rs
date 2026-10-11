use super::*;

#[test]
fn failed_second_session_reloads_the_prior_configuration_without_restart() -> Result<()> {
    recover_after_options_failure(2)
}

#[test]
fn failed_first_session_reloads_the_prior_configuration_without_restart() -> Result<()> {
    recover_after_options_failure(1)
}

fn recover_after_options_failure(failure_at: usize) -> Result<()> {
    if std::env::var_os("RSRS_CORE_TEST_MODEL_DIR").is_none() { return Ok(()); }
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
    assert_eq!(core.call("model_probe", json!({"model":"m3","text":"model A before failed replacement"}))?["ready"], true);
    crate::ffi::set_test_option_failure(Some(failure_at));
    let failed = initialize_model(&mut core);
    assert!(failed.is_err());
    assert_eq!(crate::ffi::test_option_callback_count(), failure_at,
        "the requested native session callback must be reached");
    crate::ffi::set_test_option_failure(None);
    // This is the real Host cache path: the previous stamp must not repeatedly
    // request reuse of a canonical group that replacement already retired.
    initialize_model(&mut core)?;
    assert_eq!(core.call("model_probe", json!({"model":"m3","text":"model A recovered without restart"}))?["ready"], true);
    // Also recover when another handle resets Core without clearing this Host stamp.
    core.call("engine_control", json!({"action":"reset"}))?;
    initialize_model(&mut core)?;
    assert_eq!(core.call("model_probe", json!({"model":"m3","text":"stale cached reuse recovered"}))?["ready"], true);
    core.call("engine_control", json!({"action":"reset"}))?;
    Ok(())
}

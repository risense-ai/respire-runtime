import assert from 'node:assert/strict';
import {CASES, selected, verifyResults} from './produce-runtime-g1-stop.mjs';

// Synthetic refusal checks, never native acceptance evidence.
const digest = 'a'.repeat(64);
const identity = {target: 'aarch64-unknown-linux-musl', source_sha: 'b'.repeat(40),
  cli_source_sha: 'c'.repeat(40), client2_source_sha: 'd'.repeat(40), run_id: '13', run_attempt: '2',
  actual_cli_native_sdk: {version: '2.0.0-dev.4', archive_sha256: digest, manifest_sha256: 'e'.repeat(64)},
  cli_sdk_lock_sha256: 'f'.repeat(64)};
const standalone = {passed: true, observations: ['normal', 'explicit-force', 'accepted-write'].map(name => ({case: name}))};
const mode = name => ({passed: true, standalone,
  credential: {passed: true, credential_before_passed: true, credential_after_passed: true,
    business_passed: true, business_credential_cleanup_passed: true, keyring_cleanup: {passed: true}},
  source_binding: {client2_source_sha: identity.client2_source_sha, probe_fixture_cli_sha: identity.cli_source_sha,
    workflow_source_sha: identity.source_sha, run_id: identity.run_id, run_attempt: identity.run_attempt, mode: name,
    probe_binary_sha256: digest, client2_source_archive_sha256: digest, generated_go_mod_sha256: digest,
    source_go_sum_sha256: digest, resolved_go_sum_sha256: digest,
    probe_fixture_sha256: Object.fromEntries(['diagnostics_darwin.go', 'diagnostics_other.go', 'host_operations.go', 'main.go']
      .map(file => [`scripts/fixtures/client2-v0256-probe/${file}`, digest]))},
  observations: ['normal', 'caller-timeout', 'explicit-force'].map(item => ({case: item,
    startup_mode: name === 'registered' ? 'cli-supervised' : 'client2-owned', provider_http_status: 200,
    provider_requests: 1, credential_cleanup_verified: true, business_sender: 'modern-harness',
    stop_sender: name === 'registered' ? (item === 'normal' ? 'modern-cli' : 'original-go-client2-managed') : 'original-go-client2',
    encrypted_write_committed: item !== 'explicit-force', forced_operation_remains_unknown: item === 'explicit-force',
    caller_timeout_ms: item === 'normal' ? null : 40000}))});
const result = {schema: 1, passed: true, test_executed: true, offline_installer_verified: true,
  release_acceptance: false, target: identity.target, identity,
  modes: {standalone: {passed: true, standalone}, registered: mode('registered'), 'client2-owned': mode('client2-owned')},
  model_sha256: {
    'tokenizer.json': '6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790',
    'onnx/model_quantized.onnx': '0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
    'onnx/model_quantized.cpu-v1.ort': '7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff',
  }};
result.prepared_memory = {schema: 1, passed: true, test_executed: true, release_acceptance: false,
  offline_installer_verified: true, target: identity.target, identity, model_sha256: structuredClone(result.model_sha256),
  passed_cases: ['diary_identity::remember_public_payload_covers_created_appended_and_merged',
    'diary_identity::concurrent_same_day_client_commands_preserve_each_successful_addition_once']};
assert.equal(Object.keys(CASES).length, 6);
assert.equal(selected.length, 9);
const verified = verifyResults(result, identity);
assert.deepEqual(Object.keys(verified).sort(), Object.keys(CASES).sort());
for (const [id, names] of Object.entries(CASES)) {
  assert.deepEqual(verified[id], names.map(name => ({name, status: 'passed'})));
}
for (const mutate of [
  r => { delete r.prepared_memory; },
  r => { r.prepared_memory.passed_cases.pop(); },
  r => { r.prepared_memory.passed_cases.push('fabricated-case'); },
  r => { r.prepared_memory.passed_cases.push(r.prepared_memory.passed_cases[0]); },
  r => { r.prepared_memory.identity = {...identity, cli_source_sha: 'e'.repeat(40)}; },
  r => { r.prepared_memory.identity.actual_cli_native_sdk.archive_sha256 = '0'.repeat(64); },
  r => { r.prepared_memory.identity.cli_sdk_lock_sha256 = '0'.repeat(64); },
  r => { r.prepared_memory.model_sha256 = {}; },
  r => { r.prepared_memory.passed = false; },
  r => { r.prepared_memory.test_executed = false; },
  r => { r.prepared_memory.offline_installer_verified = false; },
  r => { r.prepared_memory.private_log = 'private-canary'; },
  r => { delete r.modes.registered; },
  r => { r.modes['client2-owned'].observations.pop(); },
  r => { r.modes.registered.credential.keyring_cleanup.passed = false; },
  r => { r.modes.registered.credential.credential_after_passed = false; },
  r => { r.modes.registered.credential.business_credential_cleanup_passed = false; },
  r => { r.modes.registered.source_binding.client2_source_sha = 'e'.repeat(40); },
  r => { r.modes.registered.observations[0].stop_sender = 'synthetic'; },
  r => { r.modes.registered.observations[1].caller_timeout_ms = 1; },
  r => { r.modes.registered.observations[2].forced_operation_remains_unknown = false; },
  r => { r.modes.standalone.standalone.observations.pop(); },
  r => { r.target = 'aarch64-unknown-linux-gnu'; },
  r => { r.model_sha256 = {}; },
]) {
  const bad = structuredClone(result);
  mutate(bad);
  assert.throws(() => verifyResults(bad, identity));
}
console.log('six-suite producer verifies real prepared memory and stop cases; rejects incomplete coverage, identity/model changes, private fields and cleanup failures');

import assert from 'node:assert/strict';
import {selected, verifyResults, verifyOwnedStop} from './produce-runtime-g1-business.mjs';

// Synthetic data exercises refusal paths only. It is never acceptance evidence.
process.env.GITHUB_RUN_ID = '17';
process.env.GITHUB_RUN_ATTEMPT = '2';
const target = 'x86_64-unknown-linux-gnu';
const sha = 'a'.repeat(40), cliSha = 'b'.repeat(40), binary = 'c'.repeat(64), cliBinary = 'd'.repeat(64);
const archive = 'e'.repeat(64), desktop = 'f'.repeat(64);
const bound = {metadata: {binary_sha256: binary, archive_sha256: archive, runtime_version: 'synthetic'},
  metadata_sha256: '1'.repeat(64), sdk_lock_sha256: '2'.repeat(64),
  candidate: {components: {runtime: {source_sha: sha}, cli: {source_sha: cliSha, artifacts: {[target]: {binary_sha256: cliBinary}}},
    client2: {artifacts: {[target]: {binary_sha256: desktop}}}}}};
const names = [...selected];
const business = {suite: 'g1-business', passed: true, test_executed: true, release_acceptance: false,
  cli_source_sha: cliSha, runtime_source_sha: sha, target, run_id: '17', run_attempt: '2',
  cli_binary_sha256: cliBinary, runtime_binary_sha256: binary, runtime_archive_sha256: archive,
  runtime_metadata_sha256: bound.metadata_sha256, sdk_lock_sha256: bound.sdk_lock_sha256,
  offline_installer_verified: true, selected_case_count: names.length, required_cases: names, passed_cases: names,
  missing_or_failed_cases: [], selected_native_stop: true,
  standalone_stop: {passed: true, observations: ['normal', 'explicit-force', 'accepted-write'].map(name => ({
    case: name, startup_mode: 'standalone', provider_requests: 1,
    final_state: name === 'explicit-force' ? 'forced_timeout' : 'drained',
    encrypted_write_committed: name === 'accepted-write', forced_operation_remains_unknown: name === 'explicit-force',
    business_before_stop_ms: 4201, business_held_after_stop_ms: 4202}))},
  owned_process_cleanup: {passed: true, forced: 0, forced_processes: []}, keyring: {passed: true, business_passed: true}};
const launcher = {client2_source: '1734322b6c6dd543441a753f07a3517bee5e1231', g1_passed: false,
  inputs: {cli_sha256: cliBinary, runtime_archive_sha256: archive, runtime_version: 'synthetic', ordinary_cli_cold_start: true, host_credentials: true},
  desktop_headless: {enabled: true, binary_sha256: desktop, release: 'host-owned-candidate', artifact_id: 14114928434, run_id: '43597586002'},
  cases: ['client2-owned', 'external-cli-cold-start', 'reuse-cli-started', 'reuse-cli-business-started',
    'desktop-owned', 'cli-host-sigterm', 'cli-host-sigkill'].map(name => ({name, passed: true, cleanup_exit: 0, synthetic_host_credential: true}))};
verifyResults(business, launcher, bound);
for (const mutate of [
  (b) => {b.passed = false;},
  (b) => {b.selected_case_count = 3;},
  (b) => {b.selected_native_stop = false;},
  (b) => {b.standalone_stop.observations.pop();},
  (b) => {b.standalone_stop.observations[0].business_held_after_stop_ms = 4000;},
  (b) => {b.run_attempt = '1';},
  (b) => {b.runtime_archive_sha256 = '0'.repeat(64);},
  (b) => {b.passed_cases = b.passed_cases.slice(1);},
  (b) => {b.owned_process_cleanup.forced = 1;},
  (b) => {b.owned_process_cleanup.passed = false;},
  (b) => {b.owned_process_cleanup.forced_processes = [{pid: 42, image_sha256: binary, image_role: 'candidate_runtime'}];},
  (b) => {delete b.owned_process_cleanup.forced_processes;},
  (b) => {b.owned_process_cleanup.forced_processes = {};},
  (b) => {b.keyring.business_passed = false;},
  (_b, l) => {l.desktop_headless.enabled = false;},
  (_b, l) => {l.desktop_headless.artifact_id = 0;},
  (_b, l) => {l.desktop_headless.run_id = 'other';},
  (_b, l) => {l.inputs.cli_sha256 = '0'.repeat(64);},
  (_b, l) => {l.inputs.host_credentials = false;},
  (_b, l) => {delete l.cases[0].synthetic_host_credential;},
  (_b, l) => {l.cases.pop();},
  (_b, l) => {l.cases[0].cleanup_exit = 1;},
]) {
  const b = structuredClone(business), l = structuredClone(launcher);
  mutate(b, l);
  assert.throws(() => verifyResults(b, l, bound));
}
for (const mode of ['registered', 'client2-owned']) {
  const owned = {suite: 'g1-owned-stop', passed: true, test_executed: true, release_acceptance: false,
    cli_source_sha: cliSha, runtime_source_sha: sha, cli_binary_sha256: cliBinary,
    runtime_binary_sha256: binary, runtime_archive_sha256: archive, runtime_metadata_sha256: bound.metadata_sha256,
    run_id: '17', run_attempt: '2', passed_cases: ['diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay'],
    missing_or_failed_cases: [], keyring: {passed: true, business_passed: true},
    owned_process_cleanup: {passed: true, forced: 0, forced_processes: []},
    owned_stop: {passed: true, source_binding: {mode, client2_source_sha: launcher.client2_source, probe_fixture_cli_sha: cliSha},
      observations: ['normal', 'caller-timeout', 'explicit-force'].map(name => ({case: name,
        startup_mode: mode === 'registered' ? 'cli-supervised' : 'client2-owned', provider_requests: 1,
        business_sender: 'modern-harness',
        stop_sender: mode === 'registered' ? (name === 'normal' ? 'modern-cli' : 'original-go-client2-managed') : 'original-go-client2',
        caller_timeout_ms: name === 'normal' ? null : (mode === 'registered' ? 35001 : 30001),
        provider_http_status: 200, encrypted_write_committed: name !== 'explicit-force',
        forced_operation_remains_unknown: name === 'explicit-force', credential_cleanup_verified: true}))}};
  verifyOwnedStop(owned, mode, bound);
  for (const mutate of [
    r => {r.runtime_archive_sha256 = '0'.repeat(64);},
    r => {r.run_attempt = '1';},
    r => {r.owned_stop.source_binding.mode = 'other';},
    r => {r.owned_stop.source_binding.client2_source_sha = '0'.repeat(40);},
    r => {r.owned_stop.observations.pop();},
    r => {r.owned_stop.observations[1].caller_timeout_ms = 0;},
    r => {delete r.owned_stop.observations[1].caller_timeout_ms;},
    r => {r.owned_stop.observations[2].caller_timeout_ms = 0;},
    r => {r.owned_stop.observations[1].encrypted_write_committed = false;},
    r => {r.owned_stop.observations[1].forced_operation_remains_unknown = true;},
    r => {r.owned_stop.observations[1].business_sender = 'fake';},
    r => {r.owned_stop.observations[1].stop_sender = 'modern-cli';},
    r => {r.owned_stop.observations[1].credential_cleanup_verified = false;},
    r => {r.owned_stop.observations[0].provider_requests = 2;},
    r => {r.owned_stop.observations[2].forced_operation_remains_unknown = false;},
    r => {r.owned_process_cleanup.forced = 1;},
    r => {r.keyring.business_passed = false;},
  ]) {
    const changed = structuredClone(owned);
    mutate(changed);
    assert.throws(() => verifyOwnedStop(changed, mode, bound));
  }
}
console.log('Synthetic business and owned-stop evidence checks passed; no native acceptance executed');

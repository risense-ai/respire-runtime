import assert from 'node:assert/strict';
import {CASES, verifyResults} from './produce-runtime-g1-business.mjs';

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
const names = [...new Set(Object.values(CASES).flat())];
const business = {suite: 'g1-business', passed: true, test_executed: true, release_acceptance: false,
  cli_source_sha: cliSha, runtime_source_sha: sha, target, run_id: '17', run_attempt: '2',
  cli_binary_sha256: cliBinary, runtime_binary_sha256: binary, runtime_archive_sha256: archive,
  runtime_metadata_sha256: bound.metadata_sha256, sdk_lock_sha256: bound.sdk_lock_sha256,
  offline_installer_verified: true, selected_case_count: 2, required_cases: names, passed_cases: names,
  missing_or_failed_cases: [], owned_process_cleanup: {passed: true, forced: 0}, keyring: {passed: true, business_passed: true}};
const launcher = {client2_source: '57bc070826949994c3f7ce9a64277160704bdfe5', g1_passed: false,
  inputs: {cli_sha256: cliBinary, runtime_archive_sha256: archive, runtime_version: 'synthetic', ordinary_cli_cold_start: true},
  desktop_headless: {enabled: true, binary_sha256: desktop},
  cases: ['client2-owned', 'external-cli-cold-start', 'reuse-cli-started', 'reuse-cli-business-started',
    'desktop-owned', 'cli-host-sigterm', 'cli-host-sigkill'].map(name => ({name, passed: true, cleanup_exit: 0}))};
verifyResults(business, launcher, bound);
for (const mutate of [
  (b) => {b.run_attempt = '1';},
  (b) => {b.runtime_archive_sha256 = '0'.repeat(64);},
  (b) => {b.passed_cases = b.passed_cases.slice(1);},
  (b) => {b.owned_process_cleanup.forced = 1;},
  (b) => {b.keyring.business_passed = false;},
  (_b, l) => {l.desktop_headless.enabled = false;},
  (_b, l) => {l.inputs.cli_sha256 = '0'.repeat(64);},
  (_b, l) => {l.cases.pop();},
  (_b, l) => {l.cases[0].cleanup_exit = 1;},
]) {
  const b = structuredClone(business), l = structuredClone(launcher);
  mutate(b, l);
  assert.throws(() => verifyResults(b, l, bound));
}
console.log('10 synthetic business combination checks passed; no native acceptance executed');

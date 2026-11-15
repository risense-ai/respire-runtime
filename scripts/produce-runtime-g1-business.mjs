import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {context, BUSINESS_CASES, STOP_CASES as CASES} from './produce-runtime-g1-smoke.mjs';
import {auditSdkDirectory, observeSdkArchive} from './sdk-ci-cache.mjs';

const target = 'x86_64-unknown-linux-gnu';
export {CASES};
export const selected = [...new Set([
  ...Object.values(BUSINESS_CASES).flat(),
  'account::authorization_preserves_and_commits_profiles',
  'diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay',
])].sort();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function read(path) {
  const stat = lstatSync(path);
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), 'Ordinary original evidence required');
  return readFileSync(path);
}
const json = path => JSON.parse(read(path));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});

function inputs() {
  const bound = context();
  assert.equal(bound.target, target);
  assert.equal(process.platform, 'linux');
  assert.equal(process.arch, 'x64');
  assert.equal(process.env.GITHUB_JOB, 'g1-native-business');
  const cliSource = resolve('.cli-source');
  const client2Source = resolve('.client2-source');
  for (const [path, sha] of [[cliSource, bound.candidate.components.cli.source_sha], [client2Source, bound.candidate.components.client2.source_sha]]) {
    assert.equal(execFileSync('git', ['-C', path, 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), sha);
    assert.equal(execFileSync('git', ['-C', path, 'diff', '--name-only', 'HEAD'], {encoding: 'utf8'}).trim(), '');
  }
  assert.deepEqual(json(join('g1-input', 'client2-assets', 'desktop-source.json')),
    bound.candidate.components.client2.native_artifact, 'Client2 source proof differs from frozen candidate');
  const cliMeta = json(join('g1-input', 'cli-assets', `cli-build-${target}.json`));
  const cliArtifact = bound.candidate.components.cli.artifacts[target];
  assert.equal(cliMeta.git_sha, bound.candidate.components.cli.source_sha);
  assert.equal(cliMeta.version, bound.candidate.components.cli.version);
  assert.equal(cliMeta.target, target);
  assert.ok(Object.hasOwn(cliArtifact, 'native_sdk'), 'CLI SDK identity must be explicit');
  assert.equal(cliMeta.binary_file, `rsrs-${target}`);
  if (cliArtifact.native_sdk === null) {
    assert.equal(cliMeta.schema_version, 2);
    assert.equal(cliMeta.artifact_layout, 'cli-frontend-v2');
    assert.ok(!Object.hasOwn(cliMeta, 'runtime_file') && !Object.hasOwn(cliMeta, 'runtime_sha256'));
  } else {
    assert.equal(cliMeta.runtime_file, `rsrs-${target}-runtime.tar.gz`);
    assert.equal(cliMeta.runtime_sha256, cliArtifact.archive_sha256);
  }
  const cli = resolve('g1-input', 'cli-assets', cliMeta.binary_file);
  if (cliArtifact.native_sdk === null) assert.equal(cliMeta.binary_size, read(cli).length);
  assert.equal(hash(read(cli)), cliArtifact.binary_sha256);
  assert.equal(cliMeta.binary_sha256, cliArtifact.binary_sha256);
  assert.equal(hash(read(join('g1-input', 'cli-assets', `rsrs-${target}-runtime.tar.gz`))), cliArtifact.archive_sha256);
  let actualCliSdk = null;
  if (cliArtifact.native_sdk !== null) {
    const cliLock = json(join(cliSource, 'sdk/core-sdk.lock.json'));
    actualCliSdk = observeSdkArchive(read(join(cliSource, '.sdk-archives', target, 'sdk.tar.gz')), target, cliLock.targets[target]);
    auditSdkDirectory(join(cliSource, '.sdk', target), target, cliLock.targets[target]);
    assert.deepEqual(actualCliSdk, cliArtifact.native_sdk);
    const cliPayload = json(join('g1-input', 'cli-assets', 'core-runtime.json'));
    assert.equal(cliPayload.schema_version, 1);
    assert.equal(cliPayload.target, target);
    const manifest = json(join(cliSource, '.sdk', target, 'manifest.json'));
    for (const file of manifest.files) {
      const path = file.path.startsWith('runtime/') ? file.path.slice(8)
        : file.path.startsWith('notices/') ? `core-notices/${file.path.slice(8)}`
          : file.path === 'LICENSE.txt' ? 'core-notices/CORE-SDK-LICENSE.txt' : null;
      if (path === null) continue;
      const records = cliPayload.files.filter(item => item.path === path);
      assert.equal(records.length, 1);
      const actual = read(join('g1-input', 'cli-assets', path));
      assert.equal(hash(actual), file.sha256);
      assert.equal(records[0].sha256, file.sha256);
      assert.equal(actual.length, read(join(cliSource, '.sdk', target, file.path)).length);
    }
  }
  const desktop = resolve('g1-input', 'client2-assets', 'respire');
  const originalArchive = resolve('g1-input', 'client2-assets', 'respire-linux-amd64.tar.gz');
  const client2Artifact = bound.candidate.components.client2.artifacts[target];
  assert.equal(hash(read(desktop)), client2Artifact.binary_sha256);
  assert.equal(hash(read(originalArchive)), client2Artifact.archive_sha256);
  // Verify the already-hashed original archives themselves contain the exact
  // payload bytes that will execute, not independently supplied loose files.
  execFileSync('python3', ['scripts/verify-business-archive-payloads.py'], {stdio: 'pipe'});
  const runtime = resolve('release-assets', `rsrs-runtime-${target}`);
  assert.equal(hash(read(runtime)), bound.metadata.binary_sha256);
  // Match the existing CLI workflow's actual cargo compiler-artifact record;
  // a test harness executable normally has a cargo-generated hash suffix.
  const records = read(join(process.env.RUNNER_TEMP, 'g1-business-harness-build.jsonl')).toString('utf8').trim().split('\n').map(line => JSON.parse(line));
  const artifacts = records.filter(record => record.reason === 'compiler-artifact'
    && record.target?.name === 'cli_business_tests' && record.profile?.test && record.executable);
  assert.equal(artifacts.length, 1);
  const harness = realpathSync(artifacts[0].executable);
  assert.equal(dirname(harness), realpathSync(resolve('target/debug/examples')));
  read(harness);
  return {...bound, cli, cliSource, client2Source, desktop, originalArchive, runtime, harness, actualCliSdk,
    metadata_sha256: hash(read(join('release-assets', `runtime-build-${target}.json`))),
    sdk_lock_sha256: hash(read('sdk/core-sdk.lock.json'))};
}

export function verifyResults(business, launcher, bound) {
  for (const [key, expected] of Object.entries({suite: 'g1-business', passed: true, test_executed: true,
    cli_source_sha: bound.candidate.components.cli.source_sha, runtime_source_sha: bound.candidate.components.runtime.source_sha,
    target, run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    cli_binary_sha256: bound.candidate.components.cli.artifacts[target].binary_sha256,
    runtime_binary_sha256: bound.metadata.binary_sha256, runtime_archive_sha256: bound.metadata.archive_sha256,
    runtime_metadata_sha256: bound.metadata_sha256, sdk_lock_sha256: bound.sdk_lock_sha256,
    offline_installer_verified: true})) assert.equal(business[key], expected);
  assert.equal(business.release_acceptance, false, 'The wrapped fixture itself must retain its honest evidence class');
  assert.equal(business.selected_case_count, selected.length);
  for (const key of ['required_cases', 'passed_cases']) assert.deepEqual([...business[key]].sort(), selected);
  assert.deepEqual(business.missing_or_failed_cases, []);
  assert.equal(business.selected_native_stop, true);
  assert.equal(business.standalone_stop.passed, true);
  const stops = business.standalone_stop.observations;
  assert.deepEqual(stops.map(item => item.case).sort(), ['accepted-write', 'explicit-force', 'normal']);
  for (const item of stops) {
    const forced = item.case === 'explicit-force';
    assert.equal(item.startup_mode, 'standalone');
    assert.equal(item.provider_requests, 1);
    assert.equal(item.final_state, forced ? 'forced_timeout' : 'drained');
    assert.equal(item.encrypted_write_committed, item.case === 'accepted-write');
    assert.equal(item.forced_operation_remains_unknown, forced);
    assert.ok(Number.isSafeInteger(item.business_before_stop_ms) && item.business_before_stop_ms > 4000);
    assert.ok(Number.isSafeInteger(item.business_held_after_stop_ms)
      && item.business_held_after_stop_ms > (forced ? 0 : 4000));
  }
  assert.equal(business.owned_process_cleanup.passed, true);
  assert.equal(business.owned_process_cleanup.forced, 0);
  assert.deepEqual(business.owned_process_cleanup.forced_processes, []);
  assert.equal(business.keyring.passed, true);
  assert.equal(business.keyring.business_passed, true);
  const client2 = bound.candidate.components.client2;
  const proof = client2.native_artifact;
  assert.ok(proof, 'Frozen Client2 native_artifact proof required; refreeze the candidate');
  assert.equal(proof.source_commit, client2.source_sha);
  assert.equal(proof.version, client2.version);
  for (const key of ['archive_sha256', 'binary_sha256']) assert.equal(proof[key], client2.artifacts[target][key]);
  assert.equal(launcher.client2_source, client2.source_sha);
  assert.equal(launcher.g1_passed, false);
  assert.equal(launcher.inputs.cli_sha256, business.cli_binary_sha256);
  assert.equal(launcher.inputs.runtime_archive_sha256, business.runtime_archive_sha256);
  assert.equal(launcher.inputs.runtime_version, bound.metadata.runtime_version);
  assert.equal(launcher.inputs.ordinary_cli_cold_start, true);
  assert.equal(launcher.inputs.host_credentials, true);
  assert.equal(launcher.desktop_headless.enabled, true);
  assert.equal(launcher.desktop_headless.client2_source, client2.source_sha);
  assert.equal(launcher.desktop_headless.release, proof.release);
  assert.equal(launcher.desktop_headless.artifact_id, proof.artifact_id);
  assert.equal(launcher.desktop_headless.run_id, String(proof.run_id));
  assert.equal(launcher.desktop_headless.archive_sha256, proof.archive_sha256);
  assert.equal(launcher.desktop_headless.binary_sha256, proof.binary_sha256);
  const names = launcher.cases.map(item => item.name);
  assert.equal(new Set(names).size, names.length);
  assert.deepEqual([...names].sort(), ['client2-owned', 'external-cli-cold-start', 'reuse-cli-started',
    'reuse-cli-business-started', 'desktop-owned', 'cli-host-sigterm', 'cli-host-sigkill'].sort());
  assert.ok(launcher.cases.every(item => item.passed === true && item.cleanup_exit === 0 && item.synthetic_host_credential === true));
}

export function verifyOwnedStop(report, mode, bound) {
  assert.ok(['registered', 'client2-owned'].includes(mode));
  assert.equal(report.suite, 'g1-owned-stop');
  assert.equal(report.passed, true);
  assert.equal(report.test_executed, true);
  assert.equal(report.release_acceptance, false);
  assert.equal(report.cli_source_sha, bound.candidate.components.cli.source_sha);
  assert.equal(report.runtime_source_sha, bound.candidate.components.runtime.source_sha);
  assert.equal(report.cli_binary_sha256, bound.candidate.components.cli.artifacts[target].binary_sha256);
  assert.equal(report.runtime_binary_sha256, bound.metadata.binary_sha256);
  assert.equal(report.runtime_archive_sha256, bound.metadata.archive_sha256);
  assert.equal(report.runtime_metadata_sha256, bound.metadata_sha256);
  assert.equal(report.run_id, process.env.GITHUB_RUN_ID);
  assert.equal(report.run_attempt, process.env.GITHUB_RUN_ATTEMPT);
  assert.deepEqual(report.passed_cases, ['diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay']);
  assert.deepEqual(report.missing_or_failed_cases, []);
  assert.equal(report.owned_stop.passed, true);
  assert.equal(report.owned_stop.source_binding.client2_source_sha, bound.candidate.components.client2.source_sha);
  assert.equal(report.owned_stop.source_binding.probe_fixture_cli_sha, report.cli_source_sha);
  assert.equal(report.owned_stop.source_binding.mode, mode);
  const observations = report.owned_stop.observations;
  assert.deepEqual(observations.map(item => item.case).sort(), ['caller-timeout', 'explicit-force', 'normal']);
  for (const item of observations) {
    assert.equal(item.startup_mode, mode === 'registered' ? 'cli-supervised' : 'client2-owned');
    assert.equal(item.provider_requests, 1);
    assert.equal(item.provider_http_status, 200);
    assert.equal(item.encrypted_write_committed, item.case !== 'explicit-force');
    assert.equal(item.forced_operation_remains_unknown, item.case === 'explicit-force');
    assert.equal(item.credential_cleanup_verified, true);
    assert.equal(item.business_sender, 'modern-harness');
    assert.equal(item.stop_sender, mode === 'registered'
      ? (item.case === 'normal' ? 'modern-cli' : 'original-go-client2-managed') : 'original-go-client2');
    if (item.case === 'normal') assert.equal(item.caller_timeout_ms, null);
    else assert.ok(Number.isSafeInteger(item.caller_timeout_ms)
      && item.caller_timeout_ms >= (mode === 'registered' ? 35000 : 30000)
      && item.caller_timeout_ms <= 60000, 'Original caller must actually time out before explicit force or completion');
  }
  assert.equal(report.keyring.passed, true);
  assert.equal(report.keyring.business_passed, true);
  assert.equal(report.owned_process_cleanup.passed, true);
  assert.equal(report.owned_process_cleanup.forced, 0);
  assert.deepEqual(report.owned_process_cleanup.forced_processes, []);
}

function run() {
  const bound = inputs();
  const directory = resolve('g1-business-raw');
  assert.ok(!existsSync(directory));
  mkdirSync(directory);
  const root = join(process.env.RUNNER_TEMP, `g1-business-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`);
  assert.ok(!existsSync(root));
  const started_at = new Date().toISOString();
  const metadata = resolve('release-assets', `runtime-build-${target}.json`);
  const archive = resolve('release-assets', bound.metadata.archive_file);
  const result = spawnSync('python3', [join(bound.cliSource, 'scripts/native-account-candidate.py'),
    '--root', root, '--cli-source', bound.cliSource, '--runtime-source', process.cwd(),
    '--cli-sha', bound.candidate.components.cli.source_sha, '--runtime-sha', process.env.GITHUB_SHA,
    '--cli', bound.cli, '--runtime', bound.runtime, '--harness', bound.harness,
    '--suite', 'g1-business', '--runtime-archive', archive, '--runtime-metadata', metadata], {stdio: 'inherit'});
  assert.ifError(result.error);
  const businessBytes = read(join(root, 'result.json'));
  writeFileSync(join(directory, 'business.json'), businessBytes, {flag: 'wx'});
  assert.equal(result.status, 0, 'Real isolated business execution failed');
  const ownedStops = {};
  for (const mode of ['registered', 'client2-owned']) {
    const ownedRoot = `${root}-${mode}`;
    assert.ok(!existsSync(ownedRoot));
    const owned = spawnSync('python3', [join(bound.cliSource, 'scripts/native-account-candidate.py'),
      '--root', ownedRoot, '--cli-source', bound.cliSource, '--runtime-source', process.cwd(),
      '--cli-sha', bound.candidate.components.cli.source_sha, '--runtime-sha', process.env.GITHUB_SHA,
      '--cli', bound.cli, '--runtime', bound.runtime, '--harness', bound.harness,
      '--suite', 'g1-owned-stop', '--owned-stop-mode', mode, '--client2-source', bound.client2Source,
      '--runtime-archive', archive, '--runtime-metadata', metadata], {stdio: 'inherit'});
    assert.ifError(owned.error);
    const bytes = read(join(ownedRoot, 'result.json'));
    writeFileSync(join(directory, `owned-stop-${mode}.json`), bytes, {flag: 'wx'});
    assert.equal(owned.status, 0, `Frozen ${mode} stop execution failed`);
    verifyOwnedStop(JSON.parse(bytes), mode, bound);
    ownedStops[mode] = hash(bytes);
  }
  const launcherPath = join(directory, 'client2-launcher.json');
  const go = execFileSync('which', ['go'], {encoding: 'utf8'}).trim();
  const launcherKeyring = join(root, 'launcher-keyring');
  const launcher = spawnSync('env', ['-u', 'DBUS_SESSION_BUS_ADDRESS', '-u', 'DBUS_SESSION_BUS_PID',
    '-u', 'DBUS_STARTER_ADDRESS', '-u', 'DBUS_STARTER_BUS_TYPE', '-u', 'GNOME_KEYRING_CONTROL',
    '-u', 'GNOME_KEYRING_PID', '-u', 'SSH_AUTH_SOCK', 'dbus-run-session', '--',
    'env', 'RSRS_SS_FIXTURE_BUS=private', 'python3', '-B',
    join(bound.cliSource, 'scripts/dev-secret-service-keyring-selftest.py'), '--root', launcherKeyring,
    '--', 'python3', join(bound.cliSource, 'scripts/test-client2-launcher-compat.py'),
    '--cli', bound.cli, '--runtime-archive', archive, '--runtime-version', bound.metadata.runtime_version,
    '--client2-source', bound.client2Source, '--client2-baseline', 'host-owned-candidate',
    '--go', go, '--desktop-executable', bound.desktop,
    '--host-credentials', '--ordinary-cli-cold-start', '--report', launcherPath], {stdio: 'inherit'});
  assert.ifError(launcher.error);
  assert.equal(launcher.status, 0, 'Paired Client2 execution or private credential cleanup failed');
  const launcherKeyringBytes = read(join(launcherKeyring, 'business-keyring-selftest.json'));
  const credentialCheck = JSON.parse(launcherKeyringBytes);
  for (const key of ['passed', 'business_passed', 'business_credential_cleanup_passed']) assert.equal(credentialCheck[key], true);
  assert.equal(credentialCheck.keyring_cleanup.passed, true);
  writeFileSync(join(directory, 'launcher-keyring.json'), launcherKeyringBytes, {flag: 'wx'});
  const launcherBytes = read(launcherPath);
  verifyResults(JSON.parse(businessBytes), JSON.parse(launcherBytes), bound);
  inputs(); // Recheck the source, SDK and package bytes after all executions.
  writeFileSync(join(directory, 'candidate.json'), bound.bytes, {flag: 'wx'});
  save(join(directory, 'execution.json'), {schema: 1, evidence_class: 'candidate-native-raw', gate: 'not-evaluated',
    repository: process.env.GITHUB_REPOSITORY, source_sha: process.env.GITHUB_SHA,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT, target,
    job_name: 'g1-native-business', producer: 'scripts/produce-runtime-g1-business.mjs',
    candidate_sha256: hash(bound.bytes), actual_native_sdk: bound.observed, actual_cli_native_sdk: bound.actualCliSdk,
    harness_sha256: hash(read(bound.harness)), business_sha256: hash(businessBytes), launcher_sha256: hash(launcherBytes),
    owned_stop_sha256: ownedStops,
    started_at, completed_at: new Date().toISOString(), suites: Object.keys(CASES)});
}

function report() {
  const bound = inputs();
  const directory = resolve('g1-business-raw');
  assert.ok(read(join(directory, 'candidate.json')).equals(bound.bytes));
  const execution = json(join(directory, 'execution.json'));
  const businessBytes = read(join(directory, 'business.json'));
  const launcherBytes = read(join(directory, 'client2-launcher.json'));
  assert.equal(execution.business_sha256, hash(businessBytes));
  assert.equal(execution.launcher_sha256, hash(launcherBytes));
  assert.equal(execution.harness_sha256, hash(read(bound.harness)));
  assert.deepEqual(execution.actual_native_sdk, bound.observed);
  assert.deepEqual(execution.actual_cli_native_sdk, bound.actualCliSdk);
  const name = `required-tests-raw-runtime-business-${target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`;
  assert.equal(process.env.G1_RAW_ARTIFACT_NAME, name);
  assert.match(process.env.G1_RAW_ARTIFACT_ID ?? '', /^[1-9][0-9]*$/);
  assert.match(process.env.G1_RAW_ARTIFACT_SHA256 ?? '', /^[a-f0-9]{64}$/);
  for (const [key, expected] of Object.entries({source_sha: process.env.GITHUB_SHA,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    repository: process.env.GITHUB_REPOSITORY, target, candidate_sha256: hash(bound.bytes),
    job_name: 'g1-native-business', producer: 'scripts/produce-runtime-g1-business.mjs'})) assert.equal(execution[key], expected);
  verifyResults(JSON.parse(businessBytes), JSON.parse(launcherBytes), bound);
  assert.deepEqual(Object.keys(execution.owned_stop_sha256).sort(), ['client2-owned', 'registered']);
  for (const mode of ['registered', 'client2-owned']) {
    const bytes = read(join(directory, `owned-stop-${mode}.json`));
    assert.equal(hash(bytes), execution.owned_stop_sha256[mode]);
    verifyOwnedStop(JSON.parse(bytes), mode, bound);
  }
  mkdirSync('g1-business-report/reports', {recursive: true});
  writeFileSync('g1-business-report/candidate.json', bound.bytes, {flag: 'wx'});
  for (const [id, names] of Object.entries(CASES)) {
    save(join('g1-business-report/reports', `${id}-${target}.json`), {
      schema: 2, test_id: id, target, status: 'passed', coverage: 'real-artifact',
      cases: names.map(name => ({name, status: 'passed'})), source_sha: execution.source_sha,
      repository: execution.repository, run_id: execution.run_id, run_attempt: execution.run_attempt,
      candidate_sha256: execution.candidate_sha256, actual_native_sdk: execution.actual_native_sdk,
      actual_cli_native_sdk: execution.actual_cli_native_sdk, job_name: execution.job_name,
      artifact_id: Number(process.env.G1_RAW_ARTIFACT_ID), artifact_name: name,
      artifact_sha256: process.env.G1_RAW_ARTIFACT_SHA256, producer: execution.producer,
      business_sha256: execution.business_sha256, launcher_sha256: execution.launcher_sha256,
      owned_stop_sha256: execution.owned_stop_sha256,
    });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv[2] === 'run') run();
  else if (process.argv[2] === 'report') report();
  else throw new Error('usage: produce-runtime-g1-business.mjs run|report');
}

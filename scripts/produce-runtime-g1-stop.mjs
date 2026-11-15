import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {context, STOP_CASES, BUSINESS_CASES} from './produce-runtime-g1-smoke.mjs';
import {verifyResults as verifyMemoryResults} from './produce-runtime-g1-memory.mjs';
import {auditSdkDirectory, observeSdkArchive} from './sdk-ci-cache.mjs';
import {observeConsumerSdk} from './freeze-runtime-g1-candidate.mjs';

export const CASES = {...BUSINESS_CASES, ...STOP_CASES};
export const selected = [...new Set(Object.values(STOP_CASES).flat())].sort();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const read = path => {
  assert.ok(lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink());
  return readFileSync(path);
};
const json = path => JSON.parse(read(path));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});

function inputs() {
  const bound = context();
  assert.equal(process.env.GITHUB_JOB, 'g1-native-stop');
  const harnessTarget = bound.target.replace(/-musl$/, '-gnu');
  assert.equal(process.env.G1_HARNESS_TARGET, harnessTarget);
  assert.equal(process.arch, bound.target.startsWith('aarch64-') ? 'arm64' : 'x64');
  assert.equal(process.platform, bound.target.includes('windows') ? 'win32' : bound.target.includes('apple') ? 'darwin' : 'linux');
  const lock = json('sdk/core-sdk.lock.json');
  const harnessSdk = observeSdkArchive(read(join('.sdk-archives', harnessTarget, 'sdk.tar.gz')), harnessTarget, lock.targets[harnessTarget]);
  auditSdkDirectory(resolve('.sdk', harnessTarget), harnessTarget, lock.targets[harnessTarget]);
  const client2 = bound.candidate.components.client2.source_sha;
  assert.equal(client2, 'd54b38529e1fdb7d9f3e3f5c999d3e747deab151');
  assert.equal(execFileSync('git', ['-C', '.client2-source', 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), client2);
  const source = bound.candidate.components.cli.source_sha;
  assert.equal(execFileSync('git', ['-C', '.cli-source', 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), source);
  for (const directory of ['.', '.cli-source', '.client2-source']) {
    assert.equal(execFileSync('git', ['-C', directory, 'diff', 'HEAD', '--name-only'], {encoding: 'utf8'}).trim(), '');
  }
  const artifact = bound.candidate.components.cli.artifacts[bound.target];
  const actualCliSdk = observeConsumerSdk(resolve('.cli-source'), bound.target);
  assert.deepEqual(actualCliSdk, artifact.native_sdk);
  const suffix = bound.target.includes('windows') ? '.exe' : '';
  const metadataPath = resolve('g1-input/cli-assets', `cli-build-${bound.target}.json`);
  const metadata = json(metadataPath);
  for (const [key, value] of Object.entries({git_sha: source, target: bound.target,
    version: bound.candidate.components.cli.version, binary_file: `rsrs-${bound.target}${suffix}`,
    runtime_file: `rsrs-${bound.target}-runtime.tar.gz`, binary_sha256: artifact.binary_sha256,
    runtime_sha256: artifact.archive_sha256})) assert.equal(metadata[key], value);
  const cli = resolve('g1-input/cli-assets', metadata.binary_file);
  const archive = resolve('g1-input/cli-assets', metadata.runtime_file);
  assert.equal(hash(read(cli)), artifact.binary_sha256);
  assert.equal(hash(read(archive)), artifact.archive_sha256);
  const runtime = resolve('release-assets', `rsrs-runtime-${bound.target}${suffix}`);
  assert.equal(hash(read(runtime)), bound.metadata.binary_sha256);
  const records = read(join(process.env.RUNNER_TEMP, 'g1-stop-harness-build.jsonl')).toString().trim().split('\n').map(line => JSON.parse(line));
  const artifacts = records.filter(record => record.reason === 'compiler-artifact'
    && record.target?.name === 'cli_business_tests' && record.profile?.test && record.executable);
  assert.equal(artifacts.length, 1);
  const harness = realpathSync(artifacts[0].executable);
  assert.equal(dirname(harness), realpathSync(resolve('target/debug/examples')));
  return {bound, identity: {target: bound.target, source_sha: process.env.GITHUB_SHA, cli_source_sha: source, client2_source_sha: client2,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    candidate_sha256: hash(bound.bytes), harness_target: harnessTarget, harness_native_sdk: harnessSdk,
    actual_cli_native_sdk: actualCliSdk, cli_sdk_lock_sha256: hash(read('.cli-source/sdk/core-sdk.lock.json')),
    cli, cli_metadata: metadataPath,
    cli_metadata_sha256: hash(read(metadataPath)), sdk_lock_sha256: hash(read('sdk/core-sdk.lock.json')),
    cli_binary_sha256: artifact.binary_sha256, cli_archive: archive, cli_archive_sha256: artifact.archive_sha256,
    runtime_metadata: resolve('release-assets', `runtime-build-${bound.target}.json`),
    runtime_metadata_sha256: hash(read(join('release-assets', `runtime-build-${bound.target}.json`))),
    runtime_archive: resolve('release-assets', bound.metadata.archive_file),
    runtime_archive_sha256: bound.metadata.archive_sha256, runtime_binary_sha256: bound.metadata.binary_sha256,
    harness, harness_sha256: hash(read(harness)),
    root: resolve(process.env.RUNNER_TEMP, `g1-stop-${bound.target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`)}};
}

export function verifyResults(result, identity) {
  assert.equal(result.schema, 1);
  for (const key of ['passed', 'test_executed', 'offline_installer_verified']) assert.equal(result[key], true);
  assert.equal(result.release_acceptance, false);
  assert.equal(result.target, identity.target);
  assert.deepEqual(result.identity, identity);
  assert.deepEqual(Object.keys(result.prepared_memory).sort(), ['schema', 'passed', 'test_executed',
    'release_acceptance', 'offline_installer_verified', 'target', 'identity', 'passed_cases', 'model_sha256'].sort());
  verifyMemoryResults(result.prepared_memory, identity);
  assert.deepEqual(Object.keys(result.modes).sort(), ['client2-owned', 'registered', 'standalone']);
  const observed = [];
  for (const mode of ['standalone', 'registered', 'client2-owned']) {
    const part = result.modes[mode];
    assert.equal(part.passed, true);
    assert.equal(part.standalone.passed, true);
    assert.deepEqual(part.standalone.observations.map(row => row.case).sort(), ['accepted-write', 'explicit-force', 'normal']);
    if (mode === 'standalone') {
      for (const row of part.standalone.observations) observed.push(`standalone:${row.case}`);
    } else {
      const binding = part.source_binding;
      assert.equal(binding.client2_source_sha, identity.client2_source_sha);
      assert.equal(binding.probe_fixture_cli_sha, identity.cli_source_sha);
      assert.equal(binding.workflow_source_sha, identity.source_sha);
      assert.equal(binding.run_id, identity.run_id);
      assert.equal(binding.run_attempt, identity.run_attempt);
      assert.equal(binding.mode, mode);
      for (const key of ['probe_binary_sha256', 'client2_source_archive_sha256', 'generated_go_mod_sha256', 'source_go_sum_sha256', 'resolved_go_sum_sha256']) assert.match(binding[key] ?? '', /^[a-f0-9]{64}$/);
      assert.deepEqual(Object.keys(binding.probe_fixture_sha256).sort(), ['diagnostics_darwin.go', 'diagnostics_other.go', 'host_operations.go', 'main.go'].map(name => `scripts/fixtures/client2-v0256-probe/${name}`).sort());
      for (const digest of Object.values(binding.probe_fixture_sha256)) assert.match(digest, /^[a-f0-9]{64}$/);
      assert.equal(part.credential.passed, true);
      assert.equal(part.credential.credential_before_passed, true);
      assert.equal(part.credential.credential_after_passed, true);
      assert.equal(part.credential.keyring_cleanup.passed, true);
      if (identity.target.includes('linux')) {
        assert.equal(part.credential.business_passed, true);
        assert.equal(part.credential.business_credential_cleanup_passed, true);
      }
      assert.deepEqual(part.observations.map(row => row.case).sort(), ['caller-timeout', 'explicit-force', 'normal']);
      for (const row of part.observations) {
        const startup = mode === 'registered' ? 'cli-supervised' : 'client2-owned';
        assert.equal(row.startup_mode, startup);
        assert.equal(row.provider_http_status, 200);
        assert.equal(row.provider_requests, 1);
        assert.equal(row.credential_cleanup_verified, true);
        assert.equal(row.business_sender, 'modern-harness');
        const sender = mode === 'registered' ? (row.case === 'normal' ? 'modern-cli' : 'original-go-client2-managed') : 'original-go-client2';
        assert.equal(row.stop_sender, sender);
        assert.equal(row.encrypted_write_committed, row.case !== 'explicit-force');
        assert.equal(row.forced_operation_remains_unknown, row.case === 'explicit-force');
        if (row.case === 'normal') assert.equal(row.caller_timeout_ms, null);
        else assert.ok(Number.isInteger(row.caller_timeout_ms) && row.caller_timeout_ms >= (mode === 'registered' ? 35000 : 30000) && row.caller_timeout_ms <= 60000);
        observed.push(`${startup}:${row.case}`);
      }
    }
  }
  assert.deepEqual(observed.sort(), selected);
  assert.deepEqual(result.model_sha256, {
    'tokenizer.json': '6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790',
    'onnx/model_quantized.onnx': '0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
    'onnx/model_quantized.cpu-v1.ort': '7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff',
  });
  return Object.fromEntries(Object.entries(CASES).map(([id, names]) => {
    const actual = Object.hasOwn(BUSINESS_CASES, id) ? result.prepared_memory.passed_cases : observed;
    assert.ok(names.every(name => actual.includes(name)), `Missing executed cases for ${id}`);
    return [id, names.map(name => ({name: actual.find(value => value === name), status: 'passed'}))];
  }));
}

function run() {
  const {bound, identity} = inputs();
  mkdirSync('g1-stop-raw');
  const request = join(process.env.RUNNER_TEMP, 'g1-stop-request.json');
  save(request, identity);
  const started_at = new Date().toISOString();
  execFileSync('python', ['-B', 'scripts/run-runtime-g1-stop.py', request, 'g1-stop-raw/stop.json'], {stdio: 'inherit'});
  verifyResults(json('g1-stop-raw/stop.json'), identity);
  writeFileSync('g1-stop-raw/candidate.json', bound.bytes, {flag: 'wx'});
  save('g1-stop-raw/execution.json', {schema: 1, ...identity, repository: process.env.GITHUB_REPOSITORY,
    job_name: `g1-native-stop (${bound.target})`, producer: 'scripts/produce-runtime-g1-stop.mjs',
    actual_native_sdk: bound.observed,
    stop_sha256: hash(read('g1-stop-raw/stop.json')), started_at, completed_at: new Date().toISOString()});
}

function report() {
  const {bound, identity} = inputs();
  const execution = json('g1-stop-raw/execution.json');
  for (const [key, value] of Object.entries(identity)) assert.deepEqual(execution[key], value);
  assert.equal(execution.repository, process.env.GITHUB_REPOSITORY);
  assert.equal(execution.job_name, `g1-native-stop (${bound.target})`);
  assert.equal(execution.producer, 'scripts/produce-runtime-g1-stop.mjs');
  assert.deepEqual(execution.actual_native_sdk, bound.observed);
  assert.deepEqual(execution.actual_cli_native_sdk, identity.actual_cli_native_sdk);
  assert.ok(read('g1-stop-raw/candidate.json').equals(bound.bytes));
  assert.equal(execution.stop_sha256, hash(read('g1-stop-raw/stop.json')));
  const verifiedCases = verifyResults(json('g1-stop-raw/stop.json'), identity);
  const name = `required-tests-raw-runtime-stop-${bound.target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`;
  assert.equal(process.env.G1_RAW_ARTIFACT_NAME, name);
  assert.match(process.env.G1_RAW_ARTIFACT_ID ?? '', /^[1-9][0-9]*$/);
  assert.match(process.env.G1_RAW_ARTIFACT_SHA256 ?? '', /^[a-f0-9]{64}$/);
  mkdirSync('g1-stop-report/reports', {recursive: true});
  writeFileSync('g1-stop-report/candidate.json', bound.bytes, {flag: 'wx'});
  for (const id of Object.keys(CASES)) save(join('g1-stop-report/reports', `${id}-${bound.target}.json`), {
    schema: 2, test_id: id, target: bound.target, status: 'passed', coverage: 'real-artifact',
    cases: verifiedCases[id], source_sha: identity.source_sha,
    repository: execution.repository, run_id: identity.run_id, run_attempt: identity.run_attempt,
    candidate_sha256: identity.candidate_sha256, actual_native_sdk: execution.actual_native_sdk,
    actual_cli_native_sdk: execution.actual_cli_native_sdk, job_name: execution.job_name,
    artifact_id: Number(process.env.G1_RAW_ARTIFACT_ID), artifact_name: name,
    artifact_sha256: process.env.G1_RAW_ARTIFACT_SHA256, producer: execution.producer, stop_sha256: execution.stop_sha256,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv[2] === 'run') run();
  else if (process.argv[2] === 'report') report();
  else throw new Error('usage: produce-runtime-g1-stop.mjs run|report');
}

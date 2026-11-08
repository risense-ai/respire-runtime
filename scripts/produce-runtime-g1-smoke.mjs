import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {auditSdkDirectory, observeSdkArchive} from './sdk-ci-cache.mjs';

// This producer implements two suites only. Other registry entries remain missing.
export const REQUIRED_CASES = {
  'runtime.mcp-initialize-tools-list': ['initialize', 'tools/list', 'tools/call:memory_status', 'same-process-after-call'],
  'runtime.client-json-bad-config': ['scoped-structured-invalid-config-envelope',
    'invalid-client-config-bytes-preserved', 'inference-settings-preserved-on-rejection',
    'scoped-recovery-preserves-inference-settings'],
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const read = path => {
  const stat = lstatSync(path);
  assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 128 * 1024 * 1024, 'Unsafe evidence input');
  return readFileSync(path);
};
const json = path => JSON.parse(read(path));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
function context() {
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.ok(['linux', 'darwin'].includes(process.env.G1_NATIVE_PLATFORM));
  assert.ok(['x64', 'arm64'].includes(process.env.G1_NATIVE_ARCH));
  assert.equal(process.platform, process.env.G1_NATIVE_PLATFORM);
  assert.equal(process.arch, process.env.G1_NATIVE_ARCH);
  assert.equal(process.env.RUNNER_ARCH, process.arch === 'arm64' ? 'ARM64' : 'X64');
  for (const key of ['CORE_SDK_READ_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN']) assert.ok(!process.env[key], 'Product execution must be token-free');
  assert.match(process.env.GITHUB_SHA ?? '', /^[a-f0-9]{40}$/);
  for (const key of ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']) assert.match(process.env[key] ?? '', /^[1-9][0-9]*$/);
  assert.equal(process.env.GITHUB_REPOSITORY, 'risense-ai/respire-runtime');
  assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), process.env.GITHUB_SHA,
    'Build and frozen source must use the CI merge SHA, never a different PR head');
  assert.match(process.env.RUNTIME_TARGET ?? '', /^[a-z0-9_-]+$/);
  assert.match(process.env.G1_CANDIDATE_SHA256 ?? '', /^[a-f0-9]{64}$/);
  const directory = resolve('g1-input');
  const bytes = read(join(directory, 'candidate.json'));
  assert.equal(hash(bytes), process.env.G1_CANDIDATE_SHA256);
  const candidate = JSON.parse(bytes);
  assert.equal(candidate.schema, 2);
  assert.equal(candidate.frozen, true);
  assert.equal(candidate.gate, 'G1');
  assert.ok(!Object.hasOwn(candidate, 'sdk'));
  for (const owner of ['runtime', 'cli', 'client2']) {
    const component = candidate.components?.[owner];
    assert.match(component?.source_sha ?? '', /^[a-f0-9]{40}$/);
    assert.ok(typeof component.version === 'string' && component.version);
    assert.ok(component.artifacts && Object.keys(component.artifacts).length > 0);
    for (const artifact of Object.values(component.artifacts)) {
      for (const key of ['archive_sha256', 'binary_sha256']) assert.match(artifact[key] ?? '', /^[a-f0-9]{64}$/);
      if (owner === 'client2') assert.equal(artifact.native_sdk, null);
      else {
        assert.deepEqual(Object.keys(artifact.native_sdk).sort(), ['archive_sha256', 'manifest_sha256', 'version']);
        for (const key of ['archive_sha256', 'manifest_sha256']) assert.match(artifact.native_sdk[key] ?? '', /^[a-f0-9]{64}$/);
        assert.ok(typeof artifact.native_sdk.version === 'string' && artifact.native_sdk.version);
      }
    }
  }
  assert.equal(candidate.components.runtime.source_sha, process.env.GITHUB_SHA);
  const target = process.env.RUNTIME_TARGET;
  const artifact = candidate.components.runtime.artifacts[target];
  assert.ok(artifact, 'Target absent from frozen Runtime');
  const metadata = json(join('release-assets', `runtime-build-${target}.json`));
  assert.equal(metadata.source_commit, process.env.GITHUB_SHA);
  assert.equal(metadata.target_triple, target);
  assert.equal(metadata.runtime_version, candidate.components.runtime.version);
  assert.equal(metadata.archive_file, `rsrs-runtime-${target}.tar.gz`);
  assert.equal(hash(read(join('release-assets', metadata.archive_file))), artifact.archive_sha256);
  assert.equal(metadata.archive_sha256, artifact.archive_sha256);
  assert.equal(metadata.binary_sha256, artifact.binary_sha256);
  const lock = json('sdk/core-sdk.lock.json');
  const crateLock = json('crates/core-sdk/core-sdk.lock.json');
  assert.deepEqual(lock, crateLock);
  const observed = observeSdkArchive(read(join('.sdk-archives', target, 'sdk.tar.gz')), target, lock.targets[target]);
  assert.deepEqual(observed, artifact.native_sdk, 'Actual compressed SDK and embedded manifest differ from frozen Runtime');
  const sdkDirectory = resolve('.sdk', target);
  auditSdkDirectory(sdkDirectory, target, lock.targets[target]);
  const manifestBytes = read(join(sdkDirectory, 'manifest.json'));
  assert.equal(hash(manifestBytes), observed.manifest_sha256);
  // Mirror the existing stage-core-runtime path mapping and bind every native
  // payload/notices entry to the package that the smoke actually extracts.
  for (const file of JSON.parse(manifestBytes).files) {
    const path = file.path.startsWith('runtime/') ? file.path.slice(8)
      : file.path.startsWith('notices/') ? `core-notices/${file.path.slice(8)}`
        : file.path === 'LICENSE.txt' ? 'core-notices/CORE-SDK-LICENSE.txt' : null;
    if (path === null) continue;
    const packaged = metadata.files.filter(item => item.path === path);
    assert.equal(packaged.length, 1, 'SDK runtime payload missing or duplicated in native package');
    assert.equal(packaged[0].sha256, file.sha256);
    assert.equal(packaged[0].size, read(join(sdkDirectory, file.path)).length);
  }
  return {bytes, candidate, metadata, observed, target};
}

function run() {
  const bound = context();
  const directory = resolve('g1-raw');
  assert.ok(!existsSync(directory), 'Fresh execution directory required');
  assert.ok(!existsSync(join('smoke-report', `runtime-smoke-${bound.target}.json`)), 'Stale smoke evidence exists');
  mkdirSync(directory);
  const started_at = new Date().toISOString();
  const result = spawnSync(process.execPath, ['scripts/smoke-runtime-release.mjs'], {
    stdio: 'inherit', env: {...process.env, RUNTIME_VERSION: bound.metadata.runtime_version,
      EXPECTED_MIN_CLI: bound.metadata.compat.min_cli, EXPECTED_MAX_CLI: bound.metadata.compat.max_cli},
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Actual candidate native smoke failed');
  const raw = read(join('smoke-report', `runtime-smoke-${bound.target}.json`));
  const smoke = JSON.parse(raw);
  assert.equal(smoke.passed, true);
  for (const [key, expected] of Object.entries({source_sha: process.env.GITHUB_SHA,
    repository: process.env.GITHUB_REPOSITORY, run_id: process.env.GITHUB_RUN_ID,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT, target: bound.target,
    archive_sha256: bound.metadata.archive_sha256, binary_sha256: bound.metadata.binary_sha256})) assert.equal(String(smoke[key]), String(expected));
  for (const [id, names] of Object.entries(REQUIRED_CASES)) {
    const cases = smoke.case_results.filter(item => item.test_id === id);
    assert.deepEqual(cases.map(item => item.name).sort(), [...names].sort());
    assert.ok(cases.every(item => item.status === 'passed'));
  }
  writeFileSync(join(directory, 'native-smoke.json'), raw, {flag: 'wx'});
  writeFileSync(join(directory, 'candidate.json'), bound.bytes, {flag: 'wx'});
  save(join(directory, 'execution.json'), {schema: 1, evidence_class: 'candidate-native-raw',
    gate: 'not-evaluated', repository: process.env.GITHUB_REPOSITORY, source_sha: process.env.GITHUB_SHA,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    job_name: `g1-native-smoke (${bound.target})`, target: bound.target,
    candidate_sha256: hash(bound.bytes), actual_native_sdk: bound.observed,
    native_smoke_sha256: hash(raw), started_at, completed_at: new Date().toISOString(),
    producer: 'scripts/produce-runtime-g1-smoke.mjs', command: ['node', 'scripts/smoke-runtime-release.mjs'],
    suites: Object.keys(REQUIRED_CASES)});
}

function report() {
  const bound = context();
  assert.match(process.env.G1_RAW_ARTIFACT_ID ?? '', /^[1-9][0-9]*$/);
  assert.match(process.env.G1_RAW_ARTIFACT_SHA256 ?? '', /^[a-f0-9]{64}$/);
  const name = `required-tests-raw-runtime-native-${bound.target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`;
  assert.equal(process.env.G1_RAW_ARTIFACT_NAME, name);
  const execution = json('g1-raw/execution.json');
  assert.ok(read('g1-raw/candidate.json').equals(bound.bytes), 'Raw artifact must contain the exact frozen candidate bytes');
  const smokeBytes = read('g1-raw/native-smoke.json');
  assert.equal(execution.native_smoke_sha256, hash(smokeBytes));
  assert.equal(execution.candidate_sha256, hash(bound.bytes));
  assert.deepEqual(execution.actual_native_sdk, bound.observed);
  for (const key of ['source_sha', 'run_id', 'run_attempt', 'repository', 'target']) {
    const expected = {source_sha: process.env.GITHUB_SHA, run_id: process.env.GITHUB_RUN_ID,
      run_attempt: process.env.GITHUB_RUN_ATTEMPT, repository: process.env.GITHUB_REPOSITORY, target: bound.target}[key];
    assert.equal(String(execution[key]), expected);
  }
  const smoke = JSON.parse(smokeBytes);
  assert.equal(smoke.passed, true);
  mkdirSync('g1-report/reports', {recursive: true});
  writeFileSync('g1-report/candidate.json', bound.bytes, {flag: 'wx'});
  for (const [id, names] of Object.entries(REQUIRED_CASES)) {
    const cases = smoke.case_results.filter(item => item.test_id === id);
    assert.deepEqual(cases.map(item => item.name).sort(), [...names].sort());
    assert.ok(cases.every(item => item.status === 'passed'));
    save(join('g1-report/reports', `${id}-${bound.target}.json`), {
      schema: 2, test_id: id, target: bound.target, status: 'passed', coverage: 'real-artifact',
      cases: cases.map(({name, status}) => ({name, status})), source_sha: execution.source_sha,
      repository: execution.repository, run_id: execution.run_id, run_attempt: execution.run_attempt,
      candidate_sha256: execution.candidate_sha256, actual_native_sdk: execution.actual_native_sdk,
      job_name: execution.job_name, artifact_id: Number(process.env.G1_RAW_ARTIFACT_ID), artifact_name: name,
      artifact_sha256: process.env.G1_RAW_ARTIFACT_SHA256,
      producer: execution.producer, native_smoke_sha256: execution.native_smoke_sha256,
    });
  }
}

function bundle() {
  const targets = JSON.parse(process.env.G1_TARGETS ?? 'null');
  assert.ok(Array.isArray(targets) && targets.length > 0 && new Set(targets).size === targets.length);
  assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), process.env.GITHUB_SHA);
  const expectedHash = process.env.G1_CANDIDATE_SHA256;
  assert.match(expectedHash ?? '', /^[a-f0-9]{64}$/);
  const output = resolve('g1-final');
  assert.ok(!existsSync(output));
  mkdirSync(join(output, 'reports'), {recursive: true});
  let original;
  const rawIds = new Set();
  const rawHashes = new Set();
  for (const target of targets) {
    assert.match(target, /^[a-z0-9_-]+$/);
    const directory = join('g1-parts', `required-tests-report-part-${target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`);
    const bytes = read(join(directory, 'candidate.json'));
    assert.equal(hash(bytes), expectedHash);
    if (original) assert.ok(bytes.equals(original), 'Every part must contain identical frozen candidate bytes');
    original = bytes;
    const candidate = JSON.parse(bytes);
    assert.equal(candidate.components.runtime.source_sha, process.env.GITHUB_SHA);
    const files = readdirSync(join(directory, 'reports'));
    assert.equal(files.length, Object.keys(REQUIRED_CASES).length);
    let rawId;
    let rawHash;
    for (const [id, names] of Object.entries(REQUIRED_CASES)) {
      const name = `${id}-${target}.json`;
      assert.ok(files.includes(name));
      const reportBytes = read(join(directory, 'reports', name));
      const report = JSON.parse(reportBytes);
      for (const [key, expected] of Object.entries({schema: 2, test_id: id, target, status: 'passed',
        coverage: 'real-artifact', source_sha: process.env.GITHUB_SHA, repository: process.env.GITHUB_REPOSITORY,
        run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT, candidate_sha256: expectedHash,
        job_name: `g1-native-smoke (${target})`,
        artifact_name: `required-tests-raw-runtime-native-${target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`})) {
        assert.equal(String(report[key]), String(expected));
      }
      assert.deepEqual(report.actual_native_sdk, candidate.components.runtime.artifacts[target].native_sdk);
      assert.deepEqual(report.cases.map(item => item.name).sort(), [...names].sort());
      assert.ok(report.cases.every(item => item.status === 'passed'));
      assert.ok(Number.isSafeInteger(report.artifact_id) && report.artifact_id > 0);
      assert.match(report.artifact_sha256 ?? '', /^[a-f0-9]{64}$/);
      if (rawId) assert.equal(report.artifact_id, rawId);
      if (rawHash) assert.equal(report.artifact_sha256, rawHash);
      rawId = report.artifact_id;
      rawHash = report.artifact_sha256;
      writeFileSync(join(output, 'reports', name), reportBytes, {flag: 'wx'});
    }
    assert.ok(!rawIds.has(rawId), 'Different native target executions cannot share one raw artifact');
    rawIds.add(rawId);
    assert.ok(!rawHashes.has(rawHash), 'Different native target executions cannot share one raw artifact hash');
    rawHashes.add(rawHash);
  }
  writeFileSync(join(output, 'candidate.json'), original, {flag: 'wx'});
}
const command = process.argv[2];
if (command === 'run') run();
else if (command === 'report') report();
else if (command === 'bundle') bundle();
else throw new Error('usage: produce-runtime-g1-smoke.mjs run|report|bundle');

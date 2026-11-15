import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {context, BUSINESS_CASES as CASES} from './produce-runtime-g1-smoke.mjs';
import {auditSdkDirectory, observeSdkArchive} from './sdk-ci-cache.mjs';
import {observeConsumerSdk} from './freeze-runtime-g1-candidate.mjs';

export {CASES};
export const selected = [...new Set(Object.values(CASES).flat())].sort();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const read = path => {
  assert.ok(lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink());
  return readFileSync(path);
};
const json = path => JSON.parse(read(path));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});

function inputs() {
  const bound = context();
  assert.equal(process.env.GITHUB_JOB, 'g1-native-memory');
  const harnessTarget = bound.target.replace(/-musl$/, '-gnu');
  assert.equal(process.env.G1_HARNESS_TARGET, harnessTarget);
  assert.equal(process.arch, bound.target.startsWith('aarch64-') ? 'arm64' : 'x64');
  assert.equal(process.platform, bound.target.includes('windows') ? 'win32' : bound.target.includes('apple') ? 'darwin' : 'linux');
  const lock = json('sdk/core-sdk.lock.json');
  const harnessSdk = observeSdkArchive(read(join('.sdk-archives', harnessTarget, 'sdk.tar.gz')), harnessTarget, lock.targets[harnessTarget]);
  auditSdkDirectory(resolve('.sdk', harnessTarget), harnessTarget, lock.targets[harnessTarget]);
  const source = bound.candidate.components.cli.source_sha;
  assert.equal(execFileSync('git', ['-C', '.cli-source', 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), source);
  for (const directory of ['.', '.cli-source']) {
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
  const records = read(join(process.env.RUNNER_TEMP, 'g1-memory-harness-build.jsonl')).toString().trim().split('\n').map(line => JSON.parse(line));
  const artifacts = records.filter(record => record.reason === 'compiler-artifact'
    && record.target?.name === 'cli_business_tests' && record.profile?.test && record.executable);
  assert.equal(artifacts.length, 1);
  const harness = realpathSync(artifacts[0].executable);
  assert.equal(dirname(harness), realpathSync(resolve('target/debug/examples')));
  return {bound, identity: {target: bound.target, source_sha: process.env.GITHUB_SHA, cli_source_sha: source,
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
    root: resolve(process.env.RUNNER_TEMP, `g1-memory-${bound.target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`)}};
}

export function verifyResults(result, identity) {
  assert.equal(result.schema, 1);
  assert.equal(result.passed, true);
  assert.equal(result.test_executed, true);
  assert.equal(result.release_acceptance, false);
  assert.equal(result.offline_installer_verified, true);
  assert.equal(result.target, identity.target);
  assert.deepEqual(result.identity, identity);
  assert.deepEqual([...result.passed_cases].sort(), selected);
  assert.deepEqual(result.model_sha256, {
    'tokenizer.json': '6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790',
    'onnx/model_quantized.onnx': '0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
    'onnx/model_quantized.cpu-v1.ort': '7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff',
  });
}

function run() {
  const {bound, identity} = inputs();
  mkdirSync('g1-memory-raw');
  const request = join(process.env.RUNNER_TEMP, 'g1-memory-request.json');
  save(request, identity);
  const started_at = new Date().toISOString();
  execFileSync('python', ['-B', 'scripts/run-runtime-g1-memory.py', request, 'g1-memory-raw/memory.json'], {stdio: 'inherit'});
  verifyResults(json('g1-memory-raw/memory.json'), identity);
  writeFileSync('g1-memory-raw/candidate.json', bound.bytes, {flag: 'wx'});
  save('g1-memory-raw/execution.json', {schema: 1, ...identity, repository: process.env.GITHUB_REPOSITORY,
    job_name: `g1-native-memory (${bound.target})`, producer: 'scripts/produce-runtime-g1-memory.mjs',
    actual_native_sdk: bound.observed,
    memory_sha256: hash(read('g1-memory-raw/memory.json')), started_at, completed_at: new Date().toISOString()});
}

function report() {
  const {bound, identity} = inputs();
  const execution = json('g1-memory-raw/execution.json');
  for (const [key, value] of Object.entries(identity)) assert.deepEqual(execution[key], value);
  assert.equal(execution.repository, process.env.GITHUB_REPOSITORY);
  assert.equal(execution.job_name, `g1-native-memory (${bound.target})`);
  assert.equal(execution.producer, 'scripts/produce-runtime-g1-memory.mjs');
  assert.deepEqual(execution.actual_native_sdk, bound.observed);
  assert.deepEqual(execution.actual_cli_native_sdk, identity.actual_cli_native_sdk);
  assert.ok(read('g1-memory-raw/candidate.json').equals(bound.bytes));
  assert.equal(execution.memory_sha256, hash(read('g1-memory-raw/memory.json')));
  verifyResults(json('g1-memory-raw/memory.json'), identity);
  const name = `required-tests-raw-runtime-memory-${bound.target}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`;
  assert.equal(process.env.G1_RAW_ARTIFACT_NAME, name);
  assert.match(process.env.G1_RAW_ARTIFACT_ID ?? '', /^[1-9][0-9]*$/);
  assert.match(process.env.G1_RAW_ARTIFACT_SHA256 ?? '', /^[a-f0-9]{64}$/);
  mkdirSync('g1-memory-report/reports', {recursive: true});
  writeFileSync('g1-memory-report/candidate.json', bound.bytes, {flag: 'wx'});
  for (const [id, names] of Object.entries(CASES)) save(join('g1-memory-report/reports', `${id}-${bound.target}.json`), {
    schema: 2, test_id: id, target: bound.target, status: 'passed', coverage: 'real-artifact',
    cases: names.map(name => ({name, status: 'passed'})), source_sha: identity.source_sha,
    repository: execution.repository, run_id: identity.run_id, run_attempt: identity.run_attempt,
    candidate_sha256: identity.candidate_sha256, actual_native_sdk: execution.actual_native_sdk,
    actual_cli_native_sdk: execution.actual_cli_native_sdk, job_name: execution.job_name,
    artifact_id: Number(process.env.G1_RAW_ARTIFACT_ID), artifact_name: name,
    artifact_sha256: process.env.G1_RAW_ARTIFACT_SHA256, producer: execution.producer, memory_sha256: execution.memory_sha256,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv[2] === 'run') run();
  else if (process.argv[2] === 'report') report();
  else throw new Error('usage: produce-runtime-g1-memory.mjs run|report');
}

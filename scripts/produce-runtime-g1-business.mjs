import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {context, BUSINESS_CASES as CASES} from './produce-runtime-g1-smoke.mjs';
import {auditSdkDirectory, observeSdkArchive} from './sdk-ci-cache.mjs';

const target = 'x86_64-unknown-linux-gnu';
const oldClient2 = '57bc070826949994c3f7ce9a64277160704bdfe5';
export {CASES};
const selected = [...new Set(Object.values(CASES).flat())].sort();
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
  for (const [path, sha] of [[cliSource, bound.candidate.components.cli.source_sha], [client2Source, oldClient2]]) {
    assert.equal(execFileSync('git', ['-C', path, 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), sha);
    assert.equal(execFileSync('git', ['-C', path, 'diff', '--name-only', 'HEAD'], {encoding: 'utf8'}).trim(), '');
  }
  assert.equal(bound.candidate.components.client2.source_sha, oldClient2);
  assert.equal(bound.candidate.components.client2.version, '0.2.56');
  const cliMeta = json(join('g1-input', 'cli-assets', `cli-build-${target}.json`));
  const cliArtifact = bound.candidate.components.cli.artifacts[target];
  assert.equal(cliMeta.git_sha, bound.candidate.components.cli.source_sha);
  assert.equal(cliMeta.version, bound.candidate.components.cli.version);
  assert.equal(cliMeta.target, target);
  // The CLI release sidecar names a standalone binary plus its native runtime
  // archive. Neither is the separately packaged standalone Runtime archive.
  assert.equal(cliMeta.binary_file, `rsrs-${target}`);
  assert.equal(cliMeta.runtime_file, `rsrs-${target}-runtime.tar.gz`);
  const cli = resolve('g1-input', 'cli-assets', cliMeta.binary_file);
  assert.equal(hash(read(cli)), cliArtifact.binary_sha256);
  assert.equal(cliMeta.binary_sha256, cliArtifact.binary_sha256);
  assert.equal(hash(read(join('g1-input', 'cli-assets', cliMeta.runtime_file))), cliArtifact.archive_sha256);
  assert.equal(cliMeta.runtime_sha256, cliArtifact.archive_sha256);
  const cliLock = json(join(cliSource, 'sdk/core-sdk.lock.json'));
  const actualCliSdk = observeSdkArchive(read(join(cliSource, '.sdk-archives', target, 'sdk.tar.gz')), target, cliLock.targets[target]);
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
  const desktop = resolve('g1-input', 'client2-assets', 'respire');
  const originalArchive = resolve('g1-input', 'client2-assets', 'respire-linux-amd64.tar.gz');
  const client2Artifact = bound.candidate.components.client2.artifacts[target];
  assert.equal(hash(read(desktop)), client2Artifact.binary_sha256);
  assert.equal(hash(read(originalArchive)), client2Artifact.archive_sha256);
  // Verify the already-hashed original archives themselves contain the exact
  // payload bytes that will execute, not independently supplied loose files.
  execFileSync('python3', ['scripts/verify-business-archive-payloads.py'], {stdio: 'pipe'});
  // The existing launcher also requires its own fixed original desktop hash;
  // arbitrary binaries cannot replace the Go Manager/desktop acceptance input.
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
  assert.equal(business.selected_case_count, 2);
  for (const key of ['required_cases', 'passed_cases']) assert.deepEqual([...business[key]].sort(), selected);
  assert.deepEqual(business.missing_or_failed_cases, []);
  assert.deepEqual(business.owned_process_cleanup, {passed: true, forced: 0});
  assert.equal(business.keyring.passed, true);
  assert.equal(business.keyring.business_passed, true);
  assert.equal(launcher.client2_source, oldClient2);
  assert.equal(launcher.g1_passed, false);
  assert.equal(launcher.inputs.cli_sha256, business.cli_binary_sha256);
  assert.equal(launcher.inputs.runtime_archive_sha256, business.runtime_archive_sha256);
  assert.equal(launcher.inputs.runtime_version, bound.metadata.runtime_version);
  assert.equal(launcher.inputs.ordinary_cli_cold_start, true);
  assert.equal(launcher.desktop_headless.enabled, true);
  assert.equal(launcher.desktop_headless.binary_sha256, bound.candidate.components.client2.artifacts[target].binary_sha256);
  const names = launcher.cases.map(item => item.name);
  assert.equal(new Set(names).size, names.length);
  assert.deepEqual([...names].sort(), ['client2-owned', 'external-cli-cold-start', 'reuse-cli-started',
    'reuse-cli-business-started', 'desktop-owned', 'cli-host-sigterm', 'cli-host-sigkill'].sort());
  assert.ok(launcher.cases.every(item => item.passed === true && item.cleanup_exit === 0));
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
  assert.equal(result.status, 0, 'Real isolated business execution failed');
  const launcherPath = join(directory, 'client2-launcher.json');
  const go = execFileSync('which', ['go'], {encoding: 'utf8'}).trim();
  const launcher = spawnSync('python3', [join(bound.cliSource, 'scripts/test-client2-launcher-compat.py'),
    '--cli', bound.cli, '--runtime-archive', archive, '--runtime-version', bound.metadata.runtime_version,
    '--client2-source', bound.client2Source, '--go', go, '--desktop-executable', bound.desktop,
    '--ordinary-cli-cold-start', '--report', launcherPath], {stdio: 'inherit'});
  assert.ifError(launcher.error);
  assert.equal(launcher.status, 0, 'Original Client2 execution failed');
  const businessBytes = read(join(root, 'result.json'));
  const launcherBytes = read(launcherPath);
  verifyResults(JSON.parse(businessBytes), JSON.parse(launcherBytes), bound);
  inputs(); // Recheck the source, SDK and package bytes after all executions.
  writeFileSync(join(directory, 'business.json'), businessBytes, {flag: 'wx'});
  writeFileSync(join(directory, 'candidate.json'), bound.bytes, {flag: 'wx'});
  save(join(directory, 'execution.json'), {schema: 1, evidence_class: 'candidate-native-raw', gate: 'not-evaluated',
    repository: process.env.GITHUB_REPOSITORY, source_sha: process.env.GITHUB_SHA,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT, target,
    job_name: 'g1-native-business', producer: 'scripts/produce-runtime-g1-business.mjs',
    candidate_sha256: hash(bound.bytes), actual_native_sdk: bound.observed, actual_cli_native_sdk: bound.actualCliSdk,
    harness_sha256: hash(read(bound.harness)), business_sha256: hash(businessBytes), launcher_sha256: hash(launcherBytes),
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
    });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv[2] === 'run') run();
  else if (process.argv[2] === 'report') report();
  else throw new Error('usage: produce-runtime-g1-business.mjs run|report');
}

import assert from 'node:assert/strict';
import {BUSINESS_CASES, stopCasesForTarget} from './produce-runtime-g1-smoke.mjs';
import {TARGETS} from './sdk-ci-cache.mjs';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

// Synthetic evidence validates only assembly rejection paths, never a G1 run.
const script = fileURLToPath(new URL('./produce-runtime-g1-smoke.mjs', import.meta.url));
const parent = resolve(dirname(script), '../.verification/producer-selfcheck');
mkdirSync(parent, {recursive: true});
const gitDir = execFileSync('git', ['rev-parse', '--absolute-git-dir'], {encoding: 'utf8'}).trim();
const sha = execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();
const suites = {
  'runtime.mcp-initialize-tools-list': ['initialize', 'tools/list', 'tools/call:memory_status', 'same-process-after-call'],
  'runtime.client-json-bad-config': ['scoped-structured-invalid-config-envelope',
    'invalid-client-config-bytes-preserved', 'inference-settings-preserved-on-rejection', 'scoped-recovery-preserves-inference-settings'],
};
const targets = ['x86_64-unknown-linux-gnu', ...TARGETS.filter(target => target !== 'x86_64-unknown-linux-gnu')];
const sdk = {version: 'synthetic-only', archive_sha256: 'a'.repeat(64), manifest_sha256: 'b'.repeat(64)};
const legacyCliSdk = {version: 'synthetic-cli-only', archive_sha256: 'c'.repeat(64), manifest_sha256: 'd'.repeat(64)};
for (const cliSdk of [legacyCliSdk, null]) {
const candidateBytes = Buffer.from(JSON.stringify({schema: 2, frozen: true, gate: 'G1',
  components: {runtime: {source_sha: sha, artifacts: Object.fromEntries(targets.map(target => [target, {native_sdk: sdk}]))},
    cli: {artifacts: Object.fromEntries(targets.map(target => [target, {native_sdk: cliSdk}]))}}}));
const digest = createHash('sha256').update(candidateBytes).digest('hex');
const mutations = [
  ['valid', () => {}, true],
  ['candidate bytes', (part) => {part.candidate = Buffer.from('{}');}, false],
  ['SDK archive identity', (part) => {part.reports[0].actual_native_sdk = {...sdk, archive_sha256: 'c'.repeat(64)};}, false],
  ['source identity', (part) => {part.reports[0].source_sha = 'f'.repeat(40);}, false],
  ['mandatory case', (part) => {part.reports[0].cases.pop();}, false],
  ['raw ID reused across targets', (part) => {for (const report of part.reports) report.artifact_id = 31;}, false],
  ['raw hash reused across targets', (part) => {for (const report of part.reports) report.artifact_sha256 = createHash('sha256').update(`smoke-${targets[0]}`).digest('hex');}, false],
  ['target identity', (part) => {part.reports[0].target = 'foreign';}, false],
  ['run attempt', (part) => {part.reports[0].run_attempt = '1';}, false],
  ['stop target part missing', (part) => {part.omit = true;}, false, 'stop'],
  ['stop child missing', (part) => {part.reports[0].cases.pop();}, false, 'stop'],
  ['stop case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.stop-clean-drained').cases.pop();}, false, 'stop'],
  ['force case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.stop-forced-timeout').cases.pop();}, false, 'stop'],
  ['caller timeout case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.stop-caller-timeout-drains').cases.pop();}, false, 'stop'],
  ['Client2 stop report missing', (part) => {part.reports = part.reports.filter(report => report.test_id !== 'runtime.client2-stop-clean-drained');}, false, 'stop'],
  ['fabricated Client2 musl report', (part) => {part.reports.push({...part.reports[0], test_id: 'runtime.client2-stop-clean-drained', cases: [{name: 'client2-owned:normal', status: 'passed'}]});}, false, 'musl-stop'],
  ['stop report missing', (part) => {part.reports = part.reports.filter(report => report.test_id !== 'runtime.stop-clean-drained');}, false, 'stop'],
  ['memory suite missing from stop part', (part) => {part.reports = part.reports.filter(report => report.test_id !== 'runtime.business-memory-write-read');}, false, 'stop'],
  ['memory case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.business-memory-write-read').cases.pop();}, false, 'stop'],
  ['same fingerprint case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.idempotency-same-fingerprint-once').cases.pop();}, false, 'stop'],
  ['conflict case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.idempotency-conflict').cases.pop();}, false, 'stop'],
  ['six-suite digest differs', (part) => {part.reports[0].stop_sha256 = 'c'.repeat(64);}, false, 'stop'],
  ['stop part contains unexpected report', (part) => {part.reports.push({...part.reports[0], test_id: 'runtime.unexpected'});}, false, 'stop'],
  ['stop producer differs', (part) => {part.reports[0].producer = 'scripts/produce-runtime-g1-business.mjs';}, false, 'stop'],
  ['stop digest missing', (part) => {delete part.reports[0].stop_sha256;}, false, 'stop'],
  ['stop wrong job', (part) => {part.reports[0].job_name = 'g1-native-business';}, false, 'stop'],
  ['stop wrong attempt', (part) => {part.reports[0].run_attempt = '1';}, false, 'stop'],
  ['stop wrong SDK', (part) => {part.reports[0].actual_native_sdk = {...sdk, archive_sha256: 'c'.repeat(64)};}, false, 'stop'],
  ['stop raw hash reused', (part) => {for (const report of part.reports) report.artifact_sha256 = createHash('sha256').update(`stop-${targets[0]}`).digest('hex');}, false, 'stop'],
  ['stop CLI SDK differs', (part) => {part.reports[0].actual_cli_native_sdk = {...cliSdk, archive_sha256: 'e'.repeat(64)};}, false, 'stop'],
  ['stop CLI claims Runtime SDK', (part) => {part.reports[0].actual_cli_native_sdk = sdk;}, false, 'stop'],
  ['stop Runtime claims CLI SDK', (part) => {part.reports[0].actual_native_sdk = cliSdk;}, false, 'stop'],
  ['stop raw reused', (part) => {for (const report of part.reports) report.artifact_id = 32;}, false, 'stop'],
];
for (const [name, mutate, passed, kind = 'native'] of mutations) {
  const root = mkdtempSync(join(parent, 'case-'));
  for (const [index, target] of targets.entries()) {
    const part = {candidate: candidateBytes, reports: Object.entries(suites).map(([test_id, names]) => ({
      schema: 2, test_id, target, status: 'passed', coverage: 'real-artifact', source_sha: sha,
      repository: 'risense-ai/respire-runtime', run_id: '17', run_attempt: '2', candidate_sha256: digest,
      job_name: `g1-native-smoke (${target})`, actual_native_sdk: sdk,
      artifact_id: 31 + index, artifact_sha256: createHash('sha256').update(`smoke-${target}`).digest('hex'),
      artifact_name: `required-tests-raw-runtime-native-${target}-17-2`,
      cases: names.map(name => ({name, status: 'passed'})),
    }))};
    if (kind === 'native' && index === 1) mutate(part);
    const directory = join(root, 'g1-parts', `required-tests-report-part-${target}-17-2`);
    mkdirSync(join(directory, 'reports'), {recursive: true});
    writeFileSync(join(directory, 'candidate.json'), part.candidate);
    for (const report of part.reports) writeFileSync(join(directory, 'reports', `${report.test_id}-${target}.json`), JSON.stringify(report));
    const stop = {candidate: candidateBytes, reports: Object.entries({...BUSINESS_CASES, ...stopCasesForTarget(target)}).map(([test_id, names]) => ({
      schema: 2, test_id, target, status: 'passed', coverage: 'real-artifact', source_sha: sha,
      repository: 'risense-ai/respire-runtime', run_id: '17', run_attempt: '2', candidate_sha256: digest,
      job_name: `g1-native-stop (${target})`, actual_native_sdk: sdk, actual_cli_native_sdk: cliSdk,
      producer: 'scripts/produce-runtime-g1-stop.mjs', stop_sha256: 'b'.repeat(64),
      artifact_id: 201 + index, artifact_sha256: createHash('sha256').update(`stop-${target}`).digest('hex'),
      artifact_name: `required-tests-raw-runtime-stop-${target}-17-2`,
      cases: names.map(name => ({name, status: 'passed'})),
    }))};
    if ((kind === 'stop' && index === 1) || (kind === 'musl-stop' && target === 'x86_64-unknown-linux-musl')) mutate(stop);
    if (!stop.omit) {
      const stopDirectory = join(root, 'g1-parts', `required-tests-report-stop-${target}-17-2`);
      mkdirSync(join(stopDirectory, 'reports'), {recursive: true});
      writeFileSync(join(stopDirectory, 'candidate.json'), stop.candidate);
      for (const report of stop.reports) writeFileSync(join(stopDirectory, 'reports', `${report.test_id}-${target}.json`), JSON.stringify(report));
    }
  }
  const obsolete = join(root, 'g1-parts', `required-tests-report-business-${targets[0]}-17-2`);
  mkdirSync(join(obsolete, 'reports'), {recursive: true});
  writeFileSync(join(obsolete, 'reports/ignored.json'), '{}');
  // A real read-only git identity is supplied to a synthetic assembly fixture.
  // No runtime, SDK download, product command or GitHub API is executed.
  const result = spawnSync(process.execPath, [script, 'bundle'], {cwd: root, encoding: 'utf8',
    env: {...process.env, GIT_DIR: gitDir, GIT_WORK_TREE: root, GITHUB_SHA: sha,
      GITHUB_REPOSITORY: 'risense-ai/respire-runtime', GITHUB_RUN_ID: '17', GITHUB_RUN_ATTEMPT: '2',
      G1_CANDIDATE_SHA256: digest, G1_TARGETS: JSON.stringify(targets)}});
  if (result.error) throw result.error;
  assert.equal(result.status === 0, passed, `Synthetic case ${name}: unexpected assembly outcome`);
  if (passed) {
    assert.ok(readFileSync(join(root, 'g1-final/candidate.json')).equals(candidateBytes));
    assert.equal(readdirSync(join(root, 'g1-final/reports')).length, targets.reduce((count, target) => count + Object.keys(suites).length + Object.keys(BUSINESS_CASES).length + Object.keys(stopCasesForTarget(target)).length, 0));
  }
}
console.log(`${mutations.length} synthetic producer assembly checks passed; no product or native acceptance executed`);
}

// These schema checks stop at absent Runtime metadata, before any product execution.
for (const [name, change, reachesRuntime] of [
  ['legacy CLI SDK', () => {}, true],
  ['frontend CLI null', value => {value.components.cli.artifacts[targets[0]].native_sdk = null;}, true],
  ['missing CLI SDK', value => {delete value.components.cli.artifacts[targets[0]].native_sdk;}, false],
  ['invalid legacy CLI SDK', value => {value.components.cli.artifacts[targets[0]].native_sdk.archive_sha256 = 'bad';}, false],
  ['Runtime null', value => {value.components.runtime.artifacts[targets[0]].native_sdk = null;}, false],
]) {
  const value = {schema: 2, frozen: true, gate: 'G1', components: Object.fromEntries(
    ['runtime', 'cli', 'client2'].map(owner => [owner, {source_sha: sha, version: 'synthetic', artifacts: {
      [targets[0]]: {binary_sha256: 'e'.repeat(64), archive_sha256: 'f'.repeat(64),
        native_sdk: owner === 'client2' ? null : structuredClone(owner === 'runtime' ? sdk : legacyCliSdk)},
    }}]))};
  change(value);
  const bytes = Buffer.from(JSON.stringify(value));
  const root = mkdtempSync(join(parent, 'schema-'));
  mkdirSync(join(root, 'g1-input'));
  writeFileSync(join(root, 'g1-input/candidate.json'), bytes);
  const result = spawnSync(process.execPath, ['--input-type=module', '-e',
    `const {context} = await import(${JSON.stringify(pathToFileURL(script).href)}); context();`], {
    cwd: root, encoding: 'utf8', env: {...process.env, GIT_DIR: gitDir,
      GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', G1_NATIVE_PLATFORM: process.platform,
      G1_NATIVE_ARCH: process.arch, RUNNER_ARCH: process.arch === 'arm64' ? 'ARM64' : 'X64',
      CORE_SDK_READ_TOKEN: '', GH_TOKEN: '', GITHUB_TOKEN: '', GITHUB_SHA: sha,
      GITHUB_RUN_ID: '17', GITHUB_RUN_ATTEMPT: '2', GITHUB_REPOSITORY: 'risense-ai/respire-runtime',
      RUNTIME_TARGET: targets[0], G1_CANDIDATE_SHA256: createHash('sha256').update(bytes).digest('hex')},
  });
  assert.equal(result.status, 1, name);
  assert.equal(result.stderr.includes('ENOENT') && result.stderr.includes(`runtime-build-${targets[0]}.json`), reachesRuntime, name);
}
console.log('5 candidate schema refusal checks passed; no Runtime SDK or product execution bypassed');

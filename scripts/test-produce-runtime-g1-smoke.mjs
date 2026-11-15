import assert from 'node:assert/strict';
import {STOP_CASES, BUSINESS_CASES} from './produce-runtime-g1-smoke.mjs';
import {TARGETS} from './sdk-ci-cache.mjs';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

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
const businessSuites = STOP_CASES;
const sdk = {version: 'synthetic-only', archive_sha256: 'a'.repeat(64), manifest_sha256: 'b'.repeat(64)};
const candidateBytes = Buffer.from(JSON.stringify({schema: 2, frozen: true, gate: 'G1',
  components: {runtime: {source_sha: sha, artifacts: Object.fromEntries(targets.map(target => [target, {native_sdk: sdk}]))},
    cli: {artifacts: Object.fromEntries(targets.map(target => [target, {native_sdk: sdk}]))}}}));
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
  ['business part missing', (part) => {part.omit = true;}, false, 'business'],
  ['business case missing', (part) => {part.reports[0].cases.pop();}, false, 'business'],
  ['stop case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.stop-clean-drained').cases.pop();}, false, 'business'],
  ['force case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.stop-forced-timeout').cases.pop();}, false, 'business'],
  ['caller timeout case missing', (part) => {part.reports.find(report => report.test_id === 'runtime.stop-caller-timeout-drains').cases.pop();}, false, 'business'],
  ['stop report missing', (part) => {part.reports = part.reports.filter(report => report.test_id !== 'runtime.stop-clean-drained');}, false, 'business'],
  ['memory part missing', (part) => {part.omit = true;}, false, 'memory'],
  ['memory case missing', (part) => {part.reports[0].cases.pop();}, false, 'memory'],
  ['memory CLI SDK differs', (part) => {part.reports[0].actual_cli_native_sdk = {...sdk, archive_sha256: 'c'.repeat(64)};}, false, 'memory'],
  ['memory producer differs', (part) => {part.reports[0].producer = 'scripts/produce-runtime-g1-business.mjs';}, false, 'memory'],
  ['memory digest missing', (part) => {delete part.reports[0].memory_sha256;}, false, 'memory'],
  ['memory wrong job', (part) => {part.reports[0].job_name = 'g1-native-business';}, false, 'memory'],
  ['memory wrong attempt', (part) => {part.reports[0].run_attempt = '1';}, false, 'memory'],
  ['memory raw reused', (part) => {for (const report of part.reports) report.artifact_id = 31;}, false, 'memory'],
  ['memory duplicates Linux business', (part) => {part.reports.push({...part.reports[0], test_id: 'runtime.business-memory-write-read'});}, false, 'business'],
  ['business CLI SDK differs', (part) => {part.reports[0].actual_cli_native_sdk = {...sdk, archive_sha256: 'c'.repeat(64)};}, false, 'business'],
  ['business raw reused', (part) => {for (const report of part.reports) report.artifact_id = 32;}, false, 'business'],
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
    const memory = {candidate: candidateBytes, reports: Object.entries(BUSINESS_CASES).map(([test_id, names]) => ({
      schema: 2, test_id, target, status: 'passed', coverage: 'real-artifact', source_sha: sha,
      repository: 'risense-ai/respire-runtime', run_id: '17', run_attempt: '2', candidate_sha256: digest,
      job_name: `g1-native-memory (${target})`, actual_native_sdk: sdk, actual_cli_native_sdk: sdk,
      producer: 'scripts/produce-runtime-g1-memory.mjs', memory_sha256: 'a'.repeat(64),
      artifact_id: 101 + index, artifact_sha256: createHash('sha256').update(`memory-${target}`).digest('hex'),
      artifact_name: `required-tests-raw-runtime-memory-${target}-17-2`,
      cases: names.map(name => ({name, status: 'passed'})),
    }))};
    if (kind === 'memory' && index === 1) mutate(memory);
    if (!memory.omit) {
      const memoryDirectory = join(root, 'g1-parts', `required-tests-report-memory-${target}-17-2`);
      mkdirSync(join(memoryDirectory, 'reports'), {recursive: true});
      writeFileSync(join(memoryDirectory, 'candidate.json'), memory.candidate);
      for (const report of memory.reports) writeFileSync(join(memoryDirectory, 'reports', `${report.test_id}-${target}.json`), JSON.stringify(report));
    }
  }
  const business = {candidate: candidateBytes, reports: Object.entries(businessSuites).map(([test_id, names]) => ({
    schema: 2, test_id, target: targets[0], status: 'passed', coverage: 'real-artifact', source_sha: sha,
    repository: 'risense-ai/respire-runtime', run_id: '17', run_attempt: '2', candidate_sha256: digest,
    job_name: 'g1-native-business', actual_native_sdk: sdk, actual_cli_native_sdk: sdk,
    artifact_id: 99, artifact_sha256: 'f'.repeat(64),
    artifact_name: `required-tests-raw-runtime-business-${targets[0]}-17-2`,
    cases: names.map(name => ({name, status: 'passed'})),
  }))};
  if (kind === 'business') mutate(business);
  if (!business.omit) {
    const directory = join(root, 'g1-parts', `required-tests-report-business-${targets[0]}-17-2`);
    mkdirSync(join(directory, 'reports'), {recursive: true});
    writeFileSync(join(directory, 'candidate.json'), business.candidate);
    for (const report of business.reports) writeFileSync(join(directory, 'reports', `${report.test_id}-${targets[0]}.json`), JSON.stringify(report));
  }
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
    assert.equal(readdirSync(join(root, 'g1-final/reports')).length, targets.length * (Object.keys(suites).length + Object.keys(BUSINESS_CASES).length) + Object.keys(businessSuites).length);
  }
}
console.log(`${mutations.length} synthetic producer assembly checks passed; no product or native acceptance executed`);

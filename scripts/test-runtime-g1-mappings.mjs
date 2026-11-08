import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REQUIRED_CASES, BUSINESS_CASES} from './produce-runtime-g1-smoke.mjs';
import {TARGETS} from './sdk-ci-cache.mjs';

// Validate draft mappings directly: missing status must not hide malformed
// source/evidence declarations. This does not turn a missing suite into green.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = path => readFileSync(join(root, path), 'utf8').replace(/\r\n/g, '\n');
const registry = JSON.parse(read('scripts/required-tests.json'));
const workflow = read('.github/workflows/ci.yml');
assert.equal(registry.tests.length, 8);
assert.ok(registry.tests.every(item => item.status === 'missing' && item.reason));
function job(name) {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  assert.ok(start >= 0);
  const tail = workflow.slice(start + 1);
  const end = tail.slice(1).search(/\n  [a-z0-9_-]+:\n/);
  return end < 0 ? tail : tail.slice(0, end + 1);
}
const expected = {...REQUIRED_CASES, ...BUSINESS_CASES};
for (const [id, cases] of Object.entries(expected)) {
  const item = registry.tests.find(item => item.id === id);
  assert.ok(item);
  assert.equal(item.coverage, 'real-artifact');
  assert.deepEqual(item.required_cases, cases);
  assert.deepEqual([...item.required_targets].sort(), [...TARGETS].sort());
  assert.ok(Array.isArray(item.source_suite) && item.source_suite.length > 0);
  for (const suite of item.source_suite) {
    assert.ok(suite.file && !suite.file.startsWith('/') && !suite.file.includes('..'));
    assert.ok(typeof suite.test === 'string' && suite.test);
    assert.ok(suite.command.includes(suite.test));
    assert.ok(read(suite.file).includes(suite.test));
    if (Object.hasOwn(REQUIRED_CASES, id)) {
      assert.equal(suite.test, 'scripts/smoke-runtime-release.mjs');
      assert.equal(suite.command, 'node scripts/smoke-runtime-release.mjs');
      assert.ok(read(suite.test).includes('await runRuntimeMcpProbe('));
      assert.ok(read(suite.test).includes('assertBadConfigResponse(JSON.parse(body)'));
    } else {
      assert.match(suite.command, /^cargo test --locked -p respire_commands --example cli_business_tests diary_identity::\w+ -- --exact$/);
      assert.ok(read(suite.file).includes(`fn ${suite.test}(`));
    }
  }
  assert.equal(item.evidence.workflow, '.github/workflows/ci.yml');
  const body = job(item.evidence.job);
  assert.ok(body.includes(`run: ${item.evidence.command_fragment}`) || body.includes(`          ${item.evidence.command_fragment}\n`));
  if (Object.hasOwn(BUSINESS_CASES, id)) {
    assert.equal(item.evidence.job_name, 'g1-native-business');
    assert.equal(item.evidence.matrix, undefined, 'A plain job must not claim matrix job-name syntax');
  }
}
assert.ok(job('required-tests').includes("    if: ${{ always() && (inputs.required_candidate_run_id != '' || inputs.required_candidate_artifact_id != '' || inputs.required_candidate_sha256 != '') }}\n"));
assert.ok(job('ci-complete').includes("assert.equal(env.REQUIRED_RESULT, requested ? 'success' : 'skipped',"));
assert.ok(job('g1-report').includes('needs: [g1-native-smoke, g1-native-business]'));
assert.ok(job('g1-native-business').includes('G1_RAW_ARTIFACT_ID: ${{ steps.raw.outputs.artifact-id }}'));
assert.ok(job('g1-native-business').includes('G1_RAW_ARTIFACT_SHA256: ${{ steps.raw.outputs.artifact-digest }}'));
console.log('5 draft suite mappings validated outside the missing-status branch; all 8 entries remain missing');

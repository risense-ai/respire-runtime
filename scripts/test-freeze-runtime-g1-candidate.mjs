import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {FREEZE_TARGETS, validatePart, assembleCandidate} from './freeze-runtime-g1-candidate.mjs';

const expected = {source_sha: 'a'.repeat(40), cli_source_sha: 'b'.repeat(40), run_id: '1234', run_attempt: '2'};
const hash = 'c'.repeat(64), alternate = 'd'.repeat(64);
const sdk = {version: '1.1.0-dev.1', archive_sha256: hash, manifest_sha256: alternate};
const part = target => ({schema: 1, kind: 'unpublished-source-fixture-input', g1_passed: false,
  ...expected, target, runtime_version: '1.1.0-dev.2', cli_version: '1.1.0-dev.2',
  native_sdk: {runtime: structuredClone(sdk), cli: structuredClone(sdk)},
  files: [{path: `release-assets/rsrs-runtime-${target}`, size: 31, sha256: hash}]});
const parts = () => FREEZE_TARGETS.map(part);
const observed = () => Object.fromEntries(FREEZE_TARGETS.map(target => [target, {
  runtime: {archive_sha256: hash, binary_sha256: alternate},
  cli: {archive_sha256: alternate, binary_sha256: hash},
  ...(target === FREEZE_TARGETS[0] ? {client2: {archive_sha256: hash, binary_sha256: alternate}} : {}),
}]));

test('freeze keeps original source/bytes distinct from G1 acceptance', () => {
  const candidate = assembleCandidate(parts(), expected, observed());
  assert.equal(candidate.schema, 2);
  assert.equal(candidate.frozen, true);
  assert.equal(candidate.gate, 'G1');
  assert.equal(candidate.components.runtime.source_sha, expected.source_sha);
  assert.equal(candidate.components.cli.source_sha, expected.cli_source_sha);
  assert.equal(candidate.components.client2.source_sha, '57bc070826949994c3f7ce9a64277160704bdfe5');
  assert.equal(candidate.components.client2.version, '0.2.56');
  assert.deepEqual(Object.keys(candidate.components.runtime.artifacts).sort(), [...FREEZE_TARGETS].sort());
  assert.equal(candidate.components.client2.artifacts[FREEZE_TARGETS[0]].native_sdk, null);
  assert.deepEqual(candidate.components.cli.artifacts[FREEZE_TARGETS[0]].native_sdk, sdk);
  assert.equal(Object.hasOwn(candidate, 'g1_passed'), false);
  assert.equal(Object.hasOwn(candidate, 'sdk'), false);
});
for (const [name, mutate] of [
  ['other source', value => {value.source_sha = 'd'.repeat(40);}],
  ['other CLI', value => {value.cli_source_sha = 'd'.repeat(40);}],
  ['other run', value => {value.run_id = '1235';}],
  ['other attempt', value => {value.run_attempt = '1';}],
  ['claimed acceptance', value => {value.g1_passed = true;}],
  ['other kind', value => {value.kind = 'release';}],
  ['missing SDK archive', value => {delete value.native_sdk.runtime.archive_sha256;}],
  ['mixed SDK bytes', value => {value.native_sdk.cli.archive_sha256 = alternate;}],
  ['duplicate inventory', value => {value.files.push({...value.files[0]});}],
  ['traversal', value => {value.files[0].path = 'release-assets/../secret';}],
  ['absolute path', value => {value.files[0].path = '/release-assets/file';}],
  ['windows path', value => {value.files[0].path = 'release-assets/C:file';}],
  ['backslash', value => {value.files[0].path = 'release-assets/a\\b';}],
  ['SDK upload', value => {value.files[0].path = '.sdk-archives/sdk.tar.gz';}],
  ['unbounded size', value => {value.files[0].size = Number.MAX_SAFE_INTEGER + 1;}],
  ['false digest', value => {value.files[0].sha256 = 'invalid';}],
]) test(`reject ${name}`, () => {
  const value = part(FREEZE_TARGETS[0]); mutate(value);
  assert.throws(() => validatePart(value, expected, FREEZE_TARGETS[0]));
});
test('reject missing/duplicated targets and mixed consumer versions', () => {
  assert.throws(() => assembleCandidate([part(FREEZE_TARGETS[0])], expected, observed()));
  assert.throws(() => assembleCandidate([part(FREEZE_TARGETS[0]), part(FREEZE_TARGETS[0])], expected, observed()));
  const changed = parts(); changed[1].runtime_version = 'other';
  assert.throws(() => assembleCandidate(changed, expected, observed()));
  changed[1].runtime_version = changed[0].runtime_version; changed[1].cli_version = 'other';
  assert.throws(() => assembleCandidate(changed, expected, observed()));
  const mixedSdk = parts();
  mixedSdk[1].native_sdk.runtime.version = mixedSdk[1].native_sdk.cli.version = '1.1.0-dev.2';
  assert.throws(() => assembleCandidate(mixedSdk, expected, observed()));
});
test('reject missing actual component archive/binary observations', () => {
  for (const component of ['runtime', 'cli', 'client2']) for (const key of ['archive_sha256', 'binary_sha256']) {
    const artifacts = observed(); artifacts[FREEZE_TARGETS[0]][component][key] = null;
    assert.throws(() => assembleCandidate(parts(), expected, artifacts));
  }
});
test('workflow retains explicit read-only SDK cache and source boundaries', () => {
  const workflow = readFileSync(new URL('../.github/workflows/freeze-g1-candidate.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  // The parent script directory is scripts/, so resolve through the repository root.
  assert.ok(workflow.includes('contents: read\n  actions: read'));
  assert.doesNotMatch(workflow, /secrets\.|actions\/cache\/save|contents: write|actions: write/);
  assert.ok(workflow.includes('fail-on-cache-miss: true'));
  assert.ok(workflow.includes('archive-key "$RUNTIME_TARGET"'));
  assert.ok(workflow.includes('node scripts/sdk-ci-cache.mjs observe "$RUNTIME_TARGET"'));
  assert.ok(workflow.includes('export RSRS_CORE_SDK_DIR="$PWD/.sdk/$RUNTIME_TARGET"'));
  assert.ok(workflow.includes('hashlib.sha256(raw).hexdigest() == expected_digest'));
  assert.ok(workflow.includes("with output.open('xb')"));
  assert.doesNotMatch(workflow, /actions\/download-artifact/);
  assert.ok(workflow.includes('node --test scripts/test-freeze-runtime-g1-candidate.mjs'));
  assert.ok(workflow.includes("(output / 'respire-linux-amd64.tar.gz').write_bytes(payload)"));
  assert.ok(workflow.includes('artifact-id'));
  assert.ok(workflow.includes('artifact-digest'));
  assert.ok(workflow.includes('G1: not evaluated'));
});

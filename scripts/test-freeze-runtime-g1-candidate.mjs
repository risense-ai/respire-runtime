import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {gzipSync} from 'node:zlib';
import test from 'node:test';
import {FREEZE_TARGETS, validatePart, assembleCandidate, observeConsumerSdk} from './freeze-runtime-g1-candidate.mjs';

const expected = {source_sha: 'a'.repeat(40), cli_source_sha: 'b'.repeat(40), run_id: '1234', run_attempt: '2'};
const hash = 'c'.repeat(64), alternate = 'd'.repeat(64);
const sdk = {version: '1.1.0-dev.1', archive_sha256: hash, manifest_sha256: alternate};
const cliSdk = {version: '2.0.0-dev.4', archive_sha256: alternate, manifest_sha256: hash};
const part = target => ({schema: 1, kind: 'unpublished-source-fixture-input', g1_passed: false,
  ...expected, target, runtime_version: '1.1.0-dev.2', cli_version: '1.1.0-dev.2',
  native_sdk: {runtime: structuredClone(sdk), cli: structuredClone(cliSdk)},
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
  assert.equal(candidate.components.client2.source_sha, '1734322b6c6dd543441a753f07a3517bee5e1231');
  assert.equal(candidate.components.client2.version, '0.2.56-dev.259');
  assert.deepEqual(Object.keys(candidate.components.runtime.artifacts).sort(), [...FREEZE_TARGETS].sort());
  assert.equal(candidate.components.client2.artifacts[FREEZE_TARGETS[0]].native_sdk, null);
  assert.deepEqual(candidate.components.runtime.artifacts[FREEZE_TARGETS[0]].native_sdk, sdk);
  assert.deepEqual(candidate.components.cli.artifacts[FREEZE_TARGETS[0]].native_sdk, cliSdk);
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
  ['invalid CLI SDK digest', value => {value.native_sdk.cli.archive_sha256 = 'invalid';}],
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
  for (const owner of ['runtime', 'cli']) {
    const mixedSdk = parts();
    mixedSdk[1].native_sdk[owner].version = '1.1.0-dev.2';
    assert.throws(() => assembleCandidate(mixedSdk, expected, observed()));
  }
});
test('each consumer observes its own SDK bytes and rejects substitutions or divergent lock copies', () => {
  const root = mkdtempSync(join(process.cwd(), '.sdk-decoupling-'));
  const target = FREEZE_TARGETS[0], digest = value => createHash('sha256').update(value).digest('hex');
  function fixture(owner, version) {
    const directory = join(root, owner), payload = Buffer.from(owner);
    const manifest = Buffer.from(JSON.stringify({target, sdk_version: version, abi_version: 0x10002,
      inference_thread_contract: 1, association_contract: 1, models_bundled: false,
      redistribution: 'permitted-under-included-license',
      files: [{path: 'runtime/core.so', sha256: digest(payload)}]}));
    const entries = [['manifest.json', manifest], ['runtime/core.so', payload]];
    const blocks = [];
    for (const [name, value] of entries) {
      const header = Buffer.alloc(512);
      header.write(name); header.write(value.length.toString(8).padStart(11, '0') + '\0', 124);
      header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257);
      header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
      blocks.push(header, value, Buffer.alloc((512 - value.length % 512) % 512));
    }
    const archive = gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
    const base = `https://github.com/risense-ai/respire-core/releases/download/sdk-v${version}/respire-core-sdk-${target}`;
    const entry = {sdk_version: version, private_repository: 'risense-ai/respire-core', release_tag: `sdk-v${version}`,
      url: base + '.manifest.json', archive_url: base + '.tar.gz', redistribution: 'approved',
      manifest_sha256: digest(manifest), archive_sha256: digest(archive)};
    const lock = JSON.stringify({schema_version: 1, targets: {[target]: entry}});
    for (const [path, value] of [...entries.map(([name, value]) => [`.sdk/${target}/${name}`, value]),
      [`.sdk-archives/${target}/sdk.tar.gz`, archive], ['sdk/core-sdk.lock.json', lock],
      ['crates/core-sdk/core-sdk.lock.json', lock]]) {
      const file = join(directory, path); mkdirSync(dirname(file), {recursive: true}); writeFileSync(file, value);
    }
    return {directory, archive, lock, manifest, payload, observed: {version,
      archive_sha256: entry.archive_sha256, manifest_sha256: entry.manifest_sha256}};
  }
  try {
    const runtime = fixture('runtime', sdk.version), cli = fixture('cli', cliSdk.version);
    for (const [owner, other] of [[runtime, cli], [cli, runtime]]) {
      assert.deepEqual(observeConsumerSdk(owner.directory, target), owner.observed);
      const archive = join(owner.directory, '.sdk-archives', target, 'sdk.tar.gz');
      writeFileSync(archive, other.archive);
      assert.throws(() => observeConsumerSdk(owner.directory, target), /archive hash mismatch/);
      writeFileSync(archive, owner.archive);
      const manifest = join(owner.directory, '.sdk', target, 'manifest.json');
      writeFileSync(manifest, other.manifest);
      assert.throws(() => observeConsumerSdk(owner.directory, target), /manifest hash mismatch/);
      writeFileSync(manifest, owner.manifest);
      const payload = join(owner.directory, '.sdk', target, 'runtime/core.so');
      writeFileSync(payload, other.payload);
      assert.throws(() => observeConsumerSdk(owner.directory, target), /corrupt SDK cache file/);
      writeFileSync(payload, owner.payload);
      const crateLock = join(owner.directory, 'crates/core-sdk/core-sdk.lock.json');
      writeFileSync(crateLock, other.lock);
      assert.throws(() => observeConsumerSdk(owner.directory, target), /lock copies differ/);
      writeFileSync(crateLock, owner.lock);
      assert.deepEqual(observeConsumerSdk(owner.directory, target), owner.observed);
    }
  } finally {
    rmSync(root, {recursive: true});
  }
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
  assert.ok(workflow.includes('RSRS_CORE_SDK_DIR="$PWD/.cli-source/.sdk/$RUNTIME_TARGET" cargo build'));
  assert.ok(workflow.includes('(cd .cli-source && RSRS_CORE_SDK_DIR="$PWD/.sdk/$RUNTIME_TARGET" bash scripts/build-linux-musl.sh'));
  assert.ok(workflow.includes('hashlib.sha256(raw).hexdigest() == expected_digest'));
  assert.ok(workflow.includes("with output.open('xb')"));
  assert.doesNotMatch(workflow, /actions\/download-artifact/);
  assert.ok(workflow.includes('node --test scripts/test-freeze-runtime-g1-candidate.mjs'));
  assert.ok(workflow.includes("(output / 'respire-linux-amd64.tar.gz').write_bytes(payload)"));
  assert.ok(workflow.includes('artifact-id'));
  assert.ok(workflow.includes('artifact-digest'));
  assert.ok(workflow.includes('G1: not evaluated'));
  const ci = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const business = ci.slice(ci.indexOf('  g1-native-business:'), ci.indexOf('  g1-native-stop:'));
  const stop = ci.slice(ci.indexOf('  g1-native-stop:'), ci.indexOf('  g1-report:'));
  for (const body of [workflow, business, stop]) {
    assert.ok(body.includes('cmp sdk/core-sdk.lock.json crates/core-sdk/core-sdk.lock.json'));
    assert.ok(body.includes('cmp .cli-source/sdk/core-sdk.lock.json .cli-source/crates/core-sdk/core-sdk.lock.json'));
    assert.ok(body.includes('$(cd .cli-source && node ../scripts/sdk-ci-cache.mjs key "$RUNTIME_TARGET")'));
    assert.ok(body.includes('$(cd .cli-source && node ../scripts/sdk-ci-cache.mjs archive-key "$RUNTIME_TARGET")'));
    assert.ok(body.includes('(cd .cli-source && node ../scripts/sdk-ci-cache.mjs observe "$RUNTIME_TARGET")'));
    assert.ok(body.includes('steps.cli-payload.outputs.cache-matched-key'));
    assert.ok(body.includes('steps.cli-archive.outputs.cache-matched-key'));
    assert.ok(body.includes('mv ".sdk/$RUNTIME_TARGET" ".cli-source/.sdk/$RUNTIME_TARGET"'));
    assert.ok(body.includes('mv ".sdk-archives/$RUNTIME_TARGET" ".cli-source/.sdk-archives/$RUNTIME_TARGET"'));
    assert.ok(body.indexOf('id: cli-payload') < body.indexOf('mv ".sdk/$RUNTIME_TARGET"'));
    assert.ok(body.indexOf('mv ".sdk/$RUNTIME_TARGET"') < body.indexOf('id: payload'));
    assert.doesNotMatch(body, /cmp sdk\/core-sdk.lock.json \.cli-source|copytree|cp -a \.sdk/);
  }
  const smokeMatrix = ci.slice(ci.indexOf('  g1-native-smoke:'), ci.indexOf('  g1-native-business:'));
  for (const target of FREEZE_TARGETS) {
    assert.ok(workflow.includes(`target: ${target}`), `Missing native freeze target ${target}`);
    assert.ok(smokeMatrix.includes(`target: ${target}`), `Missing native smoke target ${target}`);
  }
  assert.deepEqual(JSON.parse(ci.match(/G1_TARGETS: '([^']+)'/)[1]), FREEZE_TARGETS);
  const producer = readFileSync(new URL('./freeze-runtime-g1-candidate.mjs', import.meta.url), 'utf8');
  const release = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  for (const capability of ['business_executor', 'mcp_server', 'offline_keygen_handoff']) {
    const declaration = `${capability}: '1'`;
    assert.ok(producer.includes(declaration), `Frozen installer metadata is missing ${capability}`);
    assert.ok(release.includes(declaration), `Published installer metadata is missing ${capability}`);
  }
});

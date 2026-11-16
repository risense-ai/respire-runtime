import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {auditSdkDirectory, observeSdkArchive} from './sdk-ci-cache.mjs';

// This creates inputs, never acceptance reports. No SDK archive is uploaded.
export const FREEZE_TARGETS = ['x86_64-unknown-linux-gnu', 'aarch64-apple-darwin',
  'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc', 'x86_64-apple-darwin',
  'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl'];
const client2Source = '6ffa187685734873721ab51f3a54d8b2c29cd269';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function ordinary(root, name) {
  assert.ok(typeof name === 'string' && name && !/[\\:\0]/.test(name));
  let path = root;
  for (const part of name.split('/')) {
    assert.ok(part && part !== '.' && part !== '..');
    path = join(path, part);
    assert.ok(!lstatSync(path).isSymbolicLink());
  }
  assert.ok(lstatSync(path).isFile());
  return path;
}
const bytes = (root, name) => readFileSync(ordinary(root, name));
const json = (root, name) => JSON.parse(bytes(root, name));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
function files(root, prefix = '') {
  return readdirSync(join(root, prefix), {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name))
    .flatMap(entry => {
      assert.ok(!entry.isSymbolicLink());
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      return entry.isDirectory() ? files(root, name) : [name];
    });
}
function copy(root, name, output) {
  const target = join(output, name);
  mkdirSync(dirname(target), {recursive: true});
  copyFileSync(ordinary(root, name), target);
}
function credentialsAbsent() {
  for (const key of ['CORE_SDK_READ_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN']) assert.ok(!process.env[key]);
}
function checkedContext() {
  credentialsAbsent();
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(process.env.GITHUB_EVENT_NAME, 'workflow_dispatch');
  assert.equal(process.env.GITHUB_REPOSITORY, 'risense-ai/respire-runtime');
  for (const key of ['GITHUB_SHA', 'FREEZE_CLI_SHA']) assert.match(process.env[key] ?? '', /^[a-f0-9]{40}$/);
  for (const key of ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']) assert.match(process.env[key] ?? '', /^[1-9][0-9]*$/);
  assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), process.env.GITHUB_SHA);
  assert.equal(execFileSync('git', ['diff', '--name-only', 'HEAD'], {encoding: 'utf8'}).trim(), '');
  return {source_sha: process.env.GITHUB_SHA, cli_source_sha: process.env.FREEZE_CLI_SHA,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT};
}
export function validatePart(part, expected, target) {
  assert.equal(part.schema, 1);
  assert.equal(part.kind, 'unpublished-source-fixture-input');
  assert.equal(part.g1_passed, false);
  assert.ok(FREEZE_TARGETS.includes(target));
  assert.equal(part.target, target);
  for (const key of ['source_sha', 'cli_source_sha', 'run_id', 'run_attempt']) assert.equal(part[key], expected[key]);
  assert.ok(typeof part.runtime_version === 'string' && part.runtime_version);
  assert.ok(typeof part.cli_version === 'string' && part.cli_version);
  assert.equal(part.native_sdk.cli, null, 'The frozen CLI is a frontend, not an SDK consumer');
  for (const owner of ['runtime']) {
    const observed = part.native_sdk[owner];
    assert.deepEqual(Object.keys(observed).sort(), ['archive_sha256', 'manifest_sha256', 'version']);
    assert.ok(typeof observed.version === 'string' && observed.version);
    for (const key of ['archive_sha256', 'manifest_sha256']) assert.match(observed[key], /^[a-f0-9]{64}$/);
  }
  assert.ok(Array.isArray(part.files) && part.files.length);
  const names = new Set();
  for (const file of part.files) {
    assert.ok(typeof file.path === 'string' && !/[\\:\0]/.test(file.path));
    assert.ok(file.path.split('/').every(value => value && value !== '.' && value !== '..'));
    assert.ok(/^(release-assets|cli-assets|client2-assets)\//.test(file.path));
    assert.ok(!names.has(file.path)); names.add(file.path);
    assert.match(file.sha256, /^[a-f0-9]{64}$/);
    assert.ok(Number.isSafeInteger(file.size) && file.size >= 0);
  }
}
function staged(sdk, script, output, target) {
  mkdirSync(output);
  execFileSync('node', [script, output], {env: {...process.env, RSRS_CORE_SDK_DIR: sdk}, stdio: 'inherit'});
  const core = json(output, 'core-runtime.json');
  assert.equal(core.target, target);
  return core;
}
function archive(payload, output) {
  // Git's tar treats Windows drive letters as remote hosts; use the native tool.
  const tar = process.platform === 'win32' ? join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar';
  execFileSync(tar, ['--format=ustar', '-czf', output, '-C', payload, '.'], {stdio: 'inherit'});
}
export function observeConsumerSdk(root, target) {
  const lock = bytes(root, 'sdk/core-sdk.lock.json');
  assert.ok(lock.equals(bytes(root, 'crates/core-sdk/core-sdk.lock.json')), 'Consumer SDK lock copies differ');
  const entry = JSON.parse(lock).targets[target];
  const observed = observeSdkArchive(bytes(root, `.sdk-archives/${target}/sdk.tar.gz`), target, entry);
  auditSdkDirectory(join(root, '.sdk', target), target, entry);
  assert.equal(digest(bytes(root, `.sdk/${target}/manifest.json`)), observed.manifest_sha256);
  return observed;
}
export function frontendMetadata(binary, target, version, context) {
  assert.ok(binary.length > 0, 'Frozen frontend binary must not be empty');
  return {schema_version: 2, artifact_layout: 'cli-frontend-v2', version, git_sha: context.cli_source_sha,
    target, binary_file: `rsrs-${target}${target.includes('windows') ? '.exe' : ''}`,
    binary_size: binary.length, binary_sha256: digest(binary),
    producer: {run_id: context.run_id, run_attempt: context.run_attempt}};
}
async function packagePart() {
  const context = checkedContext(), target = process.env.RUNTIME_TARGET;
  assert.ok(FREEZE_TARGETS.includes(target));
  assert.equal(process.platform, target.includes('windows') ? 'win32' : target.includes('apple') ? 'darwin' : 'linux');
  assert.equal(process.arch, target.includes('aarch64') ? 'arm64' : 'x64');
  const cli = resolve('.cli-source');
  assert.equal(execFileSync('git', ['-C', cli, 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(), context.cli_source_sha);
  assert.equal(execFileSync('git', ['-C', cli, 'diff', '--name-only', 'HEAD'], {encoding: 'utf8'}).trim(), '');
  const native_sdk = {runtime: observeConsumerSdk(resolve('.'), target), cli: null};
  const dependencies = execFileSync('cargo', ['tree', '--locked', '-p', 'respire', '--edges', 'normal', '--prefix', 'none'], {cwd: cli, encoding: 'utf8'});
  assert.doesNotMatch(dependencies, /^respire_core_sdk\s/m, 'Frontend CLI must not consume the native SDK');
  const runtimeMetadata = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--no-deps', '--format-version', '1'], {encoding: 'utf8'}));
  const cliMetadata = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--no-deps', '--format-version', '1'], {cwd: cli, encoding: 'utf8'}));
  const runtimePackage = runtimeMetadata.packages.filter(value => value.name === 'respire_runtime');
  const cliPackage = cliMetadata.packages.filter(value => value.name === 'respire');
  assert.equal(runtimePackage.length, 1); assert.equal(cliPackage.length, 1);
  const runtimeVersion = runtimePackage[0].version, cliVersion = cliPackage[0].version;
  const output = resolve('freeze-part'); mkdirSync(output);
  const release = join(output, 'release-assets'), cliAssets = join(output, 'cli-assets');
  mkdirSync(release); mkdirSync(cliAssets);
  const work = join(process.env.RUNNER_TEMP, `freeze-payload-${target}`); mkdirSync(work);
  const runtimePayload = join(work, 'runtime'), cliPayload = join(work, 'cli');
  staged(resolve('.sdk', target), 'scripts/stage-core-runtime.mjs', runtimePayload, target);
  mkdirSync(cliPayload);
  const suffix = target.includes('windows') ? '.exe' : '';
  const runtimeName = `rsrs-runtime-${target}${suffix}`, cliName = `rsrs-${target}${suffix}`;
  const build = target.includes('musl') ? `target/ci/${target}/debug` : `target/${target}/debug`;
  copyFileSync(ordinary('.', `${build}/rsrs-runtime${suffix}`), join(runtimePayload, runtimeName));
  copyFileSync(ordinary(cli, `${build}/rsrs${suffix}`), join(cliAssets, cliName));
  copyFileSync(join(cliAssets, cliName), join(cliPayload, cliName));
  copyFileSync(join(runtimePayload, runtimeName), join(release, runtimeName));
  const inventory = files(runtimePayload).map(path => ({path, size: bytes(runtimePayload, path).length, sha256: digest(bytes(runtimePayload, path))}));
  const runtimeArchive = `rsrs-runtime-${target}.tar.gz`, cliArchive = `rsrs-${target}-runtime.tar.gz`;
  const cliBuild = frontendMetadata(bytes(cliAssets, cliName), target, cliVersion, context);
  const {validateBuildMetadata} = await import(pathToFileURL(join(cli, 'npm/scripts/verify-binary.mjs')).href);
  validateBuildMetadata(cliBuild, json(cli, 'npm/artifact-manifest.json'), target,
    {sha: context.cli_source_sha, version: cliVersion, run_id: context.run_id, run_attempt: context.run_attempt},
    {file: cliName, size: cliBuild.binary_size, sha256: cliBuild.binary_sha256});
  save(join(cliAssets, `cli-build-${target}.json`), cliBuild);
  copyFileSync(join(cliAssets, `cli-build-${target}.json`), join(cliPayload, `cli-build-${target}.json`));
  archive(runtimePayload, join(release, runtimeArchive)); archive(cliPayload, join(cliAssets, cliArchive));
  const cliHash = digest(bytes(cliAssets, cliName));
  // Candidate identity is created BEFORE freezing or hashing this original sidecar.
  save(join(release, `runtime-build-${target}.json`), {schema_version: 2, runtime_version: runtimeVersion,
    tag: `v${runtimeVersion}`, channel: 'dev', target_triple: target, archive_file: runtimeArchive,
    archive_sha256: digest(bytes(release, runtimeArchive)), binary_file: runtimeName,
    binary_sha256: digest(bytes(release, runtimeName)), source_commit: context.source_sha,
    compat: {min_cli: cliVersion, max_cli: '*'}, protocol_range: {minimum: 1, maximum: 1},
    capabilities: {business_executor: '1', mcp_server: '1', offline_keygen_handoff: '1'}, files: inventory,
    candidate: {kind: 'unpublished-source-fixture', cli_source_sha: context.cli_source_sha, cli_binary_sha256: cliHash}});
  if (target === FREEZE_TARGETS[0]) {
    for (const path of files(cliPayload)) copy(cliPayload, path, cliAssets);
    const desktop = resolve(process.env.RUNNER_TEMP, 'legacy-desktop');
    for (const name of ['respire-linux-amd64.tar.gz', 'respire', 'desktop-source.json']) copy(desktop, name, join(output, 'client2-assets'));
    const provenance = json(output, 'client2-assets/desktop-source.json');
    assert.equal(provenance.source_commit, client2Source);
    assert.equal(provenance.archive_sha256, digest(bytes(output, 'client2-assets/respire-linux-amd64.tar.gz')));
    assert.equal(provenance.binary_sha256, digest(bytes(output, 'client2-assets/respire')));
  }
  const part = {schema: 1, kind: 'unpublished-source-fixture-input', g1_passed: false, ...context, target,
    runtime_version: runtimeVersion, cli_version: cliVersion, native_sdk,
    files: files(output).map(path => ({path, size: bytes(output, path).length, sha256: digest(bytes(output, path))}))};
  validatePart(part, context, target);
  save(join(output, 'part.json'), part);
}
export function assembleCandidate(parts, expected, artifacts) {
  assert.deepEqual(parts.map(part => part.target).sort(), [...FREEZE_TARGETS].sort());
  const observedClient2 = artifacts[FREEZE_TARGETS[0]].client2;
  assert.equal(observedClient2.metadata.source_commit, client2Source);
  assert.equal(observedClient2.metadata.version, '0.2.56-dev.263', 'Client2 source proof version mismatch');
  assert.equal(observedClient2.metadata.repository, 'risense-ai/respire-client2');
  assert.equal(observedClient2.metadata.workflow, '.github/workflows/desktop.yml');
  assert.equal(observedClient2.metadata.release, 'host-owned-candidate');
  for (const key of ['run_id', 'run_attempt', 'artifact_id']) {
    assert.ok(Number.isSafeInteger(observedClient2.metadata[key]) && observedClient2.metadata[key] > 0, `Invalid Client2 proof ${key}`);
  }
  assert.match(observedClient2.metadata.artifact_sha256 ?? '', /^[a-f0-9]{64}$/);
  for (const key of ['archive_sha256', 'binary_sha256']) assert.equal(observedClient2.metadata[key], observedClient2[key]);
  const components = {runtime: {source_sha: expected.source_sha, version: parts[0].runtime_version, artifacts: {}},
    cli: {source_sha: expected.cli_source_sha, version: parts[0].cli_version, artifacts: {}},
    client2: {source_sha: client2Source, version: observedClient2.metadata.version,
      native_artifact: {...observedClient2.metadata}, artifacts: {}}};
  for (const part of parts) {
    validatePart(part, expected, part.target);
    assert.equal(part.runtime_version, components.runtime.version); assert.equal(part.cli_version, components.cli.version);
    assert.equal(part.native_sdk.runtime.version, parts[0].native_sdk.runtime.version);
    for (const owner of ['runtime', 'cli']) {
      components[owner].artifacts[part.target] = {...artifacts[part.target][owner], native_sdk: part.native_sdk[owner]};
    }
    if (part.target === FREEZE_TARGETS[0]) components.client2.artifacts[part.target] = {
      archive_sha256: observedClient2.archive_sha256, binary_sha256: observedClient2.binary_sha256, native_sdk: null};
  }
  for (const component of Object.values(components)) for (const artifact of Object.values(component.artifacts)) {
    for (const key of ['archive_sha256', 'binary_sha256']) assert.match(artifact[key], /^[a-f0-9]{64}$/);
  }
  return {schema: 2, frozen: true, gate: 'G1', components};
}
function assemble() {
  const expected = checkedContext(), output = resolve('g1-input'); mkdirSync(output);
  const origin = json('.', 'freeze-origin.json');
  assert.equal(origin.repository, 'risense-ai/respire-runtime');
  assert.equal(origin.source_sha, expected.source_sha);
  assert.equal(origin.run_id, expected.run_id); assert.equal(origin.run_attempt, expected.run_attempt);
  assert.equal(origin.workflow, '.github/workflows/freeze-g1-candidate.yml');
  assert.deepEqual(origin.artifacts.map(value => value.target).sort(), [...FREEZE_TARGETS].sort());
  const artifactIds = new Set();
  for (const artifact of origin.artifacts) {
    assert.ok(Number.isSafeInteger(artifact.id) && artifact.id > 0 && !artifactIds.has(artifact.id));
    artifactIds.add(artifact.id);
    assert.equal(artifact.name, `g1-freeze-part-${artifact.target}-${expected.run_id}-${expected.run_attempt}`);
    assert.match(artifact.digest, /^sha256:[a-f0-9]{64}$/);
  }
  const parts = [], observedArtifacts = {};
  for (const target of FREEZE_TARGETS) {
    const root = resolve('freeze-parts', target), part = json(root, 'part.json');
    validatePart(part, expected, target);
    assert.deepEqual(files(root).sort(), [...part.files.map(value => value.path), 'part.json'].sort());
    for (const file of part.files) {
      const value = bytes(root, file.path); assert.equal(value.length, file.size); assert.equal(digest(value), file.sha256);
      assert.ok(!part.files.some(other => other !== file && other.path === file.path));
      assert.ok(!existsSync(join(output, file.path)), 'Parts must not overwrite each other');
      copy(root, file.path, output);
    }
    const suffix = target.includes('windows') ? '.exe' : '';
    const runtime = json(root, `release-assets/runtime-build-${target}.json`), cli = json(root, `cli-assets/cli-build-${target}.json`);
    assert.equal(runtime.source_commit, expected.source_sha); assert.equal(runtime.target_triple, target);
    assert.equal(runtime.runtime_version, part.runtime_version); assert.equal(cli.git_sha, expected.cli_source_sha);
    assert.equal(cli.target, target); assert.equal(cli.version, part.cli_version);
    assert.deepEqual(runtime.candidate, {kind: 'unpublished-source-fixture', cli_source_sha: expected.cli_source_sha,
      cli_binary_sha256: digest(bytes(root, `cli-assets/rsrs-${target}${suffix}`))});
    const pair = (prefix, binary, archive) => ({binary_sha256: digest(bytes(root, `${prefix}/${binary}`)), archive_sha256: digest(bytes(root, `${prefix}/${archive}`))});
    const runtimeArtifact = pair('release-assets', `rsrs-runtime-${target}${suffix}`, `rsrs-runtime-${target}.tar.gz`);
    const cliArtifact = pair('cli-assets', `rsrs-${target}${suffix}`, `rsrs-${target}-runtime.tar.gz`);
    assert.equal(runtime.binary_sha256, runtimeArtifact.binary_sha256); assert.equal(runtime.archive_sha256, runtimeArtifact.archive_sha256);
    assert.deepEqual(cli, frontendMetadata(bytes(root, `cli-assets/rsrs-${target}${suffix}`), target, part.cli_version, expected));
    observedArtifacts[target] = {runtime: runtimeArtifact, cli: cliArtifact};
    if (target === FREEZE_TARGETS[0]) observedArtifacts[target].client2 = {
      ...pair('client2-assets', 'respire', 'respire-linux-amd64.tar.gz'), metadata: json(root, 'client2-assets/desktop-source.json')};
    parts.push(part);
  }
  execFileSync('python3', ['scripts/verify-business-archive-payloads.py'], {stdio: 'inherit'});
  const candidate = assembleCandidate(parts, expected, observedArtifacts);
  save(join(output, 'candidate.json'), candidate);
  copy('.', 'freeze-origin.json', output);
  writeFileSync(process.env.GITHUB_OUTPUT, `candidate_sha256=${digest(bytes(output, 'candidate.json'))}\n`, {flag: 'a'});
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  assert.ok(['package', 'assemble'].includes(process.argv[2]));
  if (process.argv[2] === 'package') await packagePart(); else assemble();
}

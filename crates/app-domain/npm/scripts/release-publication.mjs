#!/usr/bin/env node
// Cross-workflow publication barrier. No npm credentials or new GitHub permissions.
import {appendFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {packPackage, publishPackage, readExpectedPacks, waitForPackage} from './registry-publication.mjs';
import {validateRecoverySource, validateRecoveryAuthority} from './dev6-recovery-policy.mjs';

const RELEASE_WORKFLOW = '.github/workflows/release.yml';
// Only new receipts opt into post-consumption temporary artifact deletion.
export const RELEASE_ARTIFACT_CLEANUP_POLICY = Object.freeze({schema: 1, after_consumers_seconds: 3600});
const ALIAS_WORKFLOW = '.github/workflows/npm-alias.yml';
const VERSION = /^\d+\.\d+\.\d+(?:-dev\.\d+)?$/;
const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const positive = value => /^[1-9]\d*$/.test(String(value));
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export const read = file => JSON.parse(readFileSync(file, 'utf8'));
export const write = (file, value) => writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
export const manifest = () => read('npm/artifact-manifest.json');
export function sourceManifest(source) {
  validateSource(source);
  const m = JSON.parse(command('git', ['show', `${source.sha}:npm/artifact-manifest.json`], {maxBuffer:65536}));
  m.cliVersion = source.version;
  return m;
}
export const PUBLICATION_MAX_BUFFER = 16 * 1024 * 1024;
export const publicationCommand = (name, args, options = {}) => execFileSync(name, args,
  {encoding: 'utf8', timeout: 30000, maxBuffer: PUBLICATION_MAX_BUFFER, ...options});
export const command = publicationCommand;
export const api = endpoint => JSON.parse(command('gh', ['api', endpoint]));
export const pages = endpoint => {
  for (let attempt = 0; attempt < 2; attempt++) {
    try { return JSON.parse(command('gh', ['api', '--paginate', '--slurp', endpoint])); }
    catch (error) {
      if (attempt || !endpoint.includes('/jobs?') || !/HTTP 50[0-9]/.test(String(error.stderr))) throw error;
      console.warn('GitHub job inventory returned a server error; retrying this read once');
    }
  }
};
export const output = values => appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(values).map(([k,v]) => `${k}=${v}\n`).join(''));
export const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex');
export const packIdentity = pack => ({name: pack.name, version: pack.version, integrity: pack.integrity, shasum: pack.shasum});
export const readyName = source => `scoped-ready-${source.run_id}-${source.run_attempt}`;
export const aliasName = (source, run) => `alias-ready-${source.run_id}-${source.run_attempt}-${run.id}-${run.run_attempt}`;

export function validateSource(source) {
  if (source?.repository !== 'risense-ai/respire-cli' || source.workflow !== RELEASE_WORKFLOW ||
      !positive(source.run_id) || !positive(source.run_attempt) || !SHA.test(source.sha) ||
      !VERSION.test(source.version) || source.channel !== (source.version.includes('-dev.') ? 'dev' : 'latest') ||
      !positive(source.release_id)) throw new Error('Invalid publication source binding');
  if (source.recovery) validateRecoverySource(source);
  else if (source.tooling_sha !== undefined) throw new Error('Tooling SHA requires an explicit recovery binding');
  return source;
}
export function assertSourceRun(run, source) {
  validateSource(source);
  // head_sha describes the dispatch workflow, not necessarily the selected inputs.ref.
  if (String(run.id) !== String(source.run_id) || Number(run.run_attempt) !== Number(source.run_attempt) ||
      run.path !== RELEASE_WORKFLOW || run.head_repository?.full_name !== source.repository ||
      !['push', 'workflow_dispatch'].includes(run.event) || run.status !== 'in_progress' ||
      (source.recovery && (run.head_sha !== source.tooling_sha || run.event !== 'workflow_dispatch' || run.head_branch !== 'main'))) {
    throw new Error('Source Release attempt is stale, inactive, or from another workflow/repository');
  }
}
export function assertRecoveryAuthority(source, run) {
  if (!source.recovery) return;
  const mainSha = api(`repos/${source.repository}/git/ref/heads/main`).object.sha;
  const comparison = api(`repos/${source.repository}/compare/${mainSha}...${source.tooling_sha}`);
  validateRecoveryAuthority(source, run, mainSha, comparison);
}
export function validateScoped(receipt, expectedManifest) {
  if (expectedManifest.npmScope === 'rsrs-cli' || receipt?.schema !== 1 || receipt.kind !== 'scoped-ready') throw new Error('Invalid scoped-ready receipt');
  return validateScopedPayload(receipt, expectedManifest);
}
export function validateScopedPayload(receipt, expectedManifest) {
  const source = validateSource(receipt.source);
  const names = [...expectedManifest.targets.map(t => t.pkg), ...(expectedManifest.npmScope === 'rsrs-cli' ? [] : [expectedManifest.npmScope])].sort();
  if (expectedManifest.npmScope === 'rsrs-cli') {
    if (receipt.schema !== 2 || receipt.launcher?.name !== 'rsrs-cli' || receipt.launcher.version !== source.version ||
        !/^sha512-[A-Za-z0-9+/]{86}==$/.test(receipt.launcher.integrity || '') || !/^[a-f0-9]{40}$/.test(receipt.launcher.shasum || '')) throw Error('Missing validated launcher identity');
  } else if (receipt.launcher !== undefined) throw Error('Historical scoped receipt cannot declare a direct launcher');
  if (!Array.isArray(receipt.packages) || !equal(receipt.packages.map(p => p.name).sort(), names) ||
      receipt.packages.some(p => p.version !== source.version || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(p.integrity) || !/^[a-f0-9]{40}$/.test(p.shasum))) {
    throw new Error('Scoped receipt must contain every exact version and content digest once');
  }
  const expectedAssets = expectedManifest.targets.flatMap(t => [
    `cli-build-${t.triple}.json`, `rsrs-${t.triple}-runtime.tar.gz`, `rsrs-${t.triple}${t.triple.includes('windows') ? '.exe' : ''}`,
  ]).sort();
  if (!Array.isArray(receipt.assets) || !equal(receipt.assets.map(a => a.name).sort(), expectedAssets) ||
      receipt.assets.some(a => !Number.isSafeInteger(a.size) || a.size <= 0 || !HASH.test(a.sha256))) throw new Error('Invalid validated asset set');
  if (!Array.isArray(receipt.binaries) || receipt.binaries.length !== expectedManifest.targets.length ||
      !expectedManifest.targets.every(t => receipt.binaries.some(b => b.package === t.pkg && b.target === t.triple &&
        b.file === `rsrs-${t.triple}${t.triple.includes('windows') ? '.exe' : ''}` &&
        receipt.assets.some(a => a.name === b.file && a.sha256 === b.sha256)))) throw new Error('Invalid native binary bindings');
  return receipt;
}
export function assertDraft(release, receipt) {
  const source = receipt.source;
  if (String(release.id) !== String(source.release_id) || release.tag_name !== `v${source.version}` ||
      release.target_commitish !== source.sha || release.draft !== true || release.prerelease !== (source.channel === 'dev') ||
      release.assets?.length !== receipt.assets.length || !receipt.assets.every(expected => release.assets.some(actual =>
        actual.name === expected.name && actual.size === expected.size && actual.state === 'uploaded' && actual.digest === `sha256:${expected.sha256}`))) {
    throw new Error('Draft release identity/assets changed; publication refused');
  }
}
export function validateAlias(receipt, scoped, run, jobs) {
  if (receipt?.schema !== 1 || receipt.kind !== 'alias-ready' || !equal(receipt.source, scoped.source) ||
      !equal(receipt.scoped_packages, scoped.packages) || receipt.alias?.name !== 'rsrs-cli' ||
      receipt.alias?.version !== scoped.source.version || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(receipt.alias?.integrity) ||
      !/^[a-f0-9]{40}$/.test(receipt.alias?.shasum) || receipt.publisher?.workflow !== ALIAS_WORKFLOW ||
      String(receipt.publisher.run_id) !== String(run.id) || Number(receipt.publisher.run_attempt) !== Number(run.run_attempt) ||
      run.path !== ALIAS_WORKFLOW || !['workflow_run', 'workflow_dispatch'].includes(run.event) || run.head_repository?.full_name !== scoped.source.repository ||
      run.status !== 'completed' || run.conclusion !== 'success' ||
      !jobs.some(job => job.name === 'publish-integrated' && job.conclusion === 'success') ||
      receipt.install?.platform !== 'linux-x64-gnu' || receipt.install?.version !== scoped.source.version ||
      !scoped.binaries.some(b => b.package === '@rsrsai/linux-x64-gnu' && b.sha256 === receipt.install?.binary_sha256)) {
    throw new Error('Alias receipt/run/install does not prove this exact publication');
  }
}
export function assertTagCommit(object, source, {allowMissing = true} = {}) {
  if ((object === null && !allowMissing) || (object !== null && (object.type !== 'commit' || object.sha !== source.sha))) throw new Error('Release tag points to a different source commit');
}
export function assertTag(source, {requireExisting = false} = {}) {
  let ref;
  try { ref = api(`repos/${source.repository}/git/ref/tags/v${source.version}`); }
  catch (error) {
    if (!String(error.stderr || '').includes('(HTTP 404)')) throw error;
    assertTagCommit(null, source, {allowMissing: !requireExisting}); return; // New draft: GitHub creates this tag at publication.
  }
  let object = ref.object;
  for (let depth = 0; object?.type === 'tag' && depth < 5; depth++) object = api(`repos/${source.repository}/git/tags/${object.sha}`).object;
  assertTagCommit(object, source);
}
export function assertActive(source) {
  const run = api(`repos/${source.repository}/actions/runs/${source.run_id}`);
  assertSourceRun(run, source);
  assertRecoveryAuthority(source, run);
  return run;
}
export function validateArtifact(entries, runId) {
  if (!entries.length) return null;
  if (entries.length !== 1 || entries[0].expired || String(entries[0].workflow_run?.id) !== String(runId)) throw new Error('Duplicate, expired, or unbound publication artifact');
  return entries[0];
}
export function artifact(runId, name, repository) {
  const entries = pages(`repos/${repository}/actions/runs/${runId}/artifacts?per_page=100`).flatMap(p => p.artifacts).filter(a => a.name === name);
  if (!validateArtifact(entries, runId)) return null;
  const directory = mkdtempSync(path.join(tmpdir(), 'release-receipt-'));
  try {
    command('gh', ['run', 'download', String(runId), '--repo', repository, '--name', name, '--dir', directory], {timeout: 60000});
    const files = readdirSync(directory);
    if (files.length !== 1 || !['scoped-ready.json', 'alias-ready.json', 'scoped-accepted.json', 'alias-accepted.json', 'scoped-submissions.json', 'alias-submissions.json'].includes(files[0]) || statSync(path.join(directory, files[0])).size > 1024 * 1024) throw new Error('Unexpected publication receipt files');
    return read(path.join(directory, files[0]));
  } finally { rmSync(directory, {recursive: true, force: true}); }
}
export async function verifyPackages(packages, options = {}) {
  const timeoutMs = options.timeoutMs ?? 15 * 60 * 1000;
  const deadline = Date.now() + timeoutMs;
  for (const expected of packages) {
    if (Date.now() >= deadline) throw new Error(`Public package verification exceeded ${timeoutMs / 60000} minutes`);
    await waitForPackage(expected, {...options, timeoutMs: deadline - Date.now(), pollMs: 10000});
  }
}
/** Resolve drafts from the authenticated list, since tag lookup exposes published releases. */
export function selectRelease(releasePages, version) {
  if (!VERSION.test(version) || !Array.isArray(releasePages) || releasePages.some(page => !Array.isArray(page))) throw new Error('Invalid paginated release response');
  const matches = releasePages.flat().filter(release => release?.tag_name === `v${version}`);
  if (matches.length !== 1 || !positive(matches[0].id)) throw new Error(`Expected exactly one release for v${version}`);
  if (matches[0].draft !== true) throw new Error('Selected release must still be a draft');
  return matches[0];
}
async function scopedReady() {
  const m = manifest();
  const sha = command('git', ['rev-parse', 'HEAD']).trim();
  if (sha !== process.env.CLI_SHA || m.cliVersion !== process.env.CLI_VERSION) throw new Error('Checkout/version differs from release plan');
  const release = selectRelease(pages(`repos/${process.env.GITHUB_REPOSITORY}/releases?per_page=100`), m.cliVersion);
  const source = validateSource({repository: process.env.GITHUB_REPOSITORY, workflow: RELEASE_WORKFLOW,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    sha, version: m.cliVersion, channel: process.env.CLI_CHANNEL, release_id: release.id});
  assertActive(source);
  const packages = readExpectedPacks('npm/dist', m).map(packIdentity);
  await verifyPackages(packages);
  const assets = readdirSync('release-assets').sort().map(name => ({name, size: statSync(path.join('release-assets', name)).size, sha256: digest(path.join('release-assets', name))}));
  const binaries = m.targets.map(t => { const build = read(`release-assets/cli-build-${t.triple}.json`);
    if (build.git_sha !== sha || build.version !== m.cliVersion || build.target !== t.triple) throw new Error('Build metadata source mismatch');
    return {package: t.pkg, target: t.triple, file: build.binary_file, sha256: build.binary_sha256}; });
  const receipt = validateScoped({schema: 1, kind: 'scoped-ready', cleanup_policy: RELEASE_ARTIFACT_CLEANUP_POLICY, source, packages, assets, binaries}, m);
  assertActive(source);
  assertDraft(api(`repos/${source.repository}/releases/${source.release_id}`), receipt);
  assertTag(source);
  write('scoped-ready.json', receipt);
}
export function scopedPublisherFinished(jobs) {
  return jobs.some(j => j.name === 'publish' && j.status === 'completed');
}
async function awaitScoped() {
  const repo = process.env.GITHUB_REPOSITORY, runId = process.env.SOURCE_RUN, attempt = process.env.SOURCE_ATTEMPT;
  if (repo !== 'risense-ai/respire-cli' || !positive(runId) || !positive(attempt)) throw new Error('Invalid source event');
  const run = api(`repos/${repo}/actions/runs/${runId}`);
  if (run.path !== RELEASE_WORKFLOW || run.head_repository?.full_name !== repo || !['push', 'workflow_dispatch'].includes(run.event)) throw new Error('Unexpected source workflow');
  if (Number(run.run_attempt) !== Number(attempt) || run.status === 'completed') { output({eligible: 'false'}); return; }
  const protocol2 = await import('./publication-acceptance.mjs');
  const accepted = artifact(runId, protocol2.scopedAcceptedName({run_id: runId, run_attempt: attempt}), repo);
  if (accepted) {
    protocol2.validateAcceptedScoped(accepted, sourceManifest(accepted.source));
    output(protocol2.acceptedScopedOutput(accepted, run, attempt));
    return;
  }
  const scoped = artifact(runId, readyName({run_id: runId, run_attempt: attempt}), repo);
  if (!scoped) throw new Error('Exact scoped receipt missing after explicit publication dispatch');
  validateScoped(scoped, sourceManifest(scoped.source));
  if (String(scoped.source.run_id) !== runId || Number(scoped.source.run_attempt) !== Number(attempt)) throw new Error('Receipt does not belong to source event');
  assertSourceRun(run, scoped.source);
  assertRecoveryAuthority(scoped.source, run);
  write('scoped-ready.json', scoped);
  output({eligible: 'true', sha: scoped.source.tooling_sha || scoped.source.sha,
    product_sha: scoped.source.sha, version: scoped.source.version, protocol: '1',
    artifact: readyName(scoped.source), file: 'scoped-ready.json'});
}
// Retry only a structured npm resolver miss for one of this release's pinned packages.
// Publication is outside this boundary and must never be replayed.
export async function waitForPublicInstall(install, expectedSpecs, options = {}) {
  const now = options.now ?? Date.now;
  const pause = options.sleep ?? sleep;
  const timeoutMs = options.timeoutMs ?? 10 * 60 * 1000;
  const deadline = now() + timeoutMs;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await install(deadline - now());
    } catch (error) {
      let report;
      try { report = JSON.parse(String(error.stdout)); }
      catch { throw error; }
      if (error.status !== 1 || error.signal || error.code === 'ETIMEDOUT' ||
          report?.error?.code !== 'ETARGET' ||
          !expectedSpecs.some(spec => report.error.summary === `No matching version found for ${spec}.`)) throw error;
      const delay = options.pollMs ?? 60000;
      if (attempt === 3 || now() + delay >= deadline) throw error;
      options.onRetry?.(error, attempt);
      await pause(delay);
      if (now() >= deadline) throw error;
    }
  }
}
export function publicInstallArgs(directory, cache, version) {
  return ['install', '--prefix', directory, '--cache', cache, '--registry', 'https://registry.npmjs.org',
    '--no-audit', '--no-fund', '--prefer-online', '--json', `rsrs-cli@${version}`];
}
async function publishAlias() {
  const raw = read('scoped-ready.json');
  const scoped = validateScoped(raw, sourceManifest(raw.source));
  const source = scoped.source;
  if (command('git', ['rev-parse', 'HEAD']).trim() !== (source.tooling_sha || source.sha) || String(source.run_id) !== process.env.SOURCE_RUN || Number(source.run_attempt) !== Number(process.env.SOURCE_ATTEMPT)) throw new Error('Pinned alias checkout/source mismatch');
  if (source.recovery && command('git', ['diff', source.sha, source.tooling_sha, '--', 'npm/alias', 'npm/scripts/pack-alias.mjs', 'LICENSE', 'COMMERCIAL-LICENSE.md']).trim()) {
    throw new Error('Recovery tooling changed immutable alias package sources');
  }
  assertActive(source);
  // Recheck all five public tarballs before publishing their thin entry point.
  await verifyPackages(scoped.packages, {requireInstallIndex: true, timeoutMs: 30 * 60 * 1000});
  command('node', ['npm/scripts/pack-alias.mjs', '--version', source.version]);
  const packed = packPackage('npm/dist/rsrs-cli', process.env.RUNNER_TEMP);
  if (packed.name !== 'rsrs-cli' || packed.version !== source.version) throw new Error('Alias packing identity mismatch');
  const expected = packIdentity(packed);
  assertActive(source); // Last source-attempt check immediately before irreversible npm publication.
  const result = await publishPackage('npm/dist/rsrs-cli', {...expected, dependencies: {'@rsrsai/cli': source.version}}, source.channel, {requireInstallIndex: true, timeoutMs: 30 * 60 * 1000});
  if (result.metadata.dependencies?.['@rsrsai/cli'] !== source.version) throw new Error('Alias dependency mismatch');
  const install = await publicInstall(scoped, expected, () => assertActive(source));
  write('alias-ready.json', {schema: 1, kind: 'alias-ready', source, scoped_packages: scoped.packages, alias: expected,
    publisher: {workflow: ALIAS_WORKFLOW, run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT}, install});
}
export function publicInstallPlatform(platform='linux-x64-gnu',host={platform:process.platform,arch:process.arch}) {
  const options={'linux-x64-gnu':{arch:'x64',libc:'glibc',pkg:'@rsrsai/linux-x64-gnu'},
    'linux-arm64-gnu':{arch:'arm64',libc:'glibc',pkg:'@rsrsai/linux-arm64-gnu'},
    'linux-arm64':{arch:'arm64',libc:'musl',pkg:'@rsrsai/linux-arm64'}};
  const option=options[platform];
  if(!option||host.platform!=='linux'||host.arch!==option.arch)throw Error('Public installation requires the native selected Linux architecture');
  return {...option,platform};
}
export async function publicInstall(scoped, expected, assertCurrent, platform='linux-x64-gnu') {
  const source = scoped.source;
  const selected=publicInstallPlatform(platform);
  // An isolated public install, without inherited npm credentials, cache, or user config.
  const directory = mkdtempSync(path.join(tmpdir(), 'rsrs-public-install-'));
  try {
    const env = {...process.env};
    for (const key of Object.keys(env)) if (/^(?:npm_config_|NODE_AUTH_TOKEN$|NPM_TOKEN$|GH_TOKEN$|GITHUB_TOKEN$|ACTIONS_ID_TOKEN_REQUEST_)/i.test(key)) delete env[key];
    Object.assign(env, {HOME: directory, USERPROFILE: directory,
      NPM_CONFIG_USERCONFIG: path.join(directory, 'empty.npmrc'), NPM_CONFIG_GLOBALCONFIG: path.join(directory, 'global.npmrc'),
      NPM_CONFIG_CACHE: path.join(directory, 'cache'), RSRS_DATA_DIR: path.join(directory, 'profile'),RSRS_LIBC:selected.libc});
    writeFileSync(env.NPM_CONFIG_USERCONFIG, ''); writeFileSync(env.NPM_CONFIG_GLOBALCONFIG, '');
    const installOutput = await waitForPublicInstall(remaining => {
      const installStarted = Date.now();
      assertCurrent();
      // Source validation also consumes the shared install deadline.
      const timeout = remaining - (Date.now() - installStarted);
      if (timeout <= 0) throw new Error('Public install deadline expired during source validation');
      return command('npm', publicInstallArgs(directory, env.NPM_CONFIG_CACHE, source.version), {env, timeout});
    }, [...scoped.packages, expected].map(p => `${p.name}@${p.version}`), {
      onRetry: (error, attempt) => console.error(`Public install resolver miss (attempt ${attempt}/3): ${error.stderr}`),
    });
    process.stdout.write(installOutput);
    const alias = read(path.join(directory, 'node_modules/rsrs-cli/package.json'));
    const cliPath = path.join(directory, 'node_modules/@rsrsai/cli/package.json');
    const cli = scoped.launcher ? alias : read(cliPath);
    if (scoped.launcher && (existsSync(cliPath) || alias.name !== 'rsrs-cli' || alias.dependencies !== undefined || !equal(alias.optionalDependencies, scoped.optionalDependencies))) throw Error('Clean direct installation contains an intermediate CLI or different dependencies');
    const native = read(path.join(directory, 'node_modules',selected.pkg,'package.json'));
    if (native.name!==selected.pkg||[alias, cli, native].some(p => p.version !== source.version) || (!scoped.launcher && alias.dependencies?.['@rsrsai/cli'] !== source.version)) throw new Error('Clean install resolved a different version/platform');
    const binaryHash = digest(path.join(directory, 'node_modules',selected.pkg,'bin/rsrs'));
    if (!scoped.binaries.some(b => b.package === native.name && b.sha256 === binaryHash)) throw new Error('Installed native binary differs from validated build');
    const bin = path.join(directory, 'node_modules/.bin/rsrs');
    const version = command(bin, ['--version'], {env}).trim();
    if (!version.split(/\s+/).includes(source.version)) throw new Error(`Installed CLI version mismatch: ${version}`);
    command(bin, ['--help'], {env});
    assertCurrent();
    return {platform:selected.platform, version: source.version, binary_sha256: binaryHash};
  } finally { rmSync(directory, {recursive: true, force: true}); }
}
async function awaitAlias() {
  const raw = read('scoped-ready.json');
  const scoped = validateScoped(raw, sourceManifest(raw.source));
  const source = scoped.source;
  const deadline = Date.now() + 80 * 60 * 1000;
  const createdAt = assertActive(source).created_at;
  const unrelatedCompleted = new Set();
  while (Date.now() < deadline) {
    assertActive(source);
    const runs = pages(`repos/${source.repository}/actions/workflows/npm-alias.yml/runs?per_page=100&created=%3E%3D${createdAt}`).flatMap(p => p.workflow_runs);
    for (const run of runs) {
      // An artifact alone is not success: the matching publisher and workflow must finish.
      if (run.status !== 'completed' || run.conclusion !== 'success' || unrelatedCompleted.has(`${run.id}:${run.run_attempt}`)) continue;
      const receipt = artifact(run.id, aliasName(source, run), source.repository);
      if (!receipt) { unrelatedCompleted.add(`${run.id}:${run.run_attempt}`); continue; }
      const jobs = pages(`repos/${source.repository}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=10`).flatMap(p => p.jobs);
      validateAlias(receipt, scoped, run, jobs);
      // The child proved tarball bytes; confirm public metadata is still the exact six versions.
      for (const expected of [...scoped.packages, receipt.alias]) {
        const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(expected.name)}/${expected.version}`, {headers: {'Cache-Control': 'no-cache'}, redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(30000)});
        if (!response.ok) throw new Error(`Final public registry verification failed: ${expected.name} HTTP ${response.status}`);
        const published = await response.json();
        if (published.name !== expected.name || published.version !== expected.version || published.dist?.integrity !== expected.integrity || published.dist?.shasum !== expected.shasum ||
            (expected.name === 'rsrs-cli' && published.dependencies?.['@rsrsai/cli'] !== source.version)) throw new Error('Final public package content changed');
      }
      assertActive(source);
      assertDraft(api(`repos/${source.repository}/releases/${source.release_id}`), scoped);
      write('publication-complete.json', {source, alias_run: run.id, alias_attempt: run.run_attempt, alias_receipt: receipt, packages: [...scoped.packages, receipt.alias]});
      return;
    }
    await sleep(60000);
  }
  throw new Error('Matching successful short-package publication/install receipt missing after 80 minutes; release remains draft');
}
function finalize() {
  const raw = read('scoped-ready.json');
  const scoped = validateScoped(raw, sourceManifest(raw.source));
  const complete = read('publication-complete.json');
  if (!equal(complete.source, scoped.source) || !positive(complete.alias_run) || !positive(complete.alias_attempt) ||
      String(scoped.source.run_id) !== process.env.GITHUB_RUN_ID || Number(scoped.source.run_attempt) !== Number(process.env.GITHUB_RUN_ATTEMPT)) throw new Error('Missing exact completed publication barrier');
  assertActive(scoped.source);
  const aliasRun = api(`repos/${scoped.source.repository}/actions/runs/${complete.alias_run}`);
  const jobs = pages(`repos/${scoped.source.repository}/actions/runs/${complete.alias_run}/attempts/${complete.alias_attempt}/jobs?per_page=10`).flatMap(p => p.jobs);
  validateAlias(complete.alias_receipt, scoped, aliasRun, jobs);
  assertDraft(api(`repos/${scoped.source.repository}/releases/${scoped.source.release_id}`), scoped);
  assertTag(scoped.source);
  command('gh', ['release', 'edit', `v${scoped.source.version}`, '--repo', scoped.source.repository, '--draft=false'], {stdio: 'inherit'});
}
export async function main(action) {
  if (action === 'recovery-ready') return (await import('./dev6-publication-recovery.mjs')).recoveryReady();
  if (action?.endsWith('-accepted') || action === 'verify-accepted') return (await import('./publication-acceptance.mjs')).main(action);
  if (action === 'protocol') { console.log(2); return; }
  if (action === 'scoped-ready') return scopedReady();
  if (action === 'await-scoped') return awaitScoped();
  if (action === 'publish-alias') return publishAlias();
  if (action === 'await-alias') return awaitAlias();
  if (action === 'finalize') return finalize();
  throw new Error('Expected scoped-ready, await-scoped, publish-alias, await-alias, or finalize');
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv[2]).catch(error => {console.error(error.message); process.exitCode = 1;});

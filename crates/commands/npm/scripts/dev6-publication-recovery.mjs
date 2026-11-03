// Restore publication only from the approved immutable DEV6 build and registry bytes.
import {createHash} from 'node:crypto';
import {mkdirSync, readFileSync, readdirSync, statSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {DEV6, TARGETS, PACKAGES, validateRecoveryInputs, validateOriginalValidation, validateOriginalArtifact} from './dev6-recovery-policy.mjs';
import {publicationCommand, packIdentity, validateScoped, assertDraft, assertSourceRun, assertRecoveryAuthority, assertTagCommit, selectRelease} from './release-publication.mjs';
import {checkPackage, packPackage} from './registry-publication.mjs';

const cmd = publicationCommand;
const api = endpoint => JSON.parse(cmd('gh', ['api', endpoint]));
const pages = endpoint => JSON.parse(cmd('gh', ['api', '--paginate', '--slurp', endpoint]));
const read = file => JSON.parse(readFileSync(file, 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const write = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
const sorted = value => JSON.stringify(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)));

export function validateRecoveryBuilds(manifest, assets, builds) {
  if (manifest.cliVersion !== DEV6.version || manifest.npmScope !== '@rsrsai/cli' ||
      manifest.targets.some(t => t.pkg !== PACKAGES[TARGETS.indexOf(t.triple)]) ||
      JSON.stringify(manifest.targets.map(t => t.triple).sort()) !== JSON.stringify([...TARGETS].sort()) ||
      assets.length !== 12 || new Set(assets.map(a => a.name)).size !== 12 || builds.length !== 4) throw new Error('Incomplete DEV6 build inventory');
  for (const target of manifest.targets) {
    const matches = builds.filter(b => b.target === target.triple);
    const binary = `rsrs-${target.triple}${target.triple.includes('windows') ? '.exe' : ''}`;
    const runtime = `rsrs-${target.triple}-runtime.tar.gz`;
    if (matches.length !== 1) throw new Error('Duplicate or missing build metadata');
    const b = matches[0];
    if (b.schema_version !== 1 || b.git_sha !== DEV6.sha || b.version !== DEV6.version ||
        b.binary_file !== binary || b.runtime_file !== runtime ||
        !assets.some(a => a.name === binary && a.sha256 === b.binary_sha256) ||
        !assets.some(a => a.name === runtime && a.sha256 === b.runtime_sha256) ||
        !assets.some(a => a.name === `cli-build-${target.triple}.json`)) throw new Error('Original product build source/version/digest mismatch');
  }
}

export async function verifyRecoveryPackages(packages, manifest, options = {}) {
  const names = [...manifest.targets.map(t => t.pkg), manifest.npmScope].sort();
  if (packages.length !== 5 || JSON.stringify(packages.map(p => p.name).sort()) !== JSON.stringify(names) ||
      packages.some(p => p.version !== DEV6.version)) throw new Error('Incomplete original immutable package receipts');
  for (const expected of packages) {
    const pin = {...expected};
    if (pin.name === manifest.npmScope) pin.optionalDependencies = Object.fromEntries(manifest.targets.map(t => [t.pkg, DEV6.version]));
    const metadata = await checkPackage(pin, options); // Always hashes actual streamed tarball bytes; never publishes.
    if (!metadata) throw new Error(`Previously published package disappeared: ${pin.name}`);
    if (metadata.repository?.url !== 'git+https://github.com/risense-ai/respire-cli.git') throw new Error('Registry repository mismatch');
    const platform = manifest.targets.find(t => t.pkg === pin.name);
    if (platform && ['os', 'cpu', 'libc'].some(k => JSON.stringify(metadata[k]) !== JSON.stringify(platform[k]))) throw new Error('Registry platform mismatch');
  }
}

export async function verifyRecoveryAlias(expected, options = {}) {
  const metadata = await checkPackage({...expected, dependencies: {'@rsrsai/cli': DEV6.version}}, options);
  // null alone means absent; mismatched existing bytes/dependencies and network failures throw.
  return metadata;
}

export async function recoveryReady() {
  validateRecoveryInputs(process.env);
  const tooling = cmd('git', ['rev-parse', 'HEAD']).trim();
  if (tooling !== process.env.GITHUB_SHA || tooling === DEV6.sha) throw new Error('Recovery checkout must identify actual reviewed tooling');
  if (cmd('git', ['diff', DEV6.sha, tooling, '--', 'npm/alias', 'npm/scripts/pack-alias.mjs', 'LICENSE', 'COMMERCIAL-LICENSE.md']).trim()) throw new Error('Recovery changed original alias package inputs');
  const original = api(`repos/${DEV6.repository}/actions/runs/${DEV6.run}`);
  const jobs = pages(`repos/${DEV6.repository}/actions/runs/${DEV6.run}/attempts/${DEV6.attempt}/jobs?per_page=100`).flatMap(p => p.jobs);
  const ci = api(`repos/${DEV6.repository}/actions/runs/${DEV6.ci}`);
  validateOriginalValidation(original, jobs, ci);
  const toolingRuns = api(`repos/${DEV6.repository}/actions/workflows/ci.yml/runs?head_sha=${tooling}&per_page=100`).workflow_runs;
  const toolingCi = toolingRuns.filter(r => r.event === 'push' && r.head_branch === 'main' && r.head_sha === tooling).sort((a,b) => b.id-a.id)[0];
  if (!toolingCi || toolingCi.status !== 'completed' || toolingCi.conclusion !== 'success') throw new Error('Exact tooling main CI must succeed before recovery');
  const m = JSON.parse(cmd('git', ['show', `${DEV6.sha}:npm/artifact-manifest.json`], {maxBuffer:65536}));
  m.cliVersion = DEV6.version; // Versioned manifest describes existing product bytes, not tooling HEAD.
  const artifacts = pages(`repos/${DEV6.repository}/actions/runs/${DEV6.run}/artifacts?per_page=100`).flatMap(p => p.artifacts);
  const evidence = [];
  mkdirSync('release-assets'); mkdirSync('original-pack-receipts');
  for (const name of [...TARGETS.map(t => `cli-release-${t}`), 'npm-release-validation']) {
    const artifact = validateOriginalArtifact(artifacts, name); evidence.push({id: artifact.id, name, digest: artifact.digest});
    cmd('gh', ['run', 'download', String(DEV6.run), '--repo', DEV6.repository, '--name', name,
      '--dir', name === 'npm-release-validation' ? 'original-pack-receipts' : 'release-assets'], {timeout: 120000});
  }
  const assets = readdirSync('release-assets').sort().map(name => ({name, size: statSync(join('release-assets', name)).size,
    sha256: hash(readFileSync(join('release-assets', name)))}));
  const builds = m.targets.map(t => read(`release-assets/cli-build-${t.triple}.json`));
  validateRecoveryBuilds(m, assets, builds);
  const packages = [...m.targets.map(t => t.pkg), m.npmScope].map(name => {
    const report = read(`original-pack-receipts/${name}/release.pack.json`);
    if (!Array.isArray(report) || report.length !== 1 || report[0].name !== name || report[0].version !== DEV6.version) throw new Error('Original pack receipt identity mismatch');
    return packIdentity(report[0]);
  });
  const source = {repository: DEV6.repository, workflow: DEV6.workflow, run_id: process.env.GITHUB_RUN_ID,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT, sha: DEV6.sha, tooling_sha: tooling, version: DEV6.version,
    channel: 'dev', release_id: DEV6.release,
    recovery: {kind: 'dev6-publication-only', validation_run: DEV6.run, validation_attempt: DEV6.attempt}};
  const receipt = validateScoped({schema: 1, kind: 'scoped-ready', source, packages, assets,
    binaries: builds.map(b => ({package: m.targets.find(t => t.triple === b.target).pkg, target: b.target,
      file: b.binary_file, sha256: b.binary_sha256}))}, m);
  const activeRun = api(`repos/${DEV6.repository}/actions/runs/${source.run_id}`);
  assertSourceRun(activeRun, source);
  assertRecoveryAuthority(source, activeRun);
  const draft = selectRelease(pages(`repos/${DEV6.repository}/releases?per_page=100`), DEV6.version);
  assertDraft(draft, receipt);
  for (const path of ['crates/core-sdk/core-sdk.lock.json', 'sdk/core-sdk.lock.json']) {
    const originalLock = JSON.parse(cmd('git', ['show', `${DEV6.sha}:${path}`]));
    if (sorted(read(path)) !== sorted(originalLock) || Object.values(originalLock.targets).some(t => t.sdk_version !== DEV6.sdk)) throw new Error('Recovery SDK lock changed');
  }
  await verifyRecoveryPackages(packages, m);
  cmd('node', ['npm/scripts/pack-alias.mjs', '--version', DEV6.version]);
  const alias = packIdentity(packPackage('npm/dist/rsrs-cli', process.env.RUNNER_TEMP));
  await verifyRecoveryAlias(alias);
  for (const name of [...packages.map(p => p.name), 'rsrs-cli']) {
    const response = await fetch(`https://registry.npmjs.org/-/package/${encodeURIComponent(name)}/dist-tags`,
      {redirect: 'error', credentials: 'omit', headers: {'Cache-Control': 'no-cache'}, signal: AbortSignal.timeout(30000)});
    if (!response.ok) throw new Error('Registry tag verification failed');
    const tags = await response.json();
    if (tags.latest !== '1.0.12' || (name !== 'rsrs-cli' && tags.dev !== DEV6.version) ||
        (name === 'rsrs-cli' && !['1.0.15-dev.5', DEV6.version].includes(tags.dev))) throw new Error('Recovery would change or roll back registry tags');
  }
  let ref = null;
  try { ref = api(`repos/${DEV6.repository}/git/ref/tags/v${DEV6.version}`).object; }
  catch (error) { if (!String(error.stderr || '').includes('(HTTP 404)')) throw error; }
  if (ref?.type === 'tag') ref = api(`repos/${DEV6.repository}/git/tags/${ref.sha}`).object;
  assertTagCommit(ref, source);
  const health = await fetch('https://api.dev.rsrs.rs/health', {redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(30000)});
  if (!health.ok) throw new Error('Validated DEV server health unavailable');
  const server = await health.json();
  if (server.ok !== true || server.service !== 'respire' || server.source_revision !== '63c3da9e64a4ce182bfd802518030b102dd362a3') throw new Error('Validated DEV server changed');
  const finalRun = api(`repos/${DEV6.repository}/actions/runs/${source.run_id}`);
  assertSourceRun(finalRun, source);
  assertRecoveryAuthority(source, finalRun);
  assertDraft(api(`repos/${DEV6.repository}/releases/${DEV6.release}`), receipt);
  write('recovery-validation.json', {source, original_run: original.id, original_attempt: original.run_attempt,
    product_ci: ci.id, tooling_ci: toolingCi.id, artifacts: evidence, assets, packages,
    no_build_or_scoped_publication: true, original_validation_reused_explicitly: true});
  write('scoped-ready.json', receipt);
}

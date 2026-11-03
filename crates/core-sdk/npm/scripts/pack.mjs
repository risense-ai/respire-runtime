#!/usr/bin/env node
// Assemble npm packages: node npm/scripts/pack.mjs --root <bin-root> [--publish]
// --root layout: <rust-triple>/rsrs[.exe]; default scan is target/<triple>/release.
// Builds npm/dist/<pkg>/. After verify-packages.mjs writes pack receipts,
// --publish consumes those exact packages, platform packages before the umbrella.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, cpSync, existsSync, chmodSync, rmSync } from 'node:fs';
import { assertPackMatches, currentPackSource, readExpectedPacks, readValidatedPacks } from './registry-publication.mjs';
import {assertSubmissionActive} from './publication-acceptance.mjs';
import { publishScopedPackages, acceptScopedPackages } from './parallel-publication.mjs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : d; };
const doPublish = process.argv.includes('--publish');
const acceptedOnly = doPublish && process.argv.includes('--accepted-only');
// Establish no-submission evidence before configuration/pack validation can fail.
// An unknown entry replaces this empty inventory BEFORE every actual npm write.
if (acceptedOnly) writeFileSync('scoped-submissions.json', JSON.stringify({schema: 2,
  run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
  state: 'partial', packages: [], submissions: []}, null, 2));
const npmTag = arg('--tag', 'latest');
const repoRoot = path.resolve(arg('--repo', '.'));
const outDir = path.join(repoRoot, 'npm', 'dist');
const manifestPath = path.join(repoRoot, 'npm', 'artifact-manifest.json');

const cargoMatch = readFileSync(path.join(repoRoot, 'cli', 'Cargo.toml'), 'utf8')
  .match(/^version\s*=\s*"([^"]+)"/m);
const version = cargoMatch ? cargoMatch[1] : '';
if (!version) {
  console.error('cannot read version from cli/Cargo.toml');
  process.exit(1);
}
if (doPublish && version.includes('-dev') && npmTag === 'latest') {
  console.error(`refusing to publish dev version ${version} with npm tag latest; use --tag dev`);
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
if (manifest.cliVersion !== version) {
  console.error(`artifact-manifest cliVersion ${manifest.cliVersion} != Cargo.toml ${version}`);
  process.exit(1);
}
// Publication consumes the receipts written by verify-packages.mjs. Do not
// rebuild or clear dist here: that would discard the evidence we just verified.
if (doPublish) {
  let expected = readExpectedPacks(outDir, manifest, version);
  const validated = arg('--verified-packs');
  if (process.argv.includes('--verified-packs') && !validated) throw Error('Validated tarball directory is required');
  if (validated) {
    const packs=readValidatedPacks(path.resolve(validated),{...currentPackSource(),...(manifest.npmScope==='rsrs-cli'?{job:'publish'}:{})},manifest);
    expected=expected.map(pack=>({...assertPackMatches(packs.find(p=>p.name===pack.name),pack),dir:pack.dir}));
  }
  if (manifest.npmScope === 'rsrs-cli') expected = expected.filter(p => p.name !== manifest.npmScope);
  const accepted = [];
  const submissions = new Map();
  const prior = acceptedOnly ? JSON.parse(readFileSync('prior-scoped-acceptances.json', 'utf8')) : null;
  if (acceptedOnly && (String(prior.run_id) !== process.env.GITHUB_RUN_ID ||
      Number(prior.run_attempt) !== Number(process.env.GITHUB_RUN_ATTEMPT) || !Array.isArray(prior.acceptances))) {
    throw new Error('Missing current-attempt submission reconciliation');
  }
  const persist = () => writeFileSync('scoped-submissions.json', JSON.stringify({schema: 2,
    run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    state: accepted.length === expected.length ? 'accepted' : 'partial',
    packages: accepted, submissions: [...submissions.values()]}, null, 2));
  const publish = acceptedOnly ? acceptScopedPackages : publishScopedPackages;
  for (const result of await publish(expected, manifest.npmScope, npmTag, {
    timeoutMs: 30 * 60 * 1000,
    knownAcceptances: prior?.acceptances,
    beforeWrite: acceptedOnly ? ()=>assertSubmissionActive() : undefined,
    onSubmission: acceptedOnly ? event => {
      const p = event.package;
      submissions.set(p.name, {state: 'unknown', package: {name: p.name, version: p.version, integrity: p.integrity, shasum: p.shasum}});
      persist();
    } : undefined,
    onResult: acceptedOnly ? result => {
      accepted.push(result);
      submissions.set(result.name, {state: 'accepted', package: result.acceptance});
      // Preserve partial acceptance on a later failure. This is evidence, never
      // permission to replay an uncertain write or proof of public installation.
      persist();
    } : undefined,
  })) {
    console.log(`npm ${result.name}@${version}: ${result.status}; ${acceptedOnly ? 'submission accepted' : 'registry tarball integrity verified'}`);
  }
  console.log(acceptedOnly ? 'All scoped npm submissions accepted; public verification runs separately' : 'All scoped npm packages are published and readable');
  process.exit(0);
}

const SCOPE = manifest.npmScope;
const TARGETS = Object.fromEntries(
  manifest.targets.map((t) => [t.triple, { pkg: t.pkg, os: t.os, cpu: t.cpu, libc: t.libc }]),
);

const searchRoots = [arg('--root'), 'target/ci', 'target'].filter(Boolean)
  .map((r) => path.resolve(repoRoot, r));

function findBin(triple) {
  const exe = triple.includes('windows') ? `${manifest.binaryName}.exe` : manifest.binaryName;
  const candidates = [
    ...searchRoots.map((r) => path.join(r, triple, exe)),
    ...searchRoots.map((r) => path.join(r, triple, 'release', exe)),
  ];
  return candidates.find(existsSync);
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
const built = [];

for (const [triple, t] of process.argv.includes('--launcher-only') ? [] : Object.entries(TARGETS)) {
  const src = findBin(triple);
  if (!src) {
    console.warn(`skip ${triple} (no binary)`);
    continue;
  }
  const dir = path.join(outDir, t.pkg);
  mkdirSync(path.join(dir, 'bin'), { recursive: true });
  copyFileSync(path.join(repoRoot, 'LICENSE'), path.join(dir, 'LICENSE'));
  copyFileSync(path.join(repoRoot, 'COMMERCIAL-LICENSE.md'), path.join(dir, 'COMMERCIAL-LICENSE.md'));
  const binFile = path.basename(src);
  copyFileSync(src, path.join(dir, 'bin', binFile));
  const runtime = JSON.parse(readFileSync(path.join(path.dirname(src), 'core-runtime.json'), 'utf8'));
  if (runtime.target !== triple) throw new Error(`runtime target mismatch: ${triple}`);
  if (!runtime.files.some(file => file.path === 'core-notices/native/CORE-SDK-NOTICE.txt')) {
    throw new Error(`Core SDK license notice missing: ${triple}`);
  }
  if (!runtime.files.some(file => file.path === 'core-notices/CORE-SDK-LICENSE.txt')) {
    throw new Error(`Core SDK redistribution license missing: ${triple}`);
  }
  if (doPublish && runtime.redistribution !== 'permitted-under-included-license') {
    throw new Error('Core SDK redistribution is not permitted under the included license');
  }
  for (const file of runtime.files) {
    if (file.path.includes('\\') || file.path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Unsafe runtime path');
    const bytes = readFileSync(path.join(path.dirname(src), file.path));
    if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error(`runtime checksum mismatch: ${file.path}`);
    const destination = path.join(dir, 'bin', file.path);
    mkdirSync(path.dirname(destination), {recursive:true});
    writeFileSync(destination, bytes);
  }
  copyFileSync(path.join(path.dirname(src), 'core-runtime.json'), path.join(dir, 'bin', 'core-runtime.json'));
  chmodSync(path.join(dir, 'bin', binFile), 0o755);
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: t.pkg, version,
    description: 'rsrs CLI platform binary',
    repository: { type: 'git', url: 'git+https://github.com/risense-ai/respire-cli.git' },
    license: 'SEE LICENSE IN LICENSE', os: t.os, cpu: t.cpu, ...(t.libc ? {libc: t.libc} : {}), files: ['bin', 'LICENSE', 'COMMERCIAL-LICENSE.md'],
    exports: { [`./bin/${binFile}`]: `./bin/${binFile}` },
  }, null, 2) + '\n');
  built.push({ name: t.pkg, dir });
}

// The umbrella package must always declare every supported platform package.
// Otherwise a release assembled without one downloaded artifact publishes
// successfully, but npm never installs that platform's binary and the
// wrapper reports it as missing at runtime.
const optionalDependencies = Object.fromEntries(
  manifest.targets.map((t) => [t.pkg, version]),
);
const missingTargets = manifest.targets.filter((t) => !built.some((b) => b.name === t.pkg));
if (doPublish && missingTargets.length) {
  console.error(`missing platform binaries: ${missingTargets.map((t) => t.pkg).join(', ')}`);
  process.exit(1);
}

const mainDir = path.join(outDir, SCOPE);
mkdirSync(path.join(mainDir, 'bin'), { recursive: true });
copyFileSync(path.join(repoRoot, 'npm', 'bin', 'cli.js'), path.join(mainDir, 'bin', 'cli.js'));
chmodSync(path.join(mainDir, 'bin', 'cli.js'), 0o755);
cpSync(path.join(repoRoot, 'npm', 'README.md'), path.join(mainDir, 'README.md'));
copyFileSync(path.join(repoRoot, 'LICENSE'), path.join(mainDir, 'LICENSE'));
copyFileSync(path.join(repoRoot, 'COMMERCIAL-LICENSE.md'), path.join(mainDir, 'COMMERCIAL-LICENSE.md'));
writeFileSync(path.join(mainDir, 'package.json'), JSON.stringify({
  name: SCOPE, version,
  description: 'rsrs CLI — encrypted cross-device AI memory',
  license: 'SEE LICENSE IN LICENSE',
  repository: { type: 'git', url: 'git+https://github.com/risense-ai/respire-cli.git' },
  bin: { 'rsrs': './bin/cli.js' },
  files: ['bin', 'README.md', 'LICENSE', 'COMMERCIAL-LICENSE.md'],
  engines: { node: '>=16' },
  optionalDependencies,
}, null, 2) + '\n');
built.push({ name: SCOPE, dir: mainDir });

console.log(`version ${version}: packed ${built.length} packages -> npm/dist/`);
for (const b of built) console.log(`  ${b.name}${doPublish ? '' : ' (dry run)'}`);

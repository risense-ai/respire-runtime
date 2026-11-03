import {createHash} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {execFileSync, spawnSync} from 'node:child_process';
import {verifyBinary} from './verify-binary.mjs';
import {currentPackSource, downloadValidatedPacks, packProducer, readValidatedPacks, verifyPackFile} from './registry-publication.mjs';

const root = process.cwd();
const assets = resolve(process.argv[2] || 'release-assets');
const manifest = JSON.parse(readFileSync(join(root, 'npm/artifact-manifest.json'), 'utf8'));
const sha = execFileSync('git', ['rev-parse', 'HEAD'], {encoding:'utf8'}).trim();
const hash = file => createHash('sha256').update(readFileSync(file)).digest('hex');
for (const target of manifest.targets) {
  const metadata = JSON.parse(readFileSync(join(assets, `cli-build-${target.triple}.json`), 'utf8'));
  const binary = `${manifest.binaryName}-${target.triple}${target.triple.includes('windows') ? '.exe' : ''}`;
  const runtime = `${manifest.binaryName}-${target.triple}-runtime.tar.gz`;
  verifyBinary(join(assets, binary), target.triple);
  if (metadata.schema_version !== 1 || metadata.git_sha !== sha || metadata.version !== manifest.cliVersion
      || metadata.target !== target.triple || metadata.binary_file !== binary || metadata.runtime_file !== runtime
      || hash(join(assets, binary)) !== metadata.binary_sha256 || hash(join(assets, runtime)) !== metadata.runtime_sha256) {
    throw new Error(`Release artifact metadata/checksum mismatch: ${target.triple}`);
  }
}
if (process.argv.includes('--assets-only')) {
  console.log(`Verified ${manifest.targets.length} release binary/runtime artifacts for ${sha}`);
  process.exit(0);
}

const names = [...manifest.targets.map(target => target.pkg), manifest.npmScope];
const exporting = process.argv.includes('--export-packs');
const packIndex = process.argv.indexOf(exporting ? '--export-packs' : '--pack');
const packDirectory = packIndex >= 0 ? resolve(process.argv[packIndex + 1] || 'npm/release-packages') : null;
const reuseIndex = process.argv.indexOf('--reuse-packs');
const reuseDirectory = reuseIndex >= 0 ? resolve(process.argv[reuseIndex + 1] || '') : null;
if (reuseDirectory && packDirectory && !exporting) throw Error('Packing and validated-tarball reuse are mutually exclusive');
let reused;
if (reuseDirectory) {
  const source=currentPackSource();
  if (source.sha!==sha) throw Error('Validated pack checkout/source differs');
  if (process.argv.includes('--download')) downloadValidatedPacks(reuseDirectory,source);
  reused=readValidatedPacks(reuseDirectory,source,manifest);
}
if (packDirectory) mkdirSync(packDirectory, {recursive:true});
const packages = [];
for (const name of names) {
  const directory = join(root, 'npm/dist', name);
  const pkg = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
  if (pkg.name !== name || pkg.version !== manifest.cliVersion || !pkg.repository?.url.endsWith('/risense-ai/respire-cli.git')) {
    throw new Error(`npm identity/version/repository mismatch: ${name}`);
  }
  if (name === manifest.npmScope) {
    if (pkg.dependencies !== undefined || JSON.stringify(pkg.bin) !== JSON.stringify({rsrs:'./bin/cli.js'})
        || JSON.stringify(pkg.optionalDependencies) !== JSON.stringify(Object.fromEntries(manifest.targets.map(target => [target.pkg, manifest.cliVersion])))) {
      throw new Error('npm launcher/optional dependency mismatch');
    }
  } else {
    const runtime = JSON.parse(readFileSync(join(directory, 'bin/core-runtime.json'), 'utf8'));
    if (pkg.license !== 'SEE LICENSE IN LICENSE'
        || runtime.redistribution !== 'permitted-under-included-license'
        || !existsSync(join(directory, 'bin/core-notices/CORE-SDK-LICENSE.txt'))) {
      throw new Error(`npm redistribution license mismatch: ${name}`);
    }
  }
  let report;
  if (reused) {
    const expected=reused.find(p=>p.name===name);
    verifyPackFile(expected.tarballPath,expected,directory);
    const {sha256,tarballPath,...packed}=expected;
    report=[packed];
    if (packDirectory) copyFileSync(expected.tarballPath, join(packDirectory, expected.filename));
  } else {
    const args = ['pack', '--json', ...(packDirectory ? ['--pack-destination', packDirectory] : ['--dry-run'])];
    const result = spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, {
      cwd:directory, encoding:'utf8', shell:process.platform === 'win32',
    });
    if (result.status !== 0) throw new Error(`npm pack failed: ${name}\n${result.stderr}`);
    report = JSON.parse(result.stdout);
  }
  if (report.length !== 1 || report[0].name !== name || report[0].version !== manifest.cliVersion) {
    throw new Error(`npm pack report mismatch: ${name}`);
  }
  const packedFiles = new Set(report[0].files.map(file => file.path));
  if (pkg.license !== 'SEE LICENSE IN LICENSE' || packedFiles.has('LICENSE-MIT-LEGACY') || !packedFiles.has('LICENSE') || (name !== manifest.npmScope && !packedFiles.has('bin/core-notices/CORE-SDK-LICENSE.txt'))) {
    throw new Error(`npm package is missing its source or binary SDK license: ${name}`);
  }
  writeFileSync(join(directory, 'release.pack.json'), JSON.stringify(report, null, 2)+'\n');
  if (packDirectory) packages.push({name, version:manifest.cliVersion, file:report[0].filename, sha256:hash(join(packDirectory, report[0].filename)),pack:report[0]});
  console.log(`Validated npm pack: ${name}@${manifest.cliVersion}`);
}
if (packDirectory) {
  writeFileSync(join(packDirectory, 'SHA256SUMS'), packages.map(pkg => `${pkg.sha256}  ${pkg.file}`).join('\n')+'\n');
  writeFileSync(join(packDirectory, 'source-version.json'), JSON.stringify({schema_version:1, git_sha:sha, version:manifest.cliVersion, packages,producer:packProducer(sha)}, null, 2)+'\n');
}
console.log(`Validated all ${names.length} packages without publishing`);

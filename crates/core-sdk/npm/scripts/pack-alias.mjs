#!/usr/bin/env node
// Build the short npm entry after the scoped CLI package has been published.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--version')) {
  throw new Error('Usage: pack-alias.mjs [--version X.Y.Z[-dev.N]]');
}
const version = args.length ? args[1] : readFileSync(path.join(root, 'cli/Cargo.toml'), 'utf8')
  .match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!version || !/^\d+\.\d+\.\d+(?:-dev\.\d+)?$/.test(version)) {
  throw new Error('Expected a stable or DEV CLI version');
}
const output = path.join(root, 'npm/dist/rsrs-cli');
mkdirSync(path.join(output, 'bin'), { recursive: true });
copyFileSync(path.join(root, 'npm/alias/bin/cli.js'), path.join(output, 'bin/cli.js'));
for (const file of ['LICENSE', 'COMMERCIAL-LICENSE.md']) {
  copyFileSync(path.join(root, file), path.join(output, file));
}
writeFileSync(path.join(output, 'package.json'), JSON.stringify({
  name: 'rsrs-cli', version,
  description: 'Short install entry for the Respire CLI',
  license: 'SEE LICENSE IN LICENSE',
  repository: { type: 'git', url: 'git+https://github.com/risense-ai/respire-cli.git' },
  bin: { rsrs: './bin/cli.js' },
  files: ['bin', 'README.md', 'LICENSE', 'COMMERCIAL-LICENSE.md'],
  engines: { node: '>=16' },
  dependencies: { '@rsrsai/cli': version },
}, null, 2) + '\n');
writeFileSync(path.join(output, 'README.md'),
  '# rsrs-cli\n\nInstall Respire with `npm install -g rsrs-cli`.\n\n' +
  'This entry uses the same version of the Respire launcher and its native platform packages.\n' +
  'Run `rsrs --help` after installation.\n\n' +
  'If another install entry for the Respire CLI is already installed globally, uninstall that package first to avoid a command conflict.\n' +
  'Uninstalling the npm package does not delete your Respire data.\n');
console.log(`Built rsrs-cli@${version} depending on @rsrsai/cli@${version}`);

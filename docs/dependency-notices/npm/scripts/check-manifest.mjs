#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const manifest = JSON.parse(readFileSync(join(root, 'npm', 'artifact-manifest.json'), 'utf8'));
const cargo = readFileSync(join(root, 'cli', 'Cargo.toml'), 'utf8');
const match = cargo.match(/^version\s*=\s*"([^"]+)"/m);
const version = match ? match[1] : '';
if (!version) {
  console.error('cannot read cli/Cargo.toml version');
  process.exit(1);
}
if (manifest.cliVersion !== version) {
  console.error(`artifact-manifest cliVersion ${manifest.cliVersion} != Cargo.toml ${version}`);
  process.exit(1);
}
if (!manifest.targets.length) {
  console.error('artifact-manifest has no targets');
  process.exit(1);
}
console.log(`artifact-manifest ok (${manifest.targets.length} targets, ${version})`);

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// Publishes crates/protocol (respire-protocol) of this repository to crates.io.
// Native SDK archives use private respire-core release assets, never crates.io.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const selection = process.argv[2];
if (selection === 'sdk') throw new Error('SDK registry publication is disabled; use private respire-core release assets. No registry request was attempted.');
if (selection !== 'protocol') throw new Error('Select protocol');
const path = join(root, 'crates', 'protocol', 'Cargo.toml');
const manifest = readFileSync(path, 'utf8');
const name = /^name\s*=\s*"([^"]+)"/m.exec(manifest)?.[1], version = /^version\s*=\s*"([^"]+)"/m.exec(manifest)?.[1];
if (!name || !version) throw new Error('Missing crate metadata');
const target = process.env.CARGO_TARGET_DIR;
if (!target) throw new Error('CARGO_TARGET_DIR is required to find the verified crate');
const report = JSON.parse(readFileSync(join(target, '..', 'PACKAGE.json'), 'utf8'));
const verifiedHash = createHash('sha256').update(readFileSync(join(target, 'package', `${name}-${version}.crate`))).digest('hex');
if (report.name !== name || report.version !== version || report.sha256 !== verifiedHash) throw new Error('Verified crate does not match PACKAGE.json');
const verifyDownload = async response => {
  const downloadedHash = createHash('sha256').update(Buffer.from(await response.arrayBuffer())).digest('hex');
  if (downloadedHash !== verifiedHash) throw new Error(`Downloaded ${name} ${version} SHA-256 mismatch: verified ${verifiedHash}, registry ${downloadedHash}`);
};
const url = `https://static.crates.io/crates/${name}/${name}-${version}.crate`;
const response = await fetch(url);
if (response.ok) {
  await verifyDownload(response);
  console.log(`${name} ${version} is already published and matches the verified crate.`);
} else {
  await response.body?.cancel();
  if (response.status !== 403 && response.status !== 404) throw new Error(`Registry availability check failed: HTTP ${response.status}`);
  if (!process.env.CARGO_REGISTRY_TOKEN) throw new Error('CARGO_REGISTRY_TOKEN is required to publish a new crate version');
  const result = spawnSync('cargo', ['publish', '--locked', '--manifest-path', path], { cwd: root, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Cargo publication failed');
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    const check = await fetch(url);
    if (check.ok) { await verifyDownload(check); ready = true; break; }
    await check.body?.cancel();
    await new Promise(done => setTimeout(done, 2000));
  }
  if (!ready) throw new Error('Published crate is not yet downloadable; stop before publishing dependent crates');
}

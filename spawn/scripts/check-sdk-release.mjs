import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=join(dirname(fileURLToPath(import.meta.url)),'..');
const lock=JSON.parse(readFileSync(join(root,'sdk/core-sdk.lock.json'),'utf8'));
const crateLock=JSON.parse(readFileSync(join(root,'crates/core-sdk/core-sdk.lock.json'),'utf8'));
if (JSON.stringify(lock) !== JSON.stringify(crateLock)) throw new Error('CLI and packaged SDK locks differ');
const manifest=JSON.parse(readFileSync(join(root,'npm/artifact-manifest.json'),'utf8'));
const sdkTargets = [
  'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc', 'aarch64-apple-darwin', 'x86_64-apple-darwin',
  'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
  'x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl',
];
for(const triple of new Set([...sdkTargets, ...manifest.targets.map(target => target.triple)])) {
  const sdk=lock.targets[triple];
  if(!/^[a-f0-9]{64}$/.test(sdk?.manifest_sha256 || '') || !sdk.url || !sdk.archive_url
    || !/^[a-f0-9]{64}$/.test(sdk.archive_sha256 || '') || sdk.redistribution !== 'approved')
    throw new Error(`Release blocked: ${triple} needs a validated SDK, redistribution license and pinned manifest/archive downloads`);
  if (new URL(sdk.url).protocol !== 'https:' || new URL(sdk.archive_url).protocol !== 'https:')
    throw new Error(`Release blocked: ${triple} SDK downloads must use HTTPS`);
}
console.log('All release targets have approved, pinned binary SDKs');

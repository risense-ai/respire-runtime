import { createHash } from 'node:crypto';

const REPOSITORY = 'risense-ai/respire-core';
const TARGETS = new Set(['x86_64-pc-windows-msvc','aarch64-pc-windows-msvc','aarch64-apple-darwin','x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-unknown-linux-musl','aarch64-unknown-linux-musl']);
const CDN_HOSTS = new Set(['release-assets.githubusercontent.com', 'objects.githubusercontent.com']);
const requireValue = (ok, message) => { if (!ok) throw new Error(message); };

export function assertTrustedDownloadContext(env) {
  requireValue(!['pull_request', 'pull_request_target'].includes(env.GITHUB_EVENT_NAME), 'Private SDK credentials are forbidden in PR contexts');
  if (env.GITHUB_ACTIONS === 'true') {
    requireValue(env.GITHUB_REPOSITORY === 'risense-ai/respire-cli'
      && env.GITHUB_REF === 'refs/heads/main'
      && ['push', 'workflow_dispatch'].includes(env.GITHUB_EVENT_NAME),
    'Private SDK download requires a trusted main-branch CLI workflow');
  }
}

async function boundedBytes(response, limit) {
  requireValue(response.body, 'Private SDK response has no body');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    for (;;) {
      const {value, done} = await reader.read(); if (done) break;
      size += value.length;
      requireValue(size <= limit, 'Private SDK response exceeds the pinned size bound');
      chunks.push(Buffer.from(value));
    }
  } finally { await reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks);
}

export async function downloadPrivateSdk(entry, target, kind, {env = process.env, transport = fetch} = {}) {
  requireValue(entry.private_repository === REPOSITORY && TARGETS.has(target)
    && /^1\.0\.2-dev\.[1-9][0-9]*$/.test(entry.sdk_version || '')
    && entry.release_tag === `sdk-v${entry.sdk_version}` && ['manifest', 'archive'].includes(kind),
  'Invalid private SDK repository/version/target');
  const tag = entry.release_tag, suffix = kind === 'manifest' ? 'manifest.json' : 'tar.gz';
  const name = `respire-core-sdk-${target}.${suffix}`;
  const digest = kind === 'manifest' ? entry.manifest_sha256 : entry.archive_sha256;
  requireValue(/^[a-f0-9]{64}$/.test(digest || ''), 'Missing pinned private SDK SHA256');
  const expectedUrl = `https://github.com/${REPOSITORY}/releases/download/${tag}/${name}`;
  requireValue((kind === 'manifest' ? entry.url : entry.archive_url) === expectedUrl, 'Private SDK URL differs from its fixed release identity');
  assertTrustedDownloadContext(env);
  const token = env.CORE_SDK_READ_TOKEN;
  requireValue(typeof token === 'string' && token.length > 0 && token.length <= 4096,
    'CORE_SDK_READ_TOKEN is required in an isolated trusted download step; never provide it to PR code');
  const base = `https://api.github.com/repos/${REPOSITORY}`;
  const authHeaders = {Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'};
  const request = async (url, headers) => {
    try { return await transport(url, {headers, redirect: 'manual', credentials: 'omit', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(120000)}); }
    catch { throw new Error('Private SDK request did not complete; no automatic retry'); }
  };
  const metadata = await request(`${base}/releases/tags/${encodeURIComponent(tag)}`, authHeaders);
  requireValue(metadata.status === 200, `Private SDK metadata failed with HTTP ${metadata.status}`);
  let release;
  try { release = JSON.parse((await boundedBytes(metadata, 1024 * 1024)).toString('utf8')); }
  catch { throw new Error('Invalid private SDK metadata JSON'); }
  requireValue(release.tag_name === tag && release.draft === false && release.prerelease === true
    && Number.isSafeInteger(release.id) && release.id > 0 && Array.isArray(release.assets) && release.assets.length < 100,
  'Private SDK release identity/state mismatch');
  const matches = release.assets.filter(a => a.name === name);
  requireValue(matches.length === 1, 'Private SDK asset is missing or ambiguous');
  const asset = matches[0], limit = kind === 'manifest' ? 1024 * 1024 : 128 * 1024 * 1024;
  requireValue(Number.isSafeInteger(asset.id) && asset.id > 0 && Number.isSafeInteger(asset.size)
    && asset.size > 0 && asset.size <= limit && asset.digest === `sha256:${digest}`, 'Private SDK asset identity/integrity metadata mismatch');
  let response = await request(`${base}/releases/assets/${asset.id}`, {...authHeaders, Accept: 'application/octet-stream'});
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    let redirect;
    try { redirect = new URL(response.headers.get('location')); } catch { throw new Error('Invalid private SDK asset redirect'); }
    requireValue(redirect.protocol === 'https:' && !redirect.username && !redirect.password && !redirect.port
      && CDN_HOSTS.has(redirect.hostname) && redirect.pathname.startsWith('/github-production-release-asset'),
    'Private SDK asset redirect destination is not allowed');
    // Construct a fresh request: no Authorization, cookies, referrer or ambient
    // GitHub credential is forwarded to the signed asset URL. Reject another hop.
    response = await request(redirect.href, {Accept: 'application/octet-stream'});
  }
  requireValue(response.status === 200, `Private SDK asset failed with HTTP ${response.status}`);
  const bytes = await boundedBytes(response, asset.size);
  requireValue(bytes.length === asset.size && createHash('sha256').update(bytes).digest('hex') === digest,
    'Private SDK bytes do not match their pinned SHA256/size');
  return bytes;
}

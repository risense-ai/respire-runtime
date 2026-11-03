import {writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';

const [output] = process.argv.slice(2);
const repository = process.env.GITHUB_REPOSITORY;
const tag = process.env.CLI_TAG;
const sha = process.env.CLI_SHA;
const channel = process.env.CLI_CHANNEL;
const integer = '(0|[1-9]\\d*)';
const pattern = new RegExp(`^v${integer}\\.${integer}\\.${integer}(?:-dev\\.${integer})?$`);
function parse(value) {
  const match = pattern.exec(value);
  if (!match) return null;
  const numbers = match.slice(1).map(part => part === undefined ? null : Number(part));
  if (!numbers.filter(part => part !== null).every(Number.isSafeInteger)) throw new Error('Version exceeds safe integer range');
  return numbers;
}
function compare(left, right) {
  for (let index = 0; index < 3; index++) {
    if (left[index] !== right[index]) return left[index] > right[index] ? 1 : -1;
  }
  if (left[3] === right[3]) return 0;
  if (left[3] === null) return 1;
  if (right[3] === null) return -1;
  return left[3] > right[3] ? 1 : -1;
}
function run(command, args) {
  return execFileSync(command, args, {encoding: 'utf8', maxBuffer: 32 * 1024 * 1024});
}
function commit(ref) {
  const value = run('git', ['rev-parse', '--verify', `${ref}^{commit}`]).trim();
  if (!/^[a-f0-9]{40}$/.test(value)) throw new Error('Invalid resolved source commit');
  return value;
}
function text(value) {
  return value.replace(/[\\`*_{}\[\]<>|]/g, character => `\\${character}`).replace(/\r?\n/g, ' ');
}
const version = parse(tag || '');
if (!output || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || '') || !version
    || !/^[a-f0-9]{40}$/.test(sha || '') || !['dev', 'latest'].includes(channel)
    || (version[3] !== null) !== (channel === 'dev')) throw new Error('Invalid release notes identity');
if (run('git', ['rev-parse', '--is-shallow-repository']).trim() !== 'false') throw new Error('Release notes require complete Git history');
if (commit(sha) !== sha) throw new Error('Release source mismatch');
const releases = run('gh', ['api', `repos/${repository}/releases?per_page=100`, '--paginate', '--jq', '.[] | @json'])
  .trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
const previous = releases.filter(release => !release.draft).map(release => ({release, version: parse(release.tag_name)}))
  .filter(item => item.version && compare(item.version, version) < 0
    && !item.release.prerelease && item.version[3] === null)
  .sort((left, right) => compare(right.version, left.version))[0];
let baseline;
if (previous) {
  baseline = commit(`refs/tags/${previous.release.tag_name}`);
  run('git', ['merge-base', '--is-ancestor', baseline, sha]);
}
const entries = run('git', ['log', '--format=%H%x00%s%x00%b%x00', sha, ...(baseline ? [`^${baseline}`] : [])]).split('\0');
if (entries.pop().trim() !== '' || entries.length % 3 !== 0) throw new Error('Invalid Git commit records');
const commits = [];
for (let index = 0; index < entries.length; index += 3) {
  const hash = entries[index].trim();
  if (!/^[a-f0-9]{40}$/.test(hash)) throw new Error('Invalid commit in release notes');
  commits.push({hash, subject: entries[index + 1], body: entries[index + 2].trim()});
}
const groups = {Features: [], Fixes: [], 'Other changes': []};
for (const entry of commits) {
  const subject = entry.subject;
  const group = /^feat(?:\([^)]*\))?!?:/i.test(subject) ? 'Features'
    : /^fix(?:\([^)]*\))?!?:/i.test(subject) ? 'Fixes' : 'Other changes';
  const description = entry.body.split(/\r?\n\s*\r?\n/)[0];
  groups[group].push(`- ${text(subject)}${description ? ` — ${text(description)}` : ''} ([${entry.hash.slice(0, 8)}](https://github.com/${repository}/commit/${entry.hash}))`);
}
const lines = [`# Respire CLI ${tag.slice(1)}`, '', channel === 'dev'
  ? 'Development release for testing. The npm `latest` channel remains on the stable version.' : 'Stable release.', ''];
if (previous) lines.push(`Changes since [${previous.release.tag_name}](https://github.com/${repository}/releases/tag/${previous.release.tag_name}).`, '');
else lines.push(channel === 'latest' ? 'First stable release: cumulative changes with no previous published stable baseline.'
  : 'Initial release: cumulative changes with no previous published release baseline.', '');
for (const [heading, changes] of Object.entries(groups)) lines.push(`## ${heading}`, '', ...(changes.length ? changes : ['No separately classified changes.']), '');
lines.push('## Commits', '', '| Commit | Change |', '| --- | --- |', ...commits.map(entry => `| [${entry.hash.slice(0, 8)}](https://github.com/${repository}/commit/${entry.hash}) | ${text(entry.subject)} |`), '');
if (!commits.length) lines.push('No additional commits since the previous release; this release contains the same source.', '');
if (previous) lines.push(`[Full comparison](https://github.com/${repository}/compare/${previous.release.tag_name}...${sha})`, '');
lines.push('## Install', '', '```sh', `npm install -g rsrs-cli@${tag.slice(1)} --registry=https://registry.npmjs.org`, 'rsrs --version', '```', '', '## Source and validation', '',
  `- Source: [\`${sha}\`](https://github.com/${repository}/commit/${sha}).`,
  '- Publication requires the existing platform, CLI and development API acceptance gates.');
if (process.env.GITHUB_RUN_ID && /^\d+$/.test(process.env.GITHUB_RUN_ID)) lines.push(`- [Release workflow](https://github.com/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}).`);
lines.push('');
writeFileSync(output, lines.join('\n'), 'utf8');
console.log(`Generated release notes for ${tag}: ${commits.length} commits; baseline ${previous?.release.tag_name || 'repository root'}`);

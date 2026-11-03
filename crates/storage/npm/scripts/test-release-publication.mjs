import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {execFile, execFileSync} from 'node:child_process';
import {waitForPublicInstall, publicInstallArgs, publicInstallPlatform, PUBLICATION_MAX_BUFFER, publicationCommand, scopedPublisherFinished, selectRelease, validateArtifact, assertTagCommit, assertDraft, assertSourceRun, validateAlias, validateScoped, validateSource, readyName, aliasName} from './release-publication.mjs';

const m = JSON.parse(readFileSync(new URL('../artifact-manifest.json', import.meta.url))); m.npmScope = '@rsrsai/cli'; // Historical receipt layout.
const integrity = 'sha512-' + createHash('sha512').update('synthetic package').digest('base64');
const hash = 'a'.repeat(64), sha = 'b'.repeat(40), version = '1.2.3-dev.4';
const source = {repository: 'risense-ai/respire-cli', workflow: '.github/workflows/release.yml', run_id: '100', run_attempt: '2', sha, version, channel: 'dev', release_id: 300};
const sourceRun = {id: 100, run_attempt: 2, path: source.workflow, head_repository: {full_name: source.repository}, event: 'workflow_dispatch', head_sha: 'c'.repeat(40), status: 'in_progress'};
const scoped = {schema: 1, kind: 'scoped-ready', source,
  packages: [...m.targets.map(t => t.pkg), m.npmScope].map(name => ({name, version, integrity, shasum: 'd'.repeat(40)})),
  binaries: m.targets.map(t => ({package: t.pkg, target: t.triple, file: `rsrs-${t.triple}${t.triple.includes('windows') ? '.exe' : ''}`, sha256: hash})),
  assets: m.targets.flatMap(t => [`cli-build-${t.triple}.json`, `rsrs-${t.triple}-runtime.tar.gz`, `rsrs-${t.triple}${t.triple.includes('windows') ? '.exe' : ''}`]).sort().map(name => ({name, size: 42, sha256: hash})),
};
const aliasRun = {id: 400, run_attempt: 3, path: '.github/workflows/npm-alias.yml', event: 'workflow_run', head_repository: {full_name: source.repository}, status: 'completed', conclusion: 'success'};
const alias = {schema: 1, kind: 'alias-ready', source, scoped_packages: scoped.packages,
  alias: {name: 'rsrs-cli', version, integrity, shasum: 'd'.repeat(40)},
  publisher: {workflow: aliasRun.path, run_id: '400', run_attempt: '3'},
  install: {platform: 'linux-x64-gnu', version, binary_sha256: hash}};
const jobs = [{name: 'publish-integrated', conclusion: 'success'}];
const release = {id: 300, draft: true, tag_name: `v${version}`, target_commitish: sha, prerelease: true,
  assets: scoped.assets.map(a => ({name: a.name, size: a.size, state: 'uploaded', digest: `sha256:${a.sha256}`}))};
const copy = value => structuredClone(value);

test('complete ordinary and recovery job inventories wait only for the selected publisher', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/release.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const jobSection = workflow.split('\njobs:\n')[1];
  const definitions = [...jobSection.matchAll(/^  ([\w-]+):\n([\s\S]*?)(?=^  [\w-]+:\n|$(?![\s\S]))/gm)];
  assert(definitions.length > 5, 'Use the complete release job inventory');
  for (const resume of [false, true]) {
    const inventory = definitions.map(([, id, body]) => {
      const declared = body.match(/^    name: (.+)$/m)?.[1];
      const conditional = declared?.match(/^\$\{\{ inputs.resume_dev6_publication && '([^']+)' \|\| '([^']+)' \}\}$/);
      if (id === 'publish' || id === 'dev6-publication-resume') assert(conditional, 'Both publisher names must be conditional');
      return {id, name: conditional ? conditional[resume ? 1 : 2] : declared || id, status: 'completed', conclusion: 'success'};
    });
    const activeId = resume ? 'dev6-publication-resume' : 'publish';
    const active = inventory.find(j => j.id === activeId);
    const inactive = inventory.find(j => j.id === (resume ? 'publish' : 'dev6-publication-resume'));
    assert.equal(active.name, 'publish');
    assert.notEqual(inactive.name, 'publish');
    inactive.conclusion = 'skipped';
    assert.equal(inventory.filter(j => j.name === 'publish').length, 1);
    for (const status of ['queued', 'in_progress']) {
      active.status = status;
      assert.equal(scopedPublisherFinished(inventory), false, `${resume ? 'recovery' : 'ordinary'} publisher must keep waiting`);
    }
    active.status = 'completed';
    for (const conclusion of ['success', 'failure', 'skipped', 'cancelled']) {
      active.conclusion = conclusion;
      assert.equal(scopedPublisherFinished(inventory), true, 'Terminal selected publisher without a receipt must close the wait');
    }
  }
});

test('large multi-page release inventory survives the real subprocess boundary without truncation', () => {
  const pages = [Array.from({length: 50}, (_, i) => ({id: i + 1000, tag_name: `v0.0.${i}`,
    body: 'Synthetic release notes'.repeat(2200)})), [{...release, draft: true}]];
  const input = JSON.stringify(pages);
  assert(Buffer.byteLength(input) > 1024 * 1024);
  const args = ['-e', 'process.stdout.write(require("node:fs").readFileSync(0))'];
  assert.throws(() => execFileSync(process.execPath, args, {input, encoding: 'utf8'}), error => error.code === 'ENOBUFS');
  const result = publicationCommand(process.execPath, args, {input});
  assert.equal(result, input);
  const decoded = JSON.parse(result);
  assert.equal(selectRelease(decoded, version).id, release.id);
  assert.throws(() => selectRelease([...decoded, [{...release, draft: true}]], version), /exactly one release/);
});

test('publication command output remains bounded above the valid large-list case', () => {
  assert.throws(() => publicationCommand(process.execPath,
    ['-e', `process.stdout.write('x'.repeat(${PUBLICATION_MAX_BUFFER + 1}))`]), error => error.code === 'ENOBUFS');
});

test('exact scoped packages, draft and installed alias produce a complete barrier', () => {
  validateSource(source); validateScoped(scoped, m); assertSourceRun(sourceRun, source);
  assertDraft(release, scoped); validateAlias(alias, scoped, aliasRun, jobs);
  assert.equal(readyName(source), 'scoped-ready-100-2');
  assert.equal(aliasName(source, aliasRun), 'alias-ready-100-2-400-3');
});
test('selected source may differ from the dispatch workflow head SHA', () => {
  assert.notEqual(sourceRun.head_sha, source.sha);
  assert.doesNotThrow(() => assertSourceRun(sourceRun, source));
});
test('all source identity and current-attempt checks fail closed', () => {
  for (const mutation of [{repository: 'foreign/repo'}, {workflow: '.github/workflows/ci.yml'}, {run_id: '0'}, {run_attempt: 'x'}, {sha: 'main'}, {version: 'latest'}, {channel: 'latest'}, {release_id: 0}]) {
    assert.throws(() => validateSource({...source, ...mutation}));
  }
  for (const mutation of [{id: 101}, {run_attempt: 1}, {path: '.github/workflows/ci.yml'}, {event: 'pull_request'}, {status: 'completed'}, {status: 'queued'}, {head_repository: {full_name: 'foreign/repo'}}]) {
    assert.throws(() => assertSourceRun({...sourceRun, ...mutation}, source));
  }
});
test('missing, duplicate, mismatched or digestless scoped packages never open gate', () => {
  for (const mutate of [r => r.packages.pop(), r => r.packages.push(r.packages[0]), r => r.packages[0].version = '1.2.3', r => r.packages[0].integrity = '', r => r.packages[0].shasum = 'bad']) {
    const r = copy(scoped); mutate(r); assert.throws(() => validateScoped(r, m));
  }
});
test('all native binaries and complete asset identities must remain bound', () => {
  for (const mutate of [r => r.assets.pop(), r => r.assets[0].size = -1, r => r.assets[0].sha256 = '', r => r.binaries.pop(), r => r.binaries[0].sha256 = 'f'.repeat(64), r => r.binaries[0].target = 'wrong']) {
    const r = copy(scoped); mutate(r); assert.throws(() => validateScoped(r, m));
  }
  for (const mutate of [r => r.draft = false, r => r.id++, r => r.target_commitish = 'main', r => r.tag_name = 'v1.2.3', r => r.prerelease = false, r => r.assets.pop(), r => r.assets[0].digest = 'sha256:' + 'f'.repeat(64), r => r.assets[0].state = 'new']) {
    const r = copy(release); mutate(r); assert.throws(() => assertDraft(r, scoped));
  }
});
test('alias failure, no receipt, still-running job, stale run and stale attempt cannot publish parent', () => {
  assert.throws(() => validateAlias(null, scoped, aliasRun, jobs));
  assert.throws(() => validateAlias(alias, scoped, {...aliasRun, conclusion: 'failure'}, jobs));
  assert.throws(() => validateAlias(alias, scoped, {...aliasRun, status: 'in_progress'}, jobs));
  assert.throws(() => validateAlias(alias, scoped, aliasRun, [{name: 'publish-integrated', conclusion: null}]));
  assert.throws(() => validateAlias(alias, scoped, {...aliasRun, run_attempt: 4}, jobs));
  for (const mutate of [r => r.source.run_attempt = '1', r => r.source.run_id = '101', r => r.source.sha = 'f'.repeat(40), r => r.source.version = '1.2.3-dev.5', r => r.source.release_id++, r => r.publisher.run_id = '401', r => r.publisher.workflow = '.github/workflows/ci.yml', r => r.scoped_packages[0].integrity = '', r => r.alias.name = 'other', r => r.alias.version = '1.2.3', r => r.install.binary_sha256 = 'f'.repeat(64), r => r.install.version = '1.2.3']) {
    const r = copy(alias); mutate(r); assert.throws(() => validateAlias(r, scoped, aliasRun, jobs));
  }
});
test('safe failed-job rerun needs fresh receipts while immutable package identities remain unchanged', () => {
  const retried = copy(scoped); retried.source.run_attempt = '3';
  assert.notEqual(readyName(retried.source), readyName(scoped.source));
  assert.deepEqual(retried.packages, scoped.packages);
  assert.throws(() => validateAlias(alias, retried, aliasRun, jobs));
  const newAlias = copy(alias); newAlias.source.run_attempt = '3';
  validateAlias(newAlias, retried, aliasRun, jobs);
});

test('workflow contract keeps trust identities, unprivileged waiting and acyclic publication locks', () => {
  const root = new URL('../../', import.meta.url);
  const child = readFileSync(new URL('.github/workflows/npm-alias.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const parent = readFileSync(new URL('.github/workflows/release.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const helper = readFileSync(new URL('npm/scripts/release-publication.mjs', root), 'utf8').replace(/\r\n/g, '\n');
  assert.doesNotMatch(child, /workflow_run:/);
  assert.match(child, /release_attempt:/);
  assert.doesNotMatch(child.slice(0, child.indexOf('jobs:')), /concurrency:/);
  const waiting = child.split('  await-scoped:')[1].split('  publish-integrated:')[0];
  assert.doesNotMatch(waiting, /concurrency:|id-token:/);
  const publishing = child.split('  publish-integrated:')[1].split('\n  publish:')[0];
  assert.match(publishing, /needs: await-scoped/);
  assert.match(publishing, /ref: \$\{\{ needs.await-scoped.outputs.sha \}\}/);
  assert.match(publishing, /group: npm-rsrs-cli-publication\n      queue: max\n      cancel-in-progress: false/);
  assert.match(publishing, /contents: read\n      actions: read\n      id-token: write/);
  assert.doesNotMatch(publishing, /contents: write|actions: write|workflow_call/);
  assert.match(waiting, /Read this Release attempt scoped publication receipt once/);
  assert.doesNotMatch(waiting, /concurrency:|id-token:/);
  assert.match(child.split('\n  publish:')[1], /if: github.event_name == 'workflow_dispatch'/);
  const final = parent.split('\n  publish:')[1];
  const indices = ['--publish --accepted-only --verified-packs npm/publication-packages --tag', 'scoped-accepted', 'name: scoped-accepted-', 'gh workflow run npm-alias.yml', 'await-alias-accepted', 'release-publication.mjs finalize-accepted'].map(s => final.indexOf(s));
  assert(indices.every(i => i >= 0));
  assert.deepEqual(indices, [...indices].sort((a,b) => a-b));
  assert.equal((helper.match(/'--draft=false'/g) || []).length, 1);
  assert(final.indexOf('release-publication.mjs protocol') < final.indexOf('--publish --accepted-only --verified-packs npm/publication-packages --tag'));
  assert.match(parent, /tags: \['v\*'\]/);
  assert.match(final, /group: cli-release-publication\n      queue: max\n      cancel-in-progress: false/);
  assert.match(final, /contents: write\n      actions: write\n      id-token: write/);
  const resolver=helper.split('async function awaitScoped()')[1].split('// Retry only')[0];
  assert.doesNotMatch(resolver,/while\s*\(|sleep\(|deadline/);
  assert.match(resolver,/Exact scoped receipt missing/);
  for (const name of ['Bind successful scoped npm submissions', 'Require every matching npm submission', 'Make the complete release public']) {
    assert.match(final.slice(final.indexOf(`- name: ${name}`)).split('\n      - ')[0], /!\(inputs.repair_dev12 \|\| inputs.repair_dev14\)/);
  }
});

test('same-run scoped tarball reuse is explicit current-main only; historical, prepared and repair paths keep packing',()=>{
  const workflow=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const publisher=workflow.split('\n  publish:')[1];
  const expression=publisher.match(/^      REUSE_VALIDATED_PACKS: \$\{\{ (.+) \}\}$/m)?.[1];
  assert(expression,'reuse must be selected from the workflow trust context');
  const repository=expression.match(/github.repository == '([^']+)'/)?.[1];assert(repository);
  const selected=new Function('github','needs','inputs',`return (${expression});`);
  for(const owner of [repository,'fork/repo']) for(const event of ['workflow_dispatch','push']) for(const ref of ['refs/heads/main','refs/heads/feature'])
    for(const exact of [true,false]) for(const prepared of ['', '100']) for(const repair12 of [false,true])
    for(const repair14 of [false,true]) for(const reuse of [false,true]) {
      const github={repository:owner,event_name:event,ref,sha:'a'.repeat(40)},needs={plan:{outputs:{sha:(exact?'a':'b').repeat(40)}}};
      const inputs={prepared_run:prepared,repair_dev12:repair12,repair_dev14:repair14,reuse_dev12_validation:reuse};
      assert.equal(selected(github,needs,inputs),owner===repository&&event==='workflow_dispatch'&&ref==='refs/heads/main'&&exact&&!prepared&&!repair12&&!repair14&&!reuse);
    }
  const verify=publisher.split('- name: Verify release artifacts and prepare every scoped npm package')[1].split('\n      - ')[0];
  assert.match(verify,/CLI_SHA: \$\{\{ needs.plan.outputs.sha \}\}/);
  assert.match(verify,/if \[ "\$REUSE_VALIDATED_PACKS" = true \]; then\n\s+node npm\/scripts\/verify-packages.mjs release-assets --reuse-packs "\$RUNNER_TEMP\/validated-npm" --download --export-packs npm\/publication-packages\n\s+else\n\s+node npm\/scripts\/verify-packages.mjs release-assets --pack npm\/publication-packages\n\s+fi/);
  const publish=publisher.split('- name: Publish npm using Trusted Publishing')[1].split('\n      - ')[0];
  assert.doesNotMatch(publish,/npm\/scripts\/pack.mjs.*\$RUNNER_TEMP\/validated-npm/);
  assert.match(publish,/--publish --accepted-only --verified-packs npm\/publication-packages --tag/);
  assert.match(publisher,/name: npm-publication-packages/);
  assert.match(publisher,/if: inputs.prepared_run != ''\n\s+run: node npm\/scripts\/verify-packages.mjs release-assets --pack npm\/release-packages/);
});
test('two overlapping Releases progress without waiting while holding the opposite alias lock', () => {
  // Model the actual lock graph asserted above. B's early ready wait has no lock.
  let publication = 'A', aliasLock = null;
  const ready = new Set(['A']), done = new Set();
  const acquireAlias = id => { if (!ready.has(id) || aliasLock) return false; aliasLock = id; return true; };
  assert.equal(acquireAlias('B'), false); // B waits for scoped-ready without locking.
  assert.equal(acquireAlias('A'), true);
  done.add('A'); aliasLock = null;
  assert(done.has(publication)); publication = 'B'; ready.add('B');
  assert.equal(acquireAlias('B'), true); done.add('B'); aliasLock = null;
  assert(done.has(publication));
});

test('existing lightweight or resolved annotated tag must identify the release source', () => {
  assertTagCommit(null, source);
  assertTagCommit({type: 'commit', sha: source.sha}, source);
  assert.throws(() => assertTagCommit(null, source, {allowMissing: false}));
  assertTagCommit({type: 'commit', sha: source.sha}, source, {allowMissing: false});
  assert.throws(() => assertTagCommit({type: 'commit', sha: 'f'.repeat(40)}, source));
  assert.throws(() => assertTagCommit({type: 'tag', sha: source.sha}, source));
});

test('missing is pending, but duplicate, expired or foreign-run artifacts are rejected', () => {
  const a = {expired: false, workflow_run: {id: 100}};
  assert.equal(validateArtifact([], 100), null);
  assert.equal(validateArtifact([a], 100), a);
  assert.throws(() => validateArtifact([a, a], 100));
  assert.throws(() => validateArtifact([{...a, expired: true}], 100));
  assert.throws(() => validateArtifact([a], 101));
});

test('all Actions uploads, including both handshake receipts, retain evidence for one day', () => {
  const root = new URL('../../.github/workflows/', import.meta.url);
  let uploads = 0;
  for (const file of readdirSync(root).filter(name => /\.ya?ml$/.test(name))) {
    const workflow = readFileSync(new URL(file, root), 'utf8');
    for (const match of workflow.matchAll(/^([ \t]*)(- )?uses: actions\/upload-artifact@[^\s]+.*$/gm)) {
      const stepIndent = match[1].length - (match[2] ? 0 : 2);
      const tail = workflow.slice(match.index + match[0].length);
      const nextStep = tail.search(new RegExp(`\\n[ \t]{0,${stepIndent}}\\S`));
      const body = nextStep < 0 ? tail : tail.slice(0, nextStep);
      assert.match(body, /^[ \t]+retention-days: 1[ \t]*$/m, `${file}: every upload must retain exactly one day`);
      uploads++;
    }
  }
  // Keep the validated parent publication tarballs alongside the existing evidence.
  assert.equal(uploads, 51, 'preserve active evidence, registered consumer, verified platform copies, import proof and release dependency cache');
  const crates = readFileSync(new URL('publish-crates.yml', root), 'utf8');
  assert.match(crates, /name: protocol-package-verification/);
  assert.doesNotMatch(crates, /name: sdk-package-verification/);
});

test('draft release is resolved from every list page with exactly one matching tag', () => {
  const draft = {...release, draft: true};
  assert.equal(selectRelease([[{id: 299, tag_name: 'v1.2.3-dev.3'}], [draft]], version), draft);
  assert.throws(() => selectRelease([[{id: 299, tag_name: 'v1.2.3-dev.3'}]], version), /exactly one release/);
  assert.throws(() => selectRelease([[draft], [draft]], version), /exactly one release/);
  assert.throws(() => selectRelease([[{...draft, id: 0}]], version), /exactly one release/);
  assert.throws(() => selectRelease([null], version), /Invalid paginated/);
  assert.throws(() => selectRelease([[{...draft, draft: false}]], version), /must still be a draft/);
  const helper = readFileSync(new URL('./release-publication.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(helper, /releases\/tags\//);
  assert.match(helper, /selectRelease\(pages\(`/);
});


test('alias job and parent receipt budgets cover both propagation waits and clean install', () => {
  const root = new URL('../../', import.meta.url);
  const helper = readFileSync(new URL('npm/scripts/release-publication.mjs', root), 'utf8').replace(/\r\n/g, '\n');
  const child = readFileSync(new URL('.github/workflows/npm-alias.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const parent = readFileSync(new URL('.github/workflows/release.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const minutes = (text, pattern) => {
    const match = text.match(pattern);
    assert(match, 'The publication timeout must remain explicitly bound to its call or job');
    return Number(match[1]);
  };
  const scoped = minutes(helper, /verifyPackages\(scoped\.packages, \{[^}]*timeoutMs: (\d+) \* 60 \* 1000/);
  const alias = minutes(helper, /source\.channel, \{requireInstallIndex: true, timeoutMs: (\d+) \* 60 \* 1000/);
  const install = minutes(helper, /options\.timeoutMs \?\? (\d+) \* 60 \* 1000;\n  const deadline = now\(\)/);
  const job = minutes(child.split('  publish-integrated:')[1].split('\n  publish:')[0], /timeout-minutes: (\d+)/);
  const receipt = minutes(helper, /async function awaitAlias\(\) \{[\s\S]*?Date\.now\(\) \+ (\d+) \* 60 \* 1000;/);
  assert.equal(alias, scoped);
  assert(scoped >= 30);
  assert(job > scoped + alias + install, 'Job must leave room for setup and packaging');
  assert(receipt > job, 'Receipt observer must outlive the publisher');
  const legacyParent = parent.slice(parent.indexOf('  dev6-publication-resume:'));
  const observers = [...legacyParent.matchAll(/timeout-minutes: (\d+)\n        env:\n          GH_TOKEN: \$\{\{ github\.token \}\}\n        run: node npm\/scripts\/release-publication\.mjs await-alias/g)];
  assert.equal(observers.length, 1);
  assert(observers.every(match => Number(match[1]) > receipt));
  const recovery = minutes(parent.split('\n  dev6-publication-resume:')[1], /timeout-minutes: (\d+)/);
  const revalidation = minutes(helper, /options\.timeoutMs \?\? (\d+) \* 60 \* 1000/);
  assert(recovery > revalidation + receipt, 'Historical recovery needs revalidation and observation time');
});

test('npm resolver visibility delay retries exact pinned packages inside one deadline', async () => {
  let elapsed = 0, attempts = 0;
  const remaining = [], logged = [];
  const specs = [...scoped.packages, alias.alias].map(p => `${p.name}@${p.version}`);
  const output = await waitForPublicInstall(timeout => {
    remaining.push(timeout);
    elapsed += 2;
    if (++attempts <= 2) throw Object.assign(new Error('npm failed'), {status: 1,
      stdout: JSON.stringify({error: {code: 'ETARGET', summary: `No matching version found for ${specs[attempts - 1]}.`}})});
    return 'installed';
  }, specs, {timeoutMs: 30, pollMs: 5, now: () => elapsed, sleep: async ms => {elapsed += ms;},
    onRetry: (_, attempt) => logged.push(attempt)});
  assert.equal(output, 'installed');
  assert.deepEqual(remaining, [30, 23, 16]);
  assert.deepEqual(logged, [1, 2]);
});

test('npm resolver failures remain bounded and preserve the original error', async () => {
  const error = Object.assign(new Error('npm failed'), {status: 1,
    stdout: JSON.stringify({error: {code: 'ETARGET', summary: `No matching version found for rsrs-cli@${version}.`}})});
  for (const timeoutMs of [11, 30]) {
    let elapsed = 0, attempts = 0;
    await assert.rejects(waitForPublicInstall(() => {attempts++; throw error;}, [`rsrs-cli@${version}`],
      {timeoutMs, pollMs: 5, now: () => elapsed, sleep: async ms => {elapsed += ms;}}), actual => actual === error);
    assert.equal(attempts, 3);
  }
  let attempts = 0;
  await assert.rejects(waitForPublicInstall(() => {attempts++; throw error;}, [`rsrs-cli@${version}`],
    {timeoutMs: 5, pollMs: 5}), actual => actual === error);
  assert.equal(attempts, 1);
});

test('foreign ETARGET, malformed JSON, integrity, authorization and process failures never retry', async () => {
  const report = summary => JSON.stringify({error: {code: 'ETARGET', summary}});
  for (const fields of [
    {stdout: report('No matching version found for foreign@1.0.0.')},
    {stdout: report(`No matching version found for rsrs-cli@1.2.3-dev.99.`)},
    {stdout: 'invalid JSON'},
    {stdout: JSON.stringify({error: {code: 'EINTEGRITY', summary: 'bad digest'}})},
    {stdout: JSON.stringify({error: {code: 'E401', summary: 'unauthorized'}})},
    {status: null, signal: 'SIGTERM', code: 'ETIMEDOUT', stdout: report(`No matching version found for rsrs-cli@${version}.`)},
  ]) {
    const error = Object.assign(new Error('npm failed'), {status: 1}, fields);
    let attempts = 0;
    await assert.rejects(waitForPublicInstall(() => {attempts++; throw error;}, [`rsrs-cli@${version}`]),
      actual => actual === error);
    assert.equal(attempts, 1);
  }
});

test('real publication install opts into npm freshness and structured errors without changing its pin', () => {
  const args = publicInstallArgs('/isolated/install', '/isolated/cache', version);
  assert(args.includes('--prefer-online'));
  assert(args.includes('--json'));
  assert.equal(args.at(-1), `rsrs-cli@${version}`);
  assert.equal(args[args.indexOf('--registry') + 1], 'https://registry.npmjs.org');
});

test('actual npm resolver recovers from an offline registry index delay with a fresh request', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'rsrs-install-index-test-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const npmCli = [
    path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
    path.resolve(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'),
  ].find(existsSync);
  assert(npmCli, 'The test requires the npm installed beside Node');
  const env = {...process.env};
  for (const key of Object.keys(env)) if (/^(?:npm_config_|NODE_AUTH_TOKEN$|NPM_TOKEN$|GH_TOKEN$|GITHUB_TOKEN$|ACTIONS_ID_TOKEN_REQUEST_)/i.test(key)) delete env[key];
  Object.assign(env, {HOME: root, USERPROFILE: root, NPM_CONFIG_CACHE: path.join(root, 'cache'),
    NPM_CONFIG_USERCONFIG: path.join(root, 'empty.npmrc'), NPM_CONFIG_GLOBALCONFIG: path.join(root, 'global.npmrc')});
  writeFileSync(env.NPM_CONFIG_USERCONFIG, ''); writeFileSync(env.NPM_CONFIG_GLOBALCONFIG, '');
  const pkg = path.join(root, 'package');
  mkdirSync(pkg);
  writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({name: 'rsrs-cli', version}));
  const execute = promisify(execFile);
  await execute(process.execPath, [npmCli, 'pack', '--ignore-scripts', '--json', '--pack-destination', root], {cwd: pkg, env, timeout: 30000});
  const tarball = readFileSync(path.join(root, readdirSync(root).find(file => file.endsWith('.tgz'))));
  let visible = false, indexRequests = 0, retries = 0, attempts = 0;
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/rsrs-cli') {
      indexRequests++;
      const metadata = {name: 'rsrs-cli', version, dist: {
        tarball: `http://127.0.0.1:${server.address().port}/fixture.tgz`,
        integrity: `sha512-${createHash('sha512').update(tarball).digest('base64')}`,
        shasum: createHash('sha1').update(tarball).digest('hex')}};
      response.end(JSON.stringify({name: 'rsrs-cli', 'dist-tags': {dev: version},
        versions: visible ? {[version]: metadata} : {}}));
    } else if (request.url === '/fixture.tgz') {
      response.setHeader('Content-Type', 'application/octet-stream'); response.end(tarball);
    } else { response.statusCode = 404; response.end('{}'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => {server.close(resolve); server.closeAllConnections();}));
  const args = publicInstallArgs(path.join(root, 'install'), env.NPM_CONFIG_CACHE, version);
  args[args.indexOf('--registry') + 1] = `http://127.0.0.1:${server.address().port}`;
  args.splice(1, 0, '--ignore-scripts');
  await waitForPublicInstall(async timeout => {
    attempts++;
    try { return (await execute(process.execPath, [npmCli, ...args], {env, timeout})).stdout; }
    catch (error) {
      // execFileSync (production) calls this exit code status; execFile calls it code.
      error.status = error.code; throw error;
    }
  }, [`rsrs-cli@${version}`], {timeoutMs: 30000, pollMs: 1, onRetry: error => {
    assert.equal(JSON.parse(error.stdout).error.code, 'ETARGET');
    retries++; visible = true;
  }});
  assert.equal(retries, 1);
  assert.equal(attempts, 2);
  assert(indexRequests >= 2, 'The retry must fetch the registry again rather than reuse stale cache');
  assert.equal(JSON.parse(readFileSync(path.join(root, 'install/node_modules/rsrs-cli/package.json'))).version, version);
});


test('public installation selects explicit libc and requires actual matching host architecture',()=>{
  assert.equal(publicInstallPlatform('linux-x64-gnu',{platform:'linux',arch:'x64'}).libc,'glibc');
  for(const [platform,libc] of [['linux-arm64','musl'],['linux-arm64-gnu','glibc']]){
    assert.deepEqual(publicInstallPlatform(platform,{platform:'linux',arch:'arm64'}),{arch:'arm64',libc,pkg:'@rsrsai/'+platform,platform});
    assert.throws(()=>publicInstallPlatform(platform,{platform:'linux',arch:'x64'}));
    assert.throws(()=>publicInstallPlatform(platform,{platform:'darwin',arch:'arm64'}));
  }
  assert.throws(()=>publicInstallPlatform('foreign',{platform:'linux',arch:'arm64'}));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {DEV6, TARGETS, validateRecoveryInputs, validateRecoverySource, validateRecoveryAuthority, validateOriginalValidation, validateOriginalArtifact} from './dev6-recovery-policy.mjs';
import {validateSource, assertSourceRun, validateScoped, assertDraft} from './release-publication.mjs';
import {validateRecoveryBuilds, verifyRecoveryPackages, verifyRecoveryAlias} from './dev6-publication-recovery.mjs';
const copy = structuredClone;
const m = JSON.parse(readFileSync(new URL('../artifact-manifest.json', import.meta.url))); m.npmScope = '@rsrsai/cli'; // Historical receipt layout.
m.cliVersion = DEV6.version;
m.targets=m.targets.filter(t=>TARGETS.includes(t.triple)); // immutable historical DEV6 platform inventory
const env = {GITHUB_REPOSITORY: DEV6.repository, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: 'refs/heads/main', RECOVERY_REF: DEV6.sha,
  RECOVERY_VERSION: DEV6.version, RECOVERY_PUBLISH: 'true', RECOVERY_FULL: 'true', RECOVERY_REUSE: 'false',
  RECOVERY_REPAIR12: 'false', RECOVERY_REPAIR14: 'false'};
const source = {repository: DEV6.repository, workflow: DEV6.workflow, run_id: '999', run_attempt: '2',
  sha: DEV6.sha, tooling_sha: 'a'.repeat(40), version: DEV6.version, channel: 'dev', release_id: DEV6.release,
  recovery: {kind: 'dev6-publication-only', validation_run: DEV6.run, validation_attempt: DEV6.attempt}};
const run = {id: DEV6.run, run_attempt: 3, head_sha: DEV6.sha, path: DEV6.workflow,
  head_repository: {full_name: DEV6.repository}, event: 'workflow_dispatch', status: 'completed', conclusion: 'failure'};
const ci = {id: DEV6.ci, run_attempt: 2, head_sha: DEV6.sha, path: '.github/workflows/ci.yml', event: 'push', status: 'completed', conclusion: 'success'};
const names = ['plan','validate / resolve','validate / npm-dry-run','api-smoke',
  ...TARGETS.flatMap(t => [`validate / Release (${t})`,`native-regression / Native (${t})`]),
  'cloud-sweep (ubuntu-latest, x86_64-unknown-linux-musl)','cloud-sweep (macos-latest, aarch64-apple-darwin)','cloud-sweep (windows-latest, x86_64-pc-windows-msvc)'];
const jobs = names.map(name => ({name,run_id: DEV6.run,head_sha: DEV6.sha,status:'completed',conclusion:'success'}));
jobs.push({name:'publish',run_id:DEV6.run,head_sha:DEV6.sha,status:'completed',conclusion:'failure',steps:[
  {name:'Publish npm using Trusted Publishing',conclusion:'success'},
  {name:'Verify scoped registry propagation and bind the draft receipt',conclusion:'failure'}]});
const bytes = Buffer.from('Synthetic immutable package bytes');
const integrity = 'sha512-'+createHash('sha512').update(bytes).digest('base64');
const shasum = createHash('sha1').update(bytes).digest('hex');
const packages = [...m.targets.map(t => t.pkg),m.npmScope].map(name => ({name,version:DEV6.version,integrity,shasum}));
const sha256 = 'b'.repeat(64);
const builds = m.targets.map(t => ({schema_version:1,target:t.triple,git_sha:DEV6.sha,version:DEV6.version,
  binary_file:`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,runtime_file:`rsrs-${t.triple}-runtime.tar.gz`,binary_sha256:sha256,runtime_sha256:sha256}));
const assets = builds.flatMap(b => [b.binary_file,b.runtime_file,`cli-build-${b.target}.json`]).map(name => ({name,size:42,sha256}));
const scoped = {schema:1,kind:'scoped-ready',source,packages,assets,binaries:builds.map(b => ({package:m.targets.find(t=>t.triple===b.target).pkg,target:b.target,file:b.binary_file,sha256}))};
function registry(mutate = () => {}, actual = bytes) {
  return {fetchImpl: async url => {
    if (url.includes('/-/')) return {status:200,body:(async function*(){yield actual;})()};
    const name = decodeURIComponent(new URL(url).pathname.split('/')[1]);
    const p = m.targets.find(t => t.pkg===name);
    const metadata = {name,version:DEV6.version,repository:{url:'git+https://github.com/risense-ai/respire-cli.git'},
      dist:{integrity,shasum,tarball:'https://registry.npmjs.org/-/synthetic.tgz'},
      ...(p?{os:p.os,cpu:p.cpu,...(p.libc?{libc:p.libc}:{})}:name==='rsrs-cli'?{dependencies:{'@rsrsai/cli':DEV6.version}}:{optionalDependencies:Object.fromEntries(m.targets.map(t=>[t.pkg,DEV6.version]))})};
    mutate(metadata);return {status:200,json:async()=>metadata};
  }};
}
test('recovery records actual tooling separately and preserves immutable product identity', () => {
  validateRecoveryInputs(env);validateRecoverySource(source);validateSource(source);validateScoped(scoped,m);
  assertSourceRun({id:999,run_attempt:2,path:DEV6.workflow,event:'workflow_dispatch',head_branch:'main',head_repository:{full_name:DEV6.repository},head_sha:source.tooling_sha,status:'in_progress'},source);
  assert.notEqual(source.tooling_sha,source.sha);
});

test('recovery tooling must independently belong to main before entering OIDC', () => {
  const main = 'c'.repeat(40);
  const active = {head_branch:'main',event:'workflow_dispatch',head_sha:source.tooling_sha};
  const comparison = {status:'behind',base_commit:{sha:main},merge_base_commit:{sha:source.tooling_sha}};
  validateRecoveryAuthority(source,active,main,comparison);
  validateRecoveryAuthority(source,active,source.tooling_sha,{...comparison,status:'identical',base_commit:{sha:source.tooling_sha}});
  for (const change of [{head_branch:'fix/prompt-untrusted'}, {head_branch:null}, {head_sha:'d'.repeat(40)}, {event:'push'}]) {
    assert.throws(()=>validateRecoveryAuthority(source,{...active,...change},main,comparison));
  }
  for (const change of [{status:'ahead'}, {status:'diverged'}, {base_commit:{sha:'d'.repeat(40)}}, {merge_base_commit:{sha:main}}]) {
    assert.throws(()=>validateRecoveryAuthority(source,active,main,{...comparison,...change}));
  }
  assert.throws(()=>validateRecoveryInputs({...env,GITHUB_REF:'refs/heads/fix/prompt-untrusted'}));
  const helper=readFileSync(new URL('./release-publication.mjs',import.meta.url),'utf8');
  const waiting=helper.split('async function awaitScoped()')[1].split('async function publishAlias()')[0];
  const authorityCall='assertRecoveryAuthority(scoped.source, run)';
  const outputCall="output({eligible: 'true'";
  const assertAuthorityBeforeOutput = code => {
    const authorityIndex=code.indexOf(authorityCall), outputIndex=code.indexOf(outputCall);
    assert(authorityIndex >= 0, 'Authority check must exist');
    assert(outputIndex >= 0, 'Eligible output must exist');
    assert(authorityIndex < outputIndex, 'Authority check must precede eligible output');
  };
  assertAuthorityBeforeOutput(waiting);
  assert.throws(()=>assertAuthorityBeforeOutput(waiting.replace(authorityCall,'')), /Authority check must exist/);
  assert.throws(()=>assertAuthorityBeforeOutput(waiting.replace(outputCall,'')), /Eligible output must exist/);
  const activeCheck=helper.split('function assertActive(source)')[1].split('\n}')[0];
  assert.match(activeCheck,/assertRecoveryAuthority\(source, run\)/);
  const root=new URL('../../',import.meta.url);
  const aliasWorkflow=readFileSync(new URL('.github/workflows/npm-alias.yml',root),'utf8').replace(/\r\n/g,'\n');
  const readOnlyJob=aliasWorkflow.split('  await-scoped:')[1].split('  publish-integrated:')[0];
  assert.match(readOnlyJob,/ref: main/);
  assert.doesNotMatch(readOnlyJob,/id-token:/);
  const releaseWorkflow=readFileSync(new URL('.github/workflows/release.yml',root),'utf8');
  assert.match(releaseWorkflow.split('  dev6-publication-resume:')[1],/github.ref == 'refs\/heads\/main'/);
  const recovery=readFileSync(new URL('./dev6-publication-recovery.mjs',import.meta.url),'utf8');
  assert.match(recovery,/r.head_branch === 'main'/);
});
test('wrong source/run/version/channel/tooling/input flags cannot select recovery', () => {
  for (const mutation of [{sha:'c'.repeat(40)},{version:'1.0.15-dev.7'},{channel:'latest'},{release_id:1},{run_id:DEV6.run},{tooling_sha:DEV6.sha},{recovery:{...source.recovery,validation_run:1}},{recovery:{...source.recovery,validation_attempt:2}}]) assert.throws(()=>validateSource({...source,...mutation}));
  for (const key of Object.keys(env)) assert.throws(()=>validateRecoveryInputs({...env,[key]:'wrong'}));
  assert.throws(()=>validateSource({...source,recovery:undefined}));
});
test('every original build, regression, API and CI gate is required exactly once', () => {
  validateOriginalValidation(run,jobs,ci);
  for (const name of names) {
    assert.throws(()=>validateOriginalValidation(run,jobs.filter(j=>j.name!==name),ci));
    assert.throws(()=>validateOriginalValidation(run,jobs.map(j=>j.name===name?{...j,conclusion:'skipped'}:j),ci));
  }
  for (const mutation of [{id:1},{head_sha:'c'.repeat(40)},{run_attempt:2},{status:'in_progress'},{event:'pull_request'},{conclusion:'success'}]) assert.throws(()=>validateOriginalValidation({...run,...mutation},jobs,ci));
  assert.throws(()=>validateOriginalValidation(run,[...jobs,jobs[0]],ci));
  assert.throws(()=>validateOriginalValidation(run,jobs,{...ci,conclusion:'failure'}));
});
test('original artifact ID provenance, duplicate name and expiry fail closed', () => {
  const a={name:'npm-release-validation',expired:false,workflow_run:{id:DEV6.run,head_sha:DEV6.sha}};
  assert.equal(validateOriginalArtifact([a],a.name),a);
  for(const list of [[],[a,a],[{...a,expired:true}],[{...a,workflow_run:{id:1,head_sha:DEV6.sha}}]]) assert.throws(()=>validateOriginalArtifact(list,a.name));
});
test('all original build metadata, exact draft/source and actual asset digests stay bound', () => {
  validateRecoveryBuilds(m,assets,builds);
  for(const mutate of [b=>b.git_sha='c'.repeat(40),b=>b.version='1.0.15-dev.7',b=>b.binary_sha256='c'.repeat(64),b=>b.target='wrong']) {
    const changed=copy(builds);mutate(changed[0]);assert.throws(()=>validateRecoveryBuilds(m,assets,changed));
  }
  assert.throws(()=>validateRecoveryBuilds(m,assets.slice(1),builds));
  const draft={id:DEV6.release,tag_name:'v'+DEV6.version,target_commitish:DEV6.sha,draft:true,prerelease:true,
    assets:assets.map(a=>({name:a.name,size:a.size,digest:'sha256:'+a.sha256,state:'uploaded'}))};
  assertDraft(draft,scoped);
  for(const mutate of [d=>d.id++,d=>d.draft=false,d=>d.target_commitish='main',d=>d.assets.pop(),d=>d.assets[0].digest='sha256:'+'c'.repeat(64)]) {const d=copy(draft);mutate(d);assert.throws(()=>assertDraft(d,scoped));}
});
test('five registry tarball bytes, exact dependencies and platform identity are reverified without publish', async () => {
  await verifyRecoveryPackages(packages,m,registry());
  await assert.rejects(verifyRecoveryPackages(packages.slice(1),m,registry()));
  await assert.rejects(verifyRecoveryPackages(packages,m,registry(p=>{p.version='1.0.15-dev.7';})));
  await assert.rejects(verifyRecoveryPackages(packages,m,registry(()=>{},Buffer.from('different bytes'))));
  await assert.rejects(verifyRecoveryPackages(packages,m,registry(p=>{if(p.optionalDependencies)p.optionalDependencies['@rsrsai/win-x64']='1.0.15-dev.5';})));
  await assert.rejects(verifyRecoveryPackages(packages,m,registry(p=>{if(p.os)p.os=['wrong'];})));
});
test('absent short entry is allowed but an existing inconsistent version/bytes/dependency blocks recovery', async () => {
  const expected={name:'rsrs-cli',version:DEV6.version,integrity,shasum};
  assert.equal(await verifyRecoveryAlias(expected,{fetchImpl:async()=>({status:404})}),null);
  await verifyRecoveryAlias(expected,registry());
  await assert.rejects(verifyRecoveryAlias(expected,registry(p=>{p.dependencies['@rsrsai/cli']='1.0.15-dev.5';})));
  await assert.rejects(verifyRecoveryAlias(expected,registry(()=>{},Buffer.from('inconsistent alias'))));
});
test('resume workflow retains trusted identity, no builds/scoped writes, and both publication barriers', () => {
  const root=new URL('../../',import.meta.url);
  const workflow=readFileSync(new URL('.github/workflows/release.yml',root),'utf8').replace(/\r\n/g,'\n');
  const resume=workflow.split('  dev6-publication-resume:')[1];
  assert.match(resume,/name: \$\{\{ inputs.resume_dev6_publication && 'publish' \|\| 'unused-dev6-publication-resume' \}\}/);
  assert.match(resume,/contents: write\n      actions: write/);
  assert(resume.indexOf('name: scoped-ready-')<resume.indexOf('gh workflow run npm-alias.yml'));
  assert.doesNotMatch(resume,/id-token:|cargo|--clobber|release upload|--publish|workflow_call|npm publish/);
  assert(resume.indexOf('recovery-ready')<resume.indexOf('name: scoped-ready-'));
  assert(resume.indexOf('name: scoped-ready-')<resume.indexOf('await-alias'));
  assert(resume.indexOf('await-alias')<resume.indexOf('release-publication.mjs finalize'));
  assert.match(workflow,/!inputs.resume_dev6_publication/);
});

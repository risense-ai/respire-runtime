import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync,mkdirSync,cpSync,chmodSync,rmSync,existsSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {validateAcceptedScoped,validateAcceptedAlias,validateAcceptance,validateVerified,validateArmVerified,
  assertCompletedSource,acceptedScopedOutput,reconcilePriorSubmissions,serviceDuration} from './publication-acceptance.mjs';
import {assertSourceRun,validateScoped} from './release-publication.mjs';
import {planCleanup,executeCleanup,CLEANUP_POLICY} from './cleanup-release-artifacts.mjs';
import {regressionContract} from './release-regression-contract.mjs';
import {createPreparation,preparationLink} from './release-preparation.mjs';
import {importedAnchor} from './prepared-import.mjs';
const m=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url))); m.npmScope = '@rsrsai/cli'; // Historical receipt layout.
const copy=structuredClone;
const hash='a'.repeat(64), sha='b'.repeat(40), version='1.2.3-dev.4';
const source={repository:'risense-ai/respire-cli',workflow:'.github/workflows/release.yml',run_id:'100',run_attempt:'1',sha,version,channel:'dev',release_id:300};
const identity=name=>({name,version,integrity:'sha512-'+createHash('sha512').update(name).digest('base64'),shasum:'c'.repeat(40)});
const proof=p=>({...p,schema:1,state:'accepted',evidence:'npm-exit-zero',exit_code:0,signal:null,accepted_at:'2026-10-27T00:00:00Z'});
function fixture(){
  const packages=[...m.targets.map(t=>t.pkg),m.npmScope].map(identity);
  const scoped={schema:2,kind:'scoped-accepted',state:'accepted',source:copy(source),packages,acceptances:packages.map(proof),cleanup_policy:CLEANUP_POLICY,
    binaries:m.targets.map(t=>({package:t.pkg,target:t.triple,file:`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,sha256:hash})),
    assets:m.targets.flatMap(t=>[`cli-build-${t.triple}.json`,`rsrs-${t.triple}-runtime.tar.gz`,`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`]).map(name=>({name,size:42,sha256:hash}))};
  const run={id:100,run_attempt:1,path:source.workflow,head_repository:{full_name:source.repository},head_sha:'d'.repeat(40),event:'workflow_dispatch',status:'completed',conclusion:'success',created_at:'2026-10-27T00:00:00Z',updated_at:'2026-10-27T00:10:00Z'};
  const child={...run,id:200,path:'.github/workflows/npm-alias.yml',event:'workflow_run'};
  const alias={schema:2,kind:'alias-accepted',state:'accepted',source:copy(source),scoped_packages:packages,alias:identity('rsrs-cli'),dependencies:{'@rsrsai/cli':version},publisher:{workflow:child.path,run_id:200,run_attempt:1},acceptance:proof(identity('rsrs-cli'))};
  const jobs=[{name:'publish-integrated',status:'completed',conclusion:'success',completed_at:run.updated_at}];
  const verified={schema:2,kind:'publication-verified',state:'verified',source:copy(source),packages:[...packages,alias.alias],alias_publisher:alias.publisher,
    verified_at:'2026-10-27T00:20:00Z',install:{platform:'linux-x64-gnu',version,binary_sha256:hash}};
  return {scoped,alias,run,child,jobs,verified};
}

test('service durations never mix runner ACK clocks or report negative intervals',()=>{
  assert.equal(serviceDuration('2026-10-27T00:00:00Z','2026-10-27T00:10:00Z'),600);
  assert.equal(serviceDuration('2026-10-27T00:10:00Z','2026-10-27T00:00:00Z'),null);
  assert.equal(serviceDuration('invalid','2026-10-27T00:10:00Z'),null);
  assert.equal(serviceDuration('2026-10-27T00:00:00Z',undefined),null);
});

test('accepted receipts require all exact package ACKs and cannot masquerade as verified protocol 1',()=>{
  const f=fixture();validateAcceptedScoped(f.scoped,m);
  const direct=copy(f), directManifest={...m,npmScope:'rsrs-cli'};
  direct.scoped.launcher=identity('rsrs-cli');
  direct.scoped.packages=direct.scoped.packages.filter(p=>p.name!==m.npmScope);
  direct.scoped.acceptances=direct.scoped.acceptances.filter(p=>p.name!==m.npmScope);
  direct.scoped.optionalDependencies=Object.fromEntries(m.targets.map(t=>[t.pkg,version]));
  validateAcceptedScoped(direct.scoped,directManifest);
  direct.alias.scoped_packages=direct.scoped.packages;
  delete direct.alias.dependencies;direct.alias.optionalDependencies=direct.scoped.optionalDependencies;
  validateAcceptedAlias(direct.alias,direct.scoped,direct.child,direct.jobs);
  const wrong=copy(direct.alias);wrong.alias.shasum='f'.repeat(40);
  assert.throws(()=>validateAcceptedAlias(wrong,direct.scoped,direct.child,direct.jobs));
  assert.throws(()=>validateAcceptedScoped({...direct.scoped,launcher:undefined},directManifest));
  assert.throws(()=>validateScoped({...direct.scoped,schema:1,kind:'scoped-ready'},directManifest));
  assert.throws(()=>validateScoped(f.scoped,m));
  for(const mutate of [r=>r.acceptances.pop(),r=>r.acceptances.push(r.acceptances[0]),r=>r.acceptances[0].version='0.0.0',r=>r.acceptances[0].signal='SIGTERM',r=>r.acceptances[0].exit_code=1,r=>r.acceptances[0].evidence='submitted',r=>r.install={},r=>r.assets.pop(),r=>r.binaries[0].sha256='f'.repeat(64)]){
    const r=copy(f.scoped);mutate(r);assert.throws(()=>validateAcceptedScoped(r,m));
  }
});

test('alias ACK binds local dependency, exact source attempt and completed publisher job, without waiting for whole child workflow',()=>{
  const f=fixture();f.child.status='in_progress';f.child.conclusion=null;
  validateAcceptedAlias(f.alias,f.scoped,f.child,f.jobs);
  validateAcceptedAlias(f.alias,f.scoped,{...f.child,event:'workflow_dispatch'},f.jobs);
  assert.throws(()=>validateAcceptedAlias(f.alias,f.scoped,{...f.child,event:'pull_request'},f.jobs));
  for(const mutate of [r=>r.source.run_attempt='2',r=>r.dependencies['@rsrsai/cli']='0.0.0',r=>r.alias.integrity='bad',r=>r.publisher.run_id=201,r=>r.install={},r=>r.acceptance.exit_code=1]){
    const r=copy(f.alias);mutate(r);assert.throws(()=>validateAcceptedAlias(r,f.scoped,f.child,f.jobs));
  }
  for(const conclusion of ['failure','cancelled','skipped',null])assert.throws(()=>validateAcceptedAlias(f.alias,f.scoped,f.child,[{...f.jobs[0],conclusion}]));
  assert.throws(()=>validateAcceptedAlias(f.alias,f.scoped,f.child,[{...f.jobs[0],status:'in_progress'}]));
});

test('completed exact attempts are allowed only in the read-only verifier, never the write guard',()=>{
  const f=fixture();assertCompletedSource(f.run,source);assert.throws(()=>assertSourceRun(f.run,source));
  assert.throws(()=>acceptedScopedOutput(f.scoped,f.run,1));
  f.run.status='in_progress';assertSourceRun(f.run,source);assert.throws(()=>assertCompletedSource(f.run,source));
  const output=acceptedScopedOutput(f.scoped,f.run,1);assert.equal(output.protocol,'2');assert.equal(output.artifact,'scoped-accepted-100-1');
  for(const mutate of [r=>r.run_attempt=2,r=>r.id=101,r=>r.conclusion=null,r=>r.path='.github/workflows/ci.yml',r=>r.head_repository.full_name='other/repo']){
    const r=copy(fixture().run);mutate(r);assert.throws(()=>assertCompletedSource(r,source));
  }
});

test('accepted ACKs cannot replace public digest and isolated installation proof',()=>{
  const f=fixture();validateVerified(f.verified,f.scoped,f.alias);
  assert.throws(()=>validateVerified(f.alias,f.scoped,f.alias));
  for(const mutate of [r=>r.packages.pop(),r=>r.source.sha='f'.repeat(40),r=>r.alias_publisher.run_attempt=2,r=>r.install.binary_sha256='f'.repeat(64),r=>r.install.version='0.0.0',r=>r.verified_at=null]){
    const r=copy(f.verified);mutate(r);assert.throws(()=>validateVerified(r,f.scoped,f.alias));
  }
});

test('ARM64 installation proof requires both native libc routes, exact versions and binary hashes',()=>{
  const f=fixture(),receipt={...copy(f.verified),kind:'publication-arm64-verified',installs:['linux-arm64-gnu','linux-arm64'].map(platform=>({platform,version,binary_sha256:hash}))};
  delete receipt.install;validateArmVerified(receipt,f.scoped,f.alias);
  for(const mutate of [r=>r.installs.pop(),r=>r.installs[0].platform='linux-x64-gnu',r=>r.installs[0].binary_sha256='f'.repeat(64),r=>r.installs[0].version='0.0.0',r=>r.source.sha='f'.repeat(40),r=>r.alias_publisher.run_attempt=2]){
    const bad=copy(receipt);mutate(bad);assert.throws(()=>validateArmVerified(bad,f.scoped,f.alias));
  }
});

test('GNU installation proof alone cannot authorize cleanup of a six-platform release',async()=>{
  const f=cleanupFixture(),at=Date.parse('2026-10-27T02:00:00Z');f.artifacts.delete(16);
  assert.equal((await planCleanup(f.io,100,m,at)).skip,'no-native-arm64-public-install-proof');assert.deepEqual(f.deleted,[]);
});

test('an interrupted prior submission requires read-only content reconciliation and is never replayed',async()=>{
  const p=identity('rsrs-cli'),journal={schema:2,submissions:[{state:'unknown',package:p}]};
  let reads=0;const recovered=await reconcilePriorSubmissions(journal,[p],async items=>{reads++;assert.deepEqual(items,[p]);});assert.equal(reads,1);assert.equal(recovered[0].evidence,'verified-public-bytes');
  await assert.rejects(reconcilePriorSubmissions(journal,[p],async()=>{throw Error('not publicly confirmed; no retry');}),/no retry/);
  await assert.rejects(reconcilePriorSubmissions(journal,[{...p,shasum:'e'.repeat(40)}]),/content changed/);
  journal.submissions[0]={state:'accepted',package:proof(p)};const existing=await reconcilePriorSubmissions(journal,[p],async()=>assert.fail('accepted submission does not need propagation'));assert.deepEqual(existing,[proof(p)]);
  validateAcceptance(proof(p),p);
});

function cleanupFixture(){
  const f=fixture(),last='2026-10-27T00:20:00Z';
  const verifier={...f.run,id:400,path:'.github/workflows/verify-publication.yml',event:'workflow_run',updated_at:last};
  const a=(id,name,run)=>({id,name,expired:false,digest:'sha256:'+hash,size_in_bytes:100,created_at:'2026-10-27T00:10:00Z',workflow_run:{id:run.id,head_sha:run.head_sha}});
  f.verifiers=[verifier];f.consumers=[f.child];f.deleted=[];
  f.scoped.validation_inventory=regressionContract(m);
  f.armVerified={...copy(f.verified),kind:'publication-arm64-verified',installs:['linux-arm64-gnu','linux-arm64'].map(platform=>({platform,version,binary_sha256:hash}))};delete f.armVerified.install;
  f.artifacts=new Map([[10,a(10,'cli-release-'+m.targets[0].triple,f.run)],[11,a(11,'scoped-accepted-100-1',f.run)],[12,a(12,'alias-accepted-100-1-200-1',f.child)],[13,a(13,'publication-verified-100-1-400-1',verifier)]]);
  f.artifacts.set(16,a(16,'publication-arm64-verified-100-1-400-1',verifier));
  const job=name=>({name,status:'completed',conclusion:'success',completed_at:f.run.updated_at});
  f.parentJobs=[...m.targets.map(t=>job(`native-regression / Native (${t.triple})`)),...m.targets.filter(t=>t.triple!=='x86_64-unknown-linux-gnu').map(t=>job(`cloud-sweep (${t.triple})`)),...m.targets.filter(t=>t.triple.includes('windows')||t.triple==='aarch64-apple-darwin').flatMap(t=>[job(`Native migration (${t.triple})`),job(`Migration gate (${t.triple})`)]),job('api-smoke'),job('publish')];
  f.io={repository:source.repository,run:async()=>copy(f.run),artifacts:async id=>copy([...f.artifacts.values()].filter(a=>a.workflow_run.id===id)),
    receipt:async a=>copy(a.id===11?f.scoped:a.id===12?f.alias:a.id===16?f.armVerified:f.verified),jobs:async id=>copy(id===100?f.parentJobs:id===200?f.jobs:[job('verify-publication'),job('verify-publication-arm64')]),
    release:async()=>({id:300,draft:false,published_at:f.run.updated_at,tag_name:'v'+version,target_commitish:sha,prerelease:true,assets:f.scoped.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256}))}),tag:async()=>({type:'commit',sha}),
    consumers:async()=>copy(f.consumers),verifiers:async()=>copy(f.verifiers),otherReaders:async()=>[],artifact:async id=>copy(f.artifacts.get(id)??null),deleteArtifact:async id=>{f.deleted.push(id);f.artifacts.delete(id);}};
  return f;
}

function preparedCleanupFixture(){
  const f=cleanupFixture(),previous=n=>`2026-10-26T23:${n}:00Z`;
  const original={repository:source.repository,workflow:source.workflow,run_id:'50',run_attempt:1,sha,version};
  const manifest={...m,cliVersion:version},identity={hashes:{'Cargo.lock':hash},sdk:[]};
  const job=name=>({name,status:'completed',conclusion:'success',started_at:previous('20'),completed_at:previous('30')});
  const migration=m.targets.filter(t=>t.triple.includes('windows')||t.triple==='aarch64-apple-darwin');
  const originalJobs=[...m.targets.map(t=>job(`validate / Release (${t.triple})`)),job('validate / npm-dry-run'),
    ...m.targets.map(t=>job(`native-regression / Native (${t.triple})`)),...m.targets.filter(t=>t.triple!=='x86_64-unknown-linux-gnu').map(t=>job(`cloud-sweep (runner, ${t.triple})`)),
    ...migration.map(t=>job(`Native migration (${t.triple})`)),...migration.map(t=>job(`Migration gate (${t.triple})`)),job('api-smoke')];
  const originalRun={...copy(f.run),id:50,run_attempt:1,head_sha:sha,head_branch:'main',status:'in_progress',updated_at:previous('40'),created_at:previous('10')};
  const ci={...originalRun,id:60,path:'.github/workflows/ci.yml',event:'push',status:'completed',conclusion:'success',run_started_at:previous('10'),updated_at:previous('25')};
  const artifacts=[...m.targets.map(t=>`cli-release-${t.triple}`),'npm-release-validation','npm-release-packages'].map((name,i)=>({id:50+i,name,size_in_bytes:100,digest:'sha256:'+hash,expired:false,workflow_run:{id:50,head_sha:sha}}));
  const assets=f.scoped.assets.map(a=>({file:a.name,size:a.size,sha256:a.sha256}));
  const packs=f.scoped.packages.map((p,i)=>({name:p.name,version,file:`pack-${i}.tgz`,size:10,sha256:hash}));
  f.history={source:original,identity,manifest,run:originalRun,jobs:originalJobs,ci,artifacts};
  originalJobs.push({id:900,name:'preparation-receipt',status:'in_progress',started_at:previous('30')});
  const proof=createPreparation({...f.history,assets,packs,now:previous('35')});
  Object.assign(originalJobs.at(-1),{status:'completed',conclusion:'success',completed_at:previous('36')});
  f.history.run={...originalRun,status:'completed',conclusion:'success'};
  const origin=preparationLink(proof,{id:80,name:'release-prepared-50-1',size_in_bytes:100,digest:'sha256:'+hash,expired:false,workflow_run:{id:50,head_sha:sha}});
  f.run.head_branch='main';
  const owner={repository:source.repository,workflow:source.workflow,run_id:'100',run_attempt:1,sha,version,workflow_head_sha:f.run.head_sha};
  f.imported={schema:1,kind:'prepared-import',state:'verified-copy',owner:{...owner,import_job_id:'1000'},origin:copy(origin),preparation:proof,
    validated_assets:copy(assets),validated_packs:copy(packs),imported_at:'2026-10-27T00:05:00Z'};
  f.intent={schema:1,kind:'prepared-consumer',state:'reading',owner,origin:copy(origin),created_at:'2026-10-27T00:00:30Z'};
  const artifact=(id,name)=>({id,name,expired:false,digest:'sha256:'+hash,size_in_bytes:100,created_at:'2026-10-27T00:06:00Z',workflow_run:{id:100,head_sha:f.run.head_sha}});
  f.artifacts.set(14,artifact(14,'prepared-import-100-1'));f.artifacts.set(15,{...artifact(15,'prepared-consumer-100-1'),created_at:'2026-10-27T00:00:31Z'});
  f.scoped.validation_origin=importedAnchor(f.imported,f.artifacts.get(14),f.run);
  f.scoped.validation_inventory=proof.validation.inventory;
  f.parentJobs=[{id:1000,name:'prepared-import',status:'completed',conclusion:'success',started_at:'2026-10-27T00:01:00Z',completed_at:'2026-10-27T00:06:00Z'},
    {name:'publish',status:'completed',conclusion:'success',completed_at:f.run.updated_at}];
  const read=f.io.receipt;f.io.receipt=async a=>a.id===14?copy(f.imported):a.id===15?copy(f.intent):read(a);
  f.io.preparedHistory=async()=>copy(f.history);
  return f;
}

test('prepared cleanup requires original full gates, current completed import and matching public bytes',async()=>{
  const at=Date.parse('2026-10-27T01:20:00Z'),f=preparedCleanupFixture();
  const plan=await planCleanup(f.io,100,m,at);assert.equal(plan.skip,undefined);
  assert(plan.prepared);assert(plan.artifacts.some(a=>a.id===14)&&plan.artifacts.some(a=>a.id===15));
  assert(!plan.artifacts.some(a=>a.workflow_run.id===50),'original preparation archives must never be deleted as current copies');
  await executeCleanup(f.io,plan,{apply:true,now:()=>at});assert(f.deleted.includes(14)&&f.deleted.includes(15));
  for(const mutate of [x=>x.history.jobs[0].conclusion='skipped',x=>x.history.jobs.at(-1).conclusion='failure',x=>delete x.io.preparedHistory,
    x=>x.imported.validated_packs.pop(),x=>x.intent.owner.sha='f'.repeat(40),x=>x.parentJobs[0].conclusion='failure']){
    const bad=preparedCleanupFixture();mutate(bad);await assert.rejects(planCleanup(bad.io,100,m,at));assert.deepEqual(bad.deleted,[]);
  }
});
test('original source gate changes during cleanup stop before deleting any copied proof or payload',async()=>{
  const at=Date.parse('2026-10-27T01:20:00Z'),f=preparedCleanupFixture(),plan=await planCleanup(f.io,100,m,at);
  f.history.ci.run_attempt=2;await assert.rejects(executeCleanup(f.io,plan,{apply:true,now:()=>at}),/proof changed|stale/);assert.deepEqual(f.deleted,[]);
});

test('prepared cleanup rejects wrong origin, import, consumer, history and public bytes before selecting any deletion',async()=>{
  const at=Date.parse('2026-10-27T02:00:00Z');
  const cases=[
    ['scoped origin',f=>f.scoped.validation_origin.artifact.id='999',/origin changed/],
    ['original origin',f=>f.imported.origin.artifact.id='999',/origin changed/],
    ['import owner',f=>f.imported.owner.import_job_id='999',/import job/],
    ['consumer origin',f=>f.intent.origin.artifact.id='999',/registration differs/],
    ['consumer missing',f=>f.artifacts.delete(15),/proof missing/],
    ['consumer registered too late',f=>f.artifacts.get(15).created_at='2026-10-27T00:02:00Z',/register before import/],
    ['consumer registration time missing',f=>delete f.artifacts.get(15).created_at,/register before import/],
    ['history lock',f=>f.history.identity.hashes['Cargo.lock']='f'.repeat(64),/SDK, toolchain or layout differs/],
    ['history attempt',f=>f.history.run.run_attempt=2,/stale/],
    ['public asset',f=>f.scoped.assets[0].sha256='f'.repeat(64),/Public assets differ/],
  ];
  for(const [name,mutate,expected] of cases){
    const f=preparedCleanupFixture();mutate(f);
    await assert.rejects(planCleanup(f.io,100,m,at),expected,name);assert.deepEqual(f.deleted,[],name);
  }
});

test('prepared cleanup rechecks a changed public hash before the first copied artifact deletion',async()=>{
  const at=Date.parse('2026-10-27T02:00:00Z'),f=preparedCleanupFixture(),plan=await planCleanup(f.io,100,m,at);
  assert.equal(plan.skip,undefined);f.scoped.assets[0].sha256='f'.repeat(64);
  await assert.rejects(executeCleanup(f.io,plan,{apply:true,now:()=>at}),/Public release assets differ/);
  assert.deepEqual(f.deleted,[]);
});

test('cleanup waits for verified proof and the last background consumer/report plus an hour',async()=>{
  const f=cleanupFixture(),at=Date.parse('2026-10-27T01:20:00Z');
  f.artifacts.delete(13);assert.equal((await planCleanup(f.io,100,m,at)).skip,'no-completed-public-install-proof');assert.deepEqual(f.deleted,[]);
  const complete=cleanupFixture();assert.equal((await planCleanup(complete.io,100,m,at-1)).skip,'one-hour-after-consumers-not-reached');
  const plan=await planCleanup(complete.io,100,m,at);assert.equal(plan.skip,undefined);assert.deepEqual(plan.artifacts.map(a=>a.id),[10,12,13,16,11]);
  await executeCleanup(complete.io,plan,{apply:true,now:()=>at});assert.deepEqual(complete.deleted,[10,12,13,16,11]);
});

test('cleanup installation proof keeps runner audit time without changing the service grace boundary',async()=>{
  for(const clock of ['2026-10-26T23:11:00Z','2026-10-27T01:11:00Z']){
    const f=cleanupFixture();f.verified.verified_at=clock;
    const boundary=Date.parse('2026-10-27T01:20:00Z');
    assert.equal((await planCleanup(f.io,100,m,boundary-1000)).skip,'one-hour-after-consumers-not-reached');
    const plan=await planCleanup(f.io,100,m,boundary);
    assert.equal(plan.skip,undefined);
    assert.equal(plan.finished,Date.parse('2026-10-27T00:20:00Z'));
  }
});

test('active/new background consumers, failed verification and digest drift stop cleanup',async()=>{
  const at=Date.parse('2026-10-27T02:00:00Z');
  const active=cleanupFixture();active.verifiers[0].status='in_progress';assert.equal((await planCleanup(active.io,100,m,at)).skip,'public-verification-still-active');
  const failed=cleanupFixture();failed.verifiers[0].conclusion='failure';await assert.rejects(planCleanup(failed.io,100,m,at),/failed/);
  const bad=cleanupFixture();bad.verified.install.binary_sha256='f'.repeat(64);await assert.rejects(planCleanup(bad.io,100,m,at),/verification/);
  const late=cleanupFixture(),plan=await planCleanup(late.io,100,m,at);late.verifiers.push({...late.verifiers[0],id:401,status:'queued'});
  await assert.rejects(executeCleanup(late.io,plan,{apply:true,now:()=>at}),/fence changed/);assert.deepEqual(late.deleted,[]);
});

test('new background workflow is read-only, outside publication locks and behind Release completion',()=>{
  const root=new URL('../../',import.meta.url),text=p=>readFileSync(new URL(p,root),'utf8');
  const background=text('.github/workflows/verify-publication.yml'),parent=text('.github/workflows/release.yml').split('  dev6-publication-resume:')[0];
  assert.match(background,/workflow_dispatch:/);assert.match(background,/workflow_run:\s+workflows: \[Release\]\s+types: \[completed\]/);
  assert.doesNotMatch(background,/id-token:|contents: write|actions: write|concurrency:|npm publish/);
  assert.match(background,/persist-credentials: false/);assert.match(background,/verify-accepted/);
  assert.match(parent,/--publish --accepted-only --verified-packs npm\/publication-packages --tag/);assert.match(parent,/await-alias-accepted/);assert.match(parent,/finalize-accepted/);
  assert.doesNotMatch(parent,/release-publication.mjs (?:scoped-ready|await-alias\s|finalize\s)/);
  const code=text('npm/scripts/publication-acceptance.mjs');
  const writer=code.slice(code.indexOf('async function publishAliasAccepted'),code.indexOf('export async function findAcceptedAlias'));
  assert.doesNotMatch(writer,/publicInstall\(|verifyPackages\(scoped.packages|result.metadata/);
  assert.match(writer,/assertActive\(source\); \/\/ No public propagation/);
  assert.match(code,/actions\/runs\/\$\{runId\}\/attempts\/\$\{attempt\}/);
});

test('real coordinator processes finish acceptance while child workflow runs, and stale attempts never edit Release',t=>{
  const root=mkdtempSync(path.join(tmpdir(),'rsrs-accepted-process-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
  mkdirSync(path.join(root,'bin'));mkdirSync(path.join(root,'npm'));
  cpSync(fileURLToPath(new URL('.',import.meta.url)),path.join(root,'npm/scripts'),{recursive:true});
  writeFileSync(path.join(root,'npm/artifact-manifest.json'),JSON.stringify(m));
  const f=fixture();f.run.status='in_progress';f.run.conclusion=null;f.child.status='in_progress';f.child.conclusion=null;
  const release={id:300,draft:true,prerelease:true,tag_name:'v'+version,target_commitish:sha,assets:f.scoped.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256}))};
  const successful=name=>({name,status:'completed',conclusion:'success',completed_at:'2026-10-27T00:04:00Z'});
  const migration=m.targets.filter(t=>t.triple.includes('windows')||t.triple==='aarch64-apple-darwin');
  f.full_jobs=[...m.targets.map(t=>successful(`native-regression / Native (${t.triple})`)),
    ...m.targets.filter(t=>t.triple!=='x86_64-unknown-linux-gnu').map(t=>successful(`cloud-sweep (runner, ${t.triple})`)),
    ...migration.map(t=>successful(`Native migration (${t.triple})`)),...migration.map(t=>successful(`Migration gate (${t.triple})`)),successful('api-smoke')];
  f.full_jobs[0].completed_at='2026-10-27T00:08:00Z'; // Later than fast-manual readiness at 00:05.
  const save=()=>writeFileSync(path.join(root,'fixture.json'),JSON.stringify({...f,release}));save();
  writeFileSync(path.join(root,'scoped-accepted.json'),JSON.stringify(f.scoped));
  const gh=path.join(root,'bin/gh');
  writeFileSync(gh,`#!${process.execPath}
const fs=require('fs'),path=require('path'),args=process.argv.slice(2),f=JSON.parse(fs.readFileSync('fixture.json'));
const pub=()=>fs.existsSync('edited-release');
function out(x){process.stdout.write(JSON.stringify(x));}
if(args[0]==='api'){
 const endpoint=args.at(-1),paginated=args.includes('--slurp');
 let value;
 if(endpoint.endsWith('/actions/runs/100'))value=f.run;
 else if(endpoint.includes('/actions/runs/100/attempts/1/jobs?'))value={jobs:[...f.full_jobs,{name:'publication-ready',status:'completed',conclusion:'success',completed_at:'2026-10-27T00:05:00Z'}]};
 else if(endpoint.endsWith('/commits/'+f.scoped.source.sha))value={sha:f.scoped.source.sha,commit:{committer:{date:'2026-10-26T23:59:00Z'}}};
 else if(endpoint.endsWith('/actions/runs/200/attempts/1'))value=f.child;
 else if(endpoint.includes('/workflows/npm-alias.yml/runs?'))value={workflow_runs:[f.child]};
 else if(endpoint.includes('/actions/runs/200/attempts/1/jobs?'))value={jobs:f.jobs};
 else if(endpoint.includes('/actions/runs/200/artifacts?'))value={artifacts:[{name:'alias-accepted-100-1-200-1',expired:false,workflow_run:{id:200}}]};
 else if(endpoint.endsWith('/releases/300'))value=pub()?{...f.release,draft:false,published_at:'2026-10-27T00:10:00Z'}:f.release;
 else if(endpoint.includes('/git/ref/tags/'))value={object:{type:'commit',sha:f.scoped.source.sha}};
 else throw Error('Unpermitted fake API '+endpoint);
 out(paginated?[value]:value);
}else if(args[0]==='run'&&args[1]==='download'){
 const dir=args[args.indexOf('--dir')+1];fs.writeFileSync(path.join(dir,'alias-accepted.json'),JSON.stringify(f.alias));
}else if(args[0]==='release'&&args[1]==='edit'){
 if(pub())throw Error('Release edit must never replay');
 fs.writeFileSync('edited-release',JSON.stringify(args));
}else throw Error('Unpermitted fake command '+args.join(' '));
`);chmodSync(gh,0o755);
  const bootstrap=path.join(root,'run.mjs');writeFileSync(bootstrap,`globalThis.fetch=()=>{throw Error('Accepted barrier must not wait on public registry');};
const {main}=await import('./npm/scripts/release-publication.mjs');
main(process.argv[2]).catch(e=>{console.error(e.message);process.exitCode=1;});`);
  const env={...process.env,PATH:path.join(root,'bin')+path.delimiter+process.env.PATH,GITHUB_REPOSITORY:source.repository,GITHUB_RUN_ID:'100',GITHUB_RUN_ATTEMPT:'1',FULL_REGRESSION_REQUIRED:'true'};
  const run=action=>spawnSync(process.execPath,[bootstrap,action],{cwd:root,env,encoding:'utf8',timeout:15000});
  const awaited=run('await-alias-accepted');assert.equal(awaited.error,undefined);assert.equal(awaited.status,0,awaited.stderr);
  const complete=JSON.parse(readFileSync(path.join(root,'publication-accepted.json')));assert.equal(complete.state,'accepted');assert.equal(complete.alias_run,200);assert.equal(complete.alias_receipt.install,undefined);
  f.run.status='completed';save();const stale=run('finalize-accepted');assert.notEqual(stale.status,0);assert.match(stale.stderr,/stale|inactive/);assert.equal(existsSync(path.join(root,'edited-release')),false);
  f.run.status='in_progress';const missing=f.full_jobs.pop();save();const incomplete=run('finalize-accepted');assert.notEqual(incomplete.status,0);assert.match(incomplete.stderr,/Required full regression proof missing before publication: required regressions still pending/);assert.equal(existsSync(path.join(root,'edited-release')),false);
  f.full_jobs.push(missing);env.FULL_REGRESSION_REQUIRED='false';save();const finalized=run('finalize-accepted');assert.equal(finalized.status,0,finalized.stderr);assert.equal(existsSync(path.join(root,'edited-release')),true);
  const summary=JSON.parse(readFileSync(path.join(root,'publication-accepted.json')));assert.equal(summary.public_verification,'pending');assert.equal(summary.trigger_to_accepted_seconds,600);assert.equal(summary.source_to_complete_validation_seconds,null);assert.equal(summary.full_validation_completed_at,'2026-10-27T00:08:00.000Z');assert.equal(summary.ready_to_accepted_seconds,300);
});

test('scoped and alias preflight failures retain empty journals without inventing a submission',t=>{
  const root=mkdtempSync(path.join(tmpdir(),'rsrs-preflight-journal-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
  const env={...process.env,GITHUB_REPOSITORY:source.repository,GITHUB_RUN_ID:'200',GITHUB_RUN_ATTEMPT:'1'};
  const pack=fileURLToPath(new URL('./pack.mjs',import.meta.url));
  const failed=spawnSync(process.execPath,[pack,'--repo',root,'--publish','--accepted-only'],{cwd:root,env,encoding:'utf8',timeout:10000});
  assert.notEqual(failed.status,0);assert.equal(failed.error,undefined);
  const scoped=JSON.parse(readFileSync(path.join(root,'scoped-submissions.json')));assert.deepEqual(scoped.submissions,[]);assert.deepEqual(scoped.packages,[]);assert.equal(scoped.run_id,'200');
  mkdirSync(path.join(root,'npm'));writeFileSync(path.join(root,'npm/artifact-manifest.json'),JSON.stringify(m));
  const f=fixture();f.scoped.acceptances.pop();writeFileSync(path.join(root,'scoped-accepted.json'),JSON.stringify(f.scoped));
  const helper=fileURLToPath(new URL('./release-publication.mjs',import.meta.url));
  const alias=spawnSync(process.execPath,[helper,'publish-alias-accepted'],{cwd:root,env,encoding:'utf8',timeout:10000});
  assert.notEqual(alias.status,0);assert.match(alias.stderr,/acceptance inventory/);
  const journal=JSON.parse(readFileSync(path.join(root,'alias-submissions.json')));assert.deepEqual(journal.submissions,[]);assert.deepEqual(journal.source,source);
});


test('normal publication requires protocol 2 before writing any scoped package',()=>{
  const helper=fileURLToPath(new URL('./release-publication.mjs',import.meta.url));
  const supported=spawnSync(process.execPath,[helper,'protocol'],{encoding:'utf8',timeout:10000});
  assert.equal(supported.error,undefined);assert.equal(supported.status,0);assert.equal(supported.stdout.trim(),'2');
  const workflow=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
  assert(workflow.includes('test "$(node npm/scripts/release-publication.mjs protocol)" = 2'));
  assert(workflow.indexOf('release-publication.mjs protocol')<workflow.indexOf('--publish --accepted-only'));
});


test('post-publication workflow failure does not suppress read-only verification or authorize cleanup',async()=>{
  const f=fixture();
  for(const conclusion of ['failure','cancelled','timed_out']){
    f.run.conclusion=conclusion;assertCompletedSource(f.run,source);assert.throws(()=>assertSourceRun(f.run,source));
  }
  const c=cleanupFixture();c.run.conclusion='failure';
  assert.equal((await planCleanup(c.io,100,m,Date.parse('2026-10-27T02:00:00Z'))).skip,'source-not-successfully-complete');
  assert.deepEqual(c.deleted,[]);
});

test('critical acceptance, alias and install proof cannot be relabelled as legacy full',()=>{
  const f=fixture();f.scoped.validation_profile='critical';f.scoped.validation_inventory=regressionContract(m,'critical');f.alias.validation_profile='critical';f.verified.validation_profile='critical';
  validateAcceptedScoped(f.scoped,m);validateAcceptedAlias(f.alias,f.scoped,f.child,f.jobs);validateVerified(f.verified,f.scoped,f.alias);
  for(const profile of [undefined,'full','other']){
    const scoped=copy(f.scoped);if(profile===undefined)delete scoped.validation_profile;else scoped.validation_profile=profile;assert.throws(()=>validateAcceptedScoped(scoped,m));
    const alias=copy(f.alias);if(profile===undefined)delete alias.validation_profile;else alias.validation_profile=profile;assert.throws(()=>validateAcceptedAlias(alias,f.scoped,f.child,f.jobs));
    const verified=copy(f.verified);if(profile===undefined)delete verified.validation_profile;else verified.validation_profile=profile;assert.throws(()=>validateVerified(verified,f.scoped,f.alias));
  }
  const legacy=fixture();validateAcceptedScoped(legacy.scoped,m);validateAcceptedAlias(legacy.alias,legacy.scoped,legacy.child,legacy.jobs);validateVerified(legacy.verified,legacy.scoped,legacy.alias);
});

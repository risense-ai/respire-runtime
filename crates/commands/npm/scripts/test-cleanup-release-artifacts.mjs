import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {regressionContract} from './release-regression-contract.mjs';
import {CLEANUP_POLICY,REPOSITORY,planCleanup,executeCleanup,allowedSourceArtifact,requireRegressions,githubAdapter} from './cleanup-release-artifacts.mjs';

const manifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url))); manifest.npmScope = '@rsrsai/cli'; // Historical receipt layout.
manifest.targets=manifest.targets.filter(t=>!t.triple.startsWith('aarch64-unknown-linux-')&&t.triple!=='aarch64-pc-windows-msvc'&&t.triple!=='x86_64-apple-darwin'); // frozen historical protocol-1 inventory
const sha='b'.repeat(40),digest='a'.repeat(64),zipDigest=`sha256:${'d'.repeat(64)}`;
const integrity='sha512-'+createHash('sha512').update('synthetic package').digest('base64');
const at='2026-10-25T00:20:00Z',now=Date.parse('2026-10-25T02:00:00Z');
const clone=structuredClone;
function fixture(){
  const source={repository:REPOSITORY,workflow:'.github/workflows/release.yml',run_id:'100',run_attempt:'1',sha,version:'1.2.3-dev.4',channel:'dev',release_id:300};
  const packages=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map(name=>({name,version:source.version,integrity,shasum:'e'.repeat(40)}));
  const assets=manifest.targets.flatMap(t=>[`cli-build-${t.triple}.json`,`rsrs-${t.triple}-runtime.tar.gz`,`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`]).map(name=>({name,size:10,sha256:digest}));
  const binaries=manifest.targets.map(t=>({package:t.pkg,target:t.triple,file:`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,sha256:digest}));
  const scoped={schema:1,kind:'scoped-ready',cleanup_policy:clone(CLEANUP_POLICY),source,packages,assets,binaries};
  const run={id:100,run_attempt:1,path:source.workflow,event:'workflow_dispatch',head_repository:{full_name:REPOSITORY},head_sha:'c'.repeat(40),created_at:'2026-10-25T00:00:00Z',updated_at:at,status:'completed',conclusion:'success'};
  const consumer={...clone(run),id:200,path:'.github/workflows/npm-alias.yml',event:'workflow_run',updated_at:'2026-10-25T00:18:00Z'};
  const release={id:300,tag_name:`v${source.version}`,target_commitish:sha,draft:false,prerelease:true,published_at:at,assets:assets.map(a=>({name:a.name,size:a.size,state:'uploaded',digest:`sha256:${a.sha256}`}))};
  const alias={schema:1,kind:'alias-ready',source:clone(source),scoped_packages:clone(packages),alias:{name:'rsrs-cli',version:source.version,integrity,shasum:'f'.repeat(40)},publisher:{workflow:consumer.path,run_id:200,run_attempt:1},install:{platform:'linux-x64-gnu',version:source.version,binary_sha256:digest}};
  const job=name=>({name,status:'completed',conclusion:'success',completed_at:at});
  const jobs=[...manifest.targets.map(t=>job(`native-regression / Native (${t.triple})`)),...manifest.targets.filter(t=>t.triple!=='x86_64-unknown-linux-gnu').map(t=>job(`cloud-sweep (${t.triple})`)),job('api-smoke'),job('publish'),{...job('unused-repair'),conclusion:'skipped',completed_at:null}];
  const artifact=(id,name,owner)=>({id,name,size_in_bytes:100,digest:zipDigest,expired:false,created_at:'2026-10-25T00:10:00Z',workflow_run:{id:owner.id,head_sha:owner.head_sha}});
  const artifacts=new Map([[10,artifact(10,'cli-release-x86_64-unknown-linux-gnu',run)],[11,artifact(11,'scoped-ready-100-1',run)],[12,artifact(12,'alias-ready-100-1-200-1',consumer)],[13,artifact(13,'unrelated-ci-report',run)]]);
  const state={run,consumer,release,scoped,alias,jobs,artifacts,deleted:[],tag:{type:'commit',sha},consumers:[consumer],readers:[]};
  state.io={repository:REPOSITORY,run:async()=>clone(state.run),artifacts:async id=>clone([...artifacts.values()].filter(a=>a.workflow_run.id===id)),receipt:async a=>clone(a.id===11?state.scoped:state.alias),jobs:async id=>clone(id===100?state.jobs:[job('publish-integrated')]),release:async()=>clone(state.release),tag:async()=>clone(state.tag),consumers:async()=>clone(state.consumers),otherReaders:async()=>clone(state.readers),artifact:async id=>clone(artifacts.get(id)??null),deleteArtifact:async id=>{state.deleted.push(id);artifacts.delete(id);}};
  return state;
}

test('completed public release, all eight regressions and finished alias permit only allowlisted artifacts after grace',async()=>{
  const f=fixture(),p=await planCleanup(f.io,100,manifest,now);
  assert.equal(p.skip,undefined);assert.deepEqual(p.artifacts.map(a=>a.id),[10,12,11]);assert.deepEqual(p.preserved,[{id:13,name:'unrelated-ci-report'}]);
  assert.notEqual(f.run.head_sha,f.scoped.source.sha,'dispatch workflow head may differ from selected source');
  const audit=[];assert.deepEqual(await executeCleanup(f.io,p,{now:()=>now,audit:x=>audit.push(x)}),[]);assert.deepEqual(f.deleted,[]);assert.equal(audit.filter(a=>a.action==='would-delete').length,3);
  assert.deepEqual(await executeCleanup(f.io,p,{apply:true,now:()=>now}),[10,12,11]);assert( f.artifacts.has(13));
});
test('cleanup grace uses service time at the exact hour despite runner clock skew',async t=>{
  for(const offset of [-3600_000,3600_000]){
    t.mock.method(Date,'now',()=>now+offset);
    const f=fixture(),eligible=Date.parse(at)+3600_000;
    f.io.now=()=>eligible-1000;
    assert.equal((await planCleanup(f.io,100,manifest)).skip,'one-hour-after-consumers-not-reached');
    const plan=await planCleanup(f.io,100,manifest,eligible);
    await assert.rejects(executeCleanup(f.io,plan,{apply:true}),/fence changed/);
    assert.deepEqual(f.deleted,[]);
    f.io.now=()=>eligible;
    assert.deepEqual(await executeCleanup(f.io,plan,{apply:true}),[10,12,11]);
    t.mock.restoreAll();
  }
});

test('cleanup service clock requires one valid GitHub Date header',()=>{
  const io=githubAdapter(REPOSITORY,{transport:args=>{
    assert.deepEqual(args,['api','--include','--method','HEAD',`repos/${REPOSITORY}`]);
    return 'HTTP/2.0 200 OK\r\nDate: Sun, 25 Oct 2026 02:00:00 GMT\r\n';
  }});
  assert.equal(io.now(),now);
  for(const headers of ['', 'Date: invalid\r\n', 'Date: Sun, 25 Oct 2026 02:00:00 GMT\r\nDate: Sun, 25 Oct 2026 02:00:00 GMT\r\n']){
    assert.throws(()=>githubAdapter(REPOSITORY,{transport:()=>headers}).now());
  }
});

test('historical artifacts never opt into new automatic policy retroactively',async()=>{
  for(const policy of [undefined,{schema:1,after_consumers_seconds:3599},{...CLEANUP_POLICY,extra:true}]){
    const f=fixture();f.scoped.cleanup_policy=policy;assert.equal((await planCleanup(f.io,100,manifest,now)).skip,'historical-release-not-opted-in');assert.deepEqual(f.deleted,[]);
  }
});
test('child success cannot erase alias-ready while parent awaitAlias still runs',async()=>{
  const f=fixture();f.run.status='in_progress';assert.equal(f.consumer.status,'completed');assert.equal((await planCleanup(f.io,100,manifest,now)).skip,'source-not-successfully-complete');assert.deepEqual(f.deleted,[]);
});
test('active, queued, waiting, requested or pending consumers block even a completed public parent',async()=>{
  for(const status of ['in_progress','queued','waiting','requested','pending']){const f=fixture();f.consumer.status=status;assert.equal((await planCleanup(f.io,100,manifest,now)).skip,'alias-consumer-still-active');}
});
test('one hour is measured after latest consumer, including later duplicate/manual publishers',async()=>{
  const f=fixture();f.consumers.push({...clone(f.consumer),id:201,event:'workflow_dispatch',updated_at:'2026-10-25T01:30:00Z'});
  assert.equal((await planCleanup(f.io,100,manifest,now)).skip,'one-hour-after-consumers-not-reached');
  const p=await planCleanup(f.io,100,manifest,Date.parse('2026-10-25T02:30:00Z'));assert.equal(p.skip,undefined);
});
test('failed/skipped/missing or duplicate regression lanes never authorize deletion',async()=>{
  for(const mutate of [f=>f.jobs[0].conclusion='failure',f=>f.jobs[0].conclusion='skipped',f=>f.jobs.splice(f.jobs.findIndex(j=>j.name==='publish'),1),f=>f.jobs.splice(0,1),f=>f.jobs.push(clone(f.jobs[0])),f=>f.jobs[1].name=f.jobs[0].name,f=>f.jobs[0].name='native-regression / Native (foreign-target)']){
    const f=fixture();mutate(f);await assert.rejects(planCleanup(f.io,100,manifest,now),/regressions|publisher/);assert.deepEqual(f.deleted,[]);
  }
});
test('drafts, changed tags and public binary digest drift block cleanup',async()=>{
  for(const mutate of [f=>f.release.draft=true,f=>f.release.published_at=null,f=>f.tag.sha='f'.repeat(40),f=>f.release.assets[0].digest='sha256:'+'f'.repeat(64)]){const f=fixture();mutate(f);await assert.rejects(planCleanup(f.io,100,manifest,now),/public release|assets differ/);}
});
test('missing clean-install or wrongly bound alias receipts cannot substitute for real consumption proof',async()=>{
  for(const mutate of [f=>f.alias.install.binary_sha256='f'.repeat(64),f=>f.alias.source.run_attempt='2',f=>f.alias.publisher.run_id=999,f=>f.consumer.conclusion='failure']){const f=fixture();mutate(f);await assert.rejects(planCleanup(f.io,100,manifest,now),/publication|source|binding|alias|receipt/i);}
  const f=fixture();f.artifacts.delete(12);assert.equal((await planCleanup(f.io,100,manifest,now)).skip,'no-completed-alias-install-proof');
});
test('source retry or new consumer between inventory and deletion halts before any write',async()=>{
  for(const mutate of [f=>f.run.run_attempt=2,f=>f.run.status='in_progress',f=>f.consumers.push({...clone(f.consumer),id:201,status:'queued'}),f=>f.consumer.updated_at='2026-10-25T01:59:00Z']){const f=fixture(),p=await planCleanup(f.io,100,manifest,now);mutate(f);await assert.rejects(executeCleanup(f.io,p,{apply:true,now:()=>now}),/fence changed/);assert.deepEqual(f.deleted,[]);}
});
test('a new parent attempt mid-batch stops before deleting child or parent receipts',async()=>{
  const f=fixture(),p=await planCleanup(f.io,100,manifest,now),remove=f.io.deleteArtifact;
  f.io.deleteArtifact=async id=>{await remove(id);f.run.run_attempt=2;};
  await assert.rejects(executeCleanup(f.io,p,{apply:true,now:()=>now}),/fence changed/);assert.deepEqual(f.deleted,[10]);assert(f.artifacts.has(11)&&f.artifacts.has(12));
});
test('ambiguous DELETE stops once, while already absent artifacts are not deleted again',async()=>{
  const f=fixture(),p=await planCleanup(f.io,100,manifest,now);let calls=0;
  f.io.deleteArtifact=async()=>{calls++;throw Error('uncertain transport failure');};await assert.rejects(executeCleanup(f.io,p,{apply:true,now:()=>now}),/uncertain/);assert.equal(calls,1);
  const g=fixture(),q=await planCleanup(g.io,100,manifest,now);g.artifacts.delete(10);await executeCleanup(g.io,q,{apply:true,now:()=>now});assert.deepEqual(g.deleted,[12,11]);
});
test('same-name foreign artifacts, changed digests and foreign repository are rejected',async()=>{
  const f=fixture();f.io.repository='foreign/repo';await assert.rejects(planCleanup(f.io,100,manifest,now),/scope/);
  const g=fixture(),p=await planCleanup(g.io,100,manifest,now);g.artifacts.get(10).digest='sha256:'+'f'.repeat(64);await assert.rejects(executeCleanup(g.io,p,{apply:true,now:()=>now}),/Artifact changed/);
  const h=fixture();h.artifacts.get(11).workflow_run.head_sha='f'.repeat(40);await assert.rejects(planCleanup(h.io,100,manifest,now),/identity/);
});
test('unknown names, SDK bundles and stale source-attempt receipts are never selected',()=>{
  for(const name of ['sdk-v1.0.2-dev.11','npm-release-packages-other','scoped-ready-100-2','cli-release-arbitrary','coverage','alias-ready-100-1-200-1'])assert.equal(allowedSourceArtifact(name,fixture().scoped.source,manifest.targets.map(t=>t.triple)),false,name);
});
test('workflow uses reviewed default branch, explicit minimal write permission, alias lock and dry-run default',()=>{
  const yaml=readFileSync(new URL('../../.github/workflows/cleanup-release-artifacts.yml',import.meta.url),'utf8');
  assert(yaml.includes('actions: write'));assert(!yaml.includes('contents: write'));assert(yaml.includes('ref: ${{ github.event.repository.default_branch }}'));assert(yaml.includes('group: npm-rsrs-cli-publication'));assert(yaml.includes('default: true'));assert(!yaml.includes('workflow_run:'));
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').split('  workflow_dispatch:')[0];assert.match(release,/tags: \['v\*'\]/);assert.doesNotMatch(release,/branches:|paths-ignore:/);
});

function receiptZip(entries){
  return execFileSync('python3',['-c',`import sys,json,io,zipfile
entries=json.load(sys.stdin); data=io.BytesIO()
with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as z:
 for name,text in entries: z.writestr(name,text)
sys.stdout.buffer.write(data.getvalue())`],{input:JSON.stringify(entries)});
}
test('real ZIP receipt reader verifies digest and exact single JSON member without extracting code',()=>{
  const bytes=receiptZip([['scoped-ready.json','{"safe":true}']]);let calls=0;
  const io=githubAdapter(REPOSITORY,{transport:(args)=>{calls++;assert.deepEqual(args,['api',`repos/${REPOSITORY}/actions/artifacts/11/zip`]);return bytes;}});
  const a={id:11,size_in_bytes:bytes.length,digest:'sha256:'+createHash('sha256').update(bytes).digest('hex')};
  assert.deepEqual(io.receipt(a,'scoped-ready.json'),{safe:true});assert.equal(calls,1);
  assert.throws(()=>io.receipt({...a,digest:zipDigest},'scoped-ready.json'),/digest mismatch/);
  const previous=calls;assert.throws(()=>io.receipt({...a,size_in_bytes:128*1024+1},'scoped-ready.json'),/too large/);assert.equal(calls,previous);
});
test('malicious ZIP paths and extra files are rejected before any data is executed or extracted',()=>{
  for(const entries of [[['../scoped-ready.json','{}']],[['scoped-ready.json','{}'],['run.sh','echo unsafe']],[['scoped-ready.json','{}'],['scoped-ready.json','{}']]]){
    const bytes=receiptZip(entries),io=githubAdapter(REPOSITORY,{transport:()=>bytes});
    assert.throws(()=>io.receipt({id:11,size_in_bytes:bytes.length,digest:'sha256:'+createHash('sha256').update(bytes).digest('hex')},'scoped-ready.json'),/ZIP inventory/);
  }
});
test('a highly compressed oversized JSON receipt is stopped by the uncompressed output bound',()=>{
  const bytes=receiptZip([['scoped-ready.json',JSON.stringify({padding:'x'.repeat(2*1024*1024)})]]);
  assert(bytes.length<128*1024);const io=githubAdapter(REPOSITORY,{transport:()=>bytes});
  assert.throws(()=>io.receipt({id:11,size_in_bytes:bytes.length,digest:'sha256:'+createHash('sha256').update(bytes).digest('hex')},'scoped-ready.json'),e=>e.code==='ENOBUFS');
});
test('consumer enumeration begins at the exact parent creation instant, without rounding past early children',async()=>{
  const f=fixture();f.run.created_at='2026-10-25T00:00:25Z';f.consumer.created_at='2026-10-25T00:00:31Z';
  f.io.consumers=async created=>{assert.equal(created,f.run.created_at);return clone(f.consumers.filter(r=>Date.parse(r.created_at)>=Date.parse(created)));};
  const p=await planCleanup(f.io,100,manifest,now);assert.equal(p.skip,undefined);assert(p.artifacts.some(a=>a.id===12));
  await executeCleanup(f.io,p,{now:()=>now});assert.deepEqual(f.deleted,[]);
});

test('manual CLI artifact readers must be terminal and receive their own full consumption grace',async()=>{
  const f=fixture();f.readers.push({...clone(f.run),id:400,path:'.github/workflows/ci.yml',event:'workflow_dispatch',status:'in_progress'});
  assert.equal((await planCleanup(f.io,100,manifest,now)).skip,'artifact-reader-still-active');
  f.readers[0].status='completed';f.readers[0].updated_at='2026-10-25T01:30:00Z';
  assert.equal((await planCleanup(f.io,100,manifest,now)).skip,'one-hour-after-consumers-not-reached');
  const p=await planCleanup(f.io,100,manifest,Date.parse('2026-10-25T02:30:00Z'));assert.equal(p.skip,undefined);
  assert.deepEqual(f.deleted,[]);
});
test('new, restarted or changed manual artifact readers stop deletion before any write',async()=>{
  for(const mutate of [f=>f.readers.push({...clone(f.run),id:400,path:'.github/workflows/ci.yml',event:'workflow_dispatch',status:'queued'}),
    f=>f.io.otherReaders=async()=>{throw Error('reader enumeration failed');}]){
    const f=fixture(),p=await planCleanup(f.io,100,manifest,now);mutate(f);
    await assert.rejects(executeCleanup(f.io,p,{apply:true,now:()=>now}),/reader|enumeration/);assert.deepEqual(f.deleted,[]);
  }
  const f=fixture();delete f.io.otherReaders;await assert.rejects(planCleanup(f.io,100,manifest,now),/enumeration unavailable/);
});
test('cleanup uses the publication source manifest rather than a later main platform inventory',async()=>{
  const f=fixture();let lookups=0;f.io.manifestForSource=async source=>{assert.equal(source.sha,f.scoped.source.sha);lookups++;return clone(manifest);};
  const different={...manifest,targets:[...manifest.targets,{triple:'aarch64-unknown-linux-gnu',pkg:'@rsrsai/linux-arm64-gnu'}]};
  const p=await planCleanup(f.io,100,different,now);assert.equal(p.skip,undefined);assert.equal(lookups,1);
});

test('critical cleanup requires all declared target jobs and cannot use a legacy protocol-1 receipt',async()=>{
  const critical=regressionContract(manifest,'critical'),job=name=>({name,status:'completed',conclusion:'success'});
  const jobs=[...manifest.targets.map(t=>job('native-regression / Native ('+t.triple+')')),job('api-smoke'),job('publish')];
  requireRegressions(jobs,manifest.targets.map(t=>t.triple),critical);
  for(const conclusion of ['failure','cancelled','skipped']){const bad=clone(jobs);bad[0].conclusion=conclusion;assert.throws(()=>requireRegressions(bad,manifest.targets.map(t=>t.triple),critical))}
  const f=fixture();f.scoped.validation_profile='critical';f.scoped.validation_inventory=critical;
  await assert.rejects(planCleanup(f.io,100,manifest,now),/Legacy cleanup receipts are full-only/);assert.deepEqual(f.deleted,[]);
});

test('legacy cleanup cannot smuggle critical inventory under a missing or full top-level profile',async()=>{
  for(const profile of [undefined,'full']){
    const f=fixture();if(profile!==undefined)f.scoped.validation_profile=profile;
    f.scoped.validation_inventory=regressionContract(manifest,'critical');
    f.jobs=f.jobs.filter(j=>!j.name.startsWith('cloud-sweep ('));
    await assert.rejects(planCleanup(f.io,100,manifest,now),/profile differs|inventory differs/);assert.deepEqual(f.deleted,[]);
  }
});

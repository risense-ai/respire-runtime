import test from 'node:test';
import assert from 'node:assert/strict';
import {createPreparation,preparationLink} from './release-preparation.mjs';
import {validateImportedEvidence,importedAnchor,validateImportAnchor,assertImportPin,assertImportSelection,assertImportedContents,validateConsumerIntent} from './prepared-import.mjs';
import {preparedConsumerFlow} from './fixtures/prepared-consumer-flow.mjs';
import {readFileSync} from 'node:fs';

test('Release wires registered read-only import and explicit fail-closed publication joins',()=>{
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const job=name=>release.split(`\n  ${name}:\n`)[1].split(/\n  [a-z][\w-]*:\n/)[0];
  const importer=job('prepared-import'),ready=job('publication-ready'),publish=job('publish'),plan=job('plan');
  assert.match(importer,/contents: read/);assert.match(importer,/actions: read/);
  assert.doesNotMatch(importer,/id-token:|contents: write|actions: write|secrets\.|fetch-core-sdk|npm publish|concurrency:/);
  assert(importer.indexOf('prepared-import.mjs consumer')<importer.indexOf('artifact-ids:'));
  assert(importer.indexOf('--pack imported-packs')<importer.indexOf('prepared-import.mjs record'));
  assert.match(importer,/run-id: \$\{\{ needs.plan.outputs.prepared_run \}\}/);
  assert.match(importer,/npm@11\.5\.1/);
  for(const triple of ['x86_64-unknown-linux-gnu','x86_64-unknown-linux-musl','aarch64-unknown-linux-gnu','aarch64-unknown-linux-musl','aarch64-apple-darwin','x86_64-pc-windows-msvc'])assert(importer.includes('name: cli-release-'+triple));
  assert(plan.indexOf('release-preparation.mjs inspect')<plan.indexOf('gh\',\[\'release\',\'create'));
  for(const joined of [ready,publish]){
    assert.match(joined,/inputs.prepared_run == '' && needs.validate.result == 'success' && needs.prepared-import.result == 'skipped'/);
    assert.match(joined,/inputs.prepared_run != '' && needs.validate.result == 'skipped' && needs.prepared-import.result == 'success'/);
  }
  assert.match(ready,/prepared-import.mjs readiness/);
  assert(publish.indexOf('guard-accepted')<publish.indexOf('--publish --accepted-only'));
  for(const pin of ['PREPARED_ARTIFACT_ID','PREPARED_ARTIFACT_DIGEST','PREPARED_RECEIPT_SHA256','IMPORTED_ARTIFACT_ID','IMPORTED_ARTIFACT_DIGEST','IMPORTED_RECEIPT_SHA256'])assert(publish.includes(pin+':'));
  const acceptance=readFileSync(new URL('./publication-acceptance.mjs',import.meta.url),'utf8');
  assert.match(acceptance,/assertImportedContents\(source,m,'release-assets','npm\/release-packages',importPinFromEnv\(\)\)/);
  const source=readFileSync(new URL('../../.github/workflows/release-validation.yml',import.meta.url),'utf8');
  assert.match(source,/npm@11\.5\.1/);
});

test('actual helper processes bind preparation, registered import, readiness and mandatory publication bytes',()=>{
  const result=preparedConsumerFlow();
  assert.equal(result.positive.length,6);
  assert.equal(result.rejected.length,9);
  assert.equal(result.finalized,true);
  assert.notEqual(result.source_sha,result.workflow_sha);
});
test('six-platform prepared publication checks both ARM copies and every original gate through finalization',()=>{
  const result=preparedConsumerFlow({arm64:true});
  assert.equal(result.platform_count,6);assert.equal(result.finalized,true);assert.equal(result.rejected.length,9);
});

const sha='a'.repeat(40),workflowSha='c'.repeat(40),hash='b'.repeat(64),version='1.2.3-dev.4';
const time=n=>`2026-10-27T00:${String(n).padStart(2,'0')}:00Z`;
const triples=['x86_64-unknown-linux-gnu','x86_64-unknown-linux-musl','aarch64-apple-darwin','x86_64-pc-windows-msvc'];
const manifest={cliVersion:version,npmScope:'@rsrsai/cli',targets:triples.map((triple,i)=>({triple,pkg:`@rsrsai/platform-${i}`}))};
const source={repository:'risense-ai/respire-cli',workflow:'.github/workflows/release.yml',run_id:'701',run_attempt:1,sha,version,channel:'dev',release_id:42};
function fixture(){
  const original={repository:source.repository,workflow:source.workflow,run_id:'700',run_attempt:1,sha,version};
  const job=name=>({name,status:'completed',conclusion:'success',started_at:time(0),completed_at:time(3)});
  const jobs=[...triples.map(t=>job(`validate / Release (${t})`)),job('validate / npm-dry-run'),
    ...triples.map(t=>job(`native-regression / Native (${t})`)),...triples.slice(1).map(t=>job(`cloud-sweep (runner, ${t})`)),
    ...triples.slice(2).flatMap(t=>[job(`Native migration (${t})`),job(`Migration gate (${t})`)]),job('api-smoke')];
  const run={id:700,run_attempt:1,path:source.workflow,event:'workflow_dispatch',head_branch:'main',head_sha:sha,
    head_repository:{full_name:source.repository},status:'in_progress',updated_at:time(5)};
  const ci={id:600,run_attempt:1,path:'.github/workflows/ci.yml',event:'push',head_branch:'main',head_sha:sha,
    head_repository:{full_name:source.repository},status:'completed',conclusion:'success',run_started_at:time(0),updated_at:time(2)};
  const artifacts=[...triples.map(t=>`cli-release-${t}`),'npm-release-validation','npm-release-packages'].map((name,i)=>({
    id:i+1,name,size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:700,head_sha:sha}}));
  const assets=triples.flatMap(t=>[`rsrs-${t}${t.includes('windows')?'.exe':''}`,`rsrs-${t}-runtime.tar.gz`,`cli-build-${t}.json`]).map(file=>({file,size:100,sha256:hash}));
  const packs=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map((name,i)=>({name,version,file:`pack-${i}.tgz`,size:100,sha256:hash}));
  const identity={hashes:{'Cargo.lock':hash,'rust-toolchain.toml':hash},sdk:[]};
  const history={source:original,identity,manifest,run,jobs,ci,artifacts,assets,packs};
  jobs.push({id:900,name:'preparation-receipt',status:'in_progress',started_at:time(3)});
  const proof=createPreparation({...history,now:time(4)});
  Object.assign(jobs.at(-1),{status:'completed',conclusion:'success',completed_at:time(4)});
  history.run={...run,status:'completed',conclusion:'success'};
  const origin=preparationLink(proof,{id:90,name:'release-prepared-700-1',size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:700,head_sha:sha}});
  const owner={repository:source.repository,workflow:source.workflow,run_id:'701',run_attempt:1,sha,version,workflow_head_sha:workflowSha,import_job_id:'1000'};
  const receipt={schema:1,kind:'prepared-import',state:'verified-copy',owner,origin,preparation:proof,
    validated_assets:structuredClone(assets),validated_packs:structuredClone(packs),imported_at:time(7)};
  const ownerRun={id:701,run_attempt:1,path:source.workflow,event:'workflow_dispatch',head_branch:'main',head_sha:workflowSha,
    head_repository:{full_name:source.repository},status:'in_progress',created_at:time(6)};
  const ownerJobs=[{id:1000,name:'prepared-import',status:'completed',conclusion:'success',started_at:time(6),completed_at:time(8)}];
  const metadata={id:99,name:'prepared-import-701-1',created_at:time(7),size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:701,head_sha:workflowSha}};
  return {receipt,source:structuredClone(source),manifest,context:{ownerRun,ownerJobs,history,metadata},metadata};
}

test('completed trusted import keeps exact selected CLI SHA even when workflow main has advanced',()=>{
  const f=fixture();assert.equal(validateImportedEvidence(f.receipt,f.source,f.manifest,f.context),f.receipt);
  assert.notEqual(f.context.ownerRun.head_sha,f.source.sha);
  const anchor=importedAnchor(f.receipt,f.metadata,f.context.ownerRun);assert.equal(validateImportAnchor(anchor,f.source),anchor);
});
test('consumer registration uses bound GitHub artifact time despite a different runner clock',()=>{
  const f=fixture(),run=f.context.ownerRun,job=f.context.ownerJobs[0];
  const intent={schema:1,kind:'prepared-consumer',state:'reading',owner:f.receipt.owner,origin:f.receipt.origin,
    created_at:'2026-10-26T23:06:10Z'};
  job.started_at=time(7);
  const metadata={...f.metadata,name:'prepared-consumer-701-1',created_at:'2026-10-27T00:06:20Z'};
  assert.equal(validateConsumerIntent(intent,f.source,f.receipt.origin,run,job,metadata),intent);
  intent.created_at='2026-10-27T01:06:10Z';
  assert.equal(validateConsumerIntent(intent,f.source,f.receipt.origin,run,job,metadata),intent);
  assert.throws(()=>validateConsumerIntent(intent,f.source,f.receipt.origin,run,job));
  for(const mutate of [x=>x.created_at=time(5),x=>x.created_at=time(8),x=>delete x.created_at,
    x=>x.created_at='invalid',x=>x.workflow_run.id=702,x=>x.workflow_run.head_sha=sha,x=>x.expired=true,
    x=>x.name='prepared-consumer-701-2',x=>x.digest='invalid']){
    const bad=structuredClone(metadata);mutate(bad);
    assert.throws(()=>validateConsumerIntent(intent,f.source,f.receipt.origin,run,job,bad));
  }
  intent.created_at='invalid';
  assert.throws(()=>validateConsumerIntent(intent,f.source,f.receipt.origin,run,job,metadata));
});

test('wrong source/version, owner attempt/repository, import job or immutable origin cannot authorize reuse',()=>{
  const mutations=[f=>f.source.sha='f'.repeat(40),f=>f.source.version='1.2.3-dev.5',f=>f.receipt.owner.run_attempt=2,
    f=>f.context.ownerRun.head_repository.full_name='fork/respire-cli',f=>f.context.ownerRun.head_sha=sha,
    f=>f.receipt.owner.import_job_id='1001',f=>f.receipt.origin.source.run_id='702',
    f=>f.receipt.origin.receipt_sha256='f'.repeat(64),f=>f.receipt.preparation.identity.sdk.push({target:'foreign'}),
    f=>f.receipt.validated_assets[0].sha256='f'.repeat(64),f=>f.receipt.validated_packs.pop()];
  for(const mutate of mutations){const f=structuredClone(fixture());mutate(f);assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context));}
});
test('missing/duplicate/failed/cancelled/skipped import and failed original gates remain blocking',()=>{
  for(const mode of ['missing','duplicate','failure','cancelled','skipped','in_progress']){
    const f=fixture();
    if(mode==='missing')f.context.ownerJobs=[];
    else if(mode==='duplicate')f.context.ownerJobs.push({...f.context.ownerJobs[0]});
    else if(mode==='in_progress')f.context.ownerJobs[0].status=mode;
    else f.context.ownerJobs[0].conclusion=mode;
    assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context),mode);
  }
  const f=fixture();f.context.history.jobs[0].conclusion='skipped';assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context));
});
test('preparation must finish before actual publication trigger and import must fit real job clocks',()=>{
  for(const mutate of [f=>f.context.ownerRun.created_at=time(4),f=>f.context.metadata.created_at=time(9),
    f=>f.context.ownerJobs[0].started_at='invalid',f=>f.context.ownerJobs[0].completed_at=time(5)]){
    const f=fixture();mutate(f);assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context));
  }
});
test('import verification uses its bound API upload time despite runner clock skew',()=>{
  for(const clock of ['2026-10-26T23:07:00Z','2026-10-27T01:07:00Z']){
    const f=fixture();f.receipt.imported_at=clock;
    assert.equal(validateImportedEvidence(f.receipt,f.source,f.manifest,f.context),f.receipt);
  }
  for(const mutate of [f=>delete f.context.metadata,f=>delete f.context.metadata.created_at,
    f=>f.context.metadata.created_at=time(5),f=>f.context.metadata.created_at=time(9),
    f=>f.context.metadata.workflow_run.id=702,f=>f.context.metadata.digest='invalid',
    f=>f.context.metadata.expired=true,f=>f.receipt.imported_at='invalid']){
    const f=fixture();mutate(f);
    assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context));
  }
});

test('only verified current copies may outlive original archive availability; expired current proof is refused',()=>{
  const f=fixture();f.context.history.artifacts=[];
  assert.equal(validateImportedEvidence(f.receipt,f.source,f.manifest,f.context),f.receipt);
  f.metadata.expired=true;assert.throws(()=>importedAnchor(f.receipt,f.metadata,f.context.ownerRun));
});
test('readiness pins both current import and original preparation',()=>{
  const f=fixture(),anchor=importedAnchor(f.receipt,f.metadata,f.context.ownerRun),result={receipt:f.receipt,anchor};
  const pin={artifact_id:99,artifact_digest:anchor.artifact.digest,receipt_sha256:anchor.receipt_sha256};
  assert.equal(assertImportPin(result,pin),result);
  assert.throws(()=>assertImportPin(result,{...pin,artifact_id:100}));
  assert.throws(()=>assertImportPin(result,{...pin,receipt_sha256:'f'.repeat(64)}));
  const old={attempt:1,artifact_id:90,artifact_digest:f.receipt.origin.artifact.digest,receipt_sha256:f.receipt.origin.receipt_sha256};
  assert.equal(assertImportSelection(result,700,old),result);
  assert.throws(()=>assertImportSelection(result,702,old));
  assert.throws(()=>assertImportSelection(result,700,{...old,attempt:2}));
});
test('optional historical byte parameters cannot substitute for mandatory write-boundary folders',()=>{
  for(const folders of [[undefined,undefined],['assets',undefined],[undefined,'packs'],['','packs']]){
    assert.throws(()=>assertImportedContents(source,manifest,...folders,{}),/Mandatory local asset and tarball folders missing/);
  }
});

test('prepared import preserves the exact validation profile and old missing fields remain full',()=>{
  const old=fixture();delete old.receipt.preparation.validation_profile;old.receipt.origin=preparationLink(old.receipt.preparation,{id:90,name:'release-prepared-700-1',size_in_bytes:100,digest:'sha256:'+hash,expired:false,workflow_run:{id:700,head_sha:sha}});validateImportedEvidence(old.receipt,old.source,old.manifest,old.context);
  const f=fixture(),h=f.context.history;
  h.jobs=h.jobs.filter(j=>!j.name.startsWith('cloud-sweep (')&&!j.name.startsWith('Native migration (')&&!j.name.startsWith('Migration gate ('));
  const producing=structuredClone(h.jobs);Object.assign(producing.at(-1),{status:'in_progress',conclusion:undefined,completed_at:undefined});
  const proof=createPreparation({...h,jobs:producing,run:{...h.run,status:'in_progress'},profile:'critical',now:time(4)});
  f.receipt.preparation=proof;f.receipt.validation_profile='critical';
  f.receipt.origin=preparationLink(proof,{id:90,name:'release-prepared-700-1',size_in_bytes:100,digest:'sha256:'+hash,expired:false,workflow_run:{id:700,head_sha:sha}});
  validateImportedEvidence(f.receipt,f.source,f.manifest,f.context);
  for(const profile of [undefined,'full','invalid']){const r=structuredClone(f.receipt);if(profile===undefined)delete r.validation_profile;else r.validation_profile=profile;assert.throws(()=>validateImportedEvidence(r,f.source,f.manifest,f.context))}
});

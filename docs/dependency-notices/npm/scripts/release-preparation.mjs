// Read-only evidence for reusing fully validated, exact-source release bytes.
// A preparation is never npm acceptance and never authorizes stale writes.
import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {regressionContract,validateRegressionContract,validationProfile,regressionStatus,regressionCompletedAt,parseTimestamp} from './release-regression-contract.mjs';
import {api,pages,output as setOutput} from './release-publication.mjs';
import {readVerifiedReceipt} from './verified-receipt.mjs';

const REPO='risense-ai/respire-cli',WORKFLOW='.github/workflows/release.yml';
const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/;
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const positive=value=>/^[1-9]\d*$/.test(String(value))&&Number.isSafeInteger(Number(value));
export const preparationName=source=>`release-prepared-${source.run_id}-${source.run_attempt}`;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

export function validatePreparationSource(source){
  requireValue(source?.repository===REPO&&source.workflow===WORKFLOW&&positive(source.run_id)&&positive(source.run_attempt)&&
    SHA.test(source.sha||'')&&/^\d+\.\d+\.\d+-dev\.[1-9]\d*$/.test(source.version||''), 'Invalid exact-source DEV preparation');
  return source;
}
export function validatePreparationRun(run,source,{producing=false}={}){
  validatePreparationSource(source);
  requireValue(String(run?.id)===String(source.run_id)&&Number(run.run_attempt)===Number(source.run_attempt)&&
    run.path===WORKFLOW&&run.head_repository?.full_name===REPO&&run.event==='workflow_dispatch'&&
    run.head_branch==='main'&&run.head_sha===source.sha&&
    (producing?run.status==='in_progress':run.status==='completed'&&run.conclusion==='success'),
    'Preparation must be the exact successful main Release attempt; PR, stale, fork and foreign-source runs are refused');
}

// Hash committed inputs, not a checkout whose version has been changed for packing.
export function preparationInputs(sha,version,{cwd=process.cwd()}={}){
  requireValue(SHA.test(sha||''),'Invalid preparation source SHA');
  const files=['Cargo.lock','rust-toolchain.toml','sdk/core-sdk.lock.json','crates/core-sdk/core-sdk.lock.json',
    '.github/workflows/release.yml','.github/workflows/release-validation.yml','.github/workflows/release-native-validation.yml'];
  const load=file=>execFileSync('git',['show',`${sha}:${file}`],{cwd,maxBuffer:1024*1024});
  const hashes=Object.fromEntries(files.map(file=>[file,digest(load(file))]));
  const manifest=JSON.parse(load('npm/artifact-manifest.json'));
  manifest.cliVersion=version;
  hashes['npm/artifact-manifest.json']=digest(JSON.stringify(manifest));
  const lock=JSON.parse(load('sdk/core-sdk.lock.json')),other=JSON.parse(load('crates/core-sdk/core-sdk.lock.json'));
  requireValue(same(lock,other),'Prepared SDK lock copies differ');
  const sdk=manifest.targets.map(({triple})=>{
    const entry=lock.targets?.[triple];
    requireValue(entry&&typeof entry.sdk_version==='string'&&HASH.test(entry.manifest_sha256||'')&&HASH.test(entry.archive_sha256||''),'Missing pinned SDK identity');
    return {target:triple,version:entry.sdk_version,manifest_sha256:entry.manifest_sha256,archive_sha256:entry.archive_sha256};
  });
  return {manifest,identity:{hashes,sdk}};
}

function completed(job,label){
  requireValue(job?.status==='completed'&&job.conclusion==='success',`Required preparation ${label} is not successful`);
  const end=parseTimestamp(job.completed_at),start=parseTimestamp(job.started_at);
  requireValue(end!==null&&start!==null&&start<=end,`Invalid preparation clock: ${label}`);
  return end;
}
export function preparationValidation(jobs,ci,source,manifest,profile='full'){
  validatePreparationSource(source);
  requireValue(manifest.cliVersion===source.version,'Prepared manifest version differs');
  requireValue(ci?.path==='.github/workflows/ci.yml'&&ci.head_sha===source.sha&&ci.head_branch==='main'&&
    ci.head_repository?.full_name===REPO&&ci.event==='push'&&positive(ci.id)&&positive(ci.run_attempt), 'Preparation source CI is not exact main push CI');
  let at=completed({...ci,started_at:ci.run_started_at,completed_at:ci.updated_at},'source CI');
  const required=[...manifest.targets.map(t=>`validate / Release (${t.triple})`),'validate / npm-dry-run'];
  for(const name of required){
    const matching=jobs.filter(j=>j.name===name);
    requireValue(matching.length===1,`Missing or duplicate preparation job: ${name}`);
    at=Math.max(at,completed(matching[0],name));
  }
  const inventory=regressionContract(manifest,profile);
  requireValue(regressionStatus(jobs,inventory)==='success','Prepared regressions are incomplete');
  const regressionAt=regressionCompletedAt(jobs,inventory,new Date(at).toISOString());
  requireValue(regressionAt!==null,'Prepared regression completion time is missing');
  return {inventory,completed_at:new Date(Math.max(at,regressionAt)).toISOString(),
    source_ci:{run_id:String(ci.id),run_attempt:Number(ci.run_attempt)}};
}

export function preparationArtifacts(artifacts,source,manifest){
  const names=[...manifest.targets.map(t=>`cli-release-${t.triple}`),'npm-release-validation','npm-release-packages'];
  return names.map(name=>{
    const hits=artifacts.filter(a=>a.name===name);
    requireValue(hits.length===1,`Missing or duplicate prepared artifact: ${name}`);
    const a=hits[0];
    requireValue(positive(a.id)&&a.expired===false&&Number.isSafeInteger(a.size_in_bytes)&&a.size_in_bytes>0&&
      /^sha256:[a-f0-9]{64}$/.test(a.digest||'')&&String(a.workflow_run?.id)===String(source.run_id)&&
      a.workflow_run.head_sha===source.sha,`Expired, unbound or undigested prepared artifact: ${name}`);
    return {id:String(a.id),name,size:a.size_in_bytes,digest:a.digest};
  });
}

function ordinaryFile(folder,file,maxSize=1024*1024*1024){
  requireValue(typeof file==='string'&&/^[A-Za-z0-9_.-]+$/.test(file),'Unsafe prepared filename');
  const path=join(folder,file),stat=lstatSync(path);
  requireValue(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=maxSize,'Invalid prepared file');
  return {file,size:stat.size,sha256:digest(readFileSync(path))};
}
export function preparedAssets(folder,source,manifest){
  const assets=[];
  for(const t of manifest.targets){
    const binary=`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,runtime=`rsrs-${t.triple}-runtime.tar.gz`,metadata=`cli-build-${t.triple}.json`;
    const b=ordinaryFile(folder,binary),r=ordinaryFile(folder,runtime),m=ordinaryFile(folder,metadata,65536);
    const info=JSON.parse(readFileSync(join(folder,metadata)));
    requireValue(info.schema_version===1&&info.git_sha===source.sha&&info.version===source.version&&info.target===t.triple&&
      info.binary_file===binary&&info.runtime_file===runtime&&info.binary_sha256===b.sha256&&info.runtime_sha256===r.sha256,'Prepared bytes differ from source/version/platform metadata');
    assets.push(b,r,m);
  }
  requireValue(same(readdirSync(folder).sort(),assets.map(a=>a.file).sort()),'Unexpected or missing prepared release asset');
  return assets;
}
export function preparedPacks(folder,source,manifest){
  ordinaryFile(folder,'source-version.json',1024*1024);
  const index=JSON.parse(readFileSync(join(folder,'source-version.json')));
  requireValue(index.schema_version===1&&index.git_sha===source.sha&&index.version===source.version&&Array.isArray(index.packages),'Prepared pack index identity differs');
  const names=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].sort();
  requireValue(same(index.packages.map(p=>p.name).sort(),names),'Prepared npm package inventory differs');
  return index.packages.map(p=>{
    const actual=ordinaryFile(folder,p.file);
    requireValue(p.version===source.version&&p.sha256===actual.sha256&&p.file.endsWith('.tgz'),'Prepared npm pack digest/version differs');
    return {name:p.name,version:p.version,...actual};
  }).sort((a,b)=>a.name.localeCompare(b.name));
}

export function preparationReceiptJob(jobs,{producing=false}={}){
  const matches=jobs.filter(j=>j.name==='preparation-receipt');
  requireValue(matches.length===1&&positive(matches[0].id),'Preparation receipt job is missing or duplicated');
  const job=matches[0];
  requireValue(parseTimestamp(job.started_at)!==null,'Preparation receipt job start is missing');
  if(producing)requireValue(job.status==='in_progress','Preparation receipt job is not active');
  else completed(job,'receipt');
  return job;
}

export function createPreparation({source,identity,manifest,run,jobs,ci,artifacts,assets,packs,profile='full',now=new Date().toISOString()}){
  validatePreparationRun(run,source,{producing:true});
  profile=validationProfile(profile);
  const validation=preparationValidation(jobs,ci,source,manifest,profile),time=parseTimestamp(now);
  preparationReceiptJob(jobs,{producing:true});
  // Completed API gates are read before writing; runner time is audit data only.
  requireValue(time!==null,'Preparation receipt clock is invalid');
  validatePreparedBytes(assets,packs,source,manifest);
  return structuredClone({schema:1,kind:'release-prepared',state:'validated-unpublished',validation_profile:profile,source,identity,validation,
    origin_artifacts:preparationArtifacts(artifacts,source,manifest),assets,packs,prepared_at:now});
}
export function validatePreparedBytes(assets,packs,source,manifest){
  const names=manifest.targets.flatMap(t=>[`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,`rsrs-${t.triple}-runtime.tar.gz`,`cli-build-${t.triple}.json`]).sort();
  requireValue(Array.isArray(assets)&&same(assets.map(a=>a.file).sort(),names)&&assets.every(a=>positive(a.size)&&HASH.test(a.sha256||'')), 'Prepared asset inventory/digests are incomplete');
  const packages=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].sort();
  requireValue(Array.isArray(packs)&&same(packs.map(p=>p.name).sort(),packages)&&new Set(packs.map(p=>p.file)).size===packs.length&&
    packs.every(p=>p.version===source.version&&/^[A-Za-z0-9_.-]+\.tgz$/.test(p.file||'')&&positive(p.size)&&HASH.test(p.sha256||'')), 'Prepared npm inventory/digests are incomplete');
}
// Historical evidence alone is never publication authorization. Only a trusted
// import plus mandatory checks of every copied asset and npm tarball can reuse it.
export function validatePreparationHistory(receipt,context){
  const {source,identity,manifest,run,jobs,ci}=context;
  validatePreparationRun(run,source);
  requireValue(receipt?.schema===1&&receipt.kind==='release-prepared'&&receipt.state==='validated-unpublished'&&
    same(receipt.source,source)&&same(receipt.identity,identity),'Prepared receipt source, SDK, toolchain or layout differs');
  const profile=validationProfile(receipt.validation_profile);
  validateRegressionContract(receipt.validation?.inventory,manifest,profile);
  if(context.validation_profile!==undefined)requireValue(profile===validationProfile(context.validation_profile),'Prepared validation profile differs');
  requireValue(same(receipt.validation,preparationValidation(jobs,ci,source,manifest,profile)), 'Prepared CI/regression proof changed or is stale');
  const prepared=parseTimestamp(preparationReceiptJob(jobs).completed_at),finished=parseTimestamp(run.updated_at);
  requireValue(parseTimestamp(receipt.prepared_at)!==null&&finished!==null&&prepared>=parseTimestamp(receipt.validation.completed_at)&&prepared<=finished,'Prepared receipt clock is invalid');
  validatePreparedBytes(receipt.assets,receipt.packs,source,manifest);
  if(context.assets)requireValue(same(receipt.assets,context.assets),'Downloaded prepared asset bytes differ');
  if(context.packs)requireValue(same(receipt.packs,context.packs),'Downloaded prepared npm bytes differ');
  return receipt;
}
export function validatePreparation(receipt,context){
  validatePreparationHistory(receipt,context);
  requireValue(same(receipt.origin_artifacts,preparationArtifacts(context.artifacts,context.source,context.manifest)), 'Prepared artifact IDs/digests changed');
  return receipt;
}

export function preparationContext(source){
  validatePreparationSource(source);
  const run=api(`repos/${REPO}/actions/runs/${source.run_id}`);
  const jobs=pages(`repos/${REPO}/actions/runs/${source.run_id}/attempts/${source.run_attempt}/jobs?per_page=10`).flatMap(p=>p.jobs);
  const artifacts=pages(`repos/${REPO}/actions/runs/${source.run_id}/artifacts?per_page=100`).flatMap(p=>p.artifacts);
  const candidates=pages(`repos/${REPO}/actions/workflows/ci.yml/runs?head_sha=${source.sha}&per_page=100`).flatMap(p=>p.workflow_runs)
    .filter(r=>r.head_sha===source.sha&&r.event==='push'&&r.head_branch==='main').sort((a,b)=>b.id-a.id);
  requireValue(candidates.length>0,'No exact main push CI exists for preparation');
  const ci=api(`repos/${REPO}/actions/runs/${candidates[0].id}`);
  return {...preparationInputs(source.sha,source.version),source,run,jobs,artifacts,ci};
}
export function attestPreparation(assetsFolder,packsFolder,output){
  const source=validatePreparationSource({repository:process.env.GITHUB_REPOSITORY,workflow:WORKFLOW,
    run_id:process.env.GITHUB_RUN_ID,run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),
    sha:process.env.CLI_SHA,version:process.env.CLI_VERSION});
  requireValue(process.env.GITHUB_EVENT_NAME==='workflow_dispatch'&&process.env.GITHUB_REF==='refs/heads/main'&&
    process.env.GITHUB_SHA===source.sha&&execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim()===source.sha,
    'Only the exact main workflow checkout can attest unpublished preparation');
  const context=preparationContext(source);
  validatePreparationRun(context.run,source,{producing:true});
  const receipt=createPreparation({...context,profile:validationProfile(process.env.VALIDATION_PROFILE),assets:preparedAssets(assetsFolder,source,context.manifest),
    packs:preparedPacks(packsFolder,source,context.manifest)});
  writeFileSync(output,JSON.stringify(receipt,null,2)+'\n');
  console.log(`Recorded ${receipt.validation_profile} unpublished validation for ${source.sha}@${source.version}; no publication acknowledgement`);
  return receipt;
}

export function preparationLink(receipt,metadata){
  const s=validatePreparationSource(receipt.source);
  requireValue(metadata?.name===preparationName(s)&&positive(metadata.id)&&/^sha256:[a-f0-9]{64}$/.test(metadata.digest||'')&&
    metadata.expired===false&&String(metadata.workflow_run?.id)===String(s.run_id)&&metadata.workflow_run.head_sha===s.sha,
    'Preparation proof artifact is expired, foreign or unbound');
  return {source:structuredClone(s),artifact:{id:String(metadata.id),name:metadata.name,digest:metadata.digest,size:metadata.size_in_bytes},
    receipt_sha256:digest(JSON.stringify(receipt))};
}
export function validatePreparationLink(link,source){
  validatePreparationSource(link?.source);
  requireValue(link.source.sha===source.sha&&link.source.version===source.version&&link.source.repository===source.repository&&
    String(link.source.run_id)!==String(source.run_id)&&positive(link.artifact?.id)&&positive(link.artifact.size)&&
    link.artifact.name===preparationName(link.source)&&/^sha256:[a-f0-9]{64}$/.test(link.artifact.digest||'')&&HASH.test(link.receipt_sha256||''),
    'Prepared validation origin differs from this publication');
  return link;
}
export function readPreparedRun(runId,sha,version,profile=process.env.VALIDATION_PROFILE){
  requireValue(positive(runId)&&SHA.test(sha||''),'Invalid preparation lookup');
  const initial=api(`repos/${REPO}/actions/runs/${runId}`);
  requireValue(String(initial.id)===String(runId)&&positive(initial.run_attempt)&&initial.path===WORKFLOW&&
    initial.event==='workflow_dispatch'&&initial.head_branch==='main'&&initial.head_sha===sha&&initial.head_repository?.full_name===REPO&&
    initial.status==='completed'&&initial.conclusion==='success','Only a completed exact-main preparation can be consumed');
  const name=preparationName({run_id:runId,run_attempt:initial.run_attempt});
  const initialArtifacts=pages(`repos/${REPO}/actions/runs/${runId}/artifacts?per_page=100`).flatMap(p=>p.artifacts).filter(a=>a.name===name);
  requireValue(initialArtifacts.length===1,'Preparation proof is missing or duplicated');
  const receipt=readVerifiedReceipt(initialArtifacts[0],'release-prepared.json',{runId,headSha:initial.head_sha});
  if(profile!==undefined)requireValue(validationProfile(receipt.validation_profile)===validationProfile(profile),'Selected preparation validation profile differs');
  const source=validatePreparationSource({repository:REPO,workflow:WORKFLOW,run_id:String(runId),run_attempt:Number(initial.run_attempt),
    sha,version:version||receipt.source?.version});
  const context=preparationContext(source);
  validatePreparation(receipt,context);
  const proofs=context.artifacts.filter(a=>a.name===name);
  requireValue(proofs.length===1,'Duplicate preparation proof artifact');
  requireValue(String(proofs[0].id)===String(initialArtifacts[0].id)&&proofs[0].digest===initialArtifacts[0].digest&&
    proofs[0].size_in_bytes===initialArtifacts[0].size_in_bytes,'Preparation proof changed during selection');
  return {receipt,context,link:preparationLink(receipt,proofs[0])};
}
export function assertPreparationOrigin(link,source){
  validatePreparationLink(link,source);
  const result=readPreparedRun(link.source.run_id,source.sha,source.version);
  requireValue(same(result.link,link),'Prepared origin attempt/artifact/receipt changed');
  return result;
}
export function currentPublicationOwner(sha,version){
  requireValue(process.env.GITHUB_REPOSITORY===REPO&&process.env.GITHUB_EVENT_NAME==='workflow_dispatch'&&
    process.env.GITHUB_REF==='refs/heads/main'&&positive(process.env.GITHUB_RUN_ID)&&positive(process.env.GITHUB_RUN_ATTEMPT)&&
    SHA.test(sha||'')&&SHA.test(process.env.GITHUB_SHA||'')&&/^\d+\.\d+\.\d+-dev\.[1-9]\d*$/.test(version||''),
    'Prepared publication requires a trusted main dispatch');
  const owner={repository:REPO,workflow:WORKFLOW,run_id:String(process.env.GITHUB_RUN_ID),run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),
    sha,version,workflow_head_sha:process.env.GITHUB_SHA};
  const run=api(`repos/${REPO}/actions/runs/${owner.run_id}`);
  requireValue(String(run.id)===owner.run_id&&Number(run.run_attempt)===owner.run_attempt&&run.path===WORKFLOW&&
    run.head_repository?.full_name===REPO&&run.head_branch==='main'&&run.head_sha===owner.workflow_head_sha&&run.event==='workflow_dispatch'&&
    run.status==='in_progress','Prepared publication owner is foreign, inactive or stale');
  requireValue(execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim()===sha,'Prepared publication checkout differs');
  execFileSync('git',['merge-base','--is-ancestor',sha,'origin/main']);
  return {owner,run};
}
export function requirePreparationBeforeTrigger(result,run){
  const prepared=parseTimestamp(preparationReceiptJob(result.context.jobs).completed_at),complete=parseTimestamp(result.context.run.updated_at),trigger=parseTimestamp(run.created_at);
  requireValue(prepared!==null&&complete!==null&&trigger!==null&&prepared<=complete&&complete<=trigger,
    'Complete preparation must precede this publication trigger');
}
export function inspectPreparation(runId,sha,version){
  const result=readPreparedRun(runId,sha,version);
  const {owner,run}=currentPublicationOwner(sha,result.receipt.source.version);
  validatePreparationLink(result.link,owner);
  requirePreparationBeforeTrigger(result,run);
  writeFileSync('prepared-consumer.json',JSON.stringify({schema:1,kind:'prepared-consumer',state:'reading',owner,
    origin:result.link,created_at:new Date().toISOString()},null,2)+'\n');
  // Only public artifact IDs and the exact version are workflow outputs.
  setOutput({prepared_run:result.receipt.source.run_id,prepared_version:result.receipt.source.version,
    prepared_attempt:result.receipt.source.run_attempt,prepared_artifact_id:result.link.artifact.id,
    prepared_artifact_digest:result.link.artifact.digest,prepared_receipt_sha256:result.link.receipt_sha256,
    prepared_binary_artifact_ids:result.receipt.origin_artifacts.filter(a=>a.name.startsWith('cli-release-')).map(a=>a.id).join(',')});
  return result;
}
export function assertPreparationPin(result,pin){
  requireValue(positive(pin?.attempt)&&positive(pin.artifact_id)&&/^sha256:[a-f0-9]{64}$/.test(pin.artifact_digest||'')&&HASH.test(pin.receipt_sha256||'')&&
    Number(pin.attempt)===Number(result.link.source.run_attempt)&&String(pin.artifact_id)===String(result.link.artifact.id)&&
    pin.artifact_digest===result.link.artifact.digest&&pin.receipt_sha256===result.link.receipt_sha256,
    'Prepared proof differs from the originally selected attempt/artifact/digest');
  return result;
}
export const preparationPinFromEnv=()=>({attempt:process.env.PREPARED_ATTEMPT,artifact_id:process.env.PREPARED_ARTIFACT_ID,
  artifact_digest:process.env.PREPARED_ARTIFACT_DIGEST,receipt_sha256:process.env.PREPARED_RECEIPT_SHA256});
export function assertPreparedAssets(runId,sha,version,folder,pin){
  const result=readPreparedRun(runId,sha,version);
  assertPreparationPin(result,pin);
  const actual=preparedAssets(folder,result.receipt.source,result.context.manifest);
  requireValue(same(actual,result.receipt.assets),'Downloaded bytes differ from the original complete preparation');
  return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const action=process.argv[2];
    if(action==='attest'){
      requireValue(process.argv.length===6,'Expected attest <assets> <packs> <receipt>');
      attestPreparation(...process.argv.slice(3));
    }else if(action==='inspect'){
      requireValue(process.argv.length===3,'Unexpected preparation lookup arguments');
      inspectPreparation(process.env.PREPARED_RUN,process.env.CLI_SHA,process.env.CLI_VERSION||'');
    }else if(action==='assert-assets'){
      requireValue(process.argv.length===4,'Expected assert-assets <assets>');
      assertPreparedAssets(process.env.PREPARED_RUN,process.env.CLI_SHA,process.env.CLI_VERSION,process.argv[3],preparationPinFromEnv());
    }else throw Error('Expected attest, inspect or assert-assets');
  }catch(error){console.error(error.message);process.exitCode=1;}
}

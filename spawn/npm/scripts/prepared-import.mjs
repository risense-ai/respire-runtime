// Trusted, read-only import of completed preparation into its publication run.
// A receipt shape or historical test result alone never authorizes npm writes.
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {api,pages,output,assertActive} from './release-publication.mjs';
import {readVerifiedReceipt} from './verified-receipt.mjs';
import {parseTimestamp,validateRegressionContract,validationProfile} from './release-regression-contract.mjs';
import {readPreparedRun,assertPreparationPin,preparationPinFromEnv,currentPublicationOwner,requirePreparationBeforeTrigger,
  preparationContext,validatePreparationSource,validatePreparationLink,validatePreparationHistory,
  validatePreparedBytes,preparedAssets,preparedPacks,preparationInputs} from './release-preparation.mjs';

const REPO='risense-ai/respire-cli',WORKFLOW='.github/workflows/release.yml';
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const positive=v=>/^[1-9]\d*$/.test(String(v))&&Number.isSafeInteger(Number(v));
const hash=v=>/^[a-f0-9]{64}$/.test(v||'');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const canonical=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const fields=['repository','workflow','sha','version'];
export const importName=source=>`prepared-import-${source.run_id}-${source.run_attempt}`;
export const consumerName=source=>`prepared-consumer-${source.run_id}-${source.run_attempt}`;

export function validateConsumerIntent(intent,source,origin,run,importJob,metadata){
  const owner=intent?.owner;
  requireValue(intent?.schema===1&&intent.kind==='prepared-consumer'&&intent.state==='reading'&&owner&&
    fields.every(k=>owner[k]===source[k])&&String(owner.run_id)===String(source.run_id)&&
    Number(owner.run_attempt)===Number(source.run_attempt)&&owner.workflow_head_sha===run.head_sha&&
    same(intent.origin,origin),'Cross-run consumer registration differs from the selected source');
  validatePreparationLink(intent.origin,source);
  currentReceiptMetadata(metadata,run,consumerName(source));
  // Compare GitHub service timestamps; the receipt's runner clock may differ.
  const at=parseTimestamp(metadata.created_at),start=parseTimestamp(importJob.started_at),trigger=parseTimestamp(run.created_at);
  requireValue(parseTimestamp(intent.created_at)!==null&&at!==null&&start!==null&&trigger!==null&&trigger<=at&&at<=start,'Consumer must register before import starts');
  return intent;
}
function currentReceiptMetadata(metadata,run,name){
  requireValue(metadata?.name===name&&positive(metadata.id)&&positive(metadata.size_in_bytes)&&metadata.expired===false&&
    /^sha256:[a-f0-9]{64}$/.test(metadata.digest||'')&&String(metadata.workflow_run?.id)===String(run.id)&&
    metadata.workflow_run.head_sha===run.head_sha,'Current receipt artifact is foreign, expired or undigested');
}
function readConsumer(source,run,job,origin,artifacts){
  const entries=artifacts.filter(a=>a.name===consumerName(source));
  requireValue(entries.length===1,'Missing or duplicate cross-run consumer registration');
  currentReceiptMetadata(entries[0],run,consumerName(source));
  const intent=readVerifiedReceipt(entries[0],'prepared-consumer.json',{runId:source.run_id,headSha:run.head_sha});
  validateConsumerIntent(intent,source,origin,run,job,entries[0]);
  return {intent,metadata:entries[0]};
}
export function verifyConsumerBeforeImport(){
  requireValue(process.env.GITHUB_JOB==='prepared-import','Only the trusted import job can consume prepared artifacts');
  const {owner,run}=currentPublicationOwner(process.env.CLI_SHA,process.env.CLI_VERSION);
  const jobs=pages(`repos/${REPO}/actions/runs/${owner.run_id}/attempts/${owner.run_attempt}/jobs?per_page=10`).flatMap(p=>p.jobs).filter(j=>j.name==='prepared-import');
  requireValue(jobs.length===1&&positive(jobs[0].id)&&jobs[0].status==='in_progress','Current import job is inactive or ambiguous');
  const artifacts=pages(`repos/${REPO}/actions/runs/${owner.run_id}/artifacts?per_page=100`).flatMap(p=>p.artifacts);
  const intents=artifacts.filter(a=>a.name===consumerName(owner));
  requireValue(intents.length===1,'Cross-run consumer was not registered by the plan');
  currentReceiptMetadata(intents[0],run,consumerName(owner));
  const intent=readVerifiedReceipt(intents[0],'prepared-consumer.json',{runId:owner.run_id,headSha:run.head_sha});
  validateConsumerIntent(intent,owner,intent?.origin,run,jobs[0],intents[0]);
  requireValue(String(intent.origin.source.run_id)===String(process.env.PREPARED_RUN),'Registered consumer selected a different preparation');
  assertPreparationPin({link:intent.origin},preparationPinFromEnv());
  return {owner,run,job:jobs[0],intent};
}

export function validateImportedShape(receipt,source,manifest){
  validatePreparationSource(source);
  const owner=receipt?.owner,proof=receipt?.preparation;
  requireValue(receipt?.schema===1&&receipt.kind==='prepared-import'&&receipt.state==='verified-copy'&&
    owner&&fields.every(k=>owner[k]===source[k])&&String(owner.run_id)===String(source.run_id)&&
    Number(owner.run_attempt)===Number(source.run_attempt)&&/^[a-f0-9]{40}$/.test(owner.workflow_head_sha||'')&&
    positive(owner.import_job_id)&&parseTimestamp(receipt.imported_at)!==null,'Import belongs to another publication owner');
  requireValue(proof?.schema===1&&proof.kind==='release-prepared'&&proof.state==='validated-unpublished', 'Missing original preparation snapshot');
  validatePreparationLink(receipt.origin,source);
  requireValue(same(receipt.origin.source,proof.source)&&canonical(proof)===receipt.origin.receipt_sha256,
    'Original proof snapshot differs from the selected immutable receipt');
  const profile=validationProfile(receipt.validation_profile);
  requireValue(profile===validationProfile(proof.validation_profile),'Import validation profile differs from its preparation');
  validateRegressionContract(proof.validation?.inventory,manifest,profile);
  validatePreparedBytes(proof.assets,proof.packs,proof.source,manifest);
  requireValue(same(receipt.validated_assets,proof.assets)&&same(receipt.validated_packs,proof.packs),
    'Import lacks matching mandatory asset and tarball verification');
  requireValue(receipt.accepted_at===undefined&&receipt.install===undefined,'Import cannot claim npm acceptance or installation');
  return receipt;
}

// This validates evidence, not write authority. Writers additionally require an
// active exact publication attempt and both actual local byte inventories below.
export function validateImportedEvidence(receipt,source,manifest,{ownerRun,ownerJobs,history,metadata}){
  validateImportedShape(receipt,source,manifest);
  const owner=receipt.owner;
  requireValue(String(ownerRun?.id)===String(owner.run_id)&&Number(ownerRun.run_attempt)===Number(owner.run_attempt)&&
    ownerRun.path===WORKFLOW&&ownerRun.head_repository?.full_name===REPO&&ownerRun.head_branch==='main'&&
    ownerRun.event==='workflow_dispatch'&&ownerRun.head_sha===owner.workflow_head_sha&&
    ['in_progress','completed'].includes(ownerRun.status),'Import owner workflow/attempt changed');
  const jobs=ownerJobs.filter(j=>j.name==='prepared-import');
  requireValue(jobs.length===1&&String(jobs[0].id)===String(owner.import_job_id)&&
    jobs[0].status==='completed'&&jobs[0].conclusion==='success','Trusted import job is missing, duplicated, skipped or unsuccessful');
  currentReceiptMetadata(metadata,ownerRun,importName(source));
  // The bound upload follows local byte verification in the trusted import job.
  const start=parseTimestamp(jobs[0].started_at),end=parseTimestamp(jobs[0].completed_at),at=parseTimestamp(metadata.created_at);
  requireValue(start!==null&&end!==null&&start<=at&&at<=end,'Invalid import completion clock');
  validatePreparationHistory(receipt.preparation,history);
  requirePreparationBeforeTrigger({receipt:receipt.preparation,context:history},ownerRun);
  return receipt;
}
export function importedAnchor(receipt,metadata,run){
  requireValue(metadata?.name===importName(receipt.owner)&&positive(metadata.id)&&metadata.expired===false&&
    /^sha256:[a-f0-9]{64}$/.test(metadata.digest||'')&&positive(metadata.size_in_bytes)&&
    String(metadata.workflow_run?.id)===String(receipt.owner.run_id)&&metadata.workflow_run.head_sha===run.head_sha,
    'Import receipt artifact is expired or belongs to another run');
  return {kind:'prepared-import',artifact:{id:String(metadata.id),name:metadata.name,digest:metadata.digest,size:metadata.size_in_bytes},
    receipt_sha256:canonical(receipt),origin:structuredClone(receipt.origin)};
}
export function validateImportAnchor(anchor,source){
  requireValue(anchor?.kind==='prepared-import'&&positive(anchor.artifact?.id)&&anchor.artifact.name===importName(source)&&
    positive(anchor.artifact.size)&&/^sha256:[a-f0-9]{64}$/.test(anchor.artifact.digest||'')&&hash(anchor.receipt_sha256),
    'Invalid current-run import anchor');
  validatePreparationLink(anchor.origin,source);
  return anchor;
}
export function readImportedPreparation(source,manifest){
  validatePreparationSource(source);
  const run=api(`repos/${REPO}/actions/runs/${source.run_id}`);
  const ownerJobs=pages(`repos/${REPO}/actions/runs/${source.run_id}/attempts/${source.run_attempt}/jobs?per_page=10`).flatMap(p=>p.jobs);
  const artifacts=pages(`repos/${REPO}/actions/runs/${source.run_id}/artifacts?per_page=100`).flatMap(p=>p.artifacts);
  const matches=artifacts.filter(a=>a.name===importName(source));
  requireValue(matches.length===1,'Missing or duplicate current-run import receipt');
  const receipt=readVerifiedReceipt(matches[0],'prepared-import.json',{runId:source.run_id,headSha:run.head_sha});
  validateImportedShape(receipt,source,manifest);
  const history=preparationContext(receipt.preparation.source);
  validateImportedEvidence(receipt,source,manifest,{ownerRun:run,ownerJobs,history,metadata:matches[0]});
  const anchor=importedAnchor(receipt,matches[0],run);
  const consumer=readConsumer(source,run,ownerJobs.find(j=>j.name==='prepared-import'),receipt.origin,artifacts);
  return {receipt,anchor,history,run,ownerJobs,consumer,metadata:matches[0]};
}
export function assertImportSelection(result,runId,pin){
  requireValue(validationProfile(result.receipt.validation_profile)===validationProfile(process.env.VALIDATION_PROFILE),'Imported validation profile differs from the requested profile');
  requireValue(positive(runId)&&String(result.receipt.origin.source.run_id)===String(runId),'Import used a different preparation run');
  assertPreparationPin({link:result.receipt.origin},pin);
  return result;
}
export function assertImportPin(result,pin){
  requireValue(positive(pin?.artifact_id)&&/^sha256:[a-f0-9]{64}$/.test(pin.artifact_digest||'')&&hash(pin.receipt_sha256)&&
    String(result.anchor.artifact.id)===String(pin.artifact_id)&&result.anchor.artifact.digest===pin.artifact_digest&&
    result.anchor.receipt_sha256===pin.receipt_sha256,'Current import changed after publication readiness');
  return result;
}
export const importPinFromEnv=()=>({artifact_id:process.env.IMPORTED_ARTIFACT_ID,artifact_digest:process.env.IMPORTED_ARTIFACT_DIGEST,
  receipt_sha256:process.env.IMPORTED_RECEIPT_SHA256});

export function recordPreparedImport(assetsFolder,packsFolder,outputFile){
  const {owner,run,job}=verifyConsumerBeforeImport();
  const result=readPreparedRun(process.env.PREPARED_RUN,process.env.CLI_SHA,process.env.CLI_VERSION);
  assertPreparationPin(result,preparationPinFromEnv());
  validatePreparationLink(result.link,owner);requirePreparationBeforeTrigger(result,run);
  const assets=preparedAssets(assetsFolder,result.receipt.source,result.context.manifest),packs=preparedPacks(packsFolder,result.receipt.source,result.context.manifest);
  requireValue(same(assets,result.receipt.assets)&&same(packs,result.receipt.packs),'Actual imported assets or freshly packed npm bytes differ from complete preparation');
  const receipt=validateImportedShape({schema:1,kind:'prepared-import',state:'verified-copy',validation_profile:validationProfile(result.receipt.validation_profile),owner:{...owner,import_job_id:String(job.id)},
    origin:result.link,preparation:result.receipt,validated_assets:assets,validated_packs:packs,imported_at:new Date().toISOString()},owner,result.context.manifest);
  writeFileSync(outputFile,JSON.stringify(receipt,null,2)+'\n');
  console.log('Recorded verified current-run copies; no npm submission or public installation claimed');
  return receipt;
}

// Both folders and the readiness pin are mandatory at the irreversible write
// boundary. Optional bytes in the historical validator cannot authorize reuse.
export function assertImportedContents(source,manifest,assetsFolder,packsFolder,pin){
  requireValue(typeof assetsFolder==='string'&&assetsFolder&&typeof packsFolder==='string'&&packsFolder,'Mandatory local asset and tarball folders missing');
  assertActive(source);
  const result=readImportedPreparation(source,manifest);
  assertImportSelection(result,process.env.PREPARED_RUN,preparationPinFromEnv());assertImportPin(result,pin);
  const original=result.receipt.preparation.source;
  requireValue(same(preparedAssets(assetsFolder,original,manifest),result.receipt.preparation.assets)&&
    same(preparedPacks(packsFolder,original,manifest),result.receipt.preparation.packs),
    'Mandatory publication byte verification failed');
  assertActive(source);
  return result;
}
export function verifyImportReadiness(){
  const {owner}=currentPublicationOwner(process.env.CLI_SHA,process.env.CLI_VERSION);
  const {manifest}=preparationInputs(owner.sha,owner.version);
  const result=readImportedPreparation(owner,manifest);
  assertImportSelection(result,process.env.PREPARED_RUN,preparationPinFromEnv());
  output({imported_artifact_id:result.anchor.artifact.id,imported_artifact_digest:result.anchor.artifact.digest,
    imported_receipt_sha256:result.anchor.receipt_sha256});
  return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    if(process.argv[2]==='record'&&process.argv.length===6)recordPreparedImport(...process.argv.slice(3));
    else if(process.argv[2]==='readiness'&&process.argv.length===3)verifyImportReadiness();
    else if(process.argv[2]==='consumer'&&process.argv.length===3)verifyConsumerBeforeImport();
    else throw Error('Expected record <assets> <packs> <receipt>, consumer or readiness');
  }catch(error){console.error(error.message);process.exitCode=1;}
}

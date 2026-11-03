import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,writeFileSync,rmSync,appendFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateSource,validateScoped,validateAlias,RELEASE_ARTIFACT_CLEANUP_POLICY} from './release-publication.mjs';
import {validateAcceptedScoped,validateAcceptedAlias,validateVerified,validateArmVerified} from './publication-acceptance.mjs';
import {regressionStatus,validationProfile,validateRegressionContract} from './release-regression-contract.mjs';
import {validatePreparationHistory,validatePreparationSource,preparationInputs} from './release-preparation.mjs';
import {validateImportedShape,validateImportedEvidence,importedAnchor,validateConsumerIntent,importName,consumerName} from './prepared-import.mjs';

export const REPOSITORY='risense-ai/respire-cli';
export const CLEANUP_POLICY=RELEASE_ARTIFACT_CLEANUP_POLICY;
const RELEASE='.github/workflows/release.yml', ALIAS='.github/workflows/npm-alias.yml', VERIFY='.github/workflows/verify-publication.yml', CI='.github/workflows/ci.yml';
const id=value=>Number.isSafeInteger(Number(value))&&Number(value)>0;
const timestamp=value=>{const n=Date.parse(value);if(!Number.isFinite(n))throw Error('Missing terminal timestamp');return n;};
const terminal=run=>run.status==='completed';
const workflow=(run,file)=>run.path===file&&run.head_repository?.full_name===REPOSITORY;
const samePolicy=p=>p?.schema===1&&p.after_consumers_seconds===3600&&Object.keys(p).length===2;
export function requireRegressions(jobs,targets,inventory){
  if(inventory){
    if(regressionStatus(jobs,inventory)!=='success')throw Error('All declared regressions must finish successfully');
    if(jobs.some(j=>j.status!=='completed')||!jobs.some(j=>j.name==='publish'&&j.conclusion==='success'))throw Error('Source consumers/publisher are not complete');
    return;
  }
  const native=jobs.filter(j=>j.name.includes('native-regression / Native ('));
  const cloud=jobs.filter(j=>j.name.startsWith('cloud-sweep ('));
  const api=jobs.filter(j=>j.name==='api-smoke');
  if(native.length!==4||cloud.length!==3||api.length!==1||new Set(native.map(j=>j.name)).size!==4||new Set(cloud.map(j=>j.name)).size!==3||!targets.every(t=>native.some(j=>j.name.endsWith(`Native (${t})`)))||!targets.filter(t=>t!=='x86_64-unknown-linux-gnu').every(t=>cloud.some(j=>j.name.includes(t)))||[...native,...cloud,...api].some(j=>j.status!=='completed'||j.conclusion!=='success'))throw Error('All eight regressions must finish successfully');
  if(jobs.some(j=>j.status!=='completed')||!jobs.some(j=>j.name==='publish'&&j.conclusion==='success'))throw Error('Source consumers/publisher are not complete');
}
export function requirePublished(release,scoped,tag){
  const s=scoped.source;
  if(release.id!==Number(s.release_id)||release.draft!==false||!release.published_at||release.tag_name!==`v${s.version}`||release.target_commitish!==s.sha||release.prerelease!==(s.channel==='dev')||tag?.type!=='commit'||tag.sha!==s.sha)throw Error('Exact public release/tag required');
  if(release.assets.length!==scoped.assets.length||!scoped.assets.every(e=>release.assets.some(a=>a.name===e.name&&a.size===e.size&&a.state==='uploaded'&&a.digest===`sha256:${e.sha256}`)))throw Error('Public release assets differ');
}
export function allowedSourceArtifact(name,source,targets,preparedOrigin){
  if(preparedOrigin&&[importName(source),consumerName(source)].includes(name))return true;
  if([`scoped-ready-${source.run_id}-${source.run_attempt}`,`scoped-accepted-${source.run_id}-${source.run_attempt}`,`npm-submissions-${source.run_id}-${source.run_attempt}`,`publication-accepted-${source.run_id}-${source.run_attempt}`,`npm-publication-packages-${source.run_id}-${source.run_attempt}`].includes(name))return true;
  if(['npm-release-packages','npm-release-validation','dev-api-coverage','gnu-login-interruption'].includes(name))return true;
  return targets.some(t=>['cli-release-','release-sweep-','base-release-sweep-','resident-concurrency-','published-upgrades-','native-profile-migration-','native-profile-migration-fixture-','secret-service-profile-migration-'].some(p=>name===p+t));
}
function boundArtifact(a,run){
  if(!id(a.id)||a.expired||a.workflow_run?.id!==run.id||a.workflow_run?.head_sha!==run.head_sha||!/^sha256:[a-f0-9]{64}$/.test(a.digest||''))throw Error('Artifact identity/digest/attempt changed');
}
function runStamp(r){return [r.id,r.run_attempt,r.status,r.conclusion,r.updated_at,r.head_sha,r.path];}
async function preparedCleanupEvidence(io,scoped,manifest,run,jobs,artifacts){
  if(typeof io.preparedHistory!=='function')throw Error('Prepared source history reader unavailable; cleanup refused');
  const source=scoped.source,imports=artifacts.filter(a=>a.name===importName(source)&&!a.expired),intents=artifacts.filter(a=>a.name===consumerName(source)&&!a.expired);
  if(imports.length!==1||intents.length!==1)throw Error('Prepared import/consumer proof missing or duplicated');
  for(const a of [...imports,...intents])boundArtifact(a,run);
  const receipt=await io.receipt(imports[0],'prepared-import.json');
  validateImportedShape(receipt,source,manifest);
  if(validationProfile(receipt.validation_profile)!==validationProfile(scoped.validation_profile))throw Error('Cleanup preparation profile differs from acceptance');
  const history=await io.preparedHistory(receipt.preparation.source);
  validateImportedEvidence(receipt,source,manifest,{ownerRun:run,ownerJobs:jobs,history,metadata:imports[0]});
  const actual=scoped.assets.map(a=>({file:a.name,size:a.size,sha256:a.sha256})).sort((a,b)=>a.file.localeCompare(b.file));
  const original=[...receipt.preparation.assets].sort((a,b)=>a.file.localeCompare(b.file));
  if(JSON.stringify(actual)!==JSON.stringify(original))throw Error('Public assets differ from original prepared bytes');
  if(JSON.stringify(importedAnchor(receipt,imports[0],run))!==JSON.stringify(scoped.validation_origin))throw Error('Prepared cleanup origin changed after acceptance');
  const intent=await io.receipt(intents[0],'prepared-consumer.json');
  validateConsumerIntent(intent,source,receipt.origin,run,jobs.find(j=>j.name==='prepared-import'),intents[0]);
  if(jobs.some(j=>j.status!=='completed')||!jobs.some(j=>j.name==='publish'&&j.conclusion==='success'))throw Error('Source consumers/publisher are not complete');
  return {receipt,manifest};
}
export async function planCleanup(io,runId,manifest,now=io.now()){
  if(io.repository!==REPOSITORY||!id(runId))throw Error('Cleanup repository/run scope refused');
  const run=await io.run(runId);
  if(!workflow(run,RELEASE)||!['push','workflow_dispatch'].includes(run.event)||!terminal(run)||run.conclusion!=='success')return {skip:'source-not-successfully-complete'};
  const artifacts=await io.artifacts(run.id);
  const accepted=artifacts.some(a=>a.name===`scoped-accepted-${run.id}-${run.run_attempt}`&&!a.expired);
  const readyFile=accepted?'scoped-accepted':'scoped-ready';
  const ready=artifacts.filter(a=>a.name===`${readyFile}-${run.id}-${run.run_attempt}`&&!a.expired);
  if(ready.length!==1)return {skip:'no-unique-scoped-receipt'};
  boundArtifact(ready[0],run);
  const scoped=await io.receipt(ready[0],`${readyFile}.json`);
  // An explicit opt-in written by NEW publication code prevents retroactive
  // deletion of historical artifacts not covered by a confirmed batch.
  if(!samePolicy(scoped.cleanup_policy))return {skip:'historical-release-not-opted-in'};
  const source=validateSource(scoped.source);
  if(source.recovery||String(source.run_id)!==String(run.id)||Number(source.run_attempt)!==run.run_attempt)return {skip:'unsupported-or-stale-attempt'};
  if(io.manifestForSource)manifest=await io.manifestForSource(source);
  (accepted?validateAcceptedScoped:validateScoped)(scoped,manifest);
  if(!accepted){
    if(validationProfile(scoped.validation_profile)!=='full')throw Error('Legacy cleanup receipts are full-only');
    if(scoped.validation_inventory)validateRegressionContract(scoped.validation_inventory,manifest,'full');
  }
  const jobs=await io.jobs(run.id,run.run_attempt);
  const prepared=scoped.validation_origin?await preparedCleanupEvidence(io,scoped,manifest,run,jobs,artifacts):null;
  if(!prepared)requireRegressions(jobs,manifest.targets.map(t=>t.triple),scoped.validation_inventory);
  const release=await io.release(source.release_id),tag=await io.tag(`v${source.version}`);requirePublished(release,scoped,tag);
  // Include even unsuccessful/duplicate/manual alias consumers. Unbound manual
  // inputs are not exposed in run metadata, so this barrier is conservative.
  const consumers=await io.consumers(run.created_at);
  if(consumers.some(r=>!workflow(r,ALIAS)||!terminal(r)))return {skip:'alias-consumer-still-active'};
  if(typeof io.otherReaders!=='function')throw Error('Artifact reader enumeration unavailable; cleanup refused');
  const readers=await io.otherReaders(run.created_at);
  if(readers.some(r=>!workflow(r,CI)||r.event!=='workflow_dispatch'||!terminal(r)))return {skip:'artifact-reader-still-active'};
  const readerFinishes=[];
  for(const reader of readers){
    const readerJobs=await io.jobs(reader.id,reader.run_attempt);
    if(readerJobs.some(j=>j.status!=='completed'))return {skip:'artifact-reader-jobs-not-terminal'};
    readerFinishes.push(timestamp(reader.updated_at),...readerJobs.map(j=>timestamp(j.completed_at||reader.updated_at)));
  }
  let provedAlias=false;const aliasArtifacts=[],aliasReceipts=[],consumerFinishes=[];
  for(const consumer of consumers){
    const childJobs=await io.jobs(consumer.id,consumer.run_attempt);
    if(childJobs.some(j=>j.status!=='completed'))return {skip:'alias-jobs-not-terminal'};
    consumerFinishes.push(...childJobs.map(j=>timestamp(j.completed_at||consumer.updated_at)));
    const aliasFile=accepted?'alias-accepted':'alias-ready';
    const name=`${aliasFile}-${run.id}-${run.run_attempt}-${consumer.id}-${consumer.run_attempt}`;
    for(const a of (await io.artifacts(consumer.id)).filter(a=>a.name===name&&!a.expired)){
      boundArtifact(a,consumer);
      const receipt=await io.receipt(a,`${aliasFile}.json`);
      (accepted?validateAcceptedAlias:validateAlias)(receipt,scoped,consumer,childJobs);provedAlias=true;aliasArtifacts.push(a);aliasReceipts.push(receipt);
    }
  }
  if(!provedAlias)return {skip:'no-completed-alias-install-proof'};
  // Protocol 2 acceptance is never installation proof. Every background reader
  // must finish, and at least one exact successful content/install report remains.
  const verifiers=accepted?await io.verifiers(run.created_at):[],verificationArtifacts=[];
  let provedPublic=!accepted;
  const needsArm=accepted&&manifest.targets.some(t=>t.triple==='aarch64-unknown-linux-gnu');
  let provedArm=!needsArm;
  if(verifiers.some(r=>!workflow(r,VERIFY)||!terminal(r)))return {skip:'public-verification-still-active'};
  for(const verifier of verifiers){
    const verifierJobs=await io.jobs(verifier.id,verifier.run_attempt);
    if(verifierJobs.some(j=>j.status!=='completed'))return {skip:'public-verification-jobs-not-terminal'};
    consumerFinishes.push(...verifierJobs.map(j=>timestamp(j.completed_at||verifier.updated_at)));
    const name=`publication-verified-${run.id}-${run.run_attempt}-${verifier.id}-${verifier.run_attempt}`;
    for(const a of (await io.artifacts(verifier.id)).filter(a=>a.name===name&&!a.expired)){
      boundArtifact(a,verifier);
      if(verifier.conclusion!=='success'||!verifierJobs.some(j=>j.name==='verify-publication'&&j.conclusion==='success'))throw Error('Public verification workflow/job failed');
      const receipt=await io.receipt(a,'publication-verified.json');
      const alias=aliasReceipts.find(r=>JSON.stringify(r.publisher)===JSON.stringify(receipt.alias_publisher));
      if(!alias)throw Error('Verified report has no accepted alias publisher');
      validateVerified(receipt,scoped,alias);provedPublic=true;verificationArtifacts.push(a);
    }
    const armName=`publication-arm64-verified-${run.id}-${run.run_attempt}-${verifier.id}-${verifier.run_attempt}`;
    for(const a of (await io.artifacts(verifier.id)).filter(a=>a.name===armName&&!a.expired)){
      boundArtifact(a,verifier);
      if(!needsArm||verifier.conclusion!=='success'||!verifierJobs.some(j=>j.name==='verify-publication-arm64'&&j.conclusion==='success'))throw Error('Native ARM64 public verification job failed or is unexpected');
      const receipt=await io.receipt(a,'publication-arm64-verified.json');
      const alias=aliasReceipts.find(r=>JSON.stringify(r.publisher)===JSON.stringify(receipt.alias_publisher));
      if(!alias)throw Error('ARM64 verified report has no accepted alias publisher');
      validateArmVerified(receipt,scoped,alias);provedArm=true;verificationArtifacts.push(a);
    }
  }
  if(!provedPublic)return {skip:'no-completed-public-install-proof'};
  if(!provedArm)return {skip:'no-native-arm64-public-install-proof'};
  const selected=artifacts.filter(a=>!a.expired&&allowedSourceArtifact(a.name,source,manifest.targets.map(t=>t.triple),scoped.validation_origin));
  for(const a of selected)boundArtifact(a,run);
  const all=[...selected,...aliasArtifacts,...verificationArtifacts];
  const finished=Math.max(timestamp(run.updated_at),timestamp(release.published_at),...jobs.map(j=>timestamp(j.completed_at||run.updated_at)),...consumers.map(r=>timestamp(r.updated_at)),...verifiers.map(r=>timestamp(r.updated_at)),...consumerFinishes,...readerFinishes,...all.map(a=>timestamp(a.created_at)));
  if(now-finished<3600_000)return {skip:'one-hour-after-consumers-not-reached',eligible_at:new Date(finished+3600_000).toISOString()};
  // Keep proof until the payloads are gone. A partial failure leaves receipts
  // intact where possible; subsequent invocations inventory again, never retry
  // an uncertain DELETE blindly.
  const payload=selected.filter(a=>a.id!==ready[0].id);
  return {run,source,scoped,release,tag,consumers,verifiers,readers,prepared,finished,artifacts:[...payload,...aliasArtifacts,...verificationArtifacts,ready[0]],preserved:artifacts.filter(a=>!all.some(x=>x.id===a.id)).map(a=>({id:a.id,name:a.name}))};
}
export async function executeCleanup(io,plan,{apply=false,now=()=>io.now(),audit=()=>{}}={}){
  if(plan.skip){audit(plan);return [];}
  const deleted=[];
  for(const expected of plan.artifacts){
    // Recheck the ENTIRE source and every consumer before EACH deletion. In
    // particular, child completion alone cannot erase a receipt awaitAlias is
    // still downloading in the live parent Release.
    const current=await io.run(plan.run.id),consumers=await io.consumers(plan.run.created_at);
    const readers=await io.otherReaders(plan.run.created_at);
    if(readers.some(r=>!workflow(r,CI)||r.event!=='workflow_dispatch'||!terminal(r))||JSON.stringify(readers.map(runStamp).sort())!==JSON.stringify(plan.readers.map(runStamp).sort()))throw Error('Artifact reader consumption fence changed; cleanup stopped');
    for(const reader of readers){
      const jobs=await io.jobs(reader.id,reader.run_attempt);
      if(jobs.some(j=>j.status!=='completed'||timestamp(j.completed_at||reader.updated_at)>plan.finished))throw Error('Artifact reader jobs consumption fence changed; cleanup stopped');
    }
    if(plan.prepared){
      validatePreparationHistory(plan.prepared.receipt.preparation,await io.preparedHistory(plan.prepared.receipt.preparation.source));
    }
    const verifiers=plan.scoped.schema===2?await io.verifiers(plan.run.created_at):[];
    if(verifiers.some(r=>!workflow(r,VERIFY)||!terminal(r))||JSON.stringify(verifiers.map(runStamp).sort())!==JSON.stringify(plan.verifiers.map(runStamp).sort()))throw Error('Verification consumption fence changed; cleanup stopped');
    if(!workflow(current,RELEASE)||consumers.some(r=>!workflow(r,ALIAS))||JSON.stringify(runStamp(current))!==JSON.stringify(runStamp(plan.run))||!terminal(current)||current.conclusion!=='success'||consumers.some(r=>!terminal(r))||JSON.stringify(consumers.map(runStamp).sort())!==JSON.stringify(plan.consumers.map(runStamp).sort())||now()-plan.finished<3600_000)throw Error('Consumption fence changed; cleanup stopped');
    requirePublished(await io.release(plan.source.release_id),plan.scoped,await io.tag(`v${plan.source.version}`));
    const actual=await io.artifact(expected.id);
    if(actual===null){audit({action:'already-absent',id:expected.id});continue;}
    if(actual.id!==expected.id||actual.name!==expected.name||actual.digest!==expected.digest||actual.size_in_bytes!==expected.size_in_bytes||actual.workflow_run?.id!==expected.workflow_run.id||actual.workflow_run?.head_sha!==expected.workflow_run.head_sha)throw Error('Artifact changed; cleanup stopped');
    audit({action:apply?'delete':'would-delete',run:plan.run.id,attempt:plan.run.run_attempt,release:plan.source.version,id:actual.id,name:actual.name,bytes:actual.size_in_bytes,digest:actual.digest});
    if(apply){await io.deleteArtifact(actual.id);if(await io.artifact(actual.id)!==null)throw Error('DELETE not verified absent; inspect before retrying');deleted.push(actual.id);}
  }
  return deleted;
}

export function githubAdapter(repository=process.env.GITHUB_REPOSITORY,{transport}={}){
  const command=transport||((args,options={})=>execFileSync('gh',args,{encoding:'utf8',timeout:30000,maxBuffer:16*1024*1024,...options}));
  const api=p=>JSON.parse(command(['api',p]));
  const pages=p=>JSON.parse(command(['api','--paginate','--slurp',p]));
  const base=`repos/${repository}`;
  const adapter={repository,
    now:()=>{
      const headers=command(['api','--include','--method','HEAD',base]);
      const dates=[...headers.matchAll(/^date:\s*([^\r\n]+)$/gim)];
      if(dates.length!==1)throw Error('GitHub service time is missing or ambiguous');
      return timestamp(dates[0][1]);
    },
    run:id=>api(`${base}/actions/runs/${id}`),
    jobs:(id,attempt)=>pages(`${base}/actions/runs/${id}/attempts/${attempt}/jobs?per_page=100`).flatMap(p=>p.jobs),
    artifacts:id=>pages(`${base}/actions/runs/${id}/artifacts?per_page=100`).flatMap(p=>p.artifacts),
    consumers:created=>pages(`${base}/actions/workflows/npm-alias.yml/runs?per_page=100&created=%3E%3D${encodeURIComponent(created)}`).flatMap(p=>p.workflow_runs),
    verifiers:created=>pages(`${base}/actions/workflows/verify-publication.yml/runs?per_page=100&created=%3E%3D${encodeURIComponent(created)}`).flatMap(p=>p.workflow_runs),
    otherReaders:created=>pages(`${base}/actions/workflows/ci.yml/runs?event=workflow_dispatch&per_page=100&created=%3E%3D${encodeURIComponent(created)}`).flatMap(p=>p.workflow_runs),
    manifestForSource:source=>{
      validateSource(source);
      const m=JSON.parse(execFileSync('git',['show',`${source.sha}:npm/artifact-manifest.json`],{encoding:'utf8',maxBuffer:65536}));
      m.cliVersion=source.version;return m;
    },
    preparedHistory:source=>{
      validatePreparationSource(source);
      const selected=pages(`${base}/actions/workflows/ci.yml/runs?head_sha=${source.sha}&per_page=100`).flatMap(p=>p.workflow_runs)
        .filter(r=>r.head_sha===source.sha&&r.event==='push'&&r.head_branch==='main').sort((a,b)=>b.id-a.id)[0];
      if(!selected)throw Error('Exact main push CI history unavailable');
      return {source,...preparationInputs(source.sha,source.version),run:adapter.run(source.run_id),
        jobs:adapter.jobs(source.run_id,source.run_attempt),ci:adapter.run(selected.id)};
    },
    release:id=>api(`${base}/releases/${id}`),
    tag:name=>{let o=api(`${base}/git/ref/tags/${name}`).object;for(let i=0;o?.type==='tag'&&i<5;i++)o=api(`${base}/git/tags/${o.sha}`).object;return o;},
    artifact:id=>{try{return api(`${base}/actions/artifacts/${id}`);}catch(e){if(String(e.stderr).includes('(HTTP 404)'))return null;throw e;}},
    deleteArtifact:id=>{command(['api','--method','DELETE',`${base}/actions/artifacts/${id}`]);},
  };
  // Archive contents are data only: exactly one bounded JSON file, never an
  // extracted/executed checkout, script, or path supplied by the artifact.
  adapter.receipt=(artifact,name)=>{
    if(artifact.size_in_bytes>128*1024)throw Error('Receipt ZIP too large');
    const temp=mkdtempSync(path.join(process.env.RUNNER_TEMP||tmpdir(),'release-cleanup-'));
    try{
      const zip=path.join(temp,'receipt.zip'),bytes=command(['api',`${base}/actions/artifacts/${artifact.id}/zip`],{encoding:'buffer',maxBuffer:128*1024});
      if(createHash('sha256').update(bytes).digest('hex')!==artifact.digest.slice(7))throw Error('Receipt ZIP digest mismatch');
      writeFileSync(zip,bytes);
      const names=execFileSync('unzip',['-Z1',zip],{encoding:'utf8',maxBuffer:4096}).trim().split('\n');
      if(names.length!==1||names[0]!==name)throw Error('Unexpected receipt ZIP inventory');
      return JSON.parse(execFileSync('unzip',['-p',zip,name],{encoding:'utf8',maxBuffer:1024*1024}));
    }finally{rmSync(temp,{recursive:true,force:true});}
  };
  return adapter;
}
export async function main(){
  const apply=process.argv.includes('--apply');
  if(process.argv.slice(2).some(a=>!['--apply','--dry-run'].includes(a))||process.argv.includes('--apply')&&process.argv.includes('--dry-run'))throw Error('Use --dry-run or --apply');
  const io=githubAdapter();if(io.repository!==REPOSITORY)throw Error('Repository scope refused');
  const manifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
  const since=new Date(io.now()-48*3600_000).toISOString();
  const runs=JSON.parse(execFileSync('gh',['api','--paginate','--slurp',`repos/${REPOSITORY}/actions/workflows/release.yml/runs?status=completed&per_page=100&created=%3E%3D${encodeURIComponent(since)}`],{encoding:'utf8',maxBuffer:16*1024*1024})).flatMap(p=>p.workflow_runs);
  const audit=value=>{const line=JSON.stringify(value);console.log(line);if(process.env.GITHUB_STEP_SUMMARY)appendFileSync(process.env.GITHUB_STEP_SUMMARY,`\n\`\`\`json\n${line}\n\`\`\`\n`);};
  for(const run of runs){try{const plan=await planCleanup(io,run.id,manifest);audit({mode:apply?'apply':'dry-run',source_run:run.id,skip:plan.skip||null,preserved:plan.preserved||[]});await executeCleanup(io,plan,{apply,audit});}catch(error){audit({source_run:run.id,error:error.message});throw error;}}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});

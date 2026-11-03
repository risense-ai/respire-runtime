// Digest-checked JSON only. Never execute or extract an artifact checkout.
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const REPO='risense-ai/respire-cli',MAX_ZIP=128*1024,MAX_JSON=1024*1024;
const positive=v=>/^[1-9]\d*$/.test(String(v))&&Number.isSafeInteger(Number(v));
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const files=['release-prepared.json','prepared-import.json','prepared-consumer.json'];
export function readVerifiedReceipt(metadata,file,{repository=REPO,runId,headSha,transport}={}){
  requireValue(repository===REPO&&files.includes(file)&&positive(runId)&&/^[a-f0-9]{40}$/.test(headSha||'')&&
    positive(metadata?.id)&&metadata.expired===false&&String(metadata.workflow_run?.id)===String(runId)&&
    metadata.workflow_run.head_sha===headSha&&/^sha256:[a-f0-9]{64}$/.test(metadata.digest||'')&&
    Number.isSafeInteger(metadata.size_in_bytes)&&metadata.size_in_bytes>0&&metadata.size_in_bytes<=MAX_ZIP,
    'Receipt artifact is foreign, expired, oversized or undigested');
  const command=transport||((name,args,options)=>{
    requireValue(process.env.GH_TOKEN,'Bound receipt reads require the explicit workflow GH_TOKEN');
    return execFileSync(name,args,{timeout:60000,...options});
  });
  const folder=mkdtempSync(join(process.env.RUNNER_TEMP||tmpdir(),'verified-receipt-'));
  try{
    let bytes;
    try{
      // Same GitHub CLI API transport as the existing audited cleanup reader;
      // no manually forwarded bearer/cookie/referrer on storage redirects.
      bytes=command('gh',['api','--hostname','github.com',`repos/${REPO}/actions/artifacts/${metadata.id}/zip`],
        {encoding:'buffer',maxBuffer:MAX_ZIP});
    }catch(error){
      const status=String(error.stderr||'').match(/HTTP\s+(\d{3})/)?.[1];
      throw Error(`Bound receipt download failed for ${REPO} artifact ${metadata.id}${status?` (HTTP ${status})`:''}`);
    }
    requireValue(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=MAX_ZIP&&
      createHash('sha256').update(bytes).digest('hex')===metadata.digest.slice(7),'Receipt ZIP differs from the GitHub artifact digest');
    const zip=join(folder,'receipt.zip');writeFileSync(zip,bytes);
    const names=execFileSync('unzip',['-Z1',zip],{encoding:'utf8',timeout:10000,maxBuffer:4096}).trim().split(/\r?\n/);
    requireValue(names.length===1&&names[0]===file,'Unexpected receipt ZIP inventory');
    const json=execFileSync('unzip',['-p',zip,file],{encoding:'utf8',timeout:10000,maxBuffer:MAX_JSON});
    return JSON.parse(json);
  }finally{rmSync(folder,{recursive:true,force:true});}
}

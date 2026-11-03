import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readVerifiedReceipt} from './verified-receipt.mjs';

function archive(entries){
  const folder=mkdtempSync(join(tmpdir(),'receipt-zip-test-'));
  try{
    const path=join(folder,'sample.zip');
    const result=spawnSync('python3',['-c','import json,sys,zipfile\nwith zipfile.ZipFile(sys.argv[1],"w",compression=zipfile.ZIP_DEFLATED) as z:\n for name,text in json.loads(sys.argv[2]): z.writestr(name,text)',path,JSON.stringify(entries)],
      {env:{PATH:process.env.PATH,HOME:folder,TMPDIR:folder},encoding:'utf8',timeout:10000});
    assert.equal(result.status,0,result.stderr);return readFileSync(path);
  }finally{rmSync(folder,{recursive:true,force:true});}
}
function metadata(bytes){return {id:90,size_in_bytes:bytes.length,digest:'sha256:'+createHash('sha256').update(bytes).digest('hex'),
  expired:false,workflow_run:{id:700,head_sha:'a'.repeat(40)}};}
function read(bytes,meta=metadata(bytes),file='release-prepared.json',transport){
  return readVerifiedReceipt(meta,file,{repository:'risense-ai/respire-cli',runId:700,headSha:'a'.repeat(40),transport:transport||((name,args,options)=>{
    assert.equal(name,'gh');assert.deepEqual(args,['api','--hostname','github.com','repos/risense-ai/respire-cli/actions/artifacts/90/zip']);
    assert.equal(options.encoding,'buffer');return bytes;
  })});
}
test('receipt JSON is decoded only after independently matching the actual ZIP bytes to the bound API digest',()=>{
  const bytes=archive([['release-prepared.json',JSON.stringify({kind:'synthetic',count:4})]]);
  assert.deepEqual(read(bytes),{kind:'synthetic',count:4});
  const changed=Buffer.from(bytes);changed[changed.length-1]^=1;
  assert.throws(()=>read(changed,metadata(bytes)),/ZIP differs/);
});
test('foreign run/SHA, expired, oversized, missing digest and unsafe IDs fail before any download',()=>{
  const bytes=archive([['release-prepared.json','{}']]);
  for(const mutate of [m=>m.workflow_run.id=701,m=>m.workflow_run.head_sha='f'.repeat(40),m=>m.expired=true,
    m=>m.size_in_bytes=128*1024+1,m=>delete m.digest,m=>m.id='90/../../other']){
    const m=metadata(bytes);mutate(m);let calls=0;
    assert.throws(()=>read(bytes,m,'release-prepared.json',()=>{calls++;return bytes;}));assert.equal(calls,0);
  }
});
test('ZIP path traversal, duplicate entries, additional files and other receipt types cannot enter the decoder',()=>{
  for(const entries of [[['../release-prepared.json','{}']],[['release-prepared.json','{}'],['release-prepared.json','{}']],
    [['release-prepared.json','{}'],['unexpected.sh','not executable data']]]){
    const bytes=archive(entries);assert.throws(()=>read(bytes),/ZIP inventory/);
  }
  assert.throws(()=>read(archive([['source.js','{}']]),undefined,'source.js'));
});
test('download errors report only the scoped target and status, never response credentials or signed URLs',()=>{
  const bytes=archive([['release-prepared.json','{}']]);
  const result=()=>read(bytes,metadata(bytes),'release-prepared.json',()=>{
    const e=new Error('synthetic-secret https://blob.invalid/?sig=synthetic-signature');e.stderr='HTTP 403 synthetic-secret';throw e;
  });
  assert.throws(result,error=>error.message.includes('artifact 90')&&error.message.includes('HTTP 403')&&
    !error.message.includes('synthetic-secret')&&!error.message.includes('sig='));
});

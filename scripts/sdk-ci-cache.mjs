import {createHash} from 'node:crypto';
import {existsSync,lstatSync,mkdtempSync,readFileSync,readdirSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {prepareSdk} from '../crates/core-sdk/prepare-sdk.mjs';

export const TARGETS=['x86_64-pc-windows-msvc','aarch64-pc-windows-msvc','aarch64-apple-darwin','x86_64-apple-darwin','x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-unknown-linux-musl','aarch64-unknown-linux-musl'];
const required=(ok,message)=>{if(!ok)throw Error(message);};
export function canonicalEntry(target,input){
 required(TARGETS.includes(target)&&input&&input.private_repository==='risense-ai/respire-core','Only approved private Core SDK targets are accepted');
 const v=input.sdk_version;required(/^(?:1\.0\.2|1\.1\.0)-dev\.[1-9][0-9]*$/.test(v||'')&&input.release_tag===`sdk-v${v}`,'Invalid private SDK tag/version');
 const base=`https://github.com/risense-ai/respire-core/releases/download/sdk-v${v}/respire-core-sdk-${target}`;
 required(input.url===base+'.manifest.json'&&input.archive_url===base+'.tar.gz'&&/^[a-f0-9]{64}$/.test(input.manifest_sha256||'')&&/^[a-f0-9]{64}$/.test(input.archive_sha256||'')&&input.redistribution==='approved','Invalid SDK cache identity/hash/license');
 // Never forward unknown source-controlled fields into a credential-bearing job.
 return {sdk_version:v,private_repository:'risense-ai/respire-core',release_tag:`sdk-v${v}`,url:base+'.manifest.json',archive_url:base+'.tar.gz',manifest_sha256:input.manifest_sha256,archive_sha256:input.archive_sha256,redistribution:'approved'};
}
export function cacheKey(target,entry){return `core-sdk-native-v1-${target}-${createHash('sha256').update(JSON.stringify(canonicalEntry(target,entry))).digest('hex')}`;}
export function planCaches(lock,crateLock){
 required(lock.schema_version===1&&crateLock.schema_version===1&&lock.targets&&crateLock.targets,'Invalid SDK lock schema');
 const targets=TARGETS.filter(t=>Object.hasOwn(lock.targets,t));
 required(targets.length===TARGETS.length&&Object.keys(lock.targets).length===targets.length&&Object.keys(crateLock.targets).length===targets.length&&targets.every(t=>Object.hasOwn(crateLock.targets,t)),'Require exact current SDK locks for all eight release targets');
 const include=targets.map(target=>{const entry=canonicalEntry(target,lock.targets[target]);required(JSON.stringify(entry)===JSON.stringify(canonicalEntry(target,crateLock.targets[target])),'SDK lock copies differ');return {target,entry,key:cacheKey(target,entry)};});
 required(new Set(include.map(x=>x.entry.sdk_version)).size===1,'Mixed private SDK versions');return {include};
}
export function auditSdkDirectory(directory,target,entry){
 const raw=readFileSync(join(directory,'manifest.json'));required(createHash('sha256').update(raw).digest('hex')===entry.manifest_sha256,'Cached SDK manifest hash mismatch');const m=JSON.parse(raw);
 required(m.target===target&&m.sdk_version===entry.sdk_version&&m.abi_version===0x10002&&m.inference_thread_contract===1&&m.association_contract===1&&m.models_bundled===false&&m.redistribution==='permitted-under-included-license','Cached SDK contract/license mismatch');
 const expected=new Map([['manifest.json',entry.manifest_sha256]]);
 for(const f of m.files){required(typeof f.path==='string'&&!/\.(?:rs|cpp|cc|c|py|onnx|pt|safetensors|pdb|bc|ll|key|pem|env)$/i.test(f.path)&&!f.path.includes('\\')&&f.path.split('/').every(p=>p&&p!=='.'&&p!=='..')&&(f.path==='LICENSE.txt'||f.path==='include/respire_core.h'||/^lib\/[^/]+\.(a|lib)$/.test(f.path)||/^runtime\/[^/]+\.(dll|dylib|so(?:\.[0-9.]+)?)$/.test(f.path)||(m.mlx_backend_contract===1&&f.path==='runtime/mlx.metallib')||/^notices\//.test(f.path))&&!expected.has(f.path),'Unsafe/duplicate SDK cache path');expected.set(f.path,f.sha256);}
 const seen=new Set();const visit=(dir,prefix='')=>{for(const name of readdirSync(dir)){const path=prefix+name,full=join(dir,name),stat=lstatSync(full);required(!stat.isSymbolicLink(),'SDK cache link forbidden');if(stat.isDirectory())visit(full,path+'/');else{required(stat.isFile()&&expected.has(path)&&createHash('sha256').update(readFileSync(full)).digest('hex')===expected.get(path),'Unexpected/corrupt SDK cache file');seen.add(path);}}};visit(directory);required(seen.size===expected.size,'Incomplete SDK cache');return m;
}
function readLock(path){required(lstatSync(path).isFile()&&lstatSync(path).size<=65536,'SDK lock file must be bounded ordinary JSON');return JSON.parse(readFileSync(path,'utf8'));}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [command,...args]=process.argv.slice(2);
 if(command==='plan'){console.log(JSON.stringify(planCaches(readLock(args[0]),readLock(args[1]))));}
 else if(command==='key'){const target=args[0],lock=readLock('sdk/core-sdk.lock.json'),entry=lock.targets[target];required(entry,'Unknown target');console.log(entry.private_repository?cacheKey(target,entry):'');}
 else if(command==='prepare'){
  const [target,json]=args,entry=canonicalEntry(target,JSON.parse(json));
  required(process.env.GITHUB_REPOSITORY==='risense-ai/respire-runtime'&&process.env.GITHUB_REF==='refs/heads/main'&&process.env.GITHUB_EVENT_NAME==='workflow_dispatch','SDK cache producer is trusted main manual only');
  for(const name of ['RSRS_CORE_SDK_DIR','ONEMEMORY_CORE_SDK_DIR','RESPIRE_CORE_SDK_DIR'])delete process.env[name];
  const temp=mkdtempSync(join(tmpdir(),'sdk-cache-lock-')),path=join(temp,'lock.json'),directory=resolve('.sdk',target);
  required(!existsSync(directory),'Credential-bearing producer requires a fresh SDK directory; cache restore/reuse is forbidden');
  try{writeFileSync(path,JSON.stringify({schema_version:1,targets:{[target]:entry}}));await prepareSdk(target,directory,path);auditSdkDirectory(directory,target,entry);}finally{rmSync(temp,{recursive:true});}
 }else throw Error('Usage: sdk-ci-cache.mjs plan <lock> <crate-lock> | key <target> | prepare <target> <entry-json>');
}

// Durable repository/package/version intent. Release notes outlive temporary
// Actions receipts; absence from the public registry never clears this fence.
import {mkdtempSync,writeFileSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {api,pages,command,manifest,packIdentity} from './release-publication.mjs';
import {readExpectedPacks} from './registry-publication.mjs';
const prefix='<!-- rsrs-npm-write-fence:';
const marker=/<!-- rsrs-npm-write-fence:([A-Za-z0-9_-]+) -->/g;
const id=v=>/^[1-9]\d*$/.test(String(v));
const sha=v=>/^[a-f0-9]{40}$/.test(v||'');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const names=m=>[...new Set([...m.targets.map(t=>t.pkg),m.npmScope,'rsrs-cli'])].sort();
const identities=packages=>packages.map(packIdentity).sort((a,b)=>a.name.localeCompare(b.name));
export function readFence(body=''){
  if(typeof body!=='string')throw Error('Invalid Release body');
  const matches=[...body.matchAll(marker)];
  if(!matches.length){if(body.includes(prefix))throw Error('Malformed persistent npm fence');return null;}
  if(matches.length!==1||body.split(prefix).length!==2||matches[0][1].length>32768)throw Error('Duplicate/oversized persistent npm fence');
  const bytes=Buffer.from(matches[0][1],'base64url');
  if(bytes.toString('base64url')!==matches[0][1])throw Error('Noncanonical persistent npm fence');
  const f=JSON.parse(bytes.toString('utf8'));
  if(![1,2].includes(f?.schema)||f.kind!=='npm-version-fence'||f.repository!=='risense-ai/respire-cli'||
    !/^\d+\.\d+\.\d+(?:-dev\.\d+)?$/.test(f.version||'')||!sha(f.source_sha)||!id(f.run_id)||!id(f.first_attempt)||
    !['prepared','fenced'].includes(f.phase)||typeof f.created_at!=='string'||!Number.isFinite(Date.parse(f.created_at))||
    !Array.isArray(f.package_names)||new Set(f.package_names).size!==f.package_names.length||
    (f.phase==='prepared'&&f.scoped_packages!==null)||(f.phase==='fenced'&&!Array.isArray(f.scoped_packages)))throw Error('Invalid persistent npm fence');
  if(f.phase==='fenced')assertFencePackages(f,f.scoped_packages);
  return f;
}
export function fenceBody(body,fence){
  const previous=readFence(body); // Never erase an unparseable or duplicate intent.
  const encoded=prefix+Buffer.from(JSON.stringify(fence)).toString('base64url')+' -->';
  readFence(encoded);
  if(previous){
    for(const key of ['schema','repository','version','source_sha','run_id','first_attempt','created_at'])if(previous[key]!==fence[key])throw Error('Persistent npm intent ownership cannot be replaced');
    if(!same(previous.package_names,fence.package_names)||
      (previous.phase==='fenced'&&(fence.phase!=='fenced'||!same(identities(previous.scoped_packages),identities(fence.scoped_packages)))))throw Error('Persistent npm intent cannot be erased or changed');
  }
  return body.replace(marker,'').trimEnd()+'\n\n'+encoded+'\n';
}
export function fenceContext(){
  const c={repository:process.env.GITHUB_REPOSITORY,version:process.env.CLI_VERSION,
    source_sha:process.env.CLI_SHA,run_id:process.env.GITHUB_RUN_ID,first_attempt:process.env.GITHUB_RUN_ATTEMPT};
  if(c.repository!=='risense-ai/respire-cli'||!/^\d+\.\d+\.\d+(?:-dev\.\d+)?$/.test(c.version||'')||!sha(c.source_sha)||!id(c.run_id)||!id(c.first_attempt))throw Error('Invalid npm fence context');
  return c;
}
export function assertFenceOwner(f,c,m){
  if((f.schema===2)!==(m.npmScope==='rsrs-cli')||f.repository!==c.repository||f.version!==c.version||f.source_sha!==c.source_sha||!same(f.package_names,names(m)))throw Error('Persistent npm fence source/package/version differs');
  if(String(f.run_id)!==String(c.run_id))throw Error(`Version ${c.version} is fenced by previous Release run ${f.run_id}; reconcile read-only and resume the original run or use a new version; registry 404 cannot authorize another submission`);
  return f;
}
export function assertFencePackages(f,packages){
  const expected=f.package_names.filter(name=>f.schema===2||name!=='rsrs-cli').sort();
  if(!Array.isArray(packages)||!same(packages.map(p=>p?.name).sort(),expected)||packages.some(p=>
    p.version!==f.version||!/^sha512-[A-Za-z0-9+/]{86}==$/.test(p.integrity||'')||!/^[a-f0-9]{40}$/.test(p.shasum||'')))throw Error('Persistent npm fence package/version/digest inventory differs');
  if(f.phase==='fenced'&&!same(identities(f.scoped_packages),identities(packages)))throw Error('Previously fenced immutable package content changed');
}
export function assertReusableRelease(release,c,m){
  if(!release)return null;
  const f=readFence(release.body||'');
  if(f)assertFenceOwner(f,c,m); // A changed tag must never hide an earlier owner.
  if(release.draft!==true||release.tag_name!==`v${c.version}`||release.target_commitish!==c.source_sha||release.prerelease!==c.version.includes('-dev.'))throw Error('Existing Release source/version/draft differs: '+JSON.stringify({id:release.id,expected:{tag:`v${c.version}`,source:c.source_sha,draft:true,prerelease:c.version.includes('-dev.')},actual:{tag:release.tag_name,source:release.target_commitish,draft:release.draft,prerelease:release.prerelease}}));
  if(f)return f;
  // A newly allocated DEV reservation has no package writes or assets yet.
  // Existing stable/unbound drafts have no durable no-write evidence: fail closed.
  const owner=(release.body||'').match(/Release workflow run: ([1-9]\d*)/)?.[1];
  if(c.version.includes('-dev.')&&release.assets?.length===0&&owner===String(c.run_id))return null;
  throw Error('Existing draft has no bound npm intent journal; reconcile the original publication before reusing this version');
}
// Discovery reserves identities; it never authorizes a mismatched tag to write.
export function releaseVersionClaims(release){
  const versions=new Set(),valid=v=>typeof v==='string'&&/^v?\d+\.\d+\.\d+(?:-dev\.\d+)?$/.test(v);
  if(valid(release.tag_name))versions.add(release.tag_name.replace(/^v/,''));
  if(release.draft===true&&valid(release.name))versions.add(release.name.replace(/^v/,''));
  const fence=readFence(release.body||'');
  if(fence)versions.add(fence.version);
  return [...versions];
}
export function findVersionRelease(c){
  const found=pages(`repos/${c.repository}/releases?per_page=100`).flat().filter(r=>releaseVersionClaims(r).includes(c.version));
  if(found.length>1)throw Error('Duplicate version Release');
  return found[0]||null;
}
export function checkVersionFence(){
  const c=fenceContext();return assertReusableRelease(findVersionRelease(c),c,manifest());
}
// Planning may retain the historical empty-DEV reservation path, but it must
// inspect a new durable intent BEFORE replacing the old owner/notes.
export function checkReservationFence(){
  const c=fenceContext(),r=findVersionRelease(c),f=r?readFence(r.body||''):null;
  if(f)assertFenceOwner(f,c,manifest());
}
export function bindFenceNotes(){
  const c=fenceContext(),m=manifest(),f=assertReusableRelease(findVersionRelease(c),c,m);
  const packages=readExpectedPacks('npm/dist',m,c.version).map(packIdentity);
  if(f)assertFencePackages(f,packages);
  const next=f||{schema:m.npmScope==='rsrs-cli'?2:1,kind:'npm-version-fence',...c,phase:'prepared',package_names:names(m),scoped_packages:null,created_at:new Date().toISOString()};
  const file=process.env.RELEASE_NOTES_FILE;
  if(!file)throw Error('Missing generated Release notes file');
  writeFileSync(file,fenceBody(readFileSync(file,'utf8'),next));
}
export function persistVersionFence(packages){
  const c=fenceContext(),m=manifest(),release=findVersionRelease(c);
  if(!release)throw Error('Draft missing before npm submission');
  const f=assertReusableRelease(release,c,m);
  if(!f)throw Error('Prepared durable owner missing before npm submission');
  assertFencePackages(f,packages);
  const next={...f,phase:'fenced',scoped_packages:identities(packages)};
  const directory=mkdtempSync(path.join(tmpdir(),'rsrs-npm-fence-'));
  try{
    // Preserve the canonical tag explicitly on a draft body update. Still read
    // back and reject every identity drift; do not normalize an untagged draft.
    const file=path.join(directory,'body.json');writeFileSync(file,JSON.stringify({tag_name:release.tag_name,body:fenceBody(release.body||'',next)}));
    command('gh',['api','--method','PATCH',`repos/${c.repository}/releases/${release.id}`,'--input',file]);
    const confirmed=api(`repos/${c.repository}/releases/${release.id}`);
    const actual=assertReusableRelease(confirmed,c,m);
    if(!same(actual,next))throw Error('Persistent npm fence write not confirmed; no submission is permitted');
  }finally{rmSync(directory,{recursive:true,force:true});}
  return next;
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {fenceBody} from './publication-fence.mjs';

function run({aliasVersion,aliasStatus=200,requested,releases=[]}={}){
  const root=mkdtempSync(join(tmpdir(),'dev-version-reservations-'));
  try{
    const bin=join(root,'bin');mkdirSync(bin);mkdirSync(join(root,'npm'));
    writeFileSync(join(root,'npm/artifact-manifest.json'),JSON.stringify({cliVersion:'1.0.16',npmScope:'@rsrsai/cli',targets:[
      {pkg:'@rsrsai/linux-x64-gnu'},{pkg:'@rsrsai/linux-x64'},{pkg:'@rsrsai/macos-arm64'},{pkg:'@rsrsai/win-x64'}]}));
    writeFileSync(join(bin,'git'),`#!${process.execPath}\nif(process.argv.slice(2).join(' ')!=='tag --list')throw Error('Unexpected git action');console.log('v1.0.16');\n`,{mode:0o755});
    writeFileSync(join(bin,'gh'),`#!${process.execPath}\nconst a=process.argv.slice(2);if(a[0]!=='api'||a[1]!=='repos/risense-ai/respire-cli/releases?per_page=100')throw Error('Unexpected API scope');const r=require('child_process').spawnSync('jq',['-r',a[a.indexOf('--jq')+1]],{input:JSON.stringify([{tag_name:'v1.0.16',draft:false,prerelease:false},...${JSON.stringify(releases)}]),encoding:'utf8'});process.stdout.write(r.stdout);process.stderr.write(r.stderr);process.exitCode=r.status;\n`,{mode:0o755});
    const bootstrap=join(root,'registry.mjs');
    writeFileSync(bootstrap,`globalThis.fetch=async function(input){const u=new URL(input);if(u.origin!=='https://registry.npmjs.org')throw Error('Foreign registry');const name=decodeURIComponent(u.pathname.slice(1));const names=['@rsrsai/cli','@rsrsai/linux-x64-gnu','@rsrsai/linux-x64','@rsrsai/macos-arm64','@rsrsai/win-x64','rsrs-cli'];if(!names.includes(name))throw Error('Unexpected package');if(name==='rsrs-cli'&&${aliasStatus}!==200)return new Response('',{status:${aliasStatus}});const versions={'1.0.16':{},'1.0.17-dev.12':{}};if(name==='rsrs-cli'&&${JSON.stringify(aliasVersion??null)})versions[${JSON.stringify(aliasVersion??'')} ]={};return new Response(JSON.stringify({versions,'dist-tags':{latest:'1.0.16'}}),{status:200});};\n`);
    const env={PATH:bin+':'+process.env.PATH,HOME:root,TMPDIR:root,GITHUB_REPOSITORY:'risense-ai/respire-cli',...(requested?{RELEASE_DEV_VERSION:requested}:{})};
    return spawnSync(process.execPath,['--import',bootstrap,fileURLToPath(new URL('./next-dev-version.mjs',import.meta.url))],{cwd:root,env,encoding:'utf8',timeout:15000});
  }finally{rmSync(root,{recursive:true,force:true});}
}
test('a version present only in the short entry is reserved during automatic allocation',()=>{
  const result=run({aliasVersion:'1.0.17-dev.13'});assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),'1.0.17-dev.14');
});
test('untagged DEV13 fence remains reserved automatically and rejects explicit reuse despite registry absence',()=>{
  const names=['@rsrsai/cli','@rsrsai/linux-x64-gnu','@rsrsai/linux-x64','@rsrsai/macos-arm64','@rsrsai/win-x64','rsrs-cli'];
  const fence={schema:1,kind:'npm-version-fence',repository:'risense-ai/respire-cli',version:'1.0.17-dev.13',source_sha:'a'.repeat(40),run_id:'700',first_attempt:'1',phase:'prepared',package_names:names,scoped_packages:null,created_at:'2026-10-28T01:43:00Z'};
  const releases=[{tag_name:'untagged-observed-draft',name:'v1.0.17-dev.13',draft:true,prerelease:true,body:fenceBody('Notes',fence)}];
  const automatic=run({releases});assert.equal(automatic.status,0,automatic.stderr);assert.equal(automatic.stdout.trim(),'1.0.17-dev.14');
  const explicit=run({releases,requested:'1.0.17-dev.13'});assert.notEqual(explicit.status,0);assert.match(explicit.stderr,/durable npm intent/);
  releases[0].name='Renamed human notes';assert.equal(run({releases}).stdout.trim(),'1.0.17-dev.14');
  releases.unshift({tag_name:'v1.0.17-dev.13',name:'v1.0.17-dev.13',draft:true,prerelease:true,body:'unbound duplicate'});
  const duplicate=run({releases,requested:'1.0.17-dev.13'});assert.notEqual(duplicate.status,0);assert.match(duplicate.stderr,/durable npm intent/);
});
test('explicit DEV rejects a version already accepted for the short entry alone',()=>{
  const result=run({aliasVersion:'1.0.17-dev.13',requested:'1.0.17-dev.13'});assert.notEqual(result.status,0);assert.match(result.stderr,/already has a tag or published npm package/);assert.equal(result.stdout,'');
});
test('short-entry metadata 404 provides no public version evidence; metadata errors fail closed',()=>{
  const absent=run({aliasStatus:404});assert.equal(absent.status,0,absent.stderr);assert.equal(absent.stdout.trim(),'1.0.17-dev.13');
  for(const status of [401,403,500]){const result=run({aliasStatus:status});assert.notEqual(result.status,0);assert.equal(result.stdout,'');assert.match(result.stderr,new RegExp(`HTTP ${status}`));}
});

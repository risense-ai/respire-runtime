"""Exercise actual-artifact upgrades for the selected critical or full gate."""
import argparse, hashlib, json, pathlib, re, shutil, subprocess, sys, tarfile
from concurrent.futures import ThreadPoolExecutor
from published_upgrade_policy import platform_applicability, select_upgrade_sources

parser=argparse.ArgumentParser()
parser.add_argument('--binary',required=True)
parser.add_argument('--target',required=True)
parser.add_argument('--model-dir',required=True)
parser.add_argument('--legacy-model-dir',required=True)
parser.add_argument('--output-dir',required=True)
parser.add_argument('--profile',choices=['critical','full'],default='full')
args=parser.parse_args()
root=pathlib.Path(args.output_dir).resolve(); root.mkdir(parents=True,exist_ok=True)
def command(*values):
    executable=shutil.which(values[0])
    assert executable,'required tool missing: '+values[0]
    return subprocess.check_output([executable,*values[1:]],text=True,encoding='utf-8',timeout=60).strip()
releases=[]
for page in range(1,101):
    batch=json.loads(command('gh','api',f'repos/risense-ai/respire-cli/releases?per_page=100&page={page}'))
    releases.extend(batch)
    if len(batch)<100: break
else: raise RuntimeError('release inventory pagination limit exceeded')
def stable(tag):
    return bool(re.fullmatch(r'v\d+\.\d+\.\d+',tag)) and tuple(map(int,tag[1:].split('.'))) >= (1,0,6)
sources={item['tag_name']:item for item in releases if not item['draft'] and not item['prerelease'] and stable(item['tag_name'])}
formal_sources=sorted(sources, key=lambda tag: tuple(map(int,tag[1:].split('.'))))
registry=sorted(set(json.loads(command('npm','view','@rsrsai/cli','versions','--json'))) |
                set(json.loads(command('npm','view','rsrs-cli','versions','--json'))))
missing=[version for version in registry if stable('v'+version) and 'v'+version not in sources]
assert not missing,'published npm stable has no verifiable GitHub artifact: '+str(missing)
# No formal 1.0.6 was published in either registry. Keep its last actual DEV as an extra baseline.
if args.profile=='full' and 'v1.0.6' not in sources:
    baseline=next((item for item in releases if item['tag_name']=='v1.0.6-dev.37075716045' and not item['draft']),None)
    assert baseline is not None,'1.0.6 compatibility baseline artifact missing'
    sources[baseline['tag_name']]=baseline
# The complete 1.0.10 draft is an explicit compatibility baseline, not a formal release.
additional_draft_baselines=[]
if args.profile=='full' and 'v1.0.10' not in formal_sources:
    # Draft assets retain their release/asset IDs even when the tag endpoint omits them.
    baseline=json.loads(command('gh','api','repos/risense-ai/respire-cli/releases/403872621'))
    assert baseline['tag_name']=='v1.0.10' and baseline['draft'],'1.0.10 compatibility baseline identity mismatch'
    sources[baseline['tag_name']]=baseline
    additional_draft_baselines.append(baseline['tag_name'])
assert sources,'no upgrade source versions discovered'
report={'passed':False,'target':args.target,'candidate_sha256':hashlib.sha256(pathlib.Path(args.binary).read_bytes()).hexdigest(),
        'profile':args.profile,'selected_sources':[],'full_coverage':False,'all_published_sources_covered':False,
        'published_formal_sources':formal_sources,
        'additional_draft_baselines':additional_draft_baselines,
        'unpublished_draft_stables':sorted({item['tag_name'] for item in releases if item['draft'] and stable(item['tag_name'])} | set(additional_draft_baselines)),
        'registry_formal_versions':sorted(version for version in registry if stable('v'+version)),
        'sources':[]}
def verify_upgrade(source):
    tag,release=source
    folder=root/tag; folder.mkdir(exist_ok=True)
    extension='.exe' if 'windows' in args.target else ''
    names=[f'rsrs-{args.target}{extension}',f'rsrs-{args.target}-runtime.tar.gz',f'cli-build-{args.target}.json']
    assets={asset['name']:asset for asset in release['assets']}
    not_applicable=platform_applicability(tag,args.target,assets)
    if not_applicable:
        return {'version':tag[1:],'formal':tag in formal_sources,'status':'not-applicable','reason':not_applicable}
    needed=[]
    for name in names:
        digest=assets[name].get('digest')
        assert digest and digest.startswith('sha256:'),'published asset digest missing: '+tag+' '+name
        path=folder/name
        if not path.is_file(): needed.append(name)
        else:
            with path.open('rb') as stream:
                if hashlib.file_digest(stream,'sha256').hexdigest()!=digest[7:]: needed.append(name)
    if needed:
        if release['draft']:
            for name in needed:
                with (folder/name).open('wb') as output:
                    subprocess.run(['gh','api',f"repos/risense-ai/respire-cli/releases/assets/{assets[name]['id']}",
                        '-H','Accept: application/octet-stream'],stdout=output,check=True,timeout=180)
        else:
            subprocess.run(['gh','release','download',tag,'--repo','risense-ai/respire-cli','--dir',str(folder),'--clobber',*[value for name in needed for value in ['--pattern',name]]],check=True,timeout=180)
    for name in names:
        digest=assets[name].get('digest')
        assert digest and digest.startswith('sha256:'),'published asset digest missing: '+tag+' '+name
        with (folder/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==digest[7:]
    manifest=json.loads((folder/names[2]).read_text())
    assert manifest['version']==tag[1:] and manifest['target']==args.target
    for name,key in zip(names[:2],['binary_sha256','runtime_sha256']):
        with (folder/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==manifest[key]
    with tarfile.open(folder/names[1]) as bundle: bundle.extractall(folder,filter='data')
    old=folder/('rsrs'+extension)
    shutil.copyfile(folder/names[0],old); old.chmod(old.stat().st_mode | 0o111)
    result=folder/'results'
    subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('test-real-m3-account-switch.py')),
        '--binary',args.binary,'--seed-binary',str(old),'--expect-supervised-worker','--model-dir',args.model_dir,
        '--legacy-model-dir',args.legacy_model_dir,'--output-dir',str(result)],check=True)
    checks=json.loads((result/'real-account-return-verification.json').read_text())
    assert isinstance(checks,list) and len(checks)==1,'expected one candidate upgrade report'
    check=checks[0]
    assert isinstance(check,dict) and all(check.get(name) is True for name in [
        'passed','real_model','supervised_worker_checked','global_engine_preserved','distinct_vault_keys',
        'source_and_keys_unchanged','compatible_index_reused','forced_restart_checked','old_rpc_checked',
    ]),'required real upgrade checks missing or failed'
    assert check.get('binary_sha256')==report['candidate_sha256'],'candidate changed during upgrade validation'
    assert check.get('engine')=='cpu','upgrade did not verify real CPU inference'
    sequence=check.get('sequence')
    assert isinstance(sequence,list) and [step['account'] for step in sequence]==['main','alternate','main'],'upgrade account sequence differs'
    for step in sequence:
        rows=step.get('model_rows')
        assert isinstance(rows,dict) and set(rows)=={'embedder','model index'} and all(
            row.get('status')=='ok' for row in rows.values()),'upgrade model readiness checks missing or failed'
    return {'version':tag[1:],'formal':tag in formal_sources,'passed':True,'report':str(result/'real-account-return-verification.json')}

try:
    selected=select_upgrade_sources(sources,args.target,args.profile)
    report['selected_sources']=sorted(selected)
    # Legacy macOS model workers have a fixed 30-second deadline; avoid competing model loads.
    with ThreadPoolExecutor(max_workers=1 if sys.platform == 'darwin' else 2) as pool:
        for outcome in pool.map(verify_upgrade, sorted(selected.items())):
            report['sources'].append(outcome)
    first_platform_release=(args.target=='x86_64-apple-darwin' and all(
        platform_applicability(tag,args.target,[asset['name'] for asset in source['assets']]) is not None
        for tag,source in sources.items()))
    assert first_platform_release or any(item.get('passed') is True for item in report['sources']),'no actual applicable upgrade was exercised'
    report['first_platform_release']=first_platform_release
    if first_platform_release:
        report['upgrade_status']='not-applicable: first Intel macOS release; fresh inference is validated separately'
    report['passed']=True
    report['full_coverage']=report['all_published_sources_covered']=args.profile=='full'
finally:
    (root/'published-upgrades.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')

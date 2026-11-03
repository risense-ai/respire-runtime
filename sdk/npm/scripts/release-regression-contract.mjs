// Exact required consumers for newly prepared/published platform releases.
export function validationProfile(value='full') {
  if(!['critical','full'].includes(value))throw Error('Unknown release validation profile');
  return value;
}
export function regressionContract(manifest,profile='full') {
  profile=validationProfile(profile);
  const native=manifest.targets.map(t=>t.triple);
  // Legacy migration fixtures bind architectures with published pre-1.0.20 binaries.
  const migration=native.filter(t=>t.includes('windows')||t==='aarch64-apple-darwin');
  if(profile==='critical')return {schema:1,validation_profile:profile,native,cloud:[],migration:[],migration_gate:[],api:true};
  return {schema:1,native,cloud:native.filter(t=>t!=='x86_64-unknown-linux-gnu'),migration,migration_gate:migration,api:true};
}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function validateRegressionContract(contract,manifest,expectedProfile){
  const profile=validationProfile(contract?.validation_profile);
  if(expectedProfile!==undefined&&profile!==validationProfile(expectedProfile))throw Error('Release validation profile differs');
  const actual={...contract},expected={...regressionContract(manifest,profile)};
  delete actual.validation_profile;delete expected.validation_profile;
  if(!same(actual,expected))throw Error('Release regression inventory differs from its platform manifest');
  return contract;
}
const groups=[
    ['native',j=>j.name.includes('native-regression / Native ('),t=>j=>j.name.endsWith(`Native (${t})`)],
    ['cloud',j=>j.name.startsWith('cloud-sweep ('),t=>j=>j.name.endsWith(`${t})`)],
    ['migration',j=>j.name.startsWith('Native migration ('),t=>j=>j.name===`Native migration (${t})`],
    ['migration_gate',j=>j.name.startsWith('Migration gate ('),t=>j=>j.name===`Migration gate (${t})`],
];
export function regressionStatus(jobs,contract){
  const profile=validationProfile(contract?.validation_profile);
  let pending=false;
  for(const [kind,select,match] of groups){
    const selected=jobs.filter(select);
    if(new Set(selected.map(j=>j.name)).size!==selected.length)throw Error('Duplicate '+kind+' regression');
    const fullTargets=kind==='cloud'?contract.native.filter(t=>t!=='x86_64-unknown-linux-gnu'):contract.native.filter(t=>t.includes('windows')||t==='aarch64-apple-darwin');
    const inactive=profile==='critical'&&kind!=='native'?selected.filter(j=>j.status==='completed'&&j.conclusion==='skipped'&&fullTargets.some(target=>match(target)(j))):[];
    const placeholder=selected.filter(j=>j.name==='Native migration (${{ matrix.target }})'||j.name==='Migration gate (${{ matrix.target }})');
    // Actual API run 41291097685 emits these placeholders for unselected full-only matrices.
    if(placeholder.length>(profile==='critical'?1:0)||placeholder.some(j=>j.status!=='completed'||j.conclusion!=='skipped'))throw Error('Unexpected inactive regression matrix');
    const actual=selected.filter(j=>!placeholder.includes(j)&&!inactive.includes(j)),expected=contract[kind];
    if(!Array.isArray(expected)||actual.length>expected.length||new Set(actual.map(j=>j.name)).size!==actual.length||actual.some(j=>!expected.some(t=>match(t)(j))))throw Error(`Unexpected or duplicate ${kind} regression`);
    for(const target of expected){
      const found=actual.filter(match(target));
      if(found.length>1)throw Error(`Duplicate ${kind} ${target}`);
      const job=found[0];
      if(job?.status==='completed'&&job.conclusion!=='success')throw Error(`Required ${kind} ${target}: ${job.conclusion}`);
      if(!job||job.status!=='completed'||job.conclusion!=='success')pending=true;
    }
  }
  const api=jobs.filter(j=>j.name==='api-smoke');
  if(contract.api!==true||api.length>1)throw Error('Invalid API regression inventory');
  if(api[0]?.status==='completed'&&api[0].conclusion!=='success')throw Error(`Required API regression: ${api[0].conclusion}`);
  if(api.length!==1||api[0].status!=='completed'||api[0].conclusion!=='success')pending=true;
  return pending?'pending':'success';
}

// GitHub emits UTC ISO timestamps. Reject normalization of invalid dates and
// malformed/missing clocks rather than turning them into shorter measurements.
export function parseTimestamp(value){
  if(typeof value!=='string')return null;
  const match=value.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/);
  if(!match)return null;
  const time=Date.parse(value);
  if(!Number.isFinite(time)||new Date(time).toISOString()!==`${match[1]}.${(match[2]||'').padEnd(3,'0')}Z`)return null;
  return time;
}
export function regressionCompletedAt(jobs,contract,readyTimestamp){
  if(regressionStatus(jobs,contract)!=='success')return null;
  const ready=parseTimestamp(readyTimestamp);if(ready===null)return null;
  const required=jobs.filter(j=>j.name==='api-smoke'||groups.some(([kind,,match])=>contract[kind].some(target=>match(target)(j))));
  const completions=[];
  for(const job of required){
    const end=parseTimestamp(job.completed_at);if(end===null)return null;
    if(job.started_at!==undefined&&job.started_at!==null){
      const start=parseTimestamp(job.started_at);if(start===null||end<start)return null;
    }
    completions.push(end);
  }
  return Math.max(ready,...completions);
}

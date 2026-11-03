import json, statistics, math, pathlib
import sys
root=pathlib.Path(sys.argv[1]).resolve()
def stats(values):
 v=sorted(values);return dict(median=statistics.median(v),p95=v[math.ceil(.95*len(v))-1],p99=v[math.ceil(.99*len(v))-1])
def smaps(text):
 return {line.split(':')[0]:int(line.split()[1]) for line in text.splitlines() if line.startswith(('Pss:','Rss:','VmHWM:'))}
rows=json.loads((root/'storage-matrix.json').read_text()); summary=[]
for n in range(1000,10001,1000):
 for variant in ['baseline','candidate']:
  group=[r for r in rows if r['count']==n and r['variant']==variant]
  if not group: continue
  durations=[d for r in group for d in json.loads(r['stdout'])['latency_ms']]
  summary.append(dict(count=n,variant=variant,rounds=len(group),latency_ms=stats(durations),qps=1000*len(durations)/sum(durations),cpu_s_median=statistics.median(r['cpu_s'] for r in group),peak_pss_mib=statistics.median(r['peak_pss_kib'] for r in group)/1024,peak_rss_mib=statistics.median(r['peak_rss_kib'] for r in group)/1024,idle_pss_mib=statistics.median(smaps(json.loads(r['stdout'])['smaps'])['Pss'] for r in group)/1024))
(root/'summary.json').write_text(json.dumps(summary,indent=2))
for r in summary: print(r)
if (root/'hash-matrix.json').exists():
 rows=json.loads((root/'hash-matrix.json').read_text()); results=[]
 for variant in ['baseline','candidate']:
  group=[r for r in rows if r['variant']==variant];durations=[d for r in group for d in json.loads(r['stdout'].splitlines()[0])]
  results.append(dict(variant=variant,latency_ms=stats(durations),qps=1000*len(durations)/sum(durations),cpu_s_median=statistics.median(r['cpu_s'] for r in group),peak_pss_mib=statistics.median(r['peak_pss_kib'] for r in group)/1024,peak_rss_mib=statistics.median(r['peak_rss_kib'] for r in group)/1024,idle_pss_mib=statistics.median(smaps(r['stdout'])['Pss'] for r in group)/1024))
 (root/'hash-summary.json').write_text(json.dumps(results,indent=2));print(results)

"""Summarize preserved real-M3 reports; PSS/RSS remain separate (MiB)."""
import json, math, pathlib, statistics, sys
root = pathlib.Path(sys.argv[1])
def metric(phase, role, key):
    return sum(v[key] for v in phase['processes'].values() if v['role'] == role)
def read(path):
    data = json.loads(path.read_text())
    assert data['complete'] and data['runtime_exit'] == 0 and not data.get('error'), path
    return data
summary = {'percentiles': 'nearest rank ceil(p*n)-1', 'three_rounds': {}, 'fixed_window': []}
expected = None
for variant in ('baseline', 'candidate'):
    runs = [read(root / f'm3-run-10000-indexed-{variant}{suffix}/report.json') for suffix in ('', '-r2', '-r3')]
    values = sorted(q['elapsed_ms'] for d in runs for q in d['queries'][1:])
    item = {'median_ms': statistics.median(values), 'p95_ms': values[math.ceil(.95*len(values))-1], 'p99_ms': values[math.ceil(.99*len(values))-1], 'qps': 1000*len(values)/sum(values), 'warm_idle': {}, 'warm_cpu_s_30_queries': {}}
    for role in ('host', 'worker'):
        item['warm_idle'][role] = {k: statistics.median(metric(d['phases']['warm_idle'], role, k)/1024 for d in runs) for k in ('Pss', 'Rss')}
        item['warm_cpu_s_30_queries'][role] = statistics.median(metric(d['phases']['warm_recall_complete'], role, 'cpu_s') - metric(d['phases']['cold_recall_complete'], role, 'cpu_s') for d in runs)
    summary['three_rounds'][variant] = item
    for d in runs:
        results = [q['result'] for q in d['queries']]
        if expected is None: expected = results
        assert results == expected, d['variant']
for path in sorted(root.glob('m3-run-10000-fixed-*/report.json')):
    d = read(path)
    assert [q['result'] for q in d['queries']] == expected, d['variant']
    phases = {}
    for label in ('warm_idle', 'index_readiness_validation_complete', 'post_validation_idle_2s', 'post_validation_idle_10s'):
        phases[label] = {role: {k: metric(d['phases'][label], role, k)/1024 for k in ('Pss', 'Rss')} for role in ('host', 'worker')}
    summary['fixed_window'].append({'variant': d['variant'], 'binary_sha256': d['binary_sha256'], 'phases': phases})
summary['complete_recall_results_equal'] = True
print(json.dumps(summary, indent=2))

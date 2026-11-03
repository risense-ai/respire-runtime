#!/usr/bin/env python3
"""Read-only paired top-20 analysis of existing bench JSON reports.

Never creates grades, invokes a model or changes a store. Bootstrap intervals
are paired by case; they are exploratory until a frozen holdout is supplied.
"""
import argparse,hashlib,json,random,statistics
from pathlib import Path

def paired(base,variant,seed=42,iterations=2000):
    if base['topk']<20 or variant['topk']!=base['topk']:
        raise ValueError('both reports must use the same topk >= 20')
    if base['n_entries']!=variant['n_entries']:
        raise ValueError('entry count changed; use a frozen library')
    for key in ['sdk_lock_sha256','embedding_model']:
        left=base['params'].get(key)
        if not left or left!=variant['params'].get(key):
            raise ValueError('missing or differing '+key)
    a,b=base['results'],variant['results']
    if not a or len(a)!=len(b):raise ValueError('case count changed or empty')
    deltas=[];degraded=[];improved=[];seen=set();negative_false_positives=0
    for index,(left,right) in enumerate(zip(a,b)):
        identity=(left['query'],left.get('project'),tuple(left['expect']))
        if identity!=(right['query'],right.get('project'),tuple(right['expect'])):
            raise ValueError('paired case identity/order changed at index '+str(index))
        if identity in seen:raise ValueError('duplicate case; deduplicate before evaluation')
        seen.add(identity)
        for item in [left,right]:
            rank=item['rank']
            if rank is not None and (type(rank)!=int or rank<0 or rank>=len(item['ids'])):
                raise ValueError('invalid rank/IDs at index '+str(index))
            computed=next((rank for rank,memory in enumerate(item['ids']) if any(expected.strip() and (memory.startswith(expected.strip()) or expected.strip().startswith(memory)) for expected in item['expect'])),None)
            if rank!=computed:raise ValueError('reported rank disagrees with candidate IDs at index '+str(index))
        if not left['expect']:
            negative_false_positives+=bool(right['ids']);continue
        def metric(item):
            rank=item['rank'];return (int(rank is not None and rank<20),0.0 if rank is None else 1/(rank+1))
        old,new=metric(left),metric(right);delta=(new[0]-old[0],new[1]-old[1]);deltas.append(delta)
        if delta[0]<0 or delta[1]<0:degraded.append(index)
        if delta[0]>0 or delta[1]>0:improved.append(index)
    if not deltas:raise ValueError('no positive cases')
    rng=random.Random(seed);samples=[[],[]]
    for _ in range(iterations):
        chosen=rng.choices(deltas,k=len(deltas))
        for axis in [0,1]:samples[axis].append(statistics.fmean(row[axis] for row in chosen))
    result={'positive_cases':len(deltas),'total_cases':len(a),'negative_false_positives':negative_false_positives,
            'degraded_case_indices':degraded,'improved_case_indices':improved,
            'holdout_status':'not established by these reports; supply frozen library/model/query-family/time provenance',
            'interval_method':'exploratory paired case bootstrap; not query-family cluster confidence',
            'bootstrap_seed':seed,'bootstrap_samples':iterations}
    for axis,name in enumerate(['hit20_delta','mrr_delta']):
        samples[axis].sort();result[name]={'mean':statistics.fmean(row[axis] for row in deltas),
            'interval95':[samples[axis][int(.025*iterations)],samples[axis][min(iterations-1,int(.975*iterations))]]}
    result['params']={'baseline':base['params'],'variant':variant['params']}
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('baseline');parser.add_argument('variant');parser.add_argument('--save')
    args=parser.parse_args();left,right=[Path(name) for name in [args.baseline,args.variant]]
    result=paired(json.loads(left.read_text()),json.loads(right.read_text()))
    result['report_sha256']=[hashlib.sha256(path.read_bytes()).hexdigest() for path in [left,right]]
    output=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.save:Path(args.save).write_text(output)
    else:print(output,end='')
if __name__=='__main__':main()

from pathlib import Path
import sys
root=Path(sys.argv[1]).resolve()
exec((Path(__file__).parent/'profile_memory_copies.py').read_text().split('results=[]')[0])
results=[]
for size in [1024,4096]:
    for n in [1000,10000]:
        fixture=root/f'fixture-{n}-{size}'
        subprocess.run([str(root/'storage-baseline'),'seed',str(fixture),str(n),str(size)],check=True)
        for r in range(3):
            for variant in (['baseline','candidate'] if r%2==0 else ['candidate','baseline']):
                record=measure([str(root/f'storage-{variant}'),'read',str(fixture),str(n),str(size),'10'])
                record.update(kind='storage-boundary',count=n,bytes=size,variant=variant,round=r);results.append(record)
                (root/'storage-boundaries.json').write_text(json.dumps(results,indent=2))
        print(size,n,flush=True)

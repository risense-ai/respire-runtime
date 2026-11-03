import subprocess, pathlib, os, time, json, resource, threading, statistics
import sys
root=pathlib.Path(sys.argv[1]).resolve()
# Input directory must contain independently built storage-{baseline,candidate}
# and hash-{baseline,candidate} executables. All data generated here is synthetic.
root.mkdir(parents=True, exist_ok=True)
os.environ['RSRS_CORE_TEST_MODE']='1'
def measure(command):
    start=time.monotonic(); before=resource.getrusage(resource.RUSAGE_CHILDREN)
    p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    peak_pss=peak_rss=0; samples=0
    def sample():
        nonlocal peak_pss,peak_rss,samples
        while p.poll() is None:
            try:
                data=dict((x.split(':')[0],int(x.split()[1])) for x in pathlib.Path(f'/proc/{p.pid}/smaps_rollup').read_text().splitlines() if x.startswith(('Pss:','Rss:')))
                peak_pss=max(peak_pss,data['Pss']);peak_rss=max(peak_rss,data['Rss']);samples+=1
            except (FileNotFoundError,ProcessLookupError,PermissionError): pass
            time.sleep(.002)
    t=threading.Thread(target=sample);t.start();out,err=p.communicate();t.join()
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    if p.returncode: raise RuntimeError(f'{command}: {err}')
    return dict(command=command,wall_s=time.monotonic()-start,cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,peak_pss_kib=peak_pss,peak_rss_kib=peak_rss,samples=samples,stdout=out,stderr=err)
results=[]
for n in range(1000,10001,1000):
    fixture=root/f'fixture-{n}'
    if not (fixture/'synthetic.db').exists():
        subprocess.run([str(root/'storage-baseline'),'seed',str(fixture),str(n),'16384'],check=True)
    for r in range(3):
        for variant in (['baseline','candidate'] if r%2==0 else ['candidate','baseline']):
            record=measure([str(root/f'storage-{variant}'),'read',str(fixture),str(n),'16384','20'])
            record.update(kind='storage',count=n,variant=variant,round=r);results.append(record)
            (root/'storage-matrix.json').write_text(json.dumps(results,indent=2))
    print(n,flush=True)
# Exactly 48 MiB synthetic native-sized input, no user binary or credentials.
file=root/'synthetic-native.bin'
with file.open('wb') as f:
    for _ in range(48): f.write(bytes(range(256))*4096)
hashes=[]
for r in range(3):
    for variant in (['baseline','candidate'] if r%2==0 else ['candidate','baseline']):
        result=measure([str(root/f'hash-{variant}'),str(file),'30']);result.update(kind='hash',variant=variant,round=r);hashes.append(result)
        (root/'hash-matrix.json').write_text(json.dumps(hashes,indent=2))
print('complete',flush=True)

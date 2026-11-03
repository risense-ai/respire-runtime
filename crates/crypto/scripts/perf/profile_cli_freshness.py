"""Release CLI freshness path, isolated empty synthetic profiles, no model."""
import sys, json, os, pathlib, subprocess, time, http.client, socket, shutil, threading, resource, psutil, hashlib
ROOT=pathlib.Path(sys.argv[1]).resolve(); ROOT.mkdir(parents=True,exist_ok=True)
BINS={'baseline':pathlib.Path(sys.argv[2]).resolve(),'candidate':pathlib.Path(sys.argv[3]).resolve()}
def request(port,path,body=None):
 c=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
 try:
  c.request('GET' if body is None else 'POST',path,body=None if body is None else json.dumps(body),headers={'Content-Type':'application/json'});r=c.getresponse();data=r.read();assert r.status==200,(r.status,data);return json.loads(data)
 finally:c.close()
def tree(pid):
 try:return {pid}|{p.pid for p in psutil.Process(pid).children(recursive=True)}
 except psutil.Error:return set()
def memory(pids):
 totals={'Pss':0,'Rss':0}
 for pid in pids:
  try:
   for line in pathlib.Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
    if line.startswith(('Pss:','Rss:')):totals[line.split(':')[0]]+=int(line.split()[1])
  except (OSError,ProcessLookupError):pass
 return totals
def run(variant,round):
 folder=ROOT/f'release-status-{round}-{variant}';folder.mkdir();profile=folder/'profile';profile.mkdir();stable=folder/'bin';stable.mkdir();shutil.copy2(BINS[variant],stable/'rsrs')
 (profile/'client.json').write_text(json.dumps({'autosync':False,'data_dir':str(profile),'service_mode':'normal'}))
 env={k:v for k,v in os.environ.items() if not k.startswith(('RSRS_','RESPIRE_','ONEMEMORY_'))}
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 env.update(HOME=str(folder),USERPROFILE=str(folder),RSRS_DATA_DIR=str(profile),RSRS_BIN_DIR=str(stable),RSRS_RPC_PORT=str(port),RSRS_NO_AUTOSYNC='1',RSRS_UPDATE_CHECK='0',RSRS_LANG='en')
 log=(folder/'runtime.log').open('w');server=subprocess.Popen([str(stable/'rsrs'),'--runtime-internal'],env=env,stdout=log,stderr=log)
 live=None;active=True;peak={'Pss':0,'Rss':0};samples=0;rows=[]
 def sample():
  nonlocal samples
  while active:
   ids=tree(server.pid)
   if live is not None:ids|=tree(live)
   values=memory(ids)
   for key in peak:peak[key]=max(peak[key],values[key])
   samples+=1;time.sleep(.002)
 try:
  for _ in range(1000):
   if server.poll() is not None:raise RuntimeError('runtime exited')
   try:
    health=request(port,'/api/health')
    if health['pid']==server.pid:break
   except (OSError,ValueError,http.client.HTTPException):pass
   time.sleep(.005)
  else:raise RuntimeError('runtime not ready')
  def command():
   nonlocal live
   start=time.perf_counter();p=subprocess.Popen([str(BINS[variant]),'status','--json'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);live=p.pid
   out,err=p.communicate(timeout=20);live=None
   result=json.loads(out);assert p.returncode==0 and result['status']=='ok',(p.returncode,out,err)
   assert request(port,'/api/health')['pid']==server.pid,'unexpected runtime replacement'
   return {'ms':1000*(time.perf_counter()-start),'result':result}
  command() # warm generation and prove source/destination match without replacement
  before=resource.getrusage(resource.RUSAGE_CHILDREN);runtime_before=psutil.Process(server.pid).cpu_times();thread=threading.Thread(target=sample);thread.start();start=time.perf_counter()
  for _ in range(20):rows.append(command())
  elapsed=time.perf_counter()-start;active=False;thread.join();after=resource.getrusage(resource.RUSAGE_CHILDREN);runtime_after=psutil.Process(server.pid).cpu_times()
  return {'variant':variant,'round':round,'binary_bytes':BINS[variant].stat().st_size,'binary_sha256':hashlib.sha256(BINS[variant].read_bytes()).hexdigest(),'rows':rows,'wall_s':elapsed,'client_cpu_s':after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,'runtime_cpu_s':runtime_after.user+runtime_after.system-runtime_before.user-runtime_before.system,'tree_peak_kib':peak,'tree_idle_kib':memory(tree(server.pid)),'samples':samples}
 finally:
  active=False
  try:request(port,'/api/runtime/stop',{});server.wait(timeout=15)
  except Exception:
   server.terminate();server.wait(timeout=10)
  log.close()
results=[]
for r in range(3):
 for v in (['baseline','candidate'] if r%2==0 else ['candidate','baseline']):
  results.append(run(v,r));(ROOT/'full-cli-hash-results.json').write_text(json.dumps(results,indent=2));print(v,r,flush=True)

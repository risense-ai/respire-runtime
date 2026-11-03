"""Pinned real M3, independently embedded synthetic rows, complete release runtime/CLI."""
import os,sys,json,pathlib,sqlite3,subprocess,time,socket,http.client,shutil,threading,psutil,hashlib,resource
ROOT=pathlib.Path(sys.argv[1]).resolve();COUNT=int(sys.argv[2]);VARIANT=sys.argv[3]
BINARY=pathlib.Path(sys.argv[4]).resolve();MODEL_DIR=pathlib.Path(sys.argv[5]).resolve()
SOURCE=pathlib.Path(sys.argv[6]).resolve() if len(sys.argv)>6 else ROOT/f'm3-fixture-pending-{COUNT}';FOLDER=ROOT/f'm3-run-{COUNT}-{VARIANT}';FOLDER.mkdir();PROFILE=FOLDER/'profile';PROFILE.mkdir()
for name in ['session.json','fixture-manifest.json']:shutil.copy2(SOURCE/name,PROFILE/name)
if (SOURCE/'core-index').exists():shutil.copytree(SOURCE/'core-index',PROFILE/'core-index')
with sqlite3.connect(SOURCE/'rsrs.db') as src,sqlite3.connect(PROFILE/'rsrs.db') as dst:src.backup(dst)
with sqlite3.connect(PROFILE/'rsrs.db') as db:INITIAL_ARTIFACTS=db.execute('SELECT count(*) FROM core_artifacts a JOIN memories m ON m.id=a.memory_id AND m.ciphertext=a.source WHERE m.deleted=0').fetchone()[0]
(PROFILE/'client.json').write_text(json.dumps({'autosync':False,'data_dir':str(PROFILE),'service_mode':'normal'}))
with socket.socket() as sock:sock.bind(('127.0.0.1',0));PORT=sock.getsockname()[1]
env={k:v for k,v in os.environ.items() if not k.startswith(('RSRS_','RESPIRE_','ONEMEMORY_'))};env.update(HOME=str(FOLDER),USERPROFILE=str(FOLDER),XDG_CONFIG_HOME=str(FOLDER/'config'),XDG_DATA_HOME=str(FOLDER/'share'),RSRS_DATA_DIR=str(PROFILE),RSRS_RPC_PORT=str(PORT),RSRS_NO_AUTOSYNC='1',RSRS_UPDATE_CHECK='0',RSRS_LANG='en',RSRS_USER='synthetic-m3',RSRS_SUPER=os.environ['RSRS_TEST_SUPER'],RSRS_M3_DIR=str(MODEL_DIR),RSRS_MIRROR='http://127.0.0.1:9',RSRS_CPU_ORT_MIRROR='http://127.0.0.1:9',RSRS_RPC_PARALLELISM='2')
report={'count':COUNT,'variant':VARIANT,'binary_sha256':hashlib.sha256(BINARY.read_bytes()).hexdigest(),'model':'real pinned BGE-M3 CPU owned ORT, default production feature','core_test_mode':False,'initial_artifacts':INITIAL_ARTIFACTS,'source_snapshot':str(SOURCE),'index_mode':'startup of real pre-indexed snapshot, no rebuild' if INITIAL_ARTIFACTS==COUNT else 'actual runtime automatic background indexing from pending artifacts','progress':[],'phases':{},'queries':[],'complete':False}
def save(): (FOLDER/'report.json').write_text(json.dumps(report,indent=2))
def request(path,body=None):
 c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=5)
 try:c.request('GET' if body is None else 'POST',path,body=None if body is None else json.dumps(body),headers={'Content-Type':'application/json'});r=c.getresponse();b=r.read();assert r.status==200,(r.status,b[:200]);return json.loads(b)
 finally:c.close()
def tree(pid):
 try:return {pid}|{p.pid for p in psutil.Process(pid).children(recursive=True)}
 except psutil.Error:return set()
def metrics(pid):
 try:
  memory={}
  for line in pathlib.Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
   if line.startswith(('Pss:','Rss:')):memory[line.split(':')[0]]=int(line.split()[1])
  c=psutil.Process(pid).cpu_times();memory['cpu_s']=c.user+c.system;memory['threads']=psutil.Process(pid).num_threads();return memory
 except (OSError,psutil.Error):return None
log=(FOLDER/'runtime.log').open('w');started=time.perf_counter();process=subprocess.Popen([str(BINARY),'--runtime-internal'],env=env,stdout=log,stderr=log)
phase='index';active=True;live=None;peaks={};last={};samples=0
report['host_pid']=process.pid
def snapshot():
 values={}
 ids=tree(process.pid)
 if live:ids|=tree(live)
 for pid in ids:
  m=metrics(pid)
  if m:values[str(pid)]={**m,'role':'host' if pid==process.pid else 'client' if pid==live else 'worker'}
 return values
def sample():
 global samples,last
 while active:
  values=snapshot();last=values
  sums={r:{'Pss':0,'Rss':0} for r in ['host','worker','client','family']}
  for v in values.values():
   for key in ['Pss','Rss']:sums[v['role']][key]+=v[key];sums['family'][key]+=v[key]
  peak=peaks.setdefault(phase,{r:{'Pss':0,'Rss':0} for r in sums})
  for r in sums:
   for key in sums[r]:peak[r][key]=max(peak[r][key],sums[r][key])
  samples+=1;time.sleep(.02)
thread=threading.Thread(target=sample);thread.start()
def capture(label):
 values=snapshot()
 report['phases'][label]={'elapsed_s':time.perf_counter()-started,'processes':values,'health':request('/api/health'),'sampled_peak_kib':json.loads(json.dumps(peaks))}
 if label in ('runtime_ready','post_index_idle','cold_recall_complete','warm_idle','post_validation_idle_10s'):
  for pid,info in values.items():
   if info['role'] not in ('host','worker'):continue
   for source in ('smaps','smaps_rollup','status','maps'):
    try:(FOLDER/f'{label}-{info["role"]}-{pid}-{source}.txt').write_text(pathlib.Path(f'/proc/{pid}/{source}').read_text())
    except (OSError,ProcessLookupError):pass
 save()
def indexed():
 with sqlite3.connect(PROFILE/'rsrs.db',timeout=10) as db:
  return db.execute('SELECT count(*) FROM core_artifacts a JOIN memories m ON m.id=a.memory_id AND m.ciphertext=a.source WHERE m.deleted=0').fetchone()[0]
def command(args):
 global live
 start=time.perf_counter();p=subprocess.Popen([str(BINARY),'--client-only','--json',*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);live=p.pid
 out,err=p.communicate(timeout=300);live=None
 value=json.loads(out);assert p.returncode==0 and value['status']=='ok',(p.returncode,value,err.decode()[-2000:]);return {'args':args,'elapsed_ms':1000*(time.perf_counter()-start),'result':value}
try:
 for _ in range(1000):
  if process.poll() is not None:raise RuntimeError('runtime exited during startup')
  try:
   health=request('/api/health')
   if health['pid']==process.pid and health['data_dir']==str(PROFILE):break
  except (OSError,ValueError,http.client.HTTPException):pass
  time.sleep(.01)
 else:raise RuntimeError('runtime readiness timeout')
 capture('runtime_ready')
 last_done=-1;last_report=0
 while True:
  if process.poll() is not None:raise RuntimeError('runtime exited while indexing')
  h=request('/api/health');done=indexed();now=time.perf_counter()-started
  if h['retrieval_index']['state']=='failed' or h['inference'].get('host_recovery_required'):raise RuntimeError(json.dumps(h))
  if done!=last_done or now-last_report>10:
   row={'elapsed_s':now,'indexed':done,'index_status':h['retrieval_index'],'processes':snapshot()};report['progress'].append(row);save();print(json.dumps(row),flush=True);last_done=done;last_report=now
  if done==COUNT and not h['retrieval_index'].get('running'):break
  time.sleep(2)
 report['index_complete_s']=time.perf_counter()-started;capture('index_complete');phase='post_index_idle';time.sleep(2);capture('post_index_idle')
 phase='cold_recall';report['queries'].append(command(['recall','Synthetic memory number 00042 topic 8','--limit','5','--no-related']));capture('cold_recall_complete')
 phase='warm_recall'
 for r in range(3):
  for i in range(10):
   q=['Synthetic memory number 00042 topic 8','Archive retrieval garden river','Synthetic M3 fixture practical observation'][i%3]
   result=command(['recall',q,'--limit','5','--no-related']);result['round']=r;report['queries'].append(result);save()
 capture('warm_recall_complete');phase='warm_idle';time.sleep(3);capture('warm_idle')
 phase='index_readiness_validation';report['reembed_validation']=command(['reembed']);validation_return=time.perf_counter();capture('index_readiness_validation_complete')
 phase='post_validation_idle'
 for delay in (2,10):
  time.sleep(max(0,validation_return+delay-time.perf_counter()));capture(f'post_validation_idle_{delay}s')
  report['phases'][f'post_validation_idle_{delay}s']['after_validation_return_s']=time.perf_counter()-validation_return;save()
 report['complete']=True;report['samples']=samples;save()
except BaseException as error:
 report['error']=repr(error);save();raise
finally:
 active=False;thread.join();report['sampled_peak_kib']=peaks;report['last_processes']=last;save()
 try:request('/api/runtime/stop',{});process.wait(timeout=30)
 except Exception:
  process.terminate();process.wait(timeout=15)
 log.close();report['runtime_exit']=process.returncode
 # Explicit WAL-aware snapshot for later A/B warm comparisons and audit.
 with sqlite3.connect(PROFILE/'rsrs.db') as src,sqlite3.connect(FOLDER/'indexed-snapshot.db') as dst:src.backup(dst)
 save()

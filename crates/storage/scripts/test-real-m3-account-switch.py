"""Read-only real M3 cache; disposable profiles and owned runtime port only."""
import argparse, faulthandler, hashlib, hmac, json, os, pathlib, secrets, socket, sqlite3, subprocess, sys, tempfile, time, urllib.request
from native_fixture_process import FixtureCancelled, ForegroundOverlapProbe, WorkerInspector, captured_run
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

parser=argparse.ArgumentParser()
parser.add_argument('--binary',action='append',required=True)
parser.add_argument('--model-dir',required=True)
parser.add_argument('--model-file',choices=['model_quantized.onnx','model_fp16.onnx'],default='model_quantized.onnx')
parser.add_argument('--legacy-model-file',choices=['model_fp16.onnx','model_quantized.onnx'],default='model_fp16.onnx')
parser.add_argument('--legacy-model-dir',help='Read-only baseline cache containing real FP16 and quantized files')
parser.add_argument('--output-dir',required=True)
architecture=parser.add_mutually_exclusive_group()
architecture.add_argument('--expect-in-process',action='store_true',help='Historical binaries without an inference worker')
architecture.add_argument('--expect-supervised-worker',action='store_true',help='Verify one owned worker and its lifetime/SQLite boundary')
parser.add_argument('--resident-stress',action='store_true',help='Exercise concurrent recall, short writes, lightweight reads and background indexing')
parser.add_argument('--expect-background-threads',type=int,choices=range(1,17),help='Verify the actual loaded worker foreground/background policy')
parser.add_argument('--seed-binary',help='Create both libraries with this published older binary, then upgrade its running runtime')
args=parser.parse_args()
faulthandler.enable()
# A cloud container's PID 1 may not reap orphans. Adopt workers after a forced
# host termination so this fixture can verify and reap their actual exit.
if sys.platform.startswith('linux'):
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(36,1,0,0,0)!=0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(),'cannot enable fixture child subreaper')
# Asynchronous stack dumps can race live frames (CPython #116008); fixture calls retain hard deadlines.
BASE=pathlib.Path(args.output_dir).resolve()
BASE.mkdir(parents=True,exist_ok=True)
import cryptography, importlib.metadata, psutil
(BASE/'fixture-dependencies.json').write_text(json.dumps({
    'python':sys.version,'cryptography':cryptography.__version__,'psutil':psutil.__version__,
    'psutil_source':json.loads(importlib.metadata.distribution('psutil').read_text('direct_url.json') or 'null'),
},indent=2),encoding='utf-8')
CACHE=pathlib.Path(args.model_dir).resolve()
BINARIES=[pathlib.Path(path).resolve() for path in args.binary]
MODEL_HASHES={'model_quantized.onnx':'0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
    'model_fp16.onnx':'4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9'}
def verify_model(cache,model):
    for name,expected in [('tokenizer.json','6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790'),('onnx/'+model,MODEL_HASHES[model])]:
        with (cache/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==expected
verify_model(CACHE,args.model_file)
LEGACY_CACHE=pathlib.Path(args.legacy_model_dir).resolve() if args.legacy_model_dir else CACHE
if args.seed_binary:
    verify_model(LEGACY_CACHE,args.legacy_model_file)
    if args.model_file=='model_quantized.onnx': verify_model(LEGACY_CACHE,'model_quantized.onnx')
reports = []
for binary in BINARIES:
    root = BASE / ('account-return-real-' + str(time.time_ns()))
    if os.name == 'posix':
        # Keep fixture paths short and isolated from the CI report
        # directory for cross-platform tools; keep the owned
        # fixture in a short workspace directory and retain reports in BASE.
        root = pathlib.Path.cwd() / ('rsrs-up-' + secrets.token_hex(6))
    main = root / '.rsrs'
    alternate = main / 'accounts/alternate'
    alternate.mkdir(parents=True)
    entropy = secrets.token_bytes(18)
    code = 'A3-' + '-'.join(entropy.hex().upper()[i:i+6] for i in range(0,36,6))
    for profile in [main, alternate]:
        salt,nonce,urk=secrets.token_bytes(16),secrets.token_bytes(12),secrets.token_bytes(32)
        kek=hmac.new(hmac.new(salt,entropy,hashlib.sha256).digest(),b'onememory:kek:v4\x01',hashlib.sha256).digest()
        session=json.dumps({'user':'fixture-'+str(time.time_ns()),'vault_version':4,'kdf_salt':salt.hex(),'wrapped_urk':AESGCM(kek).encrypt(nonce,urk,None).hex(),'urk_nonce':nonce.hex()}).encode()
        (profile/'session.json').write_bytes(session)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
    env = os.environ.copy()
    for suffix in ['CLIENT_ONLY','NO_AUTOSTART','RUNTIME_WORKER','CORE_TEST_MODE','RPC_TOKEN','ENGINE','ADDR','TOKEN','JSON','ORT_DEBUG']:
        for prefix in ['RSRS_', 'ONEMEMORY_', 'RESPIRE_']:
            env.pop(prefix + suffix,None)
    env.update(HOME=str(root), USERPROFILE=str(root), RSRS_DATA_DIR=str(main), RSRS_RPC_PORT=str(port),
        RSRS_SUPER=code,RSRS_NO_AUTOSYNC='1',RSRS_UPDATE_CHECK='0',RSRS_M3_DIR=str(CACHE))
    seed_env={**env,'RSRS_M3_DIR':str(LEGACY_CACHE)}
    # Historical artifacts predate RSRS_*; keep their inputs explicit and
    # isolated instead of accidentally testing the operator's default library.
    for key, value in list(seed_env.items()):
        if key.startswith(('RSRS_', 'ONEMEMORY_', 'RESPIRE_')):
            seed_env['ONEMEMORY_' + key[5:]] = value
    def run(*args, allow_failure=False, timeout=120, cancel=None):
        result = captured_run([str(binary),'--json',*args],env=env,timeout=timeout,cancel=cancel)
        if result.returncode and not allow_failure: raise RuntimeError(result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
        envelope=json.loads(result.stdout)
        envelope['_fixture_timing']=result.fixture_timing
        return envelope
    def wait_index_ready(timeout=180):
        deadline = time.monotonic() + timeout
        while True:
            doctor = run('doctor', allow_failure=True)
            rows = {item['name']: item for item in doctor['items'] if item['name'] in ['embedder', 'model index']}
            if len(rows) == 2 and all(item['status'] == 'ok' for item in rows.values()):
                return rows
            assert time.monotonic() < deadline, rows
            time.sleep(.25)

    def snapshot(profile):
        database = profile/'rsrs.db'
        if not database.exists(): database = profile/'onememory.db'
        with sqlite3.connect(database) as db:
            rows = [db.execute(query).fetchall() for query in ['SELECT id,ciphertext,nonce,dirty,deleted FROM memories ORDER BY id',
                'SELECT * FROM sync_outbox ORDER BY seq','SELECT * FROM core_artifacts ORDER BY memory_id,model']]
        artifacts = sorted((path.name,hashlib.sha256(path.read_bytes()).hexdigest()) for path in (profile/'core-index').iterdir())
        return (rows,artifacts,(profile/'session.json').read_bytes())
    old_runtime=None
    old_rpc_checked=False
    old_rpc_authenticated=False
    public_config={'addr':'https://fixture.invalid','autosync':False,'custom':'preserve-upgrade-fixture'}
    def select(profile):
        (main/'client.json').write_text(json.dumps({**public_config,'data_dir':str(profile)}),encoding='utf-8')
    worker_identities=[]
    inspector=None
    def checked_worker(health):
        global inspector
        if sys.platform=='win32':
            if inspector is None:
                inspector=WorkerInspector(root/'boundary-inspector')
            identity=inspector.inspect({'host_pid':health['pid'],
                'worker_pid':health['inference']['worker_pid'],'binary':str(binary)})
            if identity not in worker_identities: worker_identities.append(identity)
            return identity
        import psutil
        host=psutil.Process(health['pid'])
        children=[child for child in host.children(recursive=True)
                  if not (sys.platform=='win32' and child.name().lower()=='conhost.exe')]
        assert len(children)==1, 'expected exactly one supervised Core worker'
        worker=children[0]
        assert worker.pid==health['inference']['worker_pid'] and worker.ppid()==host.pid
        assert '--core-worker-internal' in worker.cmdline()
        assert pathlib.Path(worker.exe()).resolve()==pathlib.Path(host.exe()).resolve()
        assert not any(pathlib.Path(file.path).name in ('rsrs.db','lock.db') for file in worker.open_files())
        assert not {'GH_TOKEN','GITHUB_TOKEN','OPENAI_API_KEY','RSRS_SUPER'} & worker.environ().keys()
        identity=(worker.pid,worker.create_time())
        if identity not in worker_identities: worker_identities.append(identity)
        return identity
    def confirm_workers_exited(identities):
        import psutil
        deadline=time.monotonic()+10
        for pid,created in identities:
            while True:
                try: alive=psutil.Process(pid).create_time()==created
                except psutil.NoSuchProcess: alive=False
                if not alive: break
                if sys.platform.startswith('linux'):
                    try: reaped,_=os.waitpid(pid,os.WNOHANG)
                    except ChildProcessError: reaped=0
                    if reaped==pid: break
                assert time.monotonic()<deadline, 'owned Core worker survived its host: '+str(pid)
                time.sleep(.02)
    try:
        run('--direct','model','engine','cpu')
        global_engine=(main/'inference.json').read_bytes()
        for profile in [main,alternate]:
            select(profile)
            if args.seed_binary:
                for command in [('model','activate','m3'),('remember','Real account return fixture '+profile.name,'--title',profile.name,'--importance','important','--force')]:
                    seeded=captured_run([str(pathlib.Path(args.seed_binary).resolve()),'--json','--direct',*command],env=seed_env,timeout=180)
                    assert seeded.returncode==0,seeded.stdout.decode(errors='replace')+seeded.stderr.decode(errors='replace')
            else:
                run('--direct','remember','Real account return fixture '+profile.name,'--title',profile.name,'--importance','important','--force')
        original = {str(profile):snapshot(profile) for profile in [main,alternate]}
        select(main)
        if args.seed_binary:
            log=(root/'old-runtime.log').open('wb')
            web_help=subprocess.check_output([args.seed_binary,'web','--help'],text=True,encoding='utf-8',timeout=30)
            runtime_args=['web','--internal','--no-open','--port',str(port)] if '--port' in web_help else ['--runtime-internal']
            old_runtime=subprocess.Popen([str(pathlib.Path(args.seed_binary).resolve()),*runtime_args],env=seed_env,stdout=log,stderr=log)
            log.close()
            for attempt in range(200):
                assert old_runtime.poll() is None,('published old runtime exited before upgrade (exit '+str(old_runtime.returncode)+'): '+
                    (root/'old-runtime.log').read_text(encoding='utf-8',errors='replace')[-4000:])
                try:
                    headers={}
                    token=main/'runtime/token'
                    if token.exists(): headers['Authorization']='Bearer '+token.read_text().strip()
                    request=urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers=headers)
                    with urllib.request.urlopen(request,timeout=1) as response: health=json.load(response)
                    assert health['pid']==old_runtime.pid
                    break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('published old runtime did not become ready')
            # The new client must exercise the old HTTP RPC, not only health/stop.
            # Client-only status is read-only and cannot take over the old runtime.
            original_token=token.read_bytes() if token.is_file() else None
            old_status=run('--client-only','status')
            assert old_status.get('status')=='ok','new client could not read the old runtime through HTTP RPC'
            assert old_runtime.poll() is None,'client-only RPC replaced or stopped the old runtime'
            request=urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers=headers)
            with urllib.request.urlopen(request,timeout=2) as response: after_rpc=json.load(response)
            assert after_rpc['pid']==old_runtime.pid,'client-only RPC changed runtime ownership'
            assert (token.read_bytes() if token.is_file() else None)==original_token,'client-only RPC changed the old token file'
            old_rpc_checked=True
            old_rpc_authenticated=bool(original_token and original_token.strip())
        statuses=[]
        visited=set()
        generation_changes={}
        for account, profile in [('main',main),('alternate',alternate),('main',main)]:
            previous_workers=list(worker_identities)
            run('account','use',account)
            if args.expect_supervised_worker and previous_workers:
                confirm_workers_exited(previous_workers)
            if old_runtime is not None:
                assert old_runtime.wait(timeout=20)==0,'old runtime did not exit gracefully'
            assert run('model','engine')['summary']['engine']=='cpu'
            assert (main/'inference.json').read_bytes()==global_engine
            assert not (alternate/'inference.json').exists()
            # A real model change may rebuild derived indexes once; never source data.
            rows = wait_index_ready()
            if args.seed_binary and str(profile) not in visited:
                current=snapshot(profile)
                baseline=original[str(profile)]
                assert current[0][:2]==baseline[0][:2] and current[2]==baseline[2],'model migration changed ciphertext, sync work or keys'
                generation_changes[str(profile)]=current[0][2]!=baseline[0][2] or current[1]!=baseline[1]
                original[str(profile)]=current
            visited.add(str(profile))
            if args.expect_in_process or args.expect_supervised_worker:
                import psutil
                probe_stdout=tempfile.TemporaryFile()
                probe_stderr=tempfile.TemporaryFile()
                pending=subprocess.Popen([str(binary),'--json','model','probe','--model','m3'],env=env,stdout=probe_stdout,stderr=probe_stderr)
                checks=0
                deadline=time.monotonic()+120
                try:
                    while pending.poll() is None:
                        assert time.monotonic()<deadline,'native probe exceeded the acceptance deadline'
                        start=time.monotonic()
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2) as response:
                            health=json.load(response)
                        assert time.monotonic()-start < 2,'health blocked behind native inference'
                        if args.expect_supervised_worker:
                            identity=checked_worker(health)
                            if checks: assert identity==probe_worker,'warm native probe replaced its worker'
                            probe_worker=identity
                        else:
                            children=psutil.Process(health['pid']).children(recursive=True)
                            children=[child for child in children if not (sys.platform=='win32' and child.name().lower()=='conhost.exe')]
                            assert not children, 'runtime spawned an inference child: '+str([child.name() for child in children])
                        checks+=1
                        time.sleep(.05)
                    pending.wait(timeout=5)
                    probe_stdout.seek(0); probe_stderr.seek(0)
                    stdout,stderr=probe_stdout.read(),probe_stderr.read()
                    assert pending.returncode==0,stdout.decode(errors='replace')+stderr.decode(errors='replace')
                    assert checks>0,'native inference responsiveness was not exercised'
                finally:
                    if pending.poll() is None:
                        pending.kill(); pending.wait(timeout=5)
                    probe_stdout.close(); probe_stderr.close()
            else:
                run('model','probe','--model','m3')
            if args.expect_background_threads is not None:
                # Model/index metadata may be ready before the worker heartbeat.
                deadline=time.monotonic()+10
                policy=None
                while policy is None and time.monotonic()<deadline:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2) as response:
                        thread_health=json.load(response)
                    policy=thread_health.get('inference',{}).get('intra_threads')
                    if policy is None: time.sleep(.05)
                assert policy=={'foreground':1,'background':args.expect_background_threads}, 'loaded worker thread policy differs: '+str(policy)
                (BASE/('inference-threads-'+account+'.json')).write_text(json.dumps(policy),encoding='utf-8')
            recalled=run('recall','Real account return fixture','--titles')
            assert recalled.get('items'),'real recall returned no seeded entry'
            if args.expect_supervised_worker:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2) as response:
                    assert checked_worker(json.load(response))==probe_worker,'warm recall replaced its worker'
            doctor=run('doctor',allow_failure=True)
            rows={item['name']:item for item in doctor['items'] if item['name'] in ['embedder','model index']}
            assert len(rows)==2 and all(item['status']=='ok' for item in rows.values()),rows
            assert pathlib.Path(json.loads((main/'client.json').read_text())['data_dir'])==profile
            config=json.loads((main/'client.json').read_text())
            assert all(config.get(key)==value for key,value in public_config.items()),'upgrade/switch changed public API settings'
            assert snapshot(profile)==original[str(profile)],'switch/probe changed source data or rebuilt existing index'
            # Independent important entries avoid the intentional daily-trivia append behavior.
            written=run('remember','Post-upgrade real inference '+account+' '+str(time.time_ns()),'--title','post-upgrade-'+account,'--importance','important','--force')
            assert written['summary'].get('id'),'real post-upgrade remember did not commit'
            # The durable write precedes derived indexing; compare stable snapshots after background completion.
            wait_index_ready()
            updated=snapshot(profile)
            assert all(row in updated[0][0] for row in original[str(profile)][0][0]),'remember changed an existing ciphertext'
            assert all(row in updated[0][1] for row in original[str(profile)][0][1]),'remember changed existing sync work'
            assert all(row in updated[0][2] for row in original[str(profile)][0][2]),'remember changed a compatible existing index'
            assert updated[2]==original[str(profile)][2],'remember changed vault keys'
            original[str(profile)]=updated
            assert run('recall','Post-upgrade real inference','--titles').get('items'),'post-upgrade remember could not be recalled'
            statuses.append({'account':account,'model_rows':rows})
        stress = None
        if args.resident_stress:
            import concurrent.futures, contextlib, psutil, threading
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=2) as response:
                health = json.load(response)
            owned = psutil.Process(health['pid'])
            assert '--runtime-internal' in owned.cmdline(), 'stress must target its owned runtime'
            resource_members=None
            resource_members_checked=None
            def total_memory(refresh_members=True):
                global resource_members, resource_members_checked
                if refresh_members:
                    # Keep the original all-descendant audit. Continuous RSS
                    # sampling must not repeatedly scan the entire OS PID map.
                    resource_members=[owned,*owned.children(recursive=True)]
                    resource_members_checked=time.monotonic()
                members=resource_members
                memories=[member.memory_info() for member in members]
                return sum(memory.rss for memory in memories),sum(getattr(memory,'private',0) or 0 for memory in memories)
            baseline_rss,baseline_private=total_memory()
            samples = []
            observer_errors=[]
            timings = []
            body = 'resident stress query ' + 'background indexing and foreground retrieval '.join(['sample'] * 110)
            def timed(command, timeout=120, cancel=None):
                started = time.monotonic()
                try:
                    envelope = run(*command, timeout=timeout,cancel=cancel)
                except FixtureCancelled:
                    raise
                except Exception as error:
                    raise RuntimeError('stress '+command[0]+' failed after '+str(round(time.monotonic()-started,3))+'s: '+str(error)) from error
                assert envelope['status'] in ['ok', 'warn'], command[0]
                return command[0], time.monotonic() - started, envelope
            def probe_recall(timeout, cancel):
                command, elapsed, envelope = timed(['recall','Real account return fixture','--titles','--no-related'], timeout=timeout,cancel=cancel)
                assert envelope.get('items'), 'foreground overlap probe lost the indexed seed'
                return {'command':command,'seconds':elapsed,**envelope['_fixture_timing']}
            overlap = ForegroundOverlapProbe(probe_recall)
            fixed_workload_completed = None
            def sample_health(check_boundary=True):
                overlap.check()
                if check_boundary and observer_errors:
                    raise RuntimeError('continuous health observer failed: '+str(observer_errors))
                sample_started=time.monotonic()
                sample_unix=time.time()
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=2) as response:
                    current = json.load(response)
                health_completed=time.monotonic()
                assert current['pid'] == owned.pid, 'stress changed runtime ownership'
                inference = current.get('inference', {})
                overlap.observe(inference)
                rss,private=total_memory(refresh_members=check_boundary)
                memory_completed=time.monotonic()
                if check_boundary and args.expect_supervised_worker: checked_worker(current)
                samples.append({'rss':rss,'private':private,
                    'started_unix':sample_unix,'started_monotonic':sample_started,
                    'health_completed_monotonic':health_completed,
                    'health_seconds':health_completed-sample_started,
                    'memory_seconds':memory_completed-health_completed,
                    'boundary_seconds':time.monotonic()-memory_completed,
                    'membership_age_seconds':time.monotonic()-resource_members_checked,
                    'boundary_checked':check_boundary,
                    'retrieval_index':current.get('retrieval_index',{}),'inference':inference,
                    'foreground':inference.get('foreground',{}),'background':inference.get('background',{})})
            @contextlib.contextmanager
            def observed_pool():
                stopped=threading.Event()
                def observe():
                    try:
                        while not stopped.is_set():
                            # Retain every original boundary check in the main
                            # loop. Handle inspection must not starve concurrent
                            # HTTP responsiveness/lane/resource observations.
                            sample_health(check_boundary=False)
                            stopped.wait(.02)
                    except Exception as error: observer_errors.append(str(error))
                observer=threading.Thread(target=observe,name='resident-health-observer',daemon=True)
                observer.start()
                # Core lane telemetry is a 250 ms heartbeat, not a fresh native
                # sample on each HTTP poll. Model checksums/preparation can also
                # outlast the fixed CLI burst. Keep bounded real foreground work
                # available throughout preparation; never substitute queued work
                # or separate foreground/background observations for overlap.
                overlap.start()
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=18) as pool:
                        yield pool
                finally:
                    try:
                        overlap.close(cancel_pending=sys.exc_info()[0] is not None)
                    finally:
                        stopped.set()
                        observer.join(timeout=3)
                        # Persist evidence even when a deadline, client, or
                        # boundary assertion fails before final metrics exist.
                        (BASE/'resident-stress-metrics.json').write_text(json.dumps({
                            'passed':False,'requests':len(timings),'timings':timings,'samples':samples,
                            'overlap_probe':{'deadline_seconds':120,'max_in_flight':2,'timings':overlap.calls,
                                'errors':[str(error) for error in overlap.errors]},
                            'fixed_workload_completed_monotonic':fixed_workload_completed,
                            'observer_errors':observer_errors},indent=2),encoding='utf-8')
                        assert not observer.is_alive(),'continuous health observer did not stop'
                        assert not observer_errors,'continuous health observer failed: '+str(observer_errors)
            with observed_pool() as pool:
                print('resident phase: concurrent writes',flush=True)
                batch_deadline=time.monotonic()+120*2+10
                writes = [pool.submit(timed, ['remember', body, '--title', 'stress-'+str(i),
                    '--importance', 'important', '--force']) for i in range(28)]
                while any(not future.done() for future in writes):
                    assert time.monotonic()<batch_deadline,'resident write batch exceeded command deadlines'
                    sample_health()
                    time.sleep(.02)
                created = []
                for future in writes:
                    command, elapsed, envelope = future.result()
                    assert envelope['summary'].get('index_state') == 'pending', 'remember waited for derived indexing'
                    created.append(envelope['summary']['id'])
                    timings.append({'command':command,'seconds':elapsed,**envelope['_fixture_timing']})
                # Retrieval quality evaluation must use the same pending-aware
                # resident path as recall, without requiring derived artifacts.
                eval_file = BASE / 'resident-stress-eval.jsonl'
                bench_file = BASE / 'resident-stress-bench.json'
                eval_file.write_text(json.dumps({'query':'resident stress query','expect':created})+'\n',encoding='utf-8')
                run('bench','run',str(eval_file),'--save',str(bench_file))
                bench_report = json.loads(bench_file.read_text(encoding='utf-8'))
                # The worker can finish first; the controlled CLI unit fixture
                # separately proves the all-pending retrieval contract.
                assert 0 <= int(bench_report['params']['index_pending']) <= bench_report['n_entries'], 'invalid pending count'
                assert bench_report['metrics']['hitk'] == 1, 'pending-aware benchmark lost the expected source'
                run('bench','run',str(eval_file),'--baseline',str(bench_file))
                # A healthy owner must serve reads even while another process
                # holds the lifecycle gate for startup/replacement decisions.
                lifecycle = sqlite3.connect(main/'runtime/takeover/lock.db', timeout=2)
                try:
                    lifecycle.execute('BEGIN EXCLUSIVE')
                    command, elapsed, envelope = timed(['show', created[0]])
                    assert elapsed < 5, 'warm request acquired the lifecycle gate'
                finally:
                    lifecycle.rollback()
                    lifecycle.close()
                work = []
                print('resident phase: concurrent recall/show/update',flush=True)
                batch_deadline=time.monotonic()+120*5+10
                for i in range(28):
                    work.append(pool.submit(timed, ['recall','resident stress query','--titles','--no-related']))
                    work.append(pool.submit(timed, ['show',created[i]]))
                    if i < 16:
                        work.append(pool.submit(timed, ['update',created[i],'--title','updated-stress-'+str(i)]))
                work.append(pool.submit(timed, ['remember','concurrent trivial write','--importance','trivial']))
                while any(not future.done() for future in work):
                    assert time.monotonic()<batch_deadline,'resident mixed batch exceeded command deadlines'
                    sample_health()
                    time.sleep(.02)
                for future in work:
                    command, elapsed, envelope = future.result()
                    if command == 'recall':
                        assert envelope.get('items'), 'pending or indexed stress data was not recalled'
                    timings.append({'command':command,'seconds':elapsed,**envelope['_fixture_timing']})
                fixed_workload_completed = time.monotonic()
                while not overlap.observed.is_set():
                    sample_health()
                    time.sleep(.02)
            overlap_details = {'deadline_seconds':120,'max_in_flight':2,'timings':overlap.calls,
                'started_monotonic':overlap.started,
                'fixed_workload_completed_monotonic':fixed_workload_completed,
                'first_background_active_monotonic':min((sample['health_completed_monotonic'] for sample in samples if sample['background'].get('active')),default=None),
                'both_active_during_fixed_workload':any(sample['health_completed_monotonic'] <= fixed_workload_completed
                    and sample['foreground'].get('active') and sample['background'].get('active') for sample in samples)}
            metrics = {'passed':False,'requests':len(timings),'timings':timings,
                'overlap_probe':overlap_details,
                'rss_before':baseline_rss,'rss_peak':max(sample['rss'] for sample in samples),
                'resource_scope':'owned host and all descendants',
                'private_before':baseline_private,
                'private_peak':max((sample['private'] or 0) for sample in samples),
                'both_lanes_observed':any(sample['foreground'].get('active') and sample['background'].get('active') for sample in samples),
                'samples':samples}
            (BASE/'resident-stress-metrics.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')
            assert metrics['both_lanes_observed'],'concurrent foreground/background activity was not observed'
            # This fixture submits 28 long documents and 16 content-bearing edits;
            # its background batch is larger than the initial account preparation.
            print('resident phase: final index drain (900s)',flush=True)
            wait_index_ready(timeout=900)
            database = main / 'rsrs.db'
            if not database.exists(): database = main / 'onememory.db'
            with sqlite3.connect(database) as database_connection:
                missing = database_connection.execute(
                    'SELECT COUNT(*) FROM memories m WHERE deleted=0 AND NOT EXISTS '
                    '(SELECT 1 FROM core_artifacts a WHERE a.memory_id=m.id AND a.source=m.ciphertext)').fetchone()[0]
            assert missing == 0, 'background index did not catch up with edited sources'
            light = [entry['seconds'] for entry in timings if entry['command'] == 'show']
            assert max(light) < 5, 'lightweight reads were blocked by inference or background work'
            stress = {'passed':True,'requests':len(timings),'background_source_checks':True,
                'overlap_probe':overlap_details,
                'show_max_seconds':max(light),'timings':timings,'rss_before':baseline_rss,
                'resource_scope':'owned host and all descendants',
                'rss_peak':max(sample['rss'] for sample in samples),
                'private_before':baseline_private,
                'private_peak':max((sample['private'] or 0) for sample in samples),
                'both_lanes_observed':any(sample['foreground'].get('active') and sample['background'].get('active') for sample in samples),
                'samples':samples}
            (BASE/'resident-stress-metrics.json').write_text(json.dumps(stress,indent=2),encoding='utf-8')
        restart_checked=False
        if args.expect_in_process or args.expect_supervised_worker:
            import psutil
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2) as response:
                health=json.load(response)
            owned=psutil.Process(health['pid'])
            retired_workers=[checked_worker(health)] if args.expect_supervised_worker else []
            assert pathlib.Path(owned.exe()).name.lower() in ['rsrs','rsrs.exe']
            assert '--runtime-internal' in owned.cmdline(),'only the isolated runtime may be suspended'
            before_restart={str(profile):snapshot(profile) for profile in [main,alternate]}
            config_before=(main/'client.json').read_bytes()
            try:
                owned.suspend()
                restarted=run('restart','--timeout','1')
            finally:
                if owned.is_running():
                    owned.resume()
            assert restarted['summary']['forced'] is True,restarted
            assert restarted['summary']['stopped_pid']==health['pid'],restarted
            assert restarted['summary']['pid']!=health['pid'],restarted
            confirm_workers_exited(retired_workers)
            assert pathlib.Path(restarted['summary']['data_dir'])==main,restarted
            assert (main/'client.json').read_bytes()==config_before,'restart changed the account or API configuration'
            assert {str(profile):snapshot(profile) for profile in [main,alternate]}==before_restart,'restart changed source, key, sync or compatible index'
            run('model','probe','--model','m3')
            assert run('recall','Real account return fixture','--titles').get('items')
            if args.expect_supervised_worker:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2) as response:
                    checked_worker(json.load(response))
            restart_checked=True
        reports.append({'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binary':str(binary),'passed':True,
            'real_model':True,'model_file':args.model_file,'engine':'cpu','in_process_checked':args.expect_in_process,
            'supervised_worker_checked':args.expect_supervised_worker,'owned_worker_identities':worker_identities,
            'global_engine_preserved':True,'distinct_vault_keys':True,'sequence':statuses,'source_and_keys_unchanged':True,
            'compatible_index_reused':True,'resident_stress':stress,'forced_restart_checked':restart_checked,'old_rpc_checked':old_rpc_checked,
            'old_rpc_authenticated':old_rpc_authenticated,'initial_generation_changes':generation_changes,'fixture':str(root)})
        print('PASS '+str(binary)+': main -> alternate -> main; real CPU inference; compatible index reused after preparation',flush=True)
    except Exception as error:
        reports.append({'binary':str(binary),'passed':False,'error':str(error)[:2000]})
        (BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
        raise
    finally:
        cleanup_errors=[]
        try:
            if inspector is not None: inspector.close()
        except Exception as error: cleanup_errors.append('inspector: '+str(error))
        try:
            stopped=captured_run([str(binary),'--runtime-internal','--stop'],env=env,timeout=50)
            assert stopped.returncode==0,'owned runtime stop failed'
        except Exception as error: cleanup_errors.append('runtime: '+str(error))
        try:
            if args.expect_supervised_worker: confirm_workers_exited(worker_identities)
        except Exception as error: cleanup_errors.append('worker reap: '+str(error))
        try:
            if old_runtime is not None and old_runtime.poll() is None:
                old_runtime.terminate(); old_runtime.wait(timeout=15)
        except Exception as error: cleanup_errors.append('old runtime: '+str(error))
        if cleanup_errors:
            reports[-1]['passed']=False
            reports[-1]['cleanup_errors']=cleanup_errors
        (BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
        if cleanup_errors: raise RuntimeError('fixture cleanup failed: '+str(cleanup_errors))
(BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')

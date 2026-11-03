"""Verify fixture deadlines fail explicitly and reap their owned inspector."""
import argparse
import ast
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import types

from native_fixture_process import ForegroundOverlapProbe, captured_run

parser = argparse.ArgumentParser()
parser.add_argument('--output-dir', required=True)
args = parser.parse_args()
output = pathlib.Path(args.output_dir).resolve()
output.mkdir(parents=True, exist_ok=False)
results = []
# Exercise the actual sampler without starting a runtime: frequent samples read
# fresh memory values, while the original boundary audit discovers new children.
tree = ast.parse(pathlib.Path(__file__).with_name('test-real-m3-account-switch.py').read_text(encoding='utf-8'))
sampler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'total_memory')
scans = []
children = []
class FixtureProcess:
    def __init__(self, rss): self.rss = rss
    def children(self, recursive):
        assert recursive
        scans.append(True)
        return list(children)
    def memory_info(self): return types.SimpleNamespace(rss=self.rss, private=self.rss)
owned, worker = FixtureProcess(10), FixtureProcess(20)
children.append(worker)
namespace = {'owned': owned, 'time': time, 'resource_members': None, 'resource_members_checked': None}
exec(compile(ast.Module(body=[sampler], type_ignores=[]), str(__file__), 'exec'), namespace)
assert namespace['total_memory']() == (30, 30) and len(scans) == 1
worker.rss = 40
for _ in range(50):
    assert namespace['total_memory'](refresh_members=False) == (50, 50)
assert len(scans) == 1, 'continuous sampler rescanned the OS process table'
children.append(FixtureProcess(5))
assert namespace['total_memory']() == (55, 55) and len(scans) == 2
results.append({'scenario': 'fresh RSS without extra global PID scans', 'passed': True,
                'fresh_reads': 50, 'original_audit_detects_new_descendants': True})

# Reproduce a preparation interval longer than the original finite request burst.
# Probes must remain real in-flight calls until a single sample proves overlap.
active = 0
peak = 0
lock = threading.Lock()
def foreground_call(remaining, cancel):
    global active, peak
    assert 0 < remaining <= 1
    with lock:
        active += 1
        peak = max(peak, active)
    try:
        cancel.wait(.01)
        return {'completed': True}
    finally:
        with lock:
            active -= 1
probe = ForegroundOverlapProbe(foreground_call, timeout=1)
probe.start()
try:
    time.sleep(.03)  # The original finite workload has already returned.
    for _ in range(6):
        probe.observe({'foreground': {'active': True}, 'background': {'active': False}})
        probe.check()
        time.sleep(.01)
    assert not probe.observed.is_set() and len(probe.calls) >= 6
    probe.observe({'foreground': {'active': True}, 'background': {'active': True}})
    probe.check()
finally:
    probe.close()
assert probe.observed.is_set() and peak == 2 and active == 0
assert not any(thread.is_alive() for thread in probe.threads)
results.append({'scenario': 'late background preparation retains bounded foreground work', 'passed': True,
                'max_in_flight': peak, 'completed_probes': len(probe.calls)})

for scenario, snapshots in [
    ('serial lanes cannot pass', [
        {'foreground': {'active': True}, 'background': {'active': False}},
        {'foreground': {'active': False}, 'background': {'active': True}}]),
    ('queued lanes cannot pass', [
        {'foreground': {'active': True}, 'background': {'active': False, 'queued': 3}}]),
]:
    probe = ForegroundOverlapProbe(foreground_call, timeout=.15)
    probe.start()
    started = time.monotonic()
    try:
        while True:
            for snapshot in snapshots:
                probe.observe(snapshot)
            probe.check()
            time.sleep(.01)
    except TimeoutError:
        assert not probe.observed.is_set() and time.monotonic() - started < 1
    finally:
        probe.close()
    assert not any(thread.is_alive() for thread in probe.threads)
    results.append({'scenario': scenario, 'passed': True})

probe = ForegroundOverlapProbe(foreground_call, timeout=0)
try:
    probe.observe({'foreground': {'active': True}, 'background': {'active': True}})
    raise AssertionError('late first overlap was accepted')
except TimeoutError:
    assert not probe.observed.is_set()
results.append({'scenario': 'first overlap after deadline cannot pass', 'passed': True})

# A genuine probe failure must not disappear if overlap was already observed.
entered = threading.Event()
release = threading.Event()
def failed_foreground(remaining, cancel):
    entered.set()
    release.wait(timeout=remaining)
    raise RuntimeError('injected foreground error')
probe = ForegroundOverlapProbe(failed_foreground, timeout=1)
probe.start()
assert entered.wait(timeout=1)
probe.observe({'foreground': {'active': True}, 'background': {'active': True}})
release.set()
try:
    probe.close()
    raise AssertionError('failed foreground probe was accepted')
except RuntimeError as error:
    assert 'injected foreground error' in str(error)
assert not any(thread.is_alive() for thread in probe.threads)
results.append({'scenario': 'probe error survives successful overlap', 'passed': True})

# Stopping the challenge must promptly kill/reap both owned CLI processes rather
# than wait for a long command deadline or leave background Python pumps alive.
pids = output / 'cancelled-probe-pids'
pids.mkdir()
def hanging_foreground(remaining, cancel):
    return captured_run([sys.executable, '-c',
        'import os,pathlib,sys,time; pathlib.Path(sys.argv[1],str(os.getpid())).write_text("ready"); time.sleep(30)',
        str(pids)], env=None, timeout=remaining, cancel=cancel)
probe = ForegroundOverlapProbe(hanging_foreground, timeout=5)
probe.start()
deadline = time.monotonic() + 3
while len(list(pids.iterdir())) < 2:
    assert time.monotonic() < deadline, 'probe children did not start'
    time.sleep(.01)
started = time.monotonic()
probe.close(cancel_pending=True)
assert time.monotonic() - started < 2 and not probe.errors
assert not any(thread.is_alive() for thread in probe.threads)
import psutil
assert all(not psutil.pid_exists(int(path.name)) for path in pids.iterdir()), 'cancelled probe child survived'
results.append({'scenario': 'probe cancellation reaps owned clients', 'passed': True})

started = time.monotonic()
try:
    captured_run([sys.executable, '-c', 'import time; time.sleep(30)'], env=None, timeout=.2)
    raise AssertionError('command timeout was accepted')
except subprocess.TimeoutExpired:
    elapsed = time.monotonic() - started
    assert elapsed < 5, 'command cleanup exceeded deadline'
    results.append({'scenario': 'command deadline', 'passed': True, 'seconds': elapsed})

# Inject into a disposable copy, never into runtime or production source.
directory = pathlib.Path(tempfile.mkdtemp(prefix='inspector-fault-', dir=output))
source = pathlib.Path(__file__).with_name('native_fixture_process.py')
fault_source = directory / 'inspector.py'
fault_source.write_text(source.read_text(encoding='utf-8').replace(
    'import psutil\n', 'time.sleep(30)\n    import psutil\n'), encoding='utf-8')
spec = importlib.util.spec_from_file_location('fault_fixture', fault_source)
fault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fault)
inspector = fault.WorkerInspector(directory / 'responses', timeout=.2)
started = time.monotonic()
try:
    inspector.inspect({'host_pid': 0, 'worker_pid': 0})
    raise AssertionError('unresponsive inspection was accepted')
except TimeoutError:
    elapsed = time.monotonic() - started
    assert elapsed < 5 and inspector.process.poll() is not None
    failure = json.loads((directory / 'responses/inspection-failure.json').read_text(encoding='utf-8'))
    assert failure['passed'] is False and 'deadline' in failure['error']
    results.append({'scenario': 'inspection does not respond', 'passed': True,
                    'seconds': elapsed, 'helper_reaped': True})
finally:
    inspector.close()
(output / 'fixture-process-verification.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
print(json.dumps(results), flush=True)

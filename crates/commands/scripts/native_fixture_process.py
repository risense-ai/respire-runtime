"""Bound native-test process waits, including Windows handle inspection.

The inspector preserves boundary assertions in a disposable process: a hung
psutil native call must fail acceptance rather than hang its Python controller.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import traceback


class FixtureCancelled(Exception):
    """An owned fixture command was explicitly stopped and reaped."""


def captured_run(command, *, env, timeout, cancel=None):
    # Regular files avoid communicate() waiting forever for inherited pipe EOF
    # after Windows subprocess.run() kills a timed-out direct child.
    started_unix = time.time()
    started_monotonic = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr)
        try:
            if cancel is None:
                process.wait(timeout=timeout)
            else:
                deadline = started_monotonic + timeout
                while process.poll() is None:
                    if cancel.is_set():
                        raise FixtureCancelled('owned foreground probe stopped')
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        process.wait(timeout=min(.05, remaining))
                    except subprocess.TimeoutExpired:
                        pass
            wait_completed_monotonic = time.monotonic()
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            raise
        stdout.seek(0)
        stderr.seek(0)
        result = subprocess.CompletedProcess(command, process.returncode, stdout.read(), stderr.read())
        result.fixture_timing = {'client_pid': process.pid, 'started_unix': started_unix,
            'started_monotonic': started_monotonic, 'wait_completed_monotonic': wait_completed_monotonic}
        return result


class ForegroundOverlapProbe:
    """Keep at most two real foreground calls in flight during a bounded window.

    The caller must supply an operation honoring its remaining timeout and the
    cancellation event. Only an
    actual same-snapshot pair of active inference lanes completes the challenge;
    queued work or activity in two different snapshots is insufficient.
    """
    def __init__(self, invoke, timeout=120):
        self.invoke = invoke
        self.started = time.monotonic()
        self.deadline = self.started + timeout
        self.observed = threading.Event()
        self.stopped = threading.Event()
        self.cancelled = threading.Event()
        self.calls = []
        self.errors = []
        self.threads = [threading.Thread(target=self._run, name=f'foreground-overlap-{i}', daemon=True)
                        for i in range(2)]

    def start(self):
        for thread in self.threads:
            thread.start()

    def _run(self):
        try:
            while not self.stopped.is_set() and not self.observed.is_set():
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    return
                self.calls.append(self.invoke(remaining, self.cancelled))
        except FixtureCancelled as error:
            if not self.cancelled.is_set():
                self.errors.append(error)
        except BaseException as error:
            self.errors.append(error)

    def observe(self, inference):
        # A late first overlapping heartbeat must not turn an expired challenge
        # into success (HTTP or boundary inspection can cross the deadline).
        self.check()
        if inference.get('foreground', {}).get('active') and inference.get('background', {}).get('active'):
            self.observed.set()

    def check(self):
        if self.errors:
            raise RuntimeError('foreground overlap probe failed: ' + str(self.errors[0])) from self.errors[0]
        if not self.observed.is_set() and time.monotonic() >= self.deadline:
            raise TimeoutError('concurrent foreground/background activity was not observed before the overlap deadline')

    def close(self, cancel_pending=False):
        self.stopped.set()
        if cancel_pending:
            self.cancelled.set()
        # In-flight captured_run calls honor cancellation and the shared deadline,
        # reaping their child in either case. On success, drain submitted calls
        # so their errors and completion are checked before later index checks.
        for thread in self.threads:
            thread.join(timeout=max(0, self.deadline - time.monotonic()) + 6)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError('foreground overlap probe did not stop')
        if self.errors:
            raise RuntimeError('foreground overlap probe failed: ' + str(self.errors[0])) from self.errors[0]


def inspect_worker(request, phase):
    import psutil
    phase('children')
    host = psutil.Process(request['host_pid'])
    assert '--runtime-internal' in host.cmdline(), 'inspection must target the fixture runtime'
    children = [child for child in host.children(recursive=True)
                if not (sys.platform == 'win32' and child.name().lower() == 'conhost.exe')]
    assert len(children) == 1, 'expected exactly one supervised Core worker'
    worker = children[0]
    assert worker.pid == request['worker_pid'] and worker.ppid() == host.pid
    assert '--core-worker-internal' in worker.cmdline()
    assert pathlib.Path(worker.exe()).resolve() == pathlib.Path(host.exe()).resolve()
    phase('open_files')
    assert not any(pathlib.Path(file.path).name in ('rsrs.db', 'lock.db') for file in worker.open_files())
    phase('environ')
    assert not {'GH_TOKEN', 'GITHUB_TOKEN', 'OPENAI_API_KEY', 'RSRS_SUPER'} & worker.environ().keys()
    phase('identity')
    return [worker.pid, worker.create_time()]


class WorkerInspector:
    def __init__(self, directory, timeout=5):
        self.directory = pathlib.Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.timeout = timeout
        self.sequence = 0
        self.log = (self.directory / 'inspector.log').open('wb')
        self.process = subprocess.Popen([sys.executable, '-u', __file__, str(self.directory)],
                                        stdin=subprocess.PIPE, stdout=self.log, stderr=self.log)

    def inspect(self, request):
        self.sequence += 1
        request = {**request, 'sequence': self.sequence}
        response = self.directory / ('response-' + str(self.sequence) + '.json')
        self.process.stdin.write((json.dumps(request) + '\n').encode())
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            if self.process.poll() is not None:
                self.record_failure('worker inspector exited')
                raise RuntimeError('worker inspector exited; see ' + str(self.directory / 'inspector.log'))
            if time.monotonic() >= deadline:
                self.record_failure('worker boundary inspection exceeded deadline')
                self.close()
                raise TimeoutError('worker boundary inspection exceeded ' + str(self.timeout) +
                                   's; see ' + str(self.directory / 'inspector.log'))
            try:
                result = json.loads(response.read_text(encoding='utf-8'))
                break
            except (FileNotFoundError, PermissionError):
                # Windows may briefly deny access while a just-renamed file is
                # being closed or scanned. This shares the inspection deadline.
                time.sleep(.005)
        if not result['passed']:
            self.record_failure(result.get('error', 'worker boundary assertion failed'))
            raise AssertionError(result.get('error'))
        return tuple(result['identity'])

    def record_failure(self, reason):
        # Persist before kill/wait: a cleanup failure cannot erase the cause.
        (self.directory / 'inspection-failure.json').write_text(json.dumps({
            'passed': False, 'sequence': self.sequence, 'helper_pid': self.process.pid,
            'deadline_seconds': self.timeout, 'error': reason,
        }, indent=2), encoding='utf-8')

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
        finally:
            self.process.stdin.close()
            self.log.close()


def serve(directory):
    import faulthandler
    faulthandler.enable()
    directory = pathlib.Path(directory)
    import psutil
    print(json.dumps({'inspector_pid': os.getpid(), 'psutil': psutil.__version__}), flush=True)
    # One watchdog for the helper lifetime; do not create/join a timer thread
    # for every high-frequency check, and cover response I/O as well as psutil.
    faulthandler.dump_traceback_later(3, repeat=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            sequence = request['sequence']
            def phase(name):
                print(json.dumps({'sequence': sequence, 'phase': name, 'monotonic': time.monotonic()}), flush=True)
            try:
                identity = inspect_worker(request, phase)
                result = {'passed': True, 'identity': identity}
            except Exception:
                result = {'passed': False, 'error': traceback.format_exc()}
            phase('response')
            temporary = directory / 'response.tmp'
            temporary.write_text(json.dumps(result), encoding='utf-8')
            os.replace(temporary, directory / ('response-' + str(sequence) + '.json'))
            phase('responded')
    finally:
        faulthandler.cancel_dump_traceback_later()


if __name__ == '__main__':
    serve(sys.argv[1])

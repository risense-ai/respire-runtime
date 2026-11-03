"""Matched published-binary CPU benchmark. CI-owned synthetic vaults only."""
import concurrent.futures
import hashlib
import hmac
import json
import math
import os
import pathlib
import platform
import secrets
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.request

import psutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = pathlib.Path(os.environ['PERF_ROOT']).resolve()
MODEL = pathlib.Path(os.environ['PERF_MODEL']).resolve()
TARGET = os.environ['PERF_TARGET']
VERSIONS = ['1.0.12', '1.0.13-dev.6']
DOCUMENTS = ['Performance fixture document %03d. ' % i +
             ('Background indexing and foreground memory retrieval. ' * 24) +
             ' Unique topic number %03d.' % i for i in range(64)]
REPORT = {'versions': VERSIONS, 'target': TARGET, 'engine': 'cpu',
          'dataset_sha256': hashlib.sha256('\n'.join(DOCUMENTS).encode()).hexdigest(),
          'documents': len(DOCUMENTS), 'requests_per_batch': 24,
          'latency_scope': 'client-only CLI process and loopback RPC end-to-end',
          'percentile_method': 'nearest rank; successful requests only',
          'hardware': {'platform': platform.platform(), 'cpu': platform.processor(),
                       'logical_cpus': psutil.cpu_count(), 'memory_bytes': psutil.virtual_memory().total},
          'results': [], 'complete': False}


def save():
    (ROOT / 'report.json').write_text(json.dumps(REPORT, indent=2), encoding='utf-8')


def published(version):
    folder = ROOT / ('assets-' + version)
    folder.mkdir(parents=True, exist_ok=True)
    subprocess.run(['gh', 'release', 'download', 'v' + version, '--repo', 'risense-ai/respire-cli',
                    '--pattern', 'cli-build-' + TARGET + '.json', '--pattern', 'rsrs-' + TARGET + '*',
                    '--dir', str(folder)], check=True, timeout=180)
    meta = json.loads((folder / ('cli-build-' + TARGET + '.json')).read_text())
    assert meta['version'] == version and meta['target'] == TARGET
    for file_key, hash_key in [('binary_file', 'binary_sha256'), ('runtime_file', 'runtime_sha256')]:
        assert hashlib.sha256((folder / meta[file_key]).read_bytes()).hexdigest() == meta[hash_key]
    destination = ROOT / ('binary-' + version)
    destination.mkdir()
    with tarfile.open(folder / meta['runtime_file']) as archive:
        archive.extractall(destination, filter='data')
    binary = destination / ('rsrs.exe' if os.name == 'nt' else 'rsrs')
    binary.write_bytes((folder / meta['binary_file']).read_bytes())
    binary.chmod(0o755)
    return binary, meta


def environment(root):
    profile = root / '.rsrs'
    profile.mkdir(parents=True)
    entropy, salt, nonce, urk = secrets.token_bytes(18), secrets.token_bytes(16), secrets.token_bytes(12), secrets.token_bytes(32)
    code = 'A3-' + '-'.join(entropy.hex().upper()[i:i + 6] for i in range(0, 36, 6))
    kek = hmac.new(hmac.new(salt, entropy, hashlib.sha256).digest(), b'onememory:kek:v4\x01', hashlib.sha256).digest()
    (profile / 'session.json').write_text(json.dumps({'user': 'synthetic-performance', 'vault_version': 4,
        'kdf_salt': salt.hex(), 'wrapped_urk': AESGCM(kek).encrypt(nonce, urk, None).hex(), 'urk_nonce': nonce.hex()}))
    (profile / 'client.json').write_text(json.dumps({'addr': 'https://fixture.invalid', 'autosync': False, 'data_dir': str(profile)}))
    env = {k: v for k, v in os.environ.items() if not k.startswith(('RSRS_', 'ONEMEMORY_', 'RESPIRE_'))}
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    env.update(HOME=str(root), USERPROFILE=str(root), RSRS_DATA_DIR=str(profile), RSRS_RPC_PORT=str(port),
               RSRS_SUPER=code, RSRS_NO_AUTOSYNC='1', RSRS_UPDATE_CHECK='0', RSRS_M3_DIR=str(MODEL), RSRS_ENGINE='cpu')
    return env, port


def request(binary, env, args, direct=False):
    start = time.perf_counter()
    try:
        completed = subprocess.run([str(binary), '--json', '--direct' if direct else '--client-only', *args],
                                   env=env, capture_output=True, timeout=300 if direct else 60)
        try:
            envelope = json.loads(completed.stdout)
        except (ValueError, UnicodeError):
            envelope = {}
        ok = completed.returncode == 0 and envelope.get('status') in ('ok', 'warn')
        return {'seconds': time.perf_counter() - start, 'ok': ok, 'exit': completed.returncode,
                'status': envelope.get('status'), 'error_codes': [e.get('code') for e in envelope.get('errors', [])],
                'items': len(envelope.get('items', []))}, envelope
    except subprocess.TimeoutExpired:
        return {'seconds': time.perf_counter() - start, 'ok': False, 'timeout': True}, {}


def required(binary, env, args, direct=False):
    metric, envelope = request(binary, env, args, direct)
    assert metric['ok'], {'command': args[0], 'metric': metric}
    return envelope


def ready(binary, env):
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        _, data = request(binary, env, ['doctor'])
        rows = {i['name']: i['status'] for i in data.get('items', []) if i['name'] in ('embedder', 'model index')}
        if len(rows) == 2 and all(v == 'ok' for v in rows.values()):
            return
        time.sleep(.5)
    raise RuntimeError('index readiness exceeded 600 seconds')


def batch(binary, env, name, command, concurrency, count=24):
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        metrics = list(executor.map(lambda _: request(binary, env, command)[0], range(count)))
    wall = time.perf_counter() - start
    successful = sorted(m['seconds'] for m in metrics if m['ok'])
    percentile = lambda p: successful[max(0, math.ceil(p * len(successful)) - 1)] if successful else None
    return {'scenario': name, 'concurrency': concurrency, 'requests': count,
            'successful': len(successful), 'failed': count - len(successful), 'wall_seconds': wall,
            'successful_qps': len(successful) / wall, 'p50_seconds': percentile(.5), 'p95_seconds': percentile(.95),
            'max_seconds': max(successful) if successful else None, 'raw': metrics}


def benchmark(binary, meta, number):
    # Short CI-owned path also keeps UNIX socket paths within their limit.
    root = ROOT.parent / ('p' + str(number))
    root.mkdir()
    env, port = environment(root)
    result = {'version': meta['version'], 'git_sha': meta['git_sha'], 'binary_sha256': meta['binary_sha256'], 'batches': []}
    REPORT['results'].append(result)
    required(binary, env, ['model', 'engine', 'cpu'], direct=True)
    for asset in ('onnx/model_quantized.onnx', 'tokenizer.json'):
        destination = MODEL / asset
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            url = 'https://huggingface.co/Xenova/bge-m3/resolve/4de13258303883538bd53b696b452bf8099f0858/' + asset
            with urllib.request.urlopen(url, timeout=60) as response, destination.open('wb') as output:
                shutil.copyfileobj(response, output)
    for name, expected in {
        'onnx/model_quantized.onnx': '0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
        'tokenizer.json': '6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790'}.items():
        assert hashlib.sha256((MODEL / name).read_bytes()).hexdigest() == expected
    REPORT['model'] = {'name': 'BGE-M3 quantized', 'onnx_sha256':
                        hashlib.sha256((MODEL / 'onnx/model_quantized.onnx').read_bytes()).hexdigest()}
    required(binary, env, ['model', 'activate', 'm3'], direct=True)
    # Force writes bypass semantic deduplication equally in both versions.
    ids = []
    for i, document in enumerate(DOCUMENTS):
        envelope = required(binary, env, ['remember', document, '--title', 'document-%03d' % i,
                                        '--importance', 'important', '--force'], direct=True)
        ids.append(envelope['summary']['id'])
        if (i + 1) % 16 == 0:
            print(meta['version'], 'seeded', i + 1, flush=True)
    log = (root / 'runtime.log').open('wb')
    worker = subprocess.Popen([str(binary), '--runtime-internal'], env=env, stdout=log, stderr=log)
    log.close()
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            assert worker.poll() is None, 'owned runtime exited during startup'
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=1) as response:
                    health = json.load(response)
                assert health['pid'] == worker.pid
                break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('owned runtime startup timeout')
        recall = ['recall', 'Background indexing foreground memory retrieval', '--titles', '--no-related', '--limit', '5']
        result['first_recall'] = request(binary, env, recall)[0]
        ready(binary, env)
        required(binary, env, recall)
        process = psutil.Process(worker.pid)
        result['ready_rss_bytes'] = process.memory_info().rss
        for concurrency in (1, 4, 16):
            for name, command in [('warm_recall', recall), ('warm_show', ['show', ids[0]])]:
                result['batches'].append(batch(binary, env, name, command, concurrency))
                save()
        # Submit writes and readers together. Report overlap from measured
        # timelines, without claiming an artificial pure indexing benchmark.
        start = time.perf_counter()
        def write(i):
            return request(binary, env, ['remember', DOCUMENTS[i] * 3, '--title', 'new-%d' % i,
                                        '--importance', 'important', '--force'])[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            writes = [pool.submit(write, i) for i in range(8)]
            result['batches'].append(batch(binary, env, 'recall_during_writes_and_indexing', recall, 16))
            result['batches'].append(batch(binary, env, 'show_after_write_submission', ['show', ids[0]], 16))
            result['writes'] = [f.result() for f in writes]
        result['mixed_wall_seconds'] = time.perf_counter() - start
        result['mixed_rss_bytes'] = process.memory_info().rss
        ready(binary, env)
        result['complete'] = True
    finally:
        subprocess.run([str(binary), '--runtime-internal', '--stop'], env=env, capture_output=True, timeout=50)
        if worker.poll() is None:
            worker.terminate()
            worker.wait(timeout=15)
        save()


if __name__ == '__main__':
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'benchmark is restricted to CI-owned fixtures'
    ROOT.mkdir(parents=True, exist_ok=True)
    try:
        for index, version in enumerate(VERSIONS):
            print('Preparing published', version, TARGET, flush=True)
            binary, metadata = published(version)
            benchmark(binary, metadata, index)
        REPORT['complete'] = True
    finally:
        save()

#!/usr/bin/env python3
"""Real candidate lifecycle regression; deliberately not a frozen G1 report."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import tomllib
import urllib.request


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    source = Path('target/debug/rsrs-runtime').resolve()
    sdk = Path('.sdk') / os.environ['RUNTIME_TARGET']
    manifest = json.loads((sdk / 'manifest.json').read_text())
    version = tomllib.loads(Path('runtime/Cargo.toml').read_text())['package']['version']
    root = Path(tempfile.mkdtemp(prefix='runtime background with spaces ', dir=os.environ['RUNNER_TEMP']))
    data = root / 'data'
    data.mkdir()
    payload = data / 'client2' / 'runtime' / version
    payload.mkdir(parents=True)
    executable = payload / 'rsrs-runtime'
    shutil.copy2(source, executable)
    for entry in manifest['files']:
        if entry['path'].startswith('runtime/'):
            file = sdk / entry['path']
            assert digest(file) == entry['sha256']
            shutil.copy2(file, payload / file.name)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('RSRS_')
           and k not in ('GH_TOKEN', 'GITHUB_TOKEN', 'CORE_SDK_READ_TOKEN')}
    env.update(HOME=str(root), XDG_CONFIG_HOME=str(root / 'config'),
               XDG_DATA_HOME=str(root / 'xdg-data'), XDG_CACHE_HOME=str(root / 'cache'),
               RSRS_DATA_DIR=str(data), RSRS_RPC_PORT=str(port), RSRS_ENGINE='cpu')
    client2_source = Path('.client2-source').resolve()
    client2_sha = subprocess.check_output(['git', '-C', str(client2_source), 'rev-parse', 'HEAD'], text=True).strip()
    assert client2_sha == '57bc070826949994c3f7ce9a64277160704bdfe5'
    assert not subprocess.check_output(['git', '-C', str(client2_source), 'status', '--porcelain'], text=True).strip()
    probe = root / 'probe'
    probe.mkdir()
    (probe / 'go.mod').write_text('module respire-client2/regression\n\ngo 1.26.0\n\n'
        'require respire-client2 v0.0.0\nreplace respire-client2 => ' + json.dumps(str(client2_source)) + '\n')
    shutil.copy2(client2_source / 'go.sum', probe / 'go.sum')
    shutil.copy2('scripts/fixtures/client2-background/main.go', probe / 'main.go')
    # This generated wrapper has no VCS repository; the actual Client2 source
    # is independently pinned and checked above, not inferred from Go stamping.
    subprocess.run(['go', 'build', '-buildvcs=false', '-mod=mod', '-o', str(probe / 'probe'), '.'],
                   cwd=probe, check=True, timeout=180)
    (data / 'client2' / 'runtime.json').write_text(json.dumps({'version': version, 'sha256': digest(executable)}))
    evidence = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                'target': os.environ['RUNTIME_TARGET'], 'version': version,
                'client2_source': client2_sha,
                'binary_sha256': digest(executable), 'g1_passed': False, 'passed': False, 'commands': []}

    def client2(action):
        result = subprocess.run([str(probe / 'probe'), action], env=env, capture_output=True, timeout=150)
        value = {'client2_action': action, 'exit': result.returncode,
                 'stdout': result.stdout.decode('utf-8'), 'stderr': result.stderr.decode('utf-8')}
        evidence['commands'].append(value)
        assert result.returncode == 0, value
        reply = json.loads(value['stdout'])
        assert reply['ok'] is True, reply
        if action == 'start':
            assert reply['reply']['ok'] is True, reply

    def command(action):
        result = subprocess.run([str(executable), '--json', 'runtime', action], env=env,
                                capture_output=True, timeout=150)
        value = {'action': action, 'exit': result.returncode,
                 'stdout': result.stdout.decode('utf-8'), 'stderr': result.stderr.decode('utf-8')}
        evidence['commands'].append(value)
        assert result.returncode == 0, value
        reply = json.loads(value['stdout'])
        assert reply['ok'] is True and reply['exit'] == 0 and reply['v'] == 1, reply
        return reply

    try:
        client2('start')
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=5) as response:
            raw = response.read(1024 * 1024 + 1)
        assert len(raw) <= 1024 * 1024
        health = json.loads(raw)
        assert health['pid'] > 0 and health['startup_complete'] is True
        assert Path(health['exe']).resolve() == executable.resolve()
        assert Path(health['image_path']).resolve() == executable.resolve()
        assert Path(health['installation_root']).resolve() == data.resolve()
        assert health['image_sha256'] == evidence['binary_sha256']
        assert health['runtime_version'] == version and health['bin'] == version
        evidence['health'] = health
        assert command('start')['result'] == 'already_running'
        assert command('status')['pid'] == health['pid']
        client2('stop')
        receipt = json.loads((data / 'runtime' / f"stop-{health['instance_id']}.json").read_text())
        for key in ('pid', 'installation_id', 'instance_id', 'process_start_id', 'image_sha256',
                    'runtime_version', 'account_id', 'generation'):
            assert receipt[key] == health[key], key
        assert receipt['state'] == 'drained' and receipt['unfinished'] == []
        assert command('status')['result'] == 'not_running'
        evidence['passed'] = True
    finally:
        try:
            command('stop')
        except Exception:
            evidence['passed'] = False
            raise
        finally:
            print(json.dumps(evidence, indent=2), flush=True)
    shutil.rmtree(root)


if __name__ == '__main__':
    main()

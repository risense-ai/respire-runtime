#!/usr/bin/env python3
"""Actions-only local HTTP adapter smoke using a disposable Linux runtime.

Requires an ephemeral GitHub-hosted Linux runner: Linux keyring storage belongs
to the runner, not HOME. Models use this run's fresh temporary directory, on CPU.
Reports contain action names/statuses only, never payloads, keys or arguments.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def has(value, key, expected=None):
    return any(key in obj and (expected is None or obj[key] == expected) for obj in objects(value))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Suite:
    def __init__(self, args):
        self.args = args
        self.catalog = json.loads(Path(__file__).with_name('dev-local-api-coverage.json').read_text(encoding='utf-8'))
        self.coverage = {a['action']: dict(a, positive=[], negative=[], failures=[]) for a in self.catalog['actions']}
        self.events = []
        self.diagnostics = []
        self.conditional = []
        self.runtime = None
        self.dbus = None
        self.keyring = None
        self.token = None
        self.env = None
        self.root = args.root.resolve()
        self.library = self.root / 'library'
        self.home = self.root / 'home'
        self.created_user = None
        self.root_created = False
        self.register_attempted = False
        self.cleanup_ok = True
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.user = 'ci-local-' + os.environ.get('GITHUB_RUN_ID', '') + '-' + secrets.token_hex(4)
        self.password = "-" + secrets.token_urlsafe(32)
        self.super = None

    def owned(self, path):
        path = Path(path).resolve()
        require(path != self.root and self.root in path.parents, 'path-outside-owned-fixture')
        return path

    def setup(self):
        require(os.environ.get('GITHUB_ACTIONS') == 'true', 'github-actions-required')
        require(os.environ.get('RUNNER_OS') == 'Linux', 'isolated-linux-keyring-required')
        require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'ephemeral-github-hosted-runner-required')
        require(os.environ.get('RSRS_DEV_SERVER_ADDR') == 'https://api-dev.rsrs.rs', 'exact-development-server-required')
        require(re.fullmatch('[0-9a-f]{40}', self.args.cli_source_sha) is not None, 'exact-cli-source-sha-required')
        require(os.environ.get('CLI_SHA', os.environ.get('GITHUB_SHA')) == self.args.cli_source_sha, 'cli-build-source-sha-mismatch')
        require(hashlib.sha256(self.args.binary.read_bytes()).hexdigest() == self.args.binary_sha256.lower(), 'exact-cli-binary-sha-mismatch')
        require(len(self.coverage) == 72, 'local-action-catalog-mismatch')
        temporary = Path(os.environ.get('RUNNER_TEMP', '')).resolve()
        require(temporary != Path.cwd().resolve() and temporary in self.root.parents and not self.root.exists(), 'fresh-runner-temp-root-required')
        self.root.mkdir(mode=0o700)
        self.root_created = True
        for directory in ('home', 'library', 'config', 'data', 'cache', 'tmp', 'runtime', 'bin', 'models', 'files'):
            (self.root / directory).mkdir(mode=0o700)
        (self.home / '.codex').mkdir(mode=0o700)
        (self.home / '.codex' / 'AGENTS.md').write_text('# Fixture\n', encoding='utf-8')
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('ONEMEMORY_', 'RESPIRE_', 'XDG_', 'GNOME_'))
                    and not k.endswith(('_TOKEN', '_API_KEY'))
                    and k not in ('HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'DBUS_SESSION_BUS_ADDRESS')}
        self.env.update(HOME=str(self.home), USERPROFILE=str(self.home),
                        XDG_CONFIG_HOME=str(self.root / 'config'), XDG_DATA_HOME=str(self.root / 'data'),
                        XDG_CACHE_HOME=str(self.root / 'cache'), XDG_RUNTIME_DIR=str(self.root / 'runtime'),
                        TMPDIR=str(self.root / 'tmp'), RSRS_BIN_DIR=str(self.root / 'bin'),
                        RSRS_DATA_DIR=str(self.root),
                        RSRS_M3_DIR=str(self.root / 'models' / 'bge-m3'),
                        RSRS_ENGINE='cpu', RSRS_NO_AUTOSYNC='1')
        require('RSRS_CORE_TEST_MODE' not in self.env
                and Path(self.env['RSRS_DATA_DIR']).resolve() == self.root, 'fixture-environment-not-isolated')
        version = subprocess.run([str(self.args.binary), '--version'], env=self.env, capture_output=True, text=True, timeout=20)
        require(version.returncode == 0 and version.stdout.strip().split()[-1] == self.args.version, 'exact-cli-version-mismatch')
        self.direct(['config', '--data-dir', str(self.library), '--addr', 'https://api-dev.rsrs.rs', '--autosync', 'false'])
        self.direct(['model', 'install-m3'], timeout=1200)
        probe = self.direct(['model', 'probe', '--model', 'm3'], timeout=180)
        require(probe.get('status') == 'ok' and probe.get('summary', {}).get('ready') is True
                and probe['summary'].get('dimensions', 0) > 0, 'real-cpu-model-probe-failed')
        self.model_dimensions = probe['summary']['dimensions']
        self.start()

    def direct(self, command, timeout=90):
        process = subprocess.run([str(self.args.binary), '--direct', '--json', *command], env=self.env, cwd=self.root,
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        require(process.returncode == 0, 'owned-direct-command-failed')
        try:
            value = json.loads(next(x for x in reversed(process.stdout.splitlines()) if x.strip()))
        except (ValueError, StopIteration):
            raise Failure('owned-direct-envelope-invalid') from None
        require(isinstance(value, dict) and value.get('status') in ('ok', 'warn', 'pending', 'skip'), 'owned-direct-command-not-successful')
        return value

    def profile(self):
        value = self.direct(['config'])
        return self.owned(value['summary']['data_dir'])

    def start(self):
        require(self.runtime is None, 'runtime-already-owned')
        require(hashlib.sha256(self.args.binary.read_bytes()).hexdigest() == self.args.binary_sha256.lower(), 'runtime-binary-changed')
        self.current_profile = self.profile()
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            self.port = port.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(self.port)
        env = dict(self.env, RSRS_RPC_PORT=str(self.port))
        self.runtime = subprocess.Popen([str(self.args.binary), 'web', '--internal', '--no-open', '--port', str(self.port)],
                                        env=env, cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 40
        # The runtime belongs to the isolated profile root, while health reports
        # the currently selected descendant library or space profile.
        token_file = self.root / 'runtime' / 'token'
        while time.monotonic() < deadline:
            require(self.runtime.poll() is None, 'owned-runtime-exited-before-ready')
            if token_file.is_file():
                self.token = token_file.read_text(encoding='utf-8').strip()
                try:
                    status, health = self.request('GET', '/api/health')
                except Failure:
                    time.sleep(0.2)
                    continue
                if status == 200:
                    self.health_assert(health)
                    return
            time.sleep(0.2)
        raise Failure('owned-runtime-ready-timeout')

    def health_assert(self, health):
        require(isinstance(health, dict) and health.get('v') == 1 and health.get('bin') == self.args.version,
                'runtime-protocol-version-mismatch')
        require(health.get('pid') == self.runtime.pid and Path(health.get('exe', '')).resolve() == self.args.binary.resolve(),
                'runtime-process-binary-mismatch')
        require(Path(health.get('data_dir', '')).resolve() == self.current_profile, 'runtime-profile-mismatch')
        address = urllib.parse.urlsplit(health.get('url', ''))
        require(address.scheme == 'http' and address.netloc == '127.0.0.1:' + str(self.port)
                and address.path == '/' and not address.fragment
                and urllib.parse.parse_qsl(address.query, keep_blank_values=True) == [('token', self.token)],
                'runtime-owned-token-address-mismatch')

    def stop(self):
        if self.runtime is None:
            return
        self.runtime.terminate()
        try:
            self.runtime.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.runtime.kill()
            self.runtime.wait(timeout=10)
        self.runtime = None
        self.token = None

    def request(self, method, path, body=None, authenticated=True, timeout=180):
        require(self.runtime is not None and self.runtime.poll() is None, 'owned-runtime-not-running')
        headers = {'Content-Type': 'application/json'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request(self.url + path, None if body is None else json.dumps(body).encode(), headers, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError):
            raise Failure('local-http-request-failed') from None
        with response:
            status = response.code
            raw = response.read(8 * 1024 * 1024 + 1)
        require(len(raw) <= 8 * 1024 * 1024, 'local-response-size-exceeded')
        try:
            return status, json.loads(raw)
        except (UnicodeError, ValueError):
            raise Failure('local-response-not-json') from None

    def invoke(self, action, args=None, predicate=None, status=200, kind='positive', label='semantic-result', timeout=180):
        require(action in self.coverage, 'unknown-catalog-action')
        actual, value = self.request('POST', '/api/invoke', {'cmd': action, 'args': args or {}}, timeout=timeout)
        ok = actual == status and (predicate is None or predicate(value))
        event = {'action': action, 'kind': kind, 'assertion': label, 'expected_status': status, 'actual_status': actual, 'passed': bool(ok)}
        self.events.append(event)
        if not ok:
            self.coverage[action]['failures'].append(event)
            if action == 'doctor':
                self.doctor_diagnostics()
            raise Failure('local-action-semantic-assertion-failed')
        self.coverage[action][kind].append(label)
        return value

    def doctor_diagnostics(self):
        # Raw RPC preserves a failed diagnostic envelope. Only allowlisted
        # names/statuses and numeric counts leave memory; never item values.
        names = {'store', 'data dir', 'mcp bin', 'mcp http', 'session', 'embedder',
                 'lock', 'remote', 'inject', 'memory status', 'tidy counter', 'CLI version'}
        statuses = {'ok', 'warn', 'fail', 'skip', 'pending'}
        try:
            status, response = self.request('POST', '/api/rpc',
                {'v': 1, 'id': 'ci-doctor-diagnostic-' + secrets.token_hex(4),
                 'method': 'cli.exec', 'args': ['--json', 'doctor']})
            envelope = response.get('envelope', {})
            require(status == 200 and isinstance(envelope, dict) and envelope.get('command') == 'doctor',
                    'doctor-diagnostic-envelope-unavailable')
            items = envelope.get('items', [])
            require(isinstance(items, list), 'doctor-diagnostic-items-unavailable')
            summary = envelope.get('summary', {})
            require(isinstance(summary, dict), 'doctor-diagnostic-summary-unavailable')
            self.diagnostics.append({'action': 'doctor', 'available': True,
                'items': [{'name': item['name'], 'status': item['status']} for item in items
                          if isinstance(item, dict) and item.get('name') in names and item.get('status') in statuses],
                'summary': {field: summary[field] for field in ('pass', 'warn', 'fail', 'skip', 'total')
                            if type(summary.get(field)) is int and 0 <= summary[field] <= 100},
                'version': self.args.version if summary.get('version') == self.args.version else 'unexpected-version'})
        except Failure as failure:
            self.diagnostics.append({'action': 'doctor', 'available': False, 'failure_code': str(failure)})
        except Exception:
            self.diagnostics.append({'action': 'doctor', 'available': False, 'failure_code': 'doctor-diagnostics-unavailable'})

    def guarded(self, action, args, direct_args, proof):
        self.invoke(action, args, lambda v: isinstance(v, dict) and 'runtime owns its boot profile' in v.get('error', ''),
                    status=500, kind='negative', label='hot-profile-change-rejected')
        before = self.runtime.pid
        self.stop()
        outcome = self.direct(direct_args)
        require(proof(outcome), 'owned-profile-transition-proof-failed')
        self.start()
        require(self.runtime.pid != before, 'profile-transition-did-not-restart')
        self.coverage[action]['positive'].append('guarded-host-transition-and-new-runtime-health')
        self.stop()
        self.direct(['config', '--data-dir', str(self.library)])
        self.start()
        return outcome

    def negatives(self):
        for action in self.coverage:
            status, value = self.request('POST', '/api/invoke', {'cmd': action, 'args': {}}, authenticated=False)
            require(status == 401 and isinstance(value, dict) and 'error' in value, 'local-missing-auth-not-rejected')
            self.coverage[action]['negative'].append('missing-runtime-bearer-rejected')
        status, value = self.request('POST', '/api/invoke', {})
        require(status == 400 and value.get('error') == 'missing cmd', 'local-missing-command-contract-failed')
        status, value = self.request('POST', '/api/invoke', {'cmd': 'ci_unknown_action'})
        require(status == 500 and 'unknown command' in value.get('error', ''), 'local-unknown-command-contract-failed')

    def create(self, title, content, parent=None):
        args = {'title': title, 'content': content, 'kind': 'context', 'importance': 'important', 'force': True}
        if parent:
            args['parent'] = parent
        value = self.invoke('create', args, lambda v: bool(v.get('id')) and v.get('action') == 'created')
        return value['id']

    def run_actions(self):
        self.negatives()
        self.rpc_proofs()
        key = self.invoke('keygen', {}, lambda v: bool(v.get('super')) and bool(v.get('path')))
        self.super = key['super']
        self.register_attempted = True
        registered = self.invoke('register', {'user': self.user, 'pass': self.password, 'addr': 'https://api-dev.rsrs.rs'},
                                 lambda v: v.get('ok') is True and v.get('user') == self.user and bool(v.get('super')))
        self.created_user = self.user
        self.super = registered['super']
        self.invoke('login', {'user': self.user, 'pass': self.password, 'addr': 'https://api-dev.rsrs.rs', 'super_pass': self.super},
                    lambda v: v.get('ok') is True and v.get('user') == self.user)
        self.invoke('resume_session', {}, lambda v: v.get('resumed') is True and v.get('user') == self.user)
        self.invoke('server_addr_set', {'addr': 'https://api-dev.rsrs.rs'}, lambda v: v.get('addr') == 'https://api-dev.rsrs.rs')
        self.invoke('server_addr_get', {}, lambda v: v.get('addr') == 'https://api-dev.rsrs.rs')
        self.invoke('sync_config_set', {'autosync': False}, lambda v: v.get('autosync') is False)
        self.invoke('cure_config_set', {'on': False}, lambda v: v.get('cure_auto') is False)
        self.invoke('config_get', {}, lambda v: Path(v['data_dir']).resolve() == self.library and v['addr'] == 'https://api-dev.rsrs.rs')
        self.invoke('data_dir_set', {'dir': str(self.library)}, lambda v: Path(v['data_dir']).resolve() == self.library)
        self.invoke('diary_mode_set', {'mode': 'verbose'}, lambda v: v.get('action') == 'updated'
                    and v.get('key') == 'diary_mode' and v.get('value') == 'verbose')
        self.invoke('diary_mode_get', {}, lambda v: v.get('diary_mode') == 'verbose')
        self.invoke('workspace_mode_set', {'mode': 'normal'}, lambda v: v.get('ok') is True and v.get('mode') == 'normal')
        self.invoke('workspace_mode_get', {}, lambda v: v.get('mode') == 'normal')
        self.invoke('list_system_fonts', {}, lambda v: isinstance(v.get('fonts'), list) and bool(v['fonts']))
        root_id = self.create('Local HTTP root', 'Fixture root: durable local HTTP adapter validation with distinct semantic content.')
        child_id = self.create('Local HTTP child', 'Fixture child: a separate record to validate editing, causal attachment and archive restore.', root_id)
        self.invoke('status', {}, lambda v: v.get('local_alive', 0) >= 2 and v.get('unlocked') is True)
        self.invoke('db_stamp', {}, lambda v: isinstance(v, int) and v > 0)
        self.invoke('list', {'limit': 50}, lambda v: isinstance(v, list) and has(v, 'id', child_id))
        self.invoke('search', {'q': 'local HTTP adapter', 'limit': 20}, lambda v: isinstance(v, list) and has(v, 'id', root_id))
        self.invoke('show', {'id': child_id}, lambda v: v.get('entry', {}).get('id') == child_id)
        self.invoke('tree', {'from': root_id, 'depth': 5}, lambda v: isinstance(v, list) and has(v, 'id', child_id))
        self.invoke('candidates', {'content': 'Durable local HTTP adapter validation candidate'}, lambda v: 'merge' in v and 'parent' in v)
        self.invoke('update', {'id': child_id, 'title': 'Local HTTP updated'}, lambda v: v.get('id') == child_id)
        self.invoke('show', {'id': child_id}, lambda v: v.get('entry', {}).get('title') == 'Local HTTP updated', label='update-readback')
        self.invoke('promote', {'id': child_id}, lambda v: v.get('id') == child_id and 'new_parent' in v)
        self.invoke('attach', {'id': child_id, 'parent': root_id}, lambda v: v.get('child') == child_id and v.get('parent') == root_id)
        self.invoke('demote', {'id': child_id, 'parent': root_id}, lambda v: v.get('id') == child_id and v.get('parent') == root_id)
        self.invoke('delete', {'id': child_id}, lambda v: v.get('deleted') is True)
        self.invoke('restore', {'id': child_id}, lambda v: v.get('restored') is True)
        exported = self.root / 'files' / 'export.json'
        self.invoke('export_memories', {'path': str(exported)}, lambda v: v.get('exported', 0) >= 2 and exported.is_file())
        self.invoke('purge', {'id': child_id}, lambda v: v.get('purged') is True)
        self.invoke('import_memories', {'path': str(exported)}, lambda v: v.get('imported') == 1 and v.get('duplicates') == 1
                    and v.get('reattached') == 1 and v.get('orphaned') == 0)
        self.invoke('import_memories', {'path': str(exported)}, lambda v: v.get('imported') == 0
                    and v.get('duplicates') == 2, label='repeat-import-is-idempotent')
        imported = self.invoke('list', {'limit': 50}, lambda v: isinstance(v, list), label='import-copy-inventory')
        copied = [entry for entry in objects(imported) if entry.get('title') == 'Local HTTP updated' and 'id' in entry]
        require(len(copied) == 1 and copied[0]['id'] != child_id, 'import-did-not-mint-copy-id')
        copied_child = self.invoke('show', {'id': copied[0]['id']}, lambda v: v.get('entry', {}).get('title') == 'Local HTTP updated'
                    and v['entry'].get('content') == 'Fixture child: a separate record to validate editing, causal attachment and archive restore.',
                    label='import-copy-content-readback')['entry']
        require(copied_child.get('parent_id') == root_id, 'import-copy-parent-not-deduplicated')
        self.invoke('show', {'id': copied_child['parent_id']}, lambda v: v.get('entry', {}).get('title') == 'Local HTTP root',
                    label='import-copy-parent-readback')
        backup = self.root / 'files' / 'backup.db'
        self.invoke('backup_db', {'path': str(backup)}, lambda v: v.get('backed_up') == str(backup) and backup.is_file())
        self.invoke('scope_material', {'root': root_id}, lambda v: isinstance(v.get('material'), str) and 'Local HTTP root' in v['material'])
        self.invoke('book_material', {'root': root_id}, lambda v: isinstance(v.get('chapters'), list) and v.get('root', {}).get('id') == root_id)
        portrait_count = self.invoke('status', {}, lambda v: v.get('local_alive', 0) >= 2,
                    label='portrait-source-count')['local_alive']
        # service::App::portrait_material returns grouped arrays, not entries.
        self.invoke('portrait_material', {'limit': 20}, lambda v: v.get('total_entries') == portrait_count
                    and all(isinstance(v.get(field), list) for field in ('preferences', 'decisions', 'emotions', 'skills', 'top_themes', 'timeline'))
                    and any(theme == ['Local HTTP root', 1] for theme in v['top_themes'])
                    and sum(count for _, count in v['timeline']) == portrait_count)
        share = self.root / 'files' / 'share.txt'
        self.invoke('share_subtree', {'root': root_id, 'out': str(share)}, lambda v: v.get('path') == str(share) and share.is_file())
        self.invoke('share_import', {'path': str(share)}, lambda v: isinstance(v.get('candidates'), list))
        self.invoke('tree_cure', {'top': 10}, lambda v: isinstance(v.get('suggests'), list) and isinstance(v.get('roots'), list))
        self.invoke('defrag', {'min': 0.8, 'top': 10}, lambda v: v.get('total', 0) >= 2 and isinstance(v.get('roots'), int) and isinstance(v.get('clusters'), list))
        # The count is newly prepared rows: current cached artifacts legitimately
        # return zero (LocalStore::rebuild_index_with_progress), not store size.
        self.invoke('reembed', {}, lambda v: type(v.get('reembedded')) is int
                    and 0 <= v['reembedded'] <= portrait_count and v.get('dims') == self.model_dimensions)
        self.invoke('show', {'id': copied_child['id']}, lambda v: v.get('entry', {}).get('id') == copied_child['id']
                    and v['entry'].get('content') == copied_child['content'], label='post-reembed-copy-readback')
        self.invoke('search', {'q': copied_child['content'], 'limit': 50}, lambda v: isinstance(v, list)
                    and has(v, 'id', copied_child['id']), label='post-reembed-index-recall')
        self.invoke('sync', {}, lambda v: v.get('protocol') == 2 and v.get('pending') == 0, timeout=180)
        self.inject_actions()
        require('<!-- respire:begin -->' in (self.home / '.codex' / 'AGENTS.md').read_text(encoding='utf-8'),
                'doctor-fixture-injection-not-installed')
        self.invoke('doctor', {}, lambda v: v.get('version') == self.args.version and v.get('fail') == 0 and v.get('pass', 0) > 0)
        self.invoke('inject_remove', {'id': 'codex'}, lambda v: v.get('id') == 'codex' and v.get('changed') is True)
        require('<!-- respire:begin -->' not in (self.home / '.codex' / 'AGENTS.md').read_text(encoding='utf-8'),
                'injection-removal-readback-failed')
        self.invoke('classify_backend_set', {'backend': 'ds'}, lambda v: v.get('backend') == 'ds')
        self.invoke('classify_backend_get', {}, lambda v: v.get('backend') == 'ds')
        self.invoke('ds_key_save', {'key': 'ci-disposable-unused-key', 'base': 'http://127.0.0.1:9/v1', 'model': 'ci-no-provider'},
                    lambda v: v.get('ok') is True and v.get('model') == 'ci-no-provider')
        self.invoke('ds_key_status', {}, lambda v: v.get('configured') is True and v.get('base') == 'http://127.0.0.1:9/v1')
        self.invoke('causal_plan', {}, lambda v: v.get('ok') is True and v.get('mode') == 'preview' and isinstance(v.get('ops'), list) and v.get('applied') == 0)
        task = self.invoke('causal_reorder', {'apply': False, 'rounds': 1, 'backend': 'ds'}, lambda v: v.get('async') is True and bool(v.get('task_id')))
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            result = self.invoke('task_status', {'id': task['task_id']}, lambda v: v.get('id') == task['task_id'], label='task-poll')
            if result.get('status') == 'done':
                finished = result.get('result')
                require(isinstance(finished, dict) and finished.get('mode') == 'auto'
                        and finished.get('dry_run') is True and finished.get('applied') == 0
                        and isinstance(finished.get('ops'), list), 'dry-run-task-result-invalid')
                break
            require(result.get('status') != 'failed', 'dry-run-task-failed')
            time.sleep(0.3)
        else:
            raise Failure('dry-run-task-timeout')
        self.invoke('pick_save_file', {'defaultName': 'ci-export.json'}, lambda v: isinstance(v, str) and self.owned(v) is not None)
        for action in ('pick_open_file', 'pick_directory'):
            self.invoke(action, {}, lambda v: 'browser mode cannot open' in v.get('error', ''), status=500, label='designed-browser-picker-unsupported')
        keys = self.root / 'files' / 'keys.txt'
        self.invoke('keys_export', {'out': str(keys)}, lambda v: v.get('path') == str(keys) and keys.is_file())
        self.space_actions()
        reset = self.invoke('super_reset', {'super_pass': self.super}, lambda v: v.get('ok') is True and bool(v.get('super')))
        self.super = reset['super']
        self.invoke('logout', {}, lambda v: v.get('credentials_cleared') is True)
        self.invoke('login', {'user': self.user, 'pass': self.password, 'addr': 'https://api-dev.rsrs.rs', 'super_pass': self.super}, lambda v: v.get('ok') is True and v.get('user') == self.user, label='post-logout-relogin')
        actual, version = self.request('POST', '/api/invoke', {'cmd': 'update_check', 'args': {}})
        require(actual == 200 and isinstance(version, dict) and version.get('current') == self.args.version, 'update-check-adapter-contract-failed')
        if isinstance(version.get('latest'), str):
            self.coverage['update_check']['positive'].append('registry-version-result')
        else:
            self.conditional.append({'action': 'update_check', 'reason': 'registry-release-version-unavailable'})

    def inject_actions(self):
        self.invoke('inject_targets', {}, lambda v: isinstance(v, list) and has(v, 'id', 'codex'))
        preview = self.invoke('inject_preview', {}, lambda v: bool(v.get('revision')) and bool(v.get('path')))
        require(self.owned(preview['path']) == self.home / '.codex' / 'AGENTS.md', 'inject-preview-outside-fake-home')
        self.invoke('inject_apply', {'revision': preview['revision']}, lambda v: v.get('target') == 'codex' and isinstance(v.get('changed'), bool))
        self.invoke('inject', {'id': 'codex'}, lambda v: v.get('id') == 'codex' and isinstance(v.get('changed'), bool))

    def rpc_proofs(self):
        request_id = 'ci-runtime-status'
        status, value = self.request('POST', '/api/rpc', {'v': 1, 'id': request_id, 'method': 'runtime.status', 'args': []})
        require(status == 200 and value.get('ok') is True and value.get('id') == request_id
                and value.get('bin') == self.args.version and value.get('pid') == self.runtime.pid
                and Path(value.get('data_dir', '')).resolve() == self.library, 'local-rpc-runtime-identity-failed')
        status, value = self.request('POST', '/api/rpc', {'v': 1, 'id': 'ci-model-inactive', 'method': 'model.control', 'args': ['ci-no-active-model-task', 'false']})
        require(status == 200 and value.get('ok') is True and value.get('envelope', {}).get('summary', {}).get('active') is False,
                'local-rpc-inactive-model-control-failed')
        status, value = self.request('POST', '/api/rpc', {'v': 999, 'id': 'ci-bad-version', 'method': 'runtime.status', 'args': []})
        require(status == 200 and value.get('ok') is False and value.get('code') == 'protocol_version_mismatch', 'local-rpc-version-negative-failed')
        self.events.append({'endpoint': '/api/rpc', 'assertion': 'runtime-identity-inactive-model-control-and-version-rejection', 'passed': True})

    def space_actions(self):
        self.invoke('space_list', {}, lambda v: isinstance(v.get('spaces'), list) and Path(v.get('current_dir', '')).resolve() == self.library)
        invited = self.invoke('space_invite', {'note': 'local-api-member'}, lambda v: bool(v.get('session_id')) and bool(v.get('code')))
        self.invoke('space_members', {}, lambda v: has(v, 'session_id', invited['session_id']))
        name = self.user + '-space'
        created = self.guarded('space_create', {'name': name}, ['space', 'create', name],
                     lambda v: v.get('details', {}).get('name') == name and self.owned(v['details']['dir']).is_dir())
        space_dir = self.owned(created['details']['dir'])
        self.guarded('space_use', {'name': name}, ['space', 'use', name],
                     lambda v: has(v, 'name', name) and self.profile().name == name)
        self.guarded('space_join', {'code': invited['code']}, ['space', 'join', invited['code']],
                     lambda v: has(v, 'user', self.user) and has(v, 'keyring', True))
        self.invoke('space_kick', {'session': invited['session_id']}, lambda v: invited['session_id'] in v.get('revoked', []) and v.get('failed') == [])
        self.invoke('space_members', {}, lambda v: not has(v, 'session_id', invited['session_id']), label='kicked-membership-readback')
        self.guarded('space_remove', {'name': name, 'yes': True}, ['space', 'remove', name, '--yes'],
                     lambda v: v.get('summary', {}).get('name') == name and not space_dir.exists())

    def cleanup(self):
        self.stop()
        if self.root_created and self.register_attempted:
            try:
                session = json.loads((self.library / 'session.json').read_text(encoding='utf-8'))
                require(session.get('user') == self.user and session.get('addr') == 'https://api-dev.rsrs.rs', 'cleanup-account-identity-mismatch')
                request = urllib.request.Request('https://api-dev.rsrs.rs/api/self/purge',
                    json.dumps({'confirm': self.user}).encode(),
                    {'Authorization': 'Bearer ' + session['token'], 'Content-Type': 'application/json'}, method='POST')
                with self.opener.open(request, timeout=30) as response:
                    result = json.load(response)
                    require(result.get('purged') is True, 'cleanup-cloud-account-failed')
                self.created_user = None
            except Exception:
                self.cleanup_ok = False
        for process in (self.keyring, self.dbus):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        # Remove only explicitly created sensitive exports, never an existing source directory.
        secret_file = self.root / 'files' / 'keys.txt'
        if self.root_created and secret_file.is_file():
            secret_file.unlink()

    def report(self, error):
        missing = [name for name, data in self.coverage.items() if not data['positive']]
        negatives = [name for name, data in self.coverage.items() if not data['negative']]
        complete = error is None and not missing and not negatives and not self.conditional and self.cleanup_ok
        for data in self.coverage.values():
            data['observed_assertions'] = len(data['positive']) + len(data['negative'])
            data['passed'] = bool(data['positive'] and data['negative'] and not data['failures'])
        result = {'schema': 1, 'complete': complete, 'error': error,
                  'binary_sha256': self.args.binary_sha256, 'version': self.args.version,
                  'cli_source_sha': self.args.cli_source_sha, 'workflow_sha': os.environ.get('GITHUB_SHA'),
                  'counts': {'actions': 72, 'positive_observed': 72 - len(missing), 'negative_observed': 72 - len(negatives)},
                  'uncovered': missing, 'negative_uncovered': negatives, 'conditional': self.conditional,
                  'actions': list(self.coverage.values()), 'assertions': self.events,
                  'diagnostics': self.diagnostics,
                  'cloud_cleanup': self.cleanup_ok,
                  'remaining_users': [] if self.cleanup_ok else [self.user] if self.register_attempted else [],
                  'cleanup': {'passed': self.cleanup_ok, 'remaining_cloud_user': self.created_user},
                  'semantics': ['Profile-changing actions require observed HTTP guard, owned process stop, direct operation and fresh runtime identity proof.',
                                'Browser file/directory picker unsupported responses are their implemented positive contract.',
                                'Provider execution is not authorized by key storage; causal task uses dry-run only.']}
        self.args.report.parent.mkdir(parents=True, exist_ok=True)
        self.args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'complete': complete, 'error': error, 'counts': result['counts']}))
        return 0 if complete else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--cli-source-sha', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    suite = Suite(args)
    error = None
    try:
        suite.setup()
        suite.run_actions()
    except Failure as failure:
        error = str(failure)
    except Exception:
        error = 'unexpected-local-smoke-failure'
    finally:
        suite.cleanup()
    return suite.report(error)


if __name__ == '__main__':
    sys.exit(main())

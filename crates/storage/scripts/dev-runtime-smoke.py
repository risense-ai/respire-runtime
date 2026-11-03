#!/usr/bin/env python3
"""Exact-artifact runtime/dashboard checks on an ephemeral GitHub-hosted Linux runner.

Uses a fresh owned HOME, models and development account. Reports never contain
credentials, command arguments, plaintext responses or raw subprocess logs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading


REQUIRED = json.loads(Path(__file__).with_name('dev-runtime-required.json').read_text(encoding='utf-8'))['required_cases']
DEV = 'https://api-dev.rsrs.rs'
DASH = 'https://dash.rsrs.rs'


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Smoke:
    def __init__(self, args):
        self.args = args
        self.root = args.root.resolve()
        self.env = None
        self.child = None
        self.token = None
        self.created = False
        self.attempted = False
        self.cloud_clean = True
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.user = 'ci-runtime-' + os.environ.get('GITHUB_RUN_ID', '') + '-' + secrets.token_hex(5)
        self.password = '-' + secrets.token_urlsafe(32)
        self.report = {'source_sha': args.source_sha, 'workflow_sha': os.environ.get('GITHUB_SHA'),
                       'version': args.version, 'binary_sha256': args.binary_sha256,
                       'status': 'failed', 'passed': False, 'cases': {}, 'required_cases': REQUIRED,
                       'missing_cases': REQUIRED[:], 'cloud_cleanup': {'passed': False, 'remaining_users': []}}

    def passed(self, name, **evidence):
        require(name in REQUIRED, 'unknown_runtime_case')
        self.report['cases'][name] = {'passed': True, **evidence}

    def direct(self, args, timeout=90, stdin=None, expected=0):
        try:
            result = subprocess.run([str(self.args.binary), '--direct', '--json', *args],
                                    env=self.env, cwd=self.root, input=stdin,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise Failure('owned_cli_execution_failed') from None
        require(result.returncode == expected, 'owned_cli_exit_mismatch')
        try:
            value = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Failure('owned_cli_envelope_invalid') from None
        require(isinstance(value, dict) and all(k in value for k in
                ('command', 'status', 'summary', 'items', 'actions', 'errors', 'details')),
                'owned_cli_envelope_incomplete')
        require(value['status'] in ('ok', 'skip') if expected == 0 else value['status'] == 'fail',
                'owned_cli_status_mismatch')
        return value

    def http(self, base, method, path, body=None, token=None, headers=None, raw=False):
        fields = {'Content-Type': 'application/json', **(headers or {})}
        if token is not None:
            fields['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(base + path, None if body is None else json.dumps(body).encode(),
                                     fields, method=method)
        try:
            response = self.opener.open(req, timeout=90)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError):
            raise Failure('owned_http_transport_failed') from None
        with response:
            status, response_headers = response.code, response.headers
            data = response.read(8 * 1024 * 1024 + 1)
        require(len(data) <= 8 * 1024 * 1024, 'owned_http_response_too_large')
        if raw:
            return status, data, response_headers
        try:
            return status, json.loads(data), response_headers
        except (ValueError, UnicodeError):
            raise Failure('owned_http_response_not_json') from None

    def rpc(self, args, expected=0):
        code, reply, _ = self.http(self.url, 'POST', '/api/rpc',
                                  {'v': 1, 'id': secrets.token_hex(8), 'method': 'cli.exec',
                                   'args': ['--json', *args]}, self.token)
        require(code == 200 and isinstance(reply, dict) and reply.get('ok') is (expected == 0),
                'runtime_rpc_transport_failed')
        envelope = reply.get('envelope', {})
        require(reply.get('exit') == expected and envelope.get('status') in
                (('ok', 'skip') if expected == 0 else ('fail',)), 'runtime_rpc_command_failed')
        return envelope

    def stop(self):
        if self.child is None:
            return
        if self.child.poll() is None:
            code, reply, _ = self.http(self.url, 'POST', '/api/runtime/stop', {}, self.token)
            require(code == 200 and reply.get('ok') is True, 'owned_runtime_stop_rejected')
            try:
                self.child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                raise Failure('owned_runtime_stop_timeout') from None
        require(self.child.returncode == 0, 'owned_runtime_stop_exit_failed')
        self.child = None

    def start(self):
        require(self.child is None, 'runtime_already_owned')
        self.child = subprocess.Popen([str(self.args.binary), '--runtime-internal', '--port', str(self.port),
                                       '--host', '127.0.0.1'], env=self.env, cwd=self.root,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            require(self.child.poll() is None, 'owned_runtime_exited_before_ready')
            token_path = self.root / 'runtime' / 'token'
            require(not token_path.exists(), 'loopback_runtime_created_token')
            if (self.root / 'runtime' / 'endpoint.json').is_file():
                try:
                    code, health, _ = self.http(self.url, 'GET', '/api/health')
                except Failure:
                    time.sleep(0.1)
                    continue
                if code == 200:
                    require(health.get('v') == 1 and health.get('bin') == self.args.version
                            and health.get('pid') == self.child.pid
                            and Path(health.get('exe', '')).resolve() == self.args.binary
                            and Path(health.get('data_dir', '')).resolve() == self.library,
                            'owned_runtime_identity_mismatch')
                    return
            time.sleep(0.1)
        raise Failure('owned_runtime_ready_timeout')

    def setup(self):
        temp = Path(os.environ.get('RUNNER_TEMP', '')).resolve()
        require(os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and platform.system() == 'Linux', 'ephemeral_github_linux_runner_required')
        require(self.root != temp and self.root.is_relative_to(temp) and not self.root.exists(),
                'fresh_owned_runner_temp_required')
        require(re.fullmatch('[0-9a-f]{40}', self.args.source_sha)
                and re.fullmatch('[0-9a-f]{64}', self.args.binary_sha256)
                and hashlib.sha256(self.args.binary.read_bytes()).hexdigest() == self.args.binary_sha256,
                'exact_binary_identity_mismatch')
        self.root.mkdir(mode=0o700)
        self.created = True
        self.library = self.root / 'library'
        for name in ('home', 'library', 'config', 'data', 'cache', 'tmp', 'runtime', 'bin', 'models'):
            (self.root / name).mkdir(mode=0o700)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('ONEMEMORY_', 'RESPIRE_', 'XDG_', 'DS_', 'JEV_', 'GNOME_'))
                    and not k.endswith(('_TOKEN', '_API_KEY')) and 'TEST_MODE' not in k
                    and k not in ('HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'DBUS_SESSION_BUS_ADDRESS')}
        self.env.update(HOME=str(self.root / 'home'), USERPROFILE=str(self.root / 'home'),
                        XDG_CONFIG_HOME=str(self.root / 'config'), XDG_DATA_HOME=str(self.root / 'data'),
                        XDG_CACHE_HOME=str(self.root / 'cache'), XDG_RUNTIME_DIR=str(self.root / 'runtime'),
                        TMPDIR=str(self.root / 'tmp'), RSRS_DATA_DIR=str(self.root),
                        RSRS_BIN_DIR=str(self.root / 'bin'), RSRS_ENGINE='cpu',
                        RSRS_LANG='en', RSRS_NO_AUTOSYNC='1', RSRS_UPDATE_CHECK='0',
                        RSRS_M3_DIR=str(self.root / 'models/bge-m3'),
                        )
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
            self.env.pop(key, None)
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            self.port = port.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(self.port)
        self.env['RSRS_RPC_PORT'] = str(self.port)
        value = self.direct(['-v'])
        require(value.get('summary', {}).get('version') == self.args.version, 'exact_version_mismatch')
        self.passed('artifact_identity_verified')

    def dashboard(self):
        endpoint = self.root / 'runtime' / 'endpoint.json'
        require(not endpoint.exists(), 'runtime_existed_before_dashboard')
        result = self.direct(['web', '--no-open'])
        require(result['summary'] == {'url': DASH, 'opened': False} and not endpoint.exists(),
                'dashboard_started_runtime_or_wrong_url')
        self.passed('dashboard_url_without_runtime')
        browser = self.root / 'bin' / 'xdg-open'
        capture = self.root / 'browser-url.txt'
        browser.write_text('#!' + sys.executable + '\nimport pathlib,sys\n'
                           + 'pathlib.Path(' + repr(str(capture)) + ').write_text(sys.argv[1],encoding="utf-8")\n', encoding='utf-8')
        browser.chmod(0o700)
        self.env['PATH'] = str(browser.parent) + os.pathsep + self.env.get('PATH', '')
        opened = self.direct(['web'])
        deadline = time.monotonic() + 5
        while not capture.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        require(opened['summary'] == {'url': DASH, 'opened': True}
                and capture.is_file() and capture.read_text(encoding='utf-8') == DASH and not endpoint.exists(),
                'dashboard_browser_launch_failed')
        self.passed('dashboard_browser_launch_verified', method='actual_cli_with_owned_os_browser_handler')
        for flag in ('--status', '--stop', '--internal', '--port', '--host'):
            result = subprocess.run([str(self.args.binary), 'web', flag], env=self.env, cwd=self.root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            require(result.returncode != 0 and not endpoint.exists(), 'legacy_web_flag_was_accepted')
        self.passed('dashboard_legacy_flags_rejected')
        for host in ('0.0.0.0', '192.0.2.1', 'example.invalid'):
            self.direct(['--runtime-internal', '--host', host, '--port', str(self.port)], expected=1)
            with socket.socket() as check:
                check.settimeout(1)
                require(check.connect_ex(('127.0.0.1', self.port)) != 0,
                        'nonloopback_runtime_left_listener')
            require(not endpoint.exists() and not (self.root / 'runtime/token').exists(),
                    'nonloopback_runtime_created_endpoint_or_token')
        self.passed('runtime_nonloopback_rejected')
        client_home = self.root / 'client-only-home'
        old = client_home / '.onememory'
        old.mkdir(parents=True, mode=0o700)
        marker = old / 'client.json'
        marker.write_text('{"addr":"https://api-dev.rsrs.rs"}\n', encoding='utf-8')
        before = {str(path.relative_to(client_home)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in client_home.rglob('*') if path.is_file()}
        client_env = dict(self.env, HOME=str(client_home), USERPROFILE=str(client_home),
                          RSRS_CLIENT_ONLY='1')
        client_env.pop('RSRS_DATA_DIR', None)
        client_env.pop('RSRS_DEFAULT_DATA_DIR', None)
        result = subprocess.run([str(self.args.binary), '--client-only', '--json', 'status'],
                                env=client_env, cwd=self.root, capture_output=True, timeout=25)
        after = {str(path.relative_to(client_home)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in client_home.rglob('*') if path.is_file()}
        require(result.returncode != 0 and before == after and not (client_home / '.rsrs').exists()
                and not endpoint.exists(), 'client_only_migrated_or_created_profile')
        self.passed('client_only_no_profile_writes')

    def account(self):
        expected = os.environ.get('RSRS_DEV_SERVER_SHA', '')
        require(os.environ.get('RSRS_DEV_SERVER_ADDR') == DEV and re.fullmatch('[0-9a-f]{40}', expected),
                'exact_development_server_required')
        code, health, _ = self.http(DEV, 'GET', '/health')
        require(code == 200 and isinstance(health, dict) and health.get('source_revision') == expected,
                'development_server_revision_mismatch')
        self.report['server_sha'] = expected
        self.direct(['config', '--data-dir', str(self.library), '--addr', DEV, '--autosync', 'false', '--cure-auto', 'false'])
        config = self.direct(['config'])['summary']
        require(Path(config.get('data_dir', '')).resolve() == self.library and config.get('addr') == DEV,
                'data_dir_configuration_failed')
        self.passed('data_dir_persisted')
        self.direct(['model', 'install-m3'], timeout=1200)
        probe = self.direct(['model', 'probe', '--model', 'm3'], timeout=180)['summary']
        require(probe.get('ready') is True and probe.get('dimensions') == 1024
                and str(probe.get('selected', '')).lower() == 'cpu', 'real_bge_cpu_probe_failed')
        self.attempted = True
        registered = self.direct(['register', '--user', self.user, '--pass=' + self.password, '--addr', DEV])
        require(registered['summary'].get('user') == self.user, 'owned_account_registration_failed')
        self.start()

    def transport(self):
        self.passed('hidden_runtime_health_identity')
        status = self.direct(['--runtime-internal', '--status'])['summary']
        require(status.get('state') == 'up' and status.get('pid') == self.child.pid, 'hidden_status_identity_failed')
        self.passed('hidden_runtime_status_up')
        for token, name in ((None, 'runtime_loopback_without_token'), ('ci-invalid-token', 'runtime_loopback_ignores_token')):
            code, value, _ = self.http(self.url, 'GET', '/api/health', token=token)
            require(code == 200 and value.get('v') == 1 and value.get('bin') == self.args.version
                    and value.get('pid') == self.child.pid
                    and Path(value.get('exe', '')).resolve() == self.args.binary
                    and Path(value.get('data_dir', '')).resolve() == self.library
                    and not (self.root / 'runtime' / 'token').exists(), 'runtime_loopback_health_identity_failed')
            self.passed(name)
        code, value, _ = self.http(self.url, 'POST', '/api/rpc', {}, self.token, {'Origin': 'https://example.invalid'})
        require(code == 403 and value.get('error') == 'forbidden origin', 'runtime_foreign_origin_not_rejected')
        self.passed('runtime_origin_rejected')
        code, value, _ = self.http(self.url, 'POST', '/api/rpc', {'v': 999, 'id': 'bad-version', 'method': 'runtime.status', 'args': []}, self.token)
        require(code == 200 and value.get('ok') is False and value.get('code') == 'protocol_version_mismatch', 'rpc_version_not_rejected')
        self.passed('runtime_rpc_version_rejected')
        config = self.rpc(['config'])['summary']
        require(Path(config.get('data_dir', '')).resolve() == self.library and config.get('addr') == DEV, 'rpc_config_mismatch')
        self.passed('runtime_rpc_config_verified')
        require(self.rpc(['status'])['summary'].get('unlocked') is True, 'runtime_not_unlocked')
        self.passed('runtime_rpc_status_unlocked')
        for method, ident, name in (('initialize', 1, 'runtime_mcp_initialized'), ('tools/list', 2, 'runtime_mcp_tools_list')):
            body = {'jsonrpc': '2.0', 'id': ident, 'method': method}
            if method == 'initialize':
                body['params'] = {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'runtime-ci', 'version': '1'}}
            code, value, _ = self.http(self.url, 'POST', '/mcp', body, self.token)
            require(code == 200 and value.get('id') == ident and 'error' not in value, 'mcp_response_failed')
            if method == 'initialize':
                require(value.get('result', {}).get('protocolVersion') == '2025-03-26', 'mcp_protocol_mismatch')
            else:
                tools = value.get('result', {}).get('tools', [])
                require(isinstance(tools, list) and any(tool.get('name') == 'memory_status' for tool in tools), 'mcp_tools_missing')
            self.passed(name)
        for path in ('/', '/index.html', '/favicon.ico', '/fonts/example.ttf', '/api/invoke', '/api/task?id=old'):
            code, value, _ = self.http(self.url, 'POST' if path == '/api/invoke' else 'GET', path,
                                      {} if path == '/api/invoke' else None, self.token)
            require(code == 404 and value.get('error') == 'unknown runtime endpoint', 'removed_ui_route_still_served')
        self.passed('removed_ui_routes_not_served', routes=6)

    def settings(self):
        for mode in ('verbose', 'concise'):
            self.rpc(['agent-config', '--set', 'diary_mode=' + mode])
            require(self.rpc(['agent-config'])['summary'].get('diary_mode') == mode, 'diary_mode_not_persisted')
        self.passed('diary_mode_persisted')
        value = self.rpc(['remember', 'Runtime fixture persisted memory.', '--title', 'Runtime fixture', '--importance', 'important', '--force'])
        memory_id = value['summary'].get('id')
        require(isinstance(memory_id, str) and memory_id, 'owned_memory_not_created')
        self.rpc(['agent-config', '--set', 'readonly=true'])
        rejected = self.rpc(['remember', 'Readonly write must fail.', '--importance', 'important', '--force'], expected=1)
        require('read-only' in ' '.join(rejected.get('errors', [])), 'readonly_write_guard_missing')
        require(self.rpc(['show', memory_id])['details'].get('entry', {}).get('id') == memory_id, 'readonly_read_failed')
        self.rpc(['agent-config', '--set', 'readonly=false'])
        self.rpc(['agent-config', '--set', 'memory_off=true'])
        skipped = self.rpc(['show', memory_id])
        require(skipped.get('summary') == {'mode': 'off', 'skipped': True, 'count': 0}
                and skipped.get('items') == [] and skipped.get('details') == []
                and skipped.get('errors') == [], 'off_read_empty_response_missing')
        self.rpc(['agent-config', '--set', 'memory_off=false'])
        normal = self.rpc(['agent-config'])['summary']
        require(normal.get('readonly') is False and normal.get('memory_off') is False, 'normal_mode_not_restored')
        require(self.rpc(['show', memory_id])['details']['entry']['content'] == 'Runtime fixture persisted memory.', 'normal_read_not_restored')
        self.passed('workspace_three_states_persisted')
        self.stop()
        self.start()
        require(self.rpc(['status'])['summary'].get('unlocked') is True
                and self.rpc(['show', memory_id])['details']['entry']['content'] == 'Runtime fixture persisted memory.',
                'stored_session_not_resumed')
        self.passed('resume_session_real', method='fresh_runtime_reuses_owned_session_and_keyring_no_password_input')
        # Remember persists before deriving its index. Exercise recall and wait
        # for the owned worker before stopping it for strict offline diagnosis.
        require(self.rpc(['recall', 'Runtime fixture persisted memory.', '--titles']).get('items'),
                'resumed_pending_source_not_recalled')
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            code, health, _ = self.http(self.url, 'GET', '/api/health', token=self.token)
            require(code == 200, 'owned_index_health_unavailable')
            index = health.get('retrieval_index', {})
            require(index.get('state') != 'failed', 'owned_index_preparation_failed')
            if index.get('state') == 'ready' and not index.get('running') and not index.get('scheduled'):
                break
            time.sleep(.1)
        else:
            raise Failure('owned_index_not_ready_before_offline_doctor')
        self.stop()
        retired = subprocess.run([str(self.args.binary), '--direct', '--json', 'model', 'install-rerank'], env=self.env,
                                 cwd=self.root, capture_output=True, text=True, timeout=30)
        require(retired.returncode == 2, 'retired_reranker_command_was_accepted')
        agent_file = self.root / 'home/.codex/AGENTS.md'
        agent_file.parent.mkdir()
        original = '# Disposable runtime fixture\nKeep this text.\n'
        agent_file.write_text(original, encoding='utf-8')
        self.direct(['inject', '--id', 'codex'])
        installed = agent_file.read_text(encoding='utf-8')
        require(installed != original and original.strip() in installed,
                'owned_agent_injection_not_applied')
        # Keep doctor strict: a fresh supported agent must be actually injected.
        result = subprocess.run([str(self.args.binary), '--direct', '--json', 'doctor'], env=self.env,
                                cwd=self.root, capture_output=True, text=True, timeout=180)
        self.report['doctor'] = {'exit': result.returncode, 'items': []}
        try:
            diagnostic = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            diagnostic = None
        if isinstance(diagnostic, dict) and isinstance(diagnostic.get('items'), list):
            names = {'store', 'data dir', 'mcp bin', 'mcp http', 'session', 'embedder',
                     'lock', 'remote', 'inject', 'memory status',
                     'tidy counter', 'CLI version', 'Runtime version', 'model index'}
            statuses = {'ok', 'warn', 'fail', 'skip', 'pending'}
            self.report['doctor']['items'] = [
                {'name': item['name'], 'status': item['status']}
                for item in diagnostic['items']
                if isinstance(item, dict) and isinstance(item.get('name'), str)
                and item['name'] in names and isinstance(item.get('status'), str)
                and item['status'] in statuses
            ]
        require(result.returncode in (0, 2), 'm3_doctor_execution_failed')
        require(isinstance(diagnostic, dict) and isinstance(diagnostic.get('items'), list),
                'doctor_envelope_invalid')
        require(any(item.get('name') == 'inject' and item.get('status') == 'ok'
                    for item in diagnostic.get('items', [])), 'owned_agent_doctor_not_fresh')
        require(not any(item.get('name') == 'reranker' for item in diagnostic.get('items', [])), 'retired_reranker_doctor_entry_present')
        require(any(item.get('name') == 'embedder' and item.get('status') == 'ok' for item in diagnostic.get('items', [])), 'm3_doctor_not_ready')
        self.passed('m3_status_real', retired_command_exit=retired.returncode)
        self.direct(['classify-config', '--set', '--backend', 'jev'])
        require(self.direct(['classify-config'])['summary'].get('backend') == 'jev', 'backend_not_persisted')
        self.passed('classify_config_persisted')
        observed = []
        class Trap(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                observed.append(True)
                self.send_error(503)
            do_GET = do_POST
        trap = ThreadingHTTPServer(('127.0.0.1', 0), Trap)
        thread = threading.Thread(target=trap.serve_forever, daemon=True)
        thread.start()
        try:
            base = 'http://127.0.0.1:' + str(trap.server_port) + '/v1'
            value = self.direct(['classify-config', '--set', '--backend', 'ds', '--api-base', base,
                                 '--model', 'ci-unused-model', '--key-stdin'], stdin='ci-unused-runtime-key\n')['summary']
            readback = self.direct(['classify-config'])['summary']
            require(value.get('has_key') is True and readback.get('backend') == 'ds'
                    and readback.get('api_base') == base and readback.get('model') == 'ci-unused-model'
                    and not observed, 'provider_key_config_or_network_guard_failed')
            self.passed('ds_key_saved_without_network', provider_requests=0)
        finally:
            trap.shutdown()
            trap.server_close()
            thread.join(timeout=5)
        self.start()
        self.stop()
        require(self.child is None, 'runtime_not_stopped')
        self.passed('hidden_runtime_stop_clean')

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.cloud_clean = False
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)
        if self.attempted:
            try:
                session = json.loads((self.library / 'session.json').read_text(encoding='utf-8'))
                require(session.get('user') == self.user and session.get('addr') == DEV, 'cleanup_identity_mismatch')
                token = session['token']
                code, result, _ = self.http(DEV, 'POST', '/api/self/purge', {'confirm': self.user}, token)
                require(code == 200 and result.get('purged') is True, 'cloud_purge_failed')
                code, _, _ = self.http(DEV, 'GET', '/api/self', token=token)
                require(code == 401, 'old_account_token_not_revoked')
            except Exception:
                self.cloud_clean = False
        self.report['cloud_cleanup'] = {'passed': self.cloud_clean,
                                        'remaining_users': [] if self.cloud_clean else [self.user] if self.attempted else []}

    def doctor_model_recovery(self):
        """Exercise a real failed download and retry against the exact artifact."""
        require(self.child is None, 'doctor_fixture_requires_stopped_runtime')
        model = Path(self.env['RSRS_M3_DIR'])
        cache = self.root / 'doctor-model-cache'
        model.rename(cache)
        database = self.library / 'rsrs.db'

        def snapshot():
            with sqlite3.connect(database) as db:
                return (db.execute('SELECT id,user,ciphertext,nonce,dirty,deleted,created_at,updated_at FROM memories ORDER BY id').fetchall(),
                        db.execute('SELECT * FROM sync_outbox ORDER BY seq').fetchall())

        before = snapshot()
        session = (self.library / 'session.json').read_bytes()
        with sqlite3.connect(database) as db:
            db.execute('DELETE FROM core_artifacts')
            db.commit()
        allowed, started, release = threading.Event(), threading.Event(), threading.Event()
        requests = []
        prefix = '/Xenova/bge-m3/resolve/4de13258303883538bd53b696b452bf8099f0858/'

        class ModelSource(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if not allowed.is_set():
                    self.send_response(503)
                    self.end_headers()
                    return
                name = self.path.removeprefix(prefix)
                if not self.path.startswith(prefix) or name not in ('tokenizer.json', 'onnx/model_quantized.onnx'):
                    self.send_response(404)
                    self.end_headers()
                    return
                requests.append((name, self.headers.get('Range')))
                path = cache / name
                self.send_response(200)
                self.send_header('Content-Length', str(path.stat().st_size))
                self.end_headers()
                try:
                    with path.open('rb') as stream:
                        first = True
                        while chunk := stream.read(256 * 1024):
                            self.wfile.write(chunk)
                            self.wfile.flush()
                            if first and name.startswith('onnx/') and self.headers.get('Range') is None:
                                started.set()
                                if not release.wait(45):
                                    return
                            first = False
                except (BrokenPipeError, ConnectionResetError):
                    return

        server = ThreadingHTTPServer(('127.0.0.1', 0), ModelSource)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        previous_mirror = self.env.get('RSRS_MIRROR')
        self.env['RSRS_MIRROR'] = 'http://127.0.0.1:' + str(server.server_port)

        def doctor(fix=False):
            code, reply, _ = self.http(self.url, 'POST', '/api/rpc',
                {'v': 1, 'id': secrets.token_hex(8), 'method': 'cli.exec',
                 'args': ['--json', 'doctor', *(['--fix'] if fix else [])]}, self.token)
            envelope = reply.get('envelope', {})
            require(code == 200 and envelope.get('command') == 'doctor'
                    and reply.get('exit') in (0, 1, 2), 'doctor_repair_envelope_invalid')
            rows = {row['name']: row for row in envelope.get('items', [])
                    if row.get('name') in ('embedder', 'model index')}
            require(len(rows) == 2, 'doctor_model_rows_missing')
            return rows

        def wait_index(want, seconds=90):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if want == 'ready':
                    # Exercise the existing repair while TUI-style reads continue.
                    # These reads must not restart model verification or indexing.
                    for command in (['account', 'list'], ['config'], ['agent-config']):
                        self.rpc(command)
                index = self.rpc(['status'])['summary']['retrieval_index']
                if index.get('state') == want:
                    return index
                time.sleep(.2)
            raise Failure('doctor_index_' + want + '_timeout')

        try:
            self.start()
            wait_index('failed')
            failed = doctor()
            require(all(row['status'] == 'fail' for row in failed.values())
                    and '503' in str(failed['model index'].get('value')), 'doctor_download_error_hidden')
            self.passed('doctor_model_failed_download_visible', http_status=503)
            allowed.set()
            scheduled = doctor(True)
            require(all(row['status'] == 'warn' for row in scheduled.values()), 'doctor_retry_not_scheduled')
            require(started.wait(45), 'doctor_retry_did_not_download')
            self.passed('doctor_model_failed_download_retry')
            busy = doctor(True)
            # This source ignores Range: one support probe precedes one full
            # transfer. Block only the transfer, and reject additional requests.
            model_requests = [range_header for name, range_header in requests
                              if name == 'onnx/model_quantized.onnx']
            require(all(row['status'] == 'warn' for row in busy.values())
                    and model_requests == ['bytes=0-0', None], 'doctor_competing_installer_started')
            self.passed('doctor_model_active_download_no_duplicate', model_downloads=1, range_probes=1)
            release.set()
            wait_index('ready', 240)
            ready = doctor()
            require(all(row['status'] == 'ok' for row in ready.values()), 'doctor_ready_model_not_pass')
            self.passed('doctor_model_repair_ready')
            require(snapshot() == before and (self.library / 'session.json').read_bytes() == session,
                    'doctor_repair_changed_source_or_session')
            self.passed('doctor_model_repair_preserves_source')
        finally:
            release.set()
            try:
                self.stop()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                if previous_mirror is None:
                    self.env.pop('RSRS_MIRROR', None)
                else:
                    self.env['RSRS_MIRROR'] = previous_mirror


    def validation_errors(self):
        entry = self.direct(['remember', 'Owned validation fixture.', '--title', 'Validation leaf',
                             '--force', '--importance', 'important'])['summary']['id']
        commands = [
            ['resort', '--spec', '{"ops":[{"id":"aaaaaaaa","parent":"aaaaaaaa"}]}'],
            ['resort', '--spec', '{'], ['resort', '--spec', '{"ops":[]}'],
            ['split', entry, '--go', '--spec', '{"items":[]}'],
            ['split', entry, '--go', '--spec', '{'], ['tree-deepen', '--root', entry],
        ]
        for command in commands:
            result = subprocess.run([str(self.args.binary), '--direct', *command, '--json'],
                                    env=self.env, cwd=self.root, capture_output=True, text=True, timeout=90)
            require(result.returncode == 2, 'direct_validation_exit_not_user_error')
            value = json.loads(result.stdout.strip())
            require(value.get('status') == 'fail', 'direct_validation_status_not_fail')
            require(value['summary'].get('reason') == 'invalid_input'
                    and value['details'].get('error_type') == 'user', 'direct_validation_error_not_typed')
        self.start()
        try:
            for command in commands:
                value = self.rpc(command, expected=2)
                require(value['summary'].get('reason') == 'invalid_input'
                        and value['details'].get('error_type') == 'user', 'rpc_validation_error_not_typed')
        finally:
            self.stop()
        self.passed('runtime_validation_errors_typed', direct_cases=len(commands), rpc_cases=len(commands))

    def host_space_commands(self):
        home = self.root / 'space-command-home'
        library = home / '.rsrs'
        library.mkdir(parents=True)
        config = library / 'client.json'
        config.write_text(json.dumps({'data_dir': str(library), 'api_base': 'https://fixture.invalid',
                                      'custom': 'preserve'}), encoding='utf-8')
        env = self.env.copy()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        url = 'http://127.0.0.1:' + str(port)
        env.update(HOME=str(home), USERPROFILE=str(home), RSRS_DATA_DIR=str(library),
                   RSRS_RPC_PORT=str(port), XDG_RUNTIME_DIR=str(home / 'runtime'))
        def cli(args, expected=0):
            result = subprocess.run([str(self.args.binary), '--json', *args], env=env, cwd=home,
                                    capture_output=True, text=True, timeout=90)
            require(result.returncode == expected, 'space_host_cli_exit_mismatch')
            value = json.loads(result.stdout.strip())
            require(value['status'] == ('ok' if expected == 0 else 'fail'), 'space_host_cli_status_mismatch')
            return value
        def health(profile):
            code, actual, _ = self.http(url, 'GET', '/api/health')
            require(code == 200 and actual['bin'] == self.args.version
                    and hashlib.sha256(Path(actual['exe']).read_bytes()).hexdigest() == self.args.binary_sha256
                    and Path(actual['data_dir']).resolve() == profile.resolve(), 'space_host_runtime_readback_failed')
            return actual['pid']
        try:
            cli(['space', 'list'])
            old_pid = health(library)
            cli(['space', 'create', 'probe'])
            probe = library / 'accounts/probe'
            require(probe.joinpath('space_owner.json').is_file() and health(probe) != old_pid,
                    'space_create_did_not_take_over_runtime')
            before = config.read_bytes()
            denied = cli(['space', 'remove', 'probe'], 2)
            require(denied['summary']['reason'] == 'invalid_input' and config.read_bytes() == before,
                    'space_remove_without_confirmation_changed_profile')
            cli(['space', 'remove', 'probe', '--yes'], 2)
            require(probe.is_dir(), 'space_removed_active_profile')
            health(probe)
            cli(['space', 'use', 'main'])
            health(library)
            before = config.read_bytes()
            cli(['space', 'use', 'missing'], 2)
            require(config.read_bytes() == before, 'space_failed_switch_changed_configuration')
            health(library)
            cli(['space', 'remove', 'probe', '--yes'])
            require(not probe.exists(), 'space_remove_did_not_remove_profile')
            health(library)
            preserved = json.loads(config.read_text(encoding='utf-8'))
            require(preserved['api_base'] == 'https://fixture.invalid' and preserved['custom'] == 'preserve',
                    'space_host_command_lost_configuration')
        finally:
            cli(['--runtime-internal', '--stop'])
        with socket.socket() as listener:
            listener.settimeout(2)
            require(listener.connect_ex(('127.0.0.1', port)) != 0, 'space_fixture_runtime_not_closed')
        self.passed('host_space_lifecycle', runtime_cleanup=True, configuration_preserved=True)

    def update_check_comparisons(self):
        previous = self.env.get('RSRS_UPDATE_CHECK')
        self.env['RSRS_UPDATE_CHECK'] = '1'
        cache = self.library / 'update_check.json'
        try:
            for latest, ahead, outdated in [('0.0.1', True, False), (self.args.version, False, False),
                                             ('99.0.0', False, True)]:
                cache.write_text(json.dumps({'checked_at': int(time.time()), 'latest': latest, 'ok': True}),
                                 encoding='utf-8')
                result = subprocess.run([str(self.args.binary), '--direct', '--json', 'update-check'],
                                        env=self.env, cwd=self.root, capture_output=True, text=True, timeout=30)
                require(result.returncode == (2 if outdated else 0), 'update_check_exit_mismatch')
                value = json.loads(result.stdout.strip())
                require(value['summary'].get('ahead') is ahead and value['summary'].get('outdated') is outdated
                        and value['summary'].get('cached') is True, 'update_comparison_state_wrong')
                display = value['items'][0]['value']
                require((' -> ' in display) is outdated and ('ahead of published latest' in display) is ahead
                        and bool(value['actions']) is outdated, 'update_comparison_offers_downgrade')
        finally:
            cache.unlink(missing_ok=True)
            if previous is None:
                self.env.pop('RSRS_UPDATE_CHECK', None)
            else:
                self.env['RSRS_UPDATE_CHECK'] = previous
        self.passed('update_check_comparison', states=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    destination = args.report.resolve() if args.report else args.root.resolve() / 'runtime-coverage.json'
    temp = Path(os.environ.get('RUNNER_TEMP', '')).resolve()
    require(destination != temp and destination.is_relative_to(temp) and not destination.exists(),
            'report_path_must_be_fresh_runner_temp_file')
    smoke = Smoke(args)
    try:
        smoke.setup()
        smoke.dashboard()
        smoke.account()
        smoke.transport()
        smoke.settings()
        smoke.doctor_model_recovery()
        smoke.validation_errors()
        smoke.host_space_commands()
        smoke.update_check_comparisons()
    except Exception as error:
        smoke.report['failure_code'] = str(error) if isinstance(error, Failure) else type(error).__name__
    finally:
        smoke.cleanup()
    smoke.report['missing_cases'] = [name for name in REQUIRED if smoke.report['cases'].get(name, {}).get('passed') is not True]
    smoke.report['passed'] = not smoke.report['missing_cases'] and not smoke.report.get('failure_code') and smoke.cloud_clean
    smoke.report['status'] = 'passed' if smoke.report['passed'] else 'failed'
    if smoke.created:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(smoke.report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': smoke.report['passed'], 'failure_code': smoke.report.get('failure_code'),
                      'missing_cases': smoke.report['missing_cases'], 'cloud_cleanup': smoke.report['cloud_cleanup']}))
    return 0 if smoke.report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

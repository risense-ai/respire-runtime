#!/usr/bin/env python3
"""Opt-in cloud API smoke for Actions and api-dev.rsrs.rs; never prints credentials.

Run: python3 scripts/dev-api-smoke.py --scope all --report <coverage.json>
Requires GITHUB_ACTIONS=true, RSRS_DEV_SERVER_ADDR=https://api-dev.rsrs.rs,
RSRS_DEV_API_ADMIN_APPROVED=true and secret RSRS_DEV_ADMIN_TOKEN.
This checks the reviewed 66-operation CLI baseline, not all browser/Passkey APIs.
Synthetic opaque ciphertext checks the server
contract; actual client encryption/decryption belongs to the separate CLI run.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


BASELINE_ROUTE_SHA256 = 'd9ae8f93cfb979ba626c90da3494e4d747e2b5a25548d99caa29c8cf97622864'
REQUIRED_VAULT_ASSERTIONS = {
    'wrapped-vault-save', 'wrapped-vault-roundtrip', 'identical-legacy-vault-write',
    'identical-write-preserves-vault-and-generation', 'changed-legacy-vault-write',
    'legacy-write-advances-generation', 'rewrap-missing-generation',
    'rewrap-missing-generation-preserves-vault', 'rewrap-stale-generation',
    'rewrap-stale-generation-preserves-vault', 'unsupported-vault-operation',
    'unsupported-vault-operation-preserves-vault', 'same-urk-rewrap-current-generation',
    'same-urk-rewrap-preserves-generation', 'readonly-vault-write-rejected',
    'readonly-vault-write-preserves-state',
}


class SmokeFailure(Exception):
    """Only constant, non-sensitive reason codes may escape the request layer."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def totp(secret):
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff
    return f'{value % 1000000:06d}'


def valid_vault_reply(reply, vault, account_id=None, key_generation=None):
    """Require preserved recovery fields and the reviewed stable identity/generation schema."""
    identity = reply.get('account_id')
    generation = reply.get('key_generation')
    return (all(reply.get(key) == value for key, value in vault.items())
            and isinstance(identity, str)
            and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', identity) is not None
            and type(generation) is int and 1 <= generation <= 9007199254740991
            and (account_id is None or identity == account_id)
            and (key_generation is None or generation == key_generation))


class Smoke:
    def __init__(self, args):
        self.args = args
        manifest = Path(__file__).with_name('dev-api-coverage.json')
        self.contract = json.loads(manifest.read_text(encoding='utf-8'))
        self.routes = {}
        for route in self.contract['routes']:
            key = route['method'] + ' ' + route['path']
            self.routes[key] = dict(route, positive=[], negative=[], failures=[])
        self.events = []
        self.cleanup_events = []
        self.users = {}
        self.admins = set()
        self.seed = os.environ.get('RSRS_DEV_ADMIN_TOKEN', '')
        self.base = os.environ.get('RSRS_DEV_SERVER_ADDR', '').rstrip('/')
        self.expected_server_sha = os.environ.get('RSRS_DEV_SERVER_SHA', '').lower()
        self.actual_server_sha = None
        self.unconfirmed_creations = set()
        run = os.environ.get('GITHUB_RUN_ID', '')
        attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
        self.namespace = f'ci-api-{run}-{attempt}-{secrets.token_hex(4)}'
        self.http = urllib.request.build_opener(NoRedirect())
        self.tick = 0
        self.start = datetime.datetime.now(datetime.timezone.utc)

    def preflight(self):
        """Reject unapproved environments or any drift from the reviewed route inventory."""
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            raise SmokeFailure('github-actions-required')
        if self.base != 'https://api-dev.rsrs.rs':
            raise SmokeFailure('exact-development-address-required')
        if not re.fullmatch(r'ci-api-\d+-\d+-[0-9a-f]{8}', self.namespace):
            raise SmokeFailure('github-run-identity-required')
        if self.args.scope != 'all':
            raise SmokeFailure('full-scope-required-no-partial-success')
        if os.environ.get('RSRS_DEV_API_ADMIN_APPROVED') != 'true':
            raise SmokeFailure('development-admin-scope-not-approved')
        if not self.seed.strip():
            raise SmokeFailure('development-admin-secret-missing')
        if not re.fullmatch('[0-9a-f]{40}', self.expected_server_sha):
            raise SmokeFailure('exact-server-sha-required')
        if self.contract.get('server_source_sha') != self.expected_server_sha:
            raise SmokeFailure('route-contract-server-revision-mismatch')
        if (self.contract.get('expected_route_count') != 66 or len(self.routes) != 66
                or len(self.contract.get('routes', [])) != 66):
            raise SmokeFailure('route-contract-count-mismatch')
        inventory = '\n'.join(sorted(f"{r['method']} {r['path']} {r['group']}" for r in self.routes.values()))
        if hashlib.sha256(inventory.encode()).hexdigest() != BASELINE_ROUTE_SHA256:
            raise SmokeFailure('route-contract-inventory-mismatch')

    def key(self, method, path):
        clean = urllib.parse.urlsplit(path).path
        for key, route in self.routes.items():
            pattern = re.sub(r'\{[^}]+\}', '[^/]+', route['path'])
            if route['method'] == method and re.fullmatch(pattern, clean):
                return key
        raise SmokeFailure('request-not-in-reviewed-contract')

    def request(self, method, path, body=None, token=None):
        if not path.startswith('/') or path.startswith('//'):
            raise SmokeFailure('invalid-relative-request-path')
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = None if body is None else (body if isinstance(body, str) else json.dumps(body)).encode('utf-8')
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if isinstance(body, str) else 'application/json'
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = self.http.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError):
            raise SmokeFailure('network-request-failed') from None
        with response:
            status = response.code
            raw = response.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise SmokeFailure('response-size-limit-exceeded')
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            raise SmokeFailure('response-not-json') from None
        if not isinstance(value, dict):
            raise SmokeFailure('response-not-object')
        if method == 'GET' and path == '/health':
            advertised = value.get('source_revision')
            self.actual_server_sha = advertised if isinstance(advertised, str) and re.fullmatch('[0-9a-f]{40}', advertised) else None
            if self.actual_server_sha != self.expected_server_sha:
                raise SmokeFailure('development-server-sha-mismatch')
        return status, value

    def check(self, method, path, body=None, token=None, status=200,
              predicate=None, label='response-contract', kind='positive', contract_key=None):
        key = contract_key or self.key(method, path)
        actual, reply = self.request(method, path, body, token)
        ok = actual == status and (predicate is None or bool(predicate(reply)))
        event = {'route': key, 'assertion': label, 'kind': kind,
                 'expected_status': status, 'actual_status': actual, 'passed': ok}
        self.events.append(event)
        if ok:
            self.routes[key][kind].append(label)
        else:
            self.routes[key]['failures'].append(event)
            raise SmokeFailure('http-contract-assertion-failed')
        return reply

    def owned(self, name, admin=False):
        known = self.admins if admin else self.users
        if not name.startswith(self.namespace + '-') or name not in known:
            raise SmokeFailure('mutation-target-is-not-created-fixture')

    def register(self, suffix):
        name = self.namespace + '-' + suffix
        password = secrets.token_hex(32)
        salt = secrets.token_hex(16)
        self.unconfirmed_creations.add(name)
        result = self.check('POST', '/register', {'user': name, 'pass_hash': password,
                            'salt': salt, 'device_name': 'api-smoke'},
                            predicate=lambda r: bool(r.get('token')),
                            label='fixture-registration')
        account = {'user': name, 'pass_hash': password, 'salt': salt, 'token': result['token']}
        self.users[name] = account
        self.unconfirmed_creations.remove(name)
        return account

    def login(self, account, expected=200):
        self.owned(account['user'])
        result = self.check('POST', '/login', {'user': account['user'],
                            'pass_hash': account['pass_hash'], 'device_name': 'api-smoke-login'},
                            status=expected, predicate=lambda r: bool(r.get('token')) if expected == 200 else 'error' in r,
                            kind='positive' if expected == 200 else 'negative', label='fixture-login')
        if expected == 200:
            account['token'] = result['token']
        return result

    def create_admin(self, suffix, role, token):
        name = self.namespace + '-' + suffix
        password = secrets.token_hex(32)
        salt = secrets.token_hex(16)
        self.unconfirmed_creations.add(name)
        self.check('POST', '/admin/admins', {'user': name, 'pass_hash': password,
                   'salt': salt, 'role': role}, token,
                   predicate=lambda r: r.get('user') == name and r.get('role') == role,
                   label='fixture-admin-created')
        self.admins.add(name)
        self.unconfirmed_creations.remove(name)
        reply = self.check('POST', '/admin/login', {'user': name, 'pass_hash': password},
                           predicate=lambda r: bool(r.get('token')), label='fixture-admin-login')
        return {'user': name, 'pass_hash': password, 'salt': salt, 'token': reply['token']}

    def blob(self, ident, cipher='aa'):
        self.tick += 1
        stamp = (self.start + datetime.timedelta(milliseconds=self.tick)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        return {'id': ident, 'user': '', 'ciphertext': cipher, 'nonce': '11', 'embedding_enc': '',
                'updated_at': stamp, 'deleted': False}

    def negatives(self):
        for key, route in self.routes.items():
            if route['group'] == 'public':
                continue
            path = route['path'].replace('{user}', self.namespace + '-missing').replace('{id}', 'missing').replace('{code}', '000000000000')
            unauth = route['group'] == 'auth'
            # Serde accepts [] for TotpIn: all three fields have defaults.
            # That is an empty ticket/code authentication attempt, not bad JSON.
            empty_totp = path in ('/login/totp', '/admin/login/totp')
            self.check(route['method'], path, [] if unauth else None,
                       status=401 if empty_totp or not unauth else 400, predicate=lambda r: 'error' in r,
                       kind='negative', label='empty-default-totp-ticket' if empty_totp else 'bad-json' if unauth else 'missing-authorization')

    def vault_contract(self, token):
        """Exercise changed baseline vault semantics using only this run's synthetic account."""
        vault = {'kdf_salt': secrets.token_hex(16), 'wrapped_urk': secrets.token_hex(32),
                 'urk_nonce': secrets.token_hex(12), 'version': 4}
        self.check('POST', '/api/self/vault', vault, token,
                   predicate=lambda r: r.get('ok') is True, label='wrapped-vault-save')
        original = self.check('GET', '/api/self/vault', token=token,
                   predicate=lambda r: valid_vault_reply(r, vault, key_generation=1), label='wrapped-vault-roundtrip')
        account_id = original['account_id']
        self.check('POST', '/api/self/vault', vault, token,
                   predicate=lambda r: r.get('ok') is True, label='identical-legacy-vault-write')
        self.check('GET', '/api/self/vault', token=token,
                   predicate=lambda r: r == original, label='identical-write-preserves-vault-and-generation')
        changed = dict(vault, wrapped_urk=secrets.token_hex(32))
        self.check('POST', '/api/self/vault', changed, token,
                   predicate=lambda r: r.get('ok') is True, label='changed-legacy-vault-write')
        current = self.check('GET', '/api/self/vault', token=token,
                   predicate=lambda r: valid_vault_reply(r, changed, account_id, 2), label='legacy-write-advances-generation')
        rewrapped = dict(changed, wrapped_urk=secrets.token_hex(32))
        rejected = [
            (dict(rewrapped, operation='rewrap_same_urk'), 'rewrap-missing-generation'),
            (dict(rewrapped, operation='rewrap_same_urk', expected_key_generation=1), 'rewrap-stale-generation'),
            (dict(rewrapped, operation='unsupported', expected_key_generation=2), 'unsupported-vault-operation'),
        ]
        for body, label in rejected:
            self.check('POST', '/api/self/vault', body, token, status=400,
                       predicate=lambda r: 'error' in r, kind='negative', label=label)
            self.check('GET', '/api/self/vault', token=token,
                       predicate=lambda r: r == current, label=label + '-preserves-vault')
        self.check('POST', '/api/self/vault', dict(rewrapped, operation='rewrap_same_urk', expected_key_generation=2), token,
                   predicate=lambda r: r.get('ok') is True, label='same-urk-rewrap-current-generation')
        return self.check('GET', '/api/self/vault', token=token,
                   predicate=lambda r: valid_vault_reply(r, rewrapped, account_id, 2), label='same-urk-rewrap-preserves-generation')

    def user_and_sync(self, a, b):
        """Exercise isolated account, vault, session and encrypted sync operations."""
        token = a['token']
        self.check('GET', '/ready', predicate=lambda r: r.get('database') == 'ready' and r.get('ok') is True, label='database-readiness')
        for path in ('/health', '/ready'):
            self.check('DELETE', path, token=token, status=404, predicate=lambda r: 'error' in r,
                       kind='negative', label='unsupported-method', contract_key='GET ' + path)
        self.check('POST', '/register', {'user': a['user'], 'pass_hash': a['pass_hash'], 'salt': a['salt']},
                   status=409, predicate=lambda r: 'error' in r, kind='negative', label='duplicate-account')
        self.login(a)
        self.check('POST', '/login', {'user': a['user'], 'pass_hash': 'wrong'}, status=401,
                   predicate=lambda r: 'error' in r, kind='negative', label='wrong-password')
        token = a['token']
        self.check('GET', '/api/self', token=token, predicate=lambda r: r.get('user') == a['user'], label='own-identity')
        vault_snapshot = self.vault_contract(token)
        self.check('GET', '/api/self/keys', token=token,
                   predicate=lambda r: r.get('user') == a['user'] and r.get('auth_salt') == a['salt'] and 'token_masked' in r,
                   label='own-key-summary')
        reader = self.check('POST', '/api/self/sessions', {'device_name': 'api-reader', 'readonly': True}, token,
                            predicate=lambda r: bool(r.get('token')) and bool(r.get('session_id')) and r.get('readonly') is True,
                            label='readonly-session-create')
        self.check('POST', '/api/self/vault', vault_snapshot, reader['token'], status=403,
                   predicate=lambda r: 'error' in r, kind='negative', label='readonly-vault-write-rejected')
        self.check('GET', '/api/self/vault', token=token,
                   predicate=lambda r: r == vault_snapshot, label='readonly-vault-write-preserves-state')
        other = self.check('POST', '/api/self/sessions', {'device_name': 'api-other'}, b['token'],
                           predicate=lambda r: bool(r.get('token')) and bool(r.get('session_id')), label='second-account-session')
        self.check('GET', '/api/self/sessions', token=token,
                   predicate=lambda r: any(s.get('id', s.get('session_id')) == reader['session_id'] for s in r.get('sessions', [])),
                   label='own-sessions-list')
        foreign_path = '/api/self/sessions/' + other['session_id'] + '/revoke'
        self.check('POST', foreign_path, {}, token, predicate=lambda r: r.get('revoked') is False,
                   kind='negative', label='cross-account-revoke-rejected')
        self.check('GET', '/count', token=other['token'], predicate=lambda r: r.get('count') == 0, label='other-session-survives')
        shared_id = self.namespace + '-shared'
        initial = self.blob(shared_id)
        self.check('POST', '/push', initial, token, predicate=lambda r: r.get('replaced') is True, label='legacy-push')
        self.check('POST', '/push', self.blob(shared_id, 'bb'), reader['token'], status=403,
                   predicate=lambda r: r.get('readonly') is True, kind='negative', label='readonly-write-blocked')
        self.check('POST', '/api/self/sessions', {}, reader['token'], status=403,
                   predicate=lambda r: 'error' in r, kind='negative', label='readonly-session-creation-blocked')
        self.check('GET', '/pull', token=reader['token'], predicate=lambda r: any(x['id'] == shared_id for x in r.get('blobs', [])), label='readonly-pull-allowed')
        self.check('POST', '/push', self.blob(shared_id, 'dd'), b['token'], predicate=lambda r: r.get('replaced') is True, label='same-id-other-account')
        batch = [self.blob(self.namespace + '-batch'), self.blob(self.namespace + '-forget')]
        self.check('POST', '/push/batch', {'items': batch}, token,
                   predicate=lambda r: r.get('replaced') == [True, True], label='legacy-batch-roundtrip')
        self.check('GET', '/count', token=token, predicate=lambda r: r.get('count') == 3, label='live-count')
        self.check('GET', '/max', token=token, predicate=lambda r: r.get('max') == batch[-1]['updated_at'], label='legacy-max-timestamp')
        self.check('POST', '/forget', {'id': batch[-1]['id']}, token, predicate=lambda r: r.get('deleted') is True, label='legacy-forget-tombstone')
        cap = self.check('GET', '/sync/capabilities', token=token,
                         predicate=lambda r: 2 in r.get('protocols', []) and bool(r.get('epoch')) and r.get('conflict_resolution') is True,
                         label='v2-capabilities')
        query = '?epoch=' + urllib.parse.quote(cap['epoch'], safe='') + '&after=0'
        page = self.check('GET', '/v2/snapshot' + query, token=token,
                          predicate=lambda r: r.get('epoch') == cap['epoch'] and len(r.get('changes', [])) == 3,
                          label='initial-v2-snapshot')
        base = next(x['rev'] for x in page['changes'] if x['blob']['id'] == shared_id)
        changed = self.blob(shared_id, 'cc')
        changed['user'] = b['user']  # The bearer identity, not this untrusted field, owns the write.
        op = {'op_id': self.namespace + '-update', 'base_rev': base, 'parent_op_id': None, 'blob': changed}
        payload = {'epoch': cap['epoch'], 'items': [op]}
        receipt = self.check('POST', '/v2/push/batch', payload, token,
                             predicate=lambda r: r.get('results', [{}])[0].get('status') == 'applied', label='v2-update-applied')
        self.check('POST', '/v2/push/batch', payload, token, predicate=lambda r: r == receipt, label='v2-retry-idempotent')
        different = dict(op, blob=self.blob(shared_id, 'ee'))
        self.check('POST', '/v2/push/batch', {'epoch': cap['epoch'], 'items': [different]}, token,
                   status=409, predicate=lambda r: 'error' in r, kind='negative', label='operation-id-reuse-rejected')
        other_pull = self.check('GET', '/pull', token=b['token'],
                                predicate=lambda r: len(r.get('blobs', [])) == 1 and r['blobs'][0]['ciphertext'] == 'dd', label='cross-account-write-isolation')
        conflict = dict(op, op_id=self.namespace + '-conflict', blob=self.blob(shared_id, 'ff'))
        conflict_reply = self.check('POST', '/v2/push/batch', {'epoch': cap['epoch'], 'items': [conflict]}, token,
                                    predicate=lambda r: r.get('results', [{}])[0].get('status') == 'conflict_saved', label='stale-write-retained')
        history = self.check('GET', '/v2/pull' + query, token=token,
                             predicate=lambda r: any(x.get('status') == 'conflict_saved' for x in r.get('changes', [])), label='retained-history-readable')
        decision = {'conflict_rev': conflict_reply['results'][0]['stored_rev'],
                    'expected_head_rev': receipt['results'][0]['head_rev'], 'action': 'keep_current', 'restore_op_id': None}
        self.check('POST', '/v2/conflicts/resolve', {'epoch': cap['epoch'], 'items': [dict(decision, expected_head_rev=0)]}, token,
                   predicate=lambda r: r.get('results', [{}])[0].get('outcome') == 'stale', kind='negative', label='stale-resolution-not-applied')
        resolve = {'epoch': cap['epoch'], 'items': [decision]}
        resolved = self.check('POST', '/v2/conflicts/resolve', resolve, token,
                              predicate=lambda r: r.get('results', [{}])[0].get('outcome') == 'processed', label='keep-current-resolution')
        self.check('POST', '/v2/conflicts/resolve', resolve, token, predicate=lambda r: r == resolved, label='resolution-retry-idempotent')
        self.check('GET', '/v2/conflicts/resolutions' + query, token=token,
                   predicate=lambda r: any(x.get('conflict_rev') == decision['conflict_rev'] for x in r.get('resolutions', [])), label='resolution-stream-readable')
        self.check('GET', '/v2/pull?epoch=invalid&after=0', token=token, status=409,
                   predicate=lambda r: 'error' in r, kind='negative', label='wrong-epoch-rejected')
        self.check('POST', '/api/self/sessions/' + reader['session_id'] + '/revoke', {}, reader['token'],
                   predicate=lambda r: r.get('revoked') is True, label='readonly-self-revoke')
        self.check('GET', '/pull', token=reader['token'], status=401,
                   predicate=lambda r: 'error' in r, kind='negative', label='revoked-session-rejected')
        old = token
        rotated = self.check('POST', '/api/self/rotate', {}, token,
                             predicate=lambda r: bool(r.get('token')) and r['token'] != old, label='self-token-rotation')
        a['token'] = rotated['token']
        self.check('GET', '/count', token=old, status=401, predicate=lambda r: 'error' in r, kind='negative', label='old-token-invalidated')
        a['pass_hash'] = secrets.token_hex(32)
        self.check('POST', '/api/self/password', {'pass_hash': a['pass_hash'], 'salt': a['salt']}, a['token'],
                   predicate=lambda r: r.get('updated') is True, label='fixture-password-update')
        self.login(a)

    def mail_code(self, email, subject, admin_token, requested_at, purpose):
        for page in range(1, 21):
            result = self.check('GET', '/admin/outbox?page=' + str(page), token=admin_token,
                                predicate=lambda r: isinstance(r.get('items'), list), label='mail-outbox-read')
            # Never log or serialize global rows; only inspect this run's exact address/subject.
            for item in result['items']:
                if item.get('to') == email and item.get('subject') == subject:
                    if 'body' in item:
                        raise SmokeFailure('admin-outbox-exposes-verification-code')
                    for _ in range(30):
                        try:
                            reply = subprocess.run([sys.executable, str(Path(__file__).with_name('read-dev-mail.py')),
                                json.dumps({'recipient': email, 'requestedAt': requested_at, 'purpose': purpose})],
                                capture_output=True, text=True, timeout=20, check=True)
                            code = json.loads(reply.stdout).get('code')
                        except (subprocess.SubprocessError, ValueError):
                            raise SmokeFailure('development-mailbox-reader-failed') from None
                        if isinstance(code, str) and re.fullmatch(r'\d{6}', code):
                            return code
                        time.sleep(2)
                    raise SmokeFailure('verification-email-not-received')
            if not result['items']:
                break
        raise SmokeFailure('fixture-email-code-not-found')

    def email_and_totp(self, a, owner):
        self.owned(a['user'])
        email = os.environ.get('RSRS_DEV_MAIL_ADDRESS', '')
        if not email:
            raise SmokeFailure('development-test-mailbox-not-configured')
        requested_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.check('POST', '/api/self/email', {'email': email}, a['token'], predicate=lambda r: r.get('queued') is True, label='fixture-email-code-issued')
        code = self.mail_code(email, 'Respire email verification', owner['token'], requested_at, 'verify_email')
        self.check('POST', '/api/self/email/confirm', {'code': code}, a['token'], predicate=lambda r: r.get('updated') is True, label='fixture-email-verified')
        requested_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.check('POST', '/forgot', {'user': a['user']}, predicate=lambda r: r.get('ok') is True, label='fixture-password-reset-request')
        code = self.mail_code(email, 'Respire password reset', owner['token'], requested_at, 'reset_password')
        previous_token = a['token']
        a['pass_hash'] = secrets.token_hex(32)
        self.check('POST', '/reset', {'user': a['user'], 'code': code, 'pass_hash': a['pass_hash'], 'salt': a['salt']},
                   predicate=lambda r: r.get('updated') is True, label='fixture-password-reset-complete')
        self.check('GET', '/count', token=previous_token, status=401, predicate=lambda r: 'error' in r, kind='negative', label='reset-revokes-old-session')
        self.check('POST', '/reset', {'user': a['user'], 'code': code, 'pass_hash': a['pass_hash'], 'salt': a['salt']}, status=401, predicate=lambda r: 'error' in r, kind='negative', label='reset-code-cannot-be-replayed')
        self.login(a)
        setup = self.check('POST', '/api/self/totp/begin', {}, a['token'], predicate=lambda r: bool(r.get('secret')), label='fixture-totp-setup')
        self.check('POST', '/api/self/totp/confirm', {'code': totp(setup['secret'])}, a['token'], predicate=lambda r: r.get('totp') is True, label='fixture-totp-enabled')
        challenge = self.check('POST', '/login', {'user': a['user'], 'pass_hash': a['pass_hash']},
                               predicate=lambda r: r.get('totp_required') is True and bool(r.get('ticket')), label='fixture-totp-login-challenge')
        authenticated = self.check('POST', '/login/totp', {'ticket': challenge['ticket'], 'code': totp(setup['secret']), 'device_name': 'api-totp'},
                                   predicate=lambda r: bool(r.get('token')), label='fixture-totp-login-complete')
        a['token'] = authenticated['token']
        self.check('POST', '/api/self/totp/disable', {'code': totp(setup['secret'])}, a['token'], predicate=lambda r: r.get('totp') is False, label='fixture-totp-disabled')

    def oauth_flow(self, a, b):
        form = urllib.parse.urlencode({'client_id': 'respire-cli', 'device_name': 'API acceptance', 'expected_user': a['user']})
        grant = self.check('POST', '/oauth/device/code', form,
                           predicate=lambda r: bool(re.fullmatch('[0-9a-fA-F]{12}', r.get('user_code', ''))) and
                           urllib.parse.urlsplit(r.get('verification_uri_complete', '')).netloc == 'dash.dev.rsrs.rs',
                           label='device-grant-development-dashboard')
        path = '/api/self/cli-authorization/' + grant['user_code']
        self.check('GET', path, token=a['token'], predicate=lambda r: r.get('device_name') == 'API acceptance',
                   label='device-grant-details')
        self.check('POST', path, {'approve': True}, b['token'], status=409,
                   predicate=lambda r: 'error' in r, kind='negative', label='wrong-account-approval-rejected')
        self.check('POST', path, {'approve': True}, a['token'], predicate=lambda r: r.get('ok') is True,
                   label='device-grant-approved')
        poll = urllib.parse.urlencode({'client_id': 'respire-cli', 'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                                      'device_code': grant['device_code']})
        access = self.check('POST', '/oauth/token', poll,
                            predicate=lambda r: r.get('token_type') == 'Bearer' and r.get('user') == a['user'] and bool(r.get('access_token')),
                            label='approved-grant-exchanged')
        self.check('GET', '/api/self', token=access['access_token'], predicate=lambda r: r.get('user') == a['user'],
                   label='oauth-session-account-readback')
        self.check('POST', '/oauth/token', poll, status=400, predicate=lambda r: r.get('error') == 'invalid_grant',
                   kind='negative', label='device-grant-replay-rejected')
        self.check('GET', '/api/self/cli-authorization/000000000000', token=a['token'], status=404,
                   predicate=lambda r: 'error' in r, kind='negative', label='unknown-authorization-code')

    def admin_flow(self, owner, a):
        self.owned(owner['user'], admin=True)
        token = owner['token']
        self.check('GET', '/admin/me', token=token, predicate=lambda r: r.get('user') == owner['user'] and r.get('role') == 'owner', label='fixture-owner-identity')
        viewer = self.create_admin('viewer', 'viewer', token)
        admin = self.create_admin('operator', 'admin', token)
        def valid_stats(reply, days):
            since = reply.get('memory_tracking_since', '')
            points = reply.get('series', [])
            return (reply.get('days') == days and reply.get('timezone') == 'Asia/Shanghai'
                    and reply.get('historical_baseline') == 'retained_registrations_and_sessions'
                    and bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}', since)) and len(points) == days
                    and all((i == 0 or points[i - 1]['date'] < point['date'])
                            and type(point.get('registrations')) is int and point['registrations'] >= 0
                            and type(point.get('sessions')) is int and point['sessions'] >= 0
                            and (point.get('memories') is None if point['date'] < since else
                                 type(point.get('memories')) is int and point['memories'] >= 0)
                            for i, point in enumerate(points)))
        self.check('GET', '/admin/stats', token=token, predicate=lambda r: valid_stats(r, 30), label='owner-daily-stats-default')
        for days in [7, 90]:
            self.check('GET', f'/admin/stats?days={days}', token=admin['token'],
                       predicate=lambda r, days=days: valid_stats(r, days), label=f'admin-daily-stats-{days}-days')
        for days in ['6', '91', 'abc', '7.5']:
            self.check('GET', '/admin/stats?days=' + days, token=token, status=400,
                       predicate=lambda r: 'error' in r, kind='negative', label='stats-invalid-days-rejected')
        self.check('GET', '/admin/stats', token=viewer['token'], status=403,
                   predicate=lambda r: r.get('error') == 'forbidden', kind='negative', label='viewer-daily-stats-blocked')
        self.check('GET', '/admin/admins', token=token,
                   predicate=lambda r: any(x.get('user') == viewer['user'] for x in r.get('admins', [])), label='fixture-admin-visible')
        forbidden = self.namespace + '-forbidden'
        self.unconfirmed_creations.add(forbidden)
        self.check('POST', '/admin/admins', {'user': forbidden, 'pass_hash': 'aa', 'role': 'viewer'}, admin['token'],
                   status=403, predicate=lambda r: 'error' in r, kind='negative', label='non-owner-admin-management-blocked')
        self.unconfirmed_creations.remove(forbidden)
        self.unconfirmed_creations.add(forbidden)
        self.check('POST', '/admin/users', {'user': forbidden, 'pass_hash': 'aa'}, viewer['token'],
                   status=403, predicate=lambda r: 'error' in r, kind='negative', label='viewer-write-blocked')
        self.unconfirmed_creations.remove(forbidden)
        self.check('GET', '/admin/admins', token=viewer['token'], status=403,
                   predicate=lambda r: 'error' in r, kind='negative', label='viewer-admin-list-blocked')
        self.check('GET', '/admin/me', token=a['token'], status=403,
                   predicate=lambda r: 'error' in r, kind='negative', label='end-user-admin-access-blocked')
        self.owned(viewer['user'], admin=True)
        self.check('POST', '/admin/admins/' + viewer['user'] + '/update', {'email': viewer['user'] + '@example.invalid'}, token,
                   predicate=lambda r: r.get('updated') is True, label='fixture-admin-update')
        self.check('GET', '/admin/admins', token=token,
                   predicate=lambda r: any(x.get('user') == viewer['user'] and x.get('email') == viewer['user'] + '@example.invalid'
                                           for x in r.get('admins', [])), label='fixture-admin-update-readback')
        owner['pass_hash'] = secrets.token_hex(32)
        self.check('POST', '/admin/password', {'pass_hash': owner['pass_hash'], 'salt': owner['salt']}, token,
                   predicate=lambda r: r.get('updated') is True, label='fixture-owner-password-change')
        relogin = self.check('POST', '/admin/login', {'user': owner['user'], 'pass_hash': owner['pass_hash']},
                             predicate=lambda r: bool(r.get('token')), label='fixture-owner-new-password-login')
        owner['token'] = token = relogin['token']
        setup = self.check('POST', '/admin/totp/begin', {}, token, predicate=lambda r: bool(r.get('secret')), label='fixture-admin-totp-setup')
        self.check('POST', '/admin/totp/confirm', {'code': totp(setup['secret'])}, token, predicate=lambda r: r.get('totp') is True, label='fixture-admin-totp-enable')
        challenge = self.check('POST', '/admin/login', {'user': owner['user'], 'pass_hash': owner['pass_hash']},
                               predicate=lambda r: r.get('totp_required') is True and bool(r.get('ticket')), label='fixture-admin-totp-challenge')
        login = self.check('POST', '/admin/login/totp', {'ticket': challenge['ticket'], 'code': totp(setup['secret'])},
                           predicate=lambda r: bool(r.get('token')), label='fixture-admin-totp-login')
        owner['token'] = token = login['token']
        self.check('POST', '/admin/totp/disable', {'code': totp(setup['secret'])}, token,
                   predicate=lambda r: r.get('totp') is False, label='fixture-admin-totp-disable')
        target = self.namespace + '-managed'
        password = secrets.token_hex(32)
        salt = secrets.token_hex(16)
        self.unconfirmed_creations.add(target)
        created = self.check('POST', '/admin/users', {'user': target, 'pass_hash': password, 'salt': salt}, token,
                             predicate=lambda r: r.get('user') == target and bool(r.get('token')), label='fixture-managed-user-create')
        account = {'user': target, 'pass_hash': password, 'salt': salt, 'token': created['token']}
        self.users[target] = account
        self.unconfirmed_creations.remove(target)
        self.check('GET', '/admin/users?q=' + target + '&page=1&limit=10', token=token,
                   predicate=lambda r: r.get('total') == 1 and r.get('users', [{}])[0].get('user') == target, label='scoped-user-search')
        self.check('GET', '/admin/users?q=' + target + '&export=1', token=token,
                   predicate=lambda r: isinstance(r.get('csv'), str) and target in r['csv'], label='scoped-user-csv')
        self.owned(target)
        self.check('POST', '/admin/users/' + target + '/update', {'email': target + '@example.invalid'}, token,
                   predicate=lambda r: r.get('updated') is True, label='fixture-managed-user-update')
        self.check('GET', '/admin/users?q=' + target + '&page=1&limit=10', token=token,
                   predicate=lambda r: any(x.get('user') == target and x.get('email') == target + '@example.invalid'
                                           for x in r.get('users', [])), label='fixture-managed-user-update-readback')
        session = self.check('POST', '/admin/users/' + target + '/sessions', {'device_name': 'managed-api'}, token,
                             predicate=lambda r: bool(r.get('token')) and bool(r.get('session_id')), label='fixture-managed-session-create')
        self.check('GET', '/admin/users/' + target + '/sessions', token=token,
                   predicate=lambda r: any(x.get('id') == session['session_id'] for x in r.get('sessions', [])), label='fixture-managed-sessions-list')
        self.check('POST', '/admin/users/' + a['user'] + '/sessions/' + session['session_id'] + '/revoke', {}, token,
                   status=404, predicate=lambda r: 'error' in r, kind='negative', label='mismatched-session-user-rejected')
        self.check('POST', '/admin/users/' + target + '/sessions/' + session['session_id'] + '/revoke', {}, token,
                   predicate=lambda r: r.get('revoked') is True, label='fixture-managed-session-revoke')
        self.check('GET', '/count', token=session['token'], status=401, predicate=lambda r: 'error' in r, kind='negative', label='managed-revoked-token-rejected')
        self.check('POST', '/push', self.blob(self.namespace + '-managed-data'), account['token'], predicate=lambda r: r.get('replaced') is True, label='managed-data-before-account-transitions')
        for action, field in [('disable', 'disabled'), ('enable', 'disabled'), ('kick', 'kicked'), ('delete', 'deleted'), ('restore', 'restored')]:
            self.owned(target)
            before = account['token']
            self.check('POST', '/admin/users/' + target + '/' + action, {}, token,
                       predicate=lambda r, f=field, act=action: r.get(f) is (act != 'enable'), label='fixture-account-' + action)
            if action == 'kick':
                self.check('GET', '/count', token=before, status=401, predicate=lambda r: 'error' in r,
                           kind='negative', label='kicked-account-old-token-rejected')
            if action in ('disable', 'delete'):
                self.login(account, 403)
            elif action in ('enable', 'kick', 'restore'):
                self.login(account)
        old = account['token']
        rotated = self.check('POST', '/admin/users/' + target + '/rotate', {}, token,
                             predicate=lambda r: bool(r.get('token')) and r['token'] != old, label='fixture-admin-token-rotate')
        account['token'] = rotated['token']
        self.check('GET', '/pull', token=old, status=401, predicate=lambda r: 'error' in r, kind='negative', label='admin-rotation-old-token-rejected')
        self.check('GET', '/pull', token=account['token'], predicate=lambda r: len(r.get('blobs', [])) == 1, label='managed-data-survives-soft-transitions')
        self.check('GET', '/admin/audit?q=' + self.namespace + '&page=1&limit=100', token=token,
                   predicate=lambda r: r.get('total', 0) > 0 and bool(r.get('items')), label='fixture-audit-present')
        for suffix, alias in [('revoke-target', 'revoke'), ('purge-target', 'purge')]:
            account = self.register(suffix)
            self.owned(account['user'])
            self.check('POST', '/push', self.blob(self.namespace + '-' + suffix + '-blob'), account['token'],
                       predicate=lambda r: r.get('replaced') is True, label='fixture-data-before-admin-purge')
            self.check('POST', '/admin/users/' + account['user'] + '/' + alias, {}, token,
                       predicate=lambda r: r.get('purged') is True and r.get('blobs_deleted', 0) >= 1, label='fixture-admin-' + alias + '-alias')
            del self.users[account['user']]
            self.check('GET', '/count', token=account['token'], status=401, predicate=lambda r: 'error' in r, kind='negative', label='purged-account-token-rejected')
        for fixture in (viewer, admin):
            self.owned(fixture['user'], admin=True)
            self.check('POST', '/admin/admins/' + fixture['user'] + '/revoke', {}, token,
                       predicate=lambda r: r.get('deleted') is True, label='fixture-admin-delete')
            self.admins.remove(fixture['user'])
            self.check('POST', '/admin/login', {'user': fixture['user'], 'pass_hash': fixture['pass_hash']},
                       status=401, predicate=lambda r: 'error' in r, kind='negative', label='deleted-admin-login-rejected')
            self.check('GET', '/admin/me', token=fixture['token'], status=403,
                       predicate=lambda r: 'error' in r, kind='negative', label='deleted-admin-token-rejected')

    def cleanup(self):
        # Mutation scope is the successful creation ledger, never namespace search results.
        for name in list(self.users):
            try:
                self.owned(name)
                status, value = self.request('POST', '/admin/users/' + name + '/purge', {}, self.seed)
                ok = status == 200 and value.get('purged') is True
                if ok:
                    del self.users[name]
                self.cleanup_events.append({'kind': 'user', 'passed': ok, 'status': status})
            except Exception:
                self.cleanup_events.append({'kind': 'user', 'passed': False, 'reason': 'cleanup-failed'})
        for name in list(self.admins):
            try:
                self.owned(name, admin=True)
                status, value = self.request('POST', '/admin/admins/' + name + '/revoke', {}, self.seed)
                ok = status == 200 and value.get('deleted') is True
                if ok:
                    self.admins.remove(name)
                self.cleanup_events.append({'kind': 'admin', 'passed': ok, 'status': status})
            except Exception:
                self.cleanup_events.append({'kind': 'admin', 'passed': False, 'reason': 'cleanup-failed'})

    def run(self):
        self.preflight()
        # Check deployment identity before any fixture creation or privileged write.
        self.check('GET', '/health', predicate=lambda r: r.get('ok') is True and r.get('service') == 'respire', label='service-liveness')
        self.check('GET', '/ready', predicate=lambda r: r.get('database') == 'ready' and r.get('ok') is True,
                   label='exact-server-deployment-ready')
        self.check('GET', '/admin/me', token=self.seed, predicate=lambda r: r.get('role') == 'owner', label='development-seed-owner-check')
        owner = self.create_admin('owner', 'owner', self.seed)
        self.negatives()
        a, b = self.register('a'), self.register('b')
        self.user_and_sync(a, b)
        self.email_and_totp(a, owner)
        self.oauth_flow(a, b)
        self.admin_flow(owner, a)
        self.owned(b['user'])
        self.check('POST', '/api/self/purge', {'confirm': 'not-the-fixture'}, b['token'], status=400,
                   predicate=lambda r: r.get('confirm_required') == b['user'], kind='negative', label='account-purge-confirmation-required')
        self.check('POST', '/api/self/purge', {'confirm': b['user']}, b['token'],
                   predicate=lambda r: r.get('purged') is True and r.get('blobs_deleted', 0) >= 1, label='fixture-self-account-purge')
        del self.users[b['user']]

    def report(self, error):
        """Write a sanitized result that requires complete route, vault and cleanup coverage."""
        routes = list(self.routes.values())
        uncovered = [r['method'] + ' ' + r['path'] for r in routes if not r['positive']]
        negative_uncovered = [r['method'] + ' ' + r['path'] for r in routes if not r['negative']]
        observed_vault = {event['assertion'] for event in self.events if event['passed']
                          and event['route'] in ('GET /api/self/vault', 'POST /api/self/vault')}
        missing_vault = sorted(REQUIRED_VAULT_ASSERTIONS - observed_vault)
        complete = error is None and not uncovered and not negative_uncovered and not missing_vault and not self.users and not self.admins and not self.unconfirmed_creations and all(x['passed'] for x in self.cleanup_events)
        workflow_sha = os.environ.get('GITHUB_SHA', '').lower()
        result = {'schema': 1, 'scope': 'development-cli-baseline-api', 'server': 'https://api-dev.rsrs.rs',
                  'namespace': self.namespace, 'complete': complete, 'error': error,
                  'server_sha_expected': self.expected_server_sha,
                  'server_sha_actual': self.actual_server_sha,
                  'contract_server_sha': self.contract.get('server_source_sha'),
                  'separate_coverage': self.contract.get('separate_coverage', {}),
                  'cli_workflow_sha': workflow_sha if re.fullmatch('[0-9a-f]{40}', workflow_sha) else None,
                  'counts': {'routes': len(routes), 'positive_covered': len(routes) - len(uncovered),
                             'negative_covered': sum(bool(r['negative']) for r in routes), 'assertions': len(self.events)},
                  'uncovered': uncovered, 'negative_uncovered': negative_uncovered,
                  'missing_vault_assertions': missing_vault, 'routes': routes, 'assertions': self.events,
                  'cleanup': {'events': self.cleanup_events, 'remaining_users': list(self.users), 'remaining_admins': sorted(self.admins),
                              'unconfirmed_creations': sorted(self.unconfirmed_creations)},
                  'not_run': ['shared-server-last-owner-guard', 'CLI encryption/decryption and legacy CLI fallback proxy'],
                  'limits': ['Cloud contract fixtures use synthetic opaque ciphertext.',
                             'No forced multi-page dataset yet; pagination metadata and wrong epoch are covered.',
                             'Mail rows are inspected only in memory and never included in reports.']}
        report = Path(self.args.report)
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'complete': complete, 'counts': result['counts'], 'error': error,
                          'remaining_fixtures': len(self.users) + len(self.admins)}))
        return 0 if complete else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    parser.add_argument('--scope', choices=['all', 'user'], default='all')
    args = parser.parse_args()
    smoke = Smoke(args)
    error = None
    try:
        smoke.run()
    except SmokeFailure as failure:
        error = str(failure)
    except Exception:
        error = 'unexpected-smoke-failure'
    finally:
        if smoke.users or smoke.admins:
            smoke.cleanup()
    return smoke.report(error)


if __name__ == '__main__':
    sys.exit(main())

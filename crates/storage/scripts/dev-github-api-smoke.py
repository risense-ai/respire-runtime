#!/usr/bin/env python3
"""DEV GitHub transport/security checks; real provider login is a separate acceptance gate."""

import argparse
import json
from pathlib import Path
import re
import secrets
import urllib.parse

from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location('dev_api_smoke', Path(__file__).with_name('dev-api-smoke.py'))
baseline = module_from_spec(spec)
spec.loader.exec_module(baseline)


class GithubSmoke(baseline.Smoke):
    def __init__(self, args):
        super().__init__(args)
        self.github_events = []

    def probe(self, method, path, body=None, token=None, expected=200, predicate=None, label='contract'):
        status, reply = self.request(method, path, body, token)
        passed = status == expected and (predicate is None or predicate(reply))
        self.github_events.append({'method': method, 'path': path, 'assertion': label,
                                   'status': status, 'expected_status': expected, 'passed': bool(passed)})
        if not passed:
            raise baseline.SmokeFailure('github-contract-assertion-failed')
        return reply

    def grant(self, path, token=None):
        reply = self.probe('POST', path, {}, token, label='configured-provider-start')
        uri = urllib.parse.urlsplit(reply.get('authorization_uri', ''))
        query = urllib.parse.parse_qs(uri.query, keep_blank_values=True)
        state = reply.get('state', '')
        valid = (uri.scheme == 'https' and uri.netloc == 'github.com'
                 and uri.path == '/login/oauth/authorize' and not uri.fragment
                 and re.fullmatch('[0-9a-f]{64}', state)
                 and query.get('state') == [state]
                 and query.get('redirect_uri') == ['https://dash.dev.rsrs.rs/']
                 and query.get('scope') == ['']
                 and query.get('code_challenge_method') == ['S256']
                 and re.fullmatch('[A-Za-z0-9_-]{43}', query.get('code_challenge', [''])[0])
                 and bool(query.get('client_id', [''])[0]) and reply.get('expires_in') == 600)
        if not valid:
            raise baseline.SmokeFailure('github-start-pkce-or-origin-mismatch')
        # Correlation state and authorization URLs never enter the report.
        self.github_events.append({'method': 'POST', 'path': path, 'assertion': 'exact-dev-callback-pkce-empty-scope', 'passed': True})
        return state

    def run(self):
        self.preflight()
        self.check('GET', '/health', predicate=lambda r: r.get('ok') is True, label='exact-server-identity')
        self.check('GET', '/admin/me', token=self.seed, predicate=lambda r: r.get('role') == 'owner', label='fixture-owner')
        account = self.register('github')
        token = account['token']
        for method, path in [('GET', '/api/self/github'), ('POST', '/api/self/github/start'),
                             ('POST', '/api/self/github/exchange'), ('POST', '/api/self/github/unbind'),
                             ('POST', '/api/self/github/vault')]:
            self.probe(method, path, {}, expected=401, predicate=lambda r: 'error' in r, label='missing-session')
        self.probe('GET', '/api/self/github', token=token,
                   predicate=lambda r: r.get('bound') is False, label='new-fixture-unbound')
        reader = self.check('POST', '/api/self/sessions', {'device_name': 'github-reader', 'readonly': True}, token,
                            predicate=lambda r: bool(r.get('token')), label='readonly-fixture')
        for path in ('start', 'exchange', 'unbind', 'vault'):
            self.probe('POST', '/api/self/github/' + path, {}, reader['token'], expected=403,
                       predicate=lambda r: 'error' in r, label='readonly-write-rejected')
        unknown = {'state': secrets.token_hex(32), 'code': 'invalid-fixture-code'}
        for path, auth in [('/oauth/github/exchange', None), ('/api/self/github/exchange', token)]:
            self.probe('POST', path, {}, auth, expected=400, predicate=lambda r: 'error' in r, label='malformed-grant')
            self.probe('POST', path, unknown, auth, expected=400,
                       predicate=lambda r: 'error' in r, label='unknown-state-rejected')
        for start, exchange, auth in [('/oauth/github/start', '/oauth/github/exchange', None),
                                      ('/api/self/github/start', '/api/self/github/exchange', token)]:
            state = self.grant(start, auth)
            payload = {'state': state, 'code': 'invalid-fixture-' + secrets.token_hex(16)}
            self.probe('POST', exchange, payload, auth, expected=502,
                       predicate=lambda r: (r.get('error') == 'GitHub authorization failed; please start again'
                       or (r.get('cloudflare_error') is True and r.get('error_code') == 502 and r.get('status') == 502
                           and r.get('type') == 'https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-502/'))
                       and not any(field in r for field in ('token', 'access_token', 'refresh_token', 'session_id')),
                       label='invalid-provider-code-no-session')
            self.probe('POST', exchange, payload, auth, expected=400,
                       predicate=lambda r: 'error' in r, label='consumed-state-replay-rejected')
        vault = {'kdf_salt': secrets.token_hex(16), 'wrapped_urk': secrets.token_hex(48),
                 'urk_nonce': secrets.token_hex(12), 'version': 4}
        self.check('POST', '/api/self/vault', vault, token, predicate=lambda r: r.get('ok') is True,
                   label='original-fixture-vault')
        self.probe('POST', '/api/self/github/vault', {}, token, expected=400,
                   predicate=lambda r: 'error' in r, label='malformed-initial-vault-rejected')
        self.probe('POST', '/api/self/github/vault', vault, token, expected=409,
                   predicate=lambda r: 'error' in r, label='existing-vault-never-overwritten')
        self.probe('POST', '/api/self/github/unbind', {}, token,
                   predicate=lambda r: r.get('bound') is False, label='password-account-unbind-idempotent')
        self.check('GET', '/api/self', token=token, predicate=lambda r: r.get('user') == account['user'],
                   label='unbind-preserves-session')
        self.check('GET', '/api/self/vault', token=token,
                   predicate=lambda r: all(r.get(k) == v for k, v in vault.items()), label='vault-bytes-preserved')

    def report(self, error):
        complete = (error is None and bool(self.github_events) and all(e['passed'] for e in self.github_events)
                    and not self.users and not self.admins and not self.unconfirmed_creations
                    and all(e['passed'] for e in self.cleanup_events))
        result = {'schema': 1, 'scope': 'development-github-transport-security', 'complete': complete,
                  'error': error, 'server_sha_expected': self.expected_server_sha,
                  'server_sha_actual': self.actual_server_sha, 'assertions': self.github_events + self.events,
                  'cleanup': self.cleanup_events, 'remaining_fixture_count': len(self.users) + len(self.admins),
                  'not_run': ['Real GitHub consent/login/binding, TOTP and sole-method unbinding require separate provider acceptance.'],
                  'limits': ['Invalid provider codes test failure and state consumption; they do not prove successful GitHub login.',
                             'Cloudflare may replace an intentional origin 502 with its exact structured 502 envelope; no-session and consumed-state replay checks remain required.']}
        Path(self.args.report).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'complete': complete, 'assertions': len(result['assertions']), 'error': error,
                          'remaining_fixture_count': result['remaining_fixture_count']}))
        return 0 if complete else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    args.scope = 'all'
    smoke = GithubSmoke(args)
    error = None
    try:
        smoke.run()
    except baseline.SmokeFailure as failure:
        error = str(failure)
    except Exception:
        error = 'unexpected-github-smoke-failure'
    finally:
        if smoke.users or smoke.admins:
            smoke.cleanup()
    return smoke.report(error)


if __name__ == '__main__':
    raise SystemExit(main())

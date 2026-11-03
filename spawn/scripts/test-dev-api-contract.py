"""Offline regression tests for the exact reviewed API contract and its vault assertions."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parent
SHA = 'fb370b2a49193db64d2530c9af9a2a3895fd231c'
OLD_SHA = '22096e8e237a5b49588678577cbd96af066eabe3'
IDENTITY = '11111111-2222-4333-8444-555555555555'
ENV = {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
       'RSRS_DEV_SERVER_ADDR': 'https://api-dev.rsrs.rs', 'RSRS_DEV_SERVER_SHA': SHA,
       'RSRS_DEV_API_ADMIN_APPROVED': 'true', 'RSRS_DEV_ADMIN_TOKEN': 'synthetic-never-sent'}


def load(name, filename):
    """Import a script by filename without invoking its command-line entry point."""
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load('baseline_api_contract', 'dev-api-smoke.py')
github = load('github_api_contract', 'dev-github-api-smoke.py')


class VaultModel(api.Smoke):
    """Synthetic HTTP-shaped model, not a claim of actual server acceptance."""
    def __init__(self, fault=None):
        """Create isolated in-memory vault state with an optional deliberate regression."""
        super().__init__(argparse.Namespace(scope='all', report='unused'))
        self.vault = None
        self.fault = fault

    def request(self, method, path, body=None, token=None):
        """Model reviewed vault HTTP semantics without contacting any service."""
        assert path == '/api/self/vault', 'model must not contact any service'
        if method == 'GET':
            result = dict(self.vault)
            if self.fault == 'bad-identity':
                result['account_id'] = 'invalid'
            if self.fault == 'boolean-generation':
                result['key_generation'] = True
            return 200, result
        if token == 'reader':
            return 403, {'error': 'readonly'}
        fields = {key: body[key] for key in ('kdf_salt', 'wrapped_urk', 'urk_nonce', 'version')}
        operation = body.get('operation')
        if operation not in (None, 'rewrap_same_urk') or (operation == 'rewrap_same_urk'
                and body.get('expected_key_generation') != self.vault['key_generation']):
            if self.fault == 'rejected-write-mutates':
                self.vault.update(fields)
            return 200 if self.fault == 'wrong-rejection-status' else 400, {'error': 'rejected'}
        if self.vault is None:
            self.vault = dict(fields, account_id=IDENTITY, key_generation=1)
        else:
            changed = any(self.vault[key] != value for key, value in fields.items())
            if (changed and operation is None and self.fault != 'legacy-generation-stuck') or (
                    not changed and self.fault == 'idempotent-generation-advances') or (
                    operation == 'rewrap_same_urk' and self.fault == 'rewrap-generation-advances'):
                self.vault['key_generation'] += 1
            self.vault.update(fields)
        return 200, {'ok': True}


class ContractTests(unittest.TestCase):
    """No test obtains real secrets, creates remote accounts, or opens a network socket."""
    def setUp(self):
        """Use synthetic configuration and forbid network access for every test."""
        self.env = mock.patch.dict(os.environ, ENV, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.network = mock.patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden'))
        self.network.start()
        self.addCleanup(self.network.stop)

    def smoke(self):
        """Construct the actual baseline harness under the isolated test environment."""
        return api.Smoke(argparse.Namespace(scope='all', report='unused'))

    def test_reviewed_baseline_routes_and_all_explicit_exclusions(self):
        """Preserve the original route fingerprint and account for separately scoped APIs."""
        smoke = self.smoke()
        smoke.preflight()
        self.assertEqual(smoke.contract['server_source_sha'], SHA)
        routes = {r['method'] + ' ' + r['path'] for r in smoke.contract['routes']}
        self.assertEqual(len(routes), 66)
        inventory = '\n'.join(sorted(f"{r['method']} {r['path']} {r['group']}" for r in smoke.contract['routes']))
        self.assertEqual(hashlib.sha256(inventory.encode()).hexdigest(), api.BASELINE_ROUTE_SHA256)
        excluded = smoke.contract['separate_coverage']
        self.assertEqual([len(excluded[key]['routes']) for key in (
            'github_transport', 'existing_browser_only', 'passkey_and_vault_reset')], [7, 2, 10])
        self.assertIn('POST /api/self/passkeys/cancel', excluded['passkey_and_vault_reset']['routes'])
        complete = set(routes)
        for group in excluded.values():
            self.assertFalse(complete.intersection(group['routes']))
            complete.update(group['routes'])
        self.assertEqual(len(complete), 85)
        self.assertEqual(smoke.contract['review']['canonical_server_operations'], 85)

    def test_stale_or_unreviewed_server_sha_is_still_rejected(self):
        """Require the exact source revision whose contract has been reviewed."""
        for expected in (OLD_SHA, 'a' * 40, '', 'not-a-sha'):
            with self.subTest(expected=expected), mock.patch.dict(os.environ, {'RSRS_DEV_SERVER_SHA': expected}):
                with self.assertRaises(api.SmokeFailure):
                    self.smoke().preflight()

    def test_missing_duplicate_substituted_or_regrouped_routes_fail(self):
        """Reject route inventory changes even when the apparent count stays constant."""
        for mutation in ('missing', 'duplicate', 'substituted', 'regrouped'):
            smoke = self.smoke()
            key = next(iter(smoke.routes))
            if mutation == 'missing':
                smoke.routes.pop(key)
            elif mutation == 'duplicate':
                smoke.contract['routes'].append(smoke.contract['routes'][0])
            elif mutation == 'substituted':
                smoke.routes[key]['path'] = '/substituted'
            else:
                smoke.routes[key]['group'] = 'public'
            with self.subTest(mutation=mutation), self.assertRaises(api.SmokeFailure):
                smoke.preflight()

    def test_existing_scope_address_approval_and_secret_gates_remain(self):
        """Keep the existing Actions, destination, authorization and full-scope guards."""
        for field, value in [('GITHUB_ACTIONS', 'false'), ('RSRS_DEV_SERVER_ADDR', 'https://example.invalid'),
                             ('RSRS_DEV_API_ADMIN_APPROVED', 'false'), ('RSRS_DEV_ADMIN_TOKEN', '')]:
            with self.subTest(field=field), mock.patch.dict(os.environ, {field: value}):
                with self.assertRaises(api.SmokeFailure):
                    self.smoke().preflight()
        smoke = self.smoke()
        smoke.args.scope = 'user'
        with self.assertRaises(api.SmokeFailure):
            smoke.preflight()

    def test_live_health_revision_gate_remains_strict(self):
        """Reject a stale live server before recording assertions or creating fixtures."""
        smoke = self.smoke()
        response = mock.MagicMock()
        response.code = 200
        response.read.return_value = json.dumps({'source_revision': OLD_SHA}).encode()
        with mock.patch.object(smoke.http, 'open', return_value=response):
            with self.assertRaisesRegex(api.SmokeFailure, 'development-server-sha-mismatch'):
                smoke.request('GET', '/health')
        self.assertEqual(smoke.actual_server_sha, OLD_SHA)
        self.assertFalse(smoke.events or smoke.users or smoke.admins)

    def test_separate_github_suite_inherits_reviewed_strict_preflight(self):
        """Apply the same exact-revision gate to the separate GitHub transport suite."""
        smoke = github.GithubSmoke(argparse.Namespace(scope='all', report='unused'))
        smoke.preflight()
        smoke.expected_server_sha = OLD_SHA
        with self.assertRaises(github.baseline.SmokeFailure):
            smoke.preflight()

    def test_vault_sequence_checks_every_changed_semantic(self):
        """Exercise required vault assertions without exposing opaque fields in events."""
        smoke = VaultModel()
        final = smoke.vault_contract('writer')
        self.assertEqual(final['account_id'], IDENTITY)
        self.assertEqual(final['key_generation'], 2)
        readonly = {'readonly-vault-write-rejected', 'readonly-vault-write-preserves-state'}
        self.assertEqual({event['assertion'] for event in smoke.events}, api.REQUIRED_VAULT_ASSERTIONS - readonly)
        serialized = json.dumps(smoke.events)
        self.assertNotIn(final['wrapped_urk'], serialized)
        self.assertNotIn('synthetic-never-sent', serialized)

    def test_vault_regressions_are_detected(self):
        """Ensure each deliberate schema or persistence defect fails the actual harness."""
        for fault in ('bad-identity', 'boolean-generation', 'rejected-write-mutates', 'wrong-rejection-status',
                      'legacy-generation-stuck', 'idempotent-generation-advances', 'rewrap-generation-advances'):
            with self.subTest(fault=fault), self.assertRaises(api.SmokeFailure):
                VaultModel(fault).vault_contract('writer')

    def test_vault_schema_rejects_missing_or_wrong_types(self):
        """Validate identity, integer generation and exact recovery-field preservation."""
        vault = {'kdf_salt': 'synthetic-salt', 'wrapped_urk': 'synthetic-wrap', 'urk_nonce': 'nonce', 'version': 4}
        valid = dict(vault, account_id=IDENTITY, key_generation=1)
        self.assertTrue(api.valid_vault_reply(valid, vault))
        for identity in (None, '', 'not-a-uuid', 123):
            self.assertFalse(api.valid_vault_reply(dict(valid, account_id=identity), vault))
        for generation in (None, True, '1', 1.0, 0, -1, 9007199254740992):
            self.assertFalse(api.valid_vault_reply(dict(valid, key_generation=generation), vault))
        self.assertFalse(api.valid_vault_reply(dict(valid, wrapped_urk='different'), vault))
        self.assertFalse(api.valid_vault_reply(valid, vault, account_id='other'))
        self.assertFalse(api.valid_vault_reply(valid, vault, key_generation=2))

    def test_old_route_only_success_cannot_satisfy_new_vault_review(self):
        """Prevent legacy route-only coverage from satisfying the strengthened report."""
        smoke = self.smoke()
        for route in smoke.routes.values():
            route['positive'].append('old-success')
            route['negative'].append('old-rejection')
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            smoke.args.report = str(Path(directory) / 'report.json')
            self.assertEqual(smoke.report(None), 2)
            report = json.loads(Path(smoke.args.report).read_text())
            self.assertFalse(report['complete'])
            self.assertEqual(set(report['missing_vault_assertions']), api.REQUIRED_VAULT_ASSERTIONS)
            self.assertEqual(report['scope'], 'development-cli-baseline-api')
            self.assertIn('passkey_and_vault_reset', report['separate_coverage'])


if __name__ == '__main__':
    unittest.main()

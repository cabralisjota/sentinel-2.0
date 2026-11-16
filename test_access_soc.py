"""Temporary-data regression tests for the permanent Unified Access SOC v2 plugin."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from flask import Flask
from access_soc import correlations, epoch, register_access_soc
from sentinel_access_lab import create_app


class UnifiedSOCTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.lab, self.password = create_app(self.root / 'data', {'TESTING': True})
        self.lab_client = self.lab.test_client()
        self.lab_client.get('/')
        with self.lab_client.session_transaction() as session:
            csrf = session['csrf']
        self.lab_client.post('/login', data={'password': self.password, 'csrf': csrf})
        with self.lab_client.session_transaction() as session:
            self.lab_csrf = session['csrf']
        self.network = [{'id': 1, 'timestamp': '2026-11-16T12:00:00+00:00', 'type': 'Demo example',
                         'ip': '192.0.2.1', 'country': 'Demo', 'severity': 'medium'},
                        {'id': 2, 'timestamp': '2026-11-16T07:01:00-05:00', 'source': 'ids',
                         'type': 'IDS example', 'ip': '192.0.2.2', 'severity': 'high'}]
        self.soc = Flask('soc_test')
        self.soc.config.update(TESTING=True, ACCESS_SOC_STATE_DIR=str(self.root / 'private'),
                               ACCESS_SOC_NETWORK_PROVIDER=lambda: self.network)
        self.soc.add_url_rule('/', 'home', lambda: '<html><body><aside>Sentinel</aside></body></html>')
        with patch.dict(os.environ, {'ENABLE_ACCESS_SOC': '1', 'ACCESS_LAB_DB': self.lab.config['DATABASE']}):
            register_access_soc(self.soc)
        self.client = self.soc.test_client()
        self.login()

    def tearDown(self):
        self.temporary.cleanup()

    def login(self, client=None, password=None):
        client = client or self.client
        page = client.get('/access-monitor').get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        result = client.post('/access-soc/login', data={'password': password or self.password, 'csrf': csrf})
        if result.status_code == 303 and client == self.client:
            self.csrf = self.client.get('/api/unified-events').get_json()['csrf']
        return result

    def lab_post(self, path, payload):
        response = self.lab_client.post(path, json=payload, headers={'X-CSRF-Token': self.lab_csrf})
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()

    def state(self):
        response = self.client.get('/api/unified-events')
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_live_database_updates_and_case_evidence(self):
        self.assertEqual(self.state()['counts']['total_events'], 0)
        self.lab_post('/api/scenarios', {'name': 'denied_burst'})
        result = self.state()
        self.assertEqual(result['counts']['denied'], 5)
        self.assertEqual(result['counts']['open_cases'], 1)
        self.assertEqual(len([e for e in result['events'] if e['source'] == 'RFID simulation']), 5)
        evidence = self.client.get('/api/access-soc/cases/1').get_json()
        self.assertEqual(evidence['evidence_total'], 5)
        self.assertEqual(len(evidence['events']), 5)

    def test_central_case_updates_visible_in_access_lab(self):
        self.lab_post('/api/scenarios', {'name': 'revoked_badge'})
        response = self.client.post('/api/access-soc/cases/1', json={'status': 'resolved', 'note': 'Reviewed from SOC.'},
                                    headers={'X-CSRF-Token': self.csrf})
        self.assertEqual(response.status_code, 200)
        same_case = self.lab_client.get('/api/cases/1').get_json()
        self.assertEqual(same_case['case']['status'], 'resolved')
        self.assertEqual(same_case['notes'][0]['note'], 'Reviewed from SOC.')
        self.assertEqual(self.state()['counts']['open_cases'], 0)
        with sqlite3.connect(self.lab.config['DATABASE']) as db:
            actor, details = db.execute("SELECT actor,details FROM audit WHERE actor='unified-soc-admin'").fetchone()
        self.assertEqual(actor, 'unified-soc-admin')
        self.assertEqual(json.loads(details)['after'], 'resolved')

    def test_authentication_csrf_and_local_boundary(self):
        anonymous = self.soc.test_client()
        self.assertEqual(anonymous.get('/api/unified-events').status_code, 401)
        self.assertEqual(anonymous.get('/api/access-soc/export').status_code, 401)
        self.assertEqual(self.client.post('/api/access-soc/cases/1', json={'status': 'resolved'}).status_code, 403)
        self.assertEqual(self.client.get('/access-monitor', environ_overrides={'REMOTE_ADDR': '192.0.2.3'}).status_code, 403)
        self.assertEqual(self.client.get('/api/unified-events', headers={'Host': 'other.example'}).status_code, 403)
        self.assertIn("frame-ancestors 'none'", self.client.get('/access-monitor').headers['Content-Security-Policy'])

    def test_invalid_case_update_leaves_data_unchanged(self):
        self.lab_post('/api/scenarios', {'name': 'revoked_badge'})
        for body in [{'status': []}, {'status': 'resolved', 'note': 'x' * 2001}, []]:
            result = self.client.post('/api/access-soc/cases/1', json=body, headers={'X-CSRF-Token': self.csrf})
            self.assertEqual(result.status_code, 400)
        evidence = self.lab_client.get('/api/cases/1').get_json()
        self.assertEqual(evidence['case']['status'], 'open')
        self.assertEqual(evidence['notes'], [])

    def test_failed_audit_insert_rolls_back_case_and_note(self):
        self.lab_post('/api/scenarios', {'name': 'revoked_badge'})
        with sqlite3.connect(self.lab.config['DATABASE']) as db:
            db.execute('DROP TABLE audit')
        result = self.client.post('/api/access-soc/cases/1', json={'status': 'resolved', 'note': 'Must roll back.'},
                                  headers={'X-CSRF-Token': self.csrf})
        self.assertEqual(result.status_code, 503)
        evidence = self.lab_client.get('/api/cases/1').get_json()
        self.assertEqual(evidence['case']['status'], 'open')
        self.assertEqual(evidence['notes'], [])

    def test_multidoor_rule_and_time_window(self):
        for door in ('lobby', 'office'):
            self.lab_post('/api/swipe', {'badge_id': 'SIM-UNKNOWN', 'door_id': door})
        self.assertEqual(self.state()['correlations'], [])
        self.lab_post('/api/swipe', {'badge_id': 'SIM-UNKNOWN', 'door_id': 'server'})
        signals = self.state()['correlations']
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]['rule'], 'MULTI_DOOR_DENIALS')
        with sqlite3.connect(self.lab.config['DATABASE']) as db:
            db.execute('UPDATE events SET ts=ts-121 WHERE id=1')
        self.assertEqual(self.state()['correlations'], [])

    def test_five_denials_then_forced_door_rule(self):
        for _ in range(5):
            self.lab_post('/api/swipe', {'badge_id': 'SIM-UNKNOWN', 'door_id': 'loading'})
        self.lab_post('/api/scenarios', {'name': 'forced_door'})
        signal = self.state()['correlations'][0]
        self.assertEqual(signal['rule'], 'DENIAL_THEN_FORCED_DOOR')
        self.assertEqual(len(signal['events']), 6)
        self.assertEqual(signal['severity'], 'high')
        self.assertIn('does not establish', signal['summary'])

    def test_no_forced_door_correlation_across_doors(self):
        self.lab_post('/api/scenarios', {'name': 'denied_burst'})  # Office door.
        self.lab_post('/api/scenarios', {'name': 'forced_door'})   # Loading door.
        self.assertEqual(self.state()['correlations'], [])

    def test_no_multidoor_correlation_across_badges(self):
        events = [{'id': i, 'ts': i, 'kind': 'swipe', 'result': 'DENIED',
                   'badge_id': 'SIM-' + str(i), 'door_id': str(i)} for i in range(1, 4)]
        self.assertEqual(correlations(events), [])

    def test_timestamps_use_numeric_order_and_ids_are_labeled(self):
        result = self.state()
        self.assertEqual(result['events'][0]['source'], 'Offline IDS')
        self.assertGreater(result['events'][0]['ts'], result['events'][1]['ts'])
        self.assertIsNone(epoch('not-a-time'))
        self.assertIsNone(epoch(float('nan')))

    def test_credentials_excluded_from_export(self):
        self.lab_post('/api/scenarios', {'name': 'denied_burst'})
        result = self.client.get('/api/access-soc/export')
        self.assertEqual(result.status_code, 200)
        self.assertIn('attachment;', result.headers['Content-Disposition'])
        text = result.get_data(as_text=True)
        self.assertNotIn(self.password, text)
        self.assertNotIn('password_hash', text)
        self.assertNotIn('csrf', text)
        self.assertTrue(result.get_json()['simulation'])

    def test_duplicate_registration_and_disabled_default(self):
        with patch.dict(os.environ, {'ENABLE_ACCESS_SOC': '1'}):
            register_access_soc(self.soc)
        other = Flask('disabled_soc')
        other.config['ACCESS_SOC_STATE_DIR'] = str(self.root / 'disabled-private')
        with patch.dict(os.environ, {'ENABLE_ACCESS_SOC': '0'}):
            register_access_soc(other)
        self.assertNotIn('unified_access_soc_v2', other.extensions)
        self.assertFalse((self.root / 'disabled-private').exists())
        self.assertIn('/access-monitor', self.client.get('/').get_data(as_text=True))

    def test_login_throttling_and_logout(self):
        wrong = self.soc.test_client()
        for _ in range(10):
            self.assertEqual(self.login(wrong, 'wrong').status_code, 401)
        self.assertEqual(self.login(wrong, 'wrong').status_code, 429)
        result = self.client.post('/access-soc/logout', json={}, headers={'X-CSRF-Token': self.csrf})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.get('/api/unified-events').status_code, 401)

    def test_password_reset_invalidates_existing_soc_cookie(self):
        create_app(self.root / 'data', {'TESTING': True}, reset_password=True)
        self.assertEqual(self.client.get('/api/unified-events').status_code, 401)

    def test_missing_database_is_not_created(self):
        Path(self.lab.config['DATABASE']).unlink()
        data = self.state()
        self.assertFalse(data['access_connected'])
        self.assertEqual(data['cases'], [])
        self.assertFalse(Path(self.lab.config['DATABASE']).exists())

    def test_real_sentinel_application_registration(self):
        source = os.environ.get('SOC_TEST_APP')
        if not source:
            self.skipTest('Set SOC_TEST_APP to test the project startup hook')
        with patch.dict(os.environ, {'ENABLE_ACCESS_SOC': '1', 'ACCESS_LAB_DB': self.lab.config['DATABASE']}):
            spec = importlib.util.spec_from_file_location('sentinel_compatibility_test', source)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        client = module.app.test_client()
        self.assertEqual(client.get('/').status_code, 200)
        self.assertIn('/access-monitor', client.get('/').get_data(as_text=True))
        self.assertEqual(client.get('/access-monitor').status_code, 200)
        self.assertEqual(client.get('/api/unified-events').status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)

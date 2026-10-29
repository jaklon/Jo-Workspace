"""GreyBox two-session checks against a real local test service with two genuine accounts."""
import asyncio
import base64
import hashlib
import hmac
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch

import test_security_jobs as base
from session_vault import SessionVault

SECRET = b'two-session-fixture-secret'


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def sign(subject, audience='staging', ttl=600):
    header = b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
    claims = b64(json.dumps({'sub': subject, 'aud': audience, 'exp': int(time.time()) + ttl}).encode())
    signature = b64(hmac.new(SECRET, f'{header}.{claims}'.encode(), hashlib.sha256).digest())
    return f'{header}.{claims}.{signature}'


class Service(BaseHTTPRequestHandler):
    """Order API: /api/orders/1001 checks only authentication (BOLA); /api/secure/... checks ownership."""
    seen = []

    def subject(self):
        token = self.headers.get('Authorization', '').removeprefix('Bearer ')
        try:
            header, claims, signature = token.split('.')
            expected = b64(hmac.new(SECRET, f'{header}.{claims}'.encode(), hashlib.sha256).digest())
            payload = json.loads(base64.urlsafe_b64decode(claims + '=' * (-len(claims) % 4)))
            if hmac.compare_digest(signature, expected) and payload['aud'] == 'staging' and payload['exp'] > time.time():
                return payload['sub']
        except (ValueError, KeyError):
            pass
        return None

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        user = self.subject()
        Service.seen.append(user)
        order = {'id': 1001, 'ownerId': 'alice', 'items': [{'sku': 'A-1', 'qty': 2}], 'total': 42}
        if user is None:
            return self.reply(401, {'error': 'unauthenticated'})
        if self.path == '/api/orders/1001':
            return self.reply(200, order)
        if self.path == '/api/secure/orders/1001':
            return self.reply(200, order) if user == order['ownerId'] else self.reply(403, {'error': 'forbidden'})
        self.reply(404, {'error': 'not found'})

    def log_message(self, *args):
        pass


class TwoSessionServiceTests(base.JobApiTests):
    def setUp(self):
        super().setUp()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Service)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        Service.seen = []
        content = base.content()
        content.update(environment='staging', in_scope=[{'kind': 'url', 'value': 'https://owned.example/api/'}],
                       out_of_scope=[], ports=[443], allowed_actions=['authenticated_api_review', 'unauthenticated_access_check'],
                       test_account_refs=['qa-alice', 'qa-bob'], max_http_rps=1, max_concurrency=1, max_duration_minutes=5)
        self.engagement = self.decide(self.decide(self.create_engagement(content), 'submit'), 'approve')
        self.url = self.base + '/' + self.engagement['id']

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def two_session_job(self, path):
        plan = base.plan(self.engagement, scan={'tool': 'auth-two-session', 'binary_sha256': '', 'account_refs': ['qa-alice', 'qa-bob'],
                                                'owner_json_pointer': '/ownerId'},
                         steps=[{**base.step(), 'target': {'kind': 'url', 'value': 'https://owned.example' + path},
                                 'action': 'authenticated_api_review', 'ports': [443], 'test_account_ref': 'qa-alice'}])
        return self.client.post(self.url + '/jobs', headers=self.headers, json=plan).json()

    def approve_with(self, row, tokens):
        response = self.client.post(self.url + '/jobs/' + row['id'] + '/approve', headers=self.headers,
                                    json={**self.approval(row), 'session_tokens': tokens})
        self.assertEqual(response.status_code, 200, response.text)

    def run_claimed(self, jid):
        # Policy allows only https://…:443, so the connection is redirected to the loopback service and
        # TLS is skipped; request building, response parsing and JSON comparison stay real.
        connect = asyncio.open_connection

        async def to_service(host, port, **kwargs):
            kwargs.pop('server_hostname', None)
            return await connect('127.0.0.1', self.port, **kwargs)
        # The 1 s pacing between the three requests stays real: patching asyncio.sleep would be global.
        with patch('web_checks.resolve', new=AsyncMock(return_value='127.0.0.1')), \
             patch('web_checks.ssl.create_default_context', return_value=None), \
             patch('web_checks.asyncio.open_connection', new=to_service):
            self.client.portal.call(self.client.app.state.scan_runner.execute, self.owner, jid)
        return self.detail({'id': jid})

    def test_real_accounts_reveal_bola_and_secure_endpoint_differs(self):
        tokens = [sign('alice'), sign('bob')]
        results = {}
        for path in ('/api/orders/1001', '/api/secure/orders/1001'):
            row = self.two_session_job(path)
            self.approve_with(row, tokens)
            self.assertEqual(self.store.claim(self.owner), row['id'])
            self.store.step(self.owner, row['id'])
            done = self.run_claimed(row['id'])
            self.assertEqual(done['status'], 'completed', done)
            results[path] = done['scan_result']
            stored = json.dumps(done) + self.client.get(self.url + '/evidence/' + done['scan_result']['evidence_id'], headers=self.headers).text
            for token in tokens:
                self.assertNotIn(token, stored)
            self.assertNotIn('"total"', stored)  # response bodies are compared in memory only
        self.assertEqual(Service.seen, [None, 'alice', 'bob'] * 2)
        bola = results['/api/orders/1001']
        self.assertEqual([o['status_code'] for o in bola['observations']], [401, 200, 200])
        self.assertTrue(bola['body_comparisons'][2]['json_body_equal'])  # bob receives alice's order
        self.assertEqual(bola['observations'][2]['owner_matches_test_subject'], [True, False])
        secure = results['/api/secure/orders/1001']
        self.assertEqual([o['status_code'] for o in secure['observations']], [401, 200, 403])
        self.assertFalse(secure['body_comparisons'][2]['json_body_equal'])
        self.assertIsNone(secure['observations'][2]['owner_matches_test_subject'])

    def test_session_job_runs_before_long_queue_and_expired_tokens_fail_fast(self):
        def unauth_job():
            plan = base.plan(self.engagement, scan={'tool': 'auth-unauthenticated-get', 'binary_sha256': ''},
                             steps=[{**base.step(), 'target': {'kind': 'url', 'value': 'https://owned.example/api/orders/1001'},
                                     'action': 'unauthenticated_access_check', 'ports': [443]}])
            row = self.client.post(self.url + '/jobs', headers=self.headers, json=plan).json()
            self.assertEqual(self.client.post(self.url + '/jobs/' + row['id'] + '/approve', headers=self.headers,
                                              json=self.approval(row)).status_code, 200)
            return row
        earlier = [unauth_job() for _ in range(5)]
        session = self.two_session_job('/api/orders/1001')
        self.approve_with(session, [sign('alice'), sign('bob')])
        self.assertEqual(self.store.claim(self.owner), session['id'])  # not the five older jobs
        self.store.step(self.owner, session['id'])
        self.assertEqual(self.run_claimed(session['id'])['status'], 'completed')

        now = [1000.0]
        self.store.sessions = SessionVault(ttl=120, clock=lambda: now[0])
        late = self.two_session_job('/api/orders/1001')
        self.approve_with(late, [sign('alice'), sign('bob')])
        now[0] += 121  # five queued jobs of up to 60 s each would outlive the 120 s session
        self.assertEqual(self.store.claim(self.owner), earlier[0]['id'])
        failed = self.detail(late)
        self.assertEqual((failed['status'], failed['error_code']), ('failed', 'SESSION_EXPIRED'))
        self.assertNotIn(late['id'], self.store.sessions.entries)

    def test_vault_expiry_uses_its_clock(self):
        now = [0.0]
        vault = SessionVault(ttl=120, clock=lambda: now[0])
        vault.put('job', ['a', 'b'])
        now[0] = 119.9
        self.assertTrue(vault.alive('job'))
        now[0] = 120
        self.assertFalse(vault.alive('job'))
        with self.assertRaisesRegex(ValueError, 'kedaluwarsa'):
            vault.take('job')


# Reuse the API fixtures without re-running the inherited job tests under this engagement.
for _name in [name for name in dir(base.JobApiTests) if name.startswith('test_')]:
    setattr(TwoSessionServiceTests, _name, None)


if __name__ == '__main__':
    unittest.main()

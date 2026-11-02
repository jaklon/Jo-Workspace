import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('AGENT_API_TOKEN', 'synthetic-readiness-test-token')
import config
import readiness
from fastapi.testclient import TestClient
import main


class ReadinessTests(unittest.TestCase):
    def test_private_url_only_for_matching_backend_and_no_funnel(self):
        host = 'test.tail123.ts.net'
        status = json.dumps({'BackendState': 'Running', 'Self': {'Online': True, 'DNSName': host + '.'}})
        def serve(port=8010, funnel=None):
            return json.dumps({'TCP': {'443': {'HTTPS': True}}, 'Web': {host + ':443': {
                'Handlers': {'/': {'Proxy': f'http://127.0.0.1:{port}'}}}}, 'AllowFunnel': funnel or {}})
        with tempfile.TemporaryDirectory() as root, patch.object(config, 'DATA_DIR', Path(root)):
            with patch.object(readiness, 'command', side_effect=[None, status, serve()]):
                self.assertEqual(readiness.local_checks(8010)[2]['url'], 'https://' + host)
            with patch.object(readiness, 'command', side_effect=[None, status, serve(18010)]):
                self.assertNotIn('url', readiness.local_checks(8010)[2])
            with patch.object(readiness, 'command', side_effect=[None, status, serve(funnel={host + ':443': True})]):
                self.assertNotIn('url', readiness.local_checks(8010)[2])

    def test_endpoint_requires_auth_and_unavailable_services_are_isolated(self):
        with tempfile.TemporaryDirectory() as root, patch.object(main, 'DATA_DIR', Path(root)):
            with TestClient(main.app) as client:
                self.assertEqual(client.get('/api/readiness').status_code, 401)
                headers = {'Authorization': 'Bearer ' + os.environ['AGENT_API_TOKEN']}
                with patch.object(readiness, 'local_checks', return_value=(
                    readiness.check('ready', 'ok'), readiness.check('limited', 'docker unavailable'),
                    readiness.check('limited', 'tailscale unavailable'))), \
                    patch.object(config, 'OLLAMA_URL', 'http://127.0.0.1:1'), \
                    patch.object(readiness, 'searx_url', return_value='http://127.0.0.1:1'):
                    response = client.get('/api/readiness', headers=headers)
                self.assertEqual(response.status_code, 200)
                checks = response.json()['checks']
                self.assertEqual(checks['backend']['status'], 'ready')
                self.assertEqual(checks['ollama']['status'], 'action')
                self.assertEqual(checks['search']['status'], 'limited')
                self.assertEqual(checks['docker']['status'], 'limited')
                self.assertNotIn(os.environ['AGENT_API_TOKEN'], response.text)
                self.assertNotIn(root, response.text)

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('AGENT_API_TOKEN', 'synthetic-workspace-sync-test-token')
from fastapi.testclient import TestClient
import main


class WorkspaceSyncApiTests(unittest.TestCase):
    def test_auth_two_clients_and_conflict(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(main, 'DATA_DIR', Path(temp)):
            with TestClient(main.app) as client:
                headers = {'Authorization': 'Bearer ' + os.environ['AGENT_API_TOKEN']}
                self.assertEqual(client.get('/api/workspace-sync/changes').status_code, 401)
                data = {'id': 'project-id', 'name': 'Synthetic', 'instructions': '', 'createdAt': 1}
                operation = {'kind': 'project', 'id': 'project-id', 'expected': 0, 'data': data}
                result = client.post('/api/workspace-sync/changes', headers=headers,
                                     json={'request_id': 'initial', 'changes': [operation]})
                self.assertEqual(result.status_code, 200, result.text)
                version = result.json()['items'][0]['version']
                other_client = client.get('/api/workspace-sync/changes?after=0', headers=headers).json()
                self.assertEqual(other_client['items'][0]['data'], data)
                operation['expected'] = version
                operation['data'] = {**data, 'name': 'Device A'}
                self.assertEqual(client.post('/api/workspace-sync/changes', headers=headers,
                    json={'request_id': 'device-a', 'changes': [operation]}).status_code, 200)
                operation['data'] = {**data, 'name': 'Device B'}
                conflict = client.post('/api/workspace-sync/changes', headers=headers,
                    json={'request_id': 'device-b', 'changes': [operation]})
                self.assertEqual(conflict.status_code, 409)
                self.assertEqual(conflict.json()['detail']['conflicts'][0]['data']['name'], 'Device A')


if __name__ == '__main__':
    unittest.main()

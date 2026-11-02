import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import HTTPException
from engagements import EngagementStore
from store import Store
from workspace_sync import Batch, WorkspaceSync


def batch(request, *changes):
    return Batch.model_validate({'request_id': request, 'changes': list(changes)})


def project(version=0, name='Project'):
    return {'kind': 'project', 'id': 'p1', 'expected': version,
            'data': {'id': 'p1', 'name': name, 'instructions': '', 'createdAt': 1}}


def session(version=0, text='Hello'):
    return {'kind': 'session', 'id': 's1', 'expected': version,
            'data': {'id': 's1', 'tab': 'chat', 'title': 'Chat', 'projectId': 'p1',
                     'messages': [{'role': 'user', 'content': text}], 'attachments': []}}


class WorkspaceSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.engagements = EngagementStore(self.root)
        self.sync = WorkspaceSync(Store(self.root), self.engagements)

    def tearDown(self):
        self.temp.cleanup()

    def test_migration_is_idempotent_and_change_feed_is_paginated(self):
        request = batch('first', project(), session())
        result = self.sync.apply(request)
        self.assertEqual(self.sync.apply(request), result)
        first = self.sync.changes(0, 1)
        self.assertEqual(len(first['items']), 1)
        self.assertTrue(first['has_more'])
        second = self.sync.changes(first['cursor'], 1)
        self.assertEqual(second['items'][0]['id'], 's1')
        self.assertEqual(second['items'][0]['data']['messages'][0]['content'], 'Hello')
        with self.assertRaises(HTTPException):
            self.sync.apply(batch('first', project(name='Changed')))

    def test_project_memory_syncs_and_rejects_malformed_facts(self):
        fact = {'id': 'f1', 'kind': 'decision', 'text': 'Pakai PostgreSQL', 'source': {'kind': 'manual'},
                'createdAt': 1, 'updatedAt': 1}
        change = project()
        change['data']['memory'] = [fact]
        self.sync.apply(batch('memory', change))
        self.assertEqual(self.sync.changes(0)['items'][0]['data']['memory'][0]['text'], 'Pakai PostgreSQL')
        for bad in ({**fact, 'kind': 'secret'}, {**fact, 'text': 'x' * 301}, {**fact, 'source': 'chat'}):
            change['data']['memory'] = [bad]
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                batch('bad', change)
        change['data']['memory'] = [fact] * 51
        with self.assertRaises(ValueError):
            batch('too-many', change)

    def test_conflict_is_atomic_and_preserves_remote_and_local(self):
        result = self.sync.apply(batch('initial', project(), session()))
        p, s = (item['version'] for item in result['items'])
        self.sync.apply(batch('device-a', session(s, 'from A')))
        with self.assertRaises(HTTPException) as caught:
            self.sync.apply(batch('device-b', project(p, 'Changed'), session(s, 'from B')))
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(caught.exception.detail['conflicts'][0]['data']['messages'][0]['content'], 'from A')
        self.assertEqual(len(self.sync.changes(0)['items']), 2)

    def test_tombstone_blocks_stale_resurrection_and_orphan_projects(self):
        result = self.sync.apply(batch('initial', project(), session()))
        p, s = (item['version'] for item in result['items'])
        with self.assertRaises(HTTPException):
            self.sync.apply(batch('delete-project', {'kind': 'project', 'id': 'p1', 'expected': p, 'deleted': True}))
        self.sync.apply(batch('delete', {'kind': 'session', 'id': 's1', 'expected': s, 'deleted': True},
                              {'kind': 'project', 'id': 'p1', 'expected': p, 'deleted': True}))
        with self.assertRaises(HTTPException):
            self.sync.apply(batch('stale', session(s)))
        self.assertTrue(self.sync.changes(0)['items'][-1]['deleted'])
        with closing(self.sync.store.connect()) as db:
            self.assertIsNone(db.execute("SELECT payload FROM workspace_records WHERE kind='session' AND id='s1'").fetchone()[0])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM workspace_changes WHERE payload IS NOT NULL').fetchone()[0], 0)
            self.assertTrue(all('Hello' not in row[0] for row in db.execute('SELECT body FROM workspace_requests')))

    def test_project_with_security_history_cannot_be_deleted(self):
        version = self.sync.apply(batch('initial', project()))['items'][0]['version']
        with self.engagements.transaction() as db:
            db.execute("INSERT INTO engagements VALUES ('e1','p1','2026','2026',1)")
        with self.assertRaises(HTTPException):
            self.sync.apply(batch('delete', {'kind': 'project', 'id': 'p1', 'expected': version, 'deleted': True}))

    def test_explicit_reviewed_restore_requires_current_tombstone(self):
        version = self.sync.apply(batch('initial', project()))['items'][0]['version']
        tombstone = self.sync.apply(batch('delete', {'kind': 'project', 'id': 'p1', 'expected': version, 'deleted': True}))['items'][0]['version']
        with self.assertRaises(HTTPException):
            self.sync.apply(batch('unreviewed', project(tombstone)))
        recovered = {**project(tombstone), 'restore': True}
        self.assertFalse(self.sync.apply(batch('reviewed', recovered))['items'][0]['deleted'])

    def test_simultaneous_updates_only_one_can_commit(self):
        version = self.sync.apply(batch('initial', project()))['items'][0]['version']
        def submit(value):
            try:
                return self.sync.apply(batch('write-' + value, project(version, value)))
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, ['first', 'second']))
        self.assertEqual(sum(isinstance(item, dict) for item in results), 1)
        self.assertEqual(results.count(409), 1)


if __name__ == '__main__':
    unittest.main()

import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from backup_archive import FORMAT, VERSION, create_archive, deactivate_restored_actions, prepare_restore, stage_archive


class RecoveryArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / 'backup.zip'
        self.staging = self.root / 'staging'

    def tearDown(self):
        self.temp.cleanup()

    def make_archive(self, files, *, override=None, extra=None):
        manifest = {'format': FORMAT, 'version': VERSION, 'files': [
            {'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            for name, data in files.items()]}
        if override:
            override(manifest)
        with zipfile.ZipFile(self.archive, 'w') as bundle:
            bundle.writestr('manifest.json', json.dumps(manifest))
            for name, data in files.items():
                bundle.writestr(name, data)
            if extra:
                bundle.writestr(*extra)

    def test_valid_staging_including_sqlite(self):
        dbpath = self.root / 'original.sqlite3'
        with closing(sqlite3.connect(dbpath)) as db, db:
            db.execute('CREATE TABLE records (id TEXT)')
            db.execute('INSERT INTO records VALUES (?)', ('saved',))
        self.make_archive({'runtime/agent.sqlite3': dbpath.read_bytes(), 'browser/chat.json': b'{}'})
        stage, manifest = stage_archive(self.archive, self.staging)
        self.assertEqual(len(manifest['files']), 2)
        with closing(sqlite3.connect(stage / 'runtime/agent.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT id FROM records').fetchone(), ('saved',))
        self.assertEqual((stage / 'browser/chat.json').read_bytes(), b'{}')

    def test_create_roundtrip_uses_sqlite_snapshot_and_excludes_tokens(self):
        from engagements import EngagementStore
        runtime, workspace = self.root / 'runtime', self.root / 'workspace'
        runtime.mkdir()
        workspace.mkdir()
        dbpath = runtime / 'agent.sqlite3'
        with closing(sqlite3.connect(dbpath)) as db, db:
            db.execute('CREATE TABLE attachments (id TEXT, session TEXT)')
            db.execute('INSERT INTO attachments VALUES (?,?)', ('attachment-id', 'session-id'))
        EngagementStore(runtime)
        (runtime / 'api-token').write_text('secret')
        (workspace / '.env.production').write_text('secret')
        (workspace / 'note.txt').write_text('hello')
        state = {'format': 'jo-browser-recovery', 'version': 1, 'activeSessions': {}, 'preferences': {}, 'projects': [{'id': 'project-id', 'name': 'Project', 'instructions': ''}],
                 'sessions': {tab: [] for tab in ('chat', 'code', 'vision', 'docs', 'pentest')}}
        state['sessions']['chat'].append({'id': 'session-id', 'title': 'Chat', 'messages': [], 'attachments': [], 'projectId': 'project-id'})
        manifest = create_archive(self.archive, runtime, workspace, state)
        self.assertIn('runtime/api-token', manifest['excluded'])
        self.assertIn('workspace/.env.production', manifest['excluded'])
        stage, _ = stage_archive(self.archive, self.staging)
        self.assertEqual(json.loads((stage / 'browser/state.json').read_text(encoding='utf-8')), state)
        with closing(sqlite3.connect(stage / 'runtime/agent.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT id FROM attachments').fetchone(), ('attachment-id',))
        self.assertEqual((stage / 'workspace/note.txt').read_text(), 'hello')
        self.assertFalse((stage / 'runtime/api-token').exists())
        with self.assertRaises(FileExistsError):
            create_archive(self.archive, runtime, workspace, state)

    def test_tampering_and_undeclared_entries_leave_no_stage(self):
        self.make_archive({'browser/chat.json': b'{}'}, override=lambda m: m['files'][0].update(sha256='0'*64))
        with self.assertRaises(ValueError):
            stage_archive(self.archive, self.staging)
        self.assertEqual(list(self.staging.iterdir()), [])
        self.make_archive({'browser/chat.json': b'{}'}, extra=('workspace/extra', b'bad'))
        with self.assertRaises(ValueError):
            stage_archive(self.archive, self.staging)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_unsafe_paths_and_corrupt_database_rejected(self):
        for name in ('workspace/../escape', 'runtime/api-token', 'workspace/.env', 'browser/X:evil',
                     'workspace/\\escape', 'workspace/CON.txt', 'workspace/name.', 'workspace/bad?name'):
            with self.subTest(name=name):
                self.make_archive({name: b'bad'})
                with self.assertRaises(ValueError):
                    stage_archive(self.archive, self.staging)
                self.assertEqual(list(self.staging.iterdir()), [])
        self.make_archive({'runtime/agent.sqlite3': b'not a database'})
        with self.assertRaises(sqlite3.DatabaseError):
            stage_archive(self.archive, self.staging)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_staged_restore_revokes_approval_and_cancels_actions(self):
        from store import Store
        from engagements import EngagementStore
        from security_jobs import JobStore
        from security_evidence import EvidenceStore
        from mcp_gateway import MCPGateway
        from security_orchestration import OrchestrationStore
        from security_agents import SpecialistStore
        from workspace_sync import WorkspaceSync
        runtime = self.root / 'staged' / 'runtime'
        runtime.mkdir(parents=True)
        agent = Store(runtime)
        with closing(agent.connect()) as db, db:
            db.execute("INSERT INTO chat_actions VALUES ('action','session','{}','approved',1)")
            db.execute("INSERT INTO proposals VALUES ('proposal','session','{}','pending',1)")
        eng = EngagementStore(runtime)
        jobs = JobStore(eng)
        evidence = EvidenceStore(eng, jobs)
        gateway = MCPGateway(eng, jobs, evidence, runtime)
        OrchestrationStore(eng, jobs, gateway, evidence)
        SpecialistStore(eng, jobs, evidence)
        original_identity = WorkspaceSync(agent, eng).changes(0)['workspace_id']
        with eng.transaction() as db:
            db.execute("INSERT INTO engagements VALUES ('e','p','2026','2026',1)")
            db.execute("INSERT INTO roe_versions(engagement_id,version,status,content,content_hash) VALUES ('e',1,'approved','{}','hash')")
            db.execute("INSERT INTO security_jobs(id,engagement_id,project_id,plan,plan_hash,status,revision,created_at,updated_at) VALUES ('j','e','p','{}','hash','queued',1,'2026','2026')")
        workspace = self.root / 'files'
        workspace.mkdir()
        (workspace / 'note.txt').write_text('sample')
        state = {'format': 'jo-browser-recovery', 'version': 1, 'activeSessions': {}, 'preferences': {}, 'projects': [{'id': 'p', 'name': 'Project', 'instructions': ''}],
                 'sessions': {tab: [] for tab in ('chat', 'code', 'vision', 'docs', 'pentest')}}
        state['sessions']['chat'].append({'id': 'session', 'title': 'Chat', 'projectId': 'p', 'messages': [], 'attachments': []})
        browser = self.root / 'browser.json'
        browser.write_text(json.dumps(state), encoding='utf-8')
        cli = Path(__file__).resolve().parents[2] / 'scripts' / 'workspace_backup.py'
        def run_cli(*args):
            result = subprocess.run([sys.executable, str(cli), *map(str, args)], capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        run_cli('create', '--browser', browser, '--runtime', runtime, '--workspace', workspace, '--output', self.archive)
        self.assertGreater(run_cli('preview', self.archive)['files'], 0)
        result = run_cli('restore', self.archive, '--destination', self.root / 'restored')
        recovered = Path(result['destination'])
        self.assertEqual(result['missing_attachments'], 0)
        self.assertEqual(json.loads((recovered / 'browser/state.json').read_text(encoding='utf-8')), state)
        self.assertEqual((recovered / 'workspace/note.txt').read_text(), 'sample')
        agent = Store(recovered / 'runtime')
        eng = EngagementStore(recovered / 'runtime')
        with closing(agent.connect()) as db:
            self.assertEqual(db.execute('SELECT state FROM chat_actions').fetchone()[0], 'cancelled')
            self.assertEqual(db.execute('SELECT state FROM proposals').fetchone()[0], 'rejected')
            restored_identity = db.execute('SELECT id FROM workspace_identity').fetchone()[0]
            self.assertNotEqual(restored_identity, original_identity)
        with closing(eng.connect()) as db:
            self.assertEqual(db.execute('SELECT status FROM roe_versions').fetchone()[0], 'revoked')
            self.assertEqual(db.execute('SELECT status FROM security_jobs').fetchone()[0], 'cancelled')
            self.assertEqual(db.execute('SELECT action FROM engagement_events').fetchone()[0], 'revoke')
        with self.assertRaises(FileExistsError):
            prepare_restore(self.archive, self.root / 'restored')

    def test_portable_evidence_full_archive_restore(self):
        from store import Store
        from engagements import EngagementStore
        from security_jobs import JobStore
        from security_evidence import EvidenceStore
        runtime, workspace = self.root / 'runtime', self.root / 'workspace'
        runtime.mkdir()
        workspace.mkdir()
        Store(runtime)
        eng = EngagementStore(runtime)
        EvidenceStore(eng, JobStore(eng))
        secret = 'synthetic portable evidence'
        digest = hashlib.sha256(secret.encode()).hexdigest()
        with eng.transaction() as db:
            db.execute("INSERT INTO engagements VALUES ('e','p','2026','2026',1)")
            db.execute("INSERT INTO security_jobs(id,engagement_id,project_id,plan,plan_hash,status,revision,created_at,updated_at) VALUES ('j','e','p','{}','hash','completed',1,'2026','2026')")
            db.execute("INSERT INTO security_evidence VALUES ('evidence','p','e','j',1,'offline_policy',?,'{}','hash')", (digest,))
            db.execute("INSERT INTO security_evidence_originals VALUES ('evidence',?)", (b'old-account',))
        state = {'format': 'jo-browser-recovery', 'version': 1, 'activeSessions': {}, 'preferences': {},
                 'projects': [{'id': 'p', 'name': 'Project', 'instructions': ''}],
                 'sessions': {tab: [] for tab in ('chat', 'code', 'vision', 'docs', 'pentest')}}
        with patch('evidence_archive.available', return_value=True), patch('evidence_archive.unprotect', return_value=secret):
            manifest = create_archive(self.archive, runtime, workspace, state, 'long safe passphrase')
        self.assertTrue(manifest['portable_evidence'])
        with zipfile.ZipFile(self.archive) as bundle:
            self.assertNotIn(secret.encode(), bundle.read('runtime/portable-evidence.json'))
        with patch('evidence_archive.available', return_value=True), patch('evidence_archive.protect', return_value=b'new-account'):
            with self.assertRaises(ValueError):
                prepare_restore(self.archive, self.root / 'failed', 'wrong passphrase')
            self.assertFalse((self.root / 'failed').exists())
            result = prepare_restore(self.archive, self.root / 'success', 'long safe passphrase')
        recovered = Path(result['destination'])
        self.assertFalse((recovered / 'runtime/portable-evidence.json').exists())
        with closing(sqlite3.connect(recovered / 'runtime/engagements.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT cipher FROM security_evidence_originals').fetchone()[0], b'new-account')

    @unittest.skipUnless(sys.platform == 'win32', 'DPAPI requires Windows')
    def test_portable_archive_with_real_current_user_dpapi(self):
        import evidence_archive
        from store import Store
        from engagements import EngagementStore
        from security_jobs import JobStore
        from security_evidence import EvidenceStore
        if not evidence_archive.available():
            self.skipTest('Windows DPAPI unavailable')
        runtime, workspace = self.root / 'real-runtime', self.root / 'real-workspace'
        runtime.mkdir()
        workspace.mkdir()
        Store(runtime)
        eng = EngagementStore(runtime)
        EvidenceStore(eng, JobStore(eng))
        raw = 'DPAPI synthetic evidence round trip'
        digest = hashlib.sha256(raw.encode()).hexdigest()
        cipher = evidence_archive.protect(raw, 'real-evidence', digest)
        with eng.transaction() as db:
            db.execute("INSERT INTO engagements VALUES ('e','p','2026','2026',1)")
            db.execute("INSERT INTO security_jobs(id,engagement_id,project_id,plan,plan_hash,status,revision,created_at,updated_at) VALUES ('j','e','p','{}','hash','completed',1,'2026','2026')")
            db.execute("INSERT INTO security_evidence VALUES ('real-evidence','p','e','j',1,'offline_policy',?,'{}','hash')", (digest,))
            db.execute("INSERT INTO security_evidence_originals VALUES ('real-evidence',?)", (cipher,))
        state = {'format': 'jo-browser-recovery', 'version': 1, 'activeSessions': {}, 'preferences': {},
                 'projects': [{'id': 'p', 'name': 'Project', 'instructions': ''}],
                 'sessions': {tab: [] for tab in ('chat', 'code', 'vision', 'docs', 'pentest')}}
        create_archive(self.archive, runtime, workspace, state, 'synthetic safe passphrase')
        with self.assertRaises(ValueError):
            prepare_restore(self.archive, self.root / 'wrong', 'wrong passphrase')
        recovered = Path(prepare_restore(self.archive, self.root / 'success', 'synthetic safe passphrase')['destination'])
        self.assertTrue((recovered / 'workspace').is_dir())
        with closing(sqlite3.connect(recovered / 'runtime/engagements.sqlite3')) as db:
            restored = db.execute('SELECT cipher FROM security_evidence_originals').fetchone()[0]
        self.assertEqual(evidence_archive.unprotect(restored, 'real-evidence', digest), raw)


if __name__ == '__main__':
    unittest.main()

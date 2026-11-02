import json
import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from backup_schedule import register_schedule, require_idle, run_schedule, save_schedule
from runtime_lock import runtime_lock
from engagements import EngagementStore
from store import Store


@unittest.skipUnless(sys.platform == 'win32', 'DPAPI requires Windows')
class ScheduledBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runtime, self.workspace = self.root / 'runtime', self.root / 'workspace'
        self.runtime.mkdir()
        self.workspace.mkdir()
        Store(self.runtime)
        EngagementStore(self.runtime)
        self.browser_store = self.root / 'browser-store'
        self.browser_store.mkdir()
        self.browser = self.root / 'snapshot.json'
        self.browser.write_text(json.dumps({'format': 'jo-browser-recovery', 'version': 1,
            'activeSessions': {}, 'preferences': {}, 'projects': [],
            'sessions': {tab: [] for tab in ('chat', 'code', 'vision', 'docs', 'pentest')}}))
        self.destination = self.root / 'backups'
        self.config = self.root / 'schedule.json'
        save_schedule(self.config, runtime=self.runtime, workspace=self.workspace, browser=self.browser,
                      browser_stores=[self.browser_store], destination=self.destination, retention=1, passphrase='synthetic passphrase')

    def tearDown(self):
        self.temp.cleanup()

    def test_runs_and_retains_only_own_archives(self):
        with patch('backup_schedule.require_idle'):
            first = Path(run_schedule(self.config)['path'])
            other = self.destination / 'personal.zip'
            other.write_bytes(b'keep')
            second = Path(run_schedule(self.config)['path'])
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual(other.read_bytes(), b'keep')
        self.assertNotIn('synthetic passphrase', self.config.read_text())

    def test_skips_stale_snapshot_or_running_backend(self):
        now = time.time()
        os.utime(self.browser, (now - 90000, now - 90000))
        with patch('backup_schedule.require_idle'):
            with self.assertRaisesRegex(ValueError, '24 jam'):
                run_schedule(self.config)
        with patch('backup_schedule.require_idle', side_effect=ValueError('backend aktif')):
            with self.assertRaisesRegex(ValueError, 'backend aktif'):
                run_schedule(self.config)
        self.assertFalse(self.destination.exists())

    def test_runtime_lock_prevents_backup_while_active(self):
        with runtime_lock(self.runtime), patch('backup_schedule.require_idle'):
            with self.assertRaisesRegex(RuntimeError, 'sedang digunakan'):
                run_schedule(self.config)
        self.assertFalse(self.destination.exists())

    def test_browser_storage_change_after_export_skips_backup(self):
        browser_file = self.browser_store / 'indexeddb-change'
        browser_file.write_text('newer state')
        timestamp = self.browser.stat().st_mtime_ns + 2_000_000_000
        os.utime(browser_file, ns=(timestamp, timestamp))
        with patch('backup_schedule.require_idle'):
            with self.assertRaisesRegex(ValueError, 'lebih baru'):
                run_schedule(self.config)
        self.assertFalse(self.destination.exists())

    def test_idle_probe_rejects_live_loopback_backend(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with self.assertRaisesRegex(ValueError, 'masih aktif'):
                require_idle((port,))

    def test_idle_probe_timeout_fails_closed_and_reports_port(self):
        with patch('backup_schedule.socket.create_connection', side_effect=TimeoutError) as connect:
            with self.assertRaisesRegex(TimeoutError, '8010'):
                require_idle((8010,))
        connect.assert_called_once_with(('127.0.0.1', 8010), timeout=5)

    def test_registration_uses_non_overwriting_user_task(self):
        executable = self.root / 'python.exe'
        executable.write_text('')
        executable.with_name('pythonw.exe').write_text('')
        script = self.root / 'workspace_backup.py'
        script.write_text('')
        with patch('backup_schedule.sys.executable', str(executable)), patch('backup_schedule.subprocess.run') as launch:
            result = register_schedule(self.config, script)
        args = launch.call_args.args[0]
        self.assertEqual(args[0:2], ['schtasks.exe', '/Create'])
        self.assertIn('/IT', args)
        self.assertNotIn('/F', args)
        self.assertIn('schedule-run', args[args.index('/TR') + 1])
        self.assertIn(result['task_name'], args)


if __name__ == '__main__':
    unittest.main()

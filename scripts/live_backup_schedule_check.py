"""Real Task Scheduler smoke test using synthetic data and a temporary task."""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from backup_schedule import register_schedule, save_schedule  # noqa: E402
from engagements import EngagementStore  # noqa: E402
from store import Store  # noqa: E402


def main():
    with tempfile.TemporaryDirectory(prefix='jo-schedule-live-') as temp:
        root = Path(temp)
        runtime, workspace, browser_store = (root / 'runtime', root / 'workspace', root / 'browser-store')
        for directory in (runtime, workspace, browser_store):
            directory.mkdir()
        Store(runtime)
        EngagementStore(runtime)
        browser = root / 'snapshot.json'
        browser.write_text(json.dumps({'format': 'jo-browser-recovery', 'version': 1,
            'activeSessions': {}, 'preferences': {}, 'projects': [],
            'sessions': {tab: [] for tab in ('chat', 'code', 'vision', 'docs', 'pentest')}}), encoding='utf-8')
        config = root / 'schedule.json'
        save_schedule(config, runtime=runtime, workspace=workspace, browser=browser,
                      browser_stores=[browser_store], destination=root / 'backups', retention=2,
                      passphrase='synthetic schedule passphrase')
        task = None
        try:
            task = register_schedule(config, ROOT / 'scripts/workspace_backup.py')['task_name']
            subprocess.run(['schtasks.exe', '/Run', '/TN', task], check=True, capture_output=True, text=True)
            status_file = Path(str(config) + '.status.json')
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and not status_file.is_file():
                time.sleep(.5)
            if not status_file.is_file():
                raise RuntimeError('Tugas tidak menghasilkan status dalam 45 detik.')
            status = json.loads(status_file.read_text(encoding='utf-8'))
            if not status.get('ok') or not Path(status.get('path', '')).is_file():
                raise RuntimeError('Tugas tidak membuat backup: ' + json.dumps(status, ensure_ascii=False))
            print(json.dumps({'result': 'pass', 'task': task, 'files': status.get('files')}, ensure_ascii=False))
        finally:
            if task:
                subprocess.run(['schtasks.exe', '/End', '/TN', task], capture_output=True)
                deleted = subprocess.run(['schtasks.exe', '/Delete', '/TN', task, '/F'], capture_output=True, text=True)
                if deleted.returncode:
                    print('Gagal menghapus tugas uji: ' + task, file=sys.stderr)
                    raise RuntimeError('Tugas uji tidak berhasil dihapus.')


if __name__ == '__main__':
    main()

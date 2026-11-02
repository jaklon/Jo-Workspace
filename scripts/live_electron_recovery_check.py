"""Exercise a packaged Electron app against an isolated synthetic recovery."""
import argparse
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import closing

import psutil
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from backup_archive import create_archive, prepare_restore  # noqa: E402
from engagements import EngagementStore  # noqa: E402
from security_evidence import EvidenceStore  # noqa: E402
from security_jobs import JobStore  # noqa: E402
from store import Store  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable', type=Path)
    executable = parser.parse_args().executable.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='jo-electron-recovery-') as temporary:
        root = Path(temporary)
        runtime, workspace = root / 'source-runtime', root / 'source-workspace'
        runtime.mkdir()
        workspace.mkdir()
        agent = Store(runtime)
        engagements = EngagementStore(runtime)
        EvidenceStore(engagements, JobStore(engagements))
        project_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
        attachment = agent.add_attachment(session_id, 'synthetic.txt', 'document', 'SYNTHETIC ATTACHMENT 902')
        sessions = {tab: [] for tab in ('chat', 'code', 'vision', 'docs', 'pentest')}
        sessions['chat'].append({'id': session_id, 'title': 'Recovery test chat', 'projectId': project_id,
            'createdAt': 1, 'updatedAt': 1, 'messages': [{'role': 'user', 'content': 'SYNTHETIC RECOVERY 731'}],
            'attachments': [attachment]})
        state = {'format': 'jo-browser-recovery', 'version': 1, 'projects': [
            {'id': project_id, 'name': 'Recovery Test Project', 'instructions': '', 'createdAt': 1}],
            'sessions': sessions, 'activeSessions': {'chat': session_id}, 'preferences': {}}
        archive = root / 'backup.zip'
        create_archive(archive, runtime, workspace, state)
        recovered = Path(prepare_restore(archive, root / 'restore')['destination'])
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            devtools_port = probe.getsockname()[1]
        env = {**os.environ, 'JO_WORKSPACE_DATA_DIR': str(recovered), 'JO_TEST_HIDDEN': '1'}
        with (root / 'electron.log').open('w+', encoding='utf-8') as log:
            process = subprocess.Popen([str(executable), '--disable-gpu',
                f'--remote-debugging-port={devtools_port}', '--remote-debugging-address=127.0.0.1'],
                env=env, cwd=executable.parent, stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                with sync_playwright() as playwright:
                    deadline = time.monotonic() + 90
                    browser = None
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError('Electron berhenti sebelum siap.')
                        try:
                            browser = playwright.chromium.connect_over_cdp(f'http://127.0.0.1:{devtools_port}', timeout=2000)
                            break
                        except Exception:
                            time.sleep(.5)
                    if browser is None:
                        raise RuntimeError('CDP Electron belum tersedia.')
                    try:
                        page = browser.contexts[0].pages[0]
                        page.wait_for_url('http://127.0.0.1:18010/', timeout=90000)
                        page.get_by_role('button', name='Buka Settings').click(timeout=30000)
                        page.get_by_role('button', name='Kontrol data').click()
                        page.get_by_role('dialog', name='Settings').locator('input[type=file]').set_input_files(str(recovered / 'browser/state.json'))
                        page.get_by_text('Berkas berhasil diimpor.', exact=False).wait_for(timeout=30000)
                        page.get_by_role('button', name='Tutup dialog').click()
                        page.get_by_text('SYNTHETIC RECOVERY 731', exact=False).wait_for(timeout=30000)
                        page.get_by_text('Recovery Test Project', exact=False).first.wait_for(timeout=30000)
                        page.wait_for_timeout(1000)
                        persisted = page.evaluate("""() => new Promise((resolve, reject) => {
                          const open = indexedDB.open('agent-os', 1);
                          open.onerror = () => reject(open.error);
                          open.onsuccess = () => {
                            const db = open.result;
                            const get = db.transaction('sessions').objectStore('sessions').get('current');
                            get.onerror = () => reject(get.error);
                            get.onsuccess = () => { const data = get.result; db.close(); resolve(data); };
                          };
                        })""")
                        restored = next(s for s in persisted['sessions']['chat'] if s['id'] == session_id)
                        assert restored['projectId'] == project_id
                        assert restored['attachments'][0]['id'] == attachment['id']
                        with closing(sqlite3.connect(recovered / 'runtime/agent.sqlite3')) as db:
                            assert db.execute('SELECT content FROM attachments WHERE id=? AND session=?',
                                              (attachment['id'], session_id)).fetchone()[0] == 'SYNTHETIC ATTACHMENT 902'
                        assert (recovered / 'runtime/api-token').is_file()
                        print(json.dumps({'result': 'pass', 'profile': 'isolated', 'chat': 'restored',
                                          'project': 'restored', 'attachment': 'linked', 'backend': 'running'}))
                    finally:
                        browser.close()
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read()[-5000:], file=sys.stderr)
                raise
            finally:
                try:
                    root_process = psutil.Process(process.pid)
                    children = root_process.children(recursive=True)
                except psutil.NoSuchProcess:
                    children = []
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                _, alive = psutil.wait_procs(children, timeout=10)
                for child in alive:
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
                psutil.wait_procs(alive, timeout=5)


if __name__ == '__main__':
    main()

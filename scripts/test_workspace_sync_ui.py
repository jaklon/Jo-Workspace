"""Two isolated browser profiles exercise local sync, offline queue and conflicts."""
import asyncio
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
temporary = tempfile.TemporaryDirectory(prefix='jo-sync-ui-')
os.environ['AGENT_DATA_DIR'] = temporary.name
os.environ['AGENT_WORKSPACE'] = str(Path(temporary.name) / 'workspace')
os.environ['AGENT_API_TOKEN'] = 'synthetic-sync-ui-token-1234567890'
import uvicorn  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402
from main import app  # noqa: E402


def main():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning'))

    async def chunks(*args, **kwargs):
        yield {'message': {'content': 'Jawaban sintetis'}}
        yield {'done': True}

    with patch('main.classify', new=AsyncMock(return_value='chat')), patch('main.runtime.chunks', new=chunks):
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 20
            while not server.started and time.monotonic() < deadline:
                time.sleep(.1)
            if not server.started:
                raise RuntimeError('QA server did not start')
            with sync_playwright() as playwright:
                chrome = Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe')
                browser = playwright.chromium.launch(executable_path=str(chrome) if chrome.is_file() else None, headless=True)
                a, b = browser.new_context(), browser.new_context(viewport={'width': 390, 'height': 844})
                pa, pb = a.new_page(), b.new_page()
                for page in (pa, pb):
                    page.goto(f'http://127.0.0.1:{port}')
                    page.get_by_label('Token akses').fill(os.environ['AGENT_API_TOKEN'])
                    page.get_by_role('button', name='Hubungkan', exact=True).click()
                    page.get_by_text('Sinkron dengan backend', exact=True).wait_for(timeout=30000)
                other_tab = a.new_page()
                other_tab.goto(f'http://127.0.0.1:{port}')
                other_tab.get_by_text('Workspace sedang dibuka di tab lain', exact=False).wait_for(timeout=15000)
                other_tab.close()
                pa.get_by_role('button', name='Buat project', exact=True).click()
                dialog = pa.get_by_role('dialog', name='Project baru')
                dialog.get_by_label('Nama project').fill('Sync Project')
                dialog.get_by_role('button', name='Buat project', exact=True).click()
                pa.get_by_role('button', name='Sync Project', exact=True).wait_for(timeout=10000)
                # Mobile navigation may be collapsed; expand before inspecting sidebar.
                if pb.get_by_role('button', name='Buka sidebar').count():
                    pb.get_by_role('button', name='Buka sidebar').click()
                pb.get_by_role('button', name='Sync Project', exact=True).wait_for(timeout=30000)
                pa.get_by_role('button', name='Sync Project', exact=True).click()
                pa.get_by_role('button', name='Chat baru', exact=True).last.click()
                pa.get_by_label('Pesan untuk AI').fill('SYNC INITIAL')
                pa.get_by_label('Kirim pesan').click()
                pa.get_by_text('Jawaban sintetis', exact=True).wait_for(timeout=20000)
                pb.get_by_text('SYNC INITIAL', exact=False).first.wait_for(timeout=30000)
                pb.get_by_text('SYNC INITIAL', exact=False).first.click()
                pb.get_by_text('Jawaban sintetis', exact=True).wait_for(timeout=15000)
                b.route('**/api/workspace-sync/**', lambda route: route.abort())
                if pb.get_by_role('button', name='Buka sidebar').count():
                    pb.get_by_role('button', name='Buka sidebar').click()
                pb.get_by_role('button', name='Kelola project Sync Project').click()
                d = pb.get_by_role('dialog', name='Pengaturan project')
                d.get_by_label('Nama project').fill('Offline Project Edit')
                d.get_by_role('button', name='Simpan perubahan').click()
                pb.get_by_text('Sinkronisasi tertunda', exact=False).wait_for(timeout=15000)
                time.sleep(1)
                pb.reload()
                try:
                    pb.get_by_text('Sinkronisasi tertunda', exact=False).wait_for(timeout=40000)
                except Exception:
                    print('Offline reload state:', pb.locator('body').inner_text()[:4000], flush=True)
                    raise
                if pb.get_by_role('button', name='Buka sidebar').count():
                    pb.get_by_role('button', name='Buka sidebar').click()
                try:
                    pb.get_by_role('button', name='Offline Project Edit', exact=True).wait_for(timeout=10000)
                except Exception:
                    print('Reloaded mobile UI:', pb.locator('body').inner_text()[:4000], flush=True)
                    raise
                pa.get_by_role('button', name='Kelola project Sync Project').click()
                d = pa.get_by_role('dialog', name='Pengaturan project')
                d.get_by_label('Nama project').fill('Server Project Edit')
                d.get_by_role('button', name='Simpan perubahan').click()
                # Ensure the remote update commits before reconnecting B.
                def server_has_update():
                    data = pa.request.get(f'http://127.0.0.1:{port}/api/workspace-sync/changes?after=0').json()
                    return any(item.get('data', {}).get('name') == 'Server Project Edit' for item in data['items'] if item.get('data'))
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and not server_has_update(): time.sleep(.2)
                assert server_has_update(), 'server edit did not sync'
                b.unroute_all(behavior='wait')
                pb.get_by_text('Konflik project', exact=False).wait_for(timeout=30000)
                if pb.get_by_role('button', name='Tutup sidebar').count():
                    pb.get_by_role('button', name='Tutup sidebar').first.click(position={'x': 380, 'y': 80})
                pb.get_by_role('button', name='Gunakan versi perangkat ini').click()
                pa.get_by_role('button', name='Offline Project Edit', exact=True).wait_for(timeout=30000)
                print('Two browser profiles: project/chat sync, offline reload, conflict review and resolution OK')
                browser.close()
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            temporary.cleanup()


if __name__ == '__main__':
    main()

"""Exercise readiness UI and sanitized export with isolated synthetic data."""
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
temporary = tempfile.TemporaryDirectory(prefix='jo-readiness-ui-')
os.environ['AGENT_DATA_DIR'] = temporary.name
os.environ['AGENT_WORKSPACE'] = str(Path(temporary.name) / 'workspace')
os.environ['AGENT_API_TOKEN'] = 'synthetic-readiness-ui-token-12345'
import uvicorn
from playwright.sync_api import sync_playwright
from main import app
import readiness


def main():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning'))
    values = (readiness.check('ready', 'Runtime writable.'),
              readiness.check('limited', 'Docker unavailable.'),
              readiness.check('ready', 'Private Serve verified.', url='https://test.example.ts.net'))
    with patch.object(readiness, 'local_checks', return_value=values):
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 20
            while not server.started and time.monotonic() < deadline: time.sleep(.1)
            if not server.started: raise RuntimeError('QA server did not start')
            with sync_playwright() as playwright:
                chrome = Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe')
                browser = playwright.chromium.launch(executable_path=str(chrome) if chrome.is_file() else None, headless=True)
                for viewport in ({'width': 1280, 'height': 840}, {'width': 390, 'height': 844}):
                    context = browser.new_context(viewport=viewport, accept_downloads=True)
                    page = context.new_page()
                    page.goto(f'http://127.0.0.1:{port}')
                    page.get_by_label('Token akses').fill(os.environ['AGENT_API_TOKEN'])
                    page.get_by_role('button', name='Hubungkan', exact=True).click()
                    with page.expect_request('**/api/health', timeout=10000):
                        page.evaluate("window.dispatchEvent(new Event('online'))")
                    page.get_by_label('Buka Settings').click()
                    page.get_by_role('button', name='Kesehatan & iPhone').click()
                    page.get_by_text('Backend: Siap').wait_for(timeout=20000)
                    page.get_by_text('Docker (opsional): Terbatas').wait_for(timeout=5000)
                    page.get_by_text('IndexedDB dapat ditulis', exact=False).wait_for(timeout=5000)
                    assert page.get_by_role('link', name='https://test.example.ts.net').count() == 1
                    assert page.locator('svg[role="img"]').count() >= 1
                    with page.expect_download() as download_info:
                        page.get_by_role('button', name='Ekspor diagnostik').click()
                    download = download_info.value
                    payload = json.loads(download.path().read_text(encoding='utf-8'))
                    assert payload['checks']['docker'] == 'limited'
                    dumped = json.dumps(payload)
                    assert 'ts.net' not in dumped and 'token' not in dumped and temporary.name not in dumped
                    context.close()
                print('Readiness desktop/mobile UI, QR and sanitized export passed.')
                browser.close()
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            temporary.cleanup()


if __name__ == '__main__':
    main()

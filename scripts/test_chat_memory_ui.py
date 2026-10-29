"""Browser test for session history, reload, bounded recall, and session isolation."""
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
temp = Path(tempfile.mkdtemp(prefix='jo-memory-ui-'))
os.environ['AGENT_DATA_DIR'] = str(temp)
os.environ['AGENT_WORKSPACE'] = str(temp / 'workspace')
os.environ['AGENT_API_TOKEN'] = 'synthetic-memory-test-token-1234567890'

import uvicorn
from playwright.sync_api import sync_playwright
from main import app


def main():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning'))
    captured = []

    async def chunks(model, messages, **kwargs):
        captured.append(messages)
        last = messages[-1]['content']
        if 'Apa kode proyek saya?' in last:
            text = 'MERANTI-842' if any('MERANTI-842' in item['content'] for item in messages[:-1]) else 'Informasi belum ada.'
        else:
            text = 'Dicatat.'
        yield {'message': {'content': text}}
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
                chrome = os.environ.get('JO_CHROME_PATH', r'C:\Program Files\Google\Chrome\Application\chrome.exe')
                browser = playwright.chromium.launch(executable_path=chrome if Path(chrome).is_file() else None, headless=True)
                page = browser.new_page()
                page.goto(f'http://127.0.0.1:{port}', wait_until='domcontentloaded')
                page.get_by_label('Token akses').fill(os.environ['AGENT_API_TOKEN'])
                page.get_by_role('button', name='Hubungkan', exact=True).click()

                def send(text, expected, count):
                    page.get_by_label('Pesan untuk AI').fill(text)
                    page.get_by_label('Kirim pesan').click()
                    page.get_by_text(expected, exact=True).nth(count).wait_for(timeout=15000)

                send('Kode proyek saya MERANTI-842.', 'Dicatat.', 0)
                for index in range(7):
                    send(f'Catatan rutin nomor {index}.', 'Dicatat.', index + 1)
                send('Apa kode proyek saya?', 'MERANTI-842', 0)
                assert any('MERANTI-842' in item['content'] for item in captured[-1][:-1])
                page.wait_for_timeout(1000)
                page.reload(wait_until='domcontentloaded')
                send('Apa kode proyek saya?', 'MERANTI-842', 1)
                assert any('MERANTI-842' in item['content'] for item in captured[-1][:-1])
                page.get_by_role('button', name='Chat baru', exact=True).last.click()
                send('Apa kode proyek saya?', 'Informasi belum ada.', 0)
                assert all('MERANTI-842' not in item['content'] for item in captured[-1][:-1])
                print('Session memory UI: older context, reload and isolation OK', flush=True)
                browser.close()
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            if thread.is_alive():
                raise RuntimeError('QA server did not stop')


if __name__ == '__main__':
    main()

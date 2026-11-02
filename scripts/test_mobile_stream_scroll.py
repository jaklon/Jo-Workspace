"""Check manual scrolling and following while a response streams on mobile."""
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
temporary = tempfile.TemporaryDirectory(prefix='jo-scroll-ui-')
os.environ['AGENT_DATA_DIR'] = temporary.name
os.environ['AGENT_WORKSPACE'] = str(Path(temporary.name) / 'workspace')
os.environ['AGENT_API_TOKEN'] = 'synthetic-scroll-ui-token-123456'
import uvicorn
from playwright.sync_api import sync_playwright
from main import app


def main():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning'))

    async def chunks(*args, **kwargs):
        for index in range(120):
            await asyncio.sleep(.15)
            yield {'message': {'content': f'Baris {index}: jawaban pengujian layar ponsel.\n\n'}}
        yield {'done': True}

    with patch('main.classify', new=AsyncMock(return_value='chat')), patch('main.runtime.chunks', new=chunks):
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 20
            while not server.started and time.monotonic() < deadline: time.sleep(.1)
            if not server.started: raise RuntimeError('QA server did not start')
            with sync_playwright() as playwright:
                chrome = Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe')
                browser = playwright.chromium.launch(executable_path=str(chrome) if chrome.is_file() else None, headless=True)
                context = browser.new_context(viewport={'width': 390, 'height': 844}, is_mobile=True, has_touch=True)
                page = context.new_page()
                page.goto(f'http://127.0.0.1:{port}')
                page.get_by_label('Token akses').fill(os.environ['AGENT_API_TOKEN'])
                page.get_by_role('button', name='Hubungkan', exact=True).click()
                page.get_by_text('Sinkron dengan backend', exact=True).wait_for(timeout=30000)
                page.get_by_label('Pesan untuk AI').fill('Tuliskan jawaban panjang pengujian')
                page.get_by_label('Kirim pesan').click()
                scroller = page.get_by_label('Pesan percakapan')
                page.wait_for_function("""() => {const el = document.querySelector('[aria-label="Pesan percakapan"]');
                  return el && el.scrollHeight - el.clientHeight > 700} """, timeout=15000)
                assert page.get_by_label('Hentikan respons').is_visible(), 'stream already ended'
                # Simulate a user swipe down, then observe scroll position while more tokens arrive.
                cdp = context.new_cdp_session(page)
                cdp.send('Input.dispatchTouchEvent', {'type': 'touchStart', 'touchPoints': [{'x': 200, 'y': 280}]})
                cdp.send('Input.dispatchTouchEvent', {'type': 'touchMove', 'touchPoints': [{'x': 200, 'y': 540}]})
                cdp.send('Input.dispatchTouchEvent', {'type': 'touchEnd', 'touchPoints': []})
                page.get_by_role('button', name='Ke pesan terbaru').wait_for(timeout=5000)
                scroller.evaluate('(el) => { el.scrollTop = 0 }')
                page.wait_for_timeout(1200)
                position = scroller.evaluate('(el) => ({top: el.scrollTop, gap: el.scrollHeight - el.clientHeight - el.scrollTop})')
                assert position['top'] < 100 and position['gap'] > 600, position
                assert page.get_by_label('Hentikan respons').is_visible(), 'stream stopped during scroll test'
                page.get_by_role('button', name='Ke pesan terbaru').click()
                page.wait_for_timeout(1200)
                gap = scroller.evaluate('(el) => el.scrollHeight - el.clientHeight - el.scrollTop')
                assert gap <= 64, f'following did not resume: gap={gap}'
                page.get_by_label('Hentikan respons').click()
                print('Mobile stream: swipe up history, remain in place, jump to newest and follow passed.')
                browser.close()
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            temporary.cleanup()


if __name__ == '__main__':
    main()

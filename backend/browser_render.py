"""Bounded JavaScript rendering for an explicit public HTTPS URL."""
import asyncio
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from search_workspace import public_url
from web_checks import resolve


_BROWSER_GATE = asyncio.Semaphore(1)
_REQUEST_TYPES = frozenset(('document', 'script', 'stylesheet', 'xhr', 'fetch'))
# Automation steps an agent may script. Deliberately small: navigate same-host, type
# into/click elements, wait for a selector. No eval, no file chooser, no downloads.
_AUTOMATION_STEPS = frozenset(('goto', 'fill', 'click', 'press', 'wait_for_selector'))
_JWT_RE = re.compile(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}')


def allowed_request(target, candidate, method, resource_type):
    safe = public_url(candidate)
    return bool(safe and method == 'GET' and resource_type in _REQUEST_TYPES
                and urlsplit(safe).hostname == urlsplit(target).hostname)


def browser_channel():
    choices = (
        ('chrome', Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Google/Chrome/Application/chrome.exe'),
        ('chrome', Path(os.environ.get('LOCALAPPDATA', '')) / 'Google/Chrome/Application/chrome.exe'),
        ('msedge', Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Microsoft/Edge/Application/msedge.exe'),
        ('msedge', Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Microsoft/Edge/Application/msedge.exe'),
    )
    return next((name for name, path in choices if path.is_file()), None)


async def render_public(url):
    """Render one same-host page; no login, redirects, alternate hosts, or challenge solving."""
    safe = public_url(url)
    if not safe:
        raise ValueError('URL publik HTTPS diperlukan untuk render JavaScript.')
    channel = browser_channel()
    if not channel:
        raise RuntimeError('Chrome atau Edge diperlukan untuk membaca halaman JavaScript.')
    host = urlsplit(safe).hostname
    address = await resolve(host, 443, [])
    if ipaddress.ip_address(address).version != 4:
        raise RuntimeError('Render JavaScript hanya mendukung target dengan alamat IPv4 publik.')
    from playwright.async_api import async_playwright

    async with _BROWSER_GATE:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                channel=channel, headless=True,
                args=[f'--host-resolver-rules=MAP {host} {address}, MAP * ~NOTFOUND',
                      '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
                      '--no-proxy-server'])
            try:
                context = await browser.new_context(service_workers='block', accept_downloads=False,
                                                    ignore_https_errors=False)
                count, total = 0, 0

                async def bounded_route(route):
                    nonlocal count, total
                    request = route.request
                    if not allowed_request(safe, request.url, request.method, request.resource_type) or count >= 20:
                        await route.abort()
                        return
                    count += 1
                    try:
                        response = await route.fetch(max_redirects=0, timeout=8000)
                        if response.status >= 300 or response.status < 200:
                            await route.abort()
                            return
                        body = await response.body()
                        total += len(body)
                        if len(body) > 2_000_000 or total > 5_000_000:
                            await route.abort()
                            return
                        await route.fulfill(response=response, body=body)
                    except Exception:
                        await route.abort()

                await context.route('**/*', bounded_route)
                page = await context.new_page()
                response = await page.goto(safe, wait_until='domcontentloaded', timeout=12000)
                if not response or response.status != 200 or urlsplit(page.url).hostname != host:
                    raise ValueError('Halaman JavaScript tidak tersedia tanpa redirect.')
                try:
                    await page.wait_for_function('document.body && document.body.innerText.trim().length > 180', timeout=6000)
                except Exception:
                    pass
                html = await page.content()
                if len(html.encode('utf-8')) > 512_000:
                    raise ValueError('DOM halaman JavaScript terlalu besar.')
                return html.encode('utf-8')
            finally:
                await browser.close()


def _validate_steps(steps, max_steps):
    if len(steps) > max_steps:
        raise ValueError('Jumlah langkah otomatisasi melebihi batas.')
    for step in steps:
        action = step.get('action')
        if action not in _AUTOMATION_STEPS:
            raise ValueError('Aksi otomatisasi tidak diizinkan: ' + str(action))
        if action in ('fill', 'click', 'press', 'wait_for_selector'):
            selector = step.get('selector', '')
            if not isinstance(selector, str) or not selector.strip() or len(selector) > 300:
                raise ValueError('Selector langkah otomatisasi tidak valid.')
        if action in ('goto', 'fill', 'press') and len(str(step.get('value', ''))) > 1000:
            raise ValueError('Nilai langkah otomatisasi terlalu panjang.')


async def render_automation(url, *, session_tokens=None, steps=None, capture_xhr=False,
                            wait_selector=None, max_steps=8):
    """Gated headless automation agent (opt-in path; render_public stays the safe default).

    Supports multi-step authenticated flows, SPA DOM extraction and XHR/Fetch capture —
    all bounded and same-host. Credentials come ONLY from transient session tokens
    (SessionVault, like auth-two-session), never free-form input, and are sent only to
    the DNS-pinned target host. Returns the settled DOM plus captured XHR/Fetch metadata.
    """
    safe = public_url(url)
    if not safe:
        raise ValueError('URL publik HTTPS diperlukan untuk otomatisasi browser.')
    channel = browser_channel()
    if not channel:
        raise RuntimeError('Chrome atau Edge diperlukan untuk otomatisasi browser.')
    host = urlsplit(safe).hostname
    address = await resolve(host, 443, [])
    if ipaddress.ip_address(address).version != 4:
        raise RuntimeError('Otomatisasi hanya mendukung target dengan alamat IPv4 publik.')
    steps = list(steps or [])
    _validate_steps(steps, max_steps)
    tokens = list(session_tokens or [])
    if any(not _JWT_RE.fullmatch(token or '') for token in tokens):
        raise ValueError('Token sesi tidak valid; hanya token uji transient yang diterima.')
    from playwright.async_api import async_playwright

    async with _BROWSER_GATE:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                channel=channel, headless=True,
                args=[f'--host-resolver-rules=MAP {host} {address}, MAP * ~NOTFOUND',
                      '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
                      '--no-proxy-server'])
            try:
                context = await browser.new_context(service_workers='block', accept_downloads=False,
                                                    ignore_https_errors=False)
                # Authenticated flows: attach the transient bearer only for the pinned host.
                if tokens:
                    await context.set_extra_http_headers({'Authorization': 'Bearer ' + tokens[0]})
                captured, count, total = [], 0, 0

                async def bounded_route(route):
                    nonlocal count, total
                    request = route.request
                    if not allowed_request(safe, request.url, request.method, request.resource_type) or count >= 40:
                        await route.abort()
                        return
                    count += 1
                    try:
                        response = await route.fetch(max_redirects=0, timeout=8000)
                        if response.status >= 300 or response.status < 200:
                            await route.abort()
                            return
                        body = await response.body()
                        total += len(body)
                        if len(body) > 2_000_000 or total > 8_000_000:
                            await route.abort()
                            return
                        await route.fulfill(response=response, body=body)
                    except Exception:
                        await route.abort()

                def on_response(response):
                    request = response.request
                    if (request.resource_type in ('xhr', 'fetch') and len(captured) < 100
                            and urlsplit(request.url).hostname == host):
                        captured.append({'url': public_url(request.url) or request.url, 'method': request.method,
                                         'status': response.status, 'resource_type': request.resource_type,
                                         'content_type': (response.headers.get('content-type', '') or '')[:120]})

                await context.route('**/*', bounded_route)
                if capture_xhr:
                    context.on('response', on_response)
                page = await context.new_page()
                response = await page.goto(safe, wait_until='domcontentloaded', timeout=12000)
                if not response or urlsplit(page.url).hostname != host:
                    raise ValueError('Navigasi awal gagal atau berpindah host.')
                run = 0
                for step in steps:
                    run += 1
                    action = step['action']
                    if action == 'goto':
                        destination = public_url(step.get('value', ''))
                        if not destination or urlsplit(destination).hostname != host:
                            raise ValueError('Langkah goto lintas host ditolak.')
                        await page.goto(destination, wait_until='domcontentloaded', timeout=12000)
                    elif action == 'fill':
                        await page.fill(step['selector'], str(step.get('value', ''))[:1000], timeout=6000)
                    elif action == 'click':
                        await page.click(step['selector'], timeout=6000)
                    elif action == 'press':
                        await page.press(step['selector'], str(step.get('value', 'Enter'))[:20], timeout=6000)
                    elif action == 'wait_for_selector':
                        await page.wait_for_selector(step['selector'], timeout=6000)
                    if urlsplit(page.url).hostname != host:
                        raise ValueError('Langkah otomatisasi berpindah host; dihentikan.')
                try:
                    await page.wait_for_load_state('networkidle', timeout=6000)
                except Exception:
                    pass
                if wait_selector:
                    try:
                        await page.wait_for_selector(wait_selector, timeout=6000)
                    except Exception:
                        pass
                html = await page.content()
                if len(html.encode('utf-8')) > 512_000:
                    raise ValueError('DOM hasil otomatisasi terlalu besar.')
                return {'final_url': page.url, 'host': host, 'steps_run': run,
                        'authenticated': bool(tokens), 'dom': html.encode('utf-8'),
                        'xhr': captured if capture_xhr else [], 'xhr_count': len(captured),
                        'isolation': 'headless_same_host_dns_pinned', 'limitation':
                        'Otomatisasi same-host, DNS-pinned, token transient saja. Bukan bukti eksploitasi; tanpa lintas-host atau unduhan.'}
            finally:
                await browser.close()

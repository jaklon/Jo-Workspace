"""Bounded JavaScript rendering for an explicit public HTTPS URL."""
import asyncio
import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit

from search_workspace import public_url
from web_checks import resolve


_BROWSER_GATE = asyncio.Semaphore(1)
_REQUEST_TYPES = frozenset(('document', 'script', 'stylesheet', 'xhr', 'fetch'))


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

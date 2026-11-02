"""Bounded, read-only readiness checks; never include credentials or workspace data."""
import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request

import config
from search_workspace import searx_url

router = APIRouter(prefix='/api', tags=['Readiness'])


def check(status, detail, action='', **extra):
    return {'status': status, 'detail': detail, 'action': action, **extra}


def command(*args):
    executable = shutil.which(args[0])
    if not executable:
        return None
    try:
        result = subprocess.run([executable, *args[1:]], capture_output=True, text=True,
                                timeout=2.5, check=False, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return result.stdout if result.returncode == 0 and len(result.stdout) < 1_000_000 else None
    except (OSError, subprocess.SubprocessError):
        return None


def local_checks(port):
    try:
        usage = shutil.disk_usage(config.DATA_DIR)
        with tempfile.TemporaryFile(dir=config.DATA_DIR):
            pass
        storage = check('limited' if usage.free < 512 * 1024**2 else 'ready',
                        f'Penyimpanan runtime dapat ditulis; tersedia {usage.free // 1024**2} MB.',
                        'Kosongkan ruang disk untuk operasi berikutnya.' if usage.free < 512 * 1024**2 else '',
                        free_mb=usage.free // 1024**2)
    except OSError:
        storage = check('action', 'Penyimpanan runtime tidak dapat diperiksa atau ditulis.',
                        'Periksa ruang disk dan izin folder runtime.')
    docker = command('docker', 'version', '--format', '{{.Server.Version}}')
    docker_check = (check('ready', 'Docker daemon merespons.') if docker else
                    check('limited', 'Docker tidak terdeteksi atau daemon tidak merespons.',
                          'Jalankan Docker bila fitur yang memerlukannya akan digunakan.'))
    ts_raw = command('tailscale', 'status', '--json')
    serve_raw = command('tailscale', 'serve', 'status', '--json')
    url = None
    try:
        status = json.loads(ts_raw or '{}')
        serve = json.loads(serve_raw or '{}')
        host = status.get('Self', {}).get('DNSName', '').rstrip('.').lower()
        online = status.get('BackendState') == 'Running' and status.get('Self', {}).get('Online') is True
        funnels = serve.get('AllowFunnel') or {}
        safe_host = bool(re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.ts\.net', host))
        web = serve.get('Web') or {}
        handler = (web.get(host + ':443') or {}).get('Handlers', {}).get('/', {})
        proxy = urlsplit(handler.get('Proxy', ''))
        https_listener = (serve.get('TCP') or {}).get('443', {}).get('HTTPS') is True
        if (online and safe_host and https_listener and not any(funnels.values()) and
                proxy.scheme == 'http' and proxy.hostname in ('127.0.0.1', 'localhost', '::1') and
                proxy.port == port and proxy.path in ('', '/')):
            url = 'https://' + host
        if url:
            tailscale = check('ready', 'Tailscale aktif dan Serve mengarah ke backend ini.', url=url)
        elif online:
            tailscale = check('limited', 'Tailscale aktif; Serve belum terverifikasi untuk backend ini.',
                              'Periksa tailscale serve status dan port backend. Jangan gunakan alamat backend lain.')
        else:
            tailscale = check('limited', 'Status Tailscale tidak dapat dipastikan.',
                              'Buka Tailscale di laptop, login, lalu periksa Tailscale Serve.')
    except (ValueError, TypeError, AttributeError):
        tailscale = check('limited', 'Konfigurasi Tailscale tidak dapat dibaca.',
                          'Periksa status Tailscale dan Serve pada laptop.')
    return storage, docker_check, tailscale


async def report(request):
    from main import gpu_status, runtime

    async def probe_models():
        try:
            async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
                response = await client.get(config.OLLAMA_URL + '/api/tags')
                response.raise_for_status()
                models = [m.get('name') for m in response.json().get('models', []) if isinstance(m, dict)]
            missing = [role for role, name in config.MODELS.items() if name not in models and name + ':latest' not in models]
            if missing:
                return check('limited', 'Ollama merespons; model belum tersedia untuk: ' + ', '.join(missing),
                             'Pasang atau pilih model yang tersedia pada pengaturan Model & inferensi.', missing_roles=missing)
            return check('ready', 'Ollama dan model untuk semua peran tersedia.', missing_roles=[])
        except (httpx.HTTPError, ValueError, TypeError):
            return check('action', 'Ollama tidak dapat dijangkau.', 'Jalankan Ollama dan periksa model yang dipilih.', missing_roles=[])

    async def probe_search():
        try:
            async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
                response = await client.get(searx_url() + '/')
            if response.status_code < 400:
                return check('ready', 'SearXNG merespons; format JSON belum diuji.')
        except (httpx.HTTPError, RuntimeError):
            pass
        return check('limited', 'SearXNG tidak terjangkau; pencarian web lokal dapat terganggu.',
                     'Jalankan SearXNG jika pencarian web diperlukan.')

    async def bounded_thread(fn, fallback):
        try:
            return await asyncio.wait_for(asyncio.to_thread(fn), timeout=8)
        except Exception:
            return fallback

    port = request.scope.get('server', ('', 0))[1]
    fallback = check('limited', 'Pemeriksaan lokal tidak tersedia.', 'Coba ulang dari laptop.')
    models, search, local, gpu = await asyncio.gather(
        probe_models(), probe_search(),
        bounded_thread(lambda: local_checks(port), (fallback, fallback, fallback)),
        bounded_thread(gpu_status, {'available': False}))
    storage, docker, tailscale = local
    gpu_check = (check('ready', f"GPU terdeteksi; VRAM {gpu['vram_used_mb']}/{gpu['vram_total_mb']} MB.",
                       used_mb=gpu['vram_used_mb'], total_mb=gpu['vram_total_mb']) if gpu.get('available') else
                 check('limited', 'GPU NVIDIA tidak terdeteksi; aplikasi dapat memakai CPU.',
                       'Periksa driver NVIDIA bila GPU seharusnya tersedia.'))
    return {'checked_at': datetime.now(timezone.utc).isoformat(), 'checks': {
        'backend': check('ready', 'Backend merespons.'), 'ollama': models,
        'queue': check('ready', f'Inferensi aktif: {runtime.active}; menunggu: {runtime.waiting}.',
                       active=runtime.active, waiting=runtime.waiting),
        'gpu': gpu_check, 'storage': storage, 'search': search, 'docker': docker, 'tailscale': tailscale}}


@router.get('/readiness')
async def readiness(request: Request):
    return await report(request)

"""Scheduled offline backups based on an explicitly refreshed browser snapshot."""
import base64
import json
import re
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

from backup_archive import create_archive

ENTROPY = b'JoWorkspaceSchedulePassphrase-v1'


def save_schedule(path, *, runtime, workspace, browser, browser_stores, destination, retention, passphrase):
    import win32crypt
    target = Path(path)
    if target.exists():
        raise FileExistsError('Konfigurasi jadwal sudah ada.')
    if not 1 <= retention <= 30:
        raise ValueError('Retensi harus antara 1 dan 30 cadangan.')
    paths = [Path(x).resolve() for x in (runtime, workspace, browser, destination)]
    if not paths[0].is_dir() or not paths[1].is_dir() or not paths[2].is_file():
        raise ValueError('Runtime, workspace atau snapshot browser tidak ditemukan.')
    if any(paths[3].is_relative_to(root) for root in paths[:2]):
        raise ValueError('Lokasi cadangan harus di luar runtime dan workspace.')
    stores = [Path(x).resolve() for x in browser_stores]
    if not 1 <= len(stores) <= 4 or any(not item.is_dir() for item in stores):
        raise ValueError('Direktori penyimpanan browser perlu diberikan untuk memeriksa perubahan.')
    if any(paths[3].is_relative_to(item) for item in stores):
        raise ValueError('Lokasi cadangan harus di luar profil browser.')
    if any(target.resolve().is_relative_to(item) for item in [*paths[:2], *stores]):
        raise ValueError('Konfigurasi jadwal harus di luar runtime, workspace, dan profil browser.')
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValueError('Frasa sandi minimal 12 karakter diperlukan.')
    encrypted = win32crypt.CryptProtectData(passphrase.encode('utf-8'), 'Jo Workspace backup schedule', ENTROPY, None, None, 1)
    data = {'version': 1, 'id': uuid.uuid4().hex, 'runtime': str(paths[0]), 'workspace': str(paths[1]),
            'browser': str(paths[2]), 'destination': str(paths[3]), 'retention': retention,
            'browser_stores': [str(item) for item in stores],
            'protected_passphrase': base64.b64encode(encrypted).decode('ascii')}
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('x', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    return {'schedule_id': data['id'], 'config': str(target)}


def require_idle(ports=(8010, 18010)):
    for port in ports:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=5):
                raise ValueError(f'Backend pada port {port} masih aktif; jadwal dilewati.')
        except ConnectionRefusedError:
            continue
        except TimeoutError as exc:
            raise TimeoutError(f'Pemeriksaan loopback port {port} melewati batas waktu.') from exc


def ensure_fresh_snapshot(browser, roots, *, max_age_seconds=86400):
    snapshot = Path(browser)
    timestamp = snapshot.stat().st_mtime_ns
    if time.time_ns() - timestamp > max_age_seconds * 1_000_000_000:
        raise ValueError('Snapshot browser lebih dari 24 jam; perbarui terlebih dahulu.')
    for root in map(Path, roots):
        for path in root.rglob('*'):
            if path.is_symlink():
                raise ValueError('Symlink pada sumber tidak didukung.')
            if path.is_file() and path.name.endswith('-wal') and path.stat().st_size == 0:
                continue
            if path.name not in ('api-token', '.jo-runtime.lock') and not path.name.endswith('-shm') and path.stat().st_mtime_ns > timestamp:
                raise ValueError(f'Data backend/workspace lebih baru dari snapshot browser: {path.name}; perbarui snapshot.')


def _run_schedule(path):
    from runtime_lock import runtime_lock
    with Path(path).open(encoding='utf-8') as handle:
        config = json.load(handle)
    if not isinstance(config.get('runtime'), str) or not Path(config['runtime']).is_dir():
        raise ValueError('Direktori runtime jadwal tidak tersedia.')
    with runtime_lock(config['runtime']):
        return _run_locked(config)


def run_schedule(path):
    status_path = Path(str(path) + '.status.json')
    try:
        result = _run_schedule(path)
        status = {'ok': True, 'at': time.time(), **result}
    except Exception as exc:
        status = {'ok': False, 'at': time.time(), 'error': str(exc)[:500]}
        _write_status(status_path, status)
        raise
    _write_status(status_path, status)
    return result


def _write_status(path, status):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        temporary.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding='utf-8')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def register_schedule(config, script):
    config, script = Path(config).resolve(), Path(script).resolve()
    with config.open(encoding='utf-8') as handle:
        data = json.load(handle)
    sid = data.get('id', '')
    if data.get('version') != 1 or not re.fullmatch(r'[a-f0-9]{32}', sid):
        raise ValueError('Konfigurasi jadwal tidak valid.')
    executable = Path(sys.executable).resolve().with_name('pythonw.exe')
    if not executable.is_file():
        raise ValueError('pythonw.exe tidak tersedia pada virtual environment ini.')
    if any(any(c in str(p) for c in ('"', '&', '|', '<', '>', '^', '%', '\n', '\r')) for p in (executable, script, config)):
        raise ValueError('Path jadwal mengandung karakter yang tidak didukung.')
    command = subprocess.list2cmdline([str(executable), str(script), 'schedule-run', '--config', str(config)])
    name = 'JoWorkspace-Backup-' + sid
    subprocess.run(['schtasks.exe', '/Create', '/TN', name, '/SC', 'HOURLY', '/MO', '1', '/IT', '/TR', command],
                   check=True, capture_output=True, text=True)
    return {'task_name': name, 'config': str(config)}


def _run_locked(data):
    import win32crypt
    sid = data.get('id', '')
    if data.get('version') != 1 or not re.fullmatch(r'[a-f0-9]{32}', sid) or type(data.get('retention')) is not int or not 1 <= data['retention'] <= 30:
        raise ValueError('Konfigurasi jadwal tidak valid.')
    require_idle()
    stores = data.get('browser_stores')
    if not isinstance(stores, list) or not 1 <= len(stores) <= 4 or any(not isinstance(p, str) or not Path(p).is_dir() for p in stores):
        raise ValueError('Direktori penyimpanan browser jadwal tidak tersedia.')
    ensure_fresh_snapshot(data['browser'], (data['runtime'], data['workspace'], *stores))
    _, raw = win32crypt.CryptUnprotectData(base64.b64decode(data['protected_passphrase'], validate=True), ENTROPY, None, None, 1)
    phrase = raw.decode('utf-8')
    if Path(data['browser']).stat().st_size > 50 * 1024 * 1024:
        raise ValueError('Snapshot browser melebihi 50 MB.')
    browser = json.loads(Path(data['browser']).read_text(encoding='utf-8-sig'))
    directory = Path(data['destination'])
    directory.mkdir(parents=True, exist_ok=True)
    name = f'jo-scheduled-{sid}-{time.time_ns()}-{uuid.uuid4().hex}.zip'
    output = directory / name
    manifest = create_archive(output, data['runtime'], data['workspace'], browser, phrase, schedule_id=sid)
    try:
        ensure_fresh_snapshot(data['browser'], (data['runtime'], data['workspace'], *stores))
    except Exception:
        output.unlink(missing_ok=True)
        raise
    candidates = []
    pattern = re.compile(rf'jo-scheduled-{sid}-[0-9]+-[a-f0-9]{{32}}\.zip')
    for item in directory.iterdir():
        if item.is_symlink() or not item.is_file() or not pattern.fullmatch(item.name):
            continue
        try:
            with zipfile.ZipFile(item) as bundle:
                info = bundle.getinfo('manifest.json')
                if info.file_size > 4 * 1024 * 1024:
                    continue
                if json.loads(bundle.read(info)).get('schedule_id') == sid:
                    candidates.append(item)
        except (OSError, ValueError, KeyError, zipfile.BadZipFile):
            continue
    candidates.sort(key=lambda x: x.name, reverse=True)
    for old in candidates[data['retention']:]:
        old.unlink()
    return {'path': str(output), 'files': len(manifest['files']), 'missing_attachments': manifest['missing_attachments']}

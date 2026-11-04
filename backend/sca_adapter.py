"""Bounded local SCA (software composition analysis) with Trivy over the approved
workspace. Offline only (no DB download, no network); binary-hash pinned and run under
the job/policy gate, confined to WORKSPACE_DIR, output capped and normalized."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from sast_adapter import resolve_repo_path, MAX_RAW, MAX_FINDINGS, SEVERITY

TOOL = 'trivy-sca'


def executable():
    return shutil.which('trivy')


def binary_hash():
    path = executable()
    if not path:
        return None
    try:
        with open(path, 'rb') as file:
            return hashlib.file_digest(file, 'sha256').hexdigest()
    except OSError:
        return None


def normalize(data, root):
    findings = []
    for result in (data.get('Results') or []):
        source = str(result.get('Target', ''))
        for vuln in (result.get('Vulnerabilities') or []):
            if len(findings) >= MAX_FINDINGS:
                break
            findings.append({
                'tool': TOOL, 'pkg': str(vuln.get('PkgName', ''))[:120],
                'installed_version': str(vuln.get('InstalledVersion', ''))[:60],
                'fixed_version': str(vuln.get('FixedVersion', ''))[:120],
                'vuln_id': str(vuln.get('VulnerabilityID', ''))[:60],
                'severity': SEVERITY.get(str(vuln.get('Severity', '')).upper(), 'info'),
                'file': source[:200], 'title': str(vuln.get('Title', ''))[:300]})
    return findings


async def run(plan, guard, exclusions=()):
    step = plan['steps'][0]
    if binary_hash() != plan['scan']['binary_sha256']:
        raise ValueError('Trivy executable berubah atau tidak tersedia.')
    await guard()
    root, target = resolve_repo_path(step['target']['value'])
    env = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'LOCALAPPDATA') if key in os.environ}
    env.update(TRIVY_DISABLE_VEX_NOTICE='true', TRIVY_NO_PROGRESS='true')
    # Strictly offline: use the pre-populated local DB, never update or phone home.
    args = [executable(), 'fs', '--quiet', '--format', 'json', '--scanners', 'vuln',
            '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--timeout', '60s', str(target)]
    process = await asyncio.create_subprocess_exec(
        *args, cwd=str(root), env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    try:
        parts, size = [], 0
        while True:
            chunk = await process.stdout.read(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RAW:
                raise ValueError('Output SCA melebihi batas.')
            parts.append(chunk)
        await process.wait()
        if process.returncode:
            raise ValueError('Trivy gagal; pastikan DB vuln lokal tersedia (tanpa unduhan).')
        try:
            data = json.loads(b''.join(parts) or b'{}')
        except ValueError:
            raise ValueError('Output SCA bukan JSON yang valid.') from None
        findings = normalize(data, root)
        total = sum(len(r.get('Vulnerabilities') or []) for r in (data.get('Results') or []))
        return {'tool': TOOL, 'target': step['target']['value'], 'scope': 'local_workspace',
                'binary_sha256': plan['scan']['binary_sha256'], 'findings': findings,
                'finding_count': len(findings), 'truncated': total > len(findings),
                'limitation': 'SCA dependensi lokal memakai DB vuln lokal; tanpa jaringan. Kecocokan perlu verifikasi dan bukan bukti eksploitasi.'}
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()

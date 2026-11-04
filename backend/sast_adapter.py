"""Bounded local SAST over the approved workspace. Offline only; never reaches the
network. Follows the nuclei/zap adapter pattern: binary-hash pinned, run under the
job/policy gate, confined to WORKSPACE_DIR, output capped and normalized."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import config

TOOLS = ('semgrep-sast', 'bandit-sast')
MAX_RAW = 4_000_000       # hard read cap for the tool's JSON output
MAX_FINDINGS = 200        # keep the stored evidence within the job output budget
SEVERITY = {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low',
            'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'CRITICAL': 'high'}


def executable(tool):
    name = 'semgrep' if tool == 'semgrep-sast' else 'bandit'
    return shutil.which(name)


def binary_hash(tool):
    path = executable(tool)
    if not path:
        return None
    try:
        with open(path, 'rb') as file:
            return hashlib.file_digest(file, 'sha256').hexdigest()
    except OSError:
        return None


def resolve_repo_path(relative):
    """Resolve a workspace-relative repo path and refuse anything outside WORKSPACE_DIR."""
    root = Path(config.WORKSPACE_DIR).resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise ValueError('Path repo di luar workspace ditolak.')
    if not target.exists():
        raise ValueError('Path repo tidak ditemukan di workspace.')
    return root, target


def _rel(root, path):
    try:
        return str(Path(path).resolve().relative_to(root)).replace('\\', '/')
    except (ValueError, OSError):
        return str(path).replace('\\', '/')


def normalize_semgrep(data, root):
    findings = []
    for item in (data.get('results') or [])[:MAX_FINDINGS]:
        start = item.get('start') or {}
        end = item.get('end') or {}
        extra = item.get('extra') or {}
        findings.append({
            'tool': 'semgrep-sast', 'rule_id': str(item.get('check_id', ''))[:200],
            'severity': SEVERITY.get(str(extra.get('severity', '')).upper(), 'info'),
            'file': _rel(root, item.get('path', '')),
            'line_start': int(start.get('line', 0) or 0), 'line_end': int(end.get('line', 0) or 0),
            'message': str(extra.get('message', ''))[:500],
            'fingerprint': str(extra.get('fingerprint') or item.get('check_id', ''))[:120]})
    return findings


def normalize_bandit(data, root):
    findings = []
    for item in (data.get('results') or [])[:MAX_FINDINGS]:
        line = int(item.get('line_number', 0) or 0)
        findings.append({
            'tool': 'bandit-sast', 'rule_id': str(item.get('test_id', ''))[:200],
            'severity': SEVERITY.get(str(item.get('issue_severity', '')).upper(), 'info'),
            'file': _rel(root, item.get('filename', '')),
            'line_start': line, 'line_end': line,
            'message': str(item.get('issue_text', ''))[:500],
            'fingerprint': (str(item.get('test_id', '')) + ':' + str(item.get('filename', '')) + ':' + str(line))[:120]})
    return findings


async def run(plan, guard, exclusions=()):
    step = plan['steps'][0]
    tool = plan['scan']['tool']
    if binary_hash(tool) != plan['scan']['binary_sha256']:
        raise ValueError('SAST executable berubah atau tidak tersedia.')
    await guard()
    root, target = resolve_repo_path(step['target']['value'])
    env = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'LOCALAPPDATA') if key in os.environ}
    # Keep both tools strictly offline and non-interactive; no registry/telemetry fetch.
    if tool == 'semgrep-sast':
        config = os.environ.get('JO_SEMGREP_CONFIG')
        if not config or not Path(config).exists():
            raise ValueError('Setel JO_SEMGREP_CONFIG ke ruleset lokal; unduh registry dinonaktifkan.')
        env.update(SEMGREP_SEND_METRICS='off')
        args = [executable(tool), 'scan', '--json', '--quiet', '--disable-version-check',
                '--metrics=off', '--no-git-ignore', '--timeout', '30', '--config', config, str(target)]
    else:
        args = [executable(tool), '-f', 'json', '-q', '-r', str(target)]
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
                raise ValueError('Output SAST melebihi batas.')
            parts.append(chunk)
        await process.wait()
        # Semgrep exits non-zero when findings exist; Bandit likewise. Trust JSON parse.
        raw = b''.join(parts)
        try:
            data = json.loads(raw or b'{}')
        except ValueError:
            raise ValueError('Output SAST bukan JSON yang valid.') from None
        findings = normalize_semgrep(data, root) if tool == 'semgrep-sast' else normalize_bandit(data, root)
        truncated = len(data.get('results') or []) > MAX_FINDINGS
        return {'tool': tool, 'target': step['target']['value'], 'scope': 'local_workspace',
                'binary_sha256': plan['scan']['binary_sha256'], 'findings': findings,
                'finding_count': len(findings), 'truncated': truncated,
                'limitation': 'Analisis statis lokal pada workspace; tanpa jaringan. Temuan perlu verifikasi analis dan bukan bukti eksploitasi.'}
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()

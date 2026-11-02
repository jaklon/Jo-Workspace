"""Validate and stage a Jo Workspace recovery archive without touching live data.

This module is deliberately independent of application startup and does not apply
or activate a restored workspace. Archive creation and application are separate.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from uuid import uuid4

FORMAT = 'jo-workspace-recovery'
VERSION = 1
MAX_FILES = 10000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
TABS = ('chat', 'code', 'vision', 'docs', 'pentest')


def validate_browser_state(state):
    if not isinstance(state, dict) or state.get('format') != 'jo-browser-recovery' or state.get('version') != 1:
        raise ValueError('Snapshot browser tidak valid.')
    projects, sessions = state.get('projects'), state.get('sessions')
    if not isinstance(projects, list) or len(projects) > 500 or not isinstance(sessions, dict) or not isinstance(state.get('activeSessions'), dict) or not isinstance(state.get('preferences'), dict):
        raise ValueError('Daftar project atau chat tidak valid.')
    project_ids = set()
    for item in projects:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'] or item['id'] in project_ids:
            raise ValueError('ID project tidak valid atau duplikat.')
        if not isinstance(item.get('name'), str) or not item['name'].strip() or len(item['name']) > 80 or not isinstance(item.get('instructions'), str) or len(item['instructions']) > 1500:
            raise ValueError('Nama atau instruksi project tidak valid.')
        project_ids.add(item['id'])
    session_ids = set()
    for tab in TABS:
        rows = sessions.get(tab)
        if not isinstance(rows, list) or len(rows) > 500:
            raise ValueError('Daftar chat tidak valid.')
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not row['id'] or row['id'] in session_ids:
                raise ValueError('ID chat tidak valid atau duplikat.')
            if row.get('projectId') is not None and row['projectId'] not in project_ids:
                raise ValueError('Chat merujuk project yang tidak ada.')
            if not isinstance(row.get('title'), str):
                raise ValueError('Judul chat tidak valid.')
            messages, attachments = row.get('messages'), row.get('attachments')
            if not isinstance(messages, list) or len(messages) > 100 or not isinstance(attachments, list) or len(attachments) > 4:
                raise ValueError('Pesan atau lampiran chat tidak valid.')
            if any(not isinstance(m, dict) or m.get('role') not in ('user', 'assistant') or not isinstance(m.get('content'), str) or len(m['content']) > 200000 for m in messages):
                raise ValueError('Pesan chat tidak valid.')
            if any(not isinstance(a, dict) or not isinstance(a.get('id'), str) for a in attachments):
                raise ValueError('Referensi lampiran tidak valid.')
            session_ids.add(row['id'])
    return project_ids


def create_archive(output, runtime_dir, workspace_dir, browser_state, portable_passphrase=None, schedule_id=None):
    """Create an archive from a caller-supplied browser snapshot and local files.

    SQLite uses the backup API so WAL content is included. The caller must ensure
    application writes are quiescent for a consistent multi-store snapshot.
    Credentials and volatile SQLite sidecars are excluded. Does not overwrite.
    """
    output, runtime, workspace = Path(output), Path(runtime_dir), Path(workspace_dir)
    if output.exists():
        raise FileExistsError('Tujuan cadangan sudah ada.')
    validate_browser_state(browser_state)
    for root in (runtime, workspace):
        if root.is_symlink() or not root.is_dir():
            raise ValueError('Direktori sumber tidak valid.')
    output.parent.mkdir(parents=True, exist_ok=True)
    if any(output.resolve().is_relative_to(root.resolve()) for root in (runtime, workspace)):
        raise ValueError('Simpan cadangan di luar direktori sumber.')
    excluded = []
    with tempfile.TemporaryDirectory(prefix='jo-backup-', dir=output.parent) as temporary:
        temp = Path(temporary)
        payload = temp / 'payload'
        (payload / 'browser').mkdir(parents=True)
        (payload / 'browser/state.json').write_text(json.dumps(browser_state, ensure_ascii=False), encoding='utf-8')
        for label, root in (('runtime', runtime), ('workspace', workspace)):
            for path in root.rglob('*'):
                rel = path.relative_to(root)
                name = label + '/' + rel.as_posix()
                if path.is_symlink():
                    raise ValueError('Symlink tidak didukung dalam cadangan: ' + name)
                if path.is_dir():
                    continue
                if label == 'runtime' and (name.endswith(('-wal', '-shm', '-journal')) or rel.parts[0] in ('api-token', 'portable-evidence.json', '.jo-runtime.lock')):
                    excluded.append(name)
                    continue
                try:
                    safe_name(name)
                except ValueError:
                    excluded.append(name)
                    continue
                target = payload.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                if label == 'runtime' and rel.as_posix() in ('agent.sqlite3', 'engagements.sqlite3'):
                    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as source, closing(sqlite3.connect(target)) as dest:
                        source.backup(dest)
                else:
                    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                        raise ValueError('Berkas tidak didukung atau terlalu besar: ' + name)
                    shutil.copyfile(path, target)
        from portable_evidence import export_originals
        portable = export_originals(payload / 'runtime/engagements.sqlite3', portable_passphrase)
        if portable is not None:
            (payload / 'runtime/portable-evidence.json').write_bytes(portable)
        files = []
        for path in sorted(payload.rglob('*')):
            if not path.is_file():
                continue
            name = safe_name(path.relative_to(payload).as_posix())
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                raise ValueError('Berkas melebihi batas: ' + name)
            with path.open('rb') as handle:
                digest = hashlib.file_digest(handle, 'sha256').hexdigest()
            files.append({'path': name, 'size': size, 'sha256': digest})
        if len(files) > MAX_FILES or sum(f['size'] for f in files) > MAX_TOTAL_BYTES:
            raise ValueError('Cadangan melebihi batas ukuran atau jumlah berkas.')
        missing = check_recovery_links(payload)
        manifest = {'format': FORMAT, 'version': VERSION, 'created_at': datetime.now(timezone.utc).isoformat(),
                    'files': files, 'excluded': excluded, 'missing_attachments': missing,
                    'portable_evidence': portable is not None, 'schedule_id': schedule_id}
        candidate = temp / 'candidate.zip'
        with zipfile.ZipFile(candidate, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=True) as bundle:
            bundle.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False))
            for entry in files:
                bundle.write(payload.joinpath(*PurePosixPath(entry['path']).parts), entry['path'])
        verified, _ = stage_archive(candidate, temp)
        check_recovery_links(verified)
        shutil.rmtree(verified)
        # Exclusive creation avoids replacing an existing backup in a race.
        created = False
        try:
            with candidate.open('rb') as src, output.open('xb') as dst:
                created = True
                shutil.copyfileobj(src, dst, length=1024 * 1024)
        except Exception:
            if created:
                output.unlink(missing_ok=True)
            raise
    return manifest


def safe_name(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name or ':' in name:
        raise ValueError('Nama berkas arsip tidak valid.')
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('Path arsip tidak aman.')
    reserved = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
                *(f'lpt{i}' for i in range(1, 10))}
    if any(part.endswith((' ', '.')) or any(ord(c) < 32 or c in '<>"|?*' for c in part)
           or part.split('.')[0].lower() in reserved for part in path.parts):
        raise ValueError('Nama berkas tidak aman pada Windows.')
    if not name.startswith(('runtime/', 'workspace/', 'browser/')):
        raise ValueError('Lokasi arsip tidak dikenali.')
    if any(part.lower() in ('api-token', '.env', '.git', '.ssh') or part.lower().startswith('.env.')
           for part in path.parts):
        raise ValueError('Arsip berisi lokasi rahasia yang tidak diizinkan.')
    return name


def stage_archive(archive, staging_parent):
    """Check manifest, contents, hashes and SQLite integrity in a fresh folder.

    Return (path, manifest). On failure the temporary folder is removed. A caller
    must separately validate application state before any restore is applied.
    """
    parent = Path(staging_parent)
    parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='jo-recovery-', dir=parent))
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            names = [item.filename for item in infos]
            if len(infos) > MAX_FILES + 1 or len(names) != len(set(names)) or names.count('manifest.json') != 1:
                raise ValueError('Daftar arsip tidak valid atau duplikat.')
            manifest_info = bundle.getinfo('manifest.json')
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise ValueError('Manifest terlalu besar.')
            manifest = json.loads(bundle.read(manifest_info))
            if not isinstance(manifest, dict) or manifest.get('format') != FORMAT or manifest.get('version') != VERSION:
                raise ValueError('Format atau versi cadangan tidak didukung.')
            entries = manifest.get('files')
            if not isinstance(entries, list) or len(entries) > MAX_FILES:
                raise ValueError('Daftar berkas tidak valid.')
            declared = {}
            folded = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError('Entri manifest tidak valid.')
                name = safe_name(entry.get('path'))
                size, digest = entry.get('size'), entry.get('sha256')
                if name.casefold() in folded or type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
                    raise ValueError('Entri duplikat atau ukuran berkas tidak valid.')
                if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                    raise ValueError('Hash berkas tidak valid.')
                folded.add(name.casefold())
                declared[name] = (size, digest)
            if set(names) != set(declared) | {'manifest.json'} or sum(size for size, _ in declared.values()) > MAX_TOTAL_BYTES:
                raise ValueError('Isi atau ukuran arsip tidak sesuai manifest.')
            for name, (size, expected) in declared.items():
                info = bundle.getinfo(name)
                mode = (info.external_attr >> 16) & 0o170000
                if info.is_dir() or mode not in (0, 0o100000) or info.flag_bits & 1 or info.file_size != size:
                    raise ValueError('Jenis atau ukuran berkas arsip tidak valid.')
                destination = stage.joinpath(*PurePosixPath(name).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                count = 0
                with bundle.open(info) as source, destination.open('xb') as target:
                    while chunk := source.read(1024 * 1024):
                        count += len(chunk)
                        if count > size:
                            raise ValueError('Isi berkas melebihi manifest.')
                        digest.update(chunk)
                        target.write(chunk)
                if count != size or digest.hexdigest() != expected:
                    raise ValueError('Hash atau ukuran berkas tidak cocok.')
                if name in ('runtime/agent.sqlite3', 'runtime/engagements.sqlite3'):
                    uri = destination.resolve().as_uri() + '?mode=ro&immutable=1'
                    with closing(sqlite3.connect(uri, uri=True)) as db:
                        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                            raise ValueError('Database cadangan rusak.')
        return stage, manifest
    except (Exception, KeyboardInterrupt):
        shutil.rmtree(stage, ignore_errors=True)
        raise


def deactivate_restored_actions(stage):
    """Disable old approvals on an isolated staged copy, preserving audit history.

    Do not call this against an active data directory. This is a preparation step,
    not an operation that installs or starts the recovered workspace.
    """
    from engagements import EngagementStore
    from security_jobs import JobStore
    from security_evidence import EvidenceStore
    from mcp_gateway import MCPGateway
    from security_orchestration import OrchestrationStore
    from security_agents import SpecialistStore

    runtime = Path(stage) / 'runtime'
    if not (runtime / 'agent.sqlite3').is_file() or not (runtime / 'engagements.sqlite3').is_file():
        raise ValueError('Cadangan tidak memiliki database runtime yang lengkap.')
    engagements = EngagementStore(runtime)
    jobs = JobStore(engagements)
    evidence = EvidenceStore(engagements, jobs)
    gateway = MCPGateway(engagements, jobs, evidence, runtime)
    orchestration = OrchestrationStore(engagements, jobs, gateway, evidence)
    specialists = SpecialistStore(engagements, jobs, evidence)
    note = 'Pemulihan cadangan: tindakan lama dihentikan dan memerlukan peninjauan baru.'
    with engagements.transaction() as db:
        orchestration.recover(db)
        specialists.recover(db)
        for row in db.execute("SELECT * FROM security_jobs WHERE status IN ('awaiting_approval','queued','running')").fetchall():
            jobs.finish(db, row, 'cancelled', 'BACKUP_RESTORE', note)
        now = datetime.now(timezone.utc).isoformat()
        for row in db.execute("SELECT * FROM roe_versions WHERE status='approved'").fetchall():
            db.execute("UPDATE roe_versions SET status='revoked',revoked_at=?,revoke_note=? WHERE engagement_id=? AND version=?",
                       (now, note, row['engagement_id'], row['version']))
            engagements.event(db, row['engagement_id'], row['version'], 'revoke', 'backup-restore', note, row['content_hash'])
            db.execute('UPDATE engagements SET revision=revision+1,updated_at=? WHERE id=?', (now, row['engagement_id']))
        for table in ('security_job_worker', 'orchestration_worker', 'specialist_worker', 'mcp_runner_lease'):
            db.execute(f'UPDATE {table} SET owner=NULL,expires_at=NULL WHERE id=1')
    with closing(sqlite3.connect(runtime / 'agent.sqlite3')) as db, db:
        db.execute("UPDATE chat_actions SET state='cancelled' WHERE state IN ('pending','approved')")
        db.execute("UPDATE proposals SET state='rejected' WHERE state='pending'")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'workspace_identity' in tables:
            db.execute('DELETE FROM workspace_identity')
            db.execute('INSERT INTO workspace_identity VALUES (?)', (str(uuid4()),))


def prepare_restore(archive, destination, portable_passphrase=None):
    """Verify and prepare a new, isolated recovery directory without overwriting."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError('Direktori pemulihan sudah ada.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage, manifest = stage_archive(archive, destination.parent)
    try:
        missing = check_recovery_links(stage)
        # ZIP stores files, so an empty workspace must be recreated explicitly.
        (stage / 'workspace').mkdir(exist_ok=True)
        portable = stage / 'runtime/portable-evidence.json'
        if portable.exists():
            from portable_evidence import import_originals
            import_originals(stage / 'runtime/engagements.sqlite3', portable.read_bytes(), portable_passphrase)
            portable.unlink()
        else:
            with closing(sqlite3.connect(stage / 'runtime/engagements.sqlite3')) as db:
                tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'security_evidence_originals' in tables and db.execute('SELECT COUNT(*) FROM security_evidence_originals').fetchone()[0]:
                    from portable_evidence import verify_local_originals
                    verify_local_originals(stage / 'runtime/engagements.sqlite3')
        deactivate_restored_actions(stage)
        # Claim a fresh container atomically; never replace an existing destination.
        destination.mkdir()
        recovered = destination / 'recovered'
        try:
            stage.rename(recovered)
        except Exception:
            destination.rmdir()
            raise
        return {'destination': str(recovered), 'missing_attachments': missing,
                'files': len(manifest['files']), 'excluded': manifest.get('excluded', [])}
    except (Exception, KeyboardInterrupt):
        shutil.rmtree(stage, ignore_errors=True)
        raise


def check_recovery_links(stage):
    """Validate project and attachment links on the staged SQLite snapshots."""
    state = json.loads((stage / 'browser/state.json').read_text(encoding='utf-8'))
    project_ids = validate_browser_state(state)
    runtime = stage / 'runtime'
    if not (runtime / 'engagements.sqlite3').is_file() or not (runtime / 'agent.sqlite3').is_file():
        raise ValueError('Database runtime tidak lengkap.')
    with closing(sqlite3.connect(runtime / 'engagements.sqlite3')) as db:
        security_projects = {row[0] for row in db.execute('SELECT DISTINCT project_id FROM engagements')}
    if not security_projects.issubset(project_ids):
        raise ValueError('Snapshot browser tidak memuat semua project security; gunakan profil browser yang sesuai.')
    with closing(sqlite3.connect(runtime / 'agent.sqlite3')) as db:
        present = {(row[0], row[1]) for row in db.execute('SELECT id,session FROM attachments')}
    return sum((a['id'], row['id']) not in present for tab in TABS for row in state['sessions'][tab]
               for a in row['attachments'])

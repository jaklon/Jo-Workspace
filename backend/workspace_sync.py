"""Versioned workspace records with atomic optimistic writes and tombstones."""
import json
import hashlib
import re
import sqlite3
from uuid import uuid4
from contextlib import closing
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Change(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['project', 'session']
    id: str = Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9_-]+$')
    expected: int = Field(ge=0, strict=True)
    deleted: bool = Field(default=False, strict=True)
    restore: bool = Field(default=False, strict=True)
    data: dict | None = None

    @model_validator(mode='after')
    def check_data(self):
        if self.deleted:
            if self.data is not None or self.expected == 0 or self.restore:
                raise ValueError('Penghapusan memerlukan versi dan tanpa data.')
            return self
        data = self.data
        if self.restore and self.expected == 0:
            raise ValueError('Pemulihan memerlukan versi penghapusan yang ditinjau.')
        if not isinstance(data, dict) or data.get('id') != self.id:
            raise ValueError('ID data tidak cocok.')
        if self.kind == 'project':
            if not isinstance(data.get('name'), str) or not data['name'].strip() or len(data['name']) > 80 or not isinstance(data.get('instructions'), str) or len(data['instructions']) > 1500:
                raise ValueError('Project tidak valid.')
            memory = data.get('memory', [])
            if not isinstance(memory, list) or len(memory) > 50 or any(
                    not isinstance(f, dict) or not isinstance(f.get('text'), str) or not f['text'].strip()
                    or len(f['text']) > 300 or f.get('kind') not in ('goal', 'decision', 'term', 'note')
                    or not isinstance(f.get('source'), dict) or f['source'].get('kind') not in ('manual', 'chat')
                    for f in memory):
                raise ValueError('Memori project tidak valid.')
        else:
            if data.get('tab') not in ('chat', 'code', 'vision', 'docs', 'pentest') or not isinstance(data.get('title'), str) or len(data['title']) > 100:
                raise ValueError('Chat tidak valid.')
            messages, attachments = data.get('messages'), data.get('attachments')
            if not isinstance(messages, list) or len(messages) > 100 or not isinstance(attachments, list) or len(attachments) > 4:
                raise ValueError('Pesan atau lampiran tidak valid.')
            if any(not isinstance(m, dict) or m.get('role') not in ('user', 'assistant') or not isinstance(m.get('content'), str) or len(m['content']) > 200000 for m in messages):
                raise ValueError('Pesan tidak valid.')
            if any(not isinstance(a, dict) or not isinstance(a.get('id'), str) or len(a['id']) > 100 for a in attachments):
                raise ValueError('Lampiran tidak valid.')
            if data.get('projectId') is not None and (not isinstance(data['projectId'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', data['projectId'])):
                raise ValueError('ID project tidak valid.')
        if len(json.dumps(data, ensure_ascii=False).encode('utf-8')) > 2_000_000:
            raise ValueError('Data melebihi batas 2 MB per item.')
        return self


class Batch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    request_id: str = Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9_-]+$')
    changes: list[Change] = Field(min_length=1, max_length=100)

    @model_validator(mode='after')
    def unique(self):
        keys = [(c.kind, c.id) for c in self.changes]
        if len(keys) != len(set(keys)):
            raise ValueError('Item duplikat dalam batch.')
        return self


class WorkspaceSync:
    def __init__(self, store, engagements):
        self.store, self.engagements = store, engagements
        with closing(store.connect()) as db, db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS workspace_changes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, id TEXT NOT NULL,
                    deleted INTEGER NOT NULL, payload TEXT);
                CREATE TABLE IF NOT EXISTS workspace_records (
                    kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
                    deleted INTEGER NOT NULL, payload TEXT, PRIMARY KEY(kind,id));
                CREATE TABLE IF NOT EXISTS workspace_requests (
                    id TEXT PRIMARY KEY, body TEXT NOT NULL, result TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workspace_identity (id TEXT PRIMARY KEY);
            ''')
            if not db.execute('SELECT id FROM workspace_identity LIMIT 1').fetchone():
                db.execute('INSERT INTO workspace_identity VALUES (?)', (str(uuid4()),))

    def changes(self, after, limit=500):
        with closing(self.store.connect()) as db:
            rows = []
            size = 0
            has_more = False
            for row in db.execute('SELECT version,kind,id,deleted,payload FROM workspace_records WHERE version>? ORDER BY version LIMIT ?', (after, limit + 1)):
                item_size = len(row[4].encode('utf-8')) if row[4] else 0
                if len(rows) >= limit or (rows and size + item_size > 4_000_000):
                    has_more = True
                    break
                rows.append(row)
                size += item_size
            identity = db.execute('SELECT id FROM workspace_identity LIMIT 1').fetchone()[0]
        return {'items': [{'version': row[0], 'kind': row[1], 'id': row[2], 'deleted': bool(row[3]),
                          'data': json.loads(row[4]) if row[4] else None} for row in rows],
                'cursor': rows[-1][0] if rows else after, 'has_more': has_more, 'workspace_id': identity}

    def apply(self, batch):
        body = hashlib.sha256(batch.model_dump_json().encode('utf-8')).hexdigest()
        # Serialize security project creation/deletion with workspace deletion.
        with self.engagements.transaction() as security, closing(self.store.connect()) as db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('BEGIN IMMEDIATE')
            try:
                previous = db.execute('SELECT body,result FROM workspace_requests WHERE id=?', (batch.request_id,)).fetchone()
                if previous:
                    if previous[0] != body:
                        raise HTTPException(409, 'ID permintaan sudah digunakan untuk data berbeda.')
                    db.commit()
                    return json.loads(previous[1])
                conflicts = []
                for change in batch.changes:
                    current = db.execute('SELECT version,deleted,payload FROM workspace_records WHERE kind=? AND id=?', (change.kind, change.id)).fetchone()
                    version = current[0] if current else 0
                    if version != change.expected or (current and current[1] and not change.deleted and not change.restore) or (change.restore and (not current or not current[1])):
                        conflicts.append({'kind': change.kind, 'id': change.id, 'version': version, 'deleted': bool(current and current[1]), 'data': json.loads(current[2]) if current and current[2] else None})
                    if change.kind == 'project' and change.deleted and security.execute('SELECT 1 FROM engagements WHERE project_id=? LIMIT 1', (change.id,)).fetchone():
                        raise HTTPException(409, 'Project memiliki riwayat security dan tidak dapat dihapus.')
                if conflicts:
                    raise HTTPException(409, detail={'message': 'Konflik sinkronisasi; perubahan lokal dipertahankan.', 'conflicts': conflicts})
                results = []
                for change in batch.changes:
                    payload = json.dumps(change.data, ensure_ascii=False, separators=(',', ':')) if change.data is not None else None
                    cursor = db.execute('INSERT INTO workspace_changes(kind,id,deleted,payload) VALUES (?,?,?,NULL)', (change.kind, change.id, int(change.deleted)))
                    version = cursor.lastrowid
                    db.execute('INSERT INTO workspace_records VALUES (?,?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET version=excluded.version,deleted=excluded.deleted,payload=excluded.payload', (change.kind, change.id, version, int(change.deleted), payload))
                    results.append({'kind': change.kind, 'id': change.id, 'version': version, 'deleted': change.deleted})
                if db.execute("SELECT COUNT(*) FROM workspace_records WHERE kind='project' AND deleted=0").fetchone()[0] > 500:
                    raise HTTPException(409, 'Batas 500 project tercapai.')
                counts = {}
                for row in db.execute("SELECT payload FROM workspace_records WHERE kind='session' AND deleted=0"):
                    session = json.loads(row[0])
                    tab = session.get('tab')
                    counts[tab] = counts.get(tab, 0) + 1
                    if counts[tab] > 500:
                        raise HTTPException(409, 'Batas 500 chat per mode tercapai.')
                    project = session.get('projectId')
                    if project and not db.execute("SELECT 1 FROM workspace_records WHERE kind='project' AND id=? AND deleted=0", (project,)).fetchone():
                        raise HTTPException(409, 'Chat merujuk project yang tidak tersedia.')
                result = {'items': results}
                db.execute('INSERT INTO workspace_requests VALUES (?,?,?)', (batch.request_id, body, json.dumps(result)))
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise


router = APIRouter(prefix='/api/workspace-sync', tags=['Workspace sync'])


@router.get('/changes')
def get_changes(request: Request, after: int = 0):
    if after < 0:
        raise HTTPException(422, 'Cursor tidak valid.')
    return request.app.state.workspace_sync.changes(after)


@router.post('/changes')
def post_changes(batch: Batch, request: Request):
    return request.app.state.workspace_sync.apply(batch)

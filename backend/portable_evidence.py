"""Passphrase-protected transfer of DPAPI evidence without plaintext files."""
import base64
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import evidence_archive

AAD = b'jo-workspace-portable-evidence-v1'
MAX_ORIGINAL_BYTES = 50 * 1024 * 1024


def verify_local_originals(database):
    with closing(sqlite3.connect(Path(database))) as db:
        rows = db.execute('SELECT o.evidence_id, o.cipher, e.original_hash FROM security_evidence_originals o JOIN security_evidence e ON e.id=o.evidence_id').fetchall()
        count = db.execute('SELECT COUNT(*) FROM security_evidence_originals').fetchone()[0]
    if count != len(rows) or (rows and not evidence_archive.available()):
        raise ValueError('Evidence asli tidak dapat diperiksa dengan akun Windows ini.')
    for eid, cipher, digest in rows:
        try:
            raw = evidence_archive.unprotect(cipher, eid, digest)
            if hashlib.sha256(raw.encode('utf-8')).hexdigest() != digest:
                raise ValueError('hash')
        except Exception as exc:
            raise ValueError('Evidence DPAPI tidak dapat dibuka pada akun ini; butuh cadangan portabel.') from exc


def key_for(passphrase, salt):
    if not isinstance(passphrase, str) or len(passphrase) < 12 or len(passphrase) > 1024:
        raise ValueError('Frasa sandi harus memiliki 12–1024 karakter.')
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode('utf-8'))


def export_originals(database, passphrase):
    with closing(sqlite3.connect(Path(database))) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'security_evidence_originals' not in tables:
            return None
        rows = db.execute('SELECT o.evidence_id, o.cipher, e.original_hash FROM security_evidence_originals o JOIN security_evidence e ON e.id=o.evidence_id').fetchall()
        total = db.execute('SELECT COUNT(*) FROM security_evidence_originals').fetchone()[0]
    if total != len(rows):
        raise ValueError('Arsip evidence asli memiliki referensi yang tidak valid.')
    if not rows:
        return None
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValueError('Frasa sandi diperlukan untuk menyimpan evidence asli secara portabel.')
    if not evidence_archive.available():
        raise ValueError('DPAPI akun asal diperlukan untuk memindahkan evidence asli.')
    originals, size = [], 0
    for eid, cipher, digest in rows:
        try:
            raw = evidence_archive.unprotect(cipher, eid, digest)
        except Exception as exc:
            raise ValueError('Evidence asli tidak dapat dibuka oleh akun Windows ini.') from exc
        data = raw.encode('utf-8')
        size += len(data)
        if size > MAX_ORIGINAL_BYTES or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Evidence asli rusak atau melebihi batas backup portabel.')
        originals.append({'id': eid, 'hash': digest, 'text': raw})
    salt, nonce = os.urandom(16), os.urandom(12)
    plaintext = json.dumps(originals, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    ciphertext = AESGCM(key_for(passphrase, salt)).encrypt(nonce, plaintext, AAD)
    return json.dumps({'version': 1, 'salt': base64.b64encode(salt).decode('ascii'),
                       'nonce': base64.b64encode(nonce).decode('ascii'),
                       'ciphertext': base64.b64encode(ciphertext).decode('ascii')}).encode('utf-8')


def import_originals(database, envelope, passphrase):
    try:
        payload = json.loads(envelope)
        if payload['version'] != 1:
            raise ValueError('Versi evidence portabel tidak didukung.')
        salt = base64.b64decode(payload['salt'], validate=True)
        nonce = base64.b64decode(payload['nonce'], validate=True)
        encrypted = base64.b64decode(payload['ciphertext'], validate=True)
        if len(salt) != 16 or len(nonce) != 12 or len(encrypted) > MAX_ORIGINAL_BYTES * 2:
            raise ValueError('Format evidence portabel tidak valid.')
        originals = json.loads(AESGCM(key_for(passphrase, salt)).decrypt(nonce, encrypted, AAD))
    except Exception as exc:
        raise ValueError('Frasa sandi salah atau evidence portabel rusak.') from exc
    if not isinstance(originals, list) or not evidence_archive.available():
        raise ValueError('DPAPI akun tujuan diperlukan untuk memulihkan evidence asli.')
    with closing(sqlite3.connect(Path(database))) as db, db:
        expected = dict(db.execute('SELECT o.evidence_id, e.original_hash FROM security_evidence_originals o JOIN security_evidence e ON e.id=o.evidence_id'))
        if db.execute('SELECT COUNT(*) FROM security_evidence_originals').fetchone()[0] != len(expected):
            raise ValueError('Referensi evidence asli tidak valid.')
        if len(originals) != len(expected):
            raise ValueError('Jumlah evidence portabel tidak sesuai database.')
        seen = set()
        for item in originals:
            if not isinstance(item, dict) or not isinstance(item.get('text'), str):
                raise ValueError('Evidence portabel tidak valid.')
            eid, digest, raw = item.get('id'), item.get('hash'), item['text']
            if eid in seen or eid not in expected or digest != expected[eid] or hashlib.sha256(raw.encode('utf-8')).hexdigest() != digest:
                raise ValueError('Identitas atau hash evidence portabel tidak cocok.')
            seen.add(eid)
            cipher = evidence_archive.protect(raw, eid, digest)
            db.execute('UPDATE security_evidence_originals SET cipher=? WHERE evidence_id=?', (cipher, eid))

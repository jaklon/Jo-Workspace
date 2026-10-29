"""Bounded durable attachments, write proposals and audit metadata."""
import json
import secrets
import sqlite3
import time
from config import DATA_DIR


class Store:
    def __init__(self, directory=DATA_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "agent.sqlite3"
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS attachments (
                    id TEXT PRIMARY KEY, session TEXT NOT NULL, name TEXT NOT NULL,
                    kind TEXT NOT NULL, content TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS proposals (
                    id TEXT PRIMARY KEY, session TEXT NOT NULL, payload TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, action TEXT NOT NULL, detail TEXT NOT NULL, created REAL NOT NULL);
            """)

    def connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def add_attachment(self, session, name, kind, content):
        attachment_id = secrets.token_urlsafe(18)
        with self.connect() as db:
            # Browser sessions are local-only, so orphaned server-side material
            # needs a deterministic retention window as well as a size ceiling.
            db.execute("DELETE FROM attachments WHERE created < ?", (time.time() - 30 * 86400,))
            total = db.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(content)),0) FROM attachments").fetchone()
            if total[0] >= 500 or total[1] + len(content) > 50_000_000:
                raise ValueError("Penyimpanan lampiran penuh. Hapus lampiran lama sebelum mengunggah lagi.")
            db.execute("INSERT INTO attachments VALUES (?,?,?,?,?,?)", (attachment_id, session, name, kind, content, time.time()))
        return {"id": attachment_id, "filename": name, "kind": kind}

    def attachment(self, attachment_id, session):
        with self.connect() as db:
            row = db.execute("SELECT name,kind,content FROM attachments WHERE id=? AND session=?", (attachment_id, session)).fetchone()
        if not row:
            raise ValueError("Lampiran tidak tersedia pada sesi ini. Unggah ulang dokumen/gambar.")
        return {"id": attachment_id, "name": row[0], "kind": row[1], "content": row[2]}

    def delete_attachment(self, attachment_id, session):
        with self.connect() as db:
            db.execute("DELETE FROM attachments WHERE id=? AND session=?", (attachment_id, session))

    def propose(self, session, payload):
        proposal_id = secrets.token_urlsafe(18)
        with self.connect() as db:
            db.execute("DELETE FROM proposals WHERE created < ?", (time.time() - 86400,))
            if db.execute("SELECT COUNT(*) FROM proposals WHERE state='pending'").fetchone()[0] >= 100:
                raise ValueError("Terlalu banyak proposal tertunda.")
            db.execute("INSERT INTO proposals(id,session,payload,created) VALUES (?,?,?,?)", (proposal_id, session, json.dumps(payload), time.time()))
        return {"id": proposal_id, "path": payload["path"], "diff": payload["diff"]}

    def pending(self, proposal_id, session):
        with self.connect() as db:
            row = db.execute("SELECT payload FROM proposals WHERE id=? AND session=? AND state='pending' AND created>?", (proposal_id, session, time.time()-86400)).fetchone()
        if not row:
            raise ValueError("Proposal tidak ditemukan, kedaluwarsa, atau sudah diproses.")
        return json.loads(row[0])

    def finish(self, proposal_id, state):
        with self.connect() as db:
            db.execute("UPDATE proposals SET state=? WHERE id=?", (state, proposal_id))
        self.audit("proposal_"+state, {"id": proposal_id})

    def audit(self, action, detail):
        with self.connect() as db:
            db.execute("INSERT INTO audit(action,detail,created) VALUES (?,?,?)", (action, json.dumps(detail), time.time()))
            db.execute("DELETE FROM audit WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM audit)")

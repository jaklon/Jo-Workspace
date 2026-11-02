"""Bounded durable attachments, write proposals and audit metadata."""
import json
import secrets
import sqlite3
import time
from contextlib import closing
from config import DATA_DIR


class Store:
    def __init__(self, directory=DATA_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "agent.sqlite3"
        with closing(self.connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS attachments (
                    id TEXT PRIMARY KEY, session TEXT NOT NULL, name TEXT NOT NULL,
                    kind TEXT NOT NULL, content TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS proposals (
                    id TEXT PRIMARY KEY, session TEXT NOT NULL, payload TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, action TEXT NOT NULL, detail TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS chat_actions (
                    id TEXT PRIMARY KEY, session TEXT NOT NULL, payload TEXT NOT NULL,
                    state TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS chat_code_proposals (
                    proposal_id TEXT PRIMARY KEY, session TEXT NOT NULL, action_id TEXT NOT NULL);
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
        return {"id": proposal_id, "path": payload["path"], "diff": payload["diff"],
                "hunks": payload.get("hunks", []), "review": payload.get("review")}

    def propose_chat_action(self, session, payload):
        action_id = secrets.token_urlsafe(18)
        with closing(self.connect()) as db, db:
            db.execute("DELETE FROM chat_actions WHERE created < ?", (time.time() - 86400,))
            if db.execute("SELECT COUNT(*) FROM chat_actions WHERE state='pending'").fetchone()[0] >= 100:
                raise ValueError("Terlalu banyak rencana chat tertunda.")
            db.execute("INSERT INTO chat_actions VALUES (?,?,?,'pending',?)",
                       (action_id, session, json.dumps(payload, ensure_ascii=False), time.time()))
        return {"id": action_id, **payload}

    def decide_chat_action(self, action_id, session, approve):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload FROM chat_actions WHERE id=? AND session=? AND state='pending' AND created>?",
                             (action_id, session, time.time() - 86400)).fetchone()
            if not row:
                raise ValueError("Rencana tidak ditemukan, kedaluwarsa, atau sudah diproses.")
            db.execute("UPDATE chat_actions SET state=? WHERE id=?", ("approved" if approve else "rejected", action_id))
        self.audit("chat_action_approved" if approve else "chat_action_rejected", {"id": action_id})
        return json.loads(row[0])

    def pending_chat_action(self, action_id, session):
        with closing(self.connect()) as db:
            row = db.execute("SELECT payload FROM chat_actions WHERE id=? AND session=? AND state='pending' AND created>?",
                             (action_id, session, time.time() - 86400)).fetchone()
        if not row:
            raise ValueError("Rencana tidak ditemukan, kedaluwarsa, atau sudah diproses.")
        return json.loads(row[0])

    def approved_upload(self, action_id, session, consume=False):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload FROM chat_actions WHERE id=? AND session=? AND state='approved' AND created>?",
                             (action_id, session, time.time() - 1800)).fetchone()
            if not row:
                raise ValueError("Persetujuan lampiran tidak tersedia, kedaluwarsa, atau sudah digunakan.")
            payload = json.loads(row[0])
            if payload.get('intent') != 'attachment':
                raise ValueError("Persetujuan bukan untuk lampiran.")
            if consume:
                db.execute("UPDATE chat_actions SET state='consumed' WHERE id=?", (action_id,))
            return payload

    def authorize_code_proposals(self, session, action_id, proposal_ids):
        with closing(self.connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT payload FROM chat_actions WHERE id=? AND session=? AND state='approved'", (action_id, session)).fetchone()
            if not row or json.loads(row[0]).get('intent') != 'coding':
                raise ValueError('Proposal kode tidak terikat pada aksi chat yang disetujui.')
            for proposal_id in proposal_ids:
                if not db.execute("SELECT 1 FROM proposals WHERE id=? AND session=? AND state='pending'", (proposal_id, session)).fetchone():
                    raise ValueError('Proposal kode tidak tersedia pada sesi ini.')
                db.execute('INSERT INTO chat_code_proposals VALUES (?,?,?)', (proposal_id, session, action_id))

    def require_chat_code_proposal(self, proposal_id, session):
        with closing(self.connect()) as db:
            row = db.execute('SELECT 1 FROM chat_code_proposals WHERE proposal_id=? AND session=?', (proposal_id, session)).fetchone()
        if not row:
            raise ValueError('Proposal kode tidak memiliki persetujuan awal melalui chat.')

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
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO audit(action,detail,created) VALUES (?,?,?)", (action, json.dumps(detail), time.time()))
            db.execute("DELETE FROM audit WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM audit)")

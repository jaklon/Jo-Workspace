"""Persistent jobs: offline policy by default; pinned MCP fixture via isolated gateway only."""
import asyncio
import base64
import time
from contextlib import closing
from datetime import datetime, timedelta
import hashlib
import json
import re
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field, StrictBool, StrictInt, SecretStr, field_validator

from engagements import StrictModel, ScopeAsset, EngagementContent, PolicyProposal, utc_now
from security_policy import evaluate
from mcp_contracts import MCPBinding
from web_checks import WebBinding, validate_plan
from security import SafeValidationRoute
from bounded_scan import ScanBinding, validate_scan, uses_pinned_url

MAX_JOBS = 100
MAX_STEPS = 20
LEASE_SECONDS = 10
ACTIVE = ("awaiting_approval", "queued", "running")
TERMINAL = ("completed", "failed", "cancelled")


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


class JobStep(StrictModel):
    target: ScopeAsset
    action: Literal["tcp_discovery", "http_headers", "unauthenticated_access_check", "service_inventory", "scoped_spider", "active_reflection", "configuration_review", "document_review", "authenticated_api_review", "monitoring_read", "passive_recon"]
    ports: list[StrictInt] = Field(default_factory=list, max_length=100)
    max_http_rps: int = Field(default=1, ge=1, le=15, strict=True)
    max_concurrency: int = Field(default=1, ge=1, le=4, strict=True)
    max_duration_minutes: int = Field(default=1, ge=1, le=240, strict=True)
    test_account_ref: str = Field(default="", max_length=120)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value):
        return EngagementContent.valid_ports(value)


class RoeBinding(StrictModel):
    expected_roe_revision: int = Field(ge=1, strict=True)
    roe_version: int = Field(ge=1, strict=True)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class CreateJob(RoeBinding):
    name: str = Field(min_length=1, max_length=120)
    steps: list[JobStep] = Field(min_length=1, max_length=MAX_STEPS)
    wall_timeout_seconds: int = Field(default=60, ge=1, le=300, strict=True)
    max_output_kb: int = Field(default=64, ge=1, le=64, strict=True)
    mcp: MCPBinding | None = None
    web: WebBinding | None = None
    scan: ScanBinding | None = None


class Approval(StrictModel):
    expected_revision: int = Field(ge=1, strict=True)
    actor_label: str = Field(min_length=1, max_length=120)
    note: str = Field(min_length=1, max_length=1000)
    acknowledge: StrictBool
    session_tokens: list[SecretStr] | None = Field(default=None, min_length=2, max_length=2)

    @field_validator('session_tokens')
    @classmethod
    def valid_sessions(cls,value):
        if value is not None:
            tokens=[item.get_secret_value() for item in value]
            if len(set(tokens))!=2 or any(len(token)>4096 or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}',token) for token in tokens):
                raise ValueError('Dua token sesi uji berbeda dengan format JWT diperlukan.')
            try:
                claims=[]
                for token in tokens:
                    payload=token.split('.')[1]
                    row=json.loads(base64.urlsafe_b64decode(payload+'='*((-len(payload))%4)))
                    if not isinstance(row,dict) or not isinstance(row.get('sub'),str) or not row['sub'] or not isinstance(row.get('aud'),str) or not row['aud']:
                        raise ValueError('JWT claims missing')
                    if 'exp' in row and (not isinstance(row['exp'],(int,float)) or row['exp']<=time.time()):raise ValueError('JWT expired')
                    claims.append(row)
                if claims[0]['sub']==claims[1]['sub'] or claims[0]['aud']!=claims[1]['aud']:raise ValueError('Account identity mismatch')
            except (ValueError,TypeError,UnicodeError,KeyError):
                raise ValueError('Token harus belum kedaluwarsa dan berasal dari dua akun berbeda pada project yang sama.') from None
        return value


class Stop(StrictModel):
    actor_label: str = Field(default="operator-lokal", min_length=1, max_length=120)
    note: str = Field(default="Penghentian darurat oleh operator lokal.", min_length=1, max_length=1000)


class GateDecision(RoeBinding):
    expected_gate_revision: int = Field(ge=1, strict=True)
    actor_label: str = Field(min_length=1, max_length=120)
    note: str = Field(min_length=1, max_length=1000)
    acknowledge: StrictBool


class RetryJob(RoeBinding):
    expected_revision: int = Field(ge=1, strict=True)


class JobStore:
    def __init__(self, engagements, clock=None):
        self.engagements = engagements
        self.gateway = None
        self.web_runner = None
        self.scan_runner = None
        self.orchestrations = None
        self.specialists = None
        self.clock = clock or utc_now
        from session_vault import SessionVault
        self.sessions = SessionVault()
        with closing(engagements.connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS security_jobs (
                    id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL REFERENCES engagements(id), project_id TEXT NOT NULL,
                    plan TEXT NOT NULL, plan_hash TEXT NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, approved_at TEXT, approver TEXT, approval_note TEXT,
                    started_at TEXT, finished_at TEXT, worker TEXT, progress INTEGER NOT NULL DEFAULT 0,
                    output_bytes INTEGER NOT NULL DEFAULT 0, error_code TEXT, error_message TEXT,
                    attempt INTEGER NOT NULL DEFAULT 1, retry_of TEXT, retry_job_id TEXT
                );
                CREATE INDEX IF NOT EXISTS security_jobs_engagement ON security_jobs(engagement_id,created_at);
                CREATE TABLE IF NOT EXISTS security_job_results (
                    job_id TEXT NOT NULL REFERENCES security_jobs(id), ordinal INTEGER NOT NULL, result TEXT NOT NULL,
                    PRIMARY KEY(job_id,ordinal)
                );
                CREATE TABLE IF NOT EXISTS security_job_events (
                    id INTEGER PRIMARY KEY, job_id TEXT NOT NULL REFERENCES security_jobs(id), at TEXT NOT NULL,
                    action TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_engagement_gates (
                    engagement_id TEXT PRIMARY KEY REFERENCES engagements(id), stopped INTEGER NOT NULL,
                    revision INTEGER NOT NULL, updated_at TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_job_worker (
                    id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT, expires_at TEXT
                );
            """)

    def event(self, db, jid, action, actor="system", note=""):
        db.execute("INSERT INTO security_job_events(job_id,at,action,actor,note) VALUES (?,?,?,?,?)", (jid, self.clock().isoformat(), action, actor, note))

    def job(self, db, project, eid, jid, expected=None):
        row = db.execute("SELECT * FROM security_jobs WHERE id=? AND project_id=? AND engagement_id=?", (jid, project, eid)).fetchone()
        if row is None:
            raise HTTPException(404, "Job tidak ditemukan pada engagement ini.")
        if expected is not None and row["revision"] != expected:
            raise HTTPException(409, "Job telah berubah. Muat ulang sebelum mencatat persetujuan.")
        return row

    def gate(self, db, eid):
        row = db.execute("SELECT * FROM security_engagement_gates WHERE engagement_id=?", (eid,)).fetchone()
        return dict(row) if row else {"engagement_id": eid, "stopped": False, "revision": 1, "updated_at": None, "actor": None, "note": ""}

    def open_gate(self, db, eid):
        if self.gate(db, eid)["stopped"]:
            raise HTTPException(423, "Engagement dihentikan. Buka kembali secara eksplisit sebelum membuat atau menyetujui job baru.")

    def binding(self, db, project, eid, payload):
        engagement, head = self.engagements.head(db, project, eid, payload.expected_roe_revision)
        if payload.roe_version != head["version"] or payload.content_hash != head["content_hash"]:
            raise HTTPException(409, "Versi/hash RoE berubah. Gunakan snapshot terkini.")
        return engagement, head

    def worker_active(self, db):
        lease = db.execute("SELECT * FROM security_job_worker WHERE id=1").fetchone()
        return bool(lease and lease["owner"] and lease["expires_at"] > self.clock().isoformat())

    def create_in(self, db, project, eid, payload, attempt=1, retry_of=None):
        self.binding(db, project, eid, payload)
        self.open_gate(db, eid)
        if db.execute("SELECT COUNT(*) FROM security_jobs WHERE engagement_id=?", (eid,)).fetchone()[0] >= MAX_JOBS:
            raise HTTPException(409, "Batas 100 job per engagement tercapai. Riwayat dipertahankan.")
        jid, now = str(uuid4()), self.clock().isoformat()
        plan = payload.model_dump(mode="json")
        try:
            validate_plan(plan)
            validate_scan(plan)
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc
        if plan.get('mcp'):
            if self.gateway is None:raise HTTPException(503,'MCP gateway belum siap.')
            self.gateway.validate(db,plan)
        db.execute("INSERT INTO security_jobs(id,engagement_id,project_id,plan,plan_hash,status,revision,created_at,updated_at,attempt,retry_of) VALUES (?,?,?,?,?,'awaiting_approval',1,?,?,?,?)", (jid, eid, project, encode(plan), digest(plan), now, now, attempt, retry_of))
        self.event(db, jid, "created", "operator-lokal", "Rencana adapter dibuat; menunggu persetujuan." if plan.get('scan') else "Rencana validasi offline; tidak ada tool yang dijalankan.")
        return jid

    def create(self, project, eid, payload):
        with self.engagements.transaction() as db:
            jid = self.create_in(db, project, eid, payload)
        return self.detail(project, eid, jid)

    def detail(self, project, eid, jid):
        with closing(self.engagements.connect()) as db:
            db.execute("BEGIN")
            row = self.job(db, project, eid, jid)
            result = self.serialize(row)
            result["results"] = [{"ordinal": r["ordinal"], "result": json.loads(r["result"])} for r in db.execute("SELECT * FROM security_job_results WHERE job_id=? ORDER BY ordinal", (jid,))]
            result["events"] = [dict(r) for r in db.execute("SELECT * FROM security_job_events WHERE job_id=? ORDER BY id", (jid,))]
            if result['plan'].get('mcp') and self.gateway:
                result['mcp_result'] = self.gateway.result(project,eid,jid)
            if result['plan'].get('web') and self.web_runner:
                result['web_result'] = self.web_runner.result(db,jid)
            if result['plan'].get('scan') and self.scan_runner:
                result['scan_result'] = self.scan_runner.result(db,jid)
            return result

    def serialize(self, row):
        result = dict(row)
        result["plan"] = json.loads(result["plan"])
        result.update(mode="offline_policy_validation", execution_enabled=False, grants_execution=False)
        if result['plan'].get('mcp'):result['mode']='isolated_mcp_fixture'
        if result['plan'].get('web'):result['mode']='approved_public_url_head'
        if result['plan'].get('scan'):result.update(mode='approved_tcp_scan',execution_enabled=True)
        return result

    def listing(self, project, eid):
        with closing(self.engagements.connect()) as db:
            db.execute("BEGIN")
            self.engagements.head(db, project, eid)
            rows = [self.serialize(row) for row in db.execute("SELECT * FROM security_jobs WHERE project_id=? AND engagement_id=? ORDER BY created_at DESC,id DESC", (project, eid))]
            return {"items": rows, "gate": self.gate(db, eid), "worker_active": self.worker_active(db), "limits": {"max_jobs": MAX_JOBS, "max_steps": MAX_STEPS, "max_concurrency": 1, "max_wall_seconds": 300, "max_output_kb": 64, "max_attempts": 3}, "execution_enabled": False, "mode": "offline_policy_validation"}

    def proposals(self, plan):
        return [PolicyProposal.model_validate({**step, "expected_revision": plan["expected_roe_revision"], "roe_version": plan["roe_version"], "content_hash": plan["content_hash"]}) for step in plan["steps"]]

    def approve(self, project, eid, jid, payload):
        with self.engagements.transaction() as db:
            self.approve_in(db, project, eid, jid, payload)
        return self.detail(project, eid, jid)

    def approve_in(self, db, project, eid, jid, payload):
        if not payload.acknowledge:
            raise HTTPException(422, "Konfirmasi persetujuan terhadap rencana dan adapter yang dipilih diperlukan.")
        row = self.job(db, project, eid, jid, payload.expected_revision)
        if row["status"] != "awaiting_approval":
            raise HTTPException(409, "Hanya job menunggu persetujuan yang dapat diantrekan.")
        self.open_gate(db, eid)
        plan = json.loads(row["plan"])
        try:
            validate_plan(plan)
            validate_scan(plan)
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc
        if digest(plan) != row["plan_hash"]:
            raise HTTPException(409, "Integritas rencana job tidak sesuai.")
        engagement, head = self.engagements.head(db, project, eid)
        content = EngagementContent.model_validate_json(head["content"])
        denials = []
        for index, proposal in enumerate(self.proposals(plan)):
            report = evaluate(content, head, engagement, proposal, self.clock(), dns_pinning=uses_pinned_url(plan))
            if report["decision"] != "pass":
                denials.append(f"Langkah {index + 1}: " + ", ".join(check["code"] for check in report["checks"] if not check["passed"]))
        if plan["wall_timeout_seconds"] > content.max_duration_minutes * 60:
            denials.append("Durasi job melampaui batas RoE.")
        if denials:
            raise HTTPException(422, {"message": "Job ditolak policy sebelum antrean. Perbaiki rencana atau buat salinan dengan RoE terkini.", "errors": denials})
        if plan.get('mcp'):
            if self.gateway is None:raise HTTPException(503,'MCP gateway belum siap.')
            self.gateway.validate(db,plan)
        if not self.worker_active(db):
            raise HTTPException(503, "Worker offline belum siap. Tunggu sebentar lalu coba lagi.")
        comparison=(plan.get('scan') or {}).get('tool')=='auth-two-session'
        if comparison:
            if not payload.session_tokens:raise HTTPException(422,'Dua sesi uji sementara diperlukan untuk perbandingan.')
            if any(ref not in content.test_account_refs for ref in plan['scan']['account_refs']):
                raise HTTPException(422,'Kedua alias harus tercatat dalam RoE.')
            try:self.sessions.put(jid,[token.get_secret_value() for token in payload.session_tokens])
            except ValueError as exc:raise HTTPException(409,str(exc)) from exc
        elif payload.session_tokens:
            raise HTTPException(422,'Sesi uji hanya untuk perbandingan dua akun.')
        now = self.clock().isoformat()
        db.execute("UPDATE security_jobs SET status='queued',revision=revision+1,updated_at=?,approved_at=?,approver=?,approval_note=? WHERE id=?", (now, now, payload.actor_label, payload.note, jid))
        self.event(db, jid, "approved", payload.actor_label, payload.note)

    def finish(self, db, row, status, code=None, message=None, actor="system"):
        self.sessions.discard(row["id"])
        if row["status"] in TERMINAL:
            return
        now = self.clock().isoformat()
        db.execute("UPDATE security_jobs SET status=?,revision=revision+1,updated_at=?,finished_at=?,error_code=?,error_message=?,worker=NULL WHERE id=?", (status, now, now, code, message, row["id"]))
        self.event(db, row["id"], status, actor, message or "Validasi offline selesai; eksekusi pentest tetap terkunci.")

    def cancel(self, project, eid, jid, payload):
        with self.engagements.transaction() as db:
            row = self.job(db, project, eid, jid)
            self.finish(db, row, "cancelled", "OPERATOR_STOP", payload.note, payload.actor_label)
        return self.detail(project, eid, jid)

    def stop_engagement(self, project, eid, payload):
        with self.engagements.transaction() as db:
            self.engagements.head(db, project, eid)
            gate = self.gate(db, eid)
            if not gate["stopped"]:
                db.execute("INSERT INTO security_engagement_gates VALUES (?,1,?,?,?,?) ON CONFLICT(engagement_id) DO UPDATE SET stopped=1,revision=excluded.revision,updated_at=excluded.updated_at,actor=excluded.actor,note=excluded.note", (eid, gate["revision"] + 1, self.clock().isoformat(), payload.actor_label, payload.note))
                for row in db.execute("SELECT * FROM security_jobs WHERE engagement_id=? AND status IN ('awaiting_approval','queued','running')", (eid,)).fetchall():
                    self.finish(db, row, "cancelled", "ENGAGEMENT_STOP", payload.note, payload.actor_label)
                if self.orchestrations:
                    self.orchestrations.pause_engagement(db,eid,payload.note,payload.actor_label)
                if self.specialists:
                    self.specialists.pause_engagement(db,eid,payload.note,payload.actor_label)
        return self.listing(project, eid)

    def resume_engagement(self, project, eid, payload):
        if not payload.acknowledge:
            raise HTTPException(422, "Konfirmasi pembukaan kembali engagement diperlukan.")
        with self.engagements.transaction() as db:
            _, head = self.binding(db, project, eid, payload)
            gate = self.gate(db, eid)
            if gate["revision"] != payload.expected_gate_revision or not gate["stopped"]:
                raise HTTPException(409, "Status penghentian berubah. Muat ulang terlebih dahulu.")
            content = EngagementContent.model_validate_json(head["content"])
            now = self.clock()
            if head["status"] != "approved" or content.submission_errors() or not content.starts_at <= now < content.ends_at:
                raise HTTPException(409, "RoE terkini harus lengkap, disetujui, dan berada dalam periode aktif.")
            db.execute("UPDATE security_engagement_gates SET stopped=0,revision=revision+1,updated_at=?,actor=?,note=? WHERE engagement_id=?", (now.isoformat(), payload.actor_label, payload.note, eid))
            # Cancelled jobs stay cancelled; reopening grants no automatic resume.
        return self.listing(project, eid)

    def retry(self, project, eid, jid, payload):
        with self.engagements.transaction() as db:
            row = self.job(db, project, eid, jid, payload.expected_revision)
            if row["status"] not in ("failed", "cancelled") or row["attempt"] >= 3 or row["retry_job_id"]:
                raise HTTPException(409, "Hanya job gagal/dibatalkan yang belum diulang dapat disalin; maksimal tiga percobaan.")
            plan = CreateJob.model_validate({**json.loads(row["plan"]), **payload.model_dump(exclude={"expected_revision"})})
            new_id = self.create_in(db, project, eid, plan, row["attempt"] + 1, jid)
            db.execute("UPDATE security_jobs SET revision=revision+1,retry_job_id=?,updated_at=? WHERE id=?", (new_id, self.clock().isoformat(), jid))
            self.event(db, jid, "retry_created", "operator-lokal", new_id)
        return self.detail(project, eid, new_id)

    def acquire(self, owner):
        with self.engagements.transaction() as db:
            now = self.clock()
            row = db.execute("SELECT * FROM security_job_worker WHERE id=1").fetchone()
            if row and row["owner"] != owner and row["expires_at"] and row["expires_at"] > now.isoformat():
                return False
            fresh = not row or row["owner"] != owner or not row["expires_at"] or row["expires_at"] <= now.isoformat()
            db.execute("INSERT INTO security_job_worker VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at", (owner, (now + timedelta(seconds=LEASE_SECONDS)).isoformat()))
            if fresh:
                self.recover(db)
            return True

    def recover(self, db):
        for row in db.execute("SELECT * FROM security_jobs WHERE status IN ('running','queued')").fetchall():
            if row["status"] == "running":
                self.finish(db, row, "failed", "INTERRUPTED", "Worker terputus. Hasil sebelumnya dipertahankan; perlu percobaan dan persetujuan baru.")
            else:
                db.execute("UPDATE security_jobs SET status='awaiting_approval',revision=revision+1,updated_at=?,approved_at=NULL,approver=NULL,approval_note=NULL WHERE id=?", (self.clock().isoformat(), row["id"]))
                self.event(db, row["id"], "reapproval_required", note="Backend dimulai ulang. Antrean tidak dilanjutkan otomatis.")

    def release(self, owner):
        with self.engagements.transaction() as db:
            row = db.execute("SELECT owner FROM security_job_worker WHERE id=1").fetchone()
            if row and row[0] == owner:
                self.recover(db)
                db.execute("UPDATE security_job_worker SET owner=NULL,expires_at=NULL WHERE id=1")

    def owned(self, db, owner):
        row = db.execute("SELECT * FROM security_job_worker WHERE id=1").fetchone()
        return bool(row and row["owner"] == owner and row["expires_at"] > self.clock().isoformat())

    def claim(self, owner):
        with self.engagements.transaction() as db:
            if not self.owned(db, owner) or db.execute("SELECT COUNT(*) FROM security_jobs WHERE status='running'").fetchone()[0]:
                return None
            row = db.execute("SELECT * FROM security_jobs WHERE status='queued' ORDER BY created_at,id LIMIT 1").fetchone()
            if row is None:
                return None
            now = self.clock().isoformat()
            db.execute("UPDATE security_jobs SET status='running',revision=revision+1,updated_at=?,started_at=?,worker=? WHERE id=?", (now, now, owner, row["id"]))
            self.event(db, row["id"], "running", note="Worker memvalidasi policy secara offline. Tidak ada proses scanner.")
            return row["id"]

    def step(self, owner, jid):
        with self.engagements.transaction() as db:
            row = db.execute("SELECT * FROM security_jobs WHERE id=?", (jid,)).fetchone()
            if row is None or row["status"] != "running" or row["worker"] != owner or not self.owned(db, owner):
                return False
            plan = json.loads(row["plan"])
            now = self.clock()
            if digest(plan) != row["plan_hash"]:
                self.finish(db, row, "failed", "PLAN_INTEGRITY", "Hash rencana job tidak sesuai.")
                return False
            if self.gate(db, row["engagement_id"])["stopped"]:
                self.finish(db, row, "cancelled", "ENGAGEMENT_STOP", "Engagement dihentikan.")
                return False
            if (now - datetime.fromisoformat(row["started_at"])).total_seconds() >= plan["wall_timeout_seconds"]:
                self.finish(db, row, "failed", "TIME_LIMIT", "Batas durasi validasi offline tercapai.")
                return False
            index = row["progress"]
            if index >= len(plan["steps"]):
                if plan.get('mcp') or plan.get('web') or plan.get('scan'):return False
                self.finish(db, row, "completed")
                return False
            engagement, head = self.engagements.head(db, row["project_id"], row["engagement_id"])
            content = EngagementContent.model_validate_json(head["content"])
            proposal = self.proposals(plan)[index]
            report = evaluate(content, head, engagement, proposal, now, dns_pinning=uses_pinned_url(plan))
            report.update(mode="offline_policy_validation", tool_executed=False)
            output = encode(report)
            size = len(output.encode())
            if row["output_bytes"] + size > plan["max_output_kb"] * 1024:
                self.finish(db, row, "failed", "OUTPUT_LIMIT", "Batas output tercapai. Hasil langkah sebelumnya dipertahankan.")
                return False
            db.execute("INSERT INTO security_job_results VALUES (?,?,?)", (jid, index + 1, output))
            db.execute("UPDATE security_jobs SET progress=progress+1,output_bytes=output_bytes+?,revision=revision+1,updated_at=? WHERE id=?", (size, now.isoformat(), jid))
            self.event(db, jid, "step_validated", note=f"Langkah {index + 1}: {report['decision']} (tanpa eksekusi).")
            db.execute("UPDATE security_job_worker SET expires_at=? WHERE id=1 AND owner=?", ((now + timedelta(seconds=LEASE_SECONDS)).isoformat(), owner))
            if report["decision"] != "pass":
                self.finish(db, row, "failed", "POLICY_DENIED", "Policy berubah atau menolak tindakan. Lihat hasil langkah; tidak ada tool yang dijalankan.")
                return False
            if index + 1 == len(plan["steps"]):
                if plan.get('mcp') or plan.get('web') or plan.get('scan'):return False
                self.finish(db, row, "completed")
                return False
            return True

    def fail(self, owner, jid, code="VALIDATION_ERROR", message=None):
        with self.engagements.transaction() as db:
            row = db.execute("SELECT * FROM security_jobs WHERE id=?", (jid,)).fetchone()
            if row and row["status"] == "running" and row["worker"] == owner and self.owned(db, owner):
                self.finish(db, row, "failed", code, message or "Validasi offline dihentikan oleh batas durasi atau kegagalan worker. Tidak ada retry otomatis.")


class OfflineJobRunner:
    def __init__(self, store, before_step=None):
        self.store = store
        self.owner = str(uuid4())
        self.before_step = before_step
        self.task = None
        self.stopping = False

    def start(self):
        self.stopping = False
        self.store.acquire(self.owner)
        self.task = asyncio.create_task(self.loop())

    async def stop(self):
        self.stopping = True
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        self.store.release(self.owner)

    async def execute(self, jid):
        with closing(self.store.engagements.connect()) as db:
            row = db.execute("SELECT plan FROM security_jobs WHERE id=?", (jid,)).fetchone()
        if not row:
            return
        timeout = json.loads(row[0])["wall_timeout_seconds"]
        mcp = json.loads(row[0]).get('mcp')
        web = json.loads(row[0]).get('web')
        scan = json.loads(row[0]).get('scan')
        async def steps():
            while not self.stopping:
                await asyncio.sleep(0)
                if self.before_step:
                    await self.before_step()
                if not self.store.step(self.owner, jid):
                    break
            if mcp and not self.stopping:
                if not self.store.gateway:
                    self.store.fail(self.owner,jid,'MCP_UNAVAILABLE')
                else:
                    await self.store.gateway.execute(self.owner,jid)
            if web and not self.stopping:
                if not self.store.web_runner:self.store.fail(self.owner,jid,'WEB_UNAVAILABLE')
                else:await self.store.web_runner.execute(self.owner,jid)
            if scan and not self.stopping:
                if not self.store.scan_runner:self.store.fail(self.owner,jid,'SCAN_UNAVAILABLE')
                else:await self.store.scan_runner.execute(self.owner,jid)
        try:
            await asyncio.wait_for(steps(), timeout=timeout)
        except asyncio.TimeoutError:
            self.store.fail(self.owner, jid, "TIME_LIMIT")
        except asyncio.CancelledError:
            raise
        except Exception:
            self.store.fail(self.owner, jid)

    async def loop(self):
        while not self.stopping:
            try:
                if self.store.acquire(self.owner):
                    jid = self.store.claim(self.owner)
                    if jid:
                        await self.execute(jid)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Lease expiry enables another worker to recover, without replaying jobs.
                pass
            await asyncio.sleep(0.5)


router = APIRouter(prefix="/api/security/projects/{project_id}/engagements/{engagement_id}", tags=["Security jobs — offline/isolated fixture"],route_class=SafeValidationRoute)


@router.get("/jobs")
async def list_jobs(project_id: UUID, engagement_id: UUID, request: Request):
    return request.app.state.jobs.listing(str(project_id), str(engagement_id))


@router.post("/jobs", status_code=201)
async def create_job(project_id: UUID, engagement_id: UUID, payload: CreateJob, request: Request):
    return request.app.state.jobs.create(str(project_id), str(engagement_id), payload)


@router.get("/jobs/{job_id}")
async def get_job(project_id: UUID, engagement_id: UUID, job_id: UUID, request: Request):
    return request.app.state.jobs.detail(str(project_id), str(engagement_id), str(job_id))


@router.post("/jobs/{job_id}/approve")
async def approve_job(project_id: UUID, engagement_id: UUID, job_id: UUID, payload: Approval, request: Request):
    return request.app.state.jobs.approve(str(project_id), str(engagement_id), str(job_id), payload)


@router.post("/jobs/{job_id}/stop")
async def stop_job(project_id: UUID, engagement_id: UUID, job_id: UUID, payload: Stop, request: Request):
    return request.app.state.jobs.cancel(str(project_id), str(engagement_id), str(job_id), payload)


@router.post("/jobs/{job_id}/retry", status_code=201)
async def retry_job(project_id: UUID, engagement_id: UUID, job_id: UUID, payload: RetryJob, request: Request):
    return request.app.state.jobs.retry(str(project_id), str(engagement_id), str(job_id), payload)


@router.post("/stop")
async def stop_engagement(project_id: UUID, engagement_id: UUID, payload: Stop, request: Request):
    return request.app.state.jobs.stop_engagement(str(project_id), str(engagement_id), payload)


@router.post("/resume")
async def resume_engagement(project_id: UUID, engagement_id: UUID, payload: GateDecision, request: Request):
    return request.app.state.jobs.resume_engagement(str(project_id), str(engagement_id), payload)

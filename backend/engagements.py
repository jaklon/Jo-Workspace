"""Engagement/RoE and stage 2 offline policy checks. No scanner or model calls."""
import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
from contextlib import contextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, HTTPException, Request
from pydantic import StrictInt, StrictBool, AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from security_policy import POLICY_VERSION, scope_report, evaluate, enforce_scope_drift, ScopeDriftError

FORBIDDEN = ["DoS/DDoS dan stress testing", "Penghapusan atau modifikasi data/skema", "Pengambilan PII asli", "Eksekusi shell arbitrer"]
ACTIONS = ["tcp_discovery", "http_headers", "unauthenticated_access_check", "service_inventory", "scoped_spider", "active_reflection", "configuration_review", "document_review", "authenticated_api_review", "monitoring_read", "passive_recon"]


def utc_now():
    return datetime.now(timezone.utc)


def domain_name(value):
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Nama domain tidak valid.") from exc
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise ValueError("Gunakan domain eksplisit tanpa wildcard, path, atau port.")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ScopeAsset(StrictModel):
    kind: Literal["ip", "cidr", "domain", "url"]
    value: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def canonical(self):
        value = self.value
        if any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError("Target tidak boleh mengandung spasi atau karakter kontrol.")
        try:
            if self.kind == "ip":
                value = str(ipaddress.ip_address(value))
            elif self.kind == "cidr":
                if "/" not in value:
                    raise ValueError("CIDR harus memiliki prefix.")
                value = str(ipaddress.ip_network(value, strict=True))
            elif self.kind == "domain":
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    pass
                else:
                    raise ValueError("Gunakan jenis IP untuk alamat numerik.")
                value = domain_name(value)
            else:
                parsed = urlsplit(value)
                if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or "\\" in value:
                    raise ValueError("URL scope harus HTTP(S), tanpa kredensial, query, atau fragment.")
                host = parsed.hostname
                try:
                    host = str(ipaddress.ip_address(host))
                    if ":" in host:
                        host = "[" + host + "]"
                except ValueError:
                    host = domain_name(host)
                port = parsed.port
                if port is not None and not 1 <= port <= 65535:
                    raise ValueError("Port URL tidak valid.")
                netloc = host if port is None or (parsed.scheme, port) in (("http", 80), ("https", 443)) else f"{host}:{port}"
                value = urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))
        except ValueError as exc:
            raise ValueError(f"Target {self.kind} tidak valid: {exc}") from exc
        self.value = value
        return self


class EngagementContent(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    objective: str = Field(default="", max_length=3000)
    owner: str = Field(default="", max_length=120)
    contact: str = Field(default="", max_length=200)
    environment: Literal["lab", "development", "staging", "uat", "production_readonly"] = "lab"
    authorization_ref: str = Field(default="", max_length=500)
    in_scope: list[ScopeAsset] = Field(default_factory=list, max_length=100)
    out_of_scope: list[ScopeAsset] = Field(default_factory=list, max_length=100)
    ports: list[StrictInt] = Field(default_factory=list, max_length=100)
    allowed_actions: list[Literal["tcp_discovery", "http_headers", "unauthenticated_access_check", "service_inventory", "scoped_spider", "active_reflection", "configuration_review", "document_review", "authenticated_api_review", "monitoring_read", "passive_recon"]] = Field(default_factory=list, max_length=11)
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    timezone: str = "Asia/Jakarta"
    max_http_rps: int = Field(default=5, ge=1, le=15, strict=True)
    max_concurrency: int = Field(default=1, ge=1, le=4, strict=True)
    max_duration_minutes: int = Field(default=60, ge=1, le=240, strict=True)
    emergency_contact: str = Field(default="", max_length=200)
    stop_conditions: str = Field(default="", max_length=1500)
    test_account_refs: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("timezone")
    @classmethod
    def valid_zone(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("Zona waktu IANA tidak valid.") from exc
        return value

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, value):
        if any(type(port) is not int or not 1 <= port <= 65535 for port in value):
            raise ValueError("Port harus bilangan bulat 1–65535.")
        return sorted(set(value))

    @field_validator("test_account_refs")
    @classmethod
    def valid_refs(cls, value):
        if any(not ref.strip() or len(ref) > 120 for ref in value):
            raise ValueError("Referensi akun uji harus berisi alias 1–120 karakter, bukan kredensial.")
        return list(dict.fromkeys(ref.strip() for ref in value))

    @model_validator(mode="after")
    def consistent(self):
        if self.starts_at and self.ends_at and self.starts_at >= self.ends_at:
            raise ValueError("Akhir periode harus setelah awal periode.")
        included = {(a.kind, a.value) for a in self.in_scope}
        excluded = {(a.kind, a.value) for a in self.out_of_scope}
        if included & excluded:
            raise ValueError("Target yang sama tidak boleh berada di scope dan pengecualian.")
        if len(included) != len(self.in_scope) or len(excluded) != len(self.out_of_scope):
            raise ValueError("Target duplikat tidak diperbolehkan.")
        self.allowed_actions = list(dict.fromkeys(self.allowed_actions))
        return self

    def submission_errors(self):
        fields = {"objective": "Tujuan", "owner": "Pemilik", "contact": "PIC/kontak", "authorization_ref": "Referensi otorisasi", "in_scope": "Target scope", "allowed_actions": "Tindakan yang diizinkan", "starts_at": "Awal periode", "ends_at": "Akhir periode", "emergency_contact": "Kontak darurat", "stop_conditions": "Kondisi penghentian"}
        errors = [label + " wajib diisi." for key, label in fields.items() if not getattr(self, key)]
        if self.ends_at and self.ends_at <= utc_now():
            errors.append("Periode sudah berakhir; tentukan periode baru.")
        if "tcp_discovery" in self.allowed_actions and not self.ports:
            errors.append("Port eksplisit wajib untuk rencana discovery TCP.")
        if "authenticated_api_review" in self.allowed_actions and not self.test_account_refs:
            errors.append("Alias akun uji wajib untuk rencana review API terautentikasi.")
        if self.environment == 'production_readonly' and (self.allowed_actions != ['http_headers'] or self.max_http_rps != 1 or self.max_concurrency != 1):
            errors.append('Production read-only hanya mengizinkan http_headers, 1 request/detik, dan concurrency 1.')
        errors.extend(item["message"] for item in scope_report(self)["findings"] if item["severity"] == "error")
        return errors


class CreateEngagement(StrictModel):
    content: EngagementContent


class EditEngagement(CreateEngagement):
    expected_revision: int = Field(ge=1, strict=True)


class Decision(StrictModel):
    expected_revision: int = Field(ge=1, strict=True)
    action: Literal["submit", "approve", "request_changes", "revoke", "revise"]
    actor_label: str = Field(min_length=1, max_length=120)
    note: str = Field(default="", max_length=1500)
    acknowledge: StrictBool = False


class PolicyProposal(StrictModel):
    expected_revision: int = Field(ge=1, strict=True)
    roe_version: int = Field(ge=1, strict=True)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    target: ScopeAsset
    action: str = Field(min_length=1, max_length=64)
    ports: list[StrictInt] = Field(default_factory=list, max_length=100)
    max_http_rps: int = Field(default=1, ge=1, le=15, strict=True)
    max_concurrency: int = Field(default=1, ge=1, le=4, strict=True)
    max_duration_minutes: int = Field(default=1, ge=1, le=240, strict=True)
    test_account_ref: str = Field(default="", max_length=120)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value):
        return EngagementContent.valid_ports(value)


class SimulationStep(StrictModel):
    tool: str = Field(default="", max_length=64)
    action: str = Field(default="", max_length=64)
    target: ScopeAsset
    ports: list[StrictInt] = Field(default_factory=list, max_length=100)
    max_concurrency: int = Field(default=1, ge=1, le=4, strict=True)
    max_duration_minutes: int = Field(default=1, ge=1, le=240, strict=True)


class SimulationRequest(StrictModel):
    environment: Literal["lab", "development", "staging", "uat", "production_readonly"] = "lab"
    jobs: list[SimulationStep] = Field(min_length=1, max_length=6)


class RiskRequest(StrictModel):
    action: str = Field(default="", max_length=64)
    tool: str = Field(default="", max_length=64)


class ApprovalVerify(RiskRequest):
    session_pin: str = Field(default="", max_length=256)


def snapshot(content):
    payload = json.dumps(content.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return payload, hashlib.sha256(payload.encode()).hexdigest()


class EngagementStore:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "engagements.sqlite3"
        with closing(self.connect()) as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS engagements (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revision INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS engagements_project ON engagements(project_id);
                CREATE TABLE IF NOT EXISTS roe_versions (engagement_id TEXT NOT NULL REFERENCES engagements(id), version INTEGER NOT NULL, status TEXT NOT NULL, content TEXT NOT NULL, content_hash TEXT NOT NULL, submitted_at TEXT, reviewed_at TEXT, reviewer TEXT, review_note TEXT, revoked_at TEXT, revoke_note TEXT, PRIMARY KEY(engagement_id,version));
                CREATE TABLE IF NOT EXISTS engagement_events (id INTEGER PRIMARY KEY, engagement_id TEXT NOT NULL REFERENCES engagements(id), version INTEGER NOT NULL, at TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL, content_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS policy_checks (id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL REFERENCES engagements(id), at TEXT NOT NULL, result TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS policy_checks_engagement ON policy_checks(engagement_id,at);
                CREATE TABLE IF NOT EXISTS scope_violations (id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL REFERENCES engagements(id), at TEXT NOT NULL, surface TEXT NOT NULL, reason TEXT NOT NULL, report TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS scope_violations_engagement ON scope_violations(engagement_id,at);
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def event(self, db, eid, version, action, actor, note, digest):
        db.execute("INSERT INTO engagement_events(engagement_id,version,at,action,actor,note,content_hash) VALUES (?,?,?,?,?,?,?)", (eid, version, utc_now().isoformat(), action, actor, note, digest))

    def head(self, db, project_id, eid, expected=None):
        engagement = db.execute("SELECT * FROM engagements WHERE id=? AND project_id=?", (eid, project_id)).fetchone()
        if engagement is None:
            raise HTTPException(404, "Engagement tidak ditemukan pada project ini.")
        if expected is not None and engagement["revision"] != expected:
            raise HTTPException(409, "Data telah berubah. Muat ulang sebelum menyimpan keputusan.")
        version = db.execute("SELECT * FROM roe_versions WHERE engagement_id=? ORDER BY version DESC LIMIT 1", (eid,)).fetchone()
        return engagement, version

    def detail(self, project_id, eid, history=True):
        with closing(self.connect()) as db:
            db.execute("BEGIN")
            engagement, head = self.head(db, project_id, eid)
            versions = []
            for row in db.execute("SELECT * FROM roe_versions WHERE engagement_id=? ORDER BY version DESC" + ("" if history else " LIMIT 1"), (eid,)):
                item = dict(row)
                content = json.loads(item.pop("content"))
                item["content"] = content
                end = content.get("ends_at")
                effective = item["status"]
                if row["version"] != head["version"]:
                    effective = "superseded"
                elif effective in ("approved", "pending_review") and end and datetime.fromisoformat(end) <= utc_now():
                    effective = "expired"
                item["effective_status"] = effective
                item["submission_errors"] = EngagementContent.model_validate(content).submission_errors()
                item["scope_report"] = scope_report(EngagementContent.model_validate(content))
                versions.append(item)
            events = [dict(row) for row in db.execute("SELECT * FROM engagement_events WHERE engagement_id=? ORDER BY id", (eid,))] if history else []
        return {**dict(engagement), "versions": versions, "events": events, "execution_enabled": False, "forbidden_actions": FORBIDDEN, "approval_mode": "local_attestation"}

    def check_policy(self, project_id, eid, proposal):
        with self.transaction() as db:
            engagement, head = self.head(db, project_id, eid)
            if db.execute("SELECT COUNT(*) FROM policy_checks WHERE engagement_id=?", (eid,)).fetchone()[0] >= 500:
                raise HTTPException(409, "Batas 500 evaluasi policy per engagement tercapai. Riwayat tetap dipertahankan.")
            content = EngagementContent.model_validate_json(head["content"])
            result = evaluate(content, head, engagement, proposal, utc_now())
            result["id"] = str(uuid4())
            db.execute("INSERT INTO policy_checks VALUES (?,?,?,?)", (result["id"], eid, result["evaluated_at"], json.dumps(result, ensure_ascii=False)))
        return result

    def assert_in_scope(self, db, project_id, eid, payload, resolved=None):
        """Scope-drift interceptor: extract every target from a tool-argument
        payload and hard-block (ScopeDriftError) if any leaves the active approved
        scope or a resolved name rebinds to a forbidden/excluded network. Pure —
        does no logging and no DNS; callers resolve names and record violations."""
        _, head = self.head(db, project_id, eid)
        content = EngagementContent.model_validate_json(head["content"])
        return enforce_scope_drift(payload, content.in_scope, content.out_of_scope, content.environment, resolved)

    def record_scope_violation(self, eid, surface, report):
        """Persist a blocked scope-drift attempt on its own connection so the audit
        record survives the rollback of the transaction that was denied."""
        with closing(self.connect()) as db:
            db.execute("INSERT INTO scope_violations(id,engagement_id,at,surface,reason,report) VALUES (?,?,?,?,?,?)",
                       (str(uuid4()), eid, utc_now().isoformat(), surface[:60], (report.get("reason") or "SCOPE_DRIFT")[:60], json.dumps(report, ensure_ascii=False)[:20000]))
            db.commit()

    def scope_violations(self, project_id, eid):
        with closing(self.connect()) as db:
            db.execute("BEGIN")
            self.head(db, project_id, eid)
            rows = [{**dict(row), "report": json.loads(row["report"])} for row in
                    db.execute("SELECT id,at,surface,reason,report FROM scope_violations WHERE engagement_id=? ORDER BY at DESC,id DESC LIMIT 100", (eid,))]
            total = db.execute("SELECT COUNT(*) FROM scope_violations WHERE engagement_id=?", (eid,)).fetchone()[0]
        return {"items": rows, "total": total, "execution_enabled": False}

    def policy_history(self, project_id, eid, all_records=False):
        with closing(self.connect()) as db:
            db.execute("BEGIN")
            self.head(db, project_id, eid)
            rows = [json.loads(row[0]) for row in db.execute("SELECT result FROM policy_checks WHERE engagement_id=? ORDER BY at DESC,id DESC LIMIT ?", (eid, 500 if all_records else 20))]
            total = db.execute("SELECT COUNT(*) FROM policy_checks WHERE engagement_id=?", (eid,)).fetchone()[0]
        return {"items": rows, "total": total, "execution_enabled": False}

    def list(self, project_id):
        with closing(self.connect()) as db:
            ids = [row[0] for row in db.execute("SELECT id FROM engagements WHERE project_id=? ORDER BY updated_at DESC,id", (project_id,))]
        return [self.detail(project_id, eid, history=False) for eid in ids]

    def create(self, project_id, content):
        with self.transaction() as db:
            eid = self.create_in(db, project_id, content)
        return self.detail(project_id, eid)

    def create_in(self, db, project_id, content):
        eid, now = str(uuid4()), utc_now().isoformat()
        payload, digest = snapshot(content)
        if db.execute("SELECT COUNT(*) FROM engagements WHERE project_id=?", (project_id,)).fetchone()[0] >= 100:
            raise HTTPException(409, "Batas 100 engagement per project tercapai.")
        db.execute("INSERT INTO engagements VALUES (?,?,?,?,1)", (eid, project_id, now, now))
        db.execute("INSERT INTO roe_versions(engagement_id,version,status,content,content_hash) VALUES (?,1,'draft',?,?)", (eid, payload, digest))
        self.event(db, eid, 1, "created", "operator-lokal", "", digest)
        return eid

    def edit(self, project_id, eid, payload):
        content, digest = snapshot(payload.content)
        with self.transaction() as db:
            _, head = self.head(db, project_id, eid, payload.expected_revision)
            if head["status"] != "draft":
                raise HTTPException(409, "RoE yang sudah diajukan tidak dapat diedit. Buat revisi baru.")
            db.execute("UPDATE roe_versions SET content=?,content_hash=? WHERE engagement_id=? AND version=?", (content, digest, eid, head["version"]))
            db.execute("UPDATE engagements SET revision=revision+1,updated_at=? WHERE id=?", (utc_now().isoformat(), eid))
            self.event(db, eid, head["version"], "draft_saved", "operator-lokal", "", digest)
        return self.detail(project_id, eid)

    def decide(self, project_id, eid, decision):
        with self.transaction() as db:
            self.decide_in(db, project_id, eid, decision)
        return self.detail(project_id, eid)

    def decide_in(self, db, project_id, eid, decision):
        _, head = self.head(db, project_id, eid, decision.expected_revision)
        content = EngagementContent.model_validate_json(head["content"])
        status, action, version = head["status"], decision.action, head["version"]
        now = utc_now().isoformat()
        if action == "submit":
            if status != "draft":
                raise HTTPException(409, "Hanya draft yang dapat diajukan.")
            errors = content.submission_errors()
            if errors:
                raise HTTPException(422, {"message": "RoE belum lengkap.", "errors": errors})
            db.execute("UPDATE roe_versions SET status='pending_review',submitted_at=? WHERE engagement_id=? AND version=?", (now, eid, version))
        elif action in ("approve", "request_changes"):
            if status != "pending_review":
                raise HTTPException(409, "Hanya RoE menunggu persetujuan yang dapat ditinjau.")
            if content.ends_at and content.ends_at <= utc_now():
                raise HTTPException(409, "RoE telah kedaluwarsa. Buat revisi baru.")
            if action == "approve" and content.submission_errors():
                raise HTTPException(422, {"message": "RoE tidak memenuhi policy terbaru; minta perbaikan dan buat revisi.", "errors": content.submission_errors()})
            if not decision.acknowledge or not decision.note:
                raise HTTPException(422, "Pernyataan peninjau dan catatan keputusan wajib diisi.")
            result = "approved" if action == "approve" else "revoked"
            db.execute("UPDATE roe_versions SET status=?,reviewed_at=?,reviewer=?,review_note=? WHERE engagement_id=? AND version=?", (result, now, decision.actor_label, decision.note, eid, version))
            if action == "request_changes":
                db.execute("UPDATE roe_versions SET revoked_at=?,revoke_note=? WHERE engagement_id=? AND version=?", (now, decision.note, eid, version))
        elif action == "revoke":
            if status == "revoked":
                raise HTTPException(409, "RoE sudah dicabut.")
            if not decision.note:
                raise HTTPException(422, "Alasan pencabutan wajib diisi.")
            db.execute("UPDATE roe_versions SET status='revoked',revoked_at=?,revoke_note=? WHERE engagement_id=? AND version=?", (now, decision.note, eid, version))
        else:
            if status == "draft":
                raise HTTPException(409, "Edit draft saat ini sebelum membuat revisi lain.")
            if version >= 100:
                raise HTTPException(409, "Batas 100 versi RoE tercapai.")
            if not decision.note:
                raise HTTPException(422, "Alasan revisi wajib diisi.")
            if status != "revoked":
                db.execute("UPDATE roe_versions SET status='revoked',revoked_at=?,revoke_note=? WHERE engagement_id=? AND version=?", (now, "Digantikan revisi baru: " + decision.note, eid, version))
            version += 1
            db.execute("INSERT INTO roe_versions(engagement_id,version,status,content,content_hash) VALUES (?,?,'draft',?,?)", (eid, version, head["content"], head["content_hash"]))
        self.event(db, eid, version, action, decision.actor_label, decision.note, head["content_hash"])
        db.execute("UPDATE engagements SET revision=revision+1,updated_at=? WHERE id=?", (now, eid))


router = APIRouter(prefix="/api/security", tags=["Security Workspace — planning only"])


class ProjectRetention(StrictModel):
    project_ids: list[UUID] = Field(max_length=500)


@router.post("/project-retention")
async def project_retention(payload: ProjectRetention, request: Request):
    ids = [str(value) for value in payload.project_ids]
    if not ids:
        return {"protected_project_ids": []}
    with closing(request.app.state.engagements.connect()) as db:
        protected = [row[0] for row in db.execute("SELECT DISTINCT project_id FROM engagements WHERE project_id IN (" + ",".join("?" for _ in ids) + ")", ids)]
    return {"protected_project_ids": protected}


@router.get("/capabilities")
async def capabilities():
    return {"stage": 7, "agents_mode": "specialists_synthetic_lab_only", "agent_max_parallel": 1, "orchestration_mode": "single_local_model_fixture_only", "mcp_mode": "isolated_fixture_only", "external_mcp_enabled": False, "evidence_mode": "local_redacted_text", "findings_review": "local_attestation", "jobs_mode": "offline_policy_validation", "job_execution_enabled": False, "policy_version": POLICY_VERSION, "execution_enabled": False, "dns_resolution_enabled": False, "approval_mode": "local_attestation", "environments": ["lab", "development", "staging", "uat"], "allowed_actions": ACTIONS, "forbidden_actions": FORBIDDEN}


@router.post("/scope-validation")
async def validate_scope(payload: CreateEngagement):
    return {**scope_report(payload.content), "normalized_scope": {"in_scope": payload.content.in_scope, "out_of_scope": payload.content.out_of_scope}}


@router.get("/projects/{project_id}/engagements")
async def list_engagements(project_id: UUID, request: Request):
    return {"items": request.app.state.engagements.list(str(project_id)), "execution_enabled": False}


@router.post("/projects/{project_id}/engagements", status_code=201)
async def create_engagement(project_id: UUID, payload: CreateEngagement, request: Request):
    return request.app.state.engagements.create(str(project_id), payload.content)


@router.get("/projects/{project_id}/engagements/{engagement_id}")
async def get_engagement(project_id: UUID, engagement_id: UUID, request: Request):
    return request.app.state.engagements.detail(str(project_id), str(engagement_id))


@router.post("/projects/{project_id}/engagements/{engagement_id}")
async def edit_engagement(project_id: UUID, engagement_id: UUID, payload: EditEngagement, request: Request):
    return request.app.state.engagements.edit(str(project_id), str(engagement_id), payload)


@router.post("/projects/{project_id}/engagements/{engagement_id}/decisions")
async def decide_engagement(project_id: UUID, engagement_id: UUID, payload: Decision, request: Request):
    return request.app.state.engagements.decide(str(project_id), str(engagement_id), payload)


@router.post("/projects/{project_id}/engagements/{engagement_id}/policy-checks")
async def check_policy(project_id: UUID, engagement_id: UUID, payload: PolicyProposal, request: Request):
    return request.app.state.engagements.check_policy(str(project_id), str(engagement_id), payload)


@router.get("/projects/{project_id}/engagements/{engagement_id}/policy-checks")
async def policy_history(project_id: UUID, engagement_id: UUID, request: Request, all_records: bool = False):
    return request.app.state.engagements.policy_history(str(project_id), str(engagement_id), all_records=all_records)


@router.get("/projects/{project_id}/engagements/{engagement_id}/scope-violations")
async def scope_violations(project_id: UUID, engagement_id: UUID, request: Request):
    return request.app.state.engagements.scope_violations(str(project_id), str(engagement_id))


@router.post("/plan-simulation")
async def plan_simulation(payload: SimulationRequest):
    from auto_governance import simulate_plan
    jobs = [{"tool": step.tool, "action": step.action, "target": step.target.model_dump(mode="json"),
             "ports": step.ports, "max_concurrency": step.max_concurrency, "duration": step.max_duration_minutes,
             "timeout": min(240, step.max_duration_minutes) * 60} for step in payload.jobs]
    return {**simulate_plan({"environment": payload.environment, "jobs": jobs}), "approval_mode": "local_attestation"}


@router.post("/risk-classification")
async def risk_classification(payload: RiskRequest):
    from auto_governance import classify_risk
    return {**classify_risk(payload.action, payload.tool), "execution_enabled": False}


@router.post("/approval/verify")
async def approval_verify(payload: ApprovalVerify):
    from auto_governance import classify_risk
    from security import load_token
    risk = classify_risk(payload.action, payload.tool)
    if risk["requires"] != "session_pin":
        # Low/medium tiers do not require a PIN; nothing to verify.
        return {**risk, "verified": True, "pin_required": False, "execution_enabled": False}
    verified = bool(payload.session_pin) and hmac.compare_digest(payload.session_pin, load_token())
    return {**risk, "verified": verified, "pin_required": True, "execution_enabled": False}

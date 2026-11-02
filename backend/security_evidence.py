"""Stage 4 local evidence, analyst findings and immutable reports. No tool execution."""
from contextlib import closing, nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import re
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request
from security import SafeValidationRoute
from pydantic import AwareDatetime, Field, StrictBool, model_validator, field_validator

from engagements import StrictModel, ScopeAsset, utc_now
from security_jobs import encode, digest, TERMINAL
import evidence_archive
from security_report import readable_markdown, report_view

MAX_EVIDENCE = 100
MAX_FINDINGS = 100
MAX_REPORTS = 30
MAX_ARTIFACT = 64 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
SOURCES = ('offline_policy', 'synthetic_fixture', 'external_import')
STATUSES = ('candidate', 'validated', 'false_positive', 'inconclusive', 'retest_passed')


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def redactor(terms=()):
    """Best effort, deterministic. Custom terms are discarded, never stored."""
    count = [0]
    patterns = [
        (r'-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----', '[REDACTED PRIVATE KEY]'),
        (r'(?im)["\']?\b(?:authorization|proxy-authorization|cookie|set-cookie)["\']?\s*:\s*("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\r\n]+)', '[REDACTED HEADER]'),
        (r'(?i)(["\']?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token|session[_-]?id|cookie|set-cookie|authorization)["\']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s&,;}]+)', r'\1[REDACTED]'),
        (r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+', '[REDACTED AUTH]'),
        (r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', '[REDACTED JWT]'),
        (r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[REDACTED EMAIL]'),
        (r'(?<![\w])\+?\d[\d -]{8,22}\d(?![\w])', '[REDACTED NUMBER]'),
    ]
    def text(value):
        for pattern, replacement in patterns:
            value, n = re.subn(pattern, replacement, value)
            count[0] += n
        # Custom terms must never remove a key before automatic secret detection.
        for term in sorted(set(terms), key=len, reverse=True):
            value, n = re.subn(re.escape(term), '[REDACTED CUSTOM]', value, flags=re.I)
            count[0] += n
        return value
    def walk(value):
        if isinstance(value, str): return text(value)
        if isinstance(value, list): return [walk(item) for item in value]
        if isinstance(value, dict): return {key: walk(item) for key, item in value.items()}
        return value
    return walk, count


def cvss_base(vector):
    """CVSS 3.1 Base only. FIRST specification sections 7.1/7.4/Appendix A."""
    if not vector: return None
    allowed = {'AV':'NALP', 'AC':'LH', 'PR':'NLH', 'UI':'NR', 'S':'UC', 'C':'NLH', 'I':'NLH', 'A':'NLH'}
    parts = vector.split('/')
    metrics = {}
    if parts[0] != 'CVSS:3.1': raise ValueError('Gunakan vektor CVSS:3.1 Base lengkap.')
    for part in parts[1:]:
        pair = part.split(':')
        if len(pair) != 2 or pair[0] not in allowed or pair[0] in metrics or len(pair[1]) != 1 or pair[1] not in allowed[pair[0]]:
            raise ValueError('Metrik CVSS Base tidak valid, duplikat, atau tidak didukung.')
        metrics[pair[0]] = pair[1]
    if set(metrics) != set(allowed): raise ValueError('Delapan metrik CVSS Base wajib lengkap.')
    m = metrics
    impact_value = {'N':0, 'L':.22, 'H':.56}
    iss = 1 - math.prod(1-impact_value[m[k]] for k in ('C','I','A'))
    changed = m['S'] == 'C'
    impact = 7.52*(iss-.029)-3.25*(iss-.02)**15 if changed else 6.42*iss
    if impact <= 0: return 0.0
    pr = {'N':.85,'L':.68 if changed else .62,'H':.5 if changed else .27}[m['PR']]
    exploit = 8.22 * {'N':.85,'A':.62,'L':.55,'P':.2}[m['AV']] * {'L':.77,'H':.44}[m['AC']] * pr * {'N':.85,'R':.62}[m['UI']]
    value = min((impact+exploit)*(1.08 if changed else 1), 10)
    integer = math.floor(value*100000+.5)
    return integer/100000 if integer % 10000 == 0 else (integer//10000+1)/10


class RedactionInput(StrictModel):
    redaction_terms: list[str] = Field(default_factory=list, max_length=20)

    @field_validator('redaction_terms')
    @classmethod
    def valid_terms(cls, terms):
        if any(len(t.strip()) < 3 or len(t) > 200 for t in terms):
            raise ValueError('Istilah sensor harus 3–200 karakter.')
        return [t.strip() for t in terms]


class EvidenceInput(RedactionInput):
    model_config = {'extra':'forbid', 'str_strip_whitespace':False}
    job_id: UUID
    step_ordinal: int = Field(ge=1, le=20, strict=True)
    source: Literal['offline_policy','synthetic_fixture','external_import']
    title: str = Field(min_length=1, max_length=160)
    captured_at: AwareDatetime | None = None
    tool_name: str = Field(default='', max_length=120)
    tool_version: str = Field(default='', max_length=120)
    parameters: str = Field(default='', max_length=4000)
    content: str = Field(default='', max_length=MAX_ARTIFACT)
    redaction_terms: list[str] = Field(default_factory=list, max_length=20)
    acknowledge: StrictBool

    @model_validator(mode='after')
    def valid(self):
        if not self.title.strip(): raise ValueError('Judul wajib diisi.')
        if len(self.content.encode('utf-8')) > MAX_ARTIFACT or any(ord(c)<32 and c not in '\t\r\n' for c in self.content):
            raise ValueError('Bukti harus teks UTF-8 tanpa karakter biner, maksimal 64 KiB.')
        if any(not t.strip() or len(t)>200 for t in self.redaction_terms): raise ValueError('Istilah sensor harus 1–200 karakter.')
        if self.source != 'offline_policy' and (not self.content.strip() or not self.tool_name.strip() or not self.tool_version.strip() or self.captured_at is None):
            raise ValueError('Impor memerlukan isi, tool/versi dan waktu pengambilan.')
        if self.captured_at and self.captured_at > utc_now()+timedelta(minutes=5): raise ValueError('Waktu bukti tidak boleh di masa depan.')
        if self.source == 'offline_policy' and (self.content or self.tool_name or self.tool_version or self.parameters or self.captured_at):
            raise ValueError('Metadata hasil policy diambil server, bukan input operator.')
        return self


class FindingContent(RedactionInput):
    title: str = Field(min_length=1, max_length=160)
    target: ScopeAsset
    category: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=6000)
    ai_interpretation: str = Field(default='', max_length=6000)
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=30)
    severity: Literal['unrated','informational','low','medium','high','critical'] = 'unrated'
    severity_reason: str = Field(default='', max_length=3000)
    cvss_vector: str = Field(default='', max_length=160)
    cvss_reason: str = Field(default='', max_length=3000)
    remediation: str = Field(default='', max_length=6000)
    assignee: str = Field(default='', max_length=160)
    duplicate_of: UUID | None = None
    redaction_terms: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode='after')
    def valid(self):
        cvss_base(self.cvss_vector)
        if self.cvss_vector and not self.cvss_reason: raise ValueError('Dasar metrik CVSS wajib diisi.')
        if self.severity != 'unrated' and not self.severity_reason: raise ValueError('Dasar severity wajib diisi.')
        if len(set(self.evidence_ids)) != len(self.evidence_ids): raise ValueError('Evidence duplikat.')
        if any(not t.strip() or len(t)>200 for t in self.redaction_terms): raise ValueError('Istilah sensor tidak valid.')
        return self


class EditFinding(StrictModel):
    expected_revision: int = Field(ge=1, strict=True)
    content: FindingContent


class ReviewFinding(RedactionInput):
    expected_revision: int = Field(ge=1, strict=True)
    status: Literal['candidate','validated','false_positive','inconclusive','retest_passed']
    actor_label: str = Field(min_length=1, max_length=120)
    analyst_assessment: str = Field(min_length=1, max_length=6000)
    acknowledge: StrictBool
    retest_evidence_ids: list[UUID] = Field(default_factory=list, max_length=30)
    redaction_terms: list[str] = Field(default_factory=list, max_length=20)


class ReportInput(RedactionInput):
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=6000)
    actor_label: str = Field(min_length=1, max_length=120)
    acknowledge: StrictBool
    redaction_terms: list[str] = Field(default_factory=list, max_length=20)


class OriginalExport(StrictModel):
    actor_label: str = Field(min_length=1, max_length=120)
    note: str = Field(min_length=1, max_length=1000)
    acknowledge_sensitive_export: StrictBool


class EvidenceStore:
    def __init__(self, engagements, jobs):
        self.engagements, self.jobs = engagements, jobs
        with closing(engagements.connect()) as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS security_evidence (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, engagement_id TEXT NOT NULL REFERENCES engagements(id),
                    job_id TEXT NOT NULL REFERENCES security_jobs(id), ordinal INTEGER NOT NULL,
                    source TEXT NOT NULL, original_hash TEXT NOT NULL, payload TEXT NOT NULL, payload_hash TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS evidence_engagement ON security_evidence(engagement_id);
                CREATE TABLE IF NOT EXISTS security_findings (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, engagement_id TEXT NOT NULL REFERENCES engagements(id),
                    revision INTEGER NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_finding_versions (
                    finding_id TEXT NOT NULL REFERENCES security_findings(id), revision INTEGER NOT NULL,
                    payload TEXT NOT NULL, payload_hash TEXT NOT NULL, PRIMARY KEY(finding_id,revision)
                );
                CREATE TABLE IF NOT EXISTS security_reports (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, engagement_id TEXT NOT NULL REFERENCES engagements(id),
                    payload TEXT NOT NULL, payload_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_evidence_originals (
                    evidence_id TEXT PRIMARY KEY REFERENCES security_evidence(id), cipher BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS security_evidence_access (
                    id INTEGER PRIMARY KEY, evidence_id TEXT NOT NULL REFERENCES security_evidence(id),
                    at TEXT NOT NULL, actor_label TEXT NOT NULL, note TEXT NOT NULL
                );
            ''')

    def bounded(self, db, table, eid, limit):
        if db.execute(f'SELECT COUNT(*) FROM {table} WHERE engagement_id=?',(eid,)).fetchone()[0] >= limit:
            raise HTTPException(409, f'Batas {limit} catatan tercapai. Riwayat dipertahankan.')

    def evidence_row(self, db, project, eid, evidence_id):
        row = db.execute('SELECT * FROM security_evidence WHERE id=? AND project_id=? AND engagement_id=?',(str(evidence_id),project,eid)).fetchone()
        if not row: raise HTTPException(404,'Evidence tidak ditemukan pada engagement ini.')
        payload = json.loads(row['payload'])
        if digest(payload) != row['payload_hash'] or sha(payload['content']) != payload['artifact_hash']:
            raise HTTPException(409,'Integritas evidence tidak sesuai; review/laporan diblokir.')
        original_available = bool(db.execute('SELECT 1 FROM security_evidence_originals WHERE evidence_id=?',(str(evidence_id),)).fetchone())
        return {**payload, 'integrity':'verified', 'record_hash':row['payload_hash'], 'original_available':original_available}

    def add_evidence(self, project, eid, body, *, db=None, mcp_provenance=None, lab_provenance=None, web_provenance=None, scan_provenance=None):
        if not body.acknowledge: raise HTTPException(422,'Konfirmasi asal bukti dan sensor wajib.')
        external_db = db
        with (nullcontext(db) if db is not None else self.engagements.transaction()) as db:
            self.engagements.head(db,project,eid)
            self.bounded(db,'security_evidence',eid,MAX_EVIDENCE)
            job = self.jobs.job(db,project,eid,str(body.job_id))
            if job['status'] not in TERMINAL and not ((mcp_provenance or web_provenance or scan_provenance) and job['status']=='running'):
                raise HTTPException(409,'Pilih job terminal yang memiliki hasil langkah tersimpan.')
            plan = json.loads(job['plan'])
            if digest(plan) != job['plan_hash']: raise HTTPException(409,'Integritas rencana job tidak sesuai.')
            result_row = db.execute('SELECT result FROM security_job_results WHERE job_id=? AND ordinal=?',(str(body.job_id),body.step_ordinal)).fetchone()
            if not result_row or body.step_ordinal > len(plan['steps']): raise HTTPException(422,'Langkah belum memiliki hasil policy tersimpan.')
            result = json.loads(result_row[0])
            offline = body.source == 'offline_policy'
            raw = encode(result) if offline else body.content
            raw_hash = sha(raw)
            duplicate = db.execute('SELECT id FROM security_evidence WHERE engagement_id=? AND job_id=? AND ordinal=? AND source=? AND original_hash=?',(eid,str(body.job_id),body.step_ordinal,body.source,raw_hash)).fetchone()
            if duplicate: raise HTTPException(409,'Evidence identik sudah tersimpan: '+duplicate['id'])
            scrub, count = redactor(body.redaction_terms)
            text = scrub(raw)
            now = utc_now().isoformat()
            artifact = {
                'id':str(uuid4()),'project_id':project,'engagement_id':eid,'job_id':str(body.job_id),'step_ordinal':body.step_ordinal,
                'source':body.source,'title':scrub(body.title.strip()),'target':plan['steps'][body.step_ordinal-1]['target'],
                'captured_at':result.get('evaluated_at',now) if offline else body.captured_at.astimezone(timezone.utc).isoformat(), 'received_at':now,
                'tool_name':'Jo Workspace Policy Guard' if offline else scrub(body.tool_name.strip()),
                'tool_version':result.get('policy_version','scope-policy-2.0') if offline else scrub(body.tool_version.strip()),
                'parameters':scrub(encode(plan['steps'][body.step_ordinal-1])) if offline else scrub(body.parameters),
                'policy':scrub(result), 'roe_version':plan['roe_version'],'roe_hash':plan['content_hash'],'plan_hash':job['plan_hash'],
                'content':text,'original_hash':raw_hash,'artifact_hash':sha(text),'original_bytes':len(raw.encode()),'artifact_bytes':len(text.encode()),
                'provenance':'server_offline_validation' if offline else 'operator_declared_import',
                'tool_executed_by_agent_os':False,'execution_enabled':False,
            }
            # Target identifiers are kept exact for scope binding. Reject custom terms that would mask them.
            if scrub(artifact['target']['value']) != artifact['target']['value']:
                raise HTTPException(422,'Target mengandung data yang perlu disensor; gunakan target scope tanpa data pribadi.')
            artifact['redactions'] = count[0]
            if mcp_provenance:
                artifact.update(provenance='server_mcp_fixture',mcp=mcp_provenance,tool_executed_by_agent_os=True,pentest_executed=False)
            if lab_provenance:
                artifact.update(provenance='server_synthetic_lab',specialist_lab=lab_provenance,tool_executed_by_agent_os=True,pentest_executed=False)
            if web_provenance:
                artifact.update(provenance='server_public_head',web=web_provenance,tool_executed_by_agent_os=True,pentest_executed=False)
            if scan_provenance:
                artifact.update(provenance='server_approved_tcp_scan' if scan_provenance['tool'] in ('tcp-connect','nmap') else 'server_approved_tool_run',scan=scan_provenance,tool_executed_by_agent_os=True,pentest_executed=False)
            cipher = None
            if evidence_archive.available():
                try:
                    cipher = evidence_archive.protect(raw,artifact['id'],raw_hash)
                except Exception:
                    raise HTTPException(503,'Arsip asli Windows gagal dienkripsi; evidence tidak disimpan.') from None
            artifact['original_archive'] = 'windows_dpapi_current_user' if cipher else 'unavailable_redacted_only'
            if len(text.encode()) > MAX_ARTIFACT: raise HTTPException(422,'Hasil setelah sensor melampaui 64 KiB.')
            db.execute('INSERT INTO security_evidence VALUES (?,?,?,?,?,?,?,?,?)',(artifact['id'],project,eid,str(body.job_id),body.step_ordinal,body.source,raw_hash,encode(artifact),digest(artifact)))
            if cipher:
                db.execute('INSERT INTO security_evidence_originals VALUES (?,?)',(artifact['id'],cipher))
        return artifact if external_db is not None else self.get_evidence(project,eid,artifact['id'])

    def get_evidence(self, project, eid, evidence_id):
        with closing(self.engagements.connect()) as db:
            return self.evidence_row(db,project,eid,evidence_id)

    def export_original(self, project, eid, evidence_id, body):
        if not body.acknowledge_sensitive_export:
            raise HTTPException(422,'Konfirmasi khusus diperlukan: unduhan asli dapat berisi rahasia/PII tanpa sensor.')
        with self.engagements.transaction() as db:
            evidence = self.evidence_row(db,project,eid,evidence_id)
            row = db.execute('SELECT cipher FROM security_evidence_originals WHERE evidence_id=?',(evidence_id,)).fetchone()
            if not row: raise HTTPException(404,'Arsip asli tidak tersedia untuk evidence ini. Catatan lama tidak dapat dipulihkan dari hash.')
            try:
                text = evidence_archive.unprotect(row['cipher'],evidence_id,evidence['original_hash'])
                if sha(text) != evidence['original_hash']: raise ValueError('hash')
            except Exception:
                raise HTTPException(409,'Arsip tidak dapat diverifikasi/dibuka oleh akun Windows ini.') from None
            scrub,_ = redactor()
            db.execute('INSERT INTO security_evidence_access(evidence_id,at,actor_label,note) VALUES (?,?,?,?)',
                       (evidence_id,utc_now().isoformat(),scrub(body.actor_label),scrub(body.note)))
            return {'id':evidence_id,'content':text,'original_hash':evidence['original_hash'],'redacted':False}

    def finding_row(self, db, project, eid, fid, expected=None):
        row = db.execute('SELECT * FROM security_findings WHERE id=? AND project_id=? AND engagement_id=?',(str(fid),project,eid)).fetchone()
        if not row: raise HTTPException(404,'Finding tidak ditemukan pada engagement ini.')
        if expected is not None and row['revision'] != expected: raise HTTPException(409,'Finding berubah. Muat ulang sebelum menyimpan.')
        record = db.execute('SELECT * FROM security_finding_versions WHERE finding_id=? AND revision=?',(str(fid),row['revision'])).fetchone()
        if not record or record['payload'] != row['payload'] or digest(json.loads(row['payload'])) != record['payload_hash']:
            raise HTTPException(409,'Integritas finding tidak sesuai.')
        return json.loads(row['payload'])

    def linked(self, db, project, eid, ids, target, observation=False):
        records = [self.evidence_row(db,project,eid,x) for x in ids]
        if any(e['target'] != target for e in records): raise HTTPException(422,'Target evidence harus sama dengan target finding.')
        observations = [e for e in records if e['source'] != 'offline_policy']
        if observation and (not observations or any(e['policy'].get('decision')!='pass' for e in observations)):
            raise HTTPException(422,'Validasi memerlukan bukti observasi/fixture dan hasil policy lolos; policy offline saja tidak cukup.')
        return records

    def clean_finding(self, db, project, eid, body, fid=None):
        content = body.model_dump(mode='json',exclude={'redaction_terms'})
        self.linked(db,project,eid,content['evidence_ids'],content['target'])
        scrub, _ = redactor(body.redaction_terms)
        if scrub(content['target']['value']) != content['target']['value']: raise HTTPException(422,'Target finding tidak boleh mengandung data pribadi.')
        content = scrub(content)
        # Do not permit redaction terms to silently alter identifiers or numeric CVSS metrics.
        content['evidence_ids'] = [str(x) for x in body.evidence_ids]
        content['duplicate_of'] = str(body.duplicate_of) if body.duplicate_of else None
        content['target'] = body.target.model_dump()
        content['cvss_vector'] = body.cvss_vector
        content['severity'] = body.severity
        content['cvss_score'] = cvss_base(body.cvss_vector)
        duplicate = content['duplicate_of']
        if fid:
            children = [json.loads(r[0]) for r in db.execute('SELECT payload FROM security_findings WHERE engagement_id=?',(eid,)) if json.loads(r[0])['content'].get('duplicate_of')==fid]
            if any(child['content']['target'] != content['target'] for child in children):
                raise HTTPException(422,'Target finding utama yang memiliki duplikat harus tetap sama.')
        if duplicate:
            if duplicate == fid: raise HTTPException(422,'Finding tidak dapat menduplikasi dirinya sendiri.')
            canonical = self.finding_row(db,project,eid,duplicate)
            if canonical['content']['duplicate_of'] or canonical['content']['target'] != content['target']:
                raise HTTPException(422,'Duplikat harus menunjuk finding utama pada target yang sama.')
            if fid and any(json.loads(r[0])['content'].get('duplicate_of')==fid for r in db.execute('SELECT payload FROM security_findings WHERE engagement_id=?',(eid,))):
                raise HTTPException(422,'Finding utama dengan duplikat tidak dapat dijadikan duplikat.')
        fingerprint = digest([content['target'], re.sub(r'\s+',' ',body.category.casefold()), re.sub(r'\s+',' ',body.title.casefold())])
        match = db.execute('SELECT id FROM security_findings WHERE engagement_id=? AND fingerprint=? AND id!=?',(eid,fingerprint,fid or '')).fetchone()
        if match: raise HTTPException(409,'Finding identik sudah ada: '+match['id']+'; gunakan finding tersebut atau tautkan duplikat semantik.')
        return content, fingerprint

    def save_version(self, db, item, fingerprint, new=False):
        payload = encode(item)
        if new:
            db.execute('INSERT INTO security_findings VALUES (?,?,?,?,?,?)',(item['id'],item['project_id'],item['engagement_id'],item['revision'],fingerprint,payload))
        else:
            db.execute('UPDATE security_findings SET revision=?,fingerprint=?,payload=? WHERE id=?',(item['revision'],fingerprint,payload,item['id']))
        db.execute('INSERT INTO security_finding_versions VALUES (?,?,?,?)',(item['id'],item['revision'],payload,digest(item)))

    def create_finding(self, project, eid, body):
        with self.engagements.transaction() as db:
            self.engagements.head(db,project,eid)
            self.bounded(db,'security_findings',eid,MAX_FINDINGS)
            content, fingerprint = self.clean_finding(db,project,eid,body)
            now = utc_now().isoformat()
            item = {'id':str(uuid4()),'project_id':project,'engagement_id':eid,'revision':1,'status':'candidate',
                    'created_at':now,'updated_at':now,'content':content,'review':None,'retest_evidence_ids':[],
                    'execution_enabled':False,'review_mode':'local_attestation'}
            self.save_version(db,item,fingerprint,new=True)
        return self.get_finding(project,eid,item['id'])

    def edit_finding(self, project, eid, fid, body):
        with self.engagements.transaction() as db:
            item = self.finding_row(db,project,eid,fid,body.expected_revision)
            content, fingerprint = self.clean_finding(db,project,eid,body.content,fid)
            if item['revision'] >= 100: raise HTTPException(409,'Batas 100 versi finding tercapai.')
            item.update(content=content,status='candidate',review=None,retest_evidence_ids=[],revision=item['revision']+1,updated_at=utc_now().isoformat())
            self.save_version(db,item,fingerprint)
        return self.get_finding(project,eid,fid)

    def review(self, project, eid, fid, body):
        if not body.acknowledge: raise HTTPException(422,'Review analis dan konfirmasi wajib.')
        with self.engagements.transaction() as db:
            item = self.finding_row(db,project,eid,fid,body.expected_revision)
            c = item['content']
            if item['revision'] >= 100: raise HTTPException(409,'Batas 100 versi finding tercapai.')
            if body.status == item['status']: raise HTTPException(409,'Status finding tidak berubah.')
            self.linked(db,project,eid,c['evidence_ids'],c['target'])
            if body.status in ('validated','retest_passed'):
                self.linked(db,project,eid,c['evidence_ids'],c['target'],observation=True)
                if c['duplicate_of'] or c['severity']=='unrated' or not c['severity_reason']:
                    raise HTTPException(422,'Finding duplikat atau tanpa dasar severity tidak dapat divalidasi.')
            retests = [str(x) for x in body.retest_evidence_ids]
            if body.status == 'retest_passed':
                if item['status'] != 'validated': raise HTTPException(409,'Retest Passed hanya dapat mengikuti Validated.')
                records = self.linked(db,project,eid,retests,c['target'],observation=True)
                baseline = self.linked(db,project,eid,c['evidence_ids'],c['target'])
                if len(set(retests)) != len(retests) or any(e['source']=='offline_policy' or e['job_id'] in {b['job_id'] for b in baseline} or datetime.fromisoformat(e['captured_at']) < datetime.fromisoformat(item['review']['at']) for e in records):
                    raise HTTPException(422,'Retest memerlukan bukti baru setelah review, dari job berbeda.')
            elif retests: raise HTTPException(422,'Bukti retest hanya untuk keputusan Retest Passed.')
            scrub,_ = redactor(body.redaction_terms)
            item.update(status=body.status,revision=item['revision']+1,updated_at=utc_now().isoformat(),retest_evidence_ids=retests,
                        review={'actor_label':scrub(body.actor_label),'analyst_assessment':scrub(body.analyst_assessment),'at':utc_now().isoformat(),'mode':'local_attestation'})
            fingerprint = db.execute('SELECT fingerprint FROM security_findings WHERE id=?',(fid,)).fetchone()[0]
            self.save_version(db,item,fingerprint)
        return self.get_finding(project,eid,fid)

    def get_finding(self, project, eid, fid):
        with closing(self.engagements.connect()) as db:
            db.execute('BEGIN')
            item = self.finding_row(db,project,eid,fid)
            history = []
            for row in db.execute('SELECT * FROM security_finding_versions WHERE finding_id=? ORDER BY revision',(fid,)):
                version = json.loads(row['payload'])
                if digest(version) != row['payload_hash']: raise HTTPException(409,'Integritas riwayat finding tidak sesuai.')
                history.append({'revision':row['revision'],'snapshot':version,'hash':row['payload_hash']})
            return {**item,'history':history}

    def listing(self, project, eid):
        with closing(self.engagements.connect()) as db:
            db.execute('BEGIN')
            self.engagements.head(db,project,eid)
            evidence = [self.evidence_row(db,project,eid,r[0]) for r in db.execute('SELECT id FROM security_evidence WHERE engagement_id=? ORDER BY rowid DESC',(eid,))]
            findings = [self.finding_row(db,project,eid,r[0]) for r in db.execute('SELECT id FROM security_findings WHERE engagement_id=? ORDER BY rowid DESC',(eid,))]
            reports = []
            for r in db.execute('SELECT * FROM security_reports WHERE engagement_id=? ORDER BY rowid DESC',(eid,)):
                p = json.loads(r['payload'])
                reports.append({'id':r['id'],'title':p['title'],'created_at':p['created_at'],'hash':r['payload_hash']})
            return {'evidence':[{k:v for k,v in e.items() if k not in ('content','policy')} for e in evidence], 'findings':findings,'reports':reports,
                    'execution_enabled':False,'limits':{'evidence':MAX_EVIDENCE,'findings':MAX_FINDINGS,'reports':MAX_REPORTS,'artifact_bytes':MAX_ARTIFACT}}

    def report(self, project, eid, body):
        if not body.acknowledge: raise HTTPException(422,'Konfirmasi laporan lokal wajib.')
        with self.engagements.transaction() as db:
            engagement,head = self.engagements.head(db,project,eid)
            self.bounded(db,'security_reports',eid,MAX_REPORTS)
            evidences = [self.evidence_row(db,project,eid,r[0]) for r in db.execute('SELECT id FROM security_evidence WHERE engagement_id=? ORDER BY id',(eid,))]
            findings = [self.finding_row(db,project,eid,r[0]) for r in db.execute('SELECT id FROM security_findings WHERE engagement_id=? ORDER BY id',(eid,))]
            for f in findings:
                self.linked(db,project,eid,f['content']['evidence_ids']+f['retest_evidence_ids'],f['content']['target'],observation=f['status'] in ('validated','retest_passed'))
            scrub,_ = redactor(body.redaction_terms)
            snapshot = {'id':str(uuid4()),'project_id':project,'engagement_id':eid,'title':scrub(body.title),'summary':scrub(body.summary),
                        'author_declaration':scrub(body.actor_label),'created_at':utc_now().isoformat(),
                        'engagement_revision':engagement['revision'],'roe_version':head['version'],'roe_hash':head['content_hash'],
                        'evidence':evidences,'findings':findings,'execution_enabled':False,'review_mode':'local_attestation',
                        'limitations':['Tidak ada eksekusi pentest Jo Workspace.','Policy offline bukan bukti kerentanan.',
                                       'Bukti eksternal dan waktu/tool adalah deklarasi operator; fixture bukan hasil target nyata.',
                                       'AI interpretation belum diverifikasi; keputusan analis disimpan terpisah.',
                                       'Tampilan/laporan hanya berisi artefak tersensor; arsip asli DPAPI tidak disertakan. Sensor bersifat best effort.',
                                       'SHA-256 bukan tanda tangan digital; nama analis bukan identitas terverifikasi.']}
            payload = encode(snapshot)
            if len(payload.encode()) > MAX_REPORT_BYTES: raise HTTPException(422,'Snapshot laporan melampaui 2 MiB. Gunakan engagement terpisah untuk kumpulan bukti besar.')
            db.execute('INSERT INTO security_reports VALUES (?,?,?,?,?)',(snapshot['id'],project,eid,payload,digest(snapshot)))
        return self.get_report(project,eid,snapshot['id'])

    def get_report(self, project, eid, rid):
        with closing(self.engagements.connect()) as db:
            row = db.execute('SELECT * FROM security_reports WHERE id=? AND project_id=? AND engagement_id=?',(rid,project,eid)).fetchone()
            if not row: raise HTTPException(404,'Laporan tidak ditemukan pada engagement ini.')
            p = json.loads(row['payload'])
            if digest(p) != row['payload_hash']: raise HTTPException(409,'Integritas laporan tidak sesuai.')
            # The report created just before this one in the same engagement, for retest comparison.
            prior = db.execute('SELECT payload,payload_hash FROM security_reports WHERE engagement_id=? AND '
                               'rowid<(SELECT rowid FROM security_reports WHERE id=?) ORDER BY rowid DESC LIMIT 1',(eid,rid)).fetchone()
            previous = json.loads(prior['payload']) if prior else None
            if previous is not None and digest(previous) != prior['payload_hash']: raise HTTPException(409,'Integritas laporan sebelumnya tidak sesuai.')
            technical = report_markdown(p,row['payload_hash'])
            readable = readable_markdown(p,row['payload_hash'],previous)
            return {'snapshot':p,'hash':row['payload_hash'],'markdown':technical,'view':report_view(p,previous),
                    'readable_markdown':readable+'\n---\n\n## Lampiran teknis (snapshot lengkap)\n\n'+technical}


def report_markdown(snapshot, report_hash):
    # Untrusted text stays in a fence longer than any tilde run; no raw HTML/links.
    def block(value):
        text = value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2)
        fence = '~' * max(3, max((len(x) for x in re.findall(r'~+',text)),default=0)+1)
        return '\n'+fence+'text\n'+text+'\n'+fence+'\n'
    sections = ['# Jo Workspace — laporan Security Workspace',
                '\nEksekusi pentest tetap dinonaktifkan.\n\nSHA-256 snapshot: '+report_hash,
                '\n## Identitas laporan',block({k:snapshot[k] for k in ('title','id','project_id','engagement_id','created_at','author_declaration','roe_version','roe_hash')}),
                '\n## Ringkasan eksekutif',block(snapshot['summary']), '\n## Batas dan provenance', block(snapshot['limitations'])]
    for n,f in enumerate(snapshot['findings'],1):
        sections += ['\n## Finding '+str(n),block({'id':f['id'],'revision':f['revision'],'status':f['status'], **{k:v for k,v in f['content'].items() if k!='ai_interpretation'}}),
                     '\n### Interpretasi AI — belum diverifikasi',block(f['content']['ai_interpretation']),
                     '\n### Keputusan analis — deklarasi lokal',block(f['review']), '\n### Bukti retest',block(f['retest_evidence_ids'])]
    for n,e in enumerate(snapshot['evidence'],1):
        sections += ['\n## Evidence '+str(n),block({k:v for k,v in e.items() if k not in ('content','policy')}),
                     '\n### Artefak tersensor',block(e['content']), '\n### Policy historis — tanpa eksekusi',block(e['policy'])]
    return '\n'.join(sections)+'\n'


router = APIRouter(prefix='/api/security/projects/{project_id}/engagements/{engagement_id}',tags=['Evidence/findings/reports — no execution'],route_class=SafeValidationRoute)


@router.get('/records')
async def records(project_id:UUID,engagement_id:UUID,request:Request):
    return request.app.state.evidence.listing(str(project_id),str(engagement_id))


@router.post('/evidence',status_code=201)
async def add_evidence(project_id:UUID,engagement_id:UUID,body:EvidenceInput,request:Request):
    return request.app.state.evidence.add_evidence(str(project_id),str(engagement_id),body)


@router.get('/evidence/{evidence_id}')
async def get_evidence(project_id:UUID,engagement_id:UUID,evidence_id:UUID,request:Request):
    return request.app.state.evidence.get_evidence(str(project_id),str(engagement_id),str(evidence_id))


@router.post('/evidence/{evidence_id}/original')
async def original_evidence(project_id:UUID,engagement_id:UUID,evidence_id:UUID,body:OriginalExport,request:Request):
    from fastapi.responses import JSONResponse
    result = request.app.state.evidence.export_original(str(project_id),str(engagement_id),str(evidence_id),body)
    return JSONResponse(result,headers={'Cache-Control':'no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff'})


@router.post('/findings',status_code=201)
async def create_finding(project_id:UUID,engagement_id:UUID,body:FindingContent,request:Request):
    return request.app.state.evidence.create_finding(str(project_id),str(engagement_id),body)


@router.get('/findings/{finding_id}')
async def get_finding(project_id:UUID,engagement_id:UUID,finding_id:UUID,request:Request):
    return request.app.state.evidence.get_finding(str(project_id),str(engagement_id),str(finding_id))


@router.put('/findings/{finding_id}')
async def edit_finding(project_id:UUID,engagement_id:UUID,finding_id:UUID,body:EditFinding,request:Request):
    return request.app.state.evidence.edit_finding(str(project_id),str(engagement_id),str(finding_id),body)


@router.post('/findings/{finding_id}/review')
async def review_finding(project_id:UUID,engagement_id:UUID,finding_id:UUID,body:ReviewFinding,request:Request):
    return request.app.state.evidence.review(str(project_id),str(engagement_id),str(finding_id),body)


@router.post('/reports',status_code=201)
async def create_report(project_id:UUID,engagement_id:UUID,body:ReportInput,request:Request):
    return request.app.state.evidence.report(str(project_id),str(engagement_id),body)


@router.get('/reports/{report_id}')
async def get_report(project_id:UUID,engagement_id:UUID,report_id:UUID,request:Request):
    return request.app.state.evidence.get_report(str(project_id),str(engagement_id),str(report_id))

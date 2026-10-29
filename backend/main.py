import asyncio
import hmac
import json
import logging
import hashlib
import ipaddress
import re
import base64
import time
from uuid import uuid4, UUID
from pathlib import Path
from contextlib import asynccontextmanager, aclosing
import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr, TypeAdapter, ValidationError
from fastapi.exceptions import RequestValidationError
from sse_starlette.sse import EventSourceResponse
from config import ROOT, WORKSPACE_DIR, MODELS, OLLAMA_URL, ALLOWED_ORIGINS, MODEL_TIMEOUT, WEB_DIST_DIR, DOCUMENT_EXTENSIONS, IMAGE_EXTENSIONS, MAX_UPLOAD
from contracts import ChatPayload, AgentPayload, HistoryMessage, event
from model_runtime import runtime, clean_answer, ThinkSplitter
from security import ApiBoundary, load_token, session_cookie, image_ticket
from store import Store
from services import read_upload, ingest_document, ingest_image, prepare_chat, answer_chat, until_disconnect
from agent import execute_agent_pipeline
from router import detect_pipeline_route
from tools import apply_proposal
from pentest import Assessment, assess, targets, nmap_path
import preferences
from config import DATA_DIR
from engagements import EngagementStore, router as engagement_router
from local_desktop import router as local_desktop_router
from security_jobs import JobStore, OfflineJobRunner, router as jobs_router
from security_evidence import EvidenceStore, EvidenceInput, router as evidence_router
from mcp_gateway import MCPGateway, router as mcp_router
from security_orchestration import OrchestrationStore, OrchestrationWorker, router as orchestration_router
from security_agents import SpecialistStore, SpecialistWorker, init_evidence_specialists, analyze_evidence_specialist, router as specialists_router
from web_checks import WebRunner
from bounded_scan import ScanRunner, ApprovedScanExecution, binary_hash
from search_workspace import router as search_router
from chat_web import web_context, linked_answer
from deep_analysis import router as deep_analysis_router, init as init_deep_analysis, chat_report
from chat_orchestrator import classify, security_slots
from auto_governance import prepare_plan, create_approved_jobs
from security_jobs import Stop, Approval as JobApproval
from deep_analysis import AnalysisRequest, analyze

logger = logging.getLogger("agent.api")


@asynccontextmanager
async def lifespan(app):
    load_token()
    preferences.load_settings()
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    app.state.store = Store(DATA_DIR)
    app.state.write_lock = asyncio.Lock()
    app.state.pentest_lock = asyncio.Lock()
    app.state.engagements = EngagementStore(DATA_DIR)
    app.state.jobs = JobStore(app.state.engagements)
    app.state.evidence = EvidenceStore(app.state.engagements, app.state.jobs)
    app.state.web_runner = WebRunner(app.state.jobs, app.state.evidence)
    init_deep_analysis(app.state.engagements)
    init_evidence_specialists(app.state.engagements)
    app.state.jobs.web_runner = app.state.web_runner
    app.state.scan_runner = ScanRunner(app.state.jobs, app.state.evidence)
    app.state.jobs.scan_runner = app.state.scan_runner
    app.state.mcp = MCPGateway(app.state.engagements, app.state.jobs, app.state.evidence, DATA_DIR)
    app.state.jobs.gateway = app.state.mcp
    app.state.job_runner = OfflineJobRunner(app.state.jobs)
    app.state.job_runner.start()
    app.state.orchestrations = OrchestrationStore(app.state.engagements, app.state.jobs, app.state.mcp, app.state.evidence)
    app.state.jobs.orchestrations = app.state.orchestrations
    app.state.orchestration_worker = OrchestrationWorker(app.state.orchestrations)
    app.state.orchestration_worker.start()
    app.state.specialists = SpecialistStore(app.state.engagements, app.state.jobs, app.state.evidence)
    app.state.jobs.specialists = app.state.specialists
    app.state.specialist_worker = SpecialistWorker(app.state.specialists)
    app.state.specialist_worker.start()
    try:
        yield
    finally:
        await app.state.specialist_worker.stop()
        await app.state.orchestration_worker.stop()
        await app.state.job_runner.stop()


app = FastAPI(title="Jo Workspace", lifespan=lifespan)
app.include_router(engagement_router)
app.include_router(local_desktop_router)
app.include_router(jobs_router)
app.include_router(evidence_router)
app.include_router(mcp_router)
app.include_router(orchestration_router)
app.include_router(specialists_router)
app.include_router(search_router)
app.include_router(deep_analysis_router)
app.add_middleware(ApiBoundary)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS,
                   allow_credentials=True, allow_methods=["GET", "POST", "PUT", "DELETE"],
                   allow_headers=["Authorization", "Content-Type"])


def error_text(exc):
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return "Batas waktu inferensi/antrean tercapai. Coba permintaan yang lebih singkat."
    if isinstance(exc, httpx.HTTPError):
        return "Ollama tidak dapat dihubungi. Pastikan layanan model aktif."
    return str(exc)[:500] or "Permintaan gagal."


@app.exception_handler(ValueError)
async def invalid_input(request, exc):
    return JSONResponse({"detail": error_text(exc)}, status_code=400)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request, exc):
    return JSONResponse({"detail": [{"loc": list(item["loc"]), "msg": "Nilai tidak valid.", "type": item["type"]} for item in exc.errors()]}, status_code=422)


@app.exception_handler(TimeoutError)
@app.exception_handler(httpx.TimeoutException)
async def timed_out(request, exc):
    return JSONResponse({"detail": error_text(exc)}, status_code=504)


@app.exception_handler(httpx.HTTPError)
async def model_unavailable(request, exc):
    return JSONResponse({"detail": error_text(exc)}, status_code=503)


class Login(BaseModel):
    token: str = Field(min_length=24, max_length=200)


@app.post("/api/session")
async def login(payload: Login, request: Request, response: Response):
    if not hmac.compare_digest(payload.token, request.state.api_token):
        raise HTTPException(401, "Token akses tidak benar.")
    response.set_cookie("agent_session", session_cookie(request.state.api_token),
                        httponly=True, secure=request.url.scheme == "https",
                        samesite="strict", max_age=43200, path="/")
    return {"status": "connected"}


@app.delete("/api/session")
async def logout(response: Response):
    response.delete_cookie("agent_session", path="/")
    return {"status": "disconnected"}


@app.get("/api/health")
async def health_check():
    async with httpx.AsyncClient(timeout=3) as client:
        response = await client.get(OLLAMA_URL+"/api/tags")
        response.raise_for_status()
        models = [m["name"] for m in response.json().get("models", [])]
    missing = [name for name in set(MODELS.values()) if name not in models and name+":latest" not in models]
    return {"status": "connected" if not missing else "degraded", "installed_models": models,
            "missing_models": missing, "models": MODELS,
            "queue": {"active": runtime.active, "waiting": runtime.waiting}}


def gpu_status():
    try:
        import pynvml
        pynvml.nvmlInit()
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            info = pynvml.nvmlDeviceGetMemoryInfo(handle)
            name = pynvml.nvmlDeviceGetName(handle)
            return {"available": True, "name": name.decode() if isinstance(name, bytes) else name,
                    "vram_used_mb": info.used // 1024**2, "vram_total_mb": info.total // 1024**2,
                    "usage_percent": round(info.used / info.total * 100)}
        finally:
            pynvml.nvmlShutdown()
    except Exception:
        return {"available": False, "name": "GPU tidak tersedia", "vram_used_mb": 0,
                "vram_total_mb": 0, "usage_percent": 0}


@app.get("/api/gpu-status")
async def get_gpu_status():
    return await asyncio.to_thread(gpu_status)


@app.get("/api/metrics")
async def metrics():
    return {"active": runtime.active, "waiting": runtime.waiting,
            "completed": runtime.completed, "failed": runtime.failed, "last": runtime.last_metrics}


@app.get("/api/settings")
async def get_settings():
    return {"settings": preferences.current.model_dump(), "defaults": preferences.defaults,
            "ollama_url": OLLAMA_URL, "workspace": str(WORKSPACE_DIR),
            "max_upload_mb": 8, "max_attachments": 4}


@app.post("/api/settings")
async def update_settings(payload: preferences.ServerSettings):
    if runtime.active or runtime.waiting:
        raise HTTPException(409, "Tunggu antrean model selesai sebelum mengubah pengaturan.")
    preferences.save_settings(payload)
    return {"settings": preferences.current.model_dump()}


@app.get("/api/usage")
async def get_usage():
    return {"rows": runtime.usage.rows, "timezone": "UTC", "retention_days": 90,
            "persistence_error": runtime.usage.persistence_error,
            "active": runtime.active, "waiting": runtime.waiting}


@app.delete("/api/usage")
async def clear_usage():
    if runtime.active or runtime.waiting:
        raise HTTPException(409, "Tunggu antrean model selesai sebelum menghapus usage.")
    try:
        runtime.usage.clear()
    except OSError as exc:
        raise HTTPException(500, str(exc)) from exc
    return {"status": "cleared"}


def parse_history(value):
    try:
        parsed = TypeAdapter(list[HistoryMessage]).validate_json(value)
        if len(parsed) > 100:
            raise ValueError("Riwayat maksimal 100 pesan.")
        return parsed
    except ValidationError as exc:
        raise ValueError("Format riwayat tidak valid.") from exc


def wire(payload):
    return {"data": json.dumps(payload, ensure_ascii=False)}


def contains_session_token(text):
    for match in re.finditer(r'(?<![\w-])[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}(?![\w-])', text):
        try:
            segment = match.group().split('.')[1]
            claims = json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))
            if isinstance(claims, dict) and isinstance(claims.get('sub'), str) and isinstance(claims.get('aud'), str):
                return True
        except (ValueError, UnicodeError, TypeError):
            continue
    return False


class ChatUploadProposal(BaseModel):
    session_id: str = Field(min_length=1, max_length=100)
    filename: str = Field(min_length=1, max_length=120)
    size: int = Field(ge=1, le=MAX_UPLOAD, strict=True)
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    prompt: str = Field(min_length=1, max_length=6000)
    history: list[HistoryMessage] = Field(default_factory=list, max_length=100)
    model_override: str | None = Field(default=None, min_length=1, max_length=120, pattern=r'^[\w.\-/:]+$')


@app.post('/api/chat/uploads/prepare')
async def prepare_chat_upload(payload: ChatUploadProposal, request: Request):
    name = payload.filename
    if Path(name.replace('\\', '/')).name != name or any(c in name for c in '\r\n\x00'):
        raise HTTPException(422, 'Nama lampiran tidak valid.')
    suffix = Path(name).suffix.lower()
    if suffix not in DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS:
        raise HTTPException(422, 'Format lampiran tidak didukung.')
    if contains_session_token(payload.prompt):
        raise HTTPException(422, 'Jangan kirim token sesi dalam pesan chat.')
    vision = suffix in IMAGE_EXTENSIONS
    action = await asyncio.to_thread(request.app.state.store.propose_chat_action, payload.session_id, {
        'intent':'attachment', 'target':name, 'tools':['Vision Engine' if vision else 'Document Engine', 'Model jawaban'],
        'duration':'Bergantung pada ukuran lampiran dan model', 'summary':'Lampiran akan diproses dan digunakan sebagai sumber untuk menjawab pertanyaan.',
        'filename':name, 'size':payload.size, 'sha256':payload.sha256, 'vision':vision, 'prompt':payload.prompt,
        'history':[item.model_dump() for item in payload.history], 'model_override':payload.model_override})
    return {'action':{key:value for key,value in action.items() if key not in ('filename','size','sha256','vision','prompt','history','model_override')}}


@app.post('/api/chat/uploads/{action_id}/execute')
async def execute_chat_upload(action_id: str, request: Request, file: UploadFile = File(...),
                              session_id: str = Form(..., min_length=1, max_length=100)):
    store = request.app.state.store
    action = await asyncio.to_thread(store.approved_upload, action_id, session_id)
    name, data = await read_upload(file)
    if name != action['filename'] or len(data) != action['size'] or hashlib.sha256(data).hexdigest() != action['sha256']:
        raise HTTPException(409, 'Lampiran berbeda dari yang disetujui. Buat rencana baru.')
    await validate_model_override(action.get('model_override'))
    async with request.app.state.write_lock:
        await asyncio.to_thread(store.approved_upload, action_id, session_id, True)
    async def stream():
        try:
            yield wire(event('status', step='extracting', label='Memproses lampiran yang disetujui'))
            if action['vision']:
                attachment, evidence = await ingest_image(store, session_id, name, data, action.get('model_override'))
            else:
                attachment, evidence = await ingest_document(store, session_id, name, data), None
            yield wire(event('attachment', attachment=attachment))
            answer = await answer_chat(store, ChatPayload(prompt=action['prompt'], history=action['history'], session_id=session_id,
                target='vision' if action['vision'] else 'reasoning', attachment_ids=[attachment['id']], model_override=action.get('model_override')))
            yield wire(event('result', **answer, visual_analysis=evidence))
            yield wire(event('done'))
        except Exception as exc:
            yield wire(event('error', detail=error_text(exc)))
    return EventSourceResponse(stream(), ping=10)


TRACE_PHASES = {"thinking": {"step": "thinking", "label": "Berpikir"},
                "token": {"step": "writing", "label": "Menulis jawaban"}}
INTENT_LABELS = {"chat": "percakapan", "coding": "coding agent", "security": "pemeriksaan keamanan", "web": "pencarian web"}


async def stream_answer(model, messages, out):
    """Stream reasoning and answer text as trace events; the raw answer lands in out['text'].

    Reasoning goes out as `thinking` events, never mixed into answer `token` events. If the
    reasoning budget runs out before any answer, a second pass answers without thinking."""
    out["text"] = ""
    for think in (True, False):
        splitter, phase, exhausted = ThinkSplitter(), None, False
        async for chunk in runtime.chunks(model, messages, think=think):
            if chunk.get("status") == "running":
                yield wire(event("status", step="model", label="Memuat model dan membaca prompt", detail=model))
            elif chunk.get("status") == "thinking_unsupported":
                yield wire(event("status", step="model", label="Memuat model dan membaca prompt",
                                 detail=f"{model} · model tidak mendukung penalaran, menjawab langsung"))
            message = chunk.get("message", {})
            parts = [("thinking", message.get("thinking") or ""), *splitter.feed(message.get("content") or "")]
            if chunk.get("done"):
                parts += splitter.flush()
            for kind, text in parts:
                if not text:
                    continue
                if kind != phase:
                    phase = kind
                    yield wire(event("status", **TRACE_PHASES[kind]))
                if kind == "token":
                    out["text"] += text
                yield wire(event(kind, token=text))
            if not chunk.get("done"):
                continue
            if chunk.get("done_reason") == "length":
                if not (think and not clean_answer(out["text"])):
                    raise ValueError("Batas token tercapai. Jawaban belum lengkap; persempit pertanyaan.")
                exhausted = True
            elif phase == "token":
                tokens, seconds = chunk.get("eval_count") or 0, (chunk.get("eval_duration") or 0) / 1e9
                yield wire(event("status", **TRACE_PHASES["token"],
                                 detail=f"{tokens} token dihasilkan (penalaran + jawaban) · "
                                        f"{tokens / seconds:.1f} token/dtk".replace(".", ",") if seconds and tokens else None))
        if not exhausted:
            return
        out["text"] = ""
        yield wire(event("status", step="fallback", label="Anggaran penalaran habis, menjawab tanpa penalaran"))


async def validate_model_override(model):
    if not model:
        return None
    async with httpx.AsyncClient(timeout=3) as client:
        response = await client.get(OLLAMA_URL + "/api/tags")
        response.raise_for_status()
        installed = {item.get("name") for item in response.json().get("models", [])}
    if model not in installed:
        raise HTTPException(400, "Model yang dipilih tidak terpasang di Ollama.")
    return model


@app.post("/api/chat")
async def chat_endpoint(payload: ChatPayload, request: Request):
    if contains_session_token(payload.prompt):
        raise HTTPException(422, 'Jangan kirim token sesi di chat. Gunakan kolom rahasia pada kartu konfirmasi.')
    if not payload.unified and payload.web_mode != 'off':
        raise HTTPException(423, 'Pencarian web memerlukan persetujuan rencana di chat.')
    await validate_model_override(payload.model_override)
    prepared = (await prepare_chat(request.app.state.store, payload)
                if payload.attachment_ids or payload.target == "vision" else None)
    async def stream():
        try:
            model = payload.model_override or MODELS["reasoning" if payload.target == "vision" else payload.target]
            yield wire(event("status", step="queued", label="Menunggu giliran model"))
            if payload.unified:
                yield wire(event("status", step="routing", label="Menentukan jenis permintaan"))
                router_model = payload.model_override or MODELS["reasoning"]
                intent = await classify(payload.prompt, payload.history, router_model)
                if payload.web_mode == "on" and intent == "chat":
                    intent = "web"
                yield wire(event("status", step="routing", label="Menentukan jenis permintaan",
                                 detail=f"Intent: {INTENT_LABELS[intent]} · router {router_model}"))
                if intent == "coding":
                    if payload.attachment_ids:
                        yield wire(event("result", result="Coding Agent belum menggunakan lampiran sebagai konteks. Lepaskan lampiran atau sebutkan file workspace yang ingin diperiksa.", sources=[], images=[]))
                        yield wire(event("done"))
                        return
                    action = await asyncio.to_thread(request.app.state.store.propose_chat_action, payload.session_id, {
                        "intent": "coding", "target": "Workspace lokal", "tools": ["Coding Agent", "read_file", "list_dir", "propose_write"],
                        "duration": "Hingga batas waktu model", "summary": "Agen akan membaca workspace dan dapat mengusulkan diff. Penerapan diff memerlukan persetujuan terpisah.",
                        "prompt": payload.prompt, "history": [h.model_dump() for h in payload.history], "model_override": payload.model_override})
                    yield wire(event("action_proposal", action={k: v for k, v in action.items() if k not in ("prompt", "history", "model_override")}))
                    yield wire(event("done"))
                    return
                if intent == "security" and not payload.model_override:
                    model = MODELS["security"]
                if intent == "security":
                    yield wire(event("status", step="planning", label="Mengekstrak target, port, dan tool dari pesan"))
                    slots = await security_slots(payload.prompt, payload.history, payload.model_override or MODELS["reasoning"])
                    plan, question = prepare_plan(slots)
                    yield wire(event("status", step="planning", label="Mengekstrak target, port, dan tool dari pesan",
                                     detail="Parameter belum lengkap, perlu pertanyaan lanjutan" if question else
                                     "Tool: " + ", ".join(item["tool"] for item in (plan.get("jobs") or [plan]))))
                    if question:
                        yield wire(event("result", result=question, sources=[], images=[]))
                        yield wire(event("done"))
                        return
                    project_id = str(payload.project_id or uuid4())
                    plans = plan.get("jobs") or [plan]
                    disclosures = []
                    if plan.get('url_va_profile'):
                        disclosures.append('Paket VA URL dasar: HEAD untuk header' +
                                           (' dan satu GET untuk inventaris HTML tanpa login atau menjalankan JavaScript.' if any(item['tool'] == 'inventory-html' for item in plans) else '.') +
                                           ' Kandidat tautan tidak diakses; tidak ada scan port, subdomain, atau uji eksploitasi. Ini bukan asesmen kerentanan menyeluruh.')
                    if any(item['tool'] in ('subfinder-passive', 'amass-passive') for item in plans):
                        disclosures.append('Domain akan dikirim ke crt.sh.')
                    if any(item['tool'] == 'active-reflection' for item in plans):
                        disclosures.append('Active reflection mengirim satu marker alfanumerik melalui query GET.')
                    if any(item['tool'] == 'scoped-spider' for item in plans):
                        disclosures.append('Scoped spider dapat mengirim hingga lima GET dalam scope.')
                    auth_jobs = [item for item in plans if item['tool'] == 'auth-two-session']
                    if len(auth_jobs) > 1:
                        raise ValueError('Hanya satu job dua sesi yang dapat disetujui dalam satu rencana.')
                    if auth_jobs:
                        disclosures.append('Tiga GET: tanpa sesi dan dengan masing-masing dua akun uji; klaim JWT tidak diverifikasi. Token dimasukkan hanya di kartu dan disimpan sementara di memori.')
                    document_jobs = [item for item in plans if item["tool"] == "document-review"]
                    if document_jobs:
                        if len(payload.attachment_ids) != 1:
                            yield wire(event("result", result="Lampirkan tepat satu dokumen yang relevan untuk review ini, lalu ulangi permintaan.", sources=[], images=[]))
                            yield wire(event("done"))
                            return
                        attachment = await asyncio.to_thread(request.app.state.store.attachment, payload.attachment_ids[0], payload.session_id)
                        if attachment["kind"] != "document":
                            raise ValueError("Review WhiteBox/GreyBox memerlukan lampiran dokumen atau kode, bukan deskripsi gambar.")
                        if len(attachment["content"].encode("utf-8")) > 65536:
                            raise ValueError("Dokumen yang diekstrak melebihi batas evidence 64 KiB; gunakan bagian yang lebih kecil.")
                        reference = {"id": attachment["id"], "name": attachment["name"],
                                     "sha256": hashlib.sha256(attachment["content"].encode("utf-8")).hexdigest()}
                        for item in document_jobs:
                            item["attachment"] = reference
                    action = await asyncio.to_thread(request.app.state.store.propose_chat_action, payload.session_id, {
                        "intent": "security", "target": "; ".join(f"{item['tool']}: {item['target']['value']} (port {','.join(map(str, item['ports']))}, {item['assessment_mode']})" + (f" · dokumen {item['attachment']['name']} · SHA-256 {item['attachment']['sha256']} · bukti {item['evidence_kind']} · alias {item['test_account_ref'] or '-'}" if item.get('attachment') else '') for item in plans), "tools": [*[item["tool"] for item in plans], f"Deep Analysis {plan['assessment_mode'].title()}", *[f"Spesialis {role} (review evidence)" for role in plan.get('specialists', [])]],
                        "duration": f"Maksimal {sum(item['timeout'] for item in plans)} detik untuk tool, ditambah analisis model",
                        "summary": f"Konfirmasi menyatakan Anda berwenang menguji target dan menyetujui scope, port, lingkungan, dan batas yang ditampilkan. Mode {plan['assessment_mode'].title()}, maksimal 1 request per detik dan concurrency 1. " + " ".join(disclosures) + " Kontak darurat tidak diberikan; persetujuan lokal tidak memverifikasi izin pihak ketiga.",
                        "ports": sorted({port for item in plans for port in item["ports"]}), "environment": plan["environment"], "project_id": project_id,
                        "account_refs": auth_jobs[0]['account_refs'] if auth_jobs else [],
                        "owner_json_pointer": auth_jobs[0]['owner_json_pointer'] if auth_jobs else '',
                        "project_is_new": payload.project_id is None, "plan": plan, "model_override": payload.model_override})
                    yield wire(event("action_proposal", action={k: v for k, v in action.items() if k not in ("plan", "model_override")}))
                    yield wire(event("done"))
                    return
                if intent == "web" and payload.web_mode != "off":
                    action = await asyncio.to_thread(request.app.state.store.propose_chat_action, payload.session_id, {
                        "intent": "web", "target": "Sumber web yang relevan dengan permintaan", "tools": ["Pencarian web", "Pembacaan halaman publik"],
                        "duration": "Bergantung pada respons sumber web", "summary": "Pencarian dapat mengirim pertanyaan ke penyedia pencarian serta mengakses halaman dan gambar publik yang relevan.",
                        "prompt": payload.prompt, "history": [h.model_dump() for h in payload.history], "model_override": payload.model_override})
                    yield wire(event("action_proposal", action={k: v for k, v in action.items() if k not in ("prompt", "history", "model_override")}))
                    yield wire(event("done"))
                    return
            deep = chat_report(request.app.state, payload.project_id, payload.prompt) if payload.target == 'reasoning' and not payload.attachment_ids else None
            if deep is not None:
                yield wire(event('result', result=deep, sources=[], coverage=None, images=[]))
                yield wire(event('done'))
                return
            web = None
            if not payload.unified and not payload.attachment_ids and payload.target != "vision" and payload.web_mode != "off":
                yield wire(event("status", step="web_plan", label="Memeriksa kebutuhan sumber web"))
                web = await web_context(payload.prompt, payload.web_mode, model, payload.history)
            if web:
                messages, sources, coverage = web['messages'], web['sources'], None
                images = web['images']
                yield wire(event("status", step="web_sources", label="Menyusun jawaban dari sumber web"))
            else:
                yield wire(event("status", step="context", label="Menyiapkan konteks"))
                _, messages, sources, coverage = prepared or await prepare_chat(request.app.state.store, payload)
                images = []
                yield wire(event("status", step="context", label="Menyiapkan konteks",
                                 detail=f"{len(messages) - 2} pesan riwayat · {len(sources)} sumber lampiran"))
            if coverage:
                yield wire(event("sources", sources=sources, coverage=coverage))
            elif web:
                yield wire(event("sources", sources=sources, images=images))
            out = {}
            async for item in stream_answer(model, messages, out):
                yield item
            answer = clean_answer(out["text"])
            if not answer or answer.lower().startswith("thinking process"):
                raise ValueError("Model tidak menghasilkan jawaban akhir.")
            if web:
                answer = linked_answer(answer, sources)
            yield wire(event("result", result=answer, sources=sources, coverage=coverage, images=images))
            yield wire(event("done"))
        except Exception as exc:
            yield wire(event("error", detail=error_text(exc)))
    return EventSourceResponse(stream(), ping=10)


class ChatActionDecision(BaseModel):
    session_id: str = Field(min_length=1, max_length=100)
    approve: bool
    session_tokens: list[SecretStr] | None = Field(default=None, min_length=2, max_length=2)


@app.post("/api/chat/actions/{action_id}/confirm")
async def confirm_chat_action(action_id: str, payload: ChatActionDecision, request: Request):
    async with request.app.state.write_lock:
        action = await asyncio.to_thread(request.app.state.store.pending_chat_action, action_id, payload.session_id)
        plans = (action.get('plan') or {}).get('jobs') or ([action['plan']] if action.get('plan') else [])
        needs_tokens = any(item.get('tool') == 'auth-two-session' for item in plans)
        if payload.approve and needs_tokens:
            try:
                peer = ipaddress.ip_address(request.client.host)
            except (ValueError, AttributeError):
                peer = None
            if request.url.scheme != 'https' and not (peer and peer.is_loopback):
                raise HTTPException(403, 'Token sesi hanya diterima melalui HTTPS atau koneksi loopback.')
            if not payload.session_tokens:
                raise HTTPException(422, 'Dua token sesi uji diperlukan pada kartu konfirmasi.')
            try:
                JobApproval(expected_revision=1, actor_label='operator', note='review', acknowledge=True, session_tokens=payload.session_tokens)
            except ValidationError:
                raise HTTPException(422, 'Dua token JWT uji harus berbeda, belum kedaluwarsa, dan memiliki sub berbeda serta aud yang sama.') from None
        elif payload.session_tokens:
            raise HTTPException(422, 'Token hanya diterima untuk job dua sesi yang disetujui.')
        action = await asyncio.to_thread(request.app.state.store.decide_chat_action, action_id, payload.session_id, payload.approve)
    async def stream():
        if not payload.approve:
            yield wire(event("result", result="Rencana dibatalkan.", proposals=[]))
            yield wire(event("done"))
            return
        try:
            await validate_model_override(action.get("model_override"))
            if action["intent"] == "coding":
                yield wire(event("status", step="coding", label="Coding Agent sedang memeriksa workspace"))
                result = await execute_agent_pipeline(action["prompt"], store=request.app.state.store,
                                                  session_id=payload.session_id, model_override=action.get("model_override"),
                                                  history=action.get("history", []))
                await asyncio.to_thread(request.app.state.store.authorize_code_proposals, payload.session_id, action_id,
                                        [item['id'] for item in result.get('proposals', [])])
                yield wire(event("result", result=result["result"], proposals=result.get("proposals", [])))
            elif action["intent"] == "web":
                model = action.get("model_override") or MODELS["reasoning"]
                yield wire(event("status", step="web", label="Mencari sumber web"))
                web = await web_context(action["prompt"], "on", model, action.get("history", []))
                if not web:
                    raise ValueError("Tidak ada sumber web yang dapat digunakan.")
                yield wire(event("status", step="web", label="Mencari sumber web",
                                 detail=f"{len(web['sources'])} sumber · {len(web['images'])} gambar"))
                yield wire(event("sources", sources=web["sources"]))
                out = {}
                async for item in stream_answer(model, web["messages"], out):
                    yield item
                answer = clean_answer(out["text"])
                if not answer:
                    raise ValueError("Model tidak menghasilkan jawaban akhir.")
                images = [{**item, 'ticket': image_ticket(request.state.api_token, item['url'], int(time.time()) + 900)} for item in web['images']]
                yield wire(event("result", result=linked_answer(answer, web["sources"]), sources=web["sources"], images=images))
            elif action["intent"] == "attachment":
                yield wire(event("result", result="Lampiran disetujui; siap diproses."))
            elif action["intent"] == "security":
                yield wire(event("status", step="governance", label="Mencatat persetujuan dan membuat job"))
                plans = action["plan"].get("jobs") or [action["plan"]]
                sources = {}
                for plan_item in plans:
                    if plan_item.get("attachment"):
                        reference = plan_item["attachment"]
                        attachment = await asyncio.to_thread(request.app.state.store.attachment, reference["id"], payload.session_id)
                        if hashlib.sha256(attachment["content"].encode("utf-8")).hexdigest() != reference["sha256"]:
                            raise ValueError("Lampiran berubah sejak rencana dibuat. Buat rencana baru.")
                        sources[reference["id"]] = attachment
                project, engagement, job_ids = create_approved_jobs(request.app.state,
                    action["project_id"], payload.session_id, action["plan"], payload.session_tokens)
                payload.session_tokens = None
                summaries = []
                try:
                    for job_id, plan_item in zip(job_ids, plans):
                        last = None
                        while True:
                            job = await asyncio.to_thread(request.app.state.jobs.detail, project, engagement, job_id)
                            if job["status"] != last:
                                last = job["status"]
                                yield wire(event("status", step=last, label=f"Job {job_id}: {last}"))
                            if last in ("completed", "failed", "cancelled"):
                                break
                            await asyncio.sleep(0.5)
                        if last != "completed":
                            for other in job_ids:
                                await asyncio.to_thread(request.app.state.jobs.cancel, project, engagement, other, Stop())
                            raise ValueError(job.get("error_message") or f"Job {job_id} berakhir dengan status {last}.")
                        yield wire(event("status", step="analysis", label=f"Menganalisis bukti job {job_id}"))
                        try:
                            evidence_id = None
                            if plan_item.get("attachment"):
                                from engagements import utc_now
                                attachment = sources[plan_item["attachment"]["id"]]
                                evidence = await asyncio.to_thread(request.app.state.evidence.add_evidence, project, engagement,
                                    EvidenceInput(job_id=UUID(job_id), step_ordinal=1, source="external_import",
                                        title="Lampiran chat · " + attachment["name"], captured_at=utc_now(),
                                        tool_name="Chat attachment import", tool_version="1", content=attachment["content"], acknowledge=True))
                                evidence_id = UUID(evidence["id"])
                            analysis_request = AnalysisRequest(
                                job_id=UUID(job_id), evidence_id=evidence_id,
                                assessment_mode=plan_item["assessment_mode"],
                                evidence_kind=plan_item["evidence_kind"] or "external_observation",
                                test_account_ref=plan_item["test_account_ref"], model=action.get("model_override") or MODELS["security"],
                                actor_label="operator sesi lokal", acknowledge=True)
                            analysis = await analyze(UUID(project), UUID(engagement), analysis_request, request)
                            output = analysis["output"]
                            report = format_analysis(output)
                            source = analysis["source"]
                            summaries.append(f"{report}\n\nJob: {job_id} · Analisis: {analysis['id']}\nEvidence: {source['evidence_id']} · SHA-256: {source['artifact_hash']}")
                            for role in action['plan'].get('specialists', []):
                                yield wire(event("status", step="specialist", label=f"Spesialis {role} meninjau evidence job {job_id}"))
                                try:
                                    specialist = await analyze_evidence_specialist(request.app.state, project, engagement, analysis_request, role)
                                    sections = format_analysis(specialist['output'])
                                    summaries.append(f"**Spesialis {role} · review evidence**\n\n{sections}\n\nAnalisis: {specialist['id']}")
                                except Exception as exc:
                                    summaries.append(f"Spesialis {role} gagal meninjau job {job_id}: {error_text(exc)}.")
                        except Exception as exc:
                            summaries.append(f"Job {job_id} selesai dan bukti tersimpan, tetapi Deep Analysis gagal: {error_text(exc)}.")
                    yield wire(event("result", result="\n\n---\n\n".join(summaries) + f"\n\nEngagement: {engagement} · Analisis memerlukan review manusia.", proposals=[]))
                except asyncio.CancelledError:
                    for job_id in job_ids:
                        await asyncio.to_thread(request.app.state.jobs.cancel, project, engagement, job_id, Stop())
                    raise
            else:
                raise ValueError("Jenis rencana tidak didukung.")
            yield wire(event("done"))
        except Exception as exc:
            yield wire(event("error", detail=error_text(exc)))
    return EventSourceResponse(stream(), ping=10)


ANALYSIS_LABELS = (("summary", "Ringkasan"), ("observations", "Observasi"),
                   ("limitations", "Keterbatasan"), ("recommendations", "Rekomendasi"))


def format_analysis(output):
    """Render a grounded analysis for chat with Indonesian headings, skipping empty sections."""
    sections = []
    for key, label in ANALYSIS_LABELS:
        value = output.get(key)
        if not value:
            continue
        body = "\n".join(f"- {item}" for item in value) if isinstance(value, list) else str(value)
        sections.append(f"**{label}**\n{body}")
    return "\n\n".join(sections)


async def document_result(request, file, prompt, history, session_id):
    name, data = await read_upload(file)
    attachment = await ingest_document(request.app.state.store, session_id, name, data)
    payload = ChatPayload(prompt=prompt, history=parse_history(history), session_id=session_id, attachment_ids=[attachment["id"]])
    return {**await answer_chat(request.app.state.store, payload), "attachment": attachment, "filename": name}


@app.post("/api/document/parse")
async def parse_document_endpoint(request: Request, file: UploadFile = File(...), prompt: str = Form(..., min_length=1, max_length=6000),
                                  history: str = Form("[]", max_length=200000), session_id: str = Form("default", max_length=100)):
    return await until_disconnect(request, document_result(request, file, prompt, history, session_id))


@app.post("/api/document/analyze-stream")
async def document_stream(request: Request, file: UploadFile = File(...), prompt: str = Form(..., min_length=1, max_length=6000),
                          history: str = Form("[]", max_length=200000), session_id: str = Form("default", max_length=100),
                          model_override: str | None = Form(None, max_length=120, pattern=r"^[\w.\-/:]+$")):
    await validate_model_override(model_override)
    name, data = await read_upload(file)
    parsed = parse_history(history)
    async def stream():
        try:
            yield wire(event("status", step="extracting", label="Mengekstrak dokumen"))
            attachment = await ingest_document(request.app.state.store, session_id, name, data)
            yield wire(event("attachment", attachment=attachment))
            yield wire(event("status", step="analyzing", label="Mencari sumber dan menganalisis"))
            answer = await answer_chat(request.app.state.store, ChatPayload(prompt=prompt, history=parsed, session_id=session_id, attachment_ids=[attachment["id"]], model_override=model_override))
            yield wire(event("result", **answer, attachment=attachment))
            yield wire(event("done"))
        except Exception as exc:
            yield wire(event("error", detail=error_text(exc)))
    return EventSourceResponse(stream(), ping=10)


async def vision_result(request, image, prompt, history, session_id, model_override=None):
    name, data = await read_upload(image)
    attachment, evidence = await ingest_image(request.app.state.store, session_id, name, data, model_override)
    answer = await answer_chat(request.app.state.store, ChatPayload(prompt=prompt, target="vision", history=parse_history(history),
                                                                  session_id=session_id, attachment_ids=[attachment["id"]], model_override=model_override))
    return {**answer, "attachment": attachment, "visual_analysis": evidence}


@app.post("/api/vision/analyze")
async def vision_endpoint(request: Request, image: UploadFile = File(...), prompt: str = Form("Jelaskan gambar.", min_length=1, max_length=6000),
                          history: str = Form("[]", max_length=200000), session_id: str = Form("default", max_length=100),
                          model_override: str | None = Form(None, max_length=120, pattern=r"^[\w.\-/:]+$")):
    await validate_model_override(model_override)
    return await until_disconnect(request, vision_result(request, image, prompt, history, session_id, model_override))


@app.post("/api/agent/run")
async def run_agent_endpoint(payload: AgentPayload, request: Request):
    return await until_disconnect(request, execute_agent_pipeline(payload.prompt, payload.max_iterations,
                                  store=request.app.state.store, session_id=payload.session_id))


class Approval(BaseModel):
    session_id: str = Field(min_length=1, max_length=100)
    approve: bool


@app.post("/api/chat/code-proposals/{proposal_id}/confirm")
async def approve_proposal(proposal_id: str, payload: Approval, request: Request):
    # Serialize approval + application to prevent replay/parallel overwrites.
    async with request.app.state.write_lock:
        store = request.app.state.store
        await asyncio.to_thread(store.require_chat_code_proposal, proposal_id, payload.session_id)
        proposal = await asyncio.to_thread(store.pending, proposal_id, payload.session_id)
        if not payload.approve:
            await asyncio.to_thread(store.finish, proposal_id, "rejected")
            return {"status": "rejected"}
        try:
            result = await asyncio.to_thread(apply_proposal, proposal)
        except (ValueError, OSError) as exc:
            raise HTTPException(409, str(exc)) from exc
        await asyncio.to_thread(store.finish, proposal_id, "applied")
        return {"status": "applied", **result}


@app.delete("/api/attachments/{attachment_id}")
async def delete_attachment(attachment_id: str, request: Request, session_id: str):
    await asyncio.to_thread(request.app.state.store.delete_attachment, attachment_id, session_id)
    return {"status": "deleted"}


@app.post("/api/agent/dispatch")
async def dispatch_task_endpoint(request: Request, prompt: str = Form(..., min_length=1, max_length=6000),
                                 file: UploadFile | None = File(None), history: str = Form("[]", max_length=200000),
                                 session_id: str = Form("default", max_length=100)):
    route = detect_pipeline_route(file.filename if file else None, prompt)
    async def run():
        if route == "VISION_PIPELINE":
            return await vision_result(request, file, prompt, history, session_id)
        if route == "DOCUMENT_PIPELINE":
            return await document_result(request, file, prompt, history, session_id)
        if route == "CODING_PIPELINE":
            return await execute_agent_pipeline(prompt, store=request.app.state.store, session_id=session_id)
        return await answer_chat(request.app.state.store, ChatPayload(prompt=prompt, history=parse_history(history),
            target="security" if route == "CYBERSECURITY_PIPELINE" else "reasoning", session_id=session_id))
    return {"route": route, **await until_disconnect(request, run())}


@app.get("/api/pentest/capabilities")
async def pentest_capabilities():
    from nuclei_adapter import binary_hash as nuclei_hash
    from zap_adapter import image_hash
    from subfinder_adapter import fingerprint,amass_fingerprint
    return {"targets": [], "nmap_available": bool(nmap_path()), "execution_enabled": False, "stage": 7,
            "approved_tcp_scan_enabled":True,"nmap_binary_sha256":binary_hash(),
            "tools":["tcp-connect","nmap","nuclei-head","zap-head","auth-unauthenticated-get","auth-two-session","inventory-html","js-bundle-inventory","scoped-spider","active-reflection","subfinder-passive","amass-passive","monitoring-local"],"nuclei_binary_sha256":nuclei_hash(),"zap_image_sha256":image_hash(),"subfinder_image_sha256":fingerprint(),"amass_image_sha256":amass_fingerprint(),"approval_required":True,
            "execution_path":"Security Workspace > Engagement > Tools & monitoring"}


@app.post("/api/pentest/run")
async def pentest_run(payload: Assessment | ApprovedScanExecution, request: Request):
    if isinstance(payload, Assessment):
        raise HTTPException(423, 'Run memerlukan Project, Engagement dan job adapter yang ditinjau. Gunakan Tools & monitoring untuk menyiapkan rencana dan persetujuan.')
    from security_jobs import Approval
    project, engagement, jid = str(payload.project_id), str(payload.engagement_id), str(payload.job_id)
    detail = request.app.state.jobs.detail(project, engagement, jid)
    if not detail['plan'].get('scan'):
        raise HTTPException(422, 'Endpoint ini hanya menerima job dengan adapter eksekusi yang didukung.')
    return request.app.state.jobs.approve(project, engagement, jid, Approval(
        expected_revision=payload.expected_revision, actor_label=payload.actor_label,
        note=payload.note, acknowledge=payload.acknowledge))


if WEB_DIST_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIST_DIR, html=True), name="web")

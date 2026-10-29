import asyncio
import hmac
import json
import logging
from contextlib import asynccontextmanager, aclosing
import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, TypeAdapter, ValidationError
from sse_starlette.sse import EventSourceResponse
from config import ROOT, WORKSPACE_DIR, MODELS, OLLAMA_URL, ALLOWED_ORIGINS, MODEL_TIMEOUT, WEB_DIST_DIR
from contracts import ChatPayload, AgentPayload, HistoryMessage, event
from model_runtime import runtime, clean_answer
from security import ApiBoundary, load_token, session_cookie
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
from security_evidence import EvidenceStore, router as evidence_router
from mcp_gateway import MCPGateway, router as mcp_router
from security_orchestration import OrchestrationStore, OrchestrationWorker, router as orchestration_router
from security_agents import SpecialistStore, SpecialistWorker, router as specialists_router
from web_checks import WebRunner
from bounded_scan import ScanRunner, ApprovedScanExecution, binary_hash
from search_workspace import router as search_router
from chat_web import web_context, linked_answer
from deep_analysis import router as deep_analysis_router, init as init_deep_analysis, chat_report

logger = logging.getLogger("agent.api")


@asynccontextmanager
async def lifespan(app):
    load_token()
    preferences.load_settings()
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    app.state.store = Store()
    app.state.write_lock = asyncio.Lock()
    app.state.pentest_lock = asyncio.Lock()
    app.state.engagements = EngagementStore(DATA_DIR)
    app.state.jobs = JobStore(app.state.engagements)
    app.state.evidence = EvidenceStore(app.state.engagements, app.state.jobs)
    app.state.web_runner = WebRunner(app.state.jobs, app.state.evidence)
    init_deep_analysis(app.state.engagements)
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
        if len(parsed) > 12:
            raise ValueError("Riwayat maksimal 12 pesan.")
        return parsed
    except ValidationError as exc:
        raise ValueError("Format riwayat tidak valid.") from exc


def wire(payload):
    return {"data": json.dumps(payload, ensure_ascii=False)}


@app.post("/api/chat")
async def chat_endpoint(payload: ChatPayload, request: Request):
    model = MODELS["reasoning" if payload.target == "vision" else payload.target]
    prepared = (await prepare_chat(request.app.state.store, payload)
                if payload.attachment_ids or payload.target == "vision" else None)
    async def stream():
        try:
            yield wire(event("status", step="queued", label="Menunggu giliran model"))
            deep = chat_report(request.app.state, payload.project_id, payload.prompt) if payload.target == 'reasoning' and not payload.attachment_ids else None
            if deep is not None:
                yield wire(event('result', result=deep, sources=[], coverage=None, images=[]))
                yield wire(event('done'))
                return
            web = None
            if not payload.attachment_ids and payload.target != "vision" and payload.web_mode != "off":
                yield wire(event("status", step="web_plan", label="Memeriksa kebutuhan sumber web"))
                web = await web_context(payload.prompt, payload.web_mode, model, payload.history)
            if web:
                messages, sources, coverage = web['messages'], web['sources'], None
                images = web['images']
                yield wire(event("status", step="web_sources", label="Menyusun jawaban dari sumber web"))
            else:
                _, messages, sources, coverage = prepared or await prepare_chat(request.app.state.store, payload)
                images = []
            if coverage:
                yield wire(event("sources", sources=sources, coverage=coverage))
            elif web:
                yield wire(event("sources", sources=sources, images=images))
            text = ""
            async for chunk in runtime.chunks(model, messages):
                if chunk.get("status") == "running":
                    yield wire(event("status", step="running", label="Model sedang memproses"))
                token = chunk.get("message", {}).get("content", "")
                if token:
                    text += token
                    # Never expose partial model text: older/custom model templates can
                    # place private reasoning in content before the final answer. The UI
                    # still receives queue/running status and a cleaned terminal result.
                if chunk.get("done_reason") == "length":
                    raise ValueError("Batas token tercapai. Jawaban belum lengkap; persempit pertanyaan.")
            answer = clean_answer(text)
            if not answer or answer.lower().startswith("thinking process"):
                raise ValueError("Model tidak menghasilkan jawaban akhir.")
            if web:
                answer = linked_answer(answer, sources)
            yield wire(event("result", result=answer, sources=sources, coverage=coverage, images=images))
            yield wire(event("done"))
        except Exception as exc:
            yield wire(event("error", detail=error_text(exc)))
    return EventSourceResponse(stream(), ping=10)


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
                          history: str = Form("[]", max_length=200000), session_id: str = Form("default", max_length=100)):
    name, data = await read_upload(file)
    parsed = parse_history(history)
    async def stream():
        try:
            yield wire(event("status", step="extracting", label="Mengekstrak dokumen"))
            attachment = await ingest_document(request.app.state.store, session_id, name, data)
            yield wire(event("attachment", attachment=attachment))
            yield wire(event("status", step="analyzing", label="Mencari sumber dan menganalisis"))
            answer = await answer_chat(request.app.state.store, ChatPayload(prompt=prompt, history=parsed, session_id=session_id, attachment_ids=[attachment["id"]]))
            yield wire(event("result", **answer, attachment=attachment))
            yield wire(event("done"))
        except Exception as exc:
            yield wire(event("error", detail=error_text(exc)))
    return EventSourceResponse(stream(), ping=10)


async def vision_result(request, image, prompt, history, session_id):
    name, data = await read_upload(image)
    attachment, evidence = await ingest_image(request.app.state.store, session_id, name, data)
    answer = await answer_chat(request.app.state.store, ChatPayload(prompt=prompt, target="vision", history=parse_history(history),
                                                                  session_id=session_id, attachment_ids=[attachment["id"]]))
    return {**answer, "attachment": attachment, "visual_analysis": evidence}


@app.post("/api/vision/analyze")
async def vision_endpoint(request: Request, image: UploadFile = File(...), prompt: str = Form("Jelaskan gambar.", min_length=1, max_length=6000),
                          history: str = Form("[]", max_length=200000), session_id: str = Form("default", max_length=100)):
    return await until_disconnect(request, vision_result(request, image, prompt, history, session_id))


@app.post("/api/agent/run")
async def run_agent_endpoint(payload: AgentPayload, request: Request):
    return await until_disconnect(request, execute_agent_pipeline(payload.prompt, payload.max_iterations,
                                  store=request.app.state.store, session_id=payload.session_id))


class Approval(BaseModel):
    session_id: str = Field(min_length=1, max_length=100)
    approve: bool


@app.post("/api/agent/proposals/{proposal_id}")
async def approve_proposal(proposal_id: str, payload: Approval, request: Request):
    # Serialize approval + application to prevent replay/parallel overwrites.
    async with request.app.state.write_lock:
        store = request.app.state.store
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

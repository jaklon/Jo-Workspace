import base64
import asyncio
import json
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
import httpx
import pynvml  # Sekarang sudah menggunakan wrapper resmi nvidia-ml-py
from agent import execute_agent_pipeline
from doc_engine import parse_document_file
from router import clean_reasoning_output, detect_pipeline_route, analyze_document_with_r1

app = FastAPI(title="Local Multi-Model Agent Engine")

WEB_DIST_DIR = Path(__file__).resolve().parent.parent / "desktop-app" / "out" / "renderer"

# CORS middleware agar Desktop Electron dan VS Code bisa akses bebas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OLLAMA_BASE_URL = "http://127.0.0.1:11434"

CHAT_SYSTEM_INSTRUCTION = (
    "Jawab pengguna secara langsung, ramah, dan ringkas dalam bahasa Indonesia. "
    "Untuk pertanyaan sederhana, jangan tampilkan proses berpikir atau langkah internal. "
    "Jika penalaran memang diperlukan, tulis hanya ringkasan singkat (maksimal 4 poin) "
    "di dalam tag <think>...</think>, lalu berikan jawaban akhir setelah tag tersebut. "
    "Jangan gunakan judul 'Thinking Process' dan jangan tampilkan draf, opsi jawaban, "
    "atau self-correction kepada pengguna."
)

VISION_EXTRACTION_SYSTEM_INSTRUCTION = (
    "Kamu adalah mesin ekstraksi visual. Analisis gambar secara objektif dalam bahasa Indonesia. "
    "Ekstrak teks yang terlihat (OCR), elemen UI, struktur/layout, tabel, diagram, label, "
    "angka, dan relasi penting. Jangan membuat asumsi di luar gambar. "
    "Jangan menjawab pertanyaan pengguna secara langsung; hasilmu akan diteruskan ke AI lain."
)

VISION_REASONING_SYSTEM_INSTRUCTION = (
    "Kamu adalah AI Lead Architect & Visual Analyst. Jawab pertanyaan pengguna berdasarkan "
    "bukti visual yang diekstrak dari gambar. Jelaskan secara akurat, terstruktur, dan dalam "
    "bahasa Indonesia. Jika bukti visual tidak cukup, nyatakan keterbatasannya; jangan mengarang. "
    "Berikan jawaban akhir langsung tanpa menampilkan proses berpikir, draf, atau tag <think>."
)

# Pemetaan target modul ke nama model yang terdaftar di Ollama
MODEL_MAPPING = {
    "reasoning": "qwen-9b-reasoning",
    "coding": "qwen-9b-reasoning",
    "security": "qwen3.8-heretic-q4",
    "vision": "minicpm-v:latest",
}


class ChatHistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatPayload(BaseModel):
    prompt: str
    target: Literal["reasoning", "coding", "security"] = "reasoning"
    history: list[ChatHistoryMessage] = []


def format_chat_history(history: list[ChatHistoryMessage]) -> str:
    """Membuat konteks ringkas dari sesi yang dikirim renderer."""
    if not history:
        return ""
    transcript = "\n".join(
        f"{'Pengguna' if message.role == 'user' else 'Asisten'}: {message.content}"
        for message in history[-12:]
        if message.content.strip()
    )
    return f"Konteks percakapan sebelumnya:\n{transcript}\n\n" if transcript else ""


def parse_form_history(history: str) -> list[ChatHistoryMessage]:
    try:
        return [ChatHistoryMessage(**message) for message in json.loads(history)]
    except (TypeError, ValueError, json.JSONDecodeError):
        return []


@app.get("/api/health")
async def health_check():
    """Mengecek apakah Ollama engine aktif di latar belakang."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            if resp.status_code == 200:
                models = [m.get("name") for m in resp.json().get("models", [])]
                return {"status": "connected", "loaded_models": models}
    except Exception:
        pass
    raise HTTPException(
        status_code=503,
        detail="Ollama engine tidak terdeteksi. Pastikan aplikasi Ollama berjalan di latar belakang."
    )

@app.get("/api/gpu-status")
async def get_gpu_status():
    try:
        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        used_mb = int(info.used / (1024 ** 2))
        total_mb = int(info.total / (1024 ** 2))
        pynvml.nvmlShutdown()
        return {
            "name": "NVIDIA RTX 3060",
            "vram_used_mb": used_mb,
            "vram_total_mb": total_mb,
            "usage_percent": int((used_mb / total_mb) * 100)
        }
    except Exception:
        return {
            "name": "NVIDIA RTX 3060",
            "vram_used_mb": 0,
            "vram_total_mb": 6144,
            "usage_percent": 0
        }    


@app.post("/api/chat")
async def chat_endpoint(payload: ChatPayload):
    selected_model = MODEL_MAPPING.get(payload.target, MODEL_MAPPING["reasoning"])
    prompt_with_context = f"{format_chat_history(payload.history)}Pertanyaan terbaru pengguna: {payload.prompt}"

    async def stream_generator():
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    "POST",
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={
                        "model": selected_model,
                        "system": CHAT_SYSTEM_INSTRUCTION,
                        "prompt": prompt_with_context,
                        "stream": True,
                        "options": {
                            "num_ctx": 4096,
                            "temperature": 0.6 if payload.target == "reasoning" else 0.2
                        }
                    }
                ) as response:
                    if response.status_code != 200:
                        yield {"data": json.dumps({"token": f"Error: HTTP {response.status_code}"})}
                        return

                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            # Kirim dalam format JSON terstruktur
                            yield {"data": json.dumps({"token": token})}
                        if chunk.get("done", False):
                            break
        except Exception as err:
            yield {"data": json.dumps({"token": f"\n[Error: {str(err)}]"})}

    return EventSourceResponse(stream_generator())


@app.post("/api/vision/analyze")
async def vision_endpoint(
    image: UploadFile = File(...),
    prompt: str = Form("Jelaskan diagram/screenshot ini secara detail."),
    history: str = Form("[]"),
):
    image_bytes = await image.read()
    b64_image = base64.b64encode(image_bytes).decode("utf-8")
    vision_model = MODEL_MAPPING["vision"]

    print(f"\n[DEBUG VISION] Target model: {vision_model}")
    print(f"[DEBUG VISION] Ukuran byte gambar: {len(image_bytes)}")

    prompt_with_context = f"{format_chat_history(parse_form_history(history))}Pertanyaan terbaru pengguna: {prompt}"

    try:
        async with httpx.AsyncClient(timeout=None) as client:
            vision_response = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": vision_model,
                    "system": VISION_EXTRACTION_SYSTEM_INSTRUCTION,
                    "prompt": f"Gambar untuk dianalisis. Fokus ekstraksi visual untuk kebutuhan user: {prompt}",
                    "images": [b64_image],
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "num_ctx": 4096,
                    },
                },
            )

            if vision_response.status_code != 200:
                print(f"[OLLAMA VISION ERROR STATUS]: {vision_response.status_code}")
                print(f"[OLLAMA VISION ERROR BODY]: {vision_response.text}")
                raise HTTPException(
                    status_code=vision_response.status_code,
                    detail=f"Ollama Vision Error: {vision_response.text}",
                )

            visual_context = vision_response.json().get("response", "").strip()
            if not visual_context:
                raise HTTPException(
                    status_code=502,
                    detail="Model vision tidak menghasilkan konteks visual.",
                )

            reasoning_response = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": MODEL_MAPPING["reasoning"],
                    "system": VISION_REASONING_SYSTEM_INSTRUCTION,
                    "prompt": (
                        f"{prompt_with_context}\n\n"
                        f"BUKTI VISUAL DARI MODEL VISION:\n\"\"\"\n"
                        f"{visual_context}\n\"\"\""
                    ),
                    "stream": False,
                    "options": {"temperature": 0.3, "num_ctx": 4096},
                },
            )
            if reasoning_response.status_code != 200:
                print(f"[OLLAMA REASONING ERROR STATUS]: {reasoning_response.status_code}")
                print(f"[OLLAMA REASONING ERROR BODY]: {reasoning_response.text}")
                raise HTTPException(
                    status_code=reasoning_response.status_code,
                    detail=f"Ollama Reasoning Error: {reasoning_response.text}",
                )

            final_answer = clean_reasoning_output(
                reasoning_response.json().get("response", "")
            )
            return {
                "result": final_answer,
                # Ditampilkan sebagai detail opsional di UI agar pengguna dapat
                # memverifikasi bukti OCR/visual yang dipakai Qwen untuk menjawab.
                "visual_analysis": visual_context,
            }
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail="Tidak dapat tersambung ke Ollama. Pastikan Ollama aktif.",
        )

class AgentPayload(BaseModel):
    prompt: str
    max_iterations: int = 5


@app.post("/api/agent/run")
async def run_agent_endpoint(payload: AgentPayload):
    try:
        # Menjalankan loop tool-calling dari agent.py
        result = execute_agent_pipeline(
            payload.prompt, max_iterations=payload.max_iterations
        )
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.post("/api/document/parse")
async def parse_document_endpoint(
    file: UploadFile = File(...), prompt: str = Form(...)
):
    try:
        content_bytes = await file.read()
        file_text = content_bytes.decode("utf-8", errors="ignore")

        # Buat prompt yang menggabungkan isi file dengan instruksi user
        combined_prompt = (
            f"Konten file '{file.filename}':\n```\n{file_text}\n```\n\n"
            f"Instruksi pengguna: {prompt}"
        )

        # Jalankan ke agent pipeline untuk dianalisis/dimodifikasi
        result = execute_agent_pipeline(combined_prompt)
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 


@app.post("/api/document/analyze-stream")
async def analyze_document_stream_endpoint(
    file: UploadFile = File(...),
    prompt: str = Form(...),
    history: str = Form("[]"),
):
    """Stream tahapan kerja dokumen dan hasil akhirnya ke renderer."""
    filename = file.filename or "dokumen"
    file_bytes = await file.read()
    prompt_with_context = (
        f"{format_chat_history(parse_form_history(history))}"
        f"Permintaan terbaru pengguna: {prompt}"
    )

    async def stream_generator():
        try:
            yield {
                "data": json.dumps(
                    {
                        "type": "status",
                        "step": "received",
                        "label": "Dokumen diterima",
                        "detail": f"{filename} siap diproses.",
                    }
                )
            }
            yield {
                "data": json.dumps(
                    {
                        "type": "status",
                        "step": "extracting",
                        "label": "Mengekstrak isi dokumen",
                        "detail": "Membaca teks dan struktur yang dapat dikenali.",
                    }
                )
            }
            extracted_text = await asyncio.to_thread(
                parse_document_file, filename, file_bytes
            )
            yield {
                "data": json.dumps(
                    {
                        "type": "status",
                        "step": "analyzing",
                        "label": "AI sedang menganalisis",
                        "detail": f"{len(extracted_text):,} karakter berhasil dibaca.",
                    }
                )
            }
            analysis_result = await asyncio.to_thread(
                analyze_document_with_r1,
                extracted_text,
                prompt_with_context
                or "Berikan ringkasan dan analisis lengkap dokumen ini.",
            )
            yield {
                "data": json.dumps(
                    {
                        "type": "status",
                        "step": "finalizing",
                        "label": "Menyusun jawaban",
                        "detail": "Merapikan hasil analisis untuk ditampilkan.",
                    }
                )
            }
            yield {
                "data": json.dumps(
                    {
                        "type": "result",
                        "result": analysis_result,
                        "filename": filename,
                    }
                )
            }
        except Exception as err:
            print(f"[DOCUMENT STREAM ERROR]: {str(err)}")
            yield {
                "data": json.dumps(
                    {
                        "type": "error",
                        "detail": str(err),
                    }
                )
            }

    return EventSourceResponse(stream_generator())


@app.post("/api/agent/dispatch")
async def dispatch_task_endpoint(
    prompt: str = Form(...),
    file: UploadFile | None = File(None),
    history: str = Form("[]"),
):
    prompt_with_context = f"{format_chat_history(parse_form_history(history))}Permintaan terbaru pengguna: {prompt}"
    filename = file.filename if file else None
    route = detect_pipeline_route(filename, prompt)
    print(f"[ROUTER] Terdeteksi rute: {route} untuk file: {filename}")

    try:
        if route == "DOCUMENT_PIPELINE" and file:
            file_bytes = await file.read()
            extracted_text = parse_document_file(filename, file_bytes)
            analysis_result = analyze_document_with_r1(
                document_text=extracted_text,
                user_prompt=prompt_with_context or "Berikan ringkasan dan analisis lengkap dokumen ini.",
            )
            return {
                "route": route,
                "status": "success",
                "filename": filename,
                "result": analysis_result,
            }

        if route == "CODING_PIPELINE":
            result = execute_agent_pipeline(prompt_with_context)
            return {"route": route, "status": "success", "result": result}

        if route == "CYBERSECURITY_PIPELINE":
            async with httpx.AsyncClient(timeout=None) as client:
                resp = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={
                        "model": MODEL_MAPPING["security"],
                        "prompt": prompt_with_context,
                        "stream": False,
                        "options": {"temperature": 0.2, "num_ctx": 4096},
                    },
                )
                if resp.status_code != 200:
                    raise HTTPException(
                        status_code=resp.status_code,
                        detail=f"Ollama Error: {resp.text}",
                    )
                return {
                    "route": route,
                    "status": "success",
                    "result": resp.json().get("response", "").strip(),
                }

        analysis_result = analyze_document_with_r1(
            document_text="",
            user_prompt=prompt_with_context,
        )
        return {"route": route, "status": "success", "result": analysis_result}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[DISPATCH ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Mount this last so every /api route keeps priority. The directory is created
# by `npm run build` in desktop-app.
if WEB_DIST_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIST_DIR, html=True), name="web")

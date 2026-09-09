import base64
import json
from typing import Literal
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
import httpx
import pynvml  # Sekarang sudah menggunakan wrapper resmi nvidia-ml-py
from agent import execute_agent_pipeline
from doc_engine import parse_document_file
from router import detect_pipeline_route, analyze_document_with_r1

app = FastAPI(title="Local Multi-Model Agent Engine")

# CORS middleware agar Desktop Electron dan VS Code bisa akses bebas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OLLAMA_BASE_URL = "http://127.0.0.1:11434"

# Pemetaan target modul ke nama model yang terdaftar di Ollama
MODEL_MAPPING = {
    "reasoning": "deepseek-r1:7b",
    "coding": "qwen2.5-coder:7b",
    "vision": "minicpm-v:latest" 
}


class ChatPayload(BaseModel):
    prompt: str
    target: Literal["reasoning", "coding"] = "reasoning"


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
    selected_model = MODEL_MAPPING.get(payload.target, "deepseek-r1:7b")

    async def stream_generator():
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    "POST",
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={
                        "model": selected_model,
                        "prompt": payload.prompt,
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
):
    image_bytes = await image.read()
    b64_image = base64.b64encode(image_bytes).decode("utf-8")
    vision_model = MODEL_MAPPING.get("vision", "llava:7b")

    print(f"\n[DEBUG VISION] Target model: {vision_model}")
    print(f"[DEBUG VISION] Ukuran byte gambar: {len(image_bytes)}")

    system_instruction = (
        "Kamu adalah asisten visual AI teknis. Deskripsikan elemen visual antarmuka, "
        "teks, diagram, atau komponen yang terlihat pada gambar ini secara objektif dan jelas "
        "dalam bahasa Indonesia."
    )

    try:
        async with httpx.AsyncClient(timeout=None) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": vision_model,
                    "system": system_instruction,
                    "prompt": prompt,
                    "images": [b64_image],
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                    },
                },
            )

            # Cetak respons asli dari Ollama jika gagal
            if resp.status_code != 200:
                print(f"[OLLAMA ERROR STATUS]: {resp.status_code}")
                print(f"[OLLAMA ERROR BODY]: {resp.text}")
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=f"Ollama Error: {resp.text}",
                )

            result_data = resp.json()
            return {"result": result_data.get("response", "")}
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


@app.post("/api/agent/dispatch")
async def dispatch_task_endpoint(
    prompt: str = Form(...),
    file: UploadFile | None = File(None),
):
    filename = file.filename if file else None
    route = detect_pipeline_route(filename, prompt)
    print(f"[ROUTER] Terdeteksi rute: {route} untuk file: {filename}")

    try:
        if route == "DOCUMENT_PIPELINE" and file:
            file_bytes = await file.read()
            extracted_text = parse_document_file(filename, file_bytes)
            analysis_result = analyze_document_with_r1(
                document_text=extracted_text,
                user_prompt=prompt or "Berikan ringkasan dan analisis lengkap dokumen ini.",
            )
            return {
                "route": route,
                "status": "success",
                "filename": filename,
                "result": analysis_result,
            }

        if route == "CODING_PIPELINE":
            result = execute_agent_pipeline(prompt)
            return {"route": route, "status": "success", "result": result}

        analysis_result = analyze_document_with_r1(
            document_text="",
            user_prompt=prompt,
        )
        return {"route": route, "status": "success", "result": analysis_result}
    except Exception as e:
        print(f"[DISPATCH ERROR]: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
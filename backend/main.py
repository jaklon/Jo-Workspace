import base64
import json
from typing import Literal
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
import httpx
import pynvml

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
    "vision": "llava:7b"  # atau qwen2-vl / model vision lain yang terdaftar di ollama
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
    prompt: str = Form("Jelaskan diagram/screenshot ini secara detail.")
):
    """Endpoint analisis gambar/diagram multimodal via Ollama vision model."""
    image_bytes = await image.read()
    b64_image = base64.b64encode(image_bytes).decode("utf-8")
    vision_model = MODEL_MAPPING.get("vision", "llava:7b")

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": vision_model,
                    "prompt": prompt,
                    "images": [b64_image],
                    "stream": False
                }
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=500, detail="Gagal memproses gambar melalui engine vision.")

            result_data = resp.json()
            return {"result": result_data.get("response", "")}
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Tidak dapat tersambung ke Ollama. Pastikan Ollama aktif.")
    
    
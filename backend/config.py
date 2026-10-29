"""Configuration shared by API, models and tools. No machine-specific paths."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_DIST_DIR = Path(os.getenv("AGENT_WEB_DIR", str(ROOT / "desktop-app" / "out" / "renderer"))).resolve()
DATA_DIR = Path(os.getenv("AGENT_DATA_DIR", str(ROOT / "data" / "runtime"))).resolve()
WORKSPACE_DIR = Path(os.getenv("AGENT_WORKSPACE", str(ROOT / "workspace"))).resolve()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
MODELS = {
    "reasoning": os.getenv("REASONING_MODEL", "qwen-9b-reasoning"),
    "coding": os.getenv("CODING_MODEL", "qwen-9b-reasoning"),
    "security": os.getenv("SECURITY_MODEL", "qwen3.8-heretic-q4"),
    "vision": os.getenv("VISION_MODEL", "minicpm-v:latest"),
}
CONTEXT_TOKENS = int(os.getenv("CONTEXT_TOKENS", "4096"))
OUTPUT_TOKENS = min(int(os.getenv("OUTPUT_TOKENS", "768")), CONTEXT_TOKENS // 3)
MODEL_TIMEOUT = float(os.getenv("MODEL_TIMEOUT", "120"))
QUEUE_TIMEOUT = float(os.getenv("QUEUE_TIMEOUT", "30"))
MAX_UPLOAD = 8 * 1024 * 1024
MAX_BODY = MAX_UPLOAD + 256 * 1024
MAX_EXTRACTED = 200_000
MAX_FILE_TEXT = 64_000
MAX_PENDING = 8
DOCUMENT_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".txt", ".csv", ".json", ".md", ".py", ".ts", ".js"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
ALLOWED_ORIGINS = [x.strip() for x in os.getenv("AGENT_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,null").split(",") if x.strip()]
if "*" in ALLOWED_ORIGINS:
    raise ValueError("AGENT_ALLOWED_ORIGINS tidak boleh memakai wildcard '*'.")

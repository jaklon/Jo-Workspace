import json
import subprocess
import os
from typing import Any, Callable, Dict

WORKSPACE_ROOT = os.path.abspath("./workspace")


def safe_path(rel_path: str) -> str:
    dest = os.path.abspath(os.path.join(WORKSPACE_ROOT, rel_path))
    if not dest.startswith(WORKSPACE_ROOT):
        raise PermissionError("Akses path di luar workspace ditolak.")
    return dest


def read_file(path: str) -> str:
    full_path = safe_path(path)
    if not os.path.exists(full_path):
        return f"Error: File '{path}' tidak ditemukan."
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path: str, content: str) -> str:
    full_path = safe_path(path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Sukses menulis file: {path}"

def list_dir(path: str = ".") -> str:
    """Melihat daftar file dan folder di path tertentu."""
    full_path = safe_path(path)
    if not os.path.exists(full_path):
        return f"Error: Path '{path}' tidak ditemukan."
    try:
        entries = os.listdir(full_path)
        return "\n".join(entries) if entries else "(Direktori kosong)"
    except Exception as e:
        return f"Error listing directory: {str(e)}"


def run_command(command: str) -> str:
    """Menjalankan terminal command secara aman di dalam workspace."""
    # Whitelist command sederhana untuk keamanan
    allowed_prefixes = ["npm test", "pytest", "python -m unittest", "git status"]
    if not any(command.strip().startswith(prefix) for prefix in allowed_prefixes):
        return f"Error: Command '{command}' tidak diizinkan. Hanya test/linting commands yang diperbolehkan."

    try:
        result = subprocess.run(
            command,
            cwd=WORKSPACE_ROOT,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout if result.stdout else result.stderr
        return output.strip() if output else "Command berhasil dijalankan tanpa output."
    except subprocess.TimeoutExpired:
        return "Error: Eksekusi command melebihi batas waktu (30 detik)."
    except Exception as e:
        return f"Error: {str(e)}"


# Skema OpenAPI untuk Model
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Membaca konten file dari workspace relatif.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path relatif file dari root workspace",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Menulis atau menimpa isi file di workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relatif file"},
                    "content": {
                        "type": "string",
                        "description": "Konten teks lengkap yang akan ditulis",
                    },
                },
                "required": ["path", "content"],
            },
        },
    },
]

TOOL_RUNNERS: Dict[str, Callable[..., Any]] = {
    "read_file": read_file,
    "write_file": write_file,
}
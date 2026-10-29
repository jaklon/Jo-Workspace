"""Model tools cannot mutate files; writes require human-reviewed proposals."""
import difflib
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from config import WORKSPACE_DIR, MAX_FILE_TEXT

WORKSPACE_ROOT = str(WORKSPACE_DIR)
FORBIDDEN = {".git", ".env", ".ssh", "node_modules", "venv", ".venv", "__pycache__", ".agent-backups"}


def safe_path(rel_path):
    if not isinstance(rel_path, str) or not rel_path or "\x00" in rel_path:
        raise PermissionError("Path tidak valid.")
    relative = Path(rel_path)
    if any(part not in {".", ".."} and part.rstrip(" .") != part for part in relative.parts):
        raise PermissionError("Path dengan titik/spasi di akhir tidak diizinkan.")
    if relative.is_absolute() or relative.drive or ":" in rel_path or any(p.lower() in FORBIDDEN or p.lower().startswith(".env.") for p in relative.parts):
        raise PermissionError("Gunakan path relatif non-rahasia di workspace.")
    root = Path(WORKSPACE_ROOT).resolve()
    destination = (root / relative).resolve()
    if not destination.is_relative_to(root):
        raise PermissionError("Akses di luar workspace ditolak.")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise PermissionError("Symlink tidak diizinkan.")
        if os.name == "nt" and current.exists():
            import stat
            if getattr(current.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise PermissionError("Windows reparse point tidak diizinkan.")
    return str(destination)


def read_file(path):
    target = Path(safe_path(path))
    if target.stat().st_size > MAX_FILE_TEXT:
        raise ValueError("File terlalu besar; pilih file lebih kecil.")
    return {"ok": True, "path": path, "content": target.read_text(encoding="utf-8")}


def list_dir(path="."):
    entries = sorted(p.name for p in Path(safe_path(path)).iterdir() if p.name.lower() not in FORBIDDEN and not p.name.lower().startswith(".env."))
    return {"ok": True, "entries": entries[:200], "truncated": len(entries) > 200}


def proposal_payload(path, content):
    if len(content.encode("utf-8")) > MAX_FILE_TEXT:
        raise ValueError("Usulan file terlalu besar.")
    target = Path(safe_path(path))
    if target.exists() and target.stat().st_size > MAX_FILE_TEXT:
        raise ValueError("File tujuan terlalu besar.")
    old = target.read_bytes() if target.exists() else None
    old_text = old.decode("utf-8") if old is not None else ""
    diff = "".join(difflib.unified_diff(old_text.splitlines(True), content.splitlines(True), fromfile=path+" (sebelum)", tofile=path+" (usulan)"))
    if not diff:
        raise ValueError("Tidak ada perubahan untuk diusulkan.")
    return {"path": path, "content": content, "before_hash": hashlib.sha256(old).hexdigest() if old is not None else None, "diff": diff}


def apply_proposal(payload):
    target = Path(safe_path(payload["path"]))
    old = target.read_bytes() if target.exists() else None
    fingerprint = hashlib.sha256(old).hexdigest() if old is not None else None
    if fingerprint != payload["before_hash"]:
        raise ValueError("File berubah sejak proposal dibuat. Buat proposal baru agar perubahan terbaru tidak tertimpa.")
    target.parent.mkdir(parents=True, exist_ok=True)
    safe_path(payload["path"])
    if old is not None:
        backup_root = Path(WORKSPACE_ROOT) / ".agent-backups"
        backup_root.mkdir(exist_ok=True)
        if backup_root.is_symlink() or backup_root.resolve() != backup_root.absolute():
            raise PermissionError("Direktori backup tidak aman.")
        backup = backup_root / (hashlib.sha256(payload["path"].encode()).hexdigest()+"-"+fingerprint+".bak")
        if not backup.exists():
            backup.write_bytes(old)
    descriptor, temporary = tempfile.mkstemp(prefix=".agent-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(payload["content"])
        safe_path(payload["path"])
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"ok": True, "path": payload["path"]}


def write_file(path, content):
    raise PermissionError("Penulisan langsung dinonaktifkan. Gunakan proposal dan persetujuan pengguna.")


def run_command(command):
    # Test runners execute workspace code; never expose shell strings to models.
    if command != "git status":
        raise PermissionError("Perintah tidak diizinkan.")
    result = subprocess.run(["git", "--no-optional-locks", "status", "--short"], cwd=WORKSPACE_ROOT, shell=False, capture_output=True, text=True, timeout=10)
    return {"ok": result.returncode == 0, "exit_code": result.returncode, "stdout": result.stdout[:8000], "stderr": result.stderr[:2000]}


def definition(name, description, properties, required):
    return {"type": "function", "function": {"name": name, "description": description, "parameters": {"type": "object", "properties": properties, "required": required, "additionalProperties": False}}}


TOOL_DEFINITIONS = [
    definition("read_file", "Baca file relatif di workspace.", {"path": {"type": "string"}}, ["path"]),
    definition("list_dir", "Daftar file di workspace.", {"path": {"type": "string"}}, ["path"]),
    definition("propose_write", "Usulkan perubahan untuk persetujuan pengguna; belum menulis.", {"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"]),
]
TOOL_RUNNERS = {"read_file": read_file, "list_dir": list_dir}

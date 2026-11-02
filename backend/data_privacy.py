"""Plain answers to "where is my data, how long is it kept, what leaves this laptop".

The overview only reads sizes and row counts; it never returns file contents. The outbound
disclosures describe what an approved web or recon action will send and to whom, so the
approval card can show it before anything is sent."""
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit

MAX_WALK = 50_000
RETENTION = [
    {"item": "Lampiran chat (teks hasil ekstraksi)", "rule": "Dihapus otomatis setelah 30 hari; maksimal 500 lampiran / 50 MB."},
    {"item": "Rencana aksi chat dan proposal kode", "rule": "Kedaluwarsa setelah 24 jam bila tidak diputuskan."},
    {"item": "Statistik penggunaan model", "rule": "Disimpan 90 hari, dapat dihapus kapan saja dari Pengaturan."},
    {"item": "Log audit lokal", "rule": "2.000 entri terakhir."},
    {"item": "Chat, project, dan memori project", "rule": "Disimpan di browser/aplikasi sampai Anda menghapusnya."},
    {"item": "Evidence dan laporan security", "rule": "Disimpan sampai engagement dihapus; snapshot laporan tidak dapat diubah."},
]
EXPORTS = [
    {"name": "Ekspor data (Pengaturan → Kontrol data)",
     "includes": ["Chat dan riwayat pesan", "Project, instruksi, dan memori project", "Preferensi tampilan dan respons"],
     "excludes": ["Isi lampiran di server", "Token API", "Evidence security", "Pengaturan model"]},
    {"name": "Cadangan terjadwal / arsip pemulihan",
     "includes": ["Database lokal (lampiran, audit, aksi)", "Engagement, evidence, dan laporan security",
                  "Pengaturan model", "Snapshot data browser"],
     "excludes": ["Token API (dibuat ulang)", "Model Ollama", "File workspace di luar arsip yang dipilih"]},
]


def folder_usage(path):
    """Total bytes and file count under path, bounded so a huge folder cannot stall the API."""
    total, files, truncated = 0, 0, False
    if not path.exists():
        return {"bytes": 0, "files": 0, "truncated": False, "exists": False}
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "venv", ".venv", "__pycache__")]
        for name in names:
            files += 1
            if files > MAX_WALK:
                truncated = True
                break
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                pass
        if truncated:
            break
    return {"bytes": total, "files": min(files, MAX_WALK), "truncated": truncated, "exists": True}


def attachment_stats(db_path):
    try:
        with closing(sqlite3.connect(db_path, timeout=5)) as db:
            count, size, oldest = db.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(content)),0), MIN(created) FROM attachments").fetchone()
    except sqlite3.Error:
        return {"count": 0, "bytes": 0, "oldest_expires_in_days": None}
    expires = None if oldest is None else max(0, round((oldest + 30 * 86400 - time.time()) / 86400, 1))
    return {"count": count, "bytes": size, "oldest_expires_in_days": expires}


def storage_overview(data_dir, workspace_dir):
    data_dir, workspace_dir = Path(data_dir), Path(workspace_dir)
    entries = [{"name": "Data runtime (database, pengaturan, usage)", "path": str(data_dir), **folder_usage(data_dir)},
               {"name": "Workspace coding agent", "path": str(workspace_dir), **folder_usage(workspace_dir)}]
    return {"locations": entries, "attachments": attachment_stats(data_dir / "agent.sqlite3"),
            "retention": RETENTION, "exports": EXPORTS,
            "browser_storage": "Chat, project, dan preferensi juga tersimpan di penyimpanan lokal aplikasi/browser perangkat ini."}


def outbound_web(prompt, searx_url):
    """What an approved web search sends out. The search terms are derived from this message."""
    excerpt = prompt.strip().replace("\n", " ")
    return {
        "leaves_device": True,
        "sent": [f"Kata kunci pencarian (maks. 200 karakter) yang disusun dari pesan ini: \"{excerpt[:160]}{'…' if len(excerpt) > 160 else ''}\"",
                 "Permintaan HTTPS biasa ke hingga 3 halaman hasil dan 8 gambar; situs tersebut melihat alamat IP Anda."],
        "destinations": [f"SearXNG lokal ({searx_url}), yang meneruskan kata kunci ke mesin pencari yang dikonfigurasi",
                         "Situs publik pada hasil pencarian"],
        "not_sent": ["Riwayat chat", "Lampiran", "Instruksi dan memori project", "File workspace"],
    }


PASSIVE = {"subfinder-passive", "amass-passive"}
LOCAL_ONLY = {"document-review", "monitoring-local"}


def outbound_security(plans):
    """Which hosts each approved recon job contacts and what it sends them."""
    sent, destinations = [], []
    for item in plans:
        tool = item.get("tool", "")
        target = (item.get("target") or {}).get("value", "")
        host = urlsplit(target).hostname or target
        ports = ",".join(map(str, item.get("ports") or []))
        if tool in LOCAL_ONLY:
            sent.append(f"{tool}: diproses lokal, tidak ada data keluar.")
        elif tool in PASSIVE:
            sent.append(f"{tool}: nama domain {host} dikirim ke crt.sh (sumber publik Certificate Transparency).")
            destinations.append("crt.sh")
        else:
            sent.append(f"{tool}: koneksi langsung ke {host}" + (f" port {ports}" if ports else "") +
                        "; target melihat alamat IP Anda dan request yang dikirim.")
            destinations.append(host)
    return {"leaves_device": any(item.get("tool") not in LOCAL_ONLY for item in plans), "sent": sent,
            "destinations": list(dict.fromkeys(destinations)),
            "not_sent": ["Riwayat chat", "Lampiran (kecuali dokumen yang dipilih untuk review lokal)", "File workspace"]}

"""Explain the local model runtime: what is loaded, memory fit, queue, why it is slow, how to recover.

Everything here is read-only. Ollama is asked for its version, installed models (/api/tags)
and loaded models (/api/ps); nothing is pulled, loaded or unloaded on the user's behalf."""
import time

import httpx

import config

MB = 1024 ** 2
# Rough KV-cache cost per 1k context tokens for a 7-9B model with q8 cache; used only for estimates.
KV_MB_PER_1K = 70
OVERHEAD_MB = 500


async def ollama_snapshot(url):
    """Version, installed and loaded models, or the reason Ollama cannot be reached."""
    try:
        async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
            version = (await client.get(url + "/api/version")).json().get("version")
            tags = (await client.get(url + "/api/tags")).json().get("models", [])
            loaded = (await client.get(url + "/api/ps")).json().get("models", [])
        return {"reachable": True, "version": version, "installed": tags, "loaded": loaded, "error": None}
    except httpx.ConnectError:
        error = "Ollama tidak berjalan atau tidak mendengarkan di " + url + "."
    except httpx.TimeoutException:
        error = "Ollama tidak merespons dalam 3 detik; layanan mungkin sedang memuat model atau macet."
    except (httpx.HTTPError, ValueError) as exc:
        error = f"Respons Ollama tidak valid: {type(exc).__name__}."
    return {"reachable": False, "version": None, "installed": [], "loaded": [], "error": error}


def _find(models, name):
    return next((m for m in models if m.get("name") in (name, name + ":latest") or m.get("model") in (name, name + ":latest")), None)


def memory_estimate(size_bytes, context_tokens, vram_total_mb):
    """Estimated memory need and whether it fits fully on the GPU."""
    need = round(size_bytes / MB + context_tokens / 1000 * KV_MB_PER_1K + OVERHEAD_MB)
    if not vram_total_mb:
        fit = "cpu"
    elif need <= vram_total_mb * 0.9:
        fit = "gpu"
    else:
        fit = "partial"
    return {"estimated_mb": need, "fit": fit}


def model_rows(snapshot, models, gpu):
    rows = []
    for role, name in models.items():
        installed, loaded = _find(snapshot["installed"], name), _find(snapshot["loaded"], name)
        row = {"role": role, "name": name, "installed": bool(installed), "loaded": bool(loaded)}
        if installed:
            row.update(size_mb=round(installed.get("size", 0) / MB),
                       **memory_estimate(installed.get("size", 0), config.CONTEXT_TOKENS, gpu.get("vram_total_mb")))
        if loaded:
            size, vram = loaded.get("size") or 0, loaded.get("size_vram") or 0
            row.update(gpu_percent=round(vram / size * 100) if size else 0, expires_at=loaded.get("expires_at"),
                       context=loaded.get("context_length"))
        rows.append(row)
    return rows


def diagnose(snapshot, rows, runtime, gpu, settings):
    """Plain reasons for slowness or failure, each with a concrete next step."""
    issues = []
    if not snapshot["reachable"]:
        issues.append({"level": "error", "reason": snapshot["error"],
                       "action": "Buka aplikasi Ollama atau jalankan `ollama serve`, lalu tekan Periksa ulang."})
        return issues
    for row in rows:
        if not row["installed"]:
            issues.append({"level": "error", "reason": f"Model {row['role']} ({row['name']}) belum terpasang.",
                           "action": f"Jalankan `ollama pull {row['name']}` atau pilih model lain untuk peran ini."})
    for row in rows:
        if row.get("loaded") and row.get("gpu_percent", 100) < 100:
            issues.append({"level": "warn",
                           "reason": f"{row['name']} hanya {row['gpu_percent']}% di GPU; sisanya berjalan di CPU sehingga lebih lambat.",
                           "action": "Kurangi panjang konteks atau gunakan model/kuantisasi lebih kecil agar muat di VRAM."})
    last = runtime.last_metrics or {}
    if last.get("tokens_per_second") is not None and last["tokens_per_second"] < 6:
        issues.append({"level": "warn", "reason": f"Kecepatan terakhir {last['tokens_per_second']} token/detik.",
                       "action": "Respons panjang akan memakan beberapa menit; tutup aplikasi berat lain yang memakai GPU."})
    if last.get("load_seconds", 0) >= 10:
        issues.append({"level": "info", "reason": f"Memuat model memakan {last['load_seconds']} detik (cold start).",
                       "action": "Model tetap di memori beberapa menit setelah dipakai; permintaan berikutnya lebih cepat."})
    if last.get("done_reason") == "length":
        issues.append({"level": "warn", "reason": "Jawaban terakhir terpotong karena batas token output.",
                       "action": "Naikkan Token output atau persempit pertanyaan."})
    if settings.thinking_tokens >= 1536:
        issues.append({"level": "info",
                       "reason": f"Anggaran penalaran {settings.thinking_tokens} token; pertanyaan kompleks bisa memakan waktu lama.",
                       "action": "Turunkan Token penalaran ke 1024 bila jawaban terasa lambat."})
    if runtime.waiting:
        issues.append({"level": "info", "reason": f"{runtime.waiting} permintaan menunggu giliran; model memproses satu per satu.",
                       "action": "Tunggu antrean selesai atau batalkan permintaan yang tidak diperlukan."})
    failure = runtime.last_failure
    if failure and time.time() - failure["at"] < 3600:
        reason = ("Permintaan terakhir melewati batas waktu." if "Timeout" in failure["type"]
                  else f"Permintaan terakhir gagal: {failure['detail'] or failure['type']}")
        issues.append({"level": "warn", "reason": reason,
                       "action": "Naikkan Batas waktu model atau kurangi Token penalaran/konteks, lalu coba lagi."})
    return issues


def recommendations(gpu, rows, settings):
    """Configuration that suits the detected hardware; never applied automatically."""
    vram = gpu.get("vram_total_mb") or 0
    if not gpu.get("available"):
        profile = {"label": "Tanpa GPU", "context_tokens": 4096, "thinking_tokens": 512, "model_timeout": 600,
                   "note": "Gunakan model 3B (misalnya qwen2.5:3b-instruct) untuk chat; model 7-9B di CPU sangat lambat."}
    elif vram <= 6144:
        profile = {"label": f"GPU {round(vram / 1024)} GB", "context_tokens": 4096, "thinking_tokens": 1024, "model_timeout": 600,
                   "note": "Model 9B Q4 tidak sepenuhnya muat; pertahankan konteks 4096 agar lapisan di CPU tetap sedikit."}
    elif vram <= 12288:
        profile = {"label": f"GPU {round(vram / 1024)} GB", "context_tokens": 8192, "thinking_tokens": 1536, "model_timeout": 300,
                   "note": "Model 7-9B Q4 muat penuh di GPU dengan konteks 8192."}
    else:
        profile = {"label": f"GPU {round(vram / 1024)} GB", "context_tokens": 16384, "thinking_tokens": 2048, "model_timeout": 300,
                   "note": "Ruang VRAM cukup untuk konteks panjang atau model lebih besar."}
    current = {"context_tokens": settings.context_tokens, "thinking_tokens": settings.thinking_tokens,
               "model_timeout": settings.model_timeout}
    profile["differs"] = [key for key in current if current[key] != profile[key]]
    profile["current"] = current
    return profile


async def runtime_status(runtime, gpu, models, settings):
    snapshot = await ollama_snapshot(config.OLLAMA_URL)
    rows = model_rows(snapshot, models, gpu)
    current = runtime.current
    return {
        "ollama": {"reachable": snapshot["reachable"], "version": snapshot["version"], "url": config.OLLAMA_URL,
                   "error": snapshot["error"]},
        "gpu": gpu,
        "models": rows,
        "queue": {"active": runtime.active, "waiting": runtime.waiting, "max_pending": config.MAX_PENDING,
                  "current": {**current, "elapsed_seconds": round(time.time() - current["started"])} if current else None,
                  "completed": runtime.completed, "failed": runtime.failed},
        "last": runtime.last_metrics or None,
        "issues": diagnose(snapshot, rows, runtime, gpu, settings),
        "recommendation": recommendations(gpu, rows, settings),
    }

"""Live Chat-First check against the local Ollama and real loopback adapters.

* Uses a temporary data directory (runtime databases are not touched); the real
  data/runtime/settings.json is copied in read-only so the configured role models are used.
* The only network target is 127.0.0.1 in the "lab" environment (Ollama port 11434 and one
  closed port). No external host is scanned.
* Writes a JSON summary to output/verify/live_chat_first.json and exits 1 if a hard check fails.

Usage (from the project root):
  backend\\venv\\Scripts\\python.exe scripts\\live_chat_first_check.py [--security-model whiterabbitneo-v3-7b]
"""
import argparse
import json
import re
import os
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
temp = Path(tempfile.mkdtemp(prefix="jo-live-check-"))
real_settings = ROOT / "data" / "runtime" / "settings.json"
if real_settings.is_file():
    shutil.copyfile(real_settings, temp / "settings.json")
os.environ["AGENT_DATA_DIR"] = str(temp)
os.environ["AGENT_WORKSPACE"] = str(temp / "workspace")
os.environ["AGENT_API_TOKEN"] = "live-check-token-" + uuid.uuid4().hex

import asyncio  # noqa: E402
import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from config import MODELS, OLLAMA_URL  # noqa: E402
from main import app  # noqa: E402
from chat_orchestrator import classify, security_slots  # noqa: E402
from auto_governance import prepare_plan  # noqa: E402

HEADERS = {"Authorization": "Bearer " + os.environ["AGENT_API_TOKEN"]}
SUMMARY = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "checks": [], "models": {}}
SAMPLE_CODE = '''import sqlite3
from flask import Flask, request

app = Flask(__name__)
API_KEY = "sk-test-0000000000000000"

@app.route("/user")
def user():
    uid = request.args.get("id")
    db = sqlite3.connect("app.db")
    return str(db.execute("SELECT * FROM users WHERE id = " + uid).fetchall())
'''


def record(check, ok, hard=True, **detail):
    SUMMARY["checks"].append({"name": check, "ok": bool(ok), "hard": hard, **detail})
    print(("PASS" if ok else ("FAIL" if hard else "WARN")) + f" · {check} · " + json.dumps(detail, ensure_ascii=False)[:900], flush=True)


def events(response):
    return [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:")]


def installed():
    response = httpx.get(OLLAMA_URL + "/api/tags", timeout=5)
    response.raise_for_status()
    return [item["name"] for item in response.json().get("models", [])]


def resolve(name, names):
    return next((n for n in names if n == name or n == name + ":latest"), None)


def router_checks(reasoning):
    cases = [
        ("Halo, apa kabar hari ini?", {"chat"}, None),
        ("Perbaiki bug validasi token di file auth.py pada workspace", {"coding"}, None),
        ("Cari CVE terbaru untuk Nginx 1.24", {"web", "chat"}, None),
        ("Tolong cek celah keamanan website staging saya.", {"security"}, "question"),
        ("Jalankan tcp-connect ke IP 127.0.0.1 port 11434, 1 di lab dengan mode blackbox", {"security"}, "plan"),
    ]
    for prompt, expected, outcome in cases:
        started = time.monotonic()
        try:
            intent = asyncio.run(classify(prompt, [], reasoning))
            detail = {"prompt": prompt, "intent": intent, "seconds": round(time.monotonic() - started, 1)}
            ok = intent in expected
            if ok and outcome:
                slots = asyncio.run(security_slots(prompt, [], reasoning))
                plan, question = prepare_plan(slots)
                detail.update(question=question, plan_tool=(plan or {}).get("tool"),
                              plan_ports=(plan or {}).get("ports"), plan_target=((plan or {}).get("target") or {}).get("value"))
                ok = bool(question and "URL" in question and "belum tersedia" not in question) if outcome == "question" else bool(plan and plan.get("tool") == "tcp-connect"
                                                                         and sorted(plan.get("ports", [])) == [1, 11434])
            record("router: " + prompt[:40], ok, hard=outcome == "question", **detail)
        except Exception as exc:
            record("router: " + prompt[:40], False, hard=False, error=str(exc)[:300])


def tcp_end_to_end(client, project):
    session = "live-tcp"
    prompt = "Jalankan tcp-connect ke IP 127.0.0.1 port 11434, 1 di lab dengan mode blackbox"
    started = time.monotonic()
    rows = events(client.post("/api/chat", headers=HEADERS, json={"prompt": prompt, "session_id": session,
                                                                 "project_id": project, "unified": True}))
    actions = [row["action"] for row in rows if row["type"] == "action_proposal"]
    record("tcp: kartu konfirmasi muncul sebelum eksekusi", bool(actions), types=[r["type"] for r in rows],
           message=next((r.get("result") or r.get("detail") for r in rows if r["type"] in ("result", "error")), None))
    if not actions:
        return
    listing = client.get(f"/api/security/projects/{project}/engagements", headers=HEADERS)
    record("tcp: belum ada engagement/job sebelum Setuju", listing.status_code == 200 and not listing.json().get("items"),
           status=listing.status_code)
    rows = events(client.post(f"/api/chat/actions/{actions[0]['id']}/confirm", headers=HEADERS,
                              json={"session_id": session, "approve": True}))
    result = next((row.get("result", "") for row in rows if row["type"] == "result"), "")
    error = next((row.get("detail", "") for row in rows if row["type"] == "error"), "")
    statuses = [row.get("label") for row in rows if row["type"] == "status"]
    record("tcp: job nyata selesai dan evidence tersimpan", "Evidence:" in result and not error,
           seconds=round(time.monotonic() - started, 1), statuses=statuses[-6:], error=error)
    record("tcp: Deep Analysis model security berhasil", "Deep Analysis gagal" not in result and "Ringkasan" in result,
           report=result[:1500])
    listing = client.get(f"/api/security/projects/{project}/engagements", headers=HEADERS).json().get("items", [])
    record("tcp: Auto-RoE tercatat di Security Workspace", len(listing) == 1, engagements=len(listing))
    if listing:
        base = f"/api/security/projects/{project}/engagements/{listing[0]['id']}"
        jobs = client.get(base + "/jobs", headers=HEADERS).json().get("items", [])
        record("tcp: job berstatus completed", bool(jobs) and all(job["status"] == "completed" for job in jobs),
               jobs=[(job.get("name"), job["status"]) for job in jobs])
    replay = client.post(f"/api/chat/actions/{actions[0]['id']}/confirm", headers=HEADERS,
                         json={"session_id": session, "approve": True})
    record("tcp: konfirmasi tidak dapat dipakai ulang", replay.status_code >= 400, status=replay.status_code)


def whitebox_review(client, project, model):
    session = "live-whitebox-" + model.replace(":", "-").replace("/", "-")
    attachment = client.app.state.store.add_attachment(session, "app.py", "document", SAMPLE_CODE)
    prompt = "Lakukan document-review WhiteBox pada domain example.test dalam lab. Jenis bukti source_code."
    started = time.monotonic()
    rows = events(client.post("/api/chat", headers=HEADERS, json={
        "prompt": prompt, "session_id": session, "project_id": project, "attachment_ids": [attachment["id"]],
        "unified": True, "model_override": model}))
    actions = [row["action"] for row in rows if row["type"] == "action_proposal"]
    if not actions:
        record(f"whitebox[{model}]: kartu konfirmasi", False, hard=False,
               message=next((r.get("result") or r.get("detail") for r in rows if r["type"] in ("result", "error")), None))
        return
    rows = events(client.post(f"/api/chat/actions/{actions[0]['id']}/confirm", headers=HEADERS,
                              json={"session_id": session, "approve": True}))
    result = next((row.get("result", "") for row in rows if row["type"] == "result"), "")
    error = next((row.get("detail", "") for row in rows if row["type"] == "error"), "")
    claims = result.split("**Keterbatasan**")[0].lower()
    hallucinated = [term for term in ("cookie", "httponly", "csp", "hsts", "cors", "jwt", "xss", "csrf") if term in claims]
    removed = next((line for line in result.splitlines() if "pernyataan model dihapus" in line), "")
    record(f"whitebox[{model}]: laporan tersusun", "Evidence:" in result and not error and "gagal" not in result.lower(),
           hard=False, seconds=round(time.monotonic() - started, 1), error=error, report=result[:1800])
    record(f"whitebox[{model}]: tidak ada klaim di luar evidence", not hallucinated, hard=False,
           unsupported_terms_in_claims=hallucinated, removed_note=removed)
    SUMMARY["models"].setdefault(model, {})["whitebox_seconds"] = round(time.monotonic() - started, 1)


VA_TARGET = "https://va-fixture.example.test/"
# Synthetic page: 2 same-origin links, 1 same host over http, 3 external origins on 2 hosts.
VA_HTML = """<html><head><link href="/style.css" rel="stylesheet"><script src="https://cdn.fixture-cdn.example/lib.js"></script>
<script src="https://cdn.fixture-cdn.example:8443/x.js"></script></head><body><a href="/login">Login</a>
<a href="https://va-fixture.example.test/about">About</a><a href="http://va-fixture.example.test/old">Old</a>
<a href="https://social.fixture.example/share">Share</a><form action="/search"></form></body></html>"""


def url_va_end_to_end(client, project):
    """URL VA package with real routing, slot filling and Deep Analysis; adapters return fixtures."""
    from unittest.mock import AsyncMock, patch
    from inventory_adapter import Links
    from analysis_grounding import inventory_origin_counts
    links = Links(VA_TARGET)
    links.feed(VA_HTML)
    inventory = {"tool": "inventory-html", "target": VA_TARGET, "http_status": 200, "body_sha256": "0" * 64,
                 "candidates": links.items, "limitation": "Fixture sintetis."}
    counts = inventory_origin_counts({"result": inventory})
    expected = (f"{counts['total']} origin kandidat unik: {counts['same_origin']} sama dengan origin target, "
                f"{counts['same_host_other_origin']} pada host target dengan skema/port berbeda, dan {counts['external']} origin eksternal")
    record("va: hitungan acuan dari fixture", (counts["total"], counts["same_origin"], counts["same_host_other_origin"],
                                                counts["external"], counts["external_hosts"]) == (5, 1, 1, 3, 2), counts=counts)
    session, history = "live-url-va", []

    def chat(prompt):
        rows = events(client.post("/api/chat", headers=HEADERS, json={
            "prompt": prompt, "session_id": session, "project_id": project, "unified": True, "history": history}))
        text = next((r.get("result") or r.get("detail") or "" for r in rows if r["type"] in ("result", "error")), "")
        history.extend([{"role": "user", "content": prompt}, *([{"role": "assistant", "content": text[:16000]}] if text else [])])
        return rows, text

    async def scan(plan, *args, **kwargs):
        if plan["scan"]["tool"] != "inventory-html":
            raise AssertionError("Paket VA hanya boleh menjalankan inventory-html melalui scanner.")
        return inventory

    # Same shape as web_checks.probe; header presence only, never values.
    present = ("strict-transport-security", "x-content-type-options")
    head = {"adapter": "public-head-1.0", "url": VA_TARGET, "method": "HEAD", "requests": 1, "http_status": 200,
            "redirect_followed": False, "body_collected": False, "credentials_sent": False,
            "tls": {"verified": True, "version": "TLSv1.3", "certificate_expires": "Jan  1 00:00:00 2027 GMT"},
            "checks": [{"check": name, "status": "present" if name in present else "missing", "severity": "info", "review_required": True}
                       for name in ("strict-transport-security", "content-security-policy", "x-content-type-options",
                                    "x-frame-options", "referrer-policy", "permissions-policy")]
                      + [{"check": "https_transport", "status": "verified", "review_required": True}],
            "cookie_flags": [{"secure": True, "httponly": False, "samesite": True}], "redirect_observed": False, "head_supported": True,
            "http_configuration": {"cache": {"header_present": False, "no_store": False, "private": False},
                                   "cors": {"allow_origin_present": False, "wildcard_origin_observed": False, "allow_credentials_true": False}},
            "limitations": "Satu respons HEAD. Header absen bukan bukti exploit; tidak ada crawling, login, body, atau uji TLS legacy."}
    with patch("bounded_scan.run_scan", new=AsyncMock(side_effect=scan)), patch("web_checks.probe", new=AsyncMock(return_value=head)):
        started = time.monotonic()
        rows, first = chat(f"Jalankan vulnerabilities assessment pada {VA_TARGET}")
        actions = [r["action"] for r in rows if r["type"] == "action_proposal"]
        if not actions:
            record("va: pertanyaan lingkungan/mode", "lingkungan" in first.lower() or "mode" in first.lower(), hard=False, message=first[:300])
            rows, second = chat("lingkungan staging, mode BlackBox")
            actions = [r["action"] for r in rows if r["type"] == "action_proposal"]
        record("va: kartu memakai target dari riwayat sesi", bool(actions) and VA_TARGET in json.dumps(actions[0]),
               tools=actions[0].get("tools") if actions else None, message=history[-1]["content"][:300] if history else "")
        if not actions:
            return
        rows = events(client.post(f"/api/chat/actions/{actions[0]['id']}/confirm", headers=HEADERS,
                                  json={"session_id": session, "approve": True}))
        report = next((row.get("result", "") for row in rows if row["type"] == "result"), "")
        error = next((row.get("detail", "") for row in rows if row["type"] == "error"), "")
        history.append({"role": "assistant", "content": report[:16000]})
        record("va: dua job selesai dengan Deep Analysis", report.count("Evidence:") == 2 and "Deep Analysis gagal" not in report and not error,
               seconds=round(time.monotonic() - started, 1), error=error, report=report[:2500])
        inventory_part = next((part for part in report.split("---") if "Inventaris HTML" in part), "")
        record("va: jumlah origin di laporan sesuai evidence", expected in inventory_part, expected=expected, section=inventory_part[:900])
        wrong = [line for line in report.splitlines() if "eksternal" in line.lower() and expected not in line
                 and re.search(r"\d", line) and "Evidence:" not in line]
        record("va: tidak ada angka origin lain dari model", not wrong, lines=wrong)
        head_part = next((part for part in report.split("---") if "Respons HEAD" in part), "")
        expected_facts = ["Header ada: HSTS, X-Content-Type-Options.",
                          "Header tidak ada: CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy.",
                          "HTTPS: terverifikasi (TLSv1.3", "Cookie tercatat: 1 Set-Cookie (1 tanpa HttpOnly).",
                          "Susun Content-Security-Policy"]
        missing_facts = [fact for fact in expected_facts if fact not in head_part]
        record("va: laporan HEAD memuat fakta & rekomendasi dari evidence", not missing_facts, missing=missing_facts,
               section=head_part[:1500])
        claims = head_part.split("**Keterbatasan**")[0]
        record("va: tidak ada fakta header di bagian Keterbatasan", not re.search(
            r"content security policy|x-frame|\bcsp\b", head_part.split("**Keterbatasan**")[-1].split("**Rekomendasi**")[0], re.I),
            hard=False)
        record("va: klaim header model tidak bertentangan", "tersedia dan aman" not in claims and "Header ada: CSP" not in claims)

    started = time.monotonic()
    rows, answer = chat("Dari hasil VA tadi, berapa origin eksternal yang tercatat?")
    intent = next((r.get("detail") for r in rows if r["type"] == "status" and "Intent" in (r.get("detail") or "")), "")
    record("memori: pertanyaan lanjutan tanpa mengulang konteks", str(counts["external"]) in answer and not any(
        r["type"] == "action_proposal" for r in rows), hard=False, intent=intent, answer=answer[:500],
        seconds=round(time.monotonic() - started, 1))
    # Long session: filler turns push the report out of the model context window; session facts must keep it.
    filler = [{"role": role, "content": f"Catatan rapat nomor {i}: " + "detail operasional rutin. " * 60}
              for i in range(18) for role in ("user", "assistant")]
    history.extend(filler)
    started = time.monotonic()
    rows, answer = chat("Sebutkan lagi jumlah host luar dari pemeriksaan pertama tadi.")
    record("memori: fakta tetap diingat setelah sesi panjang", str(counts["external"]) in answer or str(counts["external_hosts"]) in answer,
           hard=False, answer=answer[:500], seconds=round(time.monotonic() - started, 1))
    rows, _ = chat("Ulangi VA pada target yang sama")
    actions = [r["action"] for r in rows if r["type"] == "action_proposal"]
    record("memori: 'target yang sama' memakai URL sebelumnya + kartu baru", bool(actions) and VA_TARGET in json.dumps(actions[0]),
           hard=False, message=history[-1]["content"][:300])


def monitoring(client, project):
    try:
        httpx.get("http://127.0.0.1:9090/-/ready", timeout=2).raise_for_status()
    except Exception:
        record("monitoring-local: stack Prometheus/Grafana tidak berjalan (dilewati)", True, hard=False)
        return
    session = "live-monitoring"
    rows = events(client.post("/api/chat", headers=HEADERS, json={
        "prompt": "Monitoring lokal monitoring-local 127.0.0.1 WhiteBox lab", "session_id": session,
        "project_id": project, "unified": True}))
    actions = [row["action"] for row in rows if row["type"] == "action_proposal"]
    if not actions:
        record("monitoring-local: kartu konfirmasi", False, hard=False)
        return
    rows = events(client.post(f"/api/chat/actions/{actions[0]['id']}/confirm", headers=HEADERS,
                              json={"session_id": session, "approve": True}))
    result = next((row.get("result", "") for row in rows if row["type"] == "result"), "")
    record("monitoring-local: snapshot nyata dan analisis", "Evidence:" in result, hard=False, report=result[:800])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--security-model", default="whiterabbitneo-v3-7b")
    args = parser.parse_args()
    out = ROOT / "output" / "verify"
    out.mkdir(parents=True, exist_ok=True)
    try:
        names = installed()
    except Exception as exc:
        record("ollama: dapat dihubungi", False, error=str(exc))
        (out / "live_chat_first.json").write_text(json.dumps(SUMMARY, ensure_ascii=False, indent=2), encoding="utf-8")
        return 1
    record("ollama: dapat dihubungi", True, installed=names)
    with TestClient(app) as client:
        reasoning = resolve(MODELS["reasoning"], names)
        configured_security = resolve(MODELS["security"], names)
        rabbit = resolve(args.security_model, names)
        SUMMARY["models"] = {"reasoning": reasoning, "configured_security": configured_security, "whiterabbitneo": rabbit}
        record("model reasoning terpasang", bool(reasoning), name=MODELS["reasoning"])
        record("WhiteRabbitNeo terpasang di Ollama", bool(rabbit), name=args.security_model)
        if not reasoning:
            return finish(out)
        router_checks(reasoning)
        security = rabbit or configured_security
        if not security:
            record("model security terpasang", False)
            return finish(out)
        MODELS["security"] = security
        project = str(uuid.uuid4())
        tcp_end_to_end(client, project)
        url_va_end_to_end(client, str(uuid.uuid4()))
        for model in dict.fromkeys(filter(None, [rabbit, configured_security])):
            whitebox_review(client, str(uuid.uuid4()), model)
        monitoring(client, str(uuid.uuid4()))
    return finish(out)


def finish(out):
    SUMMARY["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (out / "live_chat_first.json").write_text(json.dumps(SUMMARY, ensure_ascii=False, indent=2), encoding="utf-8")
    failed = [c["name"] for c in SUMMARY["checks"] if c["hard"] and not c["ok"]]
    print("RINGKASAN:", "semua pemeriksaan wajib lulus" if not failed else "gagal: " + "; ".join(failed), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

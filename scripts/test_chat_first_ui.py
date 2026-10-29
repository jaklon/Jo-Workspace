"""Browser-to-backend QA using temporary data and a synthetic scan/model."""
import asyncio
import io
import base64
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
temp = Path(tempfile.mkdtemp(prefix="jo-chat-ui-"))
os.environ["AGENT_DATA_DIR"] = str(temp)
os.environ["AGENT_WORKSPACE"] = str(temp / "workspace")
os.environ["AGENT_API_TOKEN"] = "synthetic-ui-test-token-1234567890"

import uvicorn
from playwright.sync_api import sync_playwright
from PIL import Image
from chat_orchestrator import SecuritySlots, ToolSelection
from config import MODELS
from main import app


def main():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    slots = SecuritySlots(environment="lab", assessment_mode="blackbox", selections=[
        ToolSelection(tool="tcp-connect", target="192.0.2.4", ports=[443]),
        ToolSelection(tool="http-head", target="https://example.test/"),
    ])
    slots_mock = AsyncMock(return_value=slots)
    result = {"summary":"Fixture selesai", "observations":["Port tertutup"], "limitations":["Data sintetis"], "recommendations":[]}
    import bounded_scan
    real_scan = bounded_scan.run_scan
    async def fake_scan(plan, *args, **kwargs):
        # The two-session adapter runs for real so its three GETs reach the synthetic probe below.
        if plan["scan"]["tool"] == "auth-two-session":
            return await real_scan(plan, *args, **kwargs)
        return {"tool":"tcp-connect", "target":"192.0.2.4", "ports":[{"port":443,"status":"closed"}]}
    scanner = AsyncMock(side_effect=fake_scan)
    web = AsyncMock(return_value={"http_status":200, "redirect_observed":False})
    def token(subject):
        claims = base64.urlsafe_b64encode(json.dumps({"sub":subject,"aud":"fixture"}).encode()).decode().rstrip('=')
        return 'e30.' + claims + '.signature'
    tokens = [token('account-a'), token('account-b')]
    with patch("main.classify", new=AsyncMock(return_value="security")), \
         patch("main.security_slots", new=slots_mock), \
         patch("bounded_scan.run_scan", new=scanner), \
         patch("web_checks.probe", new=web), \
         patch("deep_analysis.installed_models", new=AsyncMock(return_value=[{"name":MODELS["security"],"digest":"fixture"}])), \
         patch("security_agents.installed_models", new=AsyncMock(return_value=[{"name":MODELS["security"],"digest":"fixture"}])), \
         patch("deep_analysis.runtime.chat", new=AsyncMock(return_value={"content":json.dumps(result),"tool_calls":[]})):
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 20
            while not server.started and time.monotonic() < deadline:
                time.sleep(.1)
            if not server.started: raise RuntimeError("QA server did not start")
            with sync_playwright() as playwright:
                chrome = os.environ.get("JO_CHROME_PATH", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
                browser = playwright.chromium.launch(executable_path=chrome if Path(chrome).is_file() else None, headless=True)
                for width, height in ((1440,900),(390,844)):
                    context = browser.new_context(viewport={"width":width,"height":height})
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                    page.get_by_label("Token akses").fill(os.environ["AGENT_API_TOKEN"])
                    page.get_by_role("button", name="Hubungkan", exact=True).click()
                    page.get_by_label("Pesan untuk AI").fill("Scan tcp-connect 192.0.2.4 port 443 lab blackbox")
                    before = scanner.await_count
                    web_before = web.await_count
                    page.get_by_label("Kirim pesan").click()
                    card = page.get_by_label("Rencana tindakan")
                    card.wait_for(timeout=20000)
                    assert "192.0.2.4" in card.inner_text()
                    assert "https://example.test/" in card.inner_text()
                    assert scanner.await_count == before
                    assert web.await_count == web_before
                    card.get_by_role("button", name="Setuju & Jalankan").click()
                    page.get_by_text("Ringkasan", exact=False).first.wait_for(timeout=30000)
                    assert scanner.await_count == before + 1
                    assert web.await_count == web_before + 1
                    assert "Fixture selesai" in page.inner_text("body")
                    page.get_by_role("button", name="Lihat Detail di Security Workspace").first.click()
                    page.get_by_text("Security Workspace · Riwayat dan audit").wait_for(timeout=10000)
                    page.get_by_text("Chat · tcp-connect").wait_for(timeout=15000)
                    page.get_by_role("button", name="Kembali ke chat").click()
                    page.get_by_label("Pesan untuk AI").wait_for(timeout=10000)
                    page.locator('input[type="file"]').set_input_files({"name":"fixture.txt","mimeType":"text/plain","buffer":b"synthetic source code"})
                    page.get_by_label("Pesan untuk AI").fill("Baca dokumen ini")
                    page.get_by_label("Kirim pesan").click()
                    page.get_by_label("Rencana tindakan").last.get_by_role("button", name="Setuju & Jalankan").click()
                    page.get_by_label("Lepas fixture.txt").wait_for(timeout=30000)
                    slots_mock.return_value = SecuritySlots(tool="document-review", target="example.test", environment="lab",
                        assessment_mode="whitebox", evidence_kind="source_code", specialists=["web_api"])
                    page.get_by_label("Pesan untuk AI").fill("Review WhiteBox source_code example.test lab dengan spesialis web_api")
                    page.get_by_label("Kirim pesan").click()
                    review = page.get_by_label("Rencana tindakan").last
                    review.get_by_text("Spesialis web_api", exact=False).wait_for(timeout=20000)
                    review.get_by_role("button", name="Setuju & Jalankan").click()
                    page.get_by_text("Spesialis web_api · review evidence", exact=False).last.wait_for(timeout=30000)
                    slots_mock.return_value = SecuritySlots(tool="auth-two-session", target="https://example.test/api", environment="staging",
                        assessment_mode="greybox", account_refs=["qa-a", "qa-b"], specialists=["reporting"])
                    page.get_by_label("Pesan untuk AI").fill("GreyBox auth-two-session https://example.test/api staging alias: qa-a, qa-b dengan spesialis reporting")
                    page.get_by_label("Kirim pesan").click()
                    greybox = page.get_by_label("Rencana tindakan").last
                    greybox.get_by_text("qa-a", exact=False).first.wait_for(timeout=20000)
                    assert greybox.get_by_role("button", name="Setuju & Jalankan").is_disabled()
                    greybox.get_by_label("Token JWT sementara untuk qa-a").fill(tokens[0])
                    greybox.get_by_label("Token JWT sementara untuk qa-b").fill(tokens[1])
                    auth_before = web.await_count
                    greybox.get_by_role("button", name="Setuju & Jalankan").click()
                    page.get_by_text("Spesialis reporting · review evidence", exact=False).last.wait_for(timeout=30000)
                    assert web.await_count == auth_before + 3
                    assert tokens[0] not in page.inner_text('body') and tokens[1] not in page.inner_text('body')
                    slots_mock.return_value = slots
                    image_buffer = io.BytesIO()
                    Image.new("RGB", (8, 8), "white").save(image_buffer, format="PNG")
                    page.locator('input[type="file"]').set_input_files({"name":"fixture.png","mimeType":"image/png","buffer":image_buffer.getvalue()})
                    page.get_by_label("Pesan untuk AI").fill("Jelaskan gambar")
                    page.get_by_label("Kirim pesan").click()
                    page.get_by_label("Rencana tindakan").last.get_by_role("button", name="Setuju & Jalankan").click()
                    page.get_by_label("Lepas fixture.png").wait_for(timeout=30000)
                    if width < 1024: page.get_by_label("Buka sidebar").click()
                    page.get_by_role("button", name="Security Workspace Riwayat", exact=True).click()
                    page.get_by_text("Security Workspace · Riwayat dan audit").wait_for(timeout=10000)
                    page.locator("select").first.select_option(label="Auto Security Workspace")
                    page.get_by_text("Riwayat Job").wait_for(timeout=10000)
                    page.get_by_text("Chat · auth-two-session").wait_for(timeout=15000)
                    page.get_by_role("button", name="Laporan & Audit RoE").click()
                    page.get_by_text("Spesialis reporting · review evidence").wait_for(timeout=10000)
                    assert not errors, errors
                    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
                    print(f"UI {width}x{height}: confirmation, multi-tool, document, image, WhiteBox, GreyBox, specialist, dashboard OK", flush=True)
                    context.close()
                browser.close()
            for path in temp.glob('*.sqlite3*'):
                raw = path.read_bytes()
                assert all(value.encode() not in raw for value in tokens), path.name
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            if thread.is_alive(): raise RuntimeError("QA server did not stop")


if __name__ == "__main__":
    main()

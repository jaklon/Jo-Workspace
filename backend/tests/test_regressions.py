import asyncio
import base64
import io
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Deliberately use mkdtemp instead of TemporaryDirectory here. Starlette's
# background shutdown can otherwise race Windows' eager directory cleanup and
# produce a misleading PermissionError even though every test passed.
TEST_DATA = Path(tempfile.mkdtemp(prefix="agent-api-tests-"))
os.environ["AGENT_DATA_DIR"] = str(TEST_DATA)
os.environ["AGENT_WORKSPACE"] = str(TEST_DATA / "workspace")
os.environ["AGENT_API_TOKEN"] = "synthetic-test-key-not-a-production-secret"

from fastapi.testclient import TestClient
from docx import Document
from openpyxl import Workbook
import tools
from config import MAX_BODY
from contracts import ChatPayload
from doc_engine import parse_document_file
from main import app
from model_runtime import ModelRuntime, ThinkSplitter, bounded_messages, clean_answer
from router import retrieve, detect_pipeline_route
from store import Store


class FileBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="agent-files-")
        self.root = Path(self.directory.name) / "workspace"
        self.root.mkdir()
        self.override = patch.object(tools, "WORKSPACE_ROOT", str(self.root))
        self.override.start()

    def tearDown(self):
        self.override.stop()
        self.directory.cleanup()

    def test_prefix_escape_and_sensitive_paths(self):
        for path in ("../workspace-other/x", "../outside", str(self.root / "absolute"), ".git/config", ".env", ".ENV.secret", "x:stream"):
            with self.subTest(path=path), self.assertRaises(PermissionError):
                tools.safe_path(path)

    def test_symlink_escape(self):
        outside = Path(self.directory.name) / "outside"
        outside.mkdir()
        try:
            (self.root / "link").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation not permitted on this host")
        with self.assertRaises(PermissionError):
            tools.safe_path("link/file")

    def test_proposal_no_write_until_approved_and_backup(self):
        file = self.root / "example.txt"
        file.write_text("before\n")
        proposal = tools.proposal_payload("example.txt", "after\n")
        self.assertEqual(file.read_text(), "before\n")
        self.assertIn("+after", proposal["diff"])
        tools.apply_proposal(proposal)
        self.assertEqual(file.read_text(), "after\n")
        self.assertEqual(next((self.root / ".agent-backups").glob("*.bak")).read_text(), "before\n")

    def test_stale_proposal_does_not_overwrite(self):
        file = self.root / "example.txt"
        file.write_text("before")
        proposal = tools.proposal_payload("example.txt", "after")
        file.write_text("user edit")
        with self.assertRaises(ValueError):
            tools.apply_proposal(proposal)
        self.assertEqual(file.read_text(), "user edit")

    def test_direct_write_and_shell_injection_rejected(self):
        with self.assertRaises(PermissionError):
            tools.write_file("x", "y")
        for command in ("git status & echo BAD", "npm test", "pytest; echo BAD"):
            with self.assertRaises(PermissionError):
                tools.run_command(command)


class DocumentTests(unittest.TestCase):
    def test_docx_table_and_paragraph(self):
        doc = Document()
        doc.add_paragraph("Header text")
        doc.add_table(rows=1, cols=1).cell(0, 0).text = "CENDANA-58"
        buffer = io.BytesIO(); doc.save(buffer)
        text = parse_document_file("fixture.docx", buffer.getvalue())
        self.assertIn("CENDANA-58", text)
        self.assertIn("Tabel", text)

    def test_xlsx_formula_without_cached_value(self):
        workbook = Workbook(); workbook.active["A1"] = "=1+2"
        buffer = io.BytesIO(); workbook.save(buffer)
        self.assertIn("=1+2", parse_document_file("fixture.xlsx", buffer.getvalue()))

    def test_legacy_and_invalid_encoding_are_explicit(self):
        for name, data in (("x.doc", b"fake"), ("x.xls", b"fake"), ("x.txt", b"\xff"), ("x.pdf", b"fake")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_document_file(name, data)

    def test_tail_retrieval_and_coverage(self):
        text = "Catatan rutin.\n" * 1500 + "Kode persetujuan: ZEBRA-842."
        context, sources, coverage = retrieve([{"id": "a", "name": "long.txt", "content": text}], "Apa kode persetujuan?", "Gunakan sumber.")
        self.assertIn("ZEBRA-842", context)
        self.assertFalse(coverage["complete"])
        self.assertTrue(any(source["line_start"] > 1000 for source in sources))

    def test_budget_rejects_instead_of_silent_prompt_truncation(self):
        with self.assertRaises(ValueError):
            bounded_messages("system", "x" * 10000)

    def test_internal_reasoning_is_not_returned(self):
        self.assertEqual(clean_answer("<think>secret</think>Jawaban"), "Jawaban")
        self.assertEqual(clean_answer("Thinking Process: secret\nFinal Answer: Aman"), "Aman")
        self.assertEqual(clean_answer("Analysis: secret only"), "")

    def test_think_splitter_handles_tags_split_across_chunks(self):
        splitter = ThinkSplitter()
        parts = [*splitter.feed("Halo <th"), *splitter.feed("ink>rahasia</thi"), *splitter.feed("nk> dunia"), *splitter.flush()]
        self.assertEqual("".join(text for kind, text in parts if kind == "token"), "Halo  dunia")
        self.assertEqual("".join(text for kind, text in parts if kind == "thinking"), "rahasia")

    def test_image_dispatch_is_explicit(self):
        self.assertEqual(detect_pipeline_route("x.jpeg", "describe"), "VISION_PIPELINE")
        with self.assertRaises(ValueError):
            detect_pipeline_route("x.exe", "code")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.data_override = patch("main.DATA_DIR", TEST_DATA)
        self.data_override.start()
        self.client = TestClient(app, client=("127.0.0.1", 50000)).__enter__()
        self.headers = {"Authorization": "Bearer " + os.environ["AGENT_API_TOKEN"]}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.data_override.stop()

    def events(self, response):
        return [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:")]

    def upload_document(self, name, content, prompt, session, model=None):
        prepared = self.client.post('/api/chat/uploads/prepare', headers=self.headers, json={
            'session_id':session, 'filename':name, 'size':len(content), 'sha256':hashlib.sha256(content).hexdigest(),
            'prompt':prompt, 'model_override':model})
        self.assertEqual(prepared.status_code, 200, prepared.text)
        action_id = prepared.json()['action']['id']
        confirmed = self.client.post('/api/chat/actions/'+action_id+'/confirm', headers=self.headers,
                                     json={'session_id':session, 'approve':True})
        self.assertEqual(self.events(confirmed)[-1]['type'], 'done')
        return self.client.post('/api/chat/uploads/'+action_id+'/execute', headers=self.headers,
                                data={'session_id':session}, files={'file':(name,content,'text/plain')})

    def test_auth_blocks_agent_and_chat(self):
        for path in ("/api/agent/run", "/api/chat", "/api/gpu-status", "/api/pentest/run", "/api/pentest/capabilities"):
            response = self.client.post(path, json={"prompt": "test"})
            self.assertEqual(response.status_code, 401)

    def test_pentest_api_locked_during_planning_stage(self):
        with patch("main.assess") as assess:
            response = self.client.post('/api/pentest/run', headers=self.headers, json={'ai_report': False})
        self.assertEqual(response.status_code, 423)
        assess.assert_not_called()
        self.assertFalse(self.client.app.state.pentest_lock.locked())

    def test_legacy_execution_endpoints_require_chat_confirmation(self):
        paths = ['/api/agent/run', '/api/agent/dispatch', '/api/document/parse', '/api/document/analyze-stream',
                 '/api/vision/analyze', '/api/search/query', '/api/search/extract-images', '/api/agent/proposals/example',
                 '/api/security/mcp/servers/00000000-0000-0000-0000-000000000001/check',
                 '/api/security/projects/p/engagements/e/jobs/j/approve',
                 '/api/security/projects/p/engagements/e/deep-analysis',
                 '/api/security/projects/p/engagements/e/orchestrations',
                 '/api/security/projects/p/engagements/e/orchestrations/r/approve',
                 '/api/security/projects/p/engagements/e/agents/a/approve',
                 '/api/security/projects/p/engagements/e/jobs/j/retry', '/api/pentest/run']
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path, headers=self.headers, json={}).status_code, 423)
        response = self.client.post('/api/chat', headers=self.headers, json={'prompt':'Cari web', 'web_mode':'on'})
        self.assertEqual(response.status_code, 423)

    def test_upload_requires_matching_single_use_approval(self):
        content = b'fixture file'
        data = {'session_id':'upload-security','filename':'fixture.txt','size':len(content),
                'sha256':hashlib.sha256(content).hexdigest(),'prompt':'Ringkas'}
        action = self.client.post('/api/chat/uploads/prepare',headers=self.headers,json=data).json()['action']
        path = '/api/chat/uploads/'+action['id']+'/execute'
        def upload(value, session='upload-security'):
            return self.client.post(path,headers=self.headers,data={'session_id':session},files={'file':('fixture.txt',value,'text/plain')})
        self.assertEqual(upload(content).status_code, 400)
        response = self.client.post('/api/chat/actions/'+action['id']+'/confirm',headers=self.headers,
                                    json={'session_id':'upload-security','approve':True})
        self.assertEqual(self.events(response)[-1]['type'], 'done')
        self.assertEqual(upload(b'other file').status_code, 409)
        self.assertEqual(upload(content,'wrong').status_code, 400)
        with patch('services.runtime.chat',new=AsyncMock(return_value={'content':'OK'})):
            self.assertEqual(self.events(upload(content))[-1]['type'], 'done')
        self.assertEqual(upload(content).status_code, 400)

    def test_chat_rejects_session_jwt_without_echoing_it(self):
        claims = base64.urlsafe_b64encode(json.dumps({'sub':'a','aud':'fixture'}).encode()).decode().rstrip('=')
        token = 'e30.' + claims + '.signature'
        response = self.client.post('/api/chat',headers=self.headers,json={'prompt':'token '+token,'unified':True})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(token, response.text)

    def test_unapproved_image_fetch_is_blocked(self):
        url = 'https://example.test/image.png'
        response = self.client.get('/api/search/image',headers=self.headers,params={'url':url,'ticket':'invalid'})
        self.assertEqual(response.status_code, 403)

    def test_login_cookie_and_hostile_origin(self):
        response = self.client.post("/api/session", json={"token": os.environ["AGENT_API_TOKEN"]})
        self.assertEqual(response.status_code, 200)
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertEqual(self.client.get("/api/metrics").status_code, 200)
        self.assertEqual(self.client.post("/api/chat", headers={"Origin": "https://attacker.example"}, json={"prompt": "x"}).status_code, 403)

    def test_request_size_and_iteration_bounds(self):
        self.assertEqual(self.client.post("/api/chat", headers={**self.headers, "Content-Length": str(MAX_BODY+1)}, content="x").status_code, 413)
        for value in (-1, 0, 999):
            self.assertEqual(self.client.post("/api/agent/run", headers=self.headers, json={"prompt": "x", "max_iterations": value}).status_code, 423)

    def test_vision_followup_error_is_clear(self):
        result = self.client.post("/api/chat", headers=self.headers, json={"prompt": "gambar tadi", "target": "vision"})
        self.assertEqual(result.status_code, 400)
        self.assertIn("Unggah gambar", result.json()["detail"])

    def test_chat_model_override_applies_to_text_and_document(self):
        async def chunks(model, messages, **kwargs):
            self.assertEqual(model, "chosen:latest")
            yield {"message": {"content": "OK"}}
            yield {"done": True}
        with patch("main.validate_model_override", new=AsyncMock()), \
             patch("main.runtime.chunks", new=chunks), \
             patch("services.runtime.chat", new=AsyncMock(return_value={"content": "OK"})) as chat:
            response = self.client.post("/api/chat", headers=self.headers,
                json={"prompt": "test", "model_override": "chosen:latest"})
            self.assertEqual(self.events(response)[-1]["type"], "done")
            response = self.upload_document("example.txt", b"Contoh.", "Ringkas", "override", "chosen:latest")
            self.assertEqual(self.events(response)[-1]["type"], "done")
            self.assertEqual(chat.await_args.args[0], "chosen:latest")

    def test_unified_coding_waits_for_confirmation_and_rejects_replay(self):
        with patch("main.classify", new=AsyncMock(return_value="coding")), \
             patch("main.execute_agent_pipeline", new=AsyncMock(return_value={"result": "done", "proposals": []})) as agent:
            response = self.client.post("/api/chat", headers=self.headers,
                json={"prompt": "Periksa file workspace", "session_id": "unified-test", "unified": True})
            events = self.events(response)
            action = next(e["action"] for e in events if e["type"] == "action_proposal")
            agent.assert_not_awaited()
            path = "/api/chat/actions/" + action["id"] + "/confirm"
            self.assertEqual(self.client.post(path, headers=self.headers,
                json={"session_id": "wrong", "approve": True}).status_code, 400)
            self.assertEqual(agent.await_count, 0)
            approved = self.client.post(path, headers=self.headers,
                json={"session_id": "unified-test", "approve": True})
            self.assertEqual(self.events(approved)[-1]["type"], "done")
            self.assertEqual(agent.await_count, 1)
            self.assertEqual(self.client.post(path, headers=self.headers,
                json={"session_id": "unified-test", "approve": True}).status_code, 400)
            self.assertEqual(agent.await_count, 1)

    def test_unified_tcp_confirm_runs_synthetic_job_and_analysis(self):
        from chat_orchestrator import SecuritySlots
        slots = SecuritySlots(tool="tcp-connect", target="192.0.2.4", ports=[443],
                              environment="lab", assessment_mode="blackbox")
        fake_result = {"tool": "tcp-connect", "target": "192.0.2.4", "ports": [{"port": 443, "status": "closed"}]}
        output = {"summary": "Pemeriksaan selesai. Cookie sesi tanpa flag HttpOnly ditemukan pada port 8080.",
                  "observations": [{"statement": "Port 443 tertutup.", "evidence_quote": "closed"},
                                   {"statement": "Nginx 1.24 rentan.", "evidence_quote": "nginx/1.24"}],
                  "limitations": ["Fixture sintetis"], "recommendations": ["Aktifkan HSTS."]}
        with patch("main.classify", new=AsyncMock(return_value="security")), \
             patch("main.security_slots", new=AsyncMock(return_value=slots)), \
             patch("bounded_scan.run_scan", new=AsyncMock(return_value=fake_result)) as scanner, \
             patch("deep_analysis.installed_models", new=AsyncMock(return_value=[{"name": "security-test", "digest": "synthetic"}])), \
             patch("deep_analysis.runtime.chat", new=AsyncMock(return_value={"content": json.dumps(output), "tool_calls": []})):
            from config import MODELS
            with patch.dict(MODELS, {"security": "security-test"}):
                response = self.client.post("/api/chat", headers=self.headers, json={
                    "prompt": "Scan 192.0.2.4 port 443 lab blackbox", "session_id": "tcp-test",
                    "project_id": "89de83d0-8729-4b0a-b21d-9fcafc444095", "unified": True})
                action = next(e["action"] for e in self.events(response) if e["type"] == "action_proposal")
                scanner.assert_not_awaited()
                response = self.client.post("/api/chat/actions/" + action["id"] + "/confirm", headers=self.headers,
                    json={"session_id": "tcp-test", "approve": True})
                events = self.events(response)
                self.assertEqual(events[-1]["type"], "done", events)
                report = next(e["result"] for e in events if e["type"] == "result")
                self.assertIn("Pemeriksaan selesai", report)
                self.assertIn("Port 443 tertutup", report)
                claims = report.split("**Keterbatasan**")[0]
                for hallucinated in ("HttpOnly", "8080", "Nginx"):
                    self.assertNotIn(hallucinated, claims)
                self.assertNotIn("**Rekomendasi**", report)
                self.assertIn("3 pernyataan model dihapus", report)
                self.assertEqual(scanner.await_count, 1)

    def test_unified_web_waits_for_confirmation(self):
        web = {"messages": [{"role": "user", "content": "fixture"}], "sources": [], "images": []}
        async def chunks(model, messages, **kwargs):
            yield {"message": {"content": "Hasil sintetis"}}
            yield {"done": True}
        with patch("main.classify", new=AsyncMock(return_value="web")), \
             patch("main.web_context", new=AsyncMock(return_value=web)) as search, \
             patch("main.runtime.chunks", new=chunks):
            response = self.client.post("/api/chat", headers=self.headers,
                json={"prompt": "Cari web", "session_id": "web-test", "unified": True, "web_mode": "auto"})
            action = next(e["action"] for e in self.events(response) if e["type"] == "action_proposal")
            search.assert_not_awaited()
            response = self.client.post("/api/chat/actions/" + action["id"] + "/confirm", headers=self.headers,
                json={"session_id": "web-test", "approve": True})
            self.assertEqual(self.events(response)[-1]["type"], "done")
            search.assert_awaited_once()

    def test_unified_multi_tool_runs_confirmed_jobs(self):
        from chat_orchestrator import SecuritySlots, ToolSelection
        from config import MODELS
        slots = SecuritySlots(environment="lab", assessment_mode="blackbox", selections=[
            ToolSelection(tool="tcp-connect", target="192.0.2.4", ports=[443]),
            ToolSelection(tool="http-head", target="https://example.test/")])
        output = {"summary": "Selesai", "observations": ["Observasi"], "limitations": ["Fixture"], "recommendations": []}
        with patch("main.classify", new=AsyncMock(return_value="security")), \
             patch("main.security_slots", new=AsyncMock(return_value=slots)), \
             patch("bounded_scan.run_scan", new=AsyncMock(return_value={"tool":"tcp-connect", "ports":[]})) as scanner, \
             patch("web_checks.probe", new=AsyncMock(return_value={"http_status":200})) as web, \
             patch("deep_analysis.installed_models", new=AsyncMock(return_value=[{"name":"security-test", "digest":"synthetic"}])), \
             patch("deep_analysis.runtime.chat", new=AsyncMock(return_value={"content":json.dumps(output), "tool_calls":[]})), \
             patch.dict(MODELS, {"security":"security-test"}):
            response = self.client.post("/api/chat", headers=self.headers, json={"prompt":"Periksa TCP dan HEAD",
                "session_id":"multi-test", "project_id":"89de83d0-8729-4b0a-b21d-9fcafc444095", "unified":True})
            action = next(e["action"] for e in self.events(response) if e["type"] == "action_proposal")
            self.assertIn("tcp-connect", action["tools"])
            self.assertIn("http-head", action["tools"])
            scanner.assert_not_awaited(); web.assert_not_awaited()
            response = self.client.post("/api/chat/actions/"+action["id"]+"/confirm", headers=self.headers,
                json={"session_id":"multi-test", "approve":True})
            events = self.events(response)
            self.assertEqual(events[-1]["type"], "done", events)
            result = next(e["result"] for e in events if e["type"] == "result")
            self.assertEqual(result.count("Evidence:"), 2)
            scanner.assert_awaited_once(); web.assert_awaited_once()

    def test_unified_whitebox_and_greybox_analyze_imported_evidence(self):
        from chat_orchestrator import SecuritySlots
        from config import MODELS
        output = {"summary": "Review selesai", "observations": ["Konfigurasi dibaca"],
                  "limitations": ["Bukti impor"], "recommendations": []}
        for mode, kind, alias in (("whitebox", "source_code", ""), ("greybox", "configuration", "account-a")):
            with self.subTest(mode=mode):
                session = "review-" + mode
                attachment = self.client.app.state.store.add_attachment(session, "fixture.txt", "document", "example configuration")
                slots = SecuritySlots(tool="document-review", target="example.test", environment="lab",
                                      assessment_mode=mode, evidence_kind=kind, test_account_ref=alias)
                with patch("main.classify", new=AsyncMock(return_value="security")), \
                     patch("main.security_slots", new=AsyncMock(return_value=slots)), \
                     patch("deep_analysis.installed_models", new=AsyncMock(return_value=[{"name": "security-test", "digest": "synthetic"}])), \
                     patch("deep_analysis.runtime.chat", new=AsyncMock(return_value={"content": json.dumps(output), "tool_calls": []})), \
                     patch.dict(MODELS, {"security": "security-test"}):
                    response = self.client.post("/api/chat", headers=self.headers, json={"prompt": "Review " + mode,
                        "session_id": session, "project_id": "89de83d0-8729-4b0a-b21d-9fcafc444095",
                        "attachment_ids": [attachment["id"]], "unified": True})
                    action = next(e["action"] for e in self.events(response) if e["type"] == "action_proposal")
                    self.assertIn("fixture.txt", action["target"])
                    response = self.client.post("/api/chat/actions/" + action["id"] + "/confirm", headers=self.headers,
                        json={"session_id": session, "approve": True})
                    events = self.events(response)
                    self.assertEqual(events[-1]["type"], "done", events)
                    result = next(e["result"] for e in events if e["type"] == "result")
                    self.assertIn("Review selesai", result)
                    self.assertIn("Ringkasan", result)
                    self.assertIn("Evidence:", result)

    def test_specialist_reviews_only_confirmed_evidence_and_is_archived(self):
        from chat_orchestrator import SecuritySlots
        from config import MODELS
        session = "review-specialist"
        attachment = self.client.app.state.store.add_attachment(session, "fixture.txt", "document", "example configuration")
        slots = SecuritySlots(tool="document-review", target="example.test", environment="lab",
                              assessment_mode="whitebox", evidence_kind="source_code", specialists=["web_api"])
        output = {"summary": "Spesialis selesai", "observations": ["Bukti dibaca"],
                  "limitations": ["Tidak ada koneksi baru"], "recommendations": []}
        models = [{"name": "security-test:latest", "digest": "synthetic"}]
        with patch("main.classify", new=AsyncMock(return_value="security")), \
             patch("main.security_slots", new=AsyncMock(return_value=slots)), \
             patch("deep_analysis.installed_models", new=AsyncMock(return_value=models)), \
             patch("security_agents.installed_models", new=AsyncMock(return_value=models)), \
             patch("deep_analysis.runtime.chat", new=AsyncMock(return_value={"content": json.dumps(output), "tool_calls": []})), \
             patch.dict(MODELS, {"security": "security-test"}):
            response = self.client.post("/api/chat", headers=self.headers, json={"prompt": "Review whitebox",
                "session_id": session, "project_id": "89de83d0-8729-4b0a-b21d-9fcafc444095",
                "attachment_ids": [attachment["id"]], "unified": True})
            action = next(e["action"] for e in self.events(response) if e["type"] == "action_proposal")
            self.assertIn("Spesialis web_api (review evidence)", action["tools"])
            response = self.client.post("/api/chat/actions/" + action["id"] + "/confirm", headers=self.headers,
                json={"session_id": session, "approve": True})
            events = self.events(response)
            self.assertEqual(events[-1]["type"], "done", events)
            self.assertIn("Spesialis web_api", next(e["result"] for e in events if e["type"] == "result"))
            engagements = self.client.get("/api/security/projects/89de83d0-8729-4b0a-b21d-9fcafc444095/engagements", headers=self.headers).json()["items"]
            eid = next(item["id"] for item in engagements if any(version["content"]["authorization_ref"] == "CHAT-APPROVED-" + session for version in item["versions"]))
            records = self.client.get(f"/api/security/projects/89de83d0-8729-4b0a-b21d-9fcafc444095/engagements/{eid}/evidence-specialists", headers=self.headers).json()["items"]
            self.assertEqual(records[0]["role"], "web_api")
            self.assertEqual(records[0]["execution"], "evidence_review_only")

    def test_local_monitoring_whitebox_uses_recorded_evidence(self):
        from chat_orchestrator import SecuritySlots
        from config import MODELS
        slots = SecuritySlots(tool="monitoring-local", target="127.0.0.1", environment="lab", assessment_mode="whitebox")
        result = {"tool":"monitoring-local", "target":"127.0.0.1", "services":[]}
        output = {"summary":"Snapshot selesai", "observations":["Data sintetis"], "limitations":["Fixture"], "recommendations":[]}
        with patch("main.classify", new=AsyncMock(return_value="security")), \
             patch("main.security_slots", new=AsyncMock(return_value=slots)), \
             patch("local_monitoring.snapshot", new=AsyncMock(return_value=result)) as monitoring, \
             patch("deep_analysis.installed_models", new=AsyncMock(return_value=[{"name":"security-test", "digest":"synthetic"}])), \
             patch("deep_analysis.runtime.chat", new=AsyncMock(return_value={"content":json.dumps(output),"tool_calls":[]})), \
             patch.dict(MODELS, {"security":"security-test"}):
            response = self.client.post("/api/chat", headers=self.headers, json={"prompt":"Monitoring lokal WhiteBox lab",
                "session_id":"monitor-test", "project_id":"89de83d0-8729-4b0a-b21d-9fcafc444095", "unified":True})
            action = next(e["action"] for e in self.events(response) if e["type"] == "action_proposal")
            monitoring.assert_not_awaited()
            response = self.client.post("/api/chat/actions/"+action["id"]+"/confirm", headers=self.headers,
                json={"session_id":"monitor-test", "approve":True})
            events = self.events(response)
            self.assertEqual(events[-1]["type"], "done", events)
            self.assertIn("Snapshot selesai", next(e["result"] for e in events if e["type"] == "result"))
            monitoring.assert_awaited_once()

    def test_greybox_two_sessions_are_confirmed_ephemeral_and_bound(self):
        from chat_orchestrator import SecuritySlots
        from config import MODELS
        def token(subject):
            payload = base64.urlsafe_b64encode(json.dumps({"sub": subject, "aud": "fixture"}).encode()).decode().rstrip('=')
            return "e30." + payload + ".signature"
        tokens = [token("account-a"), token("account-b")]
        slots = SecuritySlots(tool="auth-two-session", target="https://example.test/api", environment="staging",
                              assessment_mode="greybox", account_refs=["qa-a", "qa-b"])
        observed = [{"http_status":401,"redirect_observed":False}, {"http_status":200,"redirect_observed":False},
                    {"http_status":403,"redirect_observed":False}]
        output = {"summary":"Analisis selesai", "observations":["Status diamati"], "limitations":["Fixture"], "recommendations":[]}
        with patch("main.classify", new=AsyncMock(return_value="security")), \
             patch("main.security_slots", new=AsyncMock(return_value=slots)), \
             patch("web_checks.probe", new=AsyncMock(side_effect=observed)) as probe, \
             patch("deep_analysis.installed_models", new=AsyncMock(return_value=[{"name":"security-test", "digest":"synthetic"}])), \
             patch("deep_analysis.runtime.chat", new=AsyncMock(return_value={"content":json.dumps(output), "tool_calls":[]})), \
             patch.dict(MODELS, {"security":"security-test"}):
            response = self.client.post("/api/chat", headers=self.headers, json={"prompt":"Bandingkan dua sesi GreyBox",
                "session_id":"auth-test", "project_id":"89de83d0-8729-4b0a-b21d-9fcafc444095", "unified":True})
            action = next(e["action"] for e in self.events(response) if e["type"] == "action_proposal")
            self.assertEqual(action["account_refs"], ["qa-a", "qa-b"])
            probe.assert_not_awaited()
            path = "/api/chat/actions/" + action["id"] + "/confirm"
            bad = self.client.post(path, headers=self.headers, json={"session_id":"auth-test", "approve":True, "session_tokens":[tokens[0],tokens[0]]})
            self.assertEqual(bad.status_code, 422)
            self.assertNotIn(tokens[0], bad.text)
            probe.assert_not_awaited()
            response = self.client.post(path, headers=self.headers, json={"session_id":"auth-test", "approve":True, "session_tokens":tokens})
            events = self.events(response)
            self.assertEqual(events[-1]["type"], "done", events)
            self.assertEqual(probe.await_count, 3)
            self.assertEqual([call.kwargs['bearer'] for call in probe.await_args_list], [None, *tokens])
            for secret in tokens:
                self.assertNotIn(secret, response.text)
            self.assertFalse(self.client.app.state.jobs.sessions.entries)
            for path in (self.client.app.state.store.path, self.client.app.state.engagements.path):
                raw = path.read_bytes()
                for secret in tokens:
                    self.assertNotIn(secret.encode(), raw)

    def test_document_followup_retains_source_and_session_scope(self):
        with patch("services.runtime.chat", new=AsyncMock(return_value={"content": "ORBIT"})):
            upload = self.upload_document("qa.txt", b"Proyek: ORBIT.\nGudang: CENDANA-58.", "Nama proyek?", "session-a")
        events = self.events(upload)
        attachment = next(e["attachment"] for e in events if e["type"] == "attachment")
        async def chunks(model, messages, **kwargs):
            self.assertIn("CENDANA-58", messages[-1]["content"])
            yield {"message": {"content": "CENDANA-58"}}
            yield {"done": True}
        with patch("main.runtime.chunks", new=chunks):
            followup = self.client.post("/api/chat", headers=self.headers, json={"prompt": "Gudang?", "session_id": "session-a", "attachment_ids": [attachment["id"]]})
        self.assertIn("CENDANA-58", followup.text)
        followup_events = self.events(followup)
        self.assertEqual(followup_events[-1]["type"], "done")
        self.assertEqual("".join(e["token"] for e in followup_events if e["type"] == "token"), "CENDANA-58")
        invalid = self.client.post("/api/chat", headers=self.headers, json={"prompt": "Gudang?", "session_id": "other", "attachment_ids": [attachment["id"]]})
        self.assertEqual(invalid.status_code, 400)

    def test_chat_streams_reasoning_separately_from_answer(self):
        async def chunks(model, messages, **kwargs):
            self.assertTrue(kwargs.get("think"))
            yield {"status": "running", "model": model}
            yield {"message": {"thinking": "native-reasoning "}}
            yield {"message": {"content": "<think>tagged-reasoning</think>Jawaban "}}
            yield {"message": {"content": "akhir"}}
            yield {"done": True, "done_reason": "stop", "eval_count": 4, "eval_duration": 2_000_000_000}
        with patch("main.runtime.chunks", new=chunks):
            events = self.events(self.client.post("/api/chat", headers=self.headers, json={"prompt": "test"}))
        tokens = "".join(e["token"] for e in events if e["type"] == "token")
        thinking = "".join(e["token"] for e in events if e["type"] == "thinking")
        self.assertEqual(tokens, "Jawaban akhir")
        self.assertEqual(thinking, "native-reasoning tagged-reasoning")
        self.assertEqual(next(e for e in events if e["type"] == "result")["result"], "Jawaban akhir")
        steps = [e["step"] for e in events if e["type"] == "status"]
        self.assertLess(steps.index("thinking"), steps.index("writing"))
        self.assertIn("2,0 token/dtk", [e for e in events if e["type"] == "status"][-1]["detail"])

    def test_exhausted_reasoning_budget_answers_without_thinking(self):
        calls = []
        async def chunks(model, messages, **kwargs):
            calls.append(kwargs.get("think"))
            if kwargs.get("think"):
                yield {"message": {"thinking": "panjang sekali"}}
                yield {"done": True, "done_reason": "length"}
            else:
                yield {"message": {"content": "Jawaban langsung"}}
                yield {"done": True, "done_reason": "stop"}
        with patch("main.runtime.chunks", new=chunks):
            events = self.events(self.client.post("/api/chat", headers=self.headers, json={"prompt": "test"}))
        self.assertEqual(calls, [True, False])
        self.assertIn("fallback", [e.get("step") for e in events])
        self.assertEqual(next(e for e in events if e["type"] == "result")["result"], "Jawaban langsung")
        self.assertEqual(events[-1]["type"], "done")

    def test_stream_model_failure_is_typed_error(self):
        async def chunks(*args, **kwargs):
            raise TimeoutError()
            yield
        with patch("main.runtime.chunks", new=chunks):
            response = self.client.post("/api/chat", headers=self.headers, json={"prompt": "test"})
        self.assertEqual(self.events(response)[-1]["type"], "error")

    def test_chat_web_stream_includes_cited_sources_and_images(self):
        async def chunks(model, messages, **kwargs):
            self.assertIn('https://example.com/story', messages[-1]['content'])
            yield {'message': {'content': 'Berikut hasil [1].'}}
            yield {'done': True}
        web = {'messages': [{'role': 'system', 'content': 'web'},
                            {'role': 'user', 'content': 'https://example.com/story'}],
               'sources': [{'kind': 'web', 'label': '[1]', 'title': 'Story',
                            'url': 'https://example.com/story', 'text': 'Cuplikan'}],
               'images': [{'url': 'https://example.com/image.png', 'alt': 'Foto',
                           'source_url': 'https://example.com/story'}], 'coverage': None}
        with patch('main.web_context', new=AsyncMock(return_value=web)), patch('main.classify', new=AsyncMock(return_value='web')):
            with patch('main.runtime.chunks', new=chunks):
                response = self.client.post('/api/chat', headers=self.headers,
                    json={'prompt': 'Cari gambar', 'web_mode': 'on', 'unified':True, 'session_id':'web-citations'})
                action = next(item['action'] for item in self.events(response) if item['type']=='action_proposal')
                response = self.client.post('/api/chat/actions/'+action['id']+'/confirm', headers=self.headers,
                    json={'session_id':'web-citations','approve':True})
        events = self.events(response)
        result = next(item for item in events if item['type'] == 'result')
        self.assertTrue(result['images'][0]['ticket'])
        self.assertEqual(result['images'][0]['alt'], 'Foto')
        self.assertIn('[1](https://example.com/story)', result['result'])

    def test_dispatch_vision_calls_image_pipeline(self):
        with patch("main.vision_result", new=AsyncMock(return_value={"result": "vision seen"})) as handler:
            response = self.client.post("/api/agent/dispatch", headers=self.headers, data={"prompt": "describe"}, files={"file": ("x.png", b"test", "image/png")})
        self.assertEqual(response.status_code, 423)
        handler.assert_not_awaited()

    def test_proposal_session_and_replay(self):
        proposal = self.client.app.state.store.propose("session-p", tools.proposal_payload("new-proposal-test.txt", "safe test"))
        action = self.client.app.state.store.propose_chat_action('session-p', {'intent':'coding'})
        self.client.app.state.store.decide_chat_action(action['id'], 'session-p', True)
        self.client.app.state.store.authorize_code_proposals('session-p', action['id'], [proposal['id']])
        path = "/api/chat/code-proposals/"+proposal["id"]+"/confirm"
        self.assertEqual(self.client.post(path, headers=self.headers, json={"session_id":"wrong", "approve":False}).status_code, 400)
        self.assertEqual(self.client.post(path, headers=self.headers, json={"session_id":"session-p", "approve":False}).status_code, 200)
        self.assertEqual(self.client.post(path, headers=self.headers, json={"session_id":"session-p", "approve":True}).status_code, 400)


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_queue_cancellation_releases_slot(self):
        runtime = ModelRuntime()
        async with runtime.slot():
            async def pending():
                async with runtime.slot():
                    pass
            task = asyncio.create_task(pending())
            await asyncio.sleep(0)
            self.assertEqual(runtime.waiting, 1)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            self.assertEqual(runtime.waiting, 0)
        async with runtime.slot():
            self.assertEqual(runtime.active, 1)
        self.assertEqual(runtime.active, 0)

    async def test_agent_keeps_request_and_tool_name(self):
        import agent
        calls = []
        async def chat(model, messages, **kwargs):
            calls.append(list(messages))
            if len(calls) == 1:
                return {"role":"assistant", "content":"", "tool_calls":[{"function":{"name":"list_dir", "arguments":{"path":"."}}}]}
            return {"role":"assistant", "content":"Done", "tool_calls":[]}
        with patch("agent.runtime.chat", new=chat):
            result = await agent.execute_agent_pipeline("Daftar file workspace", store=Store(), session_id="a")
        self.assertEqual(result["status"], "success")
        self.assertEqual(calls[1][1]["content"], "Daftar file workspace")
        self.assertEqual(calls[1][-1]["tool_name"], "list_dir")


if __name__ == "__main__":
    unittest.main()

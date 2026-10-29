import asyncio
import io
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
from model_runtime import ModelRuntime, bounded_messages, clean_answer
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

    def test_image_dispatch_is_explicit(self):
        self.assertEqual(detect_pipeline_route("x.jpeg", "describe"), "VISION_PIPELINE")
        with self.assertRaises(ValueError):
            detect_pipeline_route("x.exe", "code")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app).__enter__()
        self.headers = {"Authorization": "Bearer " + os.environ["AGENT_API_TOKEN"]}

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def events(self, response):
        return [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:")]

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

    def test_login_cookie_and_hostile_origin(self):
        response = self.client.post("/api/session", json={"token": os.environ["AGENT_API_TOKEN"]})
        self.assertEqual(response.status_code, 200)
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertEqual(self.client.get("/api/metrics").status_code, 200)
        self.assertEqual(self.client.post("/api/chat", headers={"Origin": "https://attacker.example"}, json={"prompt": "x"}).status_code, 403)

    def test_request_size_and_iteration_bounds(self):
        self.assertEqual(self.client.post("/api/chat", headers={**self.headers, "Content-Length": str(MAX_BODY+1)}, content="x").status_code, 413)
        for value in (-1, 0, 999):
            self.assertEqual(self.client.post("/api/agent/run", headers=self.headers, json={"prompt": "x", "max_iterations": value}).status_code, 422)

    def test_vision_followup_error_is_clear(self):
        result = self.client.post("/api/chat", headers=self.headers, json={"prompt": "gambar tadi", "target": "vision"})
        self.assertEqual(result.status_code, 400)
        self.assertIn("Unggah gambar", result.json()["detail"])

    def test_document_followup_retains_source_and_session_scope(self):
        with patch("services.runtime.chat", new=AsyncMock(return_value={"content": "ORBIT"})):
            upload = self.client.post("/api/document/analyze-stream", headers=self.headers,
                data={"prompt": "Nama proyek?", "session_id": "session-a"},
                files={"file": ("qa.txt", b"Proyek: ORBIT.\nGudang: CENDANA-58.", "text/plain")})
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
        self.assertNotIn("token", [item["type"] for item in followup_events])
        invalid = self.client.post("/api/chat", headers=self.headers, json={"prompt": "Gudang?", "session_id": "other", "attachment_ids": [attachment["id"]]})
        self.assertEqual(invalid.status_code, 400)

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
        with patch('main.web_context', new=AsyncMock(return_value=web)):
            with patch('main.runtime.chunks', new=chunks):
                response = self.client.post('/api/chat', headers=self.headers,
                    json={'prompt': 'Cari gambar', 'web_mode': 'on'})
        events = self.events(response)
        sources = next(item for item in events if item['type'] == 'sources')
        result = next(item for item in events if item['type'] == 'result')
        self.assertEqual(len(sources['images']), 1)
        self.assertEqual(result['images'][0]['alt'], 'Foto')
        self.assertIn('[1](https://example.com/story)', result['result'])

    def test_dispatch_vision_calls_image_pipeline(self):
        with patch("main.vision_result", new=AsyncMock(return_value={"result": "vision seen"})) as handler:
            response = self.client.post("/api/agent/dispatch", headers=self.headers, data={"prompt": "describe"}, files={"file": ("x.png", b"test", "image/png")})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"], "vision seen")
        handler.assert_awaited_once()

    def test_proposal_session_and_replay(self):
        proposal = self.client.app.state.store.propose("session-p", tools.proposal_payload("new-proposal-test.txt", "safe test"))
        path = "/api/agent/proposals/"+proposal["id"]
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

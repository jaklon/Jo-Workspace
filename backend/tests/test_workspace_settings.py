import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("AGENT_DATA_DIR", tempfile.mkdtemp(prefix="agent-settings-tests-"))
os.environ.setdefault("AGENT_API_TOKEN", "synthetic-test-key-not-a-production-secret")
from fastapi.testclient import TestClient
from pydantic import ValidationError
import config
import preferences
from main import app
from model_runtime import ModelRuntime, runtime
from usage import UsageLedger


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="workspace-settings-")
        self.override = patch.object(config, "DATA_DIR", Path(self.directory.name))
        self.override.start()
        self.original = preferences.current.model_copy(deep=True)
        self.client = TestClient(app).__enter__()
        self.headers = {"Authorization": "Bearer " + os.environ["AGENT_API_TOKEN"]}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        preferences.apply_settings(self.original)
        self.override.stop()
        self.directory.cleanup()

    def test_settings_and_usage_require_auth(self):
        for path in ("/api/settings", "/api/usage"):
            self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.delete("/api/usage").status_code, 401)
        self.assertEqual(self.client.post("/api/settings", json={}).status_code, 401)

    def test_settings_persist_and_update_runtime_config(self):
        value = self.client.get("/api/settings", headers=self.headers).json()["settings"]
        value["models"]["reasoning"] = "local-test:latest"
        value["inference"].update(context_tokens=8192, output_tokens=1024, temperature=0.7)
        self.assertEqual(self.client.post("/api/settings", headers=self.headers, json=value).status_code, 200)
        self.assertEqual(config.MODELS["reasoning"], "local-test:latest")
        self.assertEqual(config.CONTEXT_TOKENS, 8192)
        preferences.apply_settings(self.original)
        preferences.load_settings()
        self.assertEqual(preferences.current.inference.temperature, 0.7)
        self.assertEqual(config.OUTPUT_TOKENS, 1024)

    def test_settings_reject_invalid_budget_and_unknown_fields(self):
        value = self.original.model_dump()
        value["inference"]["output_tokens"] = value["inference"]["context_tokens"]
        self.assertEqual(self.client.post("/api/settings", headers=self.headers, json=value).status_code, 422)
        value = self.original.model_dump()
        value["ollama_url"] = "https://untrusted.example"
        self.assertEqual(self.client.post("/api/settings", headers=self.headers, json=value).status_code, 422)
        for temperature in (-1, 3, float('inf')):
            with self.assertRaises(ValidationError):
                preferences.InferenceSettings(temperature=temperature)

    def test_active_inference_blocks_settings_and_usage_reset(self):
        with patch.object(runtime, "active", 1):
            self.assertEqual(self.client.post("/api/settings", headers=self.headers, json=self.original.model_dump()).status_code, 409)
            self.assertEqual(self.client.delete("/api/usage", headers=self.headers).status_code, 409)

    def test_usage_api_uses_durable_ledger_and_clear(self):
        ledger = UsageLedger(Path(self.directory.name) / "usage.json")
        ledger.record("test", "completed", 1.5, {"prompt_eval_count": 21, "eval_count": 8})
        with patch.object(runtime, "usage", ledger):
            value = self.client.get("/api/usage", headers=self.headers).json()
            self.assertEqual(value["rows"][0]["input_tokens"], 21)
            self.assertEqual(value["timezone"], "UTC")
            self.assertEqual(self.client.delete("/api/usage", headers=self.headers).status_code, 200)
        self.assertEqual(UsageLedger(ledger.path).rows, [])


class LedgerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="usage-ledger-")
        self.ledger = UsageLedger(Path(self.directory.name) / "usage.json")
        self.runtime = ModelRuntime()
        self.runtime.usage = self.ledger

    async def asyncTearDown(self):
        self.directory.cleanup()

    async def test_completion_records_exact_tokens_once(self):
        async def source(*args, **kwargs):
            yield {"status": "running"}
            yield {"done": True, "prompt_eval_count": 54, "eval_count": 13}
        with patch.object(self.runtime, "_chunks", source):
            async for _ in self.runtime.chunks("test", []):
                pass
        persisted = UsageLedger(self.ledger.path).rows[0]
        self.assertEqual((persisted["input_tokens"], persisted["output_tokens"], persisted["completed"]), (54, 13, 1))
        self.assertNotIn("messages", persisted)

    async def test_failure_records_without_inventing_tokens(self):
        async def source(*args, **kwargs):
            yield {"status": "running"}
            raise ValueError("model offline")
        with patch.object(self.runtime, "_chunks", source):
            with self.assertRaisesRegex(ValueError, "offline"):
                async for _ in self.runtime.chunks("test", []):
                    pass
        self.assertEqual(self.ledger.rows[0]["failed"], 1)
        self.assertEqual(self.ledger.rows[0]["measured"], 0)
        self.assertEqual(self.runtime.failed, 1)

    async def test_closing_stream_releases_gpu_and_records_cancel(self):
        async def source(*args, **kwargs):
            async with self.runtime.slot():
                yield {"status": "running"}
                await asyncio.sleep(60)
        with patch.object(self.runtime, "_chunks", source):
            stream = self.runtime.chunks("test", [])
            await anext(stream)
            self.assertEqual(self.runtime.active, 1)
            await stream.aclose()
        self.assertEqual(self.runtime.active, 0)
        self.assertEqual(self.ledger.rows[0]["cancelled"], 1)

    async def test_prunes_old_rows(self):
        self.ledger.rows = [{"date": "2000-01-01", "model": "old"}]
        self.ledger.record("new", "failed", 1)
        self.assertEqual(len(self.ledger.rows), 1)
        self.assertEqual(self.ledger.rows[0]["model"], "new")

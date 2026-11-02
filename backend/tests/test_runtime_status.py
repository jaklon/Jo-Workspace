import asyncio
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx

import runtime_status
from runtime_status import diagnose, memory_estimate, model_rows, recommendations

GB = 1024 ** 3
SETTINGS = SimpleNamespace(context_tokens=4096, thinking_tokens=1536, model_timeout=600)
MODELS = {"reasoning": "qwen-9b-reasoning", "vision": "minicpm-v:latest"}
GPU6 = {"available": True, "name": "RTX 3060 Laptop", "vram_total_mb": 6144}


def runtime(**values):
    base = dict(last_metrics={}, waiting=0, active=0, completed=0, failed=0, current=None, last_failure=None)
    return SimpleNamespace(**{**base, **values})


class RuntimeStatusTests(unittest.TestCase):
    def snapshot(self, loaded_vram=None):
        installed = [{"name": "qwen-9b-reasoning:latest", "size": int(5.7 * GB)}]
        loaded = [] if loaded_vram is None else [{"name": "qwen-9b-reasoning:latest", "size": 6 * GB, "size_vram": loaded_vram}]
        return {"reachable": True, "version": "0.35.0", "installed": installed, "loaded": loaded, "error": None}

    def test_rows_report_partial_gpu_and_missing_models(self):
        rows = model_rows(self.snapshot(int(4.2 * GB)), MODELS, GPU6)
        reasoning, vision = rows
        self.assertEqual(reasoning["gpu_percent"], 70)
        self.assertEqual(reasoning["fit"], "partial")
        self.assertFalse(vision["installed"])
        issues = diagnose(self.snapshot(int(4.2 * GB)), rows, runtime(), GPU6, SETTINGS)
        text = " ".join(i["reason"] + i["action"] for i in issues)
        self.assertIn("70% di GPU", text)
        self.assertIn("ollama pull minicpm-v:latest", text)
        self.assertIn("Anggaran penalaran 1536", text)

    def test_unreachable_ollama_gives_recovery_step_only(self):
        snapshot = {"reachable": False, "installed": [], "loaded": [], "error": "Ollama tidak berjalan."}
        issues = diagnose(snapshot, model_rows(snapshot, MODELS, GPU6), runtime(), GPU6, SETTINGS)
        self.assertEqual(len(issues), 1)
        self.assertIn("ollama serve", issues[0]["action"])

    def test_slow_metrics_queue_and_recent_failure_are_explained(self):
        busy = runtime(last_metrics={"tokens_per_second": 4.1, "load_seconds": 13, "done_reason": "length"}, waiting=2,
                       last_failure={"type": "TimeoutError", "detail": "", "at": time.time()})
        reasons = " ".join(i["reason"] for i in diagnose(self.snapshot(), [], busy, GPU6, SETTINGS))
        for expected in ("4.1 token/detik", "cold start", "terpotong", "2 permintaan menunggu", "batas waktu"):
            self.assertIn(expected, reasons)

    def test_recommendation_matches_hardware(self):
        small = recommendations(GPU6, [], SETTINGS)
        self.assertEqual(small["context_tokens"], 4096)
        self.assertEqual(small["differs"], ["thinking_tokens"])
        self.assertEqual(recommendations({"available": False}, [], SETTINGS)["thinking_tokens"], 512)
        self.assertEqual(recommendations({"available": True, "vram_total_mb": 24576}, [], SETTINGS)["context_tokens"], 16384)
        self.assertEqual(memory_estimate(5 * GB, 4096, 0)["fit"], "cpu")
        self.assertEqual(memory_estimate(2 * GB, 4096, 6144)["fit"], "gpu")

    def test_snapshot_explains_connection_failure(self):
        async def refuse(*args, **kwargs):
            raise httpx.ConnectError("refused")
        with patch.object(httpx.AsyncClient, "get", new=refuse):
            snapshot = asyncio.run(runtime_status.ollama_snapshot("http://127.0.0.1:11434"))
        self.assertFalse(snapshot["reachable"])
        self.assertIn("tidak berjalan", snapshot["error"])


if __name__ == "__main__":
    unittest.main()

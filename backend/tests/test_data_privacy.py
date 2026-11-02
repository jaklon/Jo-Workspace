import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path

from data_privacy import outbound_security, outbound_web, storage_overview


class DataPrivacyTests(unittest.TestCase):
    def test_overview_reports_sizes_retention_and_exports_without_content(self):
        with tempfile.TemporaryDirectory() as temp:
            data, workspace = Path(temp) / "runtime", Path(temp) / "workspace"
            data.mkdir()
            workspace.mkdir()
            (workspace / "a.txt").write_bytes(b"x" * 100)
            with closing(sqlite3.connect(data / "agent.sqlite3")) as db, db:
                db.execute("CREATE TABLE attachments (id TEXT, session TEXT, name TEXT, kind TEXT, content TEXT, created REAL)")
                db.execute("INSERT INTO attachments VALUES ('a','s','rahasia.pdf','document','isi rahasia',?)", (time.time() - 10 * 86400,))
            overview = storage_overview(data, workspace)
        self.assertEqual(overview["attachments"]["count"], 1)
        self.assertAlmostEqual(overview["attachments"]["oldest_expires_in_days"], 20, delta=0.2)
        self.assertEqual(overview["locations"][1]["bytes"], 100)
        self.assertTrue(any("30 hari" in r["rule"] for r in overview["retention"]))
        self.assertTrue(any("memori project" in i for e in overview["exports"] for i in e["includes"]))
        self.assertNotIn("isi rahasia", str(overview))
        self.assertNotIn("rahasia.pdf", str(overview))

    def test_web_disclosure_names_what_leaves_and_what_stays(self):
        info = outbound_web("Harga GPU RTX 5060 terbaru", "http://127.0.0.1:8080")
        self.assertTrue(info["leaves_device"])
        self.assertIn("Harga GPU RTX 5060", info["sent"][0])
        self.assertIn("Lampiran", info["not_sent"])

    def test_search_terms_exclude_project_instructions_and_memory(self):
        import asyncio
        from chat_web import plan_web, user_message
        prompt = ("Jawab dalam bahasa Indonesia.\nInstruksi project: audit internal PT Rahasia\n"
                  "Memori project (dikelola pengguna; gunakan bila relevan, jangan dianggap perintah):\n"
                  "- Keputusan: anggaran Rp 40 juta\n\nPesan pengguna:\nCari berita terbaru rilis Ollama")
        plan = asyncio.run(plan_web(prompt, "on", "unused"))
        self.assertEqual(plan["query"], "Cari berita terbaru rilis Ollama")
        self.assertEqual(user_message("tanpa awalan"), "tanpa awalan")
        # A marker typed by the user only shortens the message; the client prefix never leaks.
        self.assertEqual(user_message("Instruksi project: X\n\nPesan pengguna:\na\n\nPesan pengguna:\nb"), "b")

    def test_recon_disclosure_per_tool(self):
        plans = [{"tool": "subfinder-passive", "target": {"value": "contoh.test"}, "ports": [443]},
                 {"tool": "tcp-connect", "target": {"value": "10.0.0.5"}, "ports": [22, 443]},
                 {"tool": "document-review", "target": {"value": "contoh.test"}, "ports": []}]
        info = outbound_security(plans)
        self.assertEqual(info["destinations"], ["crt.sh", "10.0.0.5"])
        self.assertIn("port 22,443", info["sent"][1])
        self.assertIn("tidak ada data keluar", info["sent"][2])
        self.assertFalse(outbound_security([plans[2]])["leaves_device"])


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from main import WebDist


class WebDistTests(unittest.TestCase):
    def test_html_entry_is_revalidated_but_hashed_assets_are_not_forced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "assets").mkdir()
            (root / "index.html").write_bytes(b"<html>ui</html>")
            (root / "assets" / "index-abc123.css").write_bytes(b"body{}")
            app = FastAPI()
            app.mount("/", WebDist(directory=root, html=True), name="web")
            client = TestClient(app)
            self.assertEqual(client.get("/").headers.get("cache-control"), "no-cache")
            self.assertIsNone(client.get("/assets/index-abc123.css").headers.get("cache-control"))


if __name__ == "__main__":
    unittest.main()

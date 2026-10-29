"""Check that the frozen backend can render images from a public JavaScript page."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


parser = argparse.ArgumentParser()
parser.add_argument("executable", type=Path)
parser.add_argument("--url", default="https://hemoforge.vercel.app/")
args = parser.parse_args()
token = secrets.token_urlsafe(32)

with tempfile.TemporaryDirectory(prefix="jo-browser-smoke-") as directory:
    root = Path(directory)
    environment = {
        **os.environ,
        "AGENT_DATA_DIR": str(root / "runtime"),
        "AGENT_WORKSPACE": str(root / "workspace"),
        "AGENT_API_TOKEN": token,
        "PATH": str(Path(os.environ["SystemRoot"]) / "System32"),
    }
    with (root / "backend.log").open("w+") as log:
        process = subprocess.Popen(
            [str(args.executable.resolve()), "--port", "18012", "--parent-pid", str(os.getpid())],
            cwd=root, env=environment, stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            endpoint = "http://127.0.0.1:18012"
            deadline = time.monotonic() + 60
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    with urlopen(Request(endpoint + "/api/metrics", headers={"Authorization": "Bearer " + token}), timeout=2):
                        break
                except URLError:
                    if time.monotonic() > deadline:
                        raise TimeoutError("Frozen backend did not start")
                    time.sleep(0.25)
            payload = json.dumps({"url": args.url}).encode()
            request = Request(endpoint + "/api/search/extract-images", data=payload,
                              headers={"Authorization": "Bearer " + token,
                                       "Content-Type": "application/json"})
            with urlopen(request, timeout=45) as response:
                result = json.load(response)
            assert result["rendered"] is True, result
            assert result["images"], result
            print(f"Frozen Playwright rendering passed: {len(result['images'])} image candidates from {args.url}")
        finally:
            process.terminate()
            process.wait(timeout=10)

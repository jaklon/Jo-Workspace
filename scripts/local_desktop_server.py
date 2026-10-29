"""Source runtime used by the free local desktop launcher."""
import argparse
from pathlib import Path
import sys

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "backend"))
    import uvicorn
    from main import app
    from local_desktop import LocalDesktopSessions
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=args.port, access_log=False, timeout_graceful_shutdown=3))
    app.state.local_desktop = LocalDesktopSessions(f"http://127.0.0.1:{args.port}", server)
    server.run()

if __name__ == "__main__":
    run()

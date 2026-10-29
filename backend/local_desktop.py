"""Local browser-app handoff. Never places the API token in a URL."""
import hashlib
import hmac
import secrets
import time
from threading import Lock

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.background import BackgroundTask
from security import session_cookie
from model_runtime import runtime


class LocalDesktopSessions:
    def __init__(self, origin, server=None, clock=None):
        self.clock = clock or time.monotonic
        self.origin = origin
        self.server = server
        self.tickets = {}
        self.lock = Lock()

    def issue(self, api_token):
        nonce = secrets.token_urlsafe(32)
        with self.lock:
            now = self.clock()
            self.tickets = {k: v for k, v in self.tickets.items() if v[0] > now}
            if len(self.tickets) >= 8:
                raise HTTPException(429, "Terlalu banyak permintaan sesi desktop.")
            self.tickets[hashlib.sha256(nonce.encode()).hexdigest()] = (now + 45, session_cookie(api_token))
        return "/_desktop/connect/" + nonce

    def consume(self, nonce):
        digest = hashlib.sha256(nonce.encode()).hexdigest()
        with self.lock:
            entry = self.tickets.pop(digest, None)
        if not entry or entry[0] <= self.clock():
            raise HTTPException(410, "Tautan sesi sudah dipakai atau kedaluwarsa. Buka Jo Workspace dari Desktop lagi.")
        return entry[1]


router = APIRouter()


def local_session(request):
    state = getattr(request.app.state, "local_desktop", None)
    if state is None:
        raise HTTPException(404, "Mode desktop lokal tidak aktif.")
    if not request.client or request.client.host != "127.0.0.1" or str(request.base_url).rstrip("/") != state.origin:
        raise HTTPException(403, "Sesi desktop hanya tersedia dari alamat loopback yang ditetapkan.")
    origin = request.headers.get("origin")
    if origin and origin != state.origin:
        raise HTTPException(403, "Origin sesi desktop tidak diizinkan.")
    return state


def require_bearer(request):
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:], request.state.api_token):
        raise HTTPException(403, "Peluncur desktop memerlukan bearer token lokal.")


@router.post("/api/desktop/session-ticket")
async def issue_ticket(request: Request):
    state = local_session(request)
    require_bearer(request)
    return {"path": state.issue(request.state.api_token), "expires_in_seconds": 45, "execution_enabled": False}


@router.get("/_desktop/connect/{nonce}")
async def connect(nonce: str, request: Request):
    state = local_session(request)
    response = RedirectResponse("/", status_code=303, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
    response.set_cookie("agent_session", state.consume(nonce), httponly=True, secure=False, samesite="strict", max_age=43200, path="/")
    return response


@router.post("/api/desktop/stop")
async def stop(request: Request):
    state = local_session(request)
    require_bearer(request)
    if state.server is None:
        raise HTTPException(409, "Backend ini tidak dikelola peluncur desktop.")
    if runtime.active or runtime.waiting:
        raise HTTPException(409, "Masih ada pekerjaan berjalan. Tunggu sebelum uninstall.")
    def shutdown():
        state.server.should_exit = True
    from fastapi.responses import JSONResponse
    return JSONResponse({"status": "stopping"}, background=BackgroundTask(shutdown))

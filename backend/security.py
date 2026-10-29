import hashlib
import hmac
import os
import secrets
import time
from http.cookies import SimpleCookie
from starlette.responses import JSONResponse
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from config import DATA_DIR, MAX_BODY, ALLOWED_ORIGINS


class SafeValidationRoute(APIRoute):
    """Schema errors must not echo pasted credentials or evidence content."""
    def get_route_handler(self):
        handler=super().get_route_handler()
        async def safe(request):
            try:return await handler(request)
            except RequestValidationError as exc:
                raise HTTPException(422,[{'loc':e['loc'],'msg':'Nilai tidak valid atau persyaratan metadata belum lengkap.','type':e['type']} for e in exc.errors()]) from None
        return safe


def load_token():
    configured = os.getenv("AGENT_API_TOKEN")
    if configured:
        if len(configured) < 24:
            raise ValueError("AGENT_API_TOKEN minimal 24 karakter.")
        return configured
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "api-token"
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(secrets.token_urlsafe(32))
        if os.name != "nt":
            path.chmod(0o600)
    except FileExistsError:
        pass
    return path.read_text(encoding="utf-8").strip()


def session_cookie(token):
    expires = str(int(time.time()) + 12 * 3600)
    signature = hmac.new(token.encode(), expires.encode(), hashlib.sha256).hexdigest()
    return expires + "." + signature


def valid_cookie(value, token):
    try:
        expires, signature = value.split(".", 1)
        expected = hmac.new(token.encode(), expires.encode(), hashlib.sha256).hexdigest()
        return int(expires) > time.time() and hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False


class ApiBoundary:
    """Authenticate and bound the body before multipart parsing; no wildcard trust."""
    def __init__(self, app):
        self.app = app
        self.token = None
        self.login_attempts = []

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api/") or scope["method"] == "OPTIONS":
            return await self.app(scope, receive, send)
        if self.token is None:
            self.token = load_token()
        headers = dict(scope["headers"])
        async def deny(code, message):
            await JSONResponse({"detail": message}, status_code=code)(scope, receive, send)
        origin = headers.get(b"origin", b"").decode()
        own_origin = scope["scheme"] + "://" + headers.get(b"host", b"").decode()
        if origin and origin != own_origin and origin not in ALLOWED_ORIGINS:
            return await deny(403, "Origin tidak diizinkan.")
        bearer = headers.get(b"authorization", b"").decode()
        authenticated = bearer.startswith("Bearer ") and hmac.compare_digest(bearer[7:], self.token)
        cookies = SimpleCookie()
        try:
            cookies.load(headers.get(b"cookie", b"").decode())
            authenticated = authenticated or valid_cookie(cookies["agent_session"].value, self.token)
        except (KeyError, ValueError):
            pass
        if scope["path"] == "/api/session" and scope["method"] == "POST":
            now = time.monotonic()
            self.login_attempts = [t for t in self.login_attempts if t > now - 60]
            if len(self.login_attempts) >= 10:
                return await deny(429, "Terlalu banyak percobaan login. Tunggu satu menit.")
            if not authenticated:
                self.login_attempts.append(now)
        elif not authenticated:
            return await deny(401, "Masukkan token akses Jo Workspace untuk terhubung.")
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await deny(400, "Content-Length tidak valid.")
        if length > MAX_BODY:
            return await deny(413, "Permintaan terlalu besar. Batas upload 8 MB.")
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY:
                return await deny(413, "Permintaan terlalu besar. Batas upload 8 MB.")
            if not message.get("more_body"):
                break
        sent = False
        async def bounded_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        scope.setdefault("state", {})["api_token"] = self.token
        scope["state"]["authenticated"] = authenticated
        return await self.app(scope, bounded_receive, send)

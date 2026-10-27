"""웹 UI 접근 제어.

- AUTOCVE_ADMIN_PASSWORD가 있으면 HTTP Basic 인증(사용자 이름 admin)을 요구한다.
- 브라우저가 Basic 인증 정보를 자동으로 보내므로, 상태를 바꾸는 요청은 Origin/Referer가
  같은 호스트일 때만 받는다 (CSRF 방지).
"""

import base64
import binascii
import secrets
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

ADMIN_USER = "admin"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_PATHS = {"/healthz"}


def _basic_credentials(request: Request) -> tuple[str, str] | None:
    header = request.headers.get("authorization", "")
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        user, _, password = base64.b64decode(encoded).decode().partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return user, password


def _same_origin(request: Request) -> bool:
    source = request.headers.get("origin") or request.headers.get("referer")
    if source is None:
        # 브라우저가 아닌 클라이언트(curl 등)는 Origin을 보내지 않는다.
        return True
    return urlsplit(source).netloc == request.headers.get("host")


class AccessControlMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, admin_password: str | None):
        super().__init__(app)
        self._password = admin_password

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        if self._password:
            creds = _basic_credentials(request)
            if (
                creds is None
                or not secrets.compare_digest(creds[0].encode(), ADMIN_USER.encode())
                or not secrets.compare_digest(creds[1].encode(), self._password.encode())
            ):
                return PlainTextResponse(
                    "인증이 필요합니다",
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="AutoCVE", charset="UTF-8"'},
                )
        if request.method not in SAFE_METHODS and not _same_origin(request):
            return PlainTextResponse("다른 출처에서 온 요청은 거부합니다", status_code=403)
        return await call_next(request)

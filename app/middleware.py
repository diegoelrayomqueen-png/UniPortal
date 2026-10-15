"""Middleware de autenticación (rutas protegidas) y de cabeceras de seguridad."""
from __future__ import annotations

import hmac

from fastapi import Request
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware

from app import database
from app.errors import error_response
from app.models import LoginSession, utcnow
from app.services import token_service as ts

# (método, ruta) -> tipo de token exigido
PROTECTED_ROUTES: dict[tuple[str, str], str] = {
    ("POST", "/auth/refresh"): ts.REFRESH,
    ("POST", "/auth/logout"): ts.ACCESS,
    ("GET", "/users/profile"): ts.ACCESS,
    ("PUT", "/users/profile"): ts.ACCESS,
}


class AuthFailure(Exception):
    """Fallo de autenticación con el código HTTP que debe devolverse."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code, self.code, self.message = status_code, code, message


def _bearer_token(request: Request) -> str | None:
    """Extrae el token de 'Authorization: Bearer <token>' (None si falta o es otro esquema)."""
    scheme, _, value = request.headers.get("Authorization", "").partition(" ")
    return value.strip() or None if scheme.lower() == "bearer" else None


def _authenticate(token: str, expected_type: str) -> ts.AuthenticatedToken:
    """Valida el JWT y comprueba en la BD que su sesión sigue activa (bloqueante: va a un hilo)."""
    try:
        payload = ts.decode_token(token)
    except ts.TokenExpired as exc:
        raise AuthFailure(401, exc.code, "El token ha expirado.") from exc
    except ts.TokenError as exc:
        raise AuthFailure(401, exc.code, "Token inválido.") from exc
    if payload["type"] != expected_type:
        raise AuthFailure(403, "wrong_token_type", "Este tipo de token no está permitido en esta ruta.")
    session_id = payload.get("sid")
    if not session_id:
        raise AuthFailure(401, "token_invalid", "Token inválido.")
    with database.SessionLocal() as db:
        session = db.scalar(select(LoginSession).where(LoginSession.session_id == session_id))
        if session is None or str(session.user_id) != payload["sub"]:
            raise AuthFailure(401, "session_revoked", "La sesión fue cerrada o ya no existe.")
        now = utcnow()
        if session.expires_at <= now or session.max_expires_at <= now:
            db.delete(session)
            db.commit()
            raise AuthFailure(401, "session_expired", "La sesión venció. Inicia sesión de nuevo.")
        token_hash = ts.hash_token(token)
        if expected_type == ts.REFRESH and not hmac.compare_digest(session.token, token_hash):
            # Un refresh token ya rotado se volvió a presentar: posible robo -> se revoca la sesión entera.
            db.delete(session)
            db.commit()
            raise AuthFailure(401, "refresh_reuse", "Refresh token ya utilizado. La sesión fue revocada por seguridad.")
        return ts.AuthenticatedToken(user_id=int(payload["sub"]), session_id=session_id,
                                     token_hash=token_hash, token_type=expected_type)


class AuthMiddleware(BaseHTTPMiddleware):
    """Valida el token Bearer en las rutas de PROTECTED_ROUTES y deja el resultado en request.state.auth."""

    async def dispatch(self, request: Request, call_next):
        """Rechaza con 401/403 si el token falta o no es válido; si no, continúa."""
        expected = PROTECTED_ROUTES.get((request.method.upper(), request.url.path.rstrip("/") or "/"))
        if expected is None:
            return await call_next(request)
        headers = {"WWW-Authenticate": "Bearer"}
        token = _bearer_token(request)
        if token is None:
            return error_response(401, "missing_token", "Se requiere autenticación (Authorization: Bearer <token>).", headers)
        try:
            request.state.auth = await run_in_threadpool(_authenticate, token, expected)
        except AuthFailure as failure:
            return error_response(failure.status_code, failure.code, failure.message, headers)
        return await call_next(request)


_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")
_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Añade cabeceras de seguridad. Swagger UI (carga recursos de CDN) queda fuera del CSP."""

    async def dispatch(self, request: Request, call_next):
        """Agrega CSP, anti-sniffing, anti-clickjacking y no-cache en endpoints de la API."""
        response = await call_next(request)
        path = request.url.path
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if not path.startswith(_DOC_PATHS):
            response.headers["Content-Security-Policy"] = _CSP
            response.headers["X-Frame-Options"] = "DENY"
        if path.startswith(("/auth", "/users")):
            response.headers["Cache-Control"] = "no-store"
        return response

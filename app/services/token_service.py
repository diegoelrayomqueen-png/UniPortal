"""Creación/validación de JWT y gestión de sesiones (tabla login_sessions).

Tipos de token (claim `type`):
  access        corta vida (15 min); autoriza peticiones normales.
  refresh       larga vida (7 días, máx. SESSION_MAX_DAYS); solo sirve en POST /auth/refresh y rota en cada uso.
  otp_challenge 15 min; prueba de que la contraseña fue válida; solo sirve en verify-otp / resend-otp.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.config import MAX_OTP_MINUTES, get_settings
from app.models import LoginSession, User, utcnow

ACCESS = "access"
REFRESH = "refresh"
CHALLENGE = "otp_challenge"


class TokenError(Exception):
    """Error base de validación de tokens."""

    code = "token_invalid"
    message = "Token inválido."


class TokenExpired(TokenError):
    """El token venció."""

    code = "token_expired"
    message = "El token ha expirado."


class TokenInvalid(TokenError):
    """Token malformado, con firma incorrecta o sin claims obligatorios."""


class WrongTokenType(TokenError):
    """El token es válido pero no es del tipo que exige la ruta."""

    code = "wrong_token_type"
    message = "Este tipo de token no es válido para esta operación."


@dataclass(frozen=True)
class IssuedTokens:
    """Par de tokens emitido tras un login o una renovación."""

    access_token: str
    refresh_token: str
    expires_in: int
    refresh_expires_in: int
    session_id: str


@dataclass(frozen=True)
class AuthenticatedToken:
    """Resultado de validar un token en el middleware (se guarda en request.state.auth)."""

    user_id: int
    session_id: str
    token_hash: str
    token_type: str


def hash_token(token: str) -> str:
    """SHA-256 hexadecimal de un token (lo que se guarda en la base de datos)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _encode(claims: dict) -> str:
    """Firma los claims como JWT con la clave y el algoritmo configurados."""
    settings = get_settings()
    return jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def _base_claims(user_id: int, token_type: str, expires_at: datetime, now: datetime) -> dict:
    """Claims comunes: sub, type, iat, exp y jti único."""
    return {"sub": str(user_id), "type": token_type, "iat": now, "exp": expires_at, "jti": uuid.uuid4().hex}


def create_access_token(user_id: int, session_id: str, now: datetime | None = None,
                        expires_delta: timedelta | None = None) -> tuple[str, datetime]:
    """Crea un access token. `expires_delta` permite fabricar tokens ya vencidos en pruebas."""
    now = now or utcnow()
    expires_at = now + (expires_delta if expires_delta is not None
                        else timedelta(minutes=get_settings().access_token_expire_minutes))
    claims = _base_claims(user_id, ACCESS, expires_at, now) | {"sid": session_id}
    return _encode(claims), expires_at


def create_refresh_token(user_id: int, session_id: str, expires_at: datetime, now: datetime | None = None) -> str:
    """Crea un refresh token que vence en `expires_at`."""
    now = now or utcnow()
    return _encode(_base_claims(user_id, REFRESH, expires_at, now) | {"sid": session_id})


def create_challenge_token(user_id: int, challenge_id: str) -> tuple[str, int]:
    """Crea el token de desafío OTP. Devuelve (token, segundos de vida)."""
    now = utcnow()
    expires_at = now + timedelta(minutes=MAX_OTP_MINUTES)
    token = _encode(_base_claims(user_id, CHALLENGE, expires_at, now) | {"cid": challenge_id})
    return token, MAX_OTP_MINUTES * 60


def decode_token(token: str, expected_type: str | None = None) -> dict:
    """Valida firma, expiración y claims obligatorios. Lanza TokenError si algo falla."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub", "jti", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpired() from exc
    except jwt.InvalidTokenError as exc:
        raise TokenInvalid() from exc
    if not str(payload["sub"]).isdigit():
        raise TokenInvalid()
    if expected_type is not None and payload["type"] != expected_type:
        raise WrongTokenType()
    return payload


def _issue_for_session(user_id: int, session_id: str, refresh_expires_at: datetime, now: datetime) -> IssuedTokens:
    """Emite el par access + refresh para una sesión existente."""
    access, access_exp = create_access_token(user_id, session_id, now=now)
    refresh = create_refresh_token(user_id, session_id, refresh_expires_at, now=now)
    return IssuedTokens(access, refresh, int((access_exp - now).total_seconds()),
                        int((refresh_expires_at - now).total_seconds()), session_id)


def create_session(db: Session, user: User) -> IssuedTokens:
    """Crea la fila en login_sessions y emite access + refresh token."""
    settings = get_settings()
    now = utcnow()
    session_id = str(uuid.uuid4())
    max_expires = now + timedelta(days=settings.session_max_days)
    refresh_expires = min(now + timedelta(days=settings.refresh_token_expire_days), max_expires)
    tokens = _issue_for_session(user.id, session_id, refresh_expires, now)
    db.add(LoginSession(user_id=user.id, token=hash_token(tokens.refresh_token), expires_at=refresh_expires,
                        created_at=now, session_id=session_id, max_expires_at=max_expires))
    db.commit()
    return tokens


def rotate_session(db: Session, user_id: int, session_id: str, old_token_hash: str) -> IssuedTokens | None:
    """Renueva los tokens de una sesión (rotación del refresh token).

    El UPDATE condicional (token == hash anterior) es atómico: si dos peticiones intentan
    renovar con el mismo refresh token, solo una gana. Devuelve None si perdió.
    """
    now = utcnow()
    session = db.scalar(select(LoginSession).where(LoginSession.session_id == session_id))
    if session is None:
        return None
    new_expires = min(now + timedelta(days=get_settings().refresh_token_expire_days), session.max_expires_at)
    tokens = _issue_for_session(user_id, session_id, new_expires, now)
    result = db.execute(
        update(LoginSession)
        .where(LoginSession.id == session.id, LoginSession.token == old_token_hash)
        .values(token=hash_token(tokens.refresh_token), expires_at=new_expires)
    )
    db.commit()
    return tokens if result.rowcount == 1 else None


def revoke_session(db: Session, session_id: str) -> bool:
    """Revoca una sesión borrando su fila. Devuelve True si existía."""
    result = db.execute(delete(LoginSession).where(LoginSession.session_id == session_id))
    db.commit()
    return result.rowcount > 0


def purge_expired_sessions(db: Session) -> int:
    """Elimina sesiones vencidas (limpieza de mantenimiento)."""
    now = utcnow()
    result = db.execute(delete(LoginSession).where(
        (LoginSession.expires_at <= now) | (LoginSession.max_expires_at <= now)))
    db.commit()
    return result.rowcount

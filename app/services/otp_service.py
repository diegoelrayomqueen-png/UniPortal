"""Generación, almacenamiento y verificación de códigos OTP de 6 dígitos."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import OTPCode, User, utcnow


class OTPError(Exception):
    """Error base de OTP; cada subclase define su código HTTP, código interno y mensaje."""

    status_code = 400
    code = "otp_invalid"
    message = "El código no es válido."
    retry_after: int | None = None

    def __init__(self, message: str | None = None, retry_after: int | None = None):
        super().__init__(message or self.message)
        self.message = message or self.message
        self.retry_after = retry_after


class OTPInvalid(OTPError):
    """Código incorrecto."""

    message = "Código incorrecto."


class OTPExpired(OTPError):
    """Código vencido."""

    code = "otp_expired"
    message = "El código ha expirado. Solicita uno nuevo."


class OTPUsed(OTPError):
    """Código ya utilizado."""

    code = "otp_used"
    message = "Este código ya fue utilizado o reemplazado."


class OTPLocked(OTPError):
    """Demasiados intentos fallidos con este código."""

    status_code = 429
    code = "otp_locked"
    message = "Demasiados intentos fallidos. Solicita un código nuevo."


class ChallengeClosed(OTPError):
    """El proceso de login ya terminó o fue reemplazado: hay que iniciar sesión de nuevo."""

    status_code = 401
    code = "challenge_closed"
    message = "La verificación ya no es válida. Inicia sesión de nuevo."


class ResendTooSoon(OTPError):
    """Se pidió otro código antes de terminar el tiempo de espera."""

    status_code = 429
    code = "resend_cooldown"


class ResendLimitReached(OTPError):
    """Se alcanzó el máximo de códigos por intento de login."""

    status_code = 429
    code = "resend_limit"
    message = "Alcanzaste el máximo de códigos para este inicio de sesión. Inicia sesión de nuevo."


def generate_otp_code() -> str:
    """Código de exactamente 6 dígitos con `secrets` (CSPRNG). Es str para conservar ceros iniciales."""
    return f"{secrets.randbelow(10**6):06d}"


def hash_otp(user_id: int, challenge_id: str, code: str) -> str:
    """HMAC-SHA256 del OTP ligado a usuario y desafío. Es lo que se guarda en otp_codes.code."""
    key = get_settings().jwt_secret_key.encode("utf-8")
    return hmac.new(key, f"{user_id}:{challenge_id}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()


def create_otp_row(db: Session, user: User, challenge_id: str, purpose: str = "login") -> tuple[OTPCode, str]:
    """Crea (y confirma) un OTP nuevo. Devuelve (fila, código en claro para enviar por correo).

    Los OTP anteriores siguen vigentes hasta `finalize_otp`, que se llama cuando el correo
    realmente salió. Así, si el envío falla, el usuario conserva su código anterior.
    """
    now = utcnow()
    code = generate_otp_code()
    row = OTPCode(user_id=user.id, code=hash_otp(user.id, challenge_id, code), used=False, created_at=now,
                  expires_at=now + timedelta(minutes=get_settings().otp_expire_minutes),
                  purpose=purpose, attempts=0, challenge_id=challenge_id)
    db.add(row)
    db.commit()
    return row, code


def finalize_otp(db: Session, row: OTPCode) -> None:
    """Invalida todos los demás OTP sin usar del usuario (el nuevo reemplaza a los viejos)."""
    db.execute(update(OTPCode).where(OTPCode.user_id == row.user_id, OTPCode.used.is_(False),
                                     OTPCode.id != row.id).values(used=True))
    db.commit()


def discard_otp(db: Session, row: OTPCode) -> None:
    """Elimina un OTP cuyo correo no pudo enviarse."""
    db.execute(delete(OTPCode).where(OTPCode.id == row.id))
    db.commit()


def latest_for_challenge(db: Session, user_id: int, challenge_id: str) -> OTPCode | None:
    """OTP más reciente de un desafío."""
    return db.scalar(select(OTPCode).where(OTPCode.user_id == user_id, OTPCode.challenge_id == challenge_id)
                     .order_by(OTPCode.created_at.desc(), OTPCode.id.desc()).limit(1))


def check_can_resend(db: Session, user_id: int, challenge_id: str) -> None:
    """Valida que se pueda reenviar: desafío abierto, tiempo de espera cumplido y tope no superado."""
    settings = get_settings()
    latest = latest_for_challenge(db, user_id, challenge_id)
    if latest is None or latest.used:
        raise ChallengeClosed()
    waited = (utcnow() - latest.created_at).total_seconds()
    if waited < settings.otp_resend_cooldown_seconds:
        remaining = int(settings.otp_resend_cooldown_seconds - waited) + 1
        raise ResendTooSoon(f"Espera {remaining} s antes de pedir otro código.", retry_after=remaining)
    total = db.scalar(select(func.count()).select_from(OTPCode).where(
        OTPCode.user_id == user_id, OTPCode.challenge_id == challenge_id))
    if total >= settings.otp_max_codes_per_challenge:
        raise ResendLimitReached()


def verify_otp(db: Session, user_id: int, challenge_id: str, code: str) -> None:
    """Verifica el OTP: existencia, uso único, expiración, intentos y coincidencia.

    Si es correcto lo marca como usado de forma atómica. Cualquier fallo lanza OTPError.
    """
    settings = get_settings()
    row = latest_for_challenge(db, user_id, challenge_id)
    if row is None:
        raise ChallengeClosed()
    if row.used:
        raise OTPUsed()
    if row.expires_at <= utcnow():
        raise OTPExpired()
    if row.attempts >= settings.otp_max_attempts:
        raise OTPLocked()
    if not hmac.compare_digest(row.code, hash_otp(user_id, challenge_id, code)):
        db.execute(update(OTPCode).where(OTPCode.id == row.id).values(attempts=OTPCode.attempts + 1))
        db.commit()
        db.refresh(row)  # valor real del contador tras el UPDATE atómico
        left = settings.otp_max_attempts - row.attempts
        if left <= 0:
            raise OTPLocked()
        raise OTPInvalid(f"Código incorrecto. Te quedan {left} intento(s).")
    result = db.execute(update(OTPCode).where(OTPCode.id == row.id, OTPCode.used.is_(False)).values(used=True))
    db.commit()
    if result.rowcount != 1:  # otra petición simultánea lo consumió primero
        raise OTPUsed()


def purge_old_otps(db: Session) -> int:
    """Borra OTP vencidos hace más de un día (mantenimiento)."""
    result = db.execute(delete(OTPCode).where(OTPCode.expires_at <= utcnow() - timedelta(days=1)))
    db.commit()
    return result.rowcount

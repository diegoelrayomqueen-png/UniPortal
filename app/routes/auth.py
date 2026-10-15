"""Endpoints de autenticación: registro, login + OTP, JWT, renovación y cierre de sesión."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_auth
from app.errors import APIError
from app.models import OTPCode, User
from app.rate_limit import clear_failures, ensure_not_blocked, rate_limit, record_failure
from app.schemas import (ErrorResponse, LoginChallengeResponse, LoginRequest, MessageResponse, RegisterRequest,
                         ResendOTPRequest, ResendResponse, TokenResponse, UserOut, VerifyOTPRequest)
from app.services import email_service, otp_service, token_service
from app.services.password_service import dummy_hash, hash_password, verify_password

logger = logging.getLogger("uniportal")
router = APIRouter(prefix="/auth", tags=["Autenticación"])

LOGIN_MAX_FAILURES, LOGIN_FAILURE_WINDOW = 5, 15 * 60
_BEARER = {"WWW-Authenticate": "Bearer"}


def _errors(*codes: int) -> dict:
    """Arma el bloque `responses` de OpenAPI para los códigos indicados."""
    descriptions = {400: "Código OTP inválido, vencido o usado.", 401: "Credenciales o token inválidos, vencidos o revocados.",
                    403: "Tipo de token no permitido en esta ruta.", 409: "El correo ya está registrado.",
                    422: "Datos inválidos.", 429: "Demasiadas solicitudes (rate limit).", 503: "No se pudo enviar el correo."}
    return {c: {"model": ErrorResponse, "description": descriptions[c]} for c in codes}


def _mask_email(email: str) -> str:
    """Oculta el correo (a***@dominio) para mostrarlo en pantalla."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


def _deliver_otp(db: Session, user: User, row: OTPCode, code: str) -> None:
    """Envía el OTP; si el correo falla descarta el código y responde 503."""
    try:
        email_service.send_otp_email(user.email, user.full_name, code)
    except email_service.EmailDeliveryError as exc:
        otp_service.discard_otp(db, row)
        raise APIError(503, "email_delivery_failed",
                       "No pudimos enviar el correo con el código. Inténtalo de nuevo en unos minutos.") from exc
    otp_service.finalize_otp(db, row)


def _read_challenge(db: Session, token: str, email: str | None = None) -> tuple[User, str]:
    """Valida el challenge_token y devuelve (usuario, challenge_id)."""
    try:
        payload = token_service.decode_token(token, token_service.CHALLENGE)
    except token_service.TokenExpired as exc:
        raise APIError(401, "challenge_expired", "La verificación expiró. Inicia sesión de nuevo.") from exc
    except token_service.TokenError as exc:
        raise APIError(401, "challenge_invalid", "Verificación inválida. Inicia sesión de nuevo.") from exc
    user = db.get(User, int(payload["sub"]))
    challenge_id = payload.get("cid")
    if user is None or not challenge_id or (email and email != user.email):
        raise APIError(401, "challenge_invalid", "Verificación inválida. Inicia sesión de nuevo.")
    return user, challenge_id


def _otp_error(exc: otp_service.OTPError) -> APIError:
    """Traduce un OTPError a APIError (con Retry-After si aplica)."""
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return APIError(exc.status_code, exc.code, exc.message, headers)


def _tokens_out(user: User, tokens: token_service.IssuedTokens) -> TokenResponse:
    """Construye la respuesta TokenResponse con el usuario."""
    return TokenResponse(access_token=tokens.access_token, refresh_token=tokens.refresh_token,
                         expires_in=tokens.expires_in, refresh_expires_in=tokens.refresh_expires_in,
                         user=UserOut.model_validate(user))


@router.post("/register", response_model=UserOut, status_code=201, summary="Registrar usuario",
             description="Crea una cuenta. La contraseña se guarda solo como hash bcrypt. "
                         "Límite: 5 solicitudes por minuto por IP.",
             dependencies=[Depends(rate_limit("register", 5, 60))], responses=_errors(409, 422, 429))
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> User:
    """Registra un usuario nuevo; 409 si el correo ya existe."""
    if db.scalar(select(User.id).where(User.email == payload.email)) is not None:
        raise APIError(409, "email_taken", "Ya existe una cuenta con este correo.")
    user = User(email=payload.email, full_name=payload.full_name, password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:  # carrera: otro registro idéntico ganó
        db.rollback()
        raise APIError(409, "email_taken", "Ya existe una cuenta con este correo.") from exc
    return user


@router.post("/login", response_model=LoginChallengeResponse, status_code=202,
             summary="Verificar credenciales y enviar OTP",
             description="Valida correo y contraseña. Si son correctas genera un OTP de 6 dígitos, lo envía al correo "
                         "registrado y devuelve un `challenge_token`. **Todavía no concede acceso**: hay que llamar a "
                         "`/auth/verify-otp`. Tras 5 fallos en 15 min para un mismo correo se bloquea temporalmente (429).",
             dependencies=[Depends(rate_limit("login", 10, 60))], responses=_errors(401, 422, 429, 503))
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginChallengeResponse:
    """Primer factor: contraseña. Genera y envía el OTP."""
    fail_key = f"login-fail:{payload.email}"
    ensure_not_blocked(fail_key, LOGIN_MAX_FAILURES, LOGIN_FAILURE_WINDOW)
    user = db.scalar(select(User).where(User.email == payload.email))
    # Si el usuario no existe se compara contra un hash falso: mismo tiempo, mismo mensaje.
    valid = verify_password(payload.password, user.password_hash if user else dummy_hash())
    if user is None or not valid:
        record_failure(fail_key)
        raise APIError(401, "invalid_credentials", "Correo o contraseña incorrectos.", _BEARER)
    clear_failures(fail_key)

    challenge_id = str(uuid.uuid4())
    row, code = otp_service.create_otp_row(db, user, challenge_id)
    _deliver_otp(db, user, row, code)
    challenge_token, ttl = token_service.create_challenge_token(user.id, challenge_id)
    hint = _mask_email(user.email)
    return LoginChallengeResponse(message=f"Enviamos un código de 6 dígitos a {hint}.", challenge_token=challenge_token,
                                  challenge_expires_in=ttl, email_hint=hint,
                                  resend_available_in=get_settings().otp_resend_cooldown_seconds)


@router.post("/verify-otp", response_model=TokenResponse,
             summary="Verificar OTP y obtener JWT",
             description="Comprueba el OTP (vigente, no usado, sin exceder intentos). Si es correcto crea la sesión y "
                         "devuelve access y refresh token. Máximo 5 intentos por código.",
             dependencies=[Depends(rate_limit("verify-otp", 10, 60))], responses=_errors(400, 401, 422, 429))
def verify_otp(payload: VerifyOTPRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Segundo factor: valida el OTP y emite los tokens."""
    user, challenge_id = _read_challenge(db, payload.challenge_token, payload.email)
    try:
        otp_service.verify_otp(db, user.id, challenge_id, payload.code)
    except otp_service.OTPError as exc:
        raise _otp_error(exc) from exc
    return _tokens_out(user, token_service.create_session(db, user))


@router.post("/resend-otp", response_model=ResendResponse, status_code=202, summary="Reenviar OTP",
             description="Envía un código nuevo para un login ya validado con contraseña (requiere el `challenge_token` "
                         "de `/auth/login`, por lo que no permite saltarse la contraseña ni crea sesiones). "
                         "Espera mínima entre reenvíos (60 s) y máximo 5 códigos por login. El código anterior queda invalidado.",
             dependencies=[Depends(rate_limit("resend-otp", 5, 60))], responses=_errors(401, 422, 429, 503))
def resend_otp(payload: ResendOTPRequest, db: Session = Depends(get_db)) -> ResendResponse:
    """Emite un OTP de reemplazo respetando espera y tope."""
    user, challenge_id = _read_challenge(db, payload.challenge_token)
    try:
        otp_service.check_can_resend(db, user.id, challenge_id)
    except otp_service.OTPError as exc:
        raise _otp_error(exc) from exc
    row, code = otp_service.create_otp_row(db, user, challenge_id)
    _deliver_otp(db, user, row, code)
    return ResendResponse(message="Enviamos un nuevo código a tu correo.",
                          resend_available_in=get_settings().otp_resend_cooldown_seconds)


@router.post("/refresh", response_model=TokenResponse, summary="Renovar tokens",
             description="Requiere `Authorization: Bearer <refresh_token>`. Valida el refresh token y que la sesión siga "
                         "activa; devuelve un access token nuevo y un refresh token nuevo (rotación). El refresh token "
                         "anterior deja de servir; si se reutiliza, la sesión completa se revoca. La sesión no se puede "
                         "extender más allá de SESSION_MAX_DAYS.",
             dependencies=[Depends(rate_limit("refresh", 30, 60))], responses=_errors(401, 403, 429))
def refresh(auth=Depends(get_auth), db: Session = Depends(get_db)) -> TokenResponse:
    """Rota el refresh token y entrega un nuevo par de tokens."""
    user = db.get(User, auth.user_id)
    tokens = token_service.rotate_session(db, auth.user_id, auth.session_id, auth.token_hash) if user else None
    if tokens is None:
        raise APIError(401, "session_revoked", "La sesión ya no es válida.", _BEARER)
    return _tokens_out(user, tokens)


@router.post("/logout", response_model=MessageResponse, summary="Cerrar sesión y revocar token",
             description="Requiere el access token. Borra la sesión en `login_sessions`: access y refresh token de esa "
                         "sesión quedan inutilizables de inmediato.",
             responses=_errors(401, 403))
def logout(auth=Depends(get_auth), db: Session = Depends(get_db)) -> MessageResponse:
    """Revoca la sesión actual en el servidor."""
    token_service.revoke_session(db, auth.session_id)
    return MessageResponse(message="Sesión cerrada correctamente.")

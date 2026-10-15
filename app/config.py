"""Configuración centralizada de UniPortal (variables de entorno y archivo .env)."""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# load_dotenv NO pisa variables ya definidas en el entorno (útil en producción y tests).
load_dotenv(PROJECT_ROOT / ".env")

logger = logging.getLogger("uniportal")

ALLOWED_JWT_ALGORITHMS = {"HS256", "HS384", "HS512"}
MAX_OTP_MINUTES = 15
MIN_SECRET_LENGTH = 32
_ephemeral_secret: str | None = None


def _get_int(name: str, default: int, minimum: int, maximum: int) -> int:
    """Lee un entero del entorno y lo limita al rango [minimum, maximum]."""
    raw = os.getenv(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _get_bool(name: str, default: bool) -> bool:
    """Lee un booleano del entorno (true/1/yes/on)."""
    raw = os.getenv(name, "").strip().lower()
    return default if not raw else raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Valores de configuración inmutables de la aplicación."""

    environment: str
    portal_name: str
    jwt_secret_key: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    session_max_days: int
    database_url: str
    otp_expire_minutes: int
    otp_max_attempts: int
    otp_resend_cooldown_seconds: int
    otp_max_codes_per_challenge: int
    email_backend: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_security: str
    allowed_origins: tuple[str, ...]
    rate_limit_enabled: bool
    bcrypt_rounds: int

    @property
    def is_production(self) -> bool:
        """True cuando ENVIRONMENT=production."""
        return self.environment == "production"


def _resolve_secret(environment: str) -> str:
    """Devuelve la clave JWT del entorno; en desarrollo genera una efímera si falta."""
    global _ephemeral_secret
    secret = os.getenv("JWT_SECRET_KEY", "").strip()
    if secret or environment == "production":
        return secret
    if _ephemeral_secret is None:
        _ephemeral_secret = secrets.token_urlsafe(64)
        logger.warning("JWT_SECRET_KEY no definida: se usa una clave efímera (las sesiones se pierden al reiniciar).")
    return _ephemeral_secret


def get_settings() -> Settings:
    """Construye la configuración leyendo el entorno actual."""
    environment = os.getenv("ENVIRONMENT", "development").strip().lower() or "development"
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    backend = os.getenv("EMAIL_BACKEND", "").strip().lower()
    if not backend:
        backend = "smtp" if (smtp_host or environment == "production") else "console"
    origins = tuple(o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip())
    return Settings(
        environment=environment,
        portal_name=os.getenv("PORTAL_NAME", "UniPortal").strip() or "UniPortal",
        jwt_secret_key=_resolve_secret(environment),
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256").strip().upper(),
        access_token_expire_minutes=_get_int("ACCESS_TOKEN_EXPIRE_MINUTES", 15, 1, 1440),
        refresh_token_expire_days=_get_int("REFRESH_TOKEN_EXPIRE_DAYS", 7, 1, 90),
        session_max_days=_get_int("SESSION_MAX_DAYS", 30, 1, 365),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./data/uniportal.db").strip(),
        otp_expire_minutes=_get_int("OTP_EXPIRE_MINUTES", 15, 1, MAX_OTP_MINUTES),
        otp_max_attempts=_get_int("OTP_MAX_ATTEMPTS", 5, 1, 10),
        otp_resend_cooldown_seconds=_get_int("OTP_RESEND_COOLDOWN_SECONDS", 60, 0, 3600),
        otp_max_codes_per_challenge=_get_int("OTP_MAX_CODES_PER_CHALLENGE", 5, 1, 20),
        email_backend=backend,
        smtp_host=smtp_host,
        smtp_port=_get_int("SMTP_PORT", 587, 1, 65535),
        smtp_user=os.getenv("SMTP_USER", "").strip(),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_from=os.getenv("SMTP_FROM", "").strip(),
        smtp_security=os.getenv("SMTP_SECURITY", "starttls").strip().lower(),
        allowed_origins=origins,
        rate_limit_enabled=_get_bool("RATE_LIMIT_ENABLED", True),
        bcrypt_rounds=_get_int("BCRYPT_ROUNDS", 12, 4, 15),
    )


def validate_settings(settings: Settings) -> None:
    """Falla al arrancar si la configuración es insegura o está incompleta."""
    problems: list[str] = []
    if settings.jwt_algorithm not in ALLOWED_JWT_ALGORITHMS:
        problems.append(f"JWT_ALGORITHM debe ser uno de {sorted(ALLOWED_JWT_ALGORITHMS)}.")
    if len(settings.jwt_secret_key) < MIN_SECRET_LENGTH:
        problems.append(f"JWT_SECRET_KEY es obligatoria y debe tener al menos {MIN_SECRET_LENGTH} caracteres.")
    if settings.email_backend not in {"smtp", "console"}:
        problems.append("EMAIL_BACKEND debe ser 'smtp' o 'console'.")
    if settings.smtp_security not in {"starttls", "ssl", "none"}:
        problems.append("SMTP_SECURITY debe ser 'starttls', 'ssl' o 'none'.")
    if settings.email_backend == "smtp" and not (settings.smtp_host and settings.smtp_from):
        problems.append("Con EMAIL_BACKEND=smtp se requieren SMTP_HOST y SMTP_FROM.")
    if settings.is_production:
        if settings.email_backend != "smtp":
            problems.append("En producción EMAIL_BACKEND debe ser 'smtp' (el OTP nunca se muestra en logs).")
        if settings.smtp_security == "none":
            problems.append("En producción SMTP_SECURITY no puede ser 'none'.")
        if "*" in settings.allowed_origins:
            problems.append("En producción ALLOWED_ORIGINS no puede contener '*'.")
    if problems:
        raise RuntimeError("Configuración inválida:\n- " + "\n- ".join(problems))

"""Modelos SQLAlchemy: users, otp_codes y login_sessions."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from app.database import Base


def utcnow() -> datetime:
    """Fecha/hora actual en UTC con zona horaria."""
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """DateTime que guarda UTC (naive) en SQLite y devuelve siempre datetimes con tz UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Normaliza a UTC y quita la zona horaria antes de guardar."""
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        """Reasigna UTC al leer."""
        return None if value is None else value.replace(tzinfo=timezone.utc)


class User(Base):
    """Estudiante registrado. Solo se guarda el hash bcrypt de la contraseña."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False)

    otp_codes: Mapped[list["OTPCode"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    sessions: Mapped[list["LoginSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class OTPCode(Base):
    """Código OTP de un solo uso.

    Campos obligatorios del parcial: id, user_id, code, expires_at, used, created_at.
    `code` guarda un HMAC-SHA256 del OTP (nunca el código en claro).
    Campos añadidos: purpose (tipo de OTP), attempts (control de fuerza bruta) y
    challenge_id (vincula el OTP con el login que lo originó).
    """

    __tablename__ = "otp_codes"
    __table_args__ = (Index("ix_otp_codes_challenge_created", "challenge_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    purpose: Mapped[str] = mapped_column(String(20), default="login", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    challenge_id: Mapped[str] = mapped_column(String(36), nullable=False)

    user: Mapped[User] = relationship(back_populates="otp_codes")


class LoginSession(Base):
    """Sesión activa. Existir en esta tabla = sesión válida; borrarla = revocarla.

    Campos obligatorios: id, user_id, token, expires_at, created_at.
    `token` guarda el SHA-256 del refresh token vigente (no el token completo).
    Campos añadidos: session_id (claim `sid` de los JWT) y max_expires_at (tope absoluto
    de vida de la sesión aunque se renueve).
    """

    __tablename__ = "login_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    session_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    max_expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    user: Mapped[User] = relationship(back_populates="sessions")

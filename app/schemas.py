"""Esquemas Pydantic de solicitud y respuesta (con ejemplos para Swagger UI)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.services.password_service import check_password_policy


def _clean_full_name(value: str) -> str:
    """Normaliza espacios y valida el nombre completo."""
    value = " ".join(value.split())
    if len(value) < 2:
        raise ValueError("El nombre debe tener al menos 2 caracteres.")
    if len(value) > 120:
        raise ValueError("El nombre no puede superar 120 caracteres.")
    if "<" in value or ">" in value:
        raise ValueError("El nombre contiene caracteres no permitidos.")
    return value


class RegisterRequest(BaseModel):
    """Datos de registro. La confirmación de contraseña se valida solo en el frontend."""

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"full_name": "Ana María Pérez", "email": "ana.perez@universidad.edu.co", "password": "Clave.Segura1"}]})

    full_name: str = Field(description="Nombre completo (2-120 caracteres).")
    email: EmailStr = Field(description="Correo electrónico (único).")
    password: str = Field(description="Mínimo 8 caracteres, con mayúscula, minúscula, número y símbolo.")

    @field_validator("full_name")
    @classmethod
    def _name(cls, v: str) -> str:
        """Normaliza y valida el nombre completo."""
        return _clean_full_name(v)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        """Normaliza el correo a minúsculas."""
        return v.lower()

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        """Aplica la política de contraseñas del servidor."""
        problems = check_password_policy(v)
        if problems:
            raise ValueError(" ".join(problems))
        return v


class LoginRequest(BaseModel):
    """Credenciales de inicio de sesión (primer factor)."""

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"email": "ana.perez@universidad.edu.co", "password": "Clave.Segura1"}]})

    email: EmailStr
    password: str = Field(min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        """Normaliza el correo a minúsculas."""
        return v.lower()


class VerifyOTPRequest(BaseModel):
    """Verificación del segundo factor. `challenge_token` lo entrega /auth/login."""

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"challenge_token": "<token devuelto por /auth/login>", "code": "038271"}]})

    challenge_token: str = Field(min_length=10, max_length=2000)
    code: str = Field(pattern=r"^[0-9]{6}$", description="Código de exactamente 6 dígitos (texto: puede empezar por 0).")
    email: EmailStr | None = Field(default=None, description="Opcional; si se envía debe coincidir con la cuenta del desafío.")

    @field_validator("email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        """Normaliza el correo a minúsculas."""
        return v.lower() if v else v


class ResendOTPRequest(BaseModel):
    """Solicitud de nuevo código para un login ya validado con contraseña."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"challenge_token": "<token devuelto por /auth/login>"}]})

    challenge_token: str = Field(min_length=10, max_length=2000)


class ProfileUpdate(BaseModel):
    """Campos que el usuario puede modificar. Cualquier otro campo se rechaza (422)."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{"full_name": "Ana María Pérez Gómez"}]})

    full_name: str = Field(description="Nuevo nombre completo.")

    @field_validator("full_name")
    @classmethod
    def _name(cls, v: str) -> str:
        """Normaliza y valida el nombre completo."""
        return _clean_full_name(v)


class UserOut(BaseModel):
    """Perfil público del usuario (sin hash de contraseña)."""

    model_config = ConfigDict(from_attributes=True, json_schema_extra={"examples": [{
        "id": 1, "email": "ana.perez@universidad.edu.co", "full_name": "Ana María Pérez",
        "created_at": "2026-10-12T15:30:00Z", "updated_at": "2026-10-12T15:30:00Z"}]})

    id: int
    email: str
    full_name: str
    created_at: datetime
    updated_at: datetime


class LoginChallengeResponse(BaseModel):
    """Respuesta de /auth/login: aún NO hay sesión; falta verificar el OTP."""

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "message": "Enviamos un código de 6 dígitos a a***@universidad.edu.co.",
        "challenge_token": "<jwt>", "challenge_expires_in": 900, "resend_available_in": 60,
        "email_hint": "a***@universidad.edu.co"}]})

    message: str
    challenge_token: str
    challenge_expires_in: int
    resend_available_in: int
    email_hint: str


class ResendResponse(BaseModel):
    """Respuesta de /auth/resend-otp."""

    message: str
    resend_available_in: int


class TokenResponse(BaseModel):
    """Tokens de sesión emitidos tras verificar el OTP o renovar."""

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "access_token": "<jwt>", "refresh_token": "<jwt>", "token_type": "bearer",
        "expires_in": 900, "refresh_expires_in": 604800}]})

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Segundos de vida del access token.")
    refresh_expires_in: int = Field(description="Segundos de vida del refresh token.")
    user: UserOut | None = None


class MessageResponse(BaseModel):
    """Respuesta simple con un mensaje."""

    message: str


class ErrorResponse(BaseModel):
    """Formato uniforme de error."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"detail": "Token inválido.", "code": "token_invalid"}]})

    detail: str | list | dict
    code: str

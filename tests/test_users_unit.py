"""Pruebas unitarias de esquemas y configuración."""
import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings, validate_settings
from app.database import resolve_database_url
from app.schemas import ProfileUpdate, RegisterRequest, VerifyOTPRequest


def test_profile_update_normalizes_name_and_rejects_privileged_fields():
    assert ProfileUpdate(full_name="  Ana   María  ").full_name == "Ana María"
    for extra in ({"id": 5}, {"password_hash": "x"}, {"email": "otro@x.co"}, {"sessions": []}):
        with pytest.raises(ValidationError):
            ProfileUpdate(full_name="Ana", **extra)


@pytest.mark.parametrize("name", ["", " ", "A", "x" * 121, "<script>alert(1)</script>"])
def test_profile_update_rejects_invalid_names(name):
    with pytest.raises(ValidationError):
        ProfileUpdate(full_name=name)


def test_register_schema_validates_email_and_lowercases():
    data = RegisterRequest(full_name="Ana", email="ANA@Universidad.edu.co", password="Clave.Segura1")
    assert data.email == "ana@universidad.edu.co"
    with pytest.raises(ValidationError):
        RegisterRequest(full_name="Ana", email="no-es-correo", password="Clave.Segura1")
    with pytest.raises(ValidationError):
        RegisterRequest(full_name="Ana", email="a@b.co", password="debil")


def test_otp_code_must_be_exactly_six_digits():
    for bad in ("12345", "1234567", "12345a", "١٢٣٤٥٦", " 12345"):
        with pytest.raises(ValidationError):
            VerifyOTPRequest(challenge_token="x" * 20, code=bad)
    assert VerifyOTPRequest(challenge_token="x" * 20, code="012345").code == "012345"


def test_database_url_is_resolved_against_project_root_and_only_sqlite():
    url = resolve_database_url("sqlite:///./data/x.db")
    assert url.database.startswith("/") and url.database.endswith("data/x.db")
    with pytest.raises(ValueError):
        resolve_database_url("postgresql://u:p@h/db")


def test_otp_validity_is_clamped_to_15_minutes(monkeypatch):
    monkeypatch.setenv("OTP_EXPIRE_MINUTES", "60")
    assert get_settings().otp_expire_minutes == 15


def test_production_settings_require_strong_secret_and_smtp(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "corta")
    monkeypatch.setenv("EMAIL_BACKEND", "console")
    with pytest.raises(RuntimeError) as exc:
        validate_settings(get_settings())
    assert "JWT_SECRET_KEY" in str(exc.value) and "smtp" in str(exc.value)
    assert isinstance(get_settings(), Settings)

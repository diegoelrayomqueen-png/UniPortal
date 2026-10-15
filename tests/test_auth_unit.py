"""Pruebas unitarias: OTP, contraseñas, JWT y correo (sin red)."""
import re
import smtplib
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from app.config import get_settings
from app.models import OTPCode, User, utcnow
from app.services import email_service, otp_service, token_service
from app.services.password_service import check_password_policy, hash_password, verify_password


def make_user(db, email="u@universidad.edu.co"):
    user = User(email=email, full_name="Usuario Prueba", password_hash=hash_password("Clave.Segura1"))
    db.add(user)
    db.commit()
    return user


# 1. Generación de OTP de seis dígitos
def test_otp_has_exactly_six_digits_and_keeps_leading_zeros(monkeypatch):
    for _ in range(200):
        assert re.fullmatch(r"\d{6}", otp_service.generate_otp_code())
    monkeypatch.setattr(otp_service.secrets, "randbelow", lambda n: 42)
    assert otp_service.generate_otp_code() == "000042"


def test_otp_is_stored_hashed_and_expires_within_15_minutes(db):
    user = make_user(db)
    row, code = otp_service.create_otp_row(db, user, "chal-1")
    assert row.code != code and len(row.code) == 64
    assert row.expires_at - row.created_at <= timedelta(minutes=15)
    assert get_settings().otp_expire_minutes <= 15


# 2. Rechazo de OTP vencidos
def test_expired_otp_is_rejected(db):
    user = make_user(db)
    row, code = otp_service.create_otp_row(db, user, "chal-2")
    row.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    with pytest.raises(otp_service.OTPExpired):
        otp_service.verify_otp(db, user.id, "chal-2", code)


# 3. Rechazo de OTP utilizados
def test_used_otp_cannot_be_reused(db):
    user = make_user(db)
    _, code = otp_service.create_otp_row(db, user, "chal-3")
    otp_service.verify_otp(db, user.id, "chal-3", code)
    with pytest.raises(otp_service.OTPUsed):
        otp_service.verify_otp(db, user.id, "chal-3", code)


def test_wrong_otp_counts_attempts_and_locks(db):
    user = make_user(db)
    row, code = otp_service.create_otp_row(db, user, "chal-4")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(get_settings().otp_max_attempts - 1):
        with pytest.raises(otp_service.OTPInvalid):
            otp_service.verify_otp(db, user.id, "chal-4", wrong)
    with pytest.raises(otp_service.OTPLocked):
        otp_service.verify_otp(db, user.id, "chal-4", wrong)
    with pytest.raises(otp_service.OTPLocked):  # ni siquiera el código correcto sirve ya
        otp_service.verify_otp(db, user.id, "chal-4", code)


def test_new_otp_invalidates_previous_one(db):
    user = make_user(db)
    old_row, old_code = otp_service.create_otp_row(db, user, "chal-5")
    new_row, _ = otp_service.create_otp_row(db, user, "chal-5")
    otp_service.finalize_otp(db, new_row)
    db.refresh(old_row)
    assert old_row.used is True and new_row.used is False
    with pytest.raises(otp_service.OTPInvalid):  # el viejo ya no coincide con el último emitido
        otp_service.verify_otp(db, user.id, "chal-5", old_code)


# 4. Hashing y verificación de contraseñas
def test_password_hashing_and_verification():
    hashed = hash_password("Clave.Segura1")
    assert hashed != "Clave.Segura1" and hashed.startswith("$2")
    assert verify_password("Clave.Segura1", hashed)
    assert not verify_password("otra", hashed)
    assert hash_password("Clave.Segura1") != hashed  # salt distinto cada vez
    assert not verify_password("x", "no-es-un-hash")


@pytest.mark.parametrize("password,fragment", [
    ("Ab1.", "8 caracteres"), ("sinmayuscula1.", "mayúscula"), ("SINMINUSCULA1.", "minúscula"),
    ("SinNumero.aa", "número"), ("SinSimbolo11a", "símbolo"), ("Aa1." + "x" * 80, "bytes")])
def test_password_policy_rejects_weak_passwords(password, fragment):
    assert any(fragment in problem for problem in check_password_policy(password))


def test_password_policy_accepts_strong_password():
    assert check_password_policy("Clave.Segura1") == []


# 5. Generación y validación de JWT
def test_access_token_roundtrip_and_claims():
    token, exp = token_service.create_access_token(7, "sid-1")
    payload = token_service.decode_token(token, token_service.ACCESS)
    assert payload["sub"] == "7" and payload["sid"] == "sid-1" and payload["type"] == "access"
    assert {"exp", "iat", "jti"} <= payload.keys()
    assert abs(payload["exp"] - exp.timestamp()) < 1


def test_expired_tampered_and_wrong_type_tokens_are_rejected():
    expired, _ = token_service.create_access_token(1, "s", expires_delta=timedelta(minutes=-5))
    with pytest.raises(token_service.TokenExpired):
        token_service.decode_token(expired)
    good, _ = token_service.create_access_token(1, "s")
    with pytest.raises(token_service.TokenInvalid):
        token_service.decode_token(good[:-4] + "AAAA")
    with pytest.raises(token_service.TokenInvalid):
        token_service.decode_token("no.es.jwt")
    with pytest.raises(token_service.WrongTokenType):
        token_service.decode_token(good, token_service.REFRESH)


def test_token_signed_with_other_key_or_alg_none_is_rejected():
    import jwt
    claims = {"sub": "1", "type": "access", "iat": utcnow(), "exp": utcnow() + timedelta(minutes=5), "jti": "x"}
    with pytest.raises(token_service.TokenInvalid):
        token_service.decode_token(jwt.encode(claims, "otra-clave-" + "y" * 40, algorithm="HS256"))
    with pytest.raises(token_service.TokenInvalid):
        token_service.decode_token(jwt.encode(claims, key=None, algorithm="none"))


# Correo: SMTP simulado
def test_smtp_sender_uses_starttls_login_and_never_leaks_code_in_logs(monkeypatch, caplog):
    for key, value in {"EMAIL_BACKEND": "smtp", "SMTP_HOST": "smtp.fake.test", "SMTP_USER": "u",
                       "SMTP_PASSWORD": "p", "SMTP_SECURITY": "starttls"}.items():
        monkeypatch.setenv(key, value)
    server = MagicMock()
    server.__enter__.return_value = server
    with patch.object(smtplib, "SMTP", return_value=server) as smtp_cls:
        email_service.send_otp_email("a@b.co", "Ana <b>", "123456")
    smtp_cls.assert_called_once()
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("u", "p")
    message = server.send_message.call_args[0][0]
    body = message.get_body(("plain",)).get_content()
    assert "123456" in body and "15 minutos" in body and "No compartas" in body
    assert "&lt;b&gt;" in message.get_body(("html",)).get_content()  # nombre escapado en HTML
    assert "123456" not in caplog.text


def test_smtp_failure_raises_delivery_error_without_secrets(monkeypatch, caplog):
    monkeypatch.setenv("EMAIL_BACKEND", "smtp")
    monkeypatch.setenv("SMTP_HOST", "smtp.fake.test")
    with patch.object(smtplib, "SMTP", side_effect=smtplib.SMTPConnectError(421, "no")):
        with pytest.raises(email_service.EmailDeliveryError):
            email_service.send_otp_email("a@b.co", "Ana", "654321")
    assert "654321" not in caplog.text


def test_console_backend_is_refused_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("EMAIL_BACKEND", "console")
    with pytest.raises(email_service.EmailDeliveryError):
        email_service.send_otp_email("a@b.co", "Ana", "111111")

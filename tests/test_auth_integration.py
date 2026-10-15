"""Pruebas de integración de extremo a extremo contra la API real (BD temporal, correo simulado)."""
from datetime import timedelta

from sqlalchemy import select

from app.models import LoginSession, OTPCode, User, utcnow
from app.services import email_service, token_service
from tests.conftest import PASSWORD, bearer, full_login, register_user


# 1. Registro y correos duplicados
def test_register_creates_user_without_exposing_secrets_and_rejects_duplicates(client, db):
    response = register_user(client, email="Ana@Universidad.edu.co")
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "ana@universidad.edu.co" and "password" not in body and "password_hash" not in body
    stored = db.scalar(select(User))
    assert stored.password_hash != PASSWORD and stored.password_hash.startswith("$2")
    duplicate = register_user(client, email="ana@universidad.edu.co")
    assert duplicate.status_code == 409 and duplicate.json()["code"] == "email_taken"


def test_register_validation_errors_do_not_echo_the_password(client):
    response = register_user(client, password="debil")
    assert response.status_code == 422
    assert "debil" not in response.text
    assert register_user(client, email="no-es-correo").status_code == 422


# 2. Login, verificación OTP y emisión de tokens
def test_login_sends_otp_and_only_verification_grants_tokens(client, outbox, db):
    register_user(client)
    login = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD})
    assert login.status_code == 202
    assert "access_token" not in login.json() and login.json()["email_hint"] == "a***@universidad.edu.co"
    assert len(outbox) == 1 and outbox[0]["to"] == "ana@universidad.edu.co" and len(outbox[0]["code"]) == 6
    assert client.get("/users/profile").status_code == 401  # aún sin acceso

    row = db.scalar(select(OTPCode))
    assert row.code != outbox[0]["code"] and row.used is False  # guardado como hash, aún sin usar

    verify = client.post("/auth/verify-otp", json={"challenge_token": login.json()["challenge_token"],
                                                  "code": outbox[0]["code"]})
    assert verify.status_code == 200
    tokens = verify.json()
    assert tokens["token_type"] == "bearer" and tokens["user"]["email"] == "ana@universidad.edu.co"
    assert token_service.decode_token(tokens["access_token"], "access")["type"] == "access"
    assert token_service.decode_token(tokens["refresh_token"], "refresh")["type"] == "refresh"
    db.expire_all()
    assert db.scalar(select(OTPCode)).used is True
    session = db.scalar(select(LoginSession))
    assert session.token != tokens["refresh_token"] and len(session.token) == 64  # solo el hash


def test_wrong_password_unknown_user_and_reused_otp_are_rejected(client, outbox):
    register_user(client)
    bad = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": "Incorrecta1!"})
    ghost = client.post("/auth/login", json={"email": "nadie@universidad.edu.co", "password": PASSWORD})
    assert bad.status_code == ghost.status_code == 401 and bad.json() == ghost.json()  # no revela si existe
    assert outbox == []  # sin credenciales válidas no se genera OTP

    login = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD}).json()
    payload = {"challenge_token": login["challenge_token"], "code": outbox[0]["code"]}
    assert client.post("/auth/verify-otp", json=payload).status_code == 200
    again = client.post("/auth/verify-otp", json=payload)
    assert again.status_code == 400 and again.json()["code"] == "otp_used"


def test_wrong_otp_is_rejected_then_locked_after_too_many_attempts(client, outbox):
    register_user(client)
    login = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD}).json()
    wrong = "000000" if outbox[0]["code"] != "000000" else "111111"
    statuses = [client.post("/auth/verify-otp", json={"challenge_token": login["challenge_token"], "code": wrong}).status_code
                for _ in range(5)]
    assert statuses == [400, 400, 400, 400, 429]
    good = client.post("/auth/verify-otp", json={"challenge_token": login["challenge_token"], "code": outbox[0]["code"]})
    assert good.status_code == 429  # bloqueado aunque ahora acierte


def test_expired_otp_is_rejected_via_api(client, outbox, db):
    register_user(client)
    login = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD}).json()
    row = db.scalar(select(OTPCode))
    row.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    response = client.post("/auth/verify-otp", json={"challenge_token": login["challenge_token"], "code": outbox[0]["code"]})
    assert response.status_code == 400 and response.json()["code"] == "otp_expired"


def test_email_failure_returns_503_and_leaves_no_usable_otp(client, monkeypatch, db):
    register_user(client)

    def boom(*_args):
        raise email_service.EmailDeliveryError("smtp caído")

    monkeypatch.setattr(email_service, "send_otp_email", boom)
    response = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD})
    assert response.status_code == 503 and response.json()["code"] == "email_delivery_failed"
    assert "challenge_token" not in response.text
    assert db.scalar(select(OTPCode)) is None


# 3. Perfil protegido; tokens inválidos, vencidos y revocados
def test_profile_requires_valid_access_token(client, outbox):
    register_user(client)
    tokens = full_login(client, outbox)
    ok = client.get("/users/profile", headers=bearer(tokens["access_token"]))
    assert ok.status_code == 200 and ok.json()["full_name"] == "Ana Pérez"

    assert client.get("/users/profile").status_code == 401
    assert client.get("/users/profile", headers=bearer("basura")).status_code == 401
    assert client.get("/users/profile", headers={"Authorization": "Token abc"}).status_code == 401
    tampered = tokens["access_token"][:-3] + ("AAA" if not tokens["access_token"].endswith("AAA") else "BBB")
    assert client.get("/users/profile", headers=bearer(tampered)).status_code == 401

    expired, _ = token_service.create_access_token(1, tokens and token_service.decode_token(tokens["access_token"])["sid"],
                                                   expires_delta=timedelta(minutes=-1))
    response = client.get("/users/profile", headers=bearer(expired))
    assert response.status_code == 401 and response.json()["code"] == "token_expired"

    # token del tipo equivocado -> 403, y un refresh token no sirve como access token
    assert client.get("/users/profile", headers=bearer(tokens["refresh_token"])).status_code == 403
    assert client.post("/auth/refresh", headers=bearer(tokens["access_token"])).status_code == 403


def test_logout_revokes_session_for_access_and_refresh_tokens(client, outbox, db):
    register_user(client)
    tokens = full_login(client, outbox)
    assert client.post("/auth/logout").status_code == 401
    out = client.post("/auth/logout", headers=bearer(tokens["access_token"]))
    assert out.status_code == 200
    assert db.scalar(select(LoginSession)) is None  # fila eliminada en el servidor
    revoked = client.get("/users/profile", headers=bearer(tokens["access_token"]))
    assert revoked.status_code == 401 and revoked.json()["code"] == "session_revoked"
    assert client.post("/auth/refresh", headers=bearer(tokens["refresh_token"])).status_code == 401
    assert client.post("/auth/logout", headers=bearer(tokens["access_token"])).status_code == 401


# Renovación
def test_refresh_rotates_tokens_and_reuse_revokes_the_session(client, outbox, db):
    register_user(client)
    first = full_login(client, outbox)
    renewed = client.post("/auth/refresh", headers=bearer(first["refresh_token"]))
    assert renewed.status_code == 200
    second = renewed.json()
    assert second["access_token"] != first["access_token"] and second["refresh_token"] != first["refresh_token"]
    assert client.get("/users/profile", headers=bearer(second["access_token"])).status_code == 200

    reuse = client.post("/auth/refresh", headers=bearer(first["refresh_token"]))  # token ya rotado
    assert reuse.status_code == 401 and reuse.json()["code"] == "refresh_reuse"
    assert db.scalar(select(LoginSession)) is None
    assert client.get("/users/profile", headers=bearer(second["access_token"])).status_code == 401


def test_refresh_cannot_extend_session_beyond_absolute_limit(client, outbox, db):
    register_user(client)
    tokens = full_login(client, outbox)
    session = db.scalar(select(LoginSession))
    session.max_expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    response = client.post("/auth/refresh", headers=bearer(tokens["refresh_token"]))
    assert response.status_code == 401 and response.json()["code"] == "session_expired"


# Reenvío de OTP
def test_resend_otp_requires_challenge_cooldown_and_invalidates_old_code(client, outbox, db):
    register_user(client)
    assert client.post("/auth/resend-otp", json={"challenge_token": "x" * 30}).status_code == 401
    login = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD}).json()
    token = login["challenge_token"]

    too_soon = client.post("/auth/resend-otp", json={"challenge_token": token})
    assert too_soon.status_code == 429 and "Retry-After" in too_soon.headers

    row = db.scalar(select(OTPCode))
    row.created_at = utcnow() - timedelta(seconds=120)
    db.commit()
    resent = client.post("/auth/resend-otp", json={"challenge_token": token})
    assert resent.status_code == 202 and len(outbox) == 2
    assert "access_token" not in resent.text  # reenviar no crea sesión

    old, new = outbox[0]["code"], outbox[1]["code"]
    if old != new:
        assert client.post("/auth/verify-otp", json={"challenge_token": token, "code": old}).status_code == 400
    assert client.post("/auth/verify-otp", json={"challenge_token": token, "code": new}).status_code == 200


def test_resend_is_impossible_with_an_access_token_or_after_login_completed(client, outbox):
    register_user(client)
    tokens = full_login(client, outbox)
    assert client.post("/auth/resend-otp", json={"challenge_token": tokens["access_token"]}).status_code == 401
    login = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD}).json()
    client.post("/auth/verify-otp", json={"challenge_token": login["challenge_token"], "code": outbox[-1]["code"]})
    assert client.post("/auth/resend-otp", json={"challenge_token": login["challenge_token"]}).status_code == 401


# Actualización de perfil y aislamiento entre usuarios
def test_profile_update_only_changes_allowed_fields(client, outbox, db):
    register_user(client)
    tokens = full_login(client, outbox)
    headers = bearer(tokens["access_token"])
    updated = client.put("/users/profile", json={"full_name": "  Ana   Gómez "}, headers=headers)
    assert updated.status_code == 200 and updated.json()["full_name"] == "Ana Gómez"
    for forbidden in ({"id": 99}, {"email": "x@y.co"}, {"password_hash": "x"}):
        assert client.put("/users/profile", json={"full_name": "Ana", **forbidden}, headers=headers).status_code == 422
    assert client.put("/users/profile", json={"full_name": "A"}, headers=headers).status_code == 422
    assert client.put("/users/profile", json={"full_name": "Ana"}).status_code == 401
    assert db.scalar(select(User)).email == "ana@universidad.edu.co"


def test_users_cannot_read_or_modify_each_others_profile(client, outbox):
    register_user(client, email="ana@universidad.edu.co", name="Ana Pérez")
    register_user(client, email="luis@universidad.edu.co", name="Luis Mora")
    ana = full_login(client, outbox, email="ana@universidad.edu.co")
    luis = full_login(client, outbox, email="luis@universidad.edu.co")
    assert client.get("/users/profile", headers=bearer(ana["access_token"])).json()["email"] == "ana@universidad.edu.co"
    assert client.get("/users/profile", headers=bearer(luis["access_token"])).json()["email"] == "luis@universidad.edu.co"
    client.put("/users/profile", json={"full_name": "Luis Editado"}, headers=bearer(luis["access_token"]))
    assert client.get("/users/profile", headers=bearer(ana["access_token"])).json()["full_name"] == "Ana Pérez"
    assert client.get("/users/profile?id=2", headers=bearer(ana["access_token"])).json()["email"] == "ana@universidad.edu.co"


# Rate limiting
def test_register_is_rate_limited_per_ip(client):
    codes = [register_user(client, email=f"u{i}@universidad.edu.co").status_code for i in range(7)]
    assert codes[:5] == [201] * 5 and codes[5:] == [429, 429]
    limited = register_user(client, email="otro@universidad.edu.co")
    assert limited.json()["code"] == "rate_limited" and int(limited.headers["Retry-After"]) >= 1


def test_login_locks_an_email_after_repeated_failures_even_with_the_right_password(client, outbox):
    register_user(client)
    bad = {"email": "ana@universidad.edu.co", "password": "Incorrecta1!"}
    assert [client.post("/auth/login", json=bad).status_code for _ in range(5)] == [401] * 5
    blocked = client.post("/auth/login", json={"email": "ana@universidad.edu.co", "password": PASSWORD})
    assert blocked.status_code == 429 and outbox == []


def test_verify_otp_endpoint_is_rate_limited(client):
    statuses = [client.post("/auth/verify-otp", json={"challenge_token": "x" * 30, "code": "123456"}).status_code
                for _ in range(12)]
    assert statuses[:10] == [401] * 10 and statuses[10:] == [429, 429]


# Varios
def test_error_format_security_headers_and_frontend_are_served(client):
    missing = client.get("/ruta-que-no-existe")
    assert missing.status_code == 404 and missing.json()["code"] == "not_found"
    api = client.get("/health")
    assert api.json() == {"status": "ok"} and api.headers["x-content-type-options"] == "nosniff"
    assert "script-src 'self'" in api.headers["content-security-policy"]
    assert client.get("/users/profile").headers["cache-control"] == "no-store"
    docs = client.get("/docs")
    assert docs.status_code == 200 and "content-security-policy" not in docs.headers
    assert "/auth/resend-otp" in client.get("/openapi.json").json()["paths"]
    for page in ("/", "/login.html", "/register.html", "/verify-otp.html", "/dashboard.html", "/profile.html"):
        assert client.get(page).status_code == 200, page

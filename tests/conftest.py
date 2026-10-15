"""Fixtures: base SQLite temporal aislada, correo simulado y rate limiter reiniciado."""
import os
import tempfile

# Se fija el entorno ANTES de importar la app, y con asignación directa para que ni el .env
# ni la base de datos real puedan colarse en las pruebas.
_TMP_DIR = tempfile.mkdtemp(prefix="uniportal-tests-")
os.environ.update({
    "ENVIRONMENT": "test",
    "DATABASE_URL": f"sqlite:///{_TMP_DIR}/test.db",
    "JWT_SECRET_KEY": "clave-de-pruebas-" + "x" * 48,
    "JWT_ALGORITHM": "HS256",
    "EMAIL_BACKEND": "console",
    "SMTP_HOST": "",
    "SMTP_USER": "",
    "SMTP_PASSWORD": "",
    "SMTP_FROM": "UniPortal <pruebas@uniportal.test>",
    "BCRYPT_ROUNDS": "4",
    "OTP_RESEND_COOLDOWN_SECONDS": "60",
    "RATE_LIMIT_ENABLED": "true",
    "ALLOWED_ORIGINS": "",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import database  # noqa: E402
from app.main import app  # noqa: E402
from app.rate_limit import limiter  # noqa: E402
from app.services import email_service  # noqa: E402

PASSWORD = "Clave.Segura1"


@pytest.fixture(autouse=True)
def clean_state():
    """Tablas vacías y contadores de rate limit en cero antes de cada prueba."""
    database.Base.metadata.drop_all(bind=database.engine)
    database.Base.metadata.create_all(bind=database.engine)
    limiter.reset()
    yield


@pytest.fixture
def client():
    """Cliente HTTP de pruebas (ejecuta el lifespan de la app)."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db():
    """Sesión directa a la base de pruebas para preparar o inspeccionar datos."""
    with database.SessionLocal() as session:
        yield session


@pytest.fixture
def outbox(monkeypatch):
    """Sustituye el envío de correo: guarda (to, name, code) en una lista; no sale nada a la red."""
    sent: list[dict] = []
    monkeypatch.setattr(email_service, "send_otp_email",
                        lambda to, name, code: sent.append({"to": to, "name": name, "code": code}))
    return sent


def register_user(client, email="ana@universidad.edu.co", name="Ana Pérez", password=PASSWORD):
    """Registra un usuario vía API."""
    return client.post("/auth/register", json={"full_name": name, "email": email, "password": password})


def full_login(client, outbox, email="ana@universidad.edu.co", password=PASSWORD):
    """Login + verificación OTP. Devuelve el JSON de tokens."""
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 202, login.text
    verify = client.post("/auth/verify-otp", json={"challenge_token": login.json()["challenge_token"],
                                                  "code": outbox[-1]["code"]})
    assert verify.status_code == 200, verify.text
    return verify.json()


def bearer(token):
    """Cabecera Authorization."""
    return {"Authorization": f"Bearer {token}"}

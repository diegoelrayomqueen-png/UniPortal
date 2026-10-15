"""Punto de entrada de UniPortal: crea la app, registra middleware, rutas y frontend estático."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app import database
from app.config import get_settings, validate_settings
from app.errors import register_exception_handlers
from app.middleware import AuthMiddleware, SecurityHeadersMiddleware
from app.routes import auth, users
from app.services import otp_service, token_service

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("uniportal")
STATIC_DIR = Path(__file__).resolve().parent / "static"

DESCRIPTION = """
Portal de estudiantes con **autenticación de dos factores** (contraseña + OTP por correo) y **JWT**.

Flujo: `register` → `login` (envía OTP) → `verify-otp` (entrega access + refresh) → rutas protegidas →
`refresh` / `logout`. En *Authorize* pega el `access_token` (o el `refresh_token` para `/auth/refresh`).
"""


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Valida la configuración, crea las tablas y limpia registros vencidos al arrancar."""
    validate_settings(get_settings())
    database.init_db()
    with database.SessionLocal() as db:
        token_service.purge_expired_sessions(db)
        otp_service.purge_old_otps(db)
    logger.info("UniPortal listo (entorno=%s, correo=%s)", get_settings().environment, get_settings().email_backend)
    yield


app = FastAPI(title="UniPortal API", version="1.0.0", description=DESCRIPTION, lifespan=lifespan,
              openapi_tags=[{"name": "Autenticación", "description": "Registro, login con OTP, JWT, renovación y logout."},
                            {"name": "Perfil", "description": "Consulta y edición del perfil propio."},
                            {"name": "Sistema", "description": "Comprobación de salud para el despliegue."}])
register_exception_handlers(app)

# Orden: el último añadido es el más externo.
app.add_middleware(AuthMiddleware)
if get_settings().allowed_origins:
    app.add_middleware(CORSMiddleware, allow_origins=list(get_settings().allowed_origins), allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health", tags=["Sistema"], summary="Estado del servicio")
def health() -> dict:
    """Comprueba que la app responde y que la base de datos es accesible."""
    with database.SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ok"}


# Debe ir al final: sirve el frontend en "/" sin tapar las rutas de la API.
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="frontend")

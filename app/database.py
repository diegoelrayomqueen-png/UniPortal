"""Configuración de SQLAlchemy + SQLite (motor, sesión e inicialización de tablas)."""
from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import PROJECT_ROOT, get_settings


class Base(DeclarativeBase):
    """Clase base declarativa de todos los modelos."""


def resolve_database_url(raw_url: str) -> URL:
    """Valida que sea SQLite y convierte rutas relativas en absolutas (respecto al proyecto).

    Así la base de datos siempre queda en el mismo sitio sin importar desde qué carpeta se
    ejecute la aplicación.
    """
    url = make_url(raw_url)
    if not url.drivername.startswith("sqlite"):
        raise ValueError("UniPortal solo soporta SQLite (DATABASE_URL debe empezar por sqlite:///).")
    if url.database and url.database != ":memory:":
        path = Path(url.database)
        if not path.is_absolute():
            path = (PROJECT_ROOT / path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        url = url.set(database=str(path))
    return url


engine = create_engine(
    resolve_database_url(get_settings().database_url),
    connect_args={"check_same_thread": False, "timeout": 15},
)


@event.listens_for(engine, "connect")
def _enable_foreign_keys(dbapi_connection, _record) -> None:  # pragma: no cover - evento de bajo nivel
    """SQLite ignora las claves foráneas por defecto; se activan en cada conexión."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Dependencia de FastAPI: entrega una sesión y la cierra siempre al terminar."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Crea las tablas si no existen (idempotente)."""
    from app import models  # noqa: F401  (registra los modelos en Base.metadata)

    Base.metadata.create_all(bind=engine)

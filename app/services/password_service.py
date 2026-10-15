"""Hashing y política de contraseñas (bcrypt)."""
from __future__ import annotations

import re
from functools import lru_cache

import bcrypt

from app.config import get_settings

MIN_LENGTH = 8
MAX_BYTES = 72  # límite técnico de bcrypt


def check_password_policy(password: str) -> list[str]:
    """Devuelve la lista de reglas incumplidas (vacía si la contraseña es válida)."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"Debe tener al menos {MIN_LENGTH} caracteres.")
    if len(password.encode("utf-8")) > MAX_BYTES:
        problems.append(f"Debe ocupar como máximo {MAX_BYTES} bytes (≈{MAX_BYTES} caracteres).")
    if not re.search(r"[a-z]", password):
        problems.append("Debe incluir una letra minúscula.")
    if not re.search(r"[A-Z]", password):
        problems.append("Debe incluir una letra mayúscula.")
    if not re.search(r"\d", password):
        problems.append("Debe incluir un número.")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("Debe incluir un símbolo (por ejemplo ! . # $).")
    return problems


def hash_password(password: str) -> str:
    """Genera el hash bcrypt (con salt aleatorio) de la contraseña."""
    salt = bcrypt.gensalt(rounds=get_settings().bcrypt_rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Compara una contraseña con un hash bcrypt; False ante cualquier hash o entrada inválida."""
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:MAX_BYTES], password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=1)
def dummy_hash() -> str:
    """Hash falso para igualar el tiempo de respuesta cuando el correo no existe."""
    return hash_password("contraseña-falsa-Zz9!")

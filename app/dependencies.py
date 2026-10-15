"""Dependencias compartidas de FastAPI (usuario autenticado)."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.errors import APIError
from app.models import User
from app.services.token_service import AuthenticatedToken

# auto_error=False: el rechazo real lo hace app/middleware.py; esto solo habilita el botón
# "Authorize" en Swagger UI.
bearer_scheme = HTTPBearer(auto_error=False, description="Pega aquí el token (access o refresh según el endpoint).")


def get_auth(request: Request, _credentials=Depends(bearer_scheme)) -> AuthenticatedToken:
    """Devuelve el token ya validado por el middleware (defensa en profundidad: 401 si falta)."""
    auth = getattr(request.state, "auth", None)
    if auth is None:
        raise APIError(401, "missing_token", "Se requiere autenticación.", {"WWW-Authenticate": "Bearer"})
    return auth


def get_current_user(auth: AuthenticatedToken = Depends(get_auth), db: Session = Depends(get_db)) -> User:
    """Carga al usuario dueño de la sesión. Siempre sale del token, nunca de un id enviado por el cliente."""
    user = db.get(User, auth.user_id)
    if user is None:
        raise APIError(401, "session_revoked", "La cuenta de esta sesión ya no existe.", {"WWW-Authenticate": "Bearer"})
    return user

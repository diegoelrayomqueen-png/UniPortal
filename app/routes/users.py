"""Endpoints del perfil del usuario autenticado."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.errors import APIError
from app.models import User
from app.schemas import ErrorResponse, ProfileUpdate, UserOut

router = APIRouter(prefix="/users", tags=["Perfil"])
_AUTH_ERRORS = {401: {"model": ErrorResponse, "description": "Token ausente, inválido, vencido o revocado."},
                403: {"model": ErrorResponse, "description": "Tipo de token no permitido."}}


@router.get("/profile", response_model=UserOut, summary="Consultar perfil",
            description="Devuelve el perfil del dueño del access token. No recibe ids: nadie puede consultar a otro usuario.",
            responses=_AUTH_ERRORS)
def get_profile(user: User = Depends(get_current_user)) -> User:
    """Perfil del usuario autenticado."""
    return user


@router.put("/profile", response_model=UserOut, summary="Actualizar perfil",
            description="Actualiza `full_name`. Cualquier otro campo (id, email, password_hash…) se rechaza con 422.",
            responses={**_AUTH_ERRORS, 422: {"model": ErrorResponse, "description": "Datos inválidos."}})
def update_profile(payload: ProfileUpdate, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)) -> User:
    """Actualiza los campos permitidos del usuario autenticado."""
    user.full_name = payload.full_name
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        raise APIError(500, "profile_update_failed", "No se pudo actualizar el perfil.") from exc
    return user

"""Errores de API y manejadores que dan un formato uniforme: {"detail": ..., "code": ...}."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("uniportal")

_STATUS_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
                 405: "method_not_allowed", 409: "conflict", 422: "validation_error", 429: "rate_limited"}


class APIError(Exception):
    """Error controlado con código HTTP, código interno estable y mensaje seguro para el usuario."""

    def __init__(self, status_code: int, code: str, detail: str, headers: dict[str, str] | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail
        self.headers = headers or {}


def error_response(status_code: int, code: str, detail, headers: dict[str, str] | None = None, **extra) -> JSONResponse:
    """Construye la respuesta JSON de error estándar."""
    return JSONResponse({"detail": detail, "code": code, **extra}, status_code=status_code, headers=headers)


def register_exception_handlers(app: FastAPI) -> None:
    """Registra los manejadores de excepciones de la aplicación."""

    @app.exception_handler(APIError)
    async def _api_error(_: Request, exc: APIError):
        """Responde con el código y mensaje de un APIError."""
        return error_response(exc.status_code, exc.code, exc.detail, exc.headers)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException):
        """Unifica los errores HTTP de Starlette (404, 405…) al formato estándar."""
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        return error_response(exc.status_code, code, str(exc.detail), getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        # Se omite `input` a propósito: podría contener la contraseña enviada.
        """Convierte los errores de Pydantic en 422 sin devolver los valores enviados."""
        errors = [
            {"field": ".".join(str(p) for p in e["loc"][1:]) or "body",
             "message": str(e["msg"]).removeprefix("Value error, ")}
            for e in exc.errors()
        ]
        return error_response(422, "validation_error", "Los datos enviados no son válidos.", errors=errors)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        """Captura cualquier excepción inesperada y responde 500 genérico."""
        logger.exception("Error no controlado: %s", type(exc).__name__)
        return error_response(500, "internal_error", "Ocurrió un error interno. Inténtalo más tarde.")

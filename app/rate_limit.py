"""Rate limiting en memoria (ventana deslizante).

LIMITACIÓN: el estado vive en la memoria de UN proceso. Con varias instancias/workers cada
una cuenta por separado; para producción multi-instancia usa Redis (p. ej. slowapi/redis).
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import Request

from app.config import get_settings
from app.errors import APIError


class RateLimiter:
    """Contador de eventos por clave dentro de una ventana de tiempo."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _prune(self, key: str, window: float, now: float) -> deque[float]:
        """Descarta los eventos que ya salieron de la ventana de tiempo."""
        events = self._events[key]
        while events and events[0] <= now - window:
            events.popleft()
        if not events:
            self._events.pop(key, None)
            return deque()
        return events

    def count(self, key: str, window: float) -> int:
        """Eventos registrados dentro de la ventana."""
        with self._lock:
            return len(self._prune(key, window, time.monotonic()))

    def retry_after(self, key: str, window: float) -> int:
        """Segundos hasta que se libere el evento más antiguo de la ventana."""
        with self._lock:
            now = time.monotonic()
            events = self._prune(key, window, now)
            return max(1, math.ceil(events[0] + window - now)) if events else 1

    def record(self, key: str) -> None:
        """Registra un evento ahora."""
        with self._lock:
            self._events[key].append(time.monotonic())

    def hit(self, key: str, limit: int, window: float) -> tuple[bool, int]:
        """Registra un evento si no se superó el límite. Devuelve (permitido, retry_after)."""
        with self._lock:
            now = time.monotonic()
            events = self._prune(key, window, now)
            if len(events) >= limit:
                return False, max(1, math.ceil(events[0] + window - now))
            self._events[key].append(now)
            return True, 0

    def clear(self, key: str) -> None:
        """Olvida los eventos de una clave."""
        with self._lock:
            self._events.pop(key, None)

    def reset(self) -> None:
        """Olvida todo (usado en pruebas)."""
        with self._lock:
            self._events.clear()


limiter = RateLimiter()


def _too_many(retry_after: int) -> APIError:
    """Construye el error 429 con la cabecera Retry-After."""
    return APIError(429, "rate_limited", f"Demasiados intentos. Inténtalo de nuevo en {retry_after} s.",
                    headers={"Retry-After": str(retry_after)})


def rate_limit(scope: str, limit: int, window_seconds: int):
    """Crea una dependencia de FastAPI que limita `limit` solicitudes por IP y ventana."""

    def dependency(request: Request) -> None:
        """Aplica el límite de solicitudes por IP."""
        if not get_settings().rate_limit_enabled:
            return
        ip = request.client.host if request.client else "unknown"
        allowed, retry = limiter.hit(f"{scope}:ip:{ip}", limit, window_seconds)
        if not allowed:
            raise _too_many(retry)

    return dependency


def ensure_not_blocked(key: str, max_failures: int, window_seconds: int) -> None:
    """Lanza 429 si la clave acumuló demasiados fallos recientes (control de fuerza bruta)."""
    if get_settings().rate_limit_enabled and limiter.count(key, window_seconds) >= max_failures:
        raise _too_many(limiter.retry_after(key, window_seconds))


def record_failure(key: str) -> None:
    """Anota un intento fallido para `key`."""
    limiter.record(key)


def clear_failures(key: str) -> None:
    """Borra los fallos de `key` (tras un acceso correcto)."""
    limiter.clear(key)

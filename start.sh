#!/usr/bin/env bash
# Arranque para despliegue (Render/Railway). Local: uvicorn app.main:app --reload
set -euo pipefail
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" \
  --proxy-headers --forwarded-allow-ips="*"

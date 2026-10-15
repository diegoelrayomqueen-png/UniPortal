# UniPortal — Portal de estudiantes con FastAPI, OTP por correo y JWT

## 1. Descripción
UniPortal es un portal web de estudiantes con **autenticación de dos factores**: contraseña + código OTP de 6 dígitos enviado al correo. Tras verificar el OTP el servidor entrega **JWT** (acceso y renovación) y las sesiones son **revocables** de verdad (se guardan en la base de datos).

El portal no inventa datos académicos (notas, horarios, pagos): se centra en identidad, perfil y seguridad de la cuenta, que es lo que exige el parcial.

## 2. Funcionalidades implementadas
- Registro con validación de correo y contraseña (frontend **y** backend), correo único, hash bcrypt.
- Login en dos pasos: credenciales → OTP por correo → tokens.
- OTP: 6 dígitos (`secrets`), vence en ≤ 15 min, un solo uso, máx. 5 intentos, reenvío con espera de 60 s y tope de 5 códigos por login; se guarda **hasheado**.
- JWT de acceso (15 min) y de renovación (7 días) con rotación y detección de reutilización.
- Middleware real (`app/middleware.py`) que valida el token **y** que la sesión siga activa en la BD.
- Perfil: consultar y editar el nombre; no se pueden tocar campos privilegiados.
- Logout que revoca la sesión en el servidor.
- Rate limiting en registro, login, verify-otp, resend-otp y refresh + bloqueo por fallos repetidos.
- Frontend responsive (HTML/CSS/JS nativo): inicio, registro, login, verificación OTP con reenvío, panel, perfil, seguridad y pantallas de error (acceso denegado, sesión vencida, error de conexión).
- Swagger UI con descripciones y ejemplos de los 8 endpoints.

## 3. Tecnologías
Python 3.12 · FastAPI · SQLAlchemy 2 · SQLite · Pydantic v2 · PyJWT · bcrypt · smtplib · Uvicorn · pytest + TestClient · HTML5/CSS3/JavaScript nativo.

## 4. Requisitos previos
- Python 3.10 o superior (desarrollado y probado con 3.12).
- Una cuenta de correo con SMTP para enviar OTP reales (opcional en desarrollo).

## 5–7. Instalación paso a paso
```bash
cd uniportal
python3 -m venv .venv                 # crear entorno virtual
source .venv/bin/activate             # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -r requirements.txt       # instalar dependencias
cp .env.example .env                  # Windows: copy .env.example .env
```

## 8. Configurar el archivo `.env`
Edita `.env`. Lo esencial:

| Variable | Para qué sirve |
|---|---|
| `JWT_SECRET_KEY` | Clave que firma los JWT (≥ 32 caracteres). Genera una: `python -c "import secrets; print(secrets.token_urlsafe(64))"` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` / `REFRESH_TOKEN_EXPIRE_DAYS` | Duración de los tokens (15 min / 7 días). |
| `SESSION_MAX_DAYS` | Tope absoluto de una sesión aunque se renueve (30). |
| `DATABASE_URL` | SQLite. Las rutas relativas se resuelven **desde la carpeta del proyecto**, no desde donde ejecutes. |
| `OTP_EXPIRE_MINUTES` | Vigencia del OTP (máximo permitido: 15; valores mayores se recortan). |
| `EMAIL_BACKEND` | `smtp` (real) o `console` (solo desarrollo: imprime el OTP en la terminal; **prohibido en producción**). |
| `SMTP_*` | Servidor, puerto, usuario, contraseña, remitente y seguridad (`starttls`/`ssl`). |
| `ENVIRONMENT` | `development`, `test` o `production`. En producción la app **se niega a arrancar** con configuración insegura. |
| `ALLOWED_ORIGINS` | CORS. Vacío = solo mismo origen (el frontend ya se sirve desde la misma app). |

El archivo `.env` está en `.gitignore`: nunca lo subas al repositorio.

## 9. Configurar SMTP (ejemplo Gmail)
1. Activa la verificación en dos pasos en tu cuenta de Google.
2. Crea una **contraseña de aplicación** (Cuenta de Google → Seguridad → Contraseñas de aplicaciones).
3. En `.env`:
```
EMAIL_BACKEND=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USER=tu_correo@gmail.com
SMTP_PASSWORD=la-contraseña-de-aplicación
SMTP_FROM=UniPortal <tu_correo@gmail.com>
```
Si el correo falla, `/auth/login` responde **503** y no deja ningún OTP utilizable.

## 10–12. Ejecución local
```bash
uvicorn app.main:app --reload
```
- Frontend: <http://127.0.0.1:8000/>
- Swagger UI: <http://127.0.0.1:8000/docs> (ReDoc en `/redoc`)
- Salud del servicio: <http://127.0.0.1:8000/health>

Sin SMTP y con `EMAIL_BACKEND=console`, el OTP aparece en la terminal donde corre Uvicorn (solo en desarrollo).

En Swagger: haz `POST /auth/login`, copia el `challenge_token`, llama a `/auth/verify-otp` con ese token y el código, y pega el `access_token` en **Authorize**. Para `/auth/refresh` pega el `refresh_token`.

## 13. Pruebas
```bash
pytest
```
Usan una base SQLite temporal propia, un correo simulado (nunca sale un email real) y reinician el rate limiter entre pruebas. Cubren los 5 casos unitarios y 3 de integración exigidos, más seguridad adicional (ver `docs/CHECKLIST_REQUISITOS.md`).

## 14. Estructura de la base de datos
```
users (id PK, email UNIQUE, password_hash, full_name, created_at, updated_at)
  ├─< otp_codes (id PK, user_id FK, code, expires_at, used, created_at,
  │              + purpose, attempts, challenge_id)
  └─< login_sessions (id PK, user_id FK, token, expires_at, created_at,
                      + session_id UNIQUE, max_expires_at)
```
- Los campos marcados con `+` son los **únicos añadidos** a los que exige el parcial.
- `otp_codes.code` guarda un HMAC-SHA256 del OTP (no el código). `login_sessions.token` guarda el SHA-256 del refresh token vigente.
- Claves foráneas con `ON DELETE CASCADE` (activadas con `PRAGMA foreign_keys=ON`). Índices en `email`, `user_id`, `session_id`, `challenge_id`.

## 15. Flujo de autenticación
```
Registro ──► POST /auth/register (201)
Login    ──► POST /auth/login {email, password}
              ├─ valida credenciales → crea OTP → envía correo
              └─ 202 + challenge_token (NO hay sesión todavía)
OTP      ──► POST /auth/verify-otp {challenge_token, code}
              └─ 200 + access_token + refresh_token (se crea la fila en login_sessions)
Uso      ──► Authorization: Bearer <access_token>  → /users/profile
Renovar  ──► POST /auth/refresh  (Bearer <refresh_token>) → tokens nuevos
Salir    ──► POST /auth/logout   (Bearer <access_token>) → se borra la sesión
```
El `challenge_token` (JWT tipo `otp_challenge`, 15 min) es la prueba de que la contraseña fue correcta. Por eso `verify-otp` y `resend-otp` lo exigen: **sin él no se puede pedir ni adivinar un OTP**, es decir, el reenvío no permite saltarse la contraseña.

## 16. Los OTP
- Generación: `secrets.randbelow(10**6)` con relleno de ceros (`"038271"`). Se trata siempre como texto.
- Validez: `OTP_EXPIRE_MINUTES` (por defecto 15, tope 15), comprobada en el servidor.
- Almacenamiento: HMAC-SHA256 con la clave secreta, ligado a usuario y login.
- Un solo uso: se consume con un `UPDATE ... WHERE used = false` atómico.
- Intentos: 5 por código; luego `429` y hay que pedir uno nuevo.
- Reenvío: espera de 60 s, máx. 5 códigos por login; el código nuevo invalida el anterior **cuando el correo realmente salió**.
- El OTP nunca aparece en respuestas ni en logs de producción.

## 17. JWT, expiración y renovación
| | Access token | Refresh token |
|---|---|---|
| Para qué | Llamar a la API | Solo `POST /auth/refresh` |
| Duración | 15 min | 7 días (nunca más allá de `SESSION_MAX_DAYS`) |
| Claims | `sub`, `exp`, `iat`, `jti`, `type=access`, `sid` | ídem con `type=refresh` |
| En la BD | No se guarda (se valida la sesión `sid`) | Solo su SHA-256 |

- Firma HS256 con `JWT_SECRET_KEY` (variable de entorno); solo se aceptan HS256/384/512, nunca `none`.
- **Rotación**: cada renovación emite un refresh token nuevo y el anterior deja de servir. Si alguien reutiliza uno viejo (señal de robo) se **revoca toda la sesión**.
- Tope absoluto: aunque se renueve, la sesión muere en `max_expires_at`.
- Usar el tipo equivocado de token en una ruta devuelve **403**.

## 18. Middleware
`app/middleware.py` → `AuthMiddleware` intercepta solo estas rutas:
`POST /auth/refresh` (exige refresh), `POST /auth/logout`, `GET /users/profile`, `PUT /users/profile` (exigen access).
Pasos: leer `Authorization: Bearer` → decodificar y validar firma/expiración → comprobar tipo → buscar la sesión (`sid`) en `login_sessions` y verificar que exista y no haya vencido → (refresh) comparar el hash con el vigente → guardar el resultado en `request.state.auth`. Cualquier fallo corta la petición con 401/403 antes de llegar a la ruta. Las rutas públicas (`register`, `login`, `verify-otp`, `resend-otp`) no pasan por esta validación. Además `SecurityHeadersMiddleware` añade CSP, `X-Frame-Options`, `nosniff` y `Cache-Control: no-store` en la API.

## 19. Revocación de sesiones
Una sesión es una fila de `login_sessions`. **Logout = borrar esa fila.** Como el middleware consulta la fila en cada petición, el access y el refresh token de esa sesión dejan de funcionar al instante, aunque no hayan vencido. El frontend además limpia sus credenciales y redirige a `/login.html`.

## 20. Códigos HTTP y errores habituales
Todos los errores tienen la forma `{"detail": "...", "code": "..."}`.

| Código | Cuándo |
|---|---|
| 200 | Verificación OTP, refresh, logout, perfil correctos |
| 201 | Registro creado |
| 202 | Login/reenvío aceptado: OTP enviado, falta verificar |
| 400 | OTP incorrecto, vencido o ya usado (`otp_invalid`, `otp_expired`, `otp_used`) |
| 401 | Credenciales incorrectas; token ausente, malformado, vencido (`token_expired`) o revocado (`session_revoked`); `refresh_reuse`; desafío OTP inválido |
| 403 | Token válido pero del tipo equivocado (`wrong_token_type`) |
| 404 | Ruta inexistente |
| 409 | Correo ya registrado |
| 422 | Datos inválidos (nunca se devuelve la contraseña enviada) |
| 429 | Rate limit, bloqueo por fallos, OTP bloqueado o reenvío demasiado pronto (cabecera `Retry-After`) |
| 500 | Error interno (mensaje genérico; el detalle va solo al log) |
| 503 | No se pudo enviar el correo |

## 21. Despliegue
### Hallazgo importante sobre el proveedor
Según el anuncio oficial de Render (16/09/2025), los servicios **gratuitos bloquean la salida a los puertos SMTP 25, 465 y 587**, y su sistema de archivos es efímero (SQLite se reiniciaría en cada despliegue). Los discos persistentes requieren plan de pago. Verifica estas condiciones en la documentación de Render antes de desplegar, porque pueden haber cambiado.

### Opción principal: Render (plan Starter + disco de 1 GB)
Con el plan de pago se desbloquean 465/587 y el disco conserva la base de datos. El repositorio incluye `render.yaml`.
1. Sube el proyecto a GitHub (`.env` y `*.db` ya están excluidos).
2. En Render: **New → Blueprint** → elige el repositorio. Crea el servicio `uniportal` con disco en `/var/data`.
3. Completa las variables marcadas como secretas: `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (`JWT_SECRET_KEY` se genera sola).
4. Comando de inicio (ya configurado): `./start.sh` → `uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"`.
5. `DATABASE_URL=sqlite:////var/data/uniportal.db` (4 barras = ruta absoluta en el disco persistente). Las tablas se crean solas al arrancar.
6. El frontend lo sirve la misma app (carpeta `app/static`), no hace falta otro servicio.

### Alternativa gratuita (solo demostración)
En el plan gratuito usa un proveedor SMTP con puerto **2525** (Brevo, Mailgun, SendGrid lo ofrecen) con `SMTP_PORT=2525` y `SMTP_SECURITY=starttls`; el puerto 2525 no está en la lista de bloqueados, pero **no lo he probado**. La base de datos se perderá en cada reinicio o despliegue: tendrás que registrarte de nuevo antes de la demostración.

### Logs y verificación
- Logs: panel de Render → pestaña **Logs** (los errores SMTP aparecen como `Fallo al enviar correo OTP (<tipo>)`, sin secretos ni códigos).
- Comprobar: abrir `https://TU-SERVICIO.onrender.com/health` → `{"status":"ok"}`; luego `/docs` y un registro + login completo recibiendo el correo real.
- Otras plataformas: Railway y PythonAnywhere sirven si la plataforma permite SMTP saliente en tu plan; el comando de inicio y las variables son las mismas.

## 22. Limitaciones conocidas y decisiones técnicas
- **Rate limiting en memoria**: cuenta por proceso. Con varias instancias o workers cada una cuenta aparte (y se reinicia al reiniciar). Para escalar, usar Redis.
- **SQLite**: una sola instancia de escritura; adecuado para este parcial, no para alta concurrencia.
- **Tokens en `sessionStorage`**: se borran al cerrar la pestaña, pero un ataque XSS podría leerlos. Se mitiga con CSP estricta (`script-src 'self'`) y escribiendo siempre con `textContent`. Alternativa más robusta: refresh token en cookie `HttpOnly` (requeriría protección CSRF).
- **Bloqueo de login por correo** (5 fallos/15 min): protege contra fuerza bruta, pero permite que un atacante bloquee temporalmente a una víctima. Es un compromiso habitual.
- **Registro revela duplicados** (409), como exige el parcial; el login, en cambio, no revela si un correo existe.
- Las páginas HTML son públicas; lo protegido son los **datos** (la API). El JS redirige al login si no hay sesión, pero la seguridad real está en el backend.
- No hay recuperación de contraseña ni cambio de contraseña (no están en los requisitos).
- Endpoint extra `GET /health` para comprobar el despliegue.
- Se usa HMAC del OTP en lugar de PyOTP porque el OTP aleatorio de un solo uso con expiración propia cumple el requisito sin dependencias extra.

## Guía de sustentación
Ver [`docs/GUIA_SUSTENTACION.md`](docs/GUIA_SUSTENTACION.md). Trazabilidad requisito → archivo → prueba en [`docs/CHECKLIST_REQUISITOS.md`](docs/CHECKLIST_REQUISITOS.md).

# Guía de sustentación — UniPortal

> Esta guía es para **estudiar y explicar con tus palabras**. No contiene contribuciones ni commits inventados: si trabajaron en equipo, anota tú qué parte hizo cada integrante.

## 1. Arquitectura en una frase
Una API **FastAPI** con tres capas — *rutas* (`app/routes`) que reciben HTTP, *servicios* (`app/services`) con la lógica (OTP, tokens, correo, contraseñas) y *modelos* (`app/models.py`) sobre SQLite — protegida por un **middleware** que valida el JWT y la sesión; el *frontend* estático (`app/static`) consume esa misma API.

```
Navegador ──► [SecurityHeaders] ─► [CORS?] ─► [AuthMiddleware] ─► routes ─► services ─► SQLite
```

## 2. Flujo completo: registro → portal
1. `POST /auth/register`: Pydantic valida (correo, contraseña) → se busca duplicado (409) → `hash_password` (bcrypt) → INSERT en `users`.
2. `POST /auth/login`: se compara la contraseña con el hash. Si falla: 401 genérico. Si acierta: se crea un OTP (`create_otp_row`), se envía el correo (`send_otp_email`), se confirma (`finalize_otp`) y se devuelve el `challenge_token` (**sin sesión**).
3. `POST /auth/verify-otp`: valida el `challenge_token`, luego el OTP (`verify_otp`: existe, no usado, no vencido, intentos, coincide). Si todo bien: `create_session` inserta en `login_sessions` y devuelve access + refresh.
4. El navegador guarda los tokens y llama `GET /users/profile` con `Authorization: Bearer`.
5. `refresh` renueva; `logout` borra la sesión.

## 3. Hash de contraseñas (`password_service.py`)
- bcrypt = función **lenta y con sal aleatoria**: dos hashes de la misma contraseña son distintos y probar millones de contraseñas es caro.
- `hash_password` → `bcrypt.hashpw`; `verify_password` → `bcrypt.checkpw`. Nunca se guarda ni se loguea la contraseña.
- Límite de 72 bytes de bcrypt: la política lo valida (no se trunca en silencio).
- Para que "usuario inexistente" y "contraseña mala" tarden lo mismo se compara contra `dummy_hash()` (evita *user enumeration* por tiempo).

## 4. OTP (`otp_service.py`)
- **Generación**: `secrets.randbelow(10**6)` → CSPRNG, 6 dígitos con ceros a la izquierda (es `str`).
- **Almacenamiento**: HMAC-SHA256(clave, `user:challenge:code`). Si roban la BD, no ven códigos.
- **Expiración**: `expires_at = ahora + OTP_EXPIRE_MINUTES` (tope 15). Se comprueba en el servidor.
- **Un solo uso**: `UPDATE ... WHERE used = 0` atómico; si `rowcount != 1` otro lo gastó antes.
- **Fuerza bruta**: contador `attempts` (UPDATE atómico); 5 fallos → 429.
- **Reenvío**: `check_can_resend` (espera 60 s, máx. 5 códigos); el nuevo invalida al viejo solo si el correo salió.

## 5. JWT (`token_service.py`)
Estructura: `header.payload.firma`. Claims: `sub` (id usuario), `exp`, `iat`, `jti` (id único), `type` (`access`/`refresh`/`otp_challenge`), `sid` (id de sesión).
`decode_token` exige `exp, iat, sub, jti, type`, fija el algoritmo permitido (evita `alg: none`) y distingue *vencido* de *inválido*. Clave en `JWT_SECRET_KEY` (variable de entorno).
**Access vs refresh**: el access (15 min) abre la API; el refresh (7 días) solo sirve para pedir tokens nuevos y **rota** en cada uso.

## 6. Middleware (`middleware.py`)
`AuthMiddleware.dispatch` mira `(método, ruta)` en `PROTECTED_ROUTES`. Si es protegida: extrae el Bearer → `_authenticate` (decodifica, compara tipo, busca la sesión en BD, revisa vencimiento y, para refresh, el hash) → guarda `request.state.auth`. Si falla devuelve 401/403 y **la ruta nunca se ejecuta**. La BD se consulta en un hilo (`run_in_threadpool`) para no bloquear el servidor.

## 7. Rate limiting (`rate_limit.py`)
Ventana deslizante en memoria: lista de marcas de tiempo por clave. Límites por IP: register 5/min, login 10/min, verify-otp 10/min, resend-otp 5/min, refresh 30/min. Además: 5 logins fallidos/15 min por correo, 5 intentos por OTP. Respuesta 429 con `Retry-After`. Limitación: solo vale para un proceso.

## 8. Tablas
- `users`: cuenta. `email` UNIQUE.
- `otp_codes`: N por usuario. Extras: `purpose`, `attempts`, `challenge_id`.
- `login_sessions`: N por usuario (una por login). Extras: `session_id` (= claim `sid`), `max_expires_at`.
Relaciones 1-a-N con `ON DELETE CASCADE`.

## 9. Revocar una sesión
`revoke_session` hace `DELETE FROM login_sessions WHERE session_id = ?`. El middleware consulta esa fila en **cada** petición ⇒ sin fila no hay acceso, aunque el JWT esté "vigente". Esto es lo que diferencia un logout real de "borrar el token del navegador".

## 10. Los 8 endpoints
| Endpoint | Archivo → función | Idea clave |
|---|---|---|
| POST `/auth/register` | `routes/auth.py` → `register` | 201, 409 duplicado, bcrypt |
| POST `/auth/login` | `login` | Valida contraseña, envía OTP, 202 + challenge (sin sesión) |
| POST `/auth/verify-otp` | `verify_otp` | OTP válido ⇒ crea sesión y tokens |
| POST `/auth/refresh` | `refresh` → `token_service.rotate_session` | Rota refresh; reutilización ⇒ revoca |
| POST `/auth/logout` | `logout` → `revoke_session` | Borra la sesión |
| GET `/users/profile` | `routes/users.py` → `get_profile` | Usuario sale del token, no de un id |
| PUT `/users/profile` | `update_profile` | Solo `full_name`; resto ⇒ 422 |
| POST `/auth/resend-otp` | `resend_otp` | Requiere challenge ⇒ no salta la contraseña |

## 11. Dónde está cada cosa
Config: `config.py` · BD: `database.py` · modelos: `models.py` · esquemas: `schemas.py` · errores uniformes: `errors.py` · correo: `services/email_service.py` · dependencias (usuario actual): `dependencies.py` · arranque/frontend: `main.py`.

## 12. Posibles preguntas del profesor
1. **¿Por qué bcrypt y no SHA-256?** SHA-256 es rapidísimo (malo para contraseñas); bcrypt es deliberadamente lento y trae sal.
2. **¿Qué pasa si roban la base de datos?** Contraseñas con bcrypt, OTP como HMAC, refresh tokens como SHA-256: no hay secretos utilizables en claro.
3. **¿Por qué el OTP usa `secrets` y no `random`?** `random` es predecible (Mersenne Twister); `secrets` usa el CSPRNG del sistema.
4. **¿Cómo evitas que reenviar OTP salte la contraseña?** `resend-otp`/`verify-otp` exigen el `challenge_token`, que solo se entrega tras validar la contraseña.
5. **¿Cuál es la diferencia entre access y refresh token?** Duración y uso; el refresh solo renueva y rota; si se reutiliza uno viejo se revoca la sesión.
6. **¿Qué impide usar un JWT después del logout?** El middleware verifica que la sesión exista en `login_sessions`; el logout la borra.
7. **¿Cómo evitas que un usuario vea el perfil de otro?** Las rutas no reciben ids; el usuario sale del `sub` del token ya validado. El PUT rechaza `id`, `email`, `password_hash`.
8. **¿Qué hace el rate limiting y qué limitación tiene?** Frena abuso por IP/correo; vive en memoria de un proceso (con varias instancias habría que usar Redis).
9. **¿Qué código HTTP usas para token vencido y para tipo equivocado?** 401 (`token_expired`) y 403 (`wrong_token_type`).
10. **¿Por qué el login devuelve 202?** Porque la petición fue aceptada pero el proceso no terminó: falta el OTP.
11. **¿Qué pasa si el SMTP falla?** 503, se descarta el OTP y no queda un código válido; el error se registra sin el código.
12. **¿Por qué la BD usa ruta absoluta?** Para no crear una BD distinta según el directorio de ejecución y perder datos.
13. **¿Por qué el frontend no basta para la seguridad?** Todo lo decisivo (contraseñas, OTP, tokens, límites) se vuelve a validar en el backend.
14. **¿Qué es el claim `jti`/`sid`?** `jti` identifica el token; `sid` liga el token a su fila de sesión.

## 13. Demostraciones en vivo (sugeridas)
1. `pytest` → todo en verde.
2. Swagger `/docs`: register → login (llega el correo) → verify-otp → Authorize → GET profile.
3. PUT profile con `{"full_name": "X", "id": 99}` ⇒ 422.
4. Copiar el access token, hacer logout, repetir GET profile ⇒ 401 `session_revoked`.
5. Usar el refresh token como access en `/users/profile` ⇒ 403.
6. Equivocar el OTP 5 veces ⇒ 429.
7. Mostrar en SQLite (`sqlite3 data/uniportal.db "select id,user_id,length(token),expires_at from login_sessions;"`) que solo hay hashes.
8. Si desplegaste: abrir `/health` en la URL pública.

## 14. Qué problema evita cada medida
| Medida | Ataque que evita |
|---|---|
| bcrypt con sal | Robo de BD / tablas arcoíris / fuerza bruta offline |
| Mensaje genérico + hash falso | Enumeración de usuarios |
| OTP con `secrets`, 6 dígitos, 15 min máx., un solo uso | Predicción, reutilización, ventana larga |
| `attempts` + 429 | Adivinar el OTP |
| `challenge_token` | Saltarse la contraseña vía reenvío/verificación |
| HMAC del OTP / hash del refresh | Filtración de secretos desde la BD |
| JWT firmado + `exp` + tipo | Falsificación y uso fuera de contexto |
| Sesión en BD + middleware | Tokens "zombis" tras logout |
| Rotación + detección de reutilización | Robo de refresh token |
| `max_expires_at` | Renovación infinita |
| Rate limit | Fuerza bruta y spam de correos |
| `extra="forbid"` en el PUT | Mass assignment (cambiar campos privilegiados) |
| CSP + `textContent` | XSS |
| `.env` en `.gitignore`, `console` prohibido en producción | Fuga de secretos / OTP en logs |

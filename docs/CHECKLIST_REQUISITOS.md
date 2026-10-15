# Trazabilidad: requisito → implementación → prueba

> Elaborada a partir del texto del prompt maestro. El PDF `PARCIAL_FASTAPI_OTP.pdf` **no estaba adjunto**, así que conviene contrastar esta tabla con el PDF original.

| Requisito | Dónde se implementa | Prueba que lo demuestra |
|---|---|---|
| POST `/auth/register` (201, 409) | `routes/auth.py::register` | `test_register_creates_user_without_exposing_secrets_and_rejects_duplicates` |
| Validación de correo/contraseña en backend | `schemas.py`, `password_service.check_password_policy` | `test_register_schema_validates_email_and_lowercases`, `test_password_policy_rejects_weak_passwords` |
| Solo hash de contraseña (bcrypt) | `password_service.py`, `models.User.password_hash` | `test_password_hashing_and_verification`, integración de registro |
| POST `/auth/login` solo envía OTP tras validar credenciales | `routes/auth.py::login` | `test_login_sends_otp_and_only_verification_grants_tokens`, `test_wrong_password_unknown_user_and_reused_otp_are_rejected` |
| OTP 6 dígitos, CSPRNG | `otp_service.generate_otp_code` | `test_otp_has_exactly_six_digits_and_keeps_leading_zeros` |
| OTP ≤ 15 min | `config.py` (tope), `otp_service.create_otp_row` | `test_otp_is_stored_hashed_and_expires_within_15_minutes`, `test_otp_validity_is_clamped_to_15_minutes` |
| OTP vencido rechazado | `otp_service.verify_otp` | `test_expired_otp_is_rejected`, `test_expired_otp_is_rejected_via_api` |
| OTP de un solo uso | `otp_service.verify_otp` (UPDATE atómico) | `test_used_otp_cannot_be_reused` |
| Intentos limitados | `otp_service.verify_otp` | `test_wrong_otp_counts_attempts_and_locks`, `test_wrong_otp_is_rejected_then_locked_after_too_many_attempts` |
| POST `/auth/verify-otp` → JWT | `routes/auth.py::verify_otp` | `test_login_sends_otp_and_only_verification_grants_tokens` |
| POST `/auth/resend-otp` con espera y sin saltar contraseña | `routes/auth.py::resend_otp`, `otp_service.check_can_resend` | `test_resend_otp_requires_challenge_cooldown_and_invalidates_old_code`, `test_resend_is_impossible_with_an_access_token_or_after_login_completed` |
| JWT con exp/iat/jti/sub/type, clave por entorno | `token_service.py`, `config.py` | `test_access_token_roundtrip_and_claims`, `test_expired_tampered_and_wrong_type_tokens_are_rejected`, `test_token_signed_with_other_key_or_alg_none_is_rejected` |
| Middleware independiente `app/middleware.py` | `AuthMiddleware` | `test_profile_requires_valid_access_token` |
| 401 sin/inválido/vencido/revocado; 403 tipo incorrecto | `middleware.py` | `test_profile_requires_valid_access_token`, `test_logout_revokes_session_for_access_and_refresh_tokens` |
| POST `/auth/refresh` (rotación, sin extender sin límite) | `routes/auth.py::refresh`, `token_service.rotate_session` | `test_refresh_rotates_tokens_and_reuse_revokes_the_session`, `test_refresh_cannot_extend_session_beyond_absolute_limit` |
| POST `/auth/logout` revoca en servidor | `token_service.revoke_session` | `test_logout_revokes_session_for_access_and_refresh_tokens` |
| GET/PUT `/users/profile`, sin tocar campos privilegiados | `routes/users.py`, `schemas.ProfileUpdate` | `test_profile_update_only_changes_allowed_fields`, `test_profile_update_normalizes_name_and_rejects_privileged_fields` |
| Un usuario no accede a otro | `dependencies.get_current_user` | `test_users_cannot_read_or_modify_each_others_profile` |
| Tablas `users`, `otp_codes`, `login_sessions` | `models.py` | todas las pruebas de integración |
| Rate limiting en endpoints críticos | `rate_limit.py` | `test_register_is_rate_limited_per_ip`, `test_verify_otp_endpoint_is_rate_limited`, `test_login_locks_an_email_after_repeated_failures_even_with_the_right_password` |
| Correo con `smtplib`, config por entorno, sin enviar en pruebas | `services/email_service.py` | `test_smtp_sender_uses_starttls_login_and_never_leaks_code_in_logs`, `test_smtp_failure_raises_delivery_error_without_secrets` |
| Fallo de correo controlado | `routes/auth.py::_deliver_otp` | `test_email_failure_returns_503_and_leaves_no_usable_otp` |
| OTP no visible en producción | `email_service`, `config.validate_settings` | `test_console_backend_is_refused_in_production`, `test_production_settings_require_strong_secret_and_smtp` |
| Errores uniformes, sin eco de contraseñas | `errors.py` | `test_register_validation_errors_do_not_echo_the_password`, `test_error_format_security_headers_and_frontend_are_served` |
| `.env.example`, `.gitignore` | raíz del proyecto | revisión manual |
| Frontend: 10 pantallas obligatorias | `app/static/*.html`, `js/*.js` | `test_error_format_security_headers_and_frontend_are_served` + recorrido E2E en navegador simulado (jsdom), ver README |
| Swagger con ejemplos | `schemas.py` (`json_schema_extra`), `routes/*` | `test_error_format_security_headers_and_frontend_are_served` (openapi) |
| Despliegue | `render.yaml`, `start.sh`, README §21 | **No ejecutado** (ver README) |

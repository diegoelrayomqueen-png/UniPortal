"""Envío del correo con el OTP mediante smtplib."""
from __future__ import annotations

import html
import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import get_settings

logger = logging.getLogger("uniportal")
SMTP_TIMEOUT_SECONDS = 15


class EmailDeliveryError(Exception):
    """No se pudo entregar el correo (configuración, red o rechazo del servidor SMTP)."""


def build_otp_message(to_email: str, full_name: str, code: str) -> EmailMessage:
    """Arma el correo (texto + HTML) con portal, código, validez máxima y advertencia."""
    settings = get_settings()
    portal, minutes = settings.portal_name, settings.otp_expire_minutes
    msg = EmailMessage()
    msg["Subject"] = f"{portal}: tu código de verificación"
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg.set_content(
        f"Hola {full_name},\n\nTu código de verificación de {portal} es: {code}\n\n"
        f"Vence en {minutes} minutos (validez máxima: 15 minutos) y solo puede usarse una vez.\n"
        "No compartas este código con nadie: el personal de la universidad nunca te lo pedirá.\n"
        "Si no intentaste iniciar sesión, ignora este mensaje y cambia tu contraseña.\n")
    msg.add_alternative(
        f"""<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#1c2736">
<h2 style="color:#0b1f3a">{html.escape(portal)}</h2>
<p>Hola {html.escape(full_name)}, usa este código para completar tu inicio de sesión:</p>
<p style="font-size:34px;letter-spacing:8px;font-weight:bold;background:#f4f6fa;padding:16px;text-align:center;border-radius:8px">{code}</p>
<p>Vence en <b>{minutes} minutos</b> (validez máxima: 15 minutos). Solo puede usarse una vez.</p>
<p style="color:#b3261e"><b>No compartas este código con nadie.</b></p>
<p style="color:#5d6b80;font-size:13px">Si no intentaste iniciar sesión, ignora este mensaje.</p></div>""",
        subtype="html")
    return msg


def send_otp_email(to_email: str, full_name: str, code: str) -> None:
    """Envía el OTP. Lanza EmailDeliveryError si falla. Nunca registra el código en producción."""
    settings = get_settings()
    if settings.email_backend == "console":
        if settings.is_production:
            raise EmailDeliveryError("El backend 'console' no está permitido en producción.")
        logger.warning("[DESARROLLO] OTP para %s: %s", to_email, code)
        return
    message = build_otp_message(to_email, full_name, code)
    context = ssl.create_default_context()
    try:
        if settings.smtp_security == "ssl":
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_SECONDS, context=context)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_SECONDS)
        with server:
            if settings.smtp_security == "starttls":
                server.starttls(context=context)
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Fallo al enviar correo OTP (%s)", type(exc).__name__)  # sin código ni credenciales
        raise EmailDeliveryError("No se pudo enviar el correo.") from exc

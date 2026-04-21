from __future__ import annotations

import logging
import smtplib
from collections.abc import Mapping
from email.message import EmailMessage

from flask import current_app

logger = logging.getLogger(__name__)

_PLACEHOLDER_USERPASS = frozenset(
    {
        'your-email@gmail.com',
        'your-app-password',
        'replace-this-secret',
        'changeme',
        'password',
    }
)


def smtp_configured_for_config(cfg: Mapping) -> bool:
    """Same rules as :func:`smtp_configured`, but reads from a plain config mapping (no app context)."""
    server = (cfg.get('SMTP_SERVER') or '').strip()
    from_email = (cfg.get('SMTP_FROM_EMAIL') or '').strip()
    port = cfg.get('SMTP_PORT')
    if not server or not from_email or not port:
        return False
    if cfg.get('SMTP_ALLOW_NO_AUTH'):
        return True
    username = (cfg.get('SMTP_USERNAME') or '').strip()
    password = (cfg.get('SMTP_PASSWORD') or '').strip()
    if not username or not password:
        return False
    if username.lower() in _PLACEHOLDER_USERPASS or password.lower() in _PLACEHOLDER_USERPASS:
        return False
    return True


def smtp_configured() -> bool:
    """True only when all required SMTP settings are present for authenticated relay (typical Gmail/workspace).

    Partial placeholder values from a copied .env are treated as *not* configured so OTP can fall back to
    OTP_DEV_MODE instead of failing an SMTP handshake with dummy credentials.
    """
    return smtp_configured_for_config(current_app.config)


def send_login_otp(recipient_email: str, username: str, otp_code: str) -> tuple[bool, str]:
    expiry_seconds = int(current_app.config.get('OTP_EXPIRY_SECONDS', 300))
    expiry_minutes = max(1, expiry_seconds // 60)
    cfg = current_app.config
    dev = bool(cfg.get('OTP_DEV_MODE') or current_app.testing)

    if not smtp_configured():
        if dev:
            return (
                True,
                'Local dev OTP mode: email was not sent. Use the code on the next screen and/or the server log.',
            )
        return False, (
            'Misconfigured: real email OTP is off because SMTP is incomplete or still has placeholder values, '
            'and OTP_DEV_MODE is not enabled. Fix one of these: (1) Put a .env file next to run.py with '
            'OTP_DEV_MODE=true for local testing, or (2) Set SMTP_SERVER, SMTP_PORT, SMTP_FROM_EMAIL, '
            'SMTP_USERNAME, and SMTP_PASSWORD to real values and keep OTP_DEV_MODE=false.'
        )

    message = EmailMessage()
    message['Subject'] = f"{current_app.config.get('APP_NAME', 'Homelab Vault')} login OTP"
    message['From'] = current_app.config['SMTP_FROM_EMAIL']
    message['To'] = recipient_email
    message.set_content(
        f"Hello {username},\n\n"
        f"Your login verification code is: {otp_code}\n"
        f"It expires in about {expiry_minutes} minute(s).\n\n"
        "If you did not start this login, you can ignore this email.\n"
    )

    host = current_app.config['SMTP_SERVER']
    port = int(current_app.config['SMTP_PORT'])
    username_cfg = current_app.config.get('SMTP_USERNAME')
    password_cfg = current_app.config.get('SMTP_PASSWORD')
    use_tls = bool(current_app.config.get('SMTP_USE_TLS'))
    use_ssl = bool(current_app.config.get('SMTP_USE_SSL'))

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        with server:
            if use_tls and not use_ssl:
                server.starttls()
            if username_cfg and password_cfg:
                server.login(username_cfg, password_cfg)
            server.send_message(message)
        return True, 'OTP sent successfully.'
    except Exception as exc:  # pragma: no cover - depends on external SMTP
        logger.exception('SMTP send failed for OTP delivery')
        if current_app.config.get('OTP_DEV_MODE') or current_app.testing:
            return (
                True,
                f'Local dev OTP mode: SMTP send failed ({exc!s}); use the code on the next screen or server log.',
            )
        return False, f'Could not send OTP email: {exc}'


def send_account_deletion_otp(recipient_email: str, username: str, otp_code: str) -> tuple[bool, str]:
    """Email OTP for the destructive master-account deletion flow (same SMTP rules as login OTP)."""
    expiry_seconds = int(current_app.config.get('OTP_EXPIRY_SECONDS', 300))
    expiry_minutes = max(1, expiry_seconds // 60)
    cfg = current_app.config
    dev = bool(cfg.get('OTP_DEV_MODE') or current_app.testing)

    if not smtp_configured():
        if dev:
            return (
                True,
                'Local dev OTP mode: email was not sent. Use the code shown on the account page and/or the server log.',
            )
        return False, (
            'Cannot send deletion OTP: SMTP is not configured. Enable OTP_DEV_MODE for local testing '
            'or configure SMTP the same way as login OTP.'
        )

    message = EmailMessage()
    message['Subject'] = f"{current_app.config.get('APP_NAME', 'Homelab Vault')} — account deletion code"
    message['From'] = current_app.config['SMTP_FROM_EMAIL']
    message['To'] = recipient_email
    message.set_content(
        f"Hello {username},\n\n"
        f"A master account deletion was requested. Your confirmation code is: {otp_code}\n"
        f"It expires in about {expiry_minutes} minute(s).\n\n"
        "If you did not request this, sign in and change your password; do not share this code.\n"
    )

    host = current_app.config['SMTP_SERVER']
    port = int(current_app.config['SMTP_PORT'])
    username_cfg = current_app.config.get('SMTP_USERNAME')
    password_cfg = current_app.config.get('SMTP_PASSWORD')
    use_tls = bool(current_app.config.get('SMTP_USE_TLS'))
    use_ssl = bool(current_app.config.get('SMTP_USE_SSL'))

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        with server:
            if use_tls and not use_ssl:
                server.starttls()
            if username_cfg and password_cfg:
                server.login(username_cfg, password_cfg)
            server.send_message(message)
        return True, 'Deletion confirmation code sent to your email.'
    except Exception as exc:  # pragma: no cover - depends on external SMTP
        logger.exception('SMTP send failed for account deletion OTP')
        if current_app.config.get('OTP_DEV_MODE') or current_app.testing:
            return (
                True,
                f'Local dev OTP mode: SMTP send failed ({exc!s}); use the code on the account page or server log.',
            )
        return False, f'Could not send deletion OTP email: {exc}'

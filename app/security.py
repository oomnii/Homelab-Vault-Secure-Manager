from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from functools import wraps
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from flask import current_app, flash, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

IST = ZoneInfo('Asia/Kolkata')


def ensure_fernet_key(app) -> None:
    key = app.config.get('FERNET_KEY')
    if key:
        return
    secret = app.config['SECRET_KEY'].encode('utf-8')
    derived = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    app.config['FERNET_KEY'] = derived.decode('utf-8')


def get_cipher() -> Fernet:
    key = current_app.config['FERNET_KEY'].encode('utf-8')
    return Fernet(key)


def encrypt_value(raw_value: str) -> str:
    return get_cipher().encrypt(raw_value.encode('utf-8')).decode('utf-8')


def decrypt_value(encrypted_value: str) -> str:
    return get_cipher().decrypt(encrypted_value.encode('utf-8')).decode('utf-8')


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)

    return wrapped_view


def pending_login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'pending_user_id' not in session:
            flash('Start the login process first.', 'warning')
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)

    return wrapped_view


def clear_pending_login() -> None:
    for key in ('pending_user_id', 'pending_username', 'pending_email', 'dev_otp'):
        session.pop(key, None)


def complete_login_session(user) -> None:
    clear_pending_login()
    session['user_id'] = user.id
    session['username'] = user.username


def begin_pending_login(user) -> None:
    session.clear()
    session['pending_user_id'] = user.id
    session['pending_username'] = user.username
    session['pending_email'] = user.email or ''


def generate_otp_code(length: int | None = None) -> str:
    otp_length = length or int(current_app.config.get('OTP_LENGTH', 6))
    return ''.join(secrets.choice('0123456789') for _ in range(otp_length))


def create_otp_for_user(user) -> str:
    code = generate_otp_code()
    expires_in = int(current_app.config.get('OTP_EXPIRY_SECONDS', 300))
    user.otp_code_hash = generate_password_hash(code)
    user.otp_expires_at = utc_now_naive() + timedelta(seconds=expires_in)
    user.otp_attempts = 0
    user.last_otp_sent_at = utc_now_naive()
    return code


def verify_user_otp(user, candidate: str) -> tuple[bool, str]:
    max_attempts = int(current_app.config.get('OTP_MAX_ATTEMPTS', 3))
    if not user.otp_code_hash or not user.otp_expires_at:
        return False, 'No active verification code. Please log in again.'
    if user.otp_expires_at < utc_now_naive():
        return False, 'Your verification code has expired. Please request a new one.'
    if user.otp_attempts >= max_attempts:
        return False, 'Too many invalid OTP attempts. Please log in again.'
    if not check_password_hash(user.otp_code_hash, candidate):
        user.otp_attempts += 1
        return False, 'Invalid verification code.'
    user.otp_code_hash = None
    user.otp_expires_at = None
    user.otp_attempts = 0
    return True, 'OTP verified.'


def utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def format_datetime_ist(value: datetime | None, include_timezone: bool = True) -> str:
    if value is None:
        return '—'
    aware = value.replace(tzinfo=UTC).astimezone(IST)
    suffix = ' IST' if include_timezone else ''
    return aware.strftime(f'%d %b %Y, %I:%M:%S %p{suffix}')

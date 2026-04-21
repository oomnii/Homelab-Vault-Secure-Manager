from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, redirect, request
from werkzeug.middleware.proxy_fix import ProxyFix

from .auth import auth_bp
from .extensions import db
from .mailer import smtp_configured_for_config
from .migrations import migrate_schema
from .models import User
from .security import ensure_fernet_key, format_datetime_ist
from .vault import vault_bp

_config_log = logging.getLogger('homelab.config')


def _bootstrap_dotenv() -> None:
    """Load env files from fixed paths (not CWD). Project .env overrides instance/.env."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    root = Path(__file__).resolve().parent.parent
    load_dotenv(root / 'instance' / '.env', override=False)
    load_dotenv(root / '.env', override=True)


def _strip_env_scalar(raw: str) -> str:
    s = raw.strip()
    if s.startswith('\ufeff'):
        s = s.lstrip('\ufeff').strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return _strip_env_scalar(raw).lower() in {'1', 'true', 'yes', 'on'}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == '':
        return default
    return int(raw)


def _otp_delivery_mode(cfg: dict) -> str:
    if smtp_configured_for_config(cfg):
        return 'email'
    if cfg.get('OTP_DEV_MODE'):
        return 'dev'
    return 'misconfigured'


def create_app(test_config: dict | None = None) -> Flask:
    _bootstrap_dotenv()

    app = Flask(__name__, instance_relative_config=True)

    default_db_path = os.path.join(app.instance_path, 'vault.db')
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'change-this-in-production'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f'sqlite:///{default_db_path}'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=_env_bool('SESSION_COOKIE_SECURE', False),
        FORCE_HTTPS=_env_bool('FORCE_HTTPS', False),
        ENABLE_PROXY_FIX=_env_bool('ENABLE_PROXY_FIX', True),
        FERNET_KEY=os.environ.get('FERNET_KEY', ''),
        APP_NAME='Homelab Password Manager',
        OTP_LENGTH=int(os.environ.get('OTP_LENGTH', '6')),
        OTP_EXPIRY_SECONDS=int(os.environ.get('OTP_EXPIRY_SECONDS', '300')),
        OTP_MAX_ATTEMPTS=int(os.environ.get('OTP_MAX_ATTEMPTS', '3')),
        OTP_DEV_MODE=_env_bool('OTP_DEV_MODE', False),
        SMTP_SERVER=os.environ.get('SMTP_SERVER', ''),
        SMTP_PORT=_env_int('SMTP_PORT', 587),
        SMTP_USERNAME=os.environ.get('SMTP_USERNAME', ''),
        SMTP_PASSWORD=os.environ.get('SMTP_PASSWORD', ''),
        SMTP_FROM_EMAIL=os.environ.get('SMTP_FROM_EMAIL', ''),
        SMTP_USE_TLS=_env_bool('SMTP_USE_TLS', True),
        SMTP_USE_SSL=_env_bool('SMTP_USE_SSL', False),
        SMTP_ALLOW_NO_AUTH=_env_bool('SMTP_ALLOW_NO_AUTH', False),
    )

    if test_config:
        app.config.update(test_config)

    (Path(app.root_path) / 'static' / 'images').mkdir(parents=True, exist_ok=True)

    app.config['OTP_DELIVERY_MODE'] = _otp_delivery_mode(dict(app.config))
    if not app.testing:
        _config_log.info(
            'OTP delivery mode=%s (smtp_ready=%s OTP_DEV_MODE=%s)',
            app.config['OTP_DELIVERY_MODE'],
            smtp_configured_for_config(app.config),
            app.config.get('OTP_DEV_MODE'),
        )

    os.makedirs(app.instance_path, exist_ok=True)
    ensure_fernet_key(app)

    if app.config.get('ENABLE_PROXY_FIX'):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)

    with app.app_context():
        db.create_all()
        migrate_schema()
        db.create_all()

    @app.before_request
    def maybe_force_https():
        if app.testing or not app.config.get('FORCE_HTTPS'):
            return None
        forwarded_proto = request.headers.get('X-Forwarded-Proto', request.scheme)
        if forwarded_proto == 'https':
            return None
        secure_url = request.url.replace('http://', 'https://', 1)
        return redirect(secure_url, code=301)

    @app.after_request
    def apply_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        forwarded_proto = request.headers.get('X-Forwarded-Proto', request.scheme)
        if forwarded_proto == 'https':
            response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        return response

    @app.context_processor
    def inject_global_values() -> dict:
        forwarded_proto = request.headers.get('X-Forwarded-Proto', request.scheme)
        img_dir = Path(app.root_path) / 'static' / 'images'
        fav_path = img_dir / 'favicon.png'
        logo_path = img_dir / 'logo.png'
        favicon_cache_v = str(int(fav_path.stat().st_mtime)) if fav_path.is_file() else '0'
        logo_cache_v = str(int(logo_path.stat().st_mtime)) if logo_path.is_file() else '0'
        return {
            'app_name': app.config['APP_NAME'],
            'owner_exists': User.query.first() is not None,
            'format_ist': format_datetime_ist,
            'transport_mode': 'HTTPS' if forwarded_proto == 'https' or app.config.get('SESSION_COOKIE_SECURE') else 'HTTP',
            'otp_dev_mode': bool(app.config.get('OTP_DEV_MODE') or app.testing),
            'otp_delivery_mode': app.config.get('OTP_DELIVERY_MODE', 'misconfigured'),
            'folder_icon': '📂',
            'favicon_cache_v': favicon_cache_v,
            'logo_cache_v': logo_cache_v,
        }

    return app

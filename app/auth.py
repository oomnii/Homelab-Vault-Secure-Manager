from __future__ import annotations

import logging

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash

from .audit import record_login_event
from .extensions import db
from .mailer import send_login_otp
from .models import User
from .security import (
    begin_pending_login,
    clear_pending_login,
    complete_login_session,
    create_otp_for_user,
    login_required,
    pending_login_required,
    verify_user_otp,
)

auth_bp = Blueprint('auth', __name__)
_log = logging.getLogger(__name__)


def _is_valid_email(email: str) -> bool:
    return bool(email and '@' in email and '.' in email.split('@')[-1])


def _store_dev_otp(code: str | None) -> None:
    if current_app.config.get('OTP_DEV_MODE') or current_app.testing:
        session['dev_otp'] = code or ''
    else:
        session.pop('dev_otp', None)


def _start_otp_challenge(user: User) -> bool:
    otp_code = create_otp_for_user(user)
    db.session.commit()

    if current_app.config.get('OTP_DEV_MODE') and not current_app.testing:
        _log.warning(
            '[OTP_DEV_MODE / local only] Login OTP for %r: %s',
            user.username,
            otp_code,
        )

    sent, message = send_login_otp(user.email or '', user.username, otp_code)
    _store_dev_otp(otp_code)

    record_login_event(
        event_type='otp_delivery',
        status='sent' if sent else 'failed',
        username_snapshot=user.username,
        user=user,
        detail=message,
    )

    if not sent and not (current_app.config.get('OTP_DEV_MODE') or current_app.testing):
        user.otp_code_hash = None
        user.otp_expires_at = None
        user.otp_attempts = 0
        db.session.commit()
        clear_pending_login()
        flash(message, 'danger')
        return False

    flash(
        f'Password verified. {message} Enter the OTP on the next step to finish login.',
        'success' if sent else 'warning',
    )
    return True


@auth_bp.get('/')
def root_redirect():
    if User.query.first() is None:
        return redirect(url_for('auth.setup'))
    if session.get('user_id'):
        return redirect(url_for('vault.dashboard'))
    if session.get('pending_user_id'):
        user = db.session.get(User, session.get('pending_user_id'))
        if user and not user.email:
            return redirect(url_for('auth.complete_email'))
        return redirect(url_for('auth.verify_otp'))
    return redirect(url_for('auth.login'))


@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if User.query.first() is not None:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('Username, email, and master password are required.', 'danger')
        elif not _is_valid_email(email):
            flash('Enter a valid email address.', 'danger')
        elif len(password) < 8:
            flash('Master password must be at least 8 characters long.', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match.', 'danger')
        else:
            user = User(username=username, email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            flash('Master account created. Sign in to continue.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('setup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if User.query.first() is None:
        return redirect(url_for('auth.setup'))

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter(or_(User.username == identifier, User.email == identifier.lower())).first()

        if not user or not check_password_hash(user.password_hash, password):
            record_login_event(
                event_type='password_login',
                status='failed',
                username_snapshot=identifier or 'Unknown',
                detail='Invalid username/email or password.',
            )
            flash('Invalid username/email or password.', 'danger')
            return render_template('login.html')

        begin_pending_login(user)
        record_login_event(
            event_type='password_login',
            status='passed',
            username_snapshot=user.username,
            user=user,
            detail='Password verified.',
        )

        if not user.email:
            flash('Password verified. Add your email to enable OTP login.', 'warning')
            return redirect(url_for('auth.complete_email'))

        if _start_otp_challenge(user):
            return redirect(url_for('auth.verify_otp'))
        return redirect(url_for('auth.login'))

    return render_template('login.html')


@auth_bp.route('/complete-email', methods=['GET', 'POST'])
@pending_login_required
def complete_email():
    user = db.session.get(User, session.get('pending_user_id'))
    if user is None:
        clear_pending_login()
        flash('Please start the login process again.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        confirm_email = request.form.get('confirm_email', '').strip().lower()

        if not _is_valid_email(email):
            flash('Enter a valid email address.', 'danger')
        elif email != confirm_email:
            flash('Email addresses do not match.', 'danger')
        elif User.query.filter(User.email == email, User.id != user.id).first() is not None:
            flash('That email address is already used by another account.', 'danger')
        else:
            user.email = email
            db.session.commit()
            session['pending_email'] = email
            record_login_event(
                event_type='email_setup',
                status='updated',
                username_snapshot=user.username,
                user=user,
                detail='Email added for OTP login.',
            )
            if _start_otp_challenge(user):
                return redirect(url_for('auth.verify_otp'))
            return redirect(url_for('auth.login'))

    return render_template('complete_email.html', user=user)


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
@pending_login_required
def verify_otp():
    user = db.session.get(User, session.get('pending_user_id'))
    if user is None:
        clear_pending_login()
        flash('Please start the login process again.', 'warning')
        return redirect(url_for('auth.login'))

    if not user.email:
        return redirect(url_for('auth.complete_email'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        valid, message = verify_user_otp(user, otp)
        db.session.commit()

        if not valid:
            record_login_event(
                event_type='otp_verification',
                status='failed',
                username_snapshot=user.username,
                user=user,
                detail=message,
            )
            if 'expired' in message.lower() or 'too many' in message.lower():
                user.otp_code_hash = None
                user.otp_expires_at = None
                user.otp_attempts = 0
                db.session.commit()
                clear_pending_login()
                flash(message, 'danger')
                return redirect(url_for('auth.login'))
            flash(message, 'danger')
            return render_template('verify_otp.html', user=user, dev_otp=session.get('dev_otp'))

        record_login_event(
            event_type='otp_verification',
            status='passed',
            username_snapshot=user.username,
            user=user,
            detail='OTP verified and session opened.',
        )
        complete_login_session(user)
        flash('Login successful. Your vault is unlocked.', 'success')
        return redirect(url_for('vault.dashboard'))

    return render_template('verify_otp.html', user=user, dev_otp=session.get('dev_otp'))


@auth_bp.post('/resend-otp')
@pending_login_required
def resend_otp():
    user = db.session.get(User, session.get('pending_user_id'))
    if user is None or not user.email:
        clear_pending_login()
        flash('Please start the login process again.', 'warning')
        return redirect(url_for('auth.login'))

    if _start_otp_challenge(user):
        return redirect(url_for('auth.verify_otp'))
    return redirect(url_for('auth.login'))


@auth_bp.post('/logout')
@login_required
def logout():
    user = db.session.get(User, session.get('user_id'))
    if user is not None:
        record_login_event(
            event_type='logout',
            status='success',
            username_snapshot=user.username,
            user=user,
            detail='User logged out.',
        )
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

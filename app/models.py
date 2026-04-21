from __future__ import annotations

from datetime import UTC, datetime

from .extensions import db


def utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    otp_code_hash = db.Column(db.String(255), nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_otp_sent_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)

    login_history = db.relationship('LoginHistory', back_populates='user', lazy=True)


class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    icon = db.Column(db.String(40), default='📂', nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)

    vault_items = db.relationship('VaultItem', back_populates='folder', lazy=True)
    secure_ids = db.relationship('SecureID', back_populates='folder', lazy=True)
    secure_notes = db.relationship('SecureNote', back_populates='folder', lazy=True)


class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    website = db.Column(db.String(255), default='')
    username = db.Column(db.String(255), default='')
    password_encrypted = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

    folder = db.relationship('Folder', back_populates='vault_items')


class SecureID(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    id_type = db.Column(db.String(120), default='General ID', nullable=False)
    id_value_encrypted = db.Column(db.Text, nullable=False)
    expiry_date = db.Column(db.String(40), default='')
    notes = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

    folder = db.relationship('Folder', back_populates='secure_ids')


class SecureNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    note_encrypted = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

    folder = db.relationship('Folder', back_populates='secure_notes')


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username_snapshot = db.Column(db.String(120), nullable=False)
    event_type = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(40), nullable=False)
    detail = db.Column(db.String(255), default='')
    ip_address = db.Column(db.String(120), default='')
    user_agent = db.Column(db.String(255), default='')
    occurred_at = db.Column(db.DateTime, default=utc_now_naive, nullable=False)

    user = db.relationship('User', back_populates='login_history')

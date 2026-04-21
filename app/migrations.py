from __future__ import annotations

from sqlalchemy import inspect, text

from .extensions import db


def _table_columns(table_name: str) -> set[str]:
    inspector = inspect(db.engine)
    try:
        return {column['name'] for column in inspector.get_columns(table_name)}
    except Exception:
        return set()


def migrate_schema() -> None:
    with db.engine.begin() as conn:
        user_columns = _table_columns('user')
        if user_columns:
            if 'email' not in user_columns:
                conn.execute(text('ALTER TABLE "user" ADD COLUMN email VARCHAR(255)'))
            if 'otp_code_hash' not in user_columns:
                conn.execute(text('ALTER TABLE "user" ADD COLUMN otp_code_hash VARCHAR(255)'))
            if 'otp_expires_at' not in user_columns:
                conn.execute(text('ALTER TABLE "user" ADD COLUMN otp_expires_at DATETIME'))
            if 'otp_attempts' not in user_columns:
                conn.execute(text('ALTER TABLE "user" ADD COLUMN otp_attempts INTEGER NOT NULL DEFAULT 0'))
            if 'last_otp_sent_at' not in user_columns:
                conn.execute(text('ALTER TABLE "user" ADD COLUMN last_otp_sent_at DATETIME'))

        folder_columns = _table_columns('folder')
        if folder_columns and 'icon' in folder_columns:
            # Normalize legacy per-folder icons to the single app-wide default (display always uses 📂).
            conn.execute(text("UPDATE folder SET icon = '📂' WHERE icon IS NULL OR icon != '📂'"))

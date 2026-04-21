from __future__ import annotations

from flask import request

from .extensions import db
from .models import LoginHistory, User


def request_ip_address() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
    return forwarded_for or request.remote_addr or 'Unknown'


def request_user_agent() -> str:
    return (request.headers.get('User-Agent', '') or 'Unknown browser')[:255]


def record_login_event(
    *,
    event_type: str,
    status: str,
    username_snapshot: str,
    user: User | None = None,
    detail: str = '',
) -> None:
    db.session.add(
        LoginHistory(
            user_id=user.id if user else None,
            username_snapshot=username_snapshot or 'Unknown',
            event_type=event_type,
            status=status,
            detail=detail,
            ip_address=request_ip_address(),
            user_agent=request_user_agent(),
        )
    )
    db.session.commit()

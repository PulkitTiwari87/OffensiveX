"""Server-side sessions (ADR-012).

The browser holds only an opaque random token (HttpOnly cookie); the database
holds its SHA-256, so reading the `auth_sessions` table can't be replayed as a
login. Sessions have an absolute expiry (no sliding window) and can be
revoked; a deactivated user's sessions stop working immediately because the
lookup re-checks `users.is_active` on every request.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.db import models


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    session: Session, *, user: models.User, ttl_minutes: int, now: datetime | None = None
) -> tuple[str, models.AuthSession]:
    """Returns `(raw_token, row)`. The raw token exists only in this return
    value — it is never stored or logged."""
    now = now or datetime.now(UTC)
    raw_token = secrets.token_urlsafe(32)
    row = models.AuthSession(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        csrf_token=secrets.token_urlsafe(32),
        expires_at=now + timedelta(minutes=ttl_minutes),
    )
    session.add(row)
    session.flush()
    return raw_token, row


def resolve_session(
    session: Session, raw_token: str, *, now: datetime | None = None
) -> models.AuthSession | None:
    """The live session for this token, or None if it is unknown, expired,
    revoked, or its user is deactivated."""
    now = now or datetime.now(UTC)
    row = session.scalar(
        select(models.AuthSession).where(models.AuthSession.token_hash == hash_token(raw_token))
    )
    if row is None or row.revoked_at is not None or row.expires_at <= now:
        return None
    if not row.user.is_active:
        return None
    return row


def revoke_session(session: Session, row: models.AuthSession) -> None:
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        session.flush()


def revoke_all_for_user(session: Session, user_id: object) -> None:
    now = datetime.now(UTC)
    for row in session.scalars(
        select(models.AuthSession).where(
            models.AuthSession.user_id == user_id, models.AuthSession.revoked_at.is_(None)
        )
    ):
        row.revoked_at = now
    session.flush()

"""Audit log service.

Two ways to write, chosen by what the caller needs:

* `record()` — in the caller's transaction. Use for a *successful*
  sensitive action: the audit row commits or rolls back together with the
  change itself, so there is never a change without its record (or a record
  of a change that didn't happen).
* `record_independent()` — its own short transaction, committed immediately.
  Use for *denials and failures*: the request is about to raise (and its
  transaction roll back), but the attempt must stay on the record.

Nothing here updates or deletes rows, and the database rejects it anyway
(trigger in migration 0004). `details` is scrubbed of secret-looking keys and
long strings; callers should still never put credentials in it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from offensivex.auth.principal import Principal
from offensivex.core.logging import _is_sensitive_key, get_logger
from offensivex.db import models
from offensivex.db.session import session_scope

log = get_logger(__name__)

_MAX_STRING = 500
_MAX_USERNAME = 100


def scrub(value: Any) -> Any:
    """Drop secret-looking keys (password, token, cookie, ...) and truncate
    long strings, recursively."""
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items() if not _is_sensitive_key(str(k))}
    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        value = value.replace("\x00", "")  # JSONB cannot store NUL
        return value if len(value) <= _MAX_STRING else value[:_MAX_STRING] + "…"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _build(
    *,
    action: str,
    outcome: models.AuditOutcome,
    actor: Principal | None,
    actor_username: str | None,
    target_type: str | None,
    target_id: object | None,
    request_id: str | None,
    details: dict[str, Any] | None,
) -> models.AuditLogEntry:
    username = actor.username if actor else actor_username
    return models.AuditLogEntry(
        actor_user_id=actor.user_id if actor else None,
        actor_username=username[:_MAX_USERNAME] if username else None,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        request_id=request_id,
        details=scrub(details or {}),
    )


def record(
    session: Session,
    *,
    action: str,
    outcome: models.AuditOutcome = models.AuditOutcome.SUCCESS,
    actor: Principal | None = None,
    actor_username: str | None = None,
    target_type: str | None = None,
    target_id: object | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> models.AuditLogEntry:
    entry = _build(
        action=action,
        outcome=outcome,
        actor=actor,
        actor_username=actor_username,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id,
        details=details,
    )
    session.add(entry)
    session.flush()
    return entry


def record_independent(
    session_factory: sessionmaker[Session],
    *,
    action: str,
    outcome: models.AuditOutcome,
    actor: Principal | None = None,
    actor_username: str | None = None,
    target_type: str | None = None,
    target_id: object | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Never raises: a failure to write the audit row must not turn a
    denial into a different error. It is logged loudly instead."""
    try:
        with session_scope(session_factory) as session:
            record(
                session,
                action=action,
                outcome=outcome,
                actor=actor,
                actor_username=actor_username,
                target_type=target_type,
                target_id=target_id,
                request_id=request_id,
                details=details,
            )
    except Exception:
        log.error("audit.write_failed", action=action, outcome=outcome.value, exc_info=True)


def count_recent_failures(
    session: Session, *, action: str, actor_username: str, since: datetime
) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(models.AuditLogEntry)
            .where(
                models.AuditLogEntry.action == action,
                models.AuditLogEntry.outcome == models.AuditOutcome.FAILURE,
                models.AuditLogEntry.actor_username == actor_username[:_MAX_USERNAME],
                models.AuditLogEntry.occurred_at >= since,
            )
        )
        or 0
    )


def list_entries(
    session: Session,
    *,
    action: str | None = None,
    actor_user_id: object | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[models.AuditLogEntry]:
    query = select(models.AuditLogEntry)
    if action is not None:
        query = query.where(models.AuditLogEntry.action == action)
    if actor_user_id is not None:
        query = query.where(models.AuditLogEntry.actor_user_id == actor_user_id)
    return list(
        session.scalars(
            query.order_by(models.AuditLogEntry.occurred_at.desc(), models.AuditLogEntry.id)
            .limit(limit)
            .offset(offset)
        )
    )

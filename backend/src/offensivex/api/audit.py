"""Audit log read API — admin only (`audit:read`). Read-only by design:
there is no route (and the database has a trigger) that could alter history."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session, require_permission
from offensivex.auth.permissions import Permission
from offensivex.auth.principal import Principal
from offensivex.db import models
from offensivex.services import audit

router = APIRouter(prefix="/audit-log", tags=["audit"])

_ReadAudit = Annotated[Principal, Depends(require_permission(Permission.AUDIT_READ))]


class AuditEntryResponse(BaseModel):
    id: UUID
    occurred_at: datetime
    actor_user_id: UUID | None
    actor_username: str | None
    action: str
    outcome: models.AuditOutcome
    target_type: str | None
    target_id: str | None
    request_id: str | None
    details: dict[str, Any]

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AuditEntryResponse])
def list_audit_log(
    _actor: _ReadAudit,
    session: Annotated[Session, Depends(get_db_session)],
    action: Annotated[str | None, Query(max_length=100)] = None,
    actor_user_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[models.AuditLogEntry]:
    return audit.list_entries(
        session, action=action, actor_user_id=actor_user_id, limit=limit, offset=offset
    )

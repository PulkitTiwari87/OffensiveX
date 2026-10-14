"""System status + dashboard overview — read-only, `data:read`.

`/system/status` reports configuration an operator needs to know before
launching anything (is an LLM configured? are private targets allowed? is
self-approval on?). It never includes the API key or base URL.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_app_settings, get_db_session, require_permission
from offensivex.auth.permissions import Permission
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.services import overview as overview_service

router = APIRouter(
    tags=["system"], dependencies=[Depends(require_permission(Permission.DATA_READ))]
)


class LlmStatus(BaseModel):
    enabled: bool
    provider: str | None
    model: str | None


class SystemStatusResponse(BaseModel):
    environment: str
    llm: LlmStatus
    allow_private_targets: bool
    allow_self_approval: bool
    session_ttl_minutes: int


class RecentAssessment(BaseModel):
    id: UUID
    target_id: UUID
    target_name: str
    status: models.AssessmentStatus
    started_at: datetime | None
    finished_at: datetime | None
    finding_count: int


class OverviewResponse(BaseModel):
    targets: int
    assessments_by_status: dict[str, int]
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]
    recent_assessments: list[RecentAssessment]


@router.get("/system/status", response_model=SystemStatusResponse)
def system_status(settings: Annotated[Settings, Depends(get_app_settings)]) -> SystemStatusResponse:
    return SystemStatusResponse(
        environment=settings.environment,
        llm=LlmStatus(
            enabled=settings.llm_enabled,
            provider=settings.llm_provider,
            model=settings.llm_model,
        ),
        allow_private_targets=settings.allow_private_targets,
        allow_self_approval=settings.allow_self_approval,
        session_ttl_minutes=settings.session_ttl_minutes,
    )


@router.get("/overview", response_model=OverviewResponse)
def overview(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    return overview_service.build_overview(session)

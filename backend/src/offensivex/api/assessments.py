"""Assessments API — Phase 2.

docs/interfaces/api.md: `POST /assessments`, and the "CURRENTLY REQUIRED"
subset from docs/roadmap/implementation-blueprint.md section 7
(`GET /assessments/{id}`, `POST /assessments/{id}/cancel`). No business
logic here — every route calls `offensivex.services.assessments`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import (
    get_app_settings,
    get_db_session,
    get_request_id,
    require_permission,
)
from offensivex.auth.permissions import Permission
from offensivex.auth.principal import Principal
from offensivex.core.config import Settings
from offensivex.core.errors import ServiceUnavailableError
from offensivex.db import models
from offensivex.services import assessments as assessments_service
from offensivex.services import audit, pipeline

router = APIRouter(prefix="/assessments", tags=["assessments"])

_Read = Depends(require_permission(Permission.DATA_READ))
_WriteAssessments = Annotated[Principal, Depends(require_permission(Permission.ASSESSMENTS_WRITE))]


class AssessmentCreateRequest(BaseModel):
    target_id: UUID
    scan_mode: models.ScanMode = models.ScanMode.STANDARD
    validation_enabled: bool = False


class AgentRunSummary(BaseModel):
    id: UUID
    agent_type: models.AgentType
    status: models.AgentRunStatus
    attempts: int
    error: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


class AssessmentResponse(BaseModel):
    id: UUID
    target_id: UUID
    authorization_id: UUID
    scan_mode: models.ScanMode
    validation_enabled: bool
    status: models.AssessmentStatus
    started_at: datetime | None
    finished_at: datetime | None
    agent_runs: list[AgentRunSummary] = []

    model_config = {"from_attributes": True}


@router.post("", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
def create_assessment(
    body: AssessmentCreateRequest,
    request: Request,
    actor: _WriteAssessments,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Assessment:
    assessment = assessments_service.create_assessment(
        session,
        target_id=body.target_id,
        scan_mode=body.scan_mode,
        validation_enabled=body.validation_enabled,
    )
    audit.record(
        session,
        action="assessment.create",
        actor=actor,
        target_type="assessment",
        target_id=assessment.id,
        request_id=get_request_id(request),
        details={
            "target_id": str(body.target_id),
            "scan_mode": body.scan_mode.value,
            "validation_enabled": body.validation_enabled,
        },
    )
    return assessment


class AssessmentListItem(BaseModel):
    id: UUID
    target_id: UUID
    target_name: str
    status: models.AssessmentStatus
    scan_mode: models.ScanMode
    validation_enabled: bool
    started_at: datetime | None
    finished_at: datetime | None
    finding_count: int


@router.get("", response_model=list[AssessmentListItem], dependencies=[_Read])
def list_assessments(
    session: Annotated[Session, Depends(get_db_session)],
    status_filter: Annotated[models.AssessmentStatus | None, Query(alias="status")] = None,
    target_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[AssessmentListItem]:
    return [
        AssessmentListItem(
            id=a.id,
            target_id=a.target_id,
            target_name=a.target.name,
            status=a.status,
            scan_mode=a.scan_mode,
            validation_enabled=a.validation_enabled,
            started_at=a.started_at,
            finished_at=a.finished_at,
            finding_count=n,
        )
        for a, n in assessments_service.list_assessments(
            session, status=status_filter, target_id=target_id, limit=limit
        )
    ]


@router.post(
    "/{assessment_id}/run",
    response_model=AssessmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def run_assessment(
    assessment_id: UUID,
    request: Request,
    background: BackgroundTasks,
    actor: _WriteAssessments,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> models.Assessment:
    """Start the agent pipeline for a newly created assessment. Scope and
    authorization were enforced when the assessment was created and are enforced
    again by the Scope Guard on every tool call the agents make; this route adds
    no way around either."""
    provider = request.app.state.llm_provider
    if provider is None:
        raise ServiceUnavailableError(
            "No LLM is configured, so agents cannot run. Set OFFENSIVEX_LLM_ENABLED=true plus "
            "PROVIDER, MODEL and API_KEY (see docs/architecture/llm-integration.md) and restart."
        )
    assessment = assessments_service.get_assessment(session, assessment_id)
    assessments_service.assert_runnable(assessment)
    running: set[UUID] = request.app.state.running_assessments
    if assessment_id in running:
        raise assessments_service.AssessmentNotRunnableError("This assessment is already running.")
    running.add(assessment_id)
    audit.record(
        session,
        action="pipeline.run",
        actor=actor,
        target_type="assessment",
        target_id=assessment.id,
        request_id=get_request_id(request),
        details={"provider": provider.name, "model": getattr(provider, "model", None)},
    )
    session.commit()  # the intent is on record before the run begins

    def _run() -> None:
        try:
            pipeline.run_assessment_in_background(
                request.app.state.session_factory,
                assessment_id=assessment_id,
                llm_provider=provider,
                allow_private_targets=settings.allow_private_targets,
            )
        finally:
            running.discard(assessment_id)

    background.add_task(_run)
    return assessment


@router.get("/{assessment_id}", response_model=AssessmentResponse, dependencies=[_Read])
def get_assessment(
    assessment_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Assessment:
    return assessments_service.get_assessment(session, assessment_id)


@router.post("/{assessment_id}/cancel", response_model=AssessmentResponse)
def cancel_assessment(
    assessment_id: UUID,
    request: Request,
    actor: _WriteAssessments,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Assessment:
    assessment = assessments_service.cancel_assessment(session, assessment_id=assessment_id)
    audit.record(
        session,
        action="assessment.cancel",
        actor=actor,
        target_type="assessment",
        target_id=assessment.id,
        request_id=get_request_id(request),
    )
    return assessment

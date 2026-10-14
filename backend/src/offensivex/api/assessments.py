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

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session, get_request_id, require_permission
from offensivex.auth.permissions import Permission
from offensivex.auth.principal import Principal
from offensivex.db import models
from offensivex.services import assessments as assessments_service
from offensivex.services import audit

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

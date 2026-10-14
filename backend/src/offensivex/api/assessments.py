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

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session
from offensivex.db import models
from offensivex.services import assessments as assessments_service

router = APIRouter(prefix="/assessments", tags=["assessments"])


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
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Assessment:
    return assessments_service.create_assessment(
        session,
        target_id=body.target_id,
        scan_mode=body.scan_mode,
        validation_enabled=body.validation_enabled,
    )


@router.get("/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(
    assessment_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Assessment:
    return assessments_service.get_assessment(session, assessment_id)


@router.post("/{assessment_id}/cancel", response_model=AssessmentResponse)
def cancel_assessment(
    assessment_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Assessment:
    return assessments_service.cancel_assessment(session, assessment_id=assessment_id)

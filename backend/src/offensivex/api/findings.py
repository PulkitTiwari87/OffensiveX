"""Findings API — Phase 8, extended in Phases 9–11.

docs/roadmap/implementation-blueprint.md section 7:
`GET /api/v1/assessments/{id}/findings` (Phase 8, with a `status` filter
added in Phase 11 — "status filters finalized"), the top-level
`GET /api/v1/findings/{id}` (Phase 9, "Finding Details view" backing
route) — a `Finding` plus its `Evidence` — and
`PATCH /api/v1/findings/{id}/status` (Phase 10, the explicit analyst
override; restricted to `confirmed`/`rejected` — the only transition this
route exists for, per docs/data/findings.md).

Known gap, same as `services.findings`: no auth/RBAC restricts this to
the `analyst` role yet (ADR-013) — see that module's docstring.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session
from offensivex.db import models
from offensivex.services import findings as findings_service

router = APIRouter(prefix="/assessments/{assessment_id}/findings", tags=["findings"])
detail_router = APIRouter(prefix="/findings", tags=["findings"])


class FindingResponse(BaseModel):
    id: UUID
    asset_id: UUID
    title: str
    severity: models.FindingSeverity
    confidence: float
    source: str
    affected_component: str | None
    status: models.FindingStatus
    risk_score: float | None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class EvidenceResponse(BaseModel):
    id: UUID
    kind: models.EvidenceKind
    excerpt: str
    captured_at: datetime

    model_config = {"from_attributes": True}


class FindingDetailResponse(FindingResponse):
    risk_breakdown: dict | None = None
    evidence: list[EvidenceResponse] = []


@router.get("", response_model=list[FindingResponse])
def list_findings(
    assessment_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
    status: Annotated[models.FindingStatus | None, Query()] = None,
) -> list[models.Finding]:
    return findings_service.list_findings(session, assessment_id=assessment_id, status=status)


@detail_router.get("/{finding_id}", response_model=FindingDetailResponse)
def get_finding(
    finding_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Finding:
    return findings_service.get_finding(session, finding_id)


class FindingStatusOverrideRequest(BaseModel):
    status: Literal["confirmed", "rejected"]


@detail_router.patch("/{finding_id}/status", response_model=FindingDetailResponse)
def override_finding_status(
    finding_id: UUID,
    body: FindingStatusOverrideRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Finding:
    return findings_service.override_finding_status(
        session, finding_id=finding_id, new_status=models.FindingStatus(body.status)
    )

"""Findings API — Phase 8, extended in Phases 9–11.

docs/roadmap/implementation-blueprint.md section 7:
`GET /api/v1/assessments/{id}/findings` (Phase 8, with a `status` filter
added in Phase 11 — "status filters finalized"), the top-level
`GET /api/v1/findings/{id}` (Phase 9, "Finding Details view" backing
route) — a `Finding` plus its `Evidence` — and
`PATCH /api/v1/findings/{id}/status` (Phase 10, the explicit analyst
override; restricted to `confirmed`/`rejected` — the only transition this
route exists for, per docs/data/findings.md).

Access control: reads need `data:read`; the status override needs
`findings:override` (analyst, admin) and is audited with the actor and the
optional reason.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
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
from offensivex.db import models
from offensivex.ml_advisory import service as ml_service
from offensivex.services import audit
from offensivex.services import findings as findings_service

_read = Depends(require_permission(Permission.DATA_READ))
_Override = Annotated[Principal, Depends(require_permission(Permission.FINDINGS_OVERRIDE))]

router = APIRouter(
    prefix="/assessments/{assessment_id}/findings", tags=["findings"], dependencies=[_read]
)
detail_router = APIRouter(prefix="/findings", tags=["findings"])


class FindingResponse(BaseModel):
    id: UUID
    assessment_id: UUID
    asset_id: UUID
    asset_identifier: str
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
    tool_execution_id: UUID
    excerpt: str
    captured_at: datetime

    model_config = {"from_attributes": True}


class FindingDetailResponse(FindingResponse):
    description: str | None = None
    risk_breakdown: dict | None = None
    evidence: list[EvidenceResponse] = []


@router.get("", response_model=list[FindingResponse])
def list_findings(
    assessment_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
    status: Annotated[models.FindingStatus | None, Query()] = None,
) -> list[models.Finding]:
    return findings_service.list_findings(session, assessment_id=assessment_id, status=status)


@detail_router.get("", response_model=list[FindingResponse], dependencies=[_read])
def search_findings(
    session: Annotated[Session, Depends(get_db_session)],
    assessment_id: Annotated[UUID | None, Query()] = None,
    status: Annotated[models.FindingStatus | None, Query()] = None,
    severity: Annotated[models.FindingSeverity | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[models.Finding]:
    return findings_service.search_findings(
        session, assessment_id=assessment_id, status=status, severity=severity, limit=limit
    )


@detail_router.get("/{finding_id}", response_model=FindingDetailResponse, dependencies=[_read])
def get_finding(
    finding_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Finding:
    return findings_service.get_finding(session, finding_id)


class MlAdvisoryResponse(BaseModel):
    finding_id: UUID
    ml_advisory: list[dict]
    note: str


@detail_router.get(
    "/{finding_id}/ml-advisory", response_model=MlAdvisoryResponse, dependencies=[_read]
)
def get_ml_advisory(
    finding_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> MlAdvisoryResponse:
    """Advisory ML estimates (ADR-026), read-only and separate from every Finding field —
    they never change severity, cvss_score, status or risk_score. An empty list means
    "no estimate available" (feature off, model unavailable, or not a CVE finding),
    never "safe"."""
    finding = findings_service.get_finding(session, finding_id)
    advisories = ml_service.get_advisories(
        cve=finding.cve,
        description=finding.description,
        cvss_vector=finding.cvss_vector,
        cwe=finding.cwe,
        settings=settings,
    )
    return MlAdvisoryResponse(
        finding_id=finding.id,
        ml_advisory=advisories,
        note=(
            "Estimates only; an empty list means no estimate is available, not that the "
            "finding is safe. Deterministic severity, CVSS and risk_score remain authoritative."
        ),
    )


class FindingStatusOverrideRequest(BaseModel):
    status: Literal["confirmed", "rejected"]
    # "who, when, why" (ADR-013 / docs/data/findings.md) — the audit row
    # supplies who and when; this supplies why.
    reason: str | None = Field(default=None, max_length=1000)


@detail_router.patch("/{finding_id}/status", response_model=FindingDetailResponse)
def override_finding_status(
    finding_id: UUID,
    body: FindingStatusOverrideRequest,
    request: Request,
    actor: _Override,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Finding:
    previous = findings_service.get_finding(session, finding_id).status
    finding = findings_service.override_finding_status(
        session, finding_id=finding_id, new_status=models.FindingStatus(body.status)
    )
    audit.record(
        session,
        action="finding.status_override",
        actor=actor,
        target_type="finding",
        target_id=finding.id,
        request_id=get_request_id(request),
        details={"from": previous.value, "to": finding.status.value, "reason": body.reason},
    )
    return finding

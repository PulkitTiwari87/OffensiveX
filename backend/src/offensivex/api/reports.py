"""Reports API — Phase 14.

docs/roadmap/implementation-blueprint.md section 7:
`POST /api/v1/assessments/{id}/reports`, `GET /api/v1/reports/{id}`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session, get_request_id, require_permission
from offensivex.auth.permissions import Permission
from offensivex.auth.principal import Principal
from offensivex.db import models
from offensivex.services import audit
from offensivex.services import reports as reports_service

_Generate = Annotated[Principal, Depends(require_permission(Permission.REPORTS_GENERATE))]

router = APIRouter(prefix="/assessments/{assessment_id}/reports", tags=["reports"])
detail_router = APIRouter(prefix="/reports", tags=["reports"])


class GenerateReportRequest(BaseModel):
    formats: list[Literal["json", "markdown"]] = ["json", "markdown"]


class ReportResponse(BaseModel):
    id: UUID
    assessment_id: UUID
    formats: list[str]
    provenance: dict[str, Any]
    content_json: dict[str, Any] | None
    content_markdown: str | None
    generated_at: datetime

    model_config = {"from_attributes": True}


@router.post("", response_model=ReportResponse, status_code=201)
def generate_report(
    assessment_id: UUID,
    request: Request,
    actor: _Generate,
    session: Annotated[Session, Depends(get_db_session)],
    body: GenerateReportRequest | None = None,
) -> models.Report:
    formats: list[str] | None = list(body.formats) if body else None
    report = reports_service.generate_report(
        session,
        assessment_id=assessment_id,
        formats=formats,
        llm_provider=request.app.state.llm_provider,
    )
    audit.record(
        session,
        action="report.generate",
        actor=actor,
        target_type="report",
        target_id=report.id,
        request_id=get_request_id(request),
        details={
            "assessment_id": str(assessment_id),
            "formats": report.formats,
            "ai_summary": report.provenance.get("ai_summary", {}).get("status"),
        },
    )
    return report


@detail_router.get(
    "/{report_id}",
    response_model=ReportResponse,
    dependencies=[Depends(require_permission(Permission.DATA_READ))],
)
def get_report(
    report_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Report:
    return reports_service.get_report(session, report_id)

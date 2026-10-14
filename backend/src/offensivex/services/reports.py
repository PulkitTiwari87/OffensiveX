"""Reports service — Phase 14.

docs/roadmap/implementation-blueprint.md section 7:
`POST /assessments/{id}/reports`, `GET /reports/{id}`.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.core.errors import NotFoundError
from offensivex.db import models
from offensivex.llm.base import LLMProvider
from offensivex.reporting.builder import build_report
from offensivex.services.assessments import get_assessment


def generate_report(
    session: Session,
    *,
    assessment_id: UUID,
    formats: list[str] | None = None,
    llm_provider: LLMProvider | None = None,
) -> models.Report:
    """`llm_provider` is the application's configured provider, or None when
    the LLM is disabled — in which case the report has no AI summary and says
    so in its provenance (`ai_summary.status == "skipped"`)."""
    assessment = get_assessment(session, assessment_id)
    return build_report(session, assessment, formats=formats, llm_provider=llm_provider)


def list_reports(session: Session, *, assessment_id: UUID) -> list[models.Report]:
    get_assessment(session, assessment_id)  # 404s if the assessment doesn't exist
    return list(
        session.scalars(
            select(models.Report)
            .where(models.Report.assessment_id == assessment_id)
            .order_by(models.Report.generated_at.desc())
        )
    )


def get_report(session: Session, report_id: UUID) -> models.Report:
    report = session.get(models.Report, report_id)
    if report is None:
        raise NotFoundError(f"Report {report_id!r} does not exist.")
    return report

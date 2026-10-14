"""Reports service — Phase 14.

docs/roadmap/implementation-blueprint.md section 7:
`POST /assessments/{id}/reports`, `GET /reports/{id}`.
"""

from __future__ import annotations

from uuid import UUID

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


def get_report(session: Session, report_id: UUID) -> models.Report:
    report = session.get(models.Report, report_id)
    if report is None:
        raise NotFoundError(f"Report {report_id!r} does not exist.")
    return report

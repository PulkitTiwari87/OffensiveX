"""Reports service — Phase 14.

docs/roadmap/implementation-blueprint.md section 7:
`POST /assessments/{id}/reports`, `GET /reports/{id}`.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from offensivex.core.errors import NotFoundError
from offensivex.db import models
from offensivex.reporting.builder import build_report
from offensivex.services.assessments import get_assessment


def generate_report(
    session: Session, *, assessment_id: UUID, formats: list[str] | None = None
) -> models.Report:
    """`llm_provider` is intentionally not a parameter here: no concrete
    provider is wired into the running application yet (see
    docs/roadmap/current-status.md), so the HTTP-reachable path always
    generates a report without an AI-authored executive summary rather
    than silently pretending to have one. Callers with a real provider
    (tests, a future worker) use `offensivex.reporting.builder.build_report`
    directly.
    """
    assessment = get_assessment(session, assessment_id)
    return build_report(session, assessment, formats=formats)


def get_report(session: Session, report_id: UUID) -> models.Report:
    report = session.get(models.Report, report_id)
    if report is None:
        raise NotFoundError(f"Report {report_id!r} does not exist.")
    return report

"""Read-only aggregates for the dashboard overview. Counts only — everything
shown comes from stored rows; nothing is estimated or defaulted to a sample."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from offensivex.db import models
from offensivex.services import assessments as assessments_service


def build_overview(session: Session, *, recent: int = 8) -> dict[str, Any]:
    def counts(column: Any) -> dict[str, int]:
        rows: Any = session.execute(select(column, func.count()).group_by(column)).all()
        return {key.value: int(n) for key, n in rows}

    return {
        "targets": session.scalar(select(func.count(models.Target.id))) or 0,
        "assessments_by_status": counts(models.Assessment.status),
        "findings_by_severity": counts(models.Finding.severity),
        "findings_by_status": counts(models.Finding.status),
        "recent_assessments": [
            {
                "id": a.id,
                "target_id": a.target_id,
                "target_name": a.target.name,
                "status": a.status,
                "started_at": a.started_at,
                "finished_at": a.finished_at,
                "finding_count": n,
            }
            for a, n in assessments_service.list_assessments(session, limit=recent)
        ],
    }

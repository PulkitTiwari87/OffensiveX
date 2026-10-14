"""Attack graph read service — Phase 12.

docs/roadmap/implementation-blueprint.md section 7:
`GET /assessments/{id}/attack-paths`.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.db import models
from offensivex.services.assessments import get_assessment


def list_attack_paths(session: Session, *, assessment_id: UUID) -> list[models.AttackPath]:
    get_assessment(session, assessment_id)  # 404s if the assessment doesn't exist
    return list(
        session.scalars(
            select(models.AttackPath).where(models.AttackPath.assessment_id == assessment_id)
        )
    )

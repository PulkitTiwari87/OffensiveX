"""Asset read service — Phase 6.

docs/roadmap/implementation-blueprint.md section 7:
`GET /assessments/{id}/assets` ("CURRENTLY REQUIRED"). Read-only; assets
are written by agents (Recon, Phase 6+), never through this module.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.db import models
from offensivex.services.assessments import get_assessment


def list_assets(session: Session, *, assessment_id: UUID) -> list[models.Asset]:
    get_assessment(session, assessment_id)  # 404s if the assessment doesn't exist
    return list(
        session.scalars(
            select(models.Asset)
            .where(models.Asset.assessment_id == assessment_id)
            .order_by(models.Asset.created_at)
        )
    )

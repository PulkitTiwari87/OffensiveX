"""Assets API — Phase 6.

docs/roadmap/implementation-blueprint.md section 7:
`GET /api/v1/assessments/{id}/assets` ("CURRENTLY REQUIRED").
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session
from offensivex.db import models
from offensivex.services import assets as assets_service

router = APIRouter(prefix="/assessments/{assessment_id}/assets", tags=["assets"])


class AssetResponse(BaseModel):
    id: UUID
    asset_type: models.AssetType
    canonical_key: str
    attributes: dict
    criticality: models.ImpactLevel | None
    exposure: models.ImpactLevel | None
    scope_state: models.AssetScopeState

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AssetResponse])
def list_assets(
    assessment_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> list[models.Asset]:
    return assets_service.list_assets(session, assessment_id=assessment_id)

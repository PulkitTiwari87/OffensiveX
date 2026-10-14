"""Attack Path API — Phase 12.

docs/roadmap/implementation-blueprint.md section 7:
`GET /api/v1/assessments/{id}/attack-paths`.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session
from offensivex.db import models
from offensivex.services import attack_graph as attack_graph_service

router = APIRouter(prefix="/assessments/{assessment_id}/attack-paths", tags=["attack-graph"])


class AttackPathResponse(BaseModel):
    id: UUID
    entry_node_id: UUID
    target_node_id: UUID
    edge_ids: list
    path_risk: float | None
    evidence_level: models.EvidenceLevel
    rules_version: str | None

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AttackPathResponse])
def list_attack_paths(
    assessment_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> list[models.AttackPath]:
    return attack_graph_service.list_attack_paths(session, assessment_id=assessment_id)

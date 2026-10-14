"""Targets / Authorizations API — Phase 2.

docs/interfaces/api.md: `POST /targets`, `POST /targets/{id}/authorizations`,
`POST /targets/{id}/authorizations/{v}/approve`. No business logic lives
here (CLAUDE.md section 14) — every route calls `offensivex.services.targets`.

Known gap, documented rather than silently skipped: `approve` is specified
(ADR-013) to require the `admin` role via session auth. No authentication/
RBAC layer exists yet in this repository — see docs/roadmap/current-
status.md's Phase 2 gap note. This route is therefore reachable by anyone
who can reach the API, same as every other route today. Wiring auth is a
separate, explicitly tracked piece of work, not silently bundled in here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session
from offensivex.core.config import get_settings
from offensivex.db import models
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=50)
    default_exposure: models.ImpactLevel = models.ImpactLevel.MEDIUM
    default_criticality: models.ImpactLevel = models.ImpactLevel.MEDIUM


class TargetResponse(BaseModel):
    id: UUID
    name: str
    type: str
    default_exposure: models.ImpactLevel
    default_criticality: models.ImpactLevel

    model_config = {"from_attributes": True}


class ScopeRuleRequest(BaseModel):
    rule_type: str = Field(min_length=1, max_length=50)
    pattern: str = Field(min_length=1, max_length=500)
    is_exclusion: bool = False


class AuthorizationSubmitRequest(BaseModel):
    scope_rules: list[ScopeRuleRequest] = Field(min_length=1)
    attestation: str = Field(min_length=1)
    valid_from: datetime
    valid_until: datetime


class AuthorizationResponse(BaseModel):
    id: UUID
    target_id: UUID
    version: int
    status: models.AuthorizationStatus
    valid_from: datetime
    valid_until: datetime

    model_config = {"from_attributes": True}


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    body: TargetCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Target:
    return targets_service.create_target(
        session,
        name=body.name,
        type_=body.type,
        default_exposure=body.default_exposure,
        default_criticality=body.default_criticality,
    )


@router.post(
    "/{target_id}/authorizations",
    response_model=AuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
)
def submit_authorization(
    target_id: UUID,
    body: AuthorizationSubmitRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Authorization:
    settings = get_settings()
    return targets_service.submit_authorization(
        session,
        target_id=target_id,
        scope_rules=[
            ScopeRuleInput(rule_type=r.rule_type, pattern=r.pattern, is_exclusion=r.is_exclusion)
            for r in body.scope_rules
        ],
        attestation=body.attestation,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        allow_private_targets=settings.allow_private_targets,
    )


@router.post(
    "/{target_id}/authorizations/{version}/approve",
    response_model=AuthorizationResponse,
)
def approve_authorization(
    target_id: UUID,
    version: int,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Authorization:
    return targets_service.approve_authorization(session, target_id=target_id, version=version)

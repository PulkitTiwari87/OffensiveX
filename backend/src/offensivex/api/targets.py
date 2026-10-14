"""Targets / Authorizations API — Phase 2.

docs/interfaces/api.md: `POST /targets`, `POST /targets/{id}/authorizations`,
`POST /targets/{id}/authorizations/{v}/approve`. No business logic lives
here (CLAUDE.md section 14) — every route calls `offensivex.services.targets`.

Access control (ADR-013): create/submit need `targets:write` (analyst,
admin); approve/reject need `authorizations:decide` (admin only), and an
approver may not approve an authorization they submitted themselves unless
`OFFENSIVEX_ALLOW_SELF_APPROVAL=true`. Every one of these is audited.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from offensivex.api.deps import (
    get_app_settings,
    get_db_session,
    get_request_id,
    require_permission,
)
from offensivex.auth.permissions import Permission
from offensivex.auth.principal import Principal
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.services import audit
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput

router = APIRouter(prefix="/targets", tags=["targets"])

_WriteTargets = Annotated[Principal, Depends(require_permission(Permission.TARGETS_WRITE))]
_Decide = Annotated[Principal, Depends(require_permission(Permission.AUTHORIZATIONS_DECIDE))]


class TargetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=50)
    default_exposure: models.ImpactLevel = models.ImpactLevel.MEDIUM
    default_criticality: models.ImpactLevel = models.ImpactLevel.MEDIUM
    # http(s) URL where assessment starts, e.g. "https://app.example.com:8443/".
    # Validated and normalized server-side (422 on anything ambiguous or
    # malformed); no credentials, query string or fragment. Optional for
    # backward compatibility. Fixed once created — create a new target to
    # change it — and must be covered by the authorization's scope.
    entry_point: str | None = Field(default=None, min_length=1, max_length=2048)


class TargetResponse(BaseModel):
    id: UUID
    name: str
    type: str
    default_exposure: models.ImpactLevel
    default_criticality: models.ImpactLevel
    entry_point: str | None = None

    model_config = {"from_attributes": True}


class ScopeRuleRequest(BaseModel):
    rule_type: str = Field(min_length=1, max_length=50)
    pattern: str = Field(min_length=1, max_length=500)
    is_exclusion: bool = False
    # "80,443,8000-8100". Omitted: an include rule covers ports 80/443 only and an
    # exclude rule covers every port (docs/security/network-safety.md, ADR-024).
    ports: str | None = Field(default=None, min_length=1, max_length=200)


class AuthorizationSubmitRequest(BaseModel):
    scope_rules: list[ScopeRuleRequest] = Field(min_length=1)
    attestation: str = Field(min_length=1)
    valid_from: datetime
    valid_until: datetime


class ScopeRuleResponse(BaseModel):
    rule_type: str
    pattern: str
    is_exclusion: bool
    ports: str | None = None

    model_config = {"from_attributes": True}


class AuthorizationResponse(BaseModel):
    id: UUID
    target_id: UUID
    version: int
    status: models.AuthorizationStatus
    valid_from: datetime
    valid_until: datetime
    attestation: str | None = None
    submitted_by_id: UUID | None = None
    decided_by_id: UUID | None = None
    scope_rules: list[ScopeRuleResponse] = []

    model_config = {"from_attributes": True}


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    body: TargetCreateRequest,
    request: Request,
    actor: _WriteTargets,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> models.Target:
    target = targets_service.create_target(
        session,
        name=body.name,
        type_=body.type,
        default_exposure=body.default_exposure,
        default_criticality=body.default_criticality,
        entry_point=body.entry_point,
        allow_private_targets=settings.allow_private_targets,
    )
    audit.record(
        session,
        action="target.create",
        actor=actor,
        target_type="target",
        target_id=target.id,
        request_id=get_request_id(request),
        details={"name": target.name, "type": target.type, "entry_point": target.entry_point},
    )
    return target


@router.get(
    "",
    response_model=list[TargetResponse],
    dependencies=[Depends(require_permission(Permission.DATA_READ))],
)
def list_targets(session: Annotated[Session, Depends(get_db_session)]) -> list[models.Target]:
    return targets_service.list_targets(session)


@router.get(
    "/{target_id}/authorizations",
    response_model=list[AuthorizationResponse],
    dependencies=[Depends(require_permission(Permission.DATA_READ))],
)
def list_authorizations(
    target_id: UUID, session: Annotated[Session, Depends(get_db_session)]
) -> list[models.Authorization]:
    return targets_service.list_authorizations(session, target_id)


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    dependencies=[Depends(require_permission(Permission.DATA_READ))],
)
def get_target(
    target_id: UUID,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Target:
    return targets_service.get_target(session, target_id)


@router.post(
    "/{target_id}/authorizations",
    response_model=AuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
)
def submit_authorization(
    target_id: UUID,
    body: AuthorizationSubmitRequest,
    request: Request,
    actor: _WriteTargets,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> models.Authorization:
    authorization = targets_service.submit_authorization(
        session,
        target_id=target_id,
        scope_rules=[
            ScopeRuleInput(
                rule_type=r.rule_type,
                pattern=r.pattern,
                is_exclusion=r.is_exclusion,
                ports=r.ports,
            )
            for r in body.scope_rules
        ],
        attestation=body.attestation,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        allow_private_targets=settings.allow_private_targets,
        submitted_by=actor,
    )
    audit.record(
        session,
        action="authorization.submit",
        actor=actor,
        target_type="authorization",
        target_id=authorization.id,
        request_id=get_request_id(request),
        details={
            "target_id": str(target_id),
            "version": authorization.version,
            "scope_rules": [r.model_dump() for r in body.scope_rules],
        },
    )
    return authorization


@router.post(
    "/{target_id}/authorizations/{version}/approve",
    response_model=AuthorizationResponse,
)
def approve_authorization(
    target_id: UUID,
    version: int,
    request: Request,
    actor: _Decide,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> models.Authorization:
    request_id = get_request_id(request)
    try:
        authorization = targets_service.approve_authorization(
            session,
            target_id=target_id,
            version=version,
            approver=actor,
            allow_self_approval=settings.allow_self_approval,
        )
    except targets_service.SelfApprovalNotAllowedError:
        # The request transaction is about to roll back; the refusal must not.
        audit.record_independent(
            request.app.state.session_factory,
            action="authorization.approve",
            outcome=models.AuditOutcome.DENIED,
            actor=actor,
            target_type="authorization",
            request_id=request_id,
            details={
                "target_id": str(target_id),
                "version": version,
                "reason": "self_approval",
            },
        )
        raise
    audit.record(
        session,
        action="authorization.approve",
        actor=actor,
        target_type="authorization",
        target_id=authorization.id,
        request_id=request_id,
        details={"target_id": str(target_id), "version": version},
    )
    return authorization


@router.post(
    "/{target_id}/authorizations/{version}/reject",
    response_model=AuthorizationResponse,
)
def reject_authorization(
    target_id: UUID,
    version: int,
    request: Request,
    actor: _Decide,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.Authorization:
    authorization = targets_service.reject_authorization(
        session, target_id=target_id, version=version, rejecter=actor
    )
    audit.record(
        session,
        action="authorization.reject",
        actor=actor,
        target_type="authorization",
        target_id=authorization.id,
        request_id=get_request_id(request),
        details={"target_id": str(target_id), "version": version},
    )
    return authorization

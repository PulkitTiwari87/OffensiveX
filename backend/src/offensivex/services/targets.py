"""Target / Authorization service — Phase 2.

Owns the target-authorization gate from ADR-013: a target is only
assessable through an Authorization that is `approved`, unexpired, and has
a non-empty valid scope. This module is where that gate lives on the write
side (submission, approval); `services.assessments` is where it is
*checked* before a scan may start.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from offensivex.core.errors import NotFoundError, OffensiveXError
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.services.scope import ScopeRuleInput, validate_scope_rules


class TargetAlreadyExistsError(OffensiveXError):
    status_code = 409
    title = "Target already exists"


def create_target(
    session: Session,
    *,
    name: str,
    type_: str,
    default_exposure: models.ImpactLevel = models.ImpactLevel.MEDIUM,
    default_criticality: models.ImpactLevel = models.ImpactLevel.MEDIUM,
) -> models.Target:
    target = models.Target(
        name=name,
        type=type_,
        default_exposure=default_exposure,
        default_criticality=default_criticality,
    )
    session.add(target)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise TargetAlreadyExistsError(f"A target named {name!r} already exists.") from exc
    return target


def get_target(session: Session, target_id: object) -> models.Target:
    target = session.get(models.Target, target_id)
    if target is None:
        raise NotFoundError(f"Target {target_id!r} does not exist.")
    return target


def submit_authorization(
    session: Session,
    *,
    target_id: object,
    scope_rules: list[ScopeRuleInput],
    attestation: str,
    valid_from: datetime,
    valid_until: datetime,
    allow_private_targets: bool,
) -> models.Authorization:
    """Create a new, `pending` Authorization version for a target.

    Validates scope rules (services.scope) before anything is written —
    an invalid submission creates no rows at all, not a half-written one.
    """
    target = get_target(session, target_id)
    validate_scope_rules(scope_rules, allow_private_targets=allow_private_targets)

    latest_version = session.scalar(
        select(models.Authorization.version)
        .where(models.Authorization.target_id == target.id)
        .order_by(models.Authorization.version.desc())
        .limit(1)
    )
    next_version = (latest_version or 0) + 1

    authorization = models.Authorization(
        target_id=target.id,
        version=next_version,
        attestation=attestation,
        valid_from=valid_from,
        valid_until=valid_until,
        status=models.AuthorizationStatus.PENDING,
    )
    session.add(authorization)
    session.flush()

    for rule in scope_rules:
        session.add(
            models.ScopeRule(
                authorization_id=authorization.id,
                rule_type=rule.rule_type,
                pattern=rule.pattern,
                is_exclusion=rule.is_exclusion,
            )
        )
    session.flush()
    return authorization


def _get_authorization(session: Session, target_id: object, version: int) -> models.Authorization:
    authorization = session.scalar(
        select(models.Authorization).where(
            models.Authorization.target_id == target_id,
            models.Authorization.version == version,
        )
    )
    if authorization is None:
        raise NotFoundError(
            f"Authorization version {version} for target {target_id!r} does not exist."
        )
    return authorization


def approve_authorization(
    session: Session, *, target_id: object, version: int
) -> models.Authorization:
    """Approve a pending Authorization.

    Note: ADR-013 requires this to be restricted to the `admin` role. No
    authentication/RBAC layer exists yet (see docs/roadmap/current-
    status.md's Phase 2 gap note) — this function enforces only the state
    machine, not who may call it. The API route documents the same gap.
    """
    authorization = _get_authorization(session, target_id, version)
    assert_valid_transition(authorization.status, models.AuthorizationStatus.APPROVED)
    authorization.status = models.AuthorizationStatus.APPROVED
    session.flush()
    return authorization


def get_current_approved_authorization(
    session: Session, target_id: object
) -> models.Authorization | None:
    """The authorization that would back a new assessment right now, or
    None if the target isn't currently assessable (ADR-013's gate).

    "Approved, unexpired, and not revoked, with a non-empty valid scope."
    Revoked is excluded by construction — `status == APPROVED` already
    isn't `REVOKED`. Non-empty scope is guaranteed by `submit_authorization`
    rejecting an empty rule list at creation, so it is not re-checked here.
    """
    now = datetime.now(UTC)
    return session.scalar(
        select(models.Authorization)
        .where(
            models.Authorization.target_id == target_id,
            models.Authorization.status == models.AuthorizationStatus.APPROVED,
            models.Authorization.valid_from <= now,
            models.Authorization.valid_until > now,
        )
        .order_by(models.Authorization.version.desc())
        .limit(1)
    )

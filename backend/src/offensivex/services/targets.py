"""Target / Authorization service — Phase 2.

Owns the target-authorization gate from ADR-013: a target is only
assessable through an Authorization that is `approved`, unexpired, and has
a non-empty valid scope. This module is where that gate lives on the write
side (submission, approval); `services.assessments` is where it is
*checked* before a scan may start.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from offensivex.auth.principal import Principal
from offensivex.core.errors import NotFoundError, OffensiveXError, PermissionDeniedError
from offensivex.core.ports import normalize_port_spec
from offensivex.core.urls import InvalidUrlError, parse_http_url
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.services.scope import (
    ScopeRuleInput,
    is_private_or_loopback_host,
    validate_scope_rules,
)
from offensivex.tools.scope_guard import ScopeRuleLike, check_destination


class SelfApprovalNotAllowedError(PermissionDeniedError):
    title = "Self-approval not allowed"


class TargetAlreadyExistsError(OffensiveXError):
    status_code = 409
    title = "Target already exists"


class InvalidEntryPointError(OffensiveXError):
    status_code = 422
    title = "Invalid entry point"


class EntryPointOutOfScopeError(OffensiveXError):
    status_code = 422
    title = "Entry point outside authorized scope"


def normalize_entry_point(raw: str, *, allow_private_targets: bool) -> str:
    """Validate an entry-point URL and return its normalized form (what is
    stored). Syntax and unambiguity come from `offensivex.core.urls`; loopback
    / private / metadata IP literals follow the same deployment policy as scope
    rules (Guardrail.md section 2.7)."""
    try:
        parsed = parse_http_url(raw, allow_query=False)
    except InvalidUrlError as exc:
        raise InvalidEntryPointError(str(exc)) from None
    if not allow_private_targets and is_private_or_loopback_host(parsed.host):
        raise InvalidEntryPointError(
            f"Entry point host {parsed.host!r} is a private/loopback/link-local address. "
            "Set OFFENSIVEX_ALLOW_PRIVATE_TARGETS=true to permit this for lab/development use "
            "(Guardrail.md section 2.7)."
        )
    return parsed.url


def assert_entry_point_in_scope(entry_point: str, rules: Sequence[ScopeRuleLike]) -> None:
    """The entry point's host must be allowed by the scope rules — the same
    default-deny, exclude-wins check the Scope Guard applies to every tool
    call. An entry point is a starting point, never extra permission."""
    parsed = parse_http_url(entry_point, allow_query=False)
    result = check_destination(parsed.host, list(rules), parsed.port)
    if not result.allowed:
        raise EntryPointOutOfScopeError(
            f"Entry point {entry_point!r} is not covered by the authorization's scope: "
            f"{result.reason}"
        )


def create_target(
    session: Session,
    *,
    name: str,
    type_: str,
    default_exposure: models.ImpactLevel = models.ImpactLevel.MEDIUM,
    default_criticality: models.ImpactLevel = models.ImpactLevel.MEDIUM,
    entry_point: str | None = None,
    allow_private_targets: bool = False,
) -> models.Target:
    target = models.Target(
        name=name,
        type=type_,
        default_exposure=default_exposure,
        default_criticality=default_criticality,
        entry_point=(
            normalize_entry_point(entry_point, allow_private_targets=allow_private_targets)
            if entry_point is not None
            else None
        ),
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


def list_targets(session: Session) -> list[models.Target]:
    return list(session.scalars(select(models.Target).order_by(models.Target.created_at.desc())))


def list_authorizations(session: Session, target_id: object) -> list[models.Authorization]:
    get_target(session, target_id)  # 404s if the target doesn't exist
    return list(
        session.scalars(
            select(models.Authorization)
            .where(models.Authorization.target_id == target_id)
            .order_by(models.Authorization.version.desc())
        )
    )


def submit_authorization(
    session: Session,
    *,
    target_id: object,
    scope_rules: list[ScopeRuleInput],
    attestation: str,
    valid_from: datetime,
    valid_until: datetime,
    allow_private_targets: bool,
    submitted_by: Principal | None = None,
) -> models.Authorization:
    """Create a new, `pending` Authorization version for a target.

    Validates scope rules (services.scope) before anything is written —
    an invalid submission creates no rows at all, not a half-written one.
    """
    target = get_target(session, target_id)
    validate_scope_rules(scope_rules, allow_private_targets=allow_private_targets)
    if target.entry_point:
        # Fail early: an authorization whose scope doesn't even cover the
        # target's own entry point can never produce a usable assessment.
        assert_entry_point_in_scope(target.entry_point, scope_rules)

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
        submitted_by_id=submitted_by.user_id if submitted_by else None,
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
                ports=normalize_port_spec(rule.ports) if rule.ports is not None else None,
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
    session: Session,
    *,
    target_id: object,
    version: int,
    approver: Principal | None = None,
    allow_self_approval: bool = False,
) -> models.Authorization:
    """Approve a pending Authorization.

    Who may call this (`authorizations:decide`, admin) is enforced at the API
    boundary. What is enforced *here*, because it depends on the stored
    record: the state machine, and ADR-013's self-approval rule — an
    approver may not approve a version they submitted themselves unless
    `allow_self_approval` (a deployment-level switch for single-user labs).
    `approver=None` is for internal/test callers with no human actor; no
    HTTP path can reach it.
    """
    authorization = _get_authorization(session, target_id, version)
    if (
        approver is not None
        and not allow_self_approval
        and authorization.submitted_by_id == approver.user_id
    ):
        raise SelfApprovalNotAllowedError(
            "You submitted this authorization and may not approve it yourself."
        )
    assert_valid_transition(authorization.status, models.AuthorizationStatus.APPROVED)
    authorization.status = models.AuthorizationStatus.APPROVED
    authorization.decided_by_id = approver.user_id if approver else None
    session.flush()
    return authorization


def reject_authorization(
    session: Session, *, target_id: object, version: int, rejecter: Principal | None = None
) -> models.Authorization:
    authorization = _get_authorization(session, target_id, version)
    assert_valid_transition(authorization.status, models.AuthorizationStatus.REJECTED)
    authorization.status = models.AuthorizationStatus.REJECTED
    authorization.decided_by_id = rejecter.user_id if rejecter else None
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

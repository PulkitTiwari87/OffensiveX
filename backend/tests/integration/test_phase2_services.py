"""Integration tests for the Phase 2 service layer (targets, assessments,
orchestrator): require a real PostgreSQL instance, same skip-gracefully
convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.db.transitions import InvalidTransitionError
from offensivex.services import assessments as assessments_service
from offensivex.services import targets as targets_service
from offensivex.services.assessments import ScopeNotAuthorizedError
from offensivex.services.scope import ScopeRuleInput, ScopeValidationError
from offensivex.services.targets import TargetAlreadyExistsError

pytestmark = pytest.mark.integration


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test")


@pytest.fixture
def db_engine(settings: Settings):
    url = settings.test_database_url or settings.database_url
    engine = create_engine(
        url, pool_pre_ping=True, future=True, connect_args={"connect_timeout": 2}
    )
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable at {url!r} ({exc.__class__.__name__}).")
    yield engine
    engine.dispose()


@pytest.fixture
def session(db_engine):
    with Session(db_engine) as s:
        yield s
        s.rollback()


def _unique_name() -> str:
    return f"phase2-{uuid.uuid4().hex[:8]}.test"


def _approved_target(session: Session) -> models.Target:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=[ScopeRuleInput(rule_type="domain", pattern=target.name)],
        attestation="I attest I am authorized to test this target.",
        valid_from=now,
        valid_until=now + timedelta(days=30),
        allow_private_targets=False,
    )
    targets_service.approve_authorization(
        session, target_id=target.id, version=authorization.version
    )
    session.flush()
    return target


def test_create_target(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    assert target.id is not None
    assert target.default_exposure is models.ImpactLevel.MEDIUM


def test_create_target_duplicate_name_rejected(session: Session) -> None:
    name = _unique_name()
    targets_service.create_target(session, name=name, type_="web_application")
    session.commit()
    with pytest.raises(TargetAlreadyExistsError):
        targets_service.create_target(session, name=name, type_="web_application")


def test_submit_authorization_rejects_invalid_scope(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    now = datetime.now(UTC)
    with pytest.raises(ScopeValidationError):
        targets_service.submit_authorization(
            session,
            target_id=target.id,
            scope_rules=[ScopeRuleInput(rule_type="cidr", pattern="0.0.0.0/0")],
            attestation="attestation",
            valid_from=now,
            valid_until=now + timedelta(days=1),
            allow_private_targets=False,
        )


def test_submit_authorization_versions_increment(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    now = datetime.now(UTC)
    kwargs = {
        "scope_rules": [ScopeRuleInput(rule_type="domain", pattern=target.name)],
        "attestation": "attestation",
        "valid_from": now,
        "valid_until": now + timedelta(days=1),
        "allow_private_targets": False,
    }
    auth1 = targets_service.submit_authorization(session, target_id=target.id, **kwargs)
    auth2 = targets_service.submit_authorization(session, target_id=target.id, **kwargs)
    assert auth1.version == 1
    assert auth2.version == 2


def test_approve_authorization_transitions_state(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=[ScopeRuleInput(rule_type="domain", pattern=target.name)],
        attestation="attestation",
        valid_from=now,
        valid_until=now + timedelta(days=1),
        allow_private_targets=False,
    )
    assert authorization.status is models.AuthorizationStatus.PENDING
    approved = targets_service.approve_authorization(
        session, target_id=target.id, version=authorization.version
    )
    assert approved.status is models.AuthorizationStatus.APPROVED


def test_approve_authorization_twice_rejected(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=[ScopeRuleInput(rule_type="domain", pattern=target.name)],
        attestation="attestation",
        valid_from=now,
        valid_until=now + timedelta(days=1),
        allow_private_targets=False,
    )
    targets_service.approve_authorization(
        session, target_id=target.id, version=authorization.version
    )
    with pytest.raises(InvalidTransitionError):
        targets_service.approve_authorization(
            session, target_id=target.id, version=authorization.version
        )


def test_get_current_approved_authorization_none_without_approval(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    assert targets_service.get_current_approved_authorization(session, target.id) is None


def test_get_current_approved_authorization_none_when_expired(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=[ScopeRuleInput(rule_type="domain", pattern=target.name)],
        attestation="attestation",
        valid_from=now - timedelta(days=2),
        valid_until=now - timedelta(days=1),  # already expired
        allow_private_targets=False,
    )
    targets_service.approve_authorization(
        session, target_id=target.id, version=authorization.version
    )
    assert targets_service.get_current_approved_authorization(session, target.id) is None


def test_create_assessment_without_authorization_rejected(session: Session) -> None:
    target = targets_service.create_target(session, name=_unique_name(), type_="web_application")
    with pytest.raises(ScopeNotAuthorizedError):
        assessments_service.create_assessment(session, target_id=target.id)


def test_create_assessment_happy_path_schedules_recon(session: Session) -> None:
    target = _approved_target(session)
    assessment = assessments_service.create_assessment(session, target_id=target.id)
    assert assessment.status is models.AssessmentStatus.RUNNING
    assert assessment.started_at is not None
    runs = session.query(models.AgentRun).filter_by(assessment_id=assessment.id).all()
    assert len(runs) == 1
    assert runs[0].agent_type is models.AgentType.RECON
    assert runs[0].status is models.AgentRunStatus.QUEUED


def test_cancel_assessment(session: Session) -> None:
    target = _approved_target(session)
    assessment = assessments_service.create_assessment(session, target_id=target.id)
    cancelled = assessments_service.cancel_assessment(session, assessment_id=assessment.id)
    assert cancelled.status is models.AssessmentStatus.CANCELLED
    assert cancelled.finished_at is not None


def test_cancel_twice_rejected(session: Session) -> None:
    target = _approved_target(session)
    assessment = assessments_service.create_assessment(session, target_id=target.id)
    assessments_service.cancel_assessment(session, assessment_id=assessment.id)
    with pytest.raises(InvalidTransitionError):
        assessments_service.cancel_assessment(session, assessment_id=assessment.id)

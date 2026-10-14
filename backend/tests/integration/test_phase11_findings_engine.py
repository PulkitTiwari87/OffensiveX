"""Integration test for the Phase 11 Findings Engine: the complete
DISCOVERED -> ... -> REPORTED lifecycle driven end to end through real
service calls (not just the abstract transition-table unit tests from
Phase 1), the status query filter, and REPORTED's terminality — against
a real Postgres container.
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
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
from offensivex.services import targets as targets_service
from offensivex.services.findings import mark_finding_reported, override_finding_status
from offensivex.services.scope import ScopeRuleInput
from tests.integration.auth_support import authenticated_client

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


def _make_assessment(session: Session):
    name = f"phase11-{uuid.uuid4().hex[:8]}.test"
    target = targets_service.create_target(session, name=name, type_="web_application")
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=[ScopeRuleInput(rule_type="domain", pattern="localhost")],
        attestation="attestation",
        valid_from=now,
        valid_until=now + timedelta(days=1),
        allow_private_targets=True,
    )
    targets_service.approve_authorization(
        session, target_id=target.id, version=authorization.version
    )
    assessment = models.Assessment(
        target_id=target.id,
        authorization_id=authorization.id,
        status=models.AssessmentStatus.RUNNING,
    )
    session.add(assessment)
    session.flush()
    return assessment


def test_full_lifecycle_discovered_to_reported(session: Session) -> None:
    assessment = _make_assessment(session)
    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.ENDPOINT,
        canonical_key="http://localhost:1/",
        attributes={},
    )
    finding, created = get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="Missing security header: X-Frame-Options",
        severity=models.FindingSeverity.MEDIUM,
        confidence=1.0,
        source="security_header_scan",
        affected_component="X-Frame-Options",
    )
    assert created is True
    assert finding.status is models.FindingStatus.DISCOVERED

    finding.status = models.FindingStatus.SUSPECTED
    session.flush()
    finding.status = models.FindingStatus.INVESTIGATING
    session.flush()

    override_finding_status(
        session, finding_id=finding.id, new_status=models.FindingStatus.CONFIRMED
    )
    assert finding.status is models.FindingStatus.CONFIRMED

    reported = mark_finding_reported(session, finding.id)
    assert reported.status is models.FindingStatus.REPORTED


def test_reported_is_terminal(session: Session) -> None:
    assessment = _make_assessment(session)
    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.ENDPOINT,
        canonical_key="http://localhost:1/",
        attributes={},
    )
    finding, _ = get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="x",
        severity=models.FindingSeverity.LOW,
        confidence=1.0,
        source="security_header_scan",
        affected_component="X-Content-Type-Options",
    )
    finding.status = models.FindingStatus.SUSPECTED
    session.flush()
    mark_finding_reported(session, finding.id)
    assert finding.status is models.FindingStatus.REPORTED

    with pytest.raises(InvalidTransitionError):
        mark_finding_reported(session, finding.id)


def test_rediscovery_after_reported_still_dedupes_and_bumps_last_seen(session: Session) -> None:
    """A rescan finding the same condition after a finding has already
    been reported is still the same finding (fingerprint match) — it
    does not spawn a duplicate row, even though its status has moved on."""
    assessment = _make_assessment(session)
    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.ENDPOINT,
        canonical_key="http://localhost:1/",
        attributes={},
    )
    finding, _ = get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="x",
        severity=models.FindingSeverity.LOW,
        confidence=1.0,
        source="security_header_scan",
        affected_component="Strict-Transport-Security",
    )
    finding.status = models.FindingStatus.SUSPECTED
    session.flush()
    mark_finding_reported(session, finding.id)
    first_seen = finding.first_seen

    rediscovered, created_again = get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="x",
        severity=models.FindingSeverity.LOW,
        confidence=1.0,
        source="security_header_scan",
        affected_component="Strict-Transport-Security",
    )
    assert created_again is False
    assert rediscovered.id == finding.id
    assert rediscovered.first_seen == first_seen
    assert rediscovered.last_seen >= first_seen
    # Status is left exactly as it was — rediscovery is not itself a
    # transition; only an agent/analyst action moves status.
    assert rediscovered.status is models.FindingStatus.REPORTED

    count = session.query(models.Finding).filter_by(assessment_id=assessment.id).count()
    assert count == 1


def test_status_filter_via_api(session: Session) -> None:
    assessment = _make_assessment(session)
    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.ENDPOINT,
        canonical_key="http://localhost:1/",
        attributes={},
    )
    f1, _ = get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="a",
        severity=models.FindingSeverity.LOW,
        confidence=1.0,
        source="security_header_scan",
        affected_component="A",
    )
    f2, _ = get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="b",
        severity=models.FindingSeverity.LOW,
        confidence=1.0,
        source="security_header_scan",
        affected_component="B",
    )
    f2.status = models.FindingStatus.SUSPECTED
    session.flush()
    session.commit()

    api_settings = Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
    )
    client = authenticated_client(api_settings)

    response_all = client.get(f"/api/v1/assessments/{assessment.id}/findings")
    assert len(response_all.json()) == 2

    response_discovered = client.get(
        f"/api/v1/assessments/{assessment.id}/findings", params={"status": "discovered"}
    )
    assert [f["id"] for f in response_discovered.json()] == [str(f1.id)]

    response_suspected = client.get(
        f"/api/v1/assessments/{assessment.id}/findings", params={"status": "suspected"}
    )
    assert [f["id"] for f in response_suspected.json()] == [str(f2.id)]

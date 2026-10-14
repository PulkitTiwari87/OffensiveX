"""Integration test for the Phase 13 Risk Engine against real Postgres:
scoring a CONFIRMED finding that sits on a real attack-graph edge (built
by Phase 12's engine) produces a higher score than the same finding
before it was on the graph, and the score/breakdown persist correctly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.attack_graph.engine import build_attack_graph
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.main import create_app
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
from offensivex.risk.engine import RISK_MODEL_VERSION, score_finding
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput

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


def _make_assessment(session: Session, *, criticality=None, exposure=None) -> models.Assessment:
    name = f"phase13-{uuid.uuid4().hex[:8]}.test"
    target = targets_service.create_target(
        session,
        name=name,
        type_="web_application",
        default_criticality=criticality or models.ImpactLevel.MEDIUM,
        default_exposure=exposure or models.ImpactLevel.MEDIUM,
    )
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


def test_score_rises_once_finding_is_on_the_real_attack_graph(session: Session) -> None:
    assessment = _make_assessment(
        session, criticality=models.ImpactLevel.HIGH, exposure=models.ImpactLevel.HIGH
    )
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
        title="Missing security header: X-Frame-Options",
        severity=models.FindingSeverity.MEDIUM,
        confidence=1.0,
        source="security_header_scan",
        affected_component="X-Frame-Options",
    )

    score_before = score_finding(session, finding)
    assert score_before.risk_model_version == RISK_MODEL_VERSION
    assert score_before.risk_breakdown["on_attack_graph"] is False
    before_value = score_before.risk_score

    finding.status = models.FindingStatus.CONFIRMED
    session.flush()
    build_attack_graph(session, assessment)

    score_after = score_finding(session, finding)
    assert score_after.risk_breakdown["on_attack_graph"] is True
    assert score_after.risk_breakdown["weakest_evidence_level"] == "verified"
    assert score_after.risk_score > before_value  # strictly higher once on the graph

    session.commit()
    api_settings = Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
    )
    client = TestClient(create_app(api_settings))
    response = client.get(f"/api/v1/findings/{finding.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] == score_after.risk_score
    assert body["risk_breakdown"]["model_version"] == RISK_MODEL_VERSION


def test_higher_criticality_target_scores_higher_for_the_same_finding(session: Session) -> None:
    low_assessment = _make_assessment(
        session, criticality=models.ImpactLevel.LOW, exposure=models.ImpactLevel.LOW
    )
    high_assessment = _make_assessment(
        session, criticality=models.ImpactLevel.CRITICAL, exposure=models.ImpactLevel.CRITICAL
    )

    def _score(assessment: models.Assessment) -> float:
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
            severity=models.FindingSeverity.MEDIUM,
            confidence=1.0,
            source="security_header_scan",
            affected_component="X-Frame-Options",
        )
        return score_finding(session, finding).risk_score

    assert _score(low_assessment) < _score(high_assessment)


def test_score_assessment_findings_scores_every_finding(session: Session) -> None:
    from offensivex.risk.engine import score_assessment_findings

    assessment = _make_assessment(session)
    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.ENDPOINT,
        canonical_key="http://localhost:1/",
        attributes={},
    )
    get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="a",
        severity=models.FindingSeverity.LOW,
        confidence=1.0,
        source="security_header_scan",
        affected_component="A",
    )
    get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="b",
        severity=models.FindingSeverity.HIGH,
        confidence=1.0,
        source="security_header_scan",
        affected_component="B",
    )

    scored = score_assessment_findings(session, assessment)
    assert len(scored) == 2
    assert all(f.risk_score is not None for f in scored)

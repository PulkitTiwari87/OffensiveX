"""Integration test for the Phase 12 Attack Graph engine: a CONFIRMED
missing-X-Frame-Options finding produces exactly one AttackEdge (verified
evidence level) and one AttackPath, against real Postgres; an unrelated
or rejected finding produces none. Also proves the graph is deterministic
(rebuilding twice doesn't duplicate) and reads back through
GET /api/v1/assessments/{id}/attack-paths.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.attack_graph.engine import build_attack_graph, find_attack_paths
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
from offensivex.services import targets as targets_service
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


def _make_assessment(session: Session) -> models.Assessment:
    name = f"phase12-{uuid.uuid4().hex[:8]}.test"
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


def test_confirmed_finding_produces_one_verified_edge_and_path(session: Session) -> None:
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
        title="Missing security header: X-Frame-Options",
        severity=models.FindingSeverity.MEDIUM,
        confidence=1.0,
        source="security_header_scan",
        affected_component="X-Frame-Options",
    )
    finding.status = models.FindingStatus.CONFIRMED
    session.flush()

    edges = build_attack_graph(session, assessment)
    assert len(edges) == 1
    assert edges[0].evidence_level is models.EvidenceLevel.VERIFIED
    assert edges[0].cause_id == finding.id
    assert edges[0].rule_id == "missing-x-frame-options-clickjacking-v1"

    paths = find_attack_paths(session, assessment)
    assert len(paths) == 1
    assert paths[0].evidence_level is models.EvidenceLevel.VERIFIED
    assert paths[0].edge_ids == [str(edges[0].id)]

    # Deterministic + idempotent: rebuilding doesn't duplicate anything.
    edges_again = build_attack_graph(session, assessment)
    assert len(edges_again) == 1
    assert edges_again[0].id == edges[0].id
    node_count = session.query(models.AttackNode).filter_by(assessment_id=assessment.id).count()
    assert node_count == 2  # entry + target, not re-created

    session.commit()
    api_settings = Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
    )
    client = authenticated_client(api_settings)
    response = client.get(f"/api/v1/assessments/{assessment.id}/attack-paths")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["evidence_level"] == "verified"


def test_rejected_finding_produces_no_edge(session: Session) -> None:
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
        severity=models.FindingSeverity.MEDIUM,
        confidence=1.0,
        source="security_header_scan",
        affected_component="X-Frame-Options",
    )
    finding.status = models.FindingStatus.REJECTED
    session.flush()

    edges = build_attack_graph(session, assessment)
    assert edges == []
    paths = find_attack_paths(session, assessment)
    assert paths == []


def test_finding_class_with_no_curated_rule_produces_no_edge(session: Session) -> None:
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
        severity=models.FindingSeverity.MEDIUM,
        confidence=1.0,
        source="security_header_scan",
        affected_component="Strict-Transport-Security",  # no rule for this one
    )
    finding.status = models.FindingStatus.CONFIRMED
    session.flush()

    edges = build_attack_graph(session, assessment)
    assert edges == []


def test_well_evidenced_suspected_finding_produces_potential_edge(session: Session) -> None:
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
        severity=models.FindingSeverity.MEDIUM,
        confidence=0.9,
        source="security_header_scan",
        affected_component="X-Frame-Options",
    )
    finding.status = models.FindingStatus.SUSPECTED
    session.flush()

    edges = build_attack_graph(session, assessment)
    assert len(edges) == 1
    assert edges[0].evidence_level is models.EvidenceLevel.POTENTIAL

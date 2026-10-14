"""Integration test for Phase 14 Reporting against real Postgres: generate
a report over HTTP, read it back, and confirm it is an immutable snapshot
that moves findings to REPORTED.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.main import create_app
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
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


@pytest.fixture
def client(db_engine) -> TestClient:
    api_settings = Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=db_engine.url.render_as_string(hide_password=False),
    )
    return TestClient(create_app(api_settings))


def _assessment_with_finding(session: Session) -> tuple[models.Assessment, models.Finding]:
    target = targets_service.create_target(
        session, name=f"phase14-{uuid.uuid4().hex[:8]}.test", type_="web_application"
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
        title="# Missing security header: X-Frame-Options",
        severity=models.FindingSeverity.MEDIUM,
        confidence=1.0,
        source="security_header_scan",
        affected_component="X-Frame-Options",
    )
    finding.status = models.FindingStatus.CONFIRMED
    agent_run = models.AgentRun(
        assessment_id=assessment.id,
        agent_type=models.AgentType.VALIDATION,
        status=models.AgentRunStatus.QUEUED,
    )
    session.add(agent_run)
    session.flush()
    tool_execution = models.ToolExecution(
        agent_run_id=agent_run.id,
        tool_name="security_header_validation_check",
        capability="security_header_validation_check",
        scope_decision=models.ScopeDecision.ALLOWED,
    )
    session.add(tool_execution)
    session.flush()
    session.add(
        models.Evidence(
            finding_id=finding.id,
            kind=models.EvidenceKind.VALIDATION_RESULT,
            tool_execution_id=tool_execution.id,
            excerpt="```\n# Owned",
        )
    )
    session.commit()
    return assessment, finding


def test_generate_and_fetch_report(session: Session, client: TestClient) -> None:
    assessment, finding = _assessment_with_finding(session)

    response = client.post(f"/api/v1/assessments/{assessment.id}/reports")
    assert response.status_code == 201
    body = response.json()
    assert body["formats"] == ["json", "markdown"]
    assert body["provenance"]["ai_generated_executive_summary"] is False
    assert body["content_json"]["executive_summary"] is None  # no provider -> none fabricated
    assert str(finding.id) in body["content_json"]["confirmed_vulnerabilities"]
    assert len(body["content_json"]["evidence"]) == 1
    assert body["content_json"]["remediation"][0]["affected_component"] == "X-Frame-Options"
    assert "\n# Owned" not in body["content_markdown"]
    assert "\\# Missing security header" in body["content_markdown"]

    fetched = client.get(f"/api/v1/reports/{body['id']}")
    assert fetched.status_code == 200
    assert fetched.json() == body

    session.expire_all()
    assert session.get(models.Finding, finding.id).status is models.FindingStatus.REPORTED


def test_regenerating_creates_a_new_report(session: Session, client: TestClient) -> None:
    assessment, _ = _assessment_with_finding(session)
    first = client.post(f"/api/v1/assessments/{assessment.id}/reports").json()
    second = client.post(f"/api/v1/assessments/{assessment.id}/reports").json()
    assert first["id"] != second["id"]
    assert client.get(f"/api/v1/reports/{first['id']}").status_code == 200


def test_markdown_only_format_omits_json(session: Session, client: TestClient) -> None:
    assessment, _ = _assessment_with_finding(session)
    body = client.post(
        f"/api/v1/assessments/{assessment.id}/reports", json={"formats": ["markdown"]}
    ).json()
    assert body["content_json"] is None
    assert body["content_markdown"]


def test_unknown_report_and_assessment_are_404(client: TestClient) -> None:
    assert client.get(f"/api/v1/reports/{uuid.uuid4()}").status_code == 404
    assert client.post(f"/api/v1/assessments/{uuid.uuid4()}/reports").status_code == 404

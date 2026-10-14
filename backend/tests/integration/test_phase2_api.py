"""HTTP-level integration tests for the Phase 2 API: Targets,
Authorizations, Assessments. Require a real PostgreSQL instance.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from offensivex.core.config import Settings
from offensivex.db import models
from tests.integration.auth_support import authenticated_client

pytestmark = pytest.mark.integration


@pytest.fixture
def settings() -> Settings:
    return Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url="postgresql+psycopg://offensivex:offensivex@localhost:5433/offensivex",
    )


@pytest.fixture
def client(settings: Settings):
    engine = create_engine(
        settings.database_url, pool_pre_ping=True, connect_args={"connect_timeout": 2}
    )
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable ({exc.__class__.__name__}).")
    finally:
        engine.dispose()
    return authenticated_client(settings, models.UserRole.ADMIN)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_full_vertical_slice_through_http(client: TestClient, settings: Settings) -> None:
    """An analyst submits scope; a *different* user (admin, `client`) approves
    it — ADR-013's separation of duties — then the analyst runs the assessment."""
    name = f"phase2-api-{uuid.uuid4().hex[:8]}.test"
    now = datetime.now(UTC)
    analyst = authenticated_client(settings, models.UserRole.ANALYST)

    r = analyst.post("/api/v1/targets", json={"name": name, "type": "web_application"})
    assert r.status_code == 201, r.text
    target = r.json()

    r = analyst.post(
        f"/api/v1/targets/{target['id']}/authorizations",
        json={
            "scope_rules": [{"rule_type": "domain", "pattern": name}],
            "attestation": "I attest I am authorized to test this target.",
            "valid_from": _iso(now),
            "valid_until": _iso(now + timedelta(days=30)),
        },
    )
    assert r.status_code == 201, r.text
    authorization = r.json()
    assert authorization["status"] == "pending"

    r = client.post(
        f"/api/v1/targets/{target['id']}/authorizations/{authorization['version']}/approve"
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved"

    r = analyst.post("/api/v1/assessments", json={"target_id": target["id"]})
    assert r.status_code == 201, r.text
    assessment = r.json()
    assert assessment["status"] == "running"
    assert len(assessment["agent_runs"]) == 1
    assert assessment["agent_runs"][0]["agent_type"] == "recon"
    assert assessment["agent_runs"][0]["status"] == "queued"

    r = client.get(f"/api/v1/assessments/{assessment['id']}")
    assert r.status_code == 200
    assert r.json()["id"] == assessment["id"]

    r = client.post(f"/api/v1/assessments/{assessment['id']}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


def test_create_assessment_without_authorization_returns_422(client: TestClient) -> None:
    name = f"phase2-api-{uuid.uuid4().hex[:8]}.test"
    r = client.post("/api/v1/targets", json={"name": name, "type": "web_application"})
    target = r.json()

    r = client.post("/api/v1/assessments", json={"target_id": target["id"]})
    assert r.status_code == 422
    body = r.json()
    assert body["title"] == "Target not authorized"
    assert "request_id" in body


def test_create_assessment_for_nonexistent_target_returns_404(client: TestClient) -> None:
    r = client.post("/api/v1/assessments", json={"target_id": str(uuid.uuid4())})
    assert r.status_code == 404


def test_get_nonexistent_assessment_returns_404(client: TestClient) -> None:
    r = client.get(f"/api/v1/assessments/{uuid.uuid4()}")
    assert r.status_code == 404


def test_submit_authorization_with_catch_all_scope_returns_422(client: TestClient) -> None:
    name = f"phase2-api-{uuid.uuid4().hex[:8]}.test"
    r = client.post("/api/v1/targets", json={"name": name, "type": "web_application"})
    target = r.json()
    now = datetime.now(UTC)

    r = client.post(
        f"/api/v1/targets/{target['id']}/authorizations",
        json={
            "scope_rules": [{"rule_type": "cidr", "pattern": "0.0.0.0/0"}],
            "attestation": "attestation",
            "valid_from": _iso(now),
            "valid_until": _iso(now + timedelta(days=1)),
        },
    )
    assert r.status_code == 422
    assert r.json()["title"] == "Invalid scope rule"


def test_duplicate_target_name_returns_409(client: TestClient) -> None:
    name = f"phase2-api-{uuid.uuid4().hex[:8]}.test"
    r1 = client.post("/api/v1/targets", json={"name": name, "type": "web_application"})
    assert r1.status_code == 201
    r2 = client.post("/api/v1/targets", json={"name": name, "type": "web_application"})
    assert r2.status_code == 409

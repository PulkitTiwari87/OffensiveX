"""`GET /api/v1/findings/{id}/ml-advisory` through the real API stack (ADR-026).

Advisory is read-only and separate: the finding's own severity / cvss_score /
status / risk_score must be identical before and after, and an empty advisory
list is a normal state (feature off, no model), never an error.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.main import create_app
from offensivex.ml_advisory import service as ml_service
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput
from tests.integration.auth_support import authenticated_client

pytestmark = pytest.mark.integration

MODELS = Path(__file__).resolve().parents[2] / "models"
DESC = (
    "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints. "
    "An attacker who can control log messages can execute arbitrary code."
)


@pytest.fixture(autouse=True)
def _fresh_ml_cache():
    ml_service.reset_cache()
    yield
    ml_service.reset_cache()


@pytest.fixture
def db_engine():
    base = Settings(environment="test")
    url = base.test_database_url or base.database_url
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


def _cve_finding(session: Session, *, cve: str | None, description: str | None) -> models.Finding:
    target = targets_service.create_target(
        session, name=f"ml-{uuid.uuid4().hex[:8]}.test", type_="web_application"
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
        title="Log4j JNDI injection",
        severity=models.FindingSeverity.MEDIUM,
        confidence=0.9,
        source="cve_lookup",
        affected_component="log4j-core",
    )
    finding.cve, finding.description = cve, description
    session.flush()
    session.commit()
    return finding


def _api_settings(session: Session, **kw) -> Settings:
    return Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
        **kw,
    )


def _real_pins() -> dict[str, str]:
    files = [*(MODELS / "severity" / "models").glob("*.joblib")]
    files += [*(MODELS / "exploit_likelihood" / "models").glob("*.joblib")]
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def test_disabled_returns_empty_list_and_finding_is_untouched(session: Session) -> None:
    finding = _cve_finding(session, cve="CVE-2021-44228", description=DESC)
    client = authenticated_client(_api_settings(session))  # ml_advisory_enabled defaults False
    response = client.get(f"/api/v1/findings/{finding.id}/ml-advisory")
    assert response.status_code == 200
    body = response.json()
    assert body["ml_advisory"] == [] and body["finding_id"] == str(finding.id)
    assert "not that the finding is safe" in body["note"]


def test_unknown_finding_is_404_and_unauthenticated_is_rejected(session: Session) -> None:
    settings = _api_settings(session)
    client = authenticated_client(settings)
    assert client.get(f"/api/v1/findings/{uuid.uuid4()}/ml-advisory").status_code == 404
    anonymous = TestClient(create_app(settings))
    assert anonymous.get(f"/api/v1/findings/{uuid.uuid4()}/ml-advisory").status_code in (401, 403)


@pytest.mark.skipif(
    not (MODELS / "severity" / "models").is_dir()
    or not (MODELS / "exploit_likelihood" / "models").is_dir(),
    reason="staged ML artifacts not present (backend/models/ is git-ignored)",
)
def test_enabled_returns_advisories_without_changing_the_finding(session: Session) -> None:
    finding = _cve_finding(session, cve="CVE-2021-44228", description=DESC)
    client = authenticated_client(
        _api_settings(session, ml_advisory_enabled=True, ml_artifact_pins=_real_pins())
    )
    before = client.get(f"/api/v1/findings/{finding.id}").json()

    response = client.get(f"/api/v1/findings/{finding.id}/ml-advisory")
    assert response.status_code == 200
    slots = {a["slot"]: a for a in response.json()["ml_advisory"]}
    assert set(slots) == {"severity", "exploit_likelihood"}
    assert all(a["is_estimate"] is True for a in slots.values())

    after = client.get(f"/api/v1/findings/{finding.id}").json()
    for field in ("severity", "status", "risk_score", "confidence", "title"):
        assert after[field] == before[field]
    assert "ml_advisory" not in after  # separate endpoint; never merged into the Finding


def test_non_cve_finding_gets_no_advisory(session: Session) -> None:
    finding = _cve_finding(session, cve=None, description=DESC)
    client = authenticated_client(
        _api_settings(session, ml_advisory_enabled=True, ml_artifact_pins={})
    )
    response = client.get(f"/api/v1/findings/{finding.id}/ml-advisory")
    assert response.status_code == 200 and response.json()["ml_advisory"] == []

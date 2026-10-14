"""Integration test for the Phase 10 Validation Agent: the opt-in gate
(both at the agent level and, independently, at the Tool Registry's
`requires_validation_mode` level), the confirmed/rejected/unresolved
outcomes, and the explicit analyst override endpoint — all against real
Postgres and real local HTTP servers.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.agents.runtime import AgentStep
from offensivex.agents.validation import ValidationNotEnabledError, run_validation_agent
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput
from offensivex.tools.adapters.security_header_validation import SecurityHeaderValidationCheck
from offensivex.tools.registry import ToolRegistry, ValidationModeRequiredError
from tests.integration.auth_support import authenticated_client

pytestmark = pytest.mark.integration


class _NoHeadersHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: Any) -> None:
        pass


class _ScriptedLLMProvider:
    name = "scripted"

    def __init__(self, steps: list[AgentStep]) -> None:
        self._steps = list(steps)

    async def generate_structured(self, *, prompt: str, schema: type, **params: Any) -> Any:
        return self._steps.pop(0)


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


def _make_investigating_finding(session: Session, url: str, *, validation_enabled: bool):
    name = f"phase10-{uuid.uuid4().hex[:8]}.test"
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
        validation_enabled=validation_enabled,
    )
    session.add(assessment)
    session.flush()

    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.ENDPOINT,
        canonical_key=url,
        attributes={},
    )
    finding, _ = get_or_create_finding(
        session,
        assessment_id=assessment.id,
        asset_id=asset.id,
        title="Missing security header: Strict-Transport-Security",
        severity=models.FindingSeverity.MEDIUM,
        confidence=1.0,
        source="security_header_scan",
        affected_component="Strict-Transport-Security",
    )
    finding.status = models.FindingStatus.INVESTIGATING
    session.flush()
    return assessment, finding


def _agent_run(session, assessment) -> models.AgentRun:
    agent_run = models.AgentRun(
        assessment_id=assessment.id,
        agent_type=models.AgentType.VALIDATION,
        status=models.AgentRunStatus.QUEUED,
    )
    session.add(agent_run)
    session.flush()
    return agent_run


def test_validation_agent_refuses_to_run_when_not_opted_in(session: Session) -> None:
    assessment, finding = _make_investigating_finding(
        session, "http://localhost:1/", validation_enabled=False
    )
    agent_run = _agent_run(session, assessment)
    registry = ToolRegistry()
    registry.register(SecurityHeaderValidationCheck())

    with pytest.raises(ValidationNotEnabledError):
        run_validation_agent(
            session,
            llm_provider=_ScriptedLLMProvider([]),
            tool_registry=registry,
            assessment=assessment,
            agent_run=agent_run,
            finding=finding,
        )
    assert finding.status is models.FindingStatus.INVESTIGATING  # untouched


def test_tool_registry_independently_refuses_the_capability_without_opt_in(
    session: Session,
) -> None:
    """Defense in depth: even bypassing the agent-level gate, the Tool
    Registry's own requires_validation_mode check (Phase 3) refuses the
    capability directly."""
    assessment, _finding = _make_investigating_finding(
        session, "http://localhost:1/", validation_enabled=False
    )
    registry = ToolRegistry()
    registry.register(SecurityHeaderValidationCheck())

    with pytest.raises(ValidationModeRequiredError):
        registry.execute(
            session,
            capability="security_header_validation_check",
            request={"url": "http://localhost:1/"},
            assessment=assessment,
        )


def test_validation_agent_confirms_finding(session: Session) -> None:
    server = HTTPServer(("127.0.0.1", 0), _NoHeadersHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://localhost:{port}/"
        assessment, finding = _make_investigating_finding(session, url, validation_enabled=True)
        agent_run = _agent_run(session, assessment)
        registry = ToolRegistry()
        registry.register(SecurityHeaderValidationCheck())
        llm = _ScriptedLLMProvider(
            [
                AgentStep(
                    action="call_tool",
                    capability="security_header_validation_check",
                    request={"url": url, "header": "Strict-Transport-Security"},
                ),
                AgentStep(
                    action="finish",
                    output={"outcome": "confirmed", "notes": "header still missing"},
                ),
            ]
        )

        run_validation_agent(
            session,
            llm_provider=llm,
            tool_registry=registry,
            assessment=assessment,
            agent_run=agent_run,
            finding=finding,
        )

        assert finding.status is models.FindingStatus.CONFIRMED
        evidence = session.query(models.Evidence).filter_by(finding_id=finding.id).all()
        assert len(evidence) == 1
        assert evidence[0].kind is models.EvidenceKind.VALIDATION_RESULT

        session.commit()
        api_settings = Settings(
            environment="test",
            secret_key="test-secret-key-not-used-for-anything-real",
            database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
        )
        client = authenticated_client(api_settings)
        response = client.get(f"/api/v1/findings/{finding.id}")
        assert response.json()["status"] == "confirmed"
    finally:
        server.shutdown()


def test_validation_agent_rejects_finding_when_condition_no_longer_holds(
    session: Session,
) -> None:
    class _AllHeadersHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Strict-Transport-Security", "max-age=1")
            self.end_headers()
            self.wfile.write(b"fixed")

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _AllHeadersHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://localhost:{port}/"
        assessment, finding = _make_investigating_finding(session, url, validation_enabled=True)
        agent_run = _agent_run(session, assessment)
        registry = ToolRegistry()
        registry.register(SecurityHeaderValidationCheck())
        llm = _ScriptedLLMProvider(
            [
                AgentStep(
                    action="call_tool",
                    capability="security_header_validation_check",
                    request={"url": url, "header": "Strict-Transport-Security"},
                ),
                AgentStep(
                    action="finish",
                    output={"outcome": "rejected", "notes": "header present now"},
                ),
            ]
        )

        run_validation_agent(
            session,
            llm_provider=llm,
            tool_registry=registry,
            assessment=assessment,
            agent_run=agent_run,
            finding=finding,
        )

        assert finding.status is models.FindingStatus.REJECTED
    finally:
        server.shutdown()


def test_validation_agent_unresolved_leaves_status_unchanged(session: Session) -> None:
    server = HTTPServer(("127.0.0.1", 0), _NoHeadersHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://localhost:{port}/"
        assessment, finding = _make_investigating_finding(session, url, validation_enabled=True)
        agent_run = _agent_run(session, assessment)
        registry = ToolRegistry()
        registry.register(SecurityHeaderValidationCheck())
        llm = _ScriptedLLMProvider(
            [
                AgentStep(
                    action="call_tool",
                    capability="security_header_validation_check",
                    request={"url": url, "header": "Strict-Transport-Security"},
                ),
                AgentStep(
                    action="finish",
                    output={"outcome": "unresolved", "notes": "ambiguous result"},
                ),
            ]
        )

        run_validation_agent(
            session,
            llm_provider=llm,
            tool_registry=registry,
            assessment=assessment,
            agent_run=agent_run,
            finding=finding,
        )

        assert finding.status is models.FindingStatus.INVESTIGATING  # unchanged
    finally:
        server.shutdown()


def test_analyst_override_confirms_a_finding_via_patch(session: Session) -> None:
    assessment, finding = _make_investigating_finding(
        session, "http://localhost:1/", validation_enabled=False
    )
    session.commit()

    api_settings = Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
    )
    client = authenticated_client(api_settings)
    response = client.patch(f"/api/v1/findings/{finding.id}/status", json={"status": "rejected"})
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"


def test_analyst_override_rejects_invalid_transition(session: Session) -> None:
    name = f"phase10-{uuid.uuid4().hex[:8]}.test"
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
    # still DISCOVERED — CONFIRMED is not reachable directly from here.
    session.commit()

    api_settings = Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
    )
    client = authenticated_client(api_settings)
    response = client.patch(f"/api/v1/findings/{finding.id}/status", json={"status": "confirmed"})
    assert response.status_code == 422

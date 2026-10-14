"""Integration test for the Phase 9 Investigation Agent: re-checks a real
Finding (created the same way Phase 8 does, against a real local HTTP
server) through the real Tool Registry, writes real Evidence, and moves
the Finding through SUSPECTED -> INVESTIGATING — against a real Postgres
container. Also covers the "condition no longer reproducible" path back
to SUSPECTED, and reads the result back through
GET /api/v1/findings/{id}.
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

from offensivex.agents.investigation import run_investigation_agent
from offensivex.agents.runtime import AgentStep
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.observations.normalizer import get_or_create_asset, get_or_create_finding
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput
from offensivex.tools.adapters.security_header_scan import SecurityHeaderScanAdapter
from offensivex.tools.registry import ToolRegistry
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


def _make_assessment_and_discovered_finding(session: Session, url: str) -> tuple:
    name = f"phase9-{uuid.uuid4().hex[:8]}.test"
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
    return assessment, finding


def test_investigation_confirms_condition_still_present(session: Session) -> None:
    server = HTTPServer(("127.0.0.1", 0), _NoHeadersHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://localhost:{port}/"
        assessment, finding = _make_assessment_and_discovered_finding(session, url)
        assert finding.status is models.FindingStatus.DISCOVERED

        agent_run = models.AgentRun(
            assessment_id=assessment.id,
            agent_type=models.AgentType.INVESTIGATION,
            status=models.AgentRunStatus.QUEUED,
        )
        session.add(agent_run)
        session.flush()

        registry = ToolRegistry()
        registry.register(SecurityHeaderScanAdapter())
        llm = _ScriptedLLMProvider(
            [
                AgentStep(
                    action="call_tool",
                    capability="security_header_scan",
                    request={"url": url},
                ),
                AgentStep(
                    action="finish",
                    output={"still_present": True, "notes": "still missing on re-check"},
                ),
            ]
        )

        run_investigation_agent(
            session,
            llm_provider=llm,
            tool_registry=registry,
            assessment=assessment,
            agent_run=agent_run,
            finding=finding,
        )

        assert finding.status is models.FindingStatus.INVESTIGATING
        evidence = session.query(models.Evidence).filter_by(finding_id=finding.id).all()
        assert len(evidence) == 1
        assert "still missing" in evidence[0].excerpt
        assert evidence[0].tool_execution_id is not None

        session.commit()
        api_settings = Settings(
            environment="test",
            secret_key="test-secret-key-not-used-for-anything-real",
            database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
        )
        client = authenticated_client(api_settings)
        response = client.get(f"/api/v1/findings/{finding.id}")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "investigating"
        assert len(body["evidence"]) == 1
    finally:
        server.shutdown()


def test_investigation_returns_finding_to_suspected_when_no_longer_reproducible(
    session: Session,
) -> None:
    class _AllHeadersHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Strict-Transport-Security", "max-age=1")
            self.end_headers()
            self.wfile.write(b"fixed now")

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _AllHeadersHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://localhost:{port}/"
        assessment, finding = _make_assessment_and_discovered_finding(session, url)

        agent_run = models.AgentRun(
            assessment_id=assessment.id,
            agent_type=models.AgentType.INVESTIGATION,
            status=models.AgentRunStatus.QUEUED,
        )
        session.add(agent_run)
        session.flush()

        registry = ToolRegistry()
        registry.register(SecurityHeaderScanAdapter())
        llm = _ScriptedLLMProvider(
            [
                AgentStep(
                    action="call_tool",
                    capability="security_header_scan",
                    request={"url": url},
                ),
                AgentStep(
                    action="finish",
                    output={"still_present": False, "notes": "header now present"},
                ),
            ]
        )

        run_investigation_agent(
            session,
            llm_provider=llm,
            tool_registry=registry,
            assessment=assessment,
            agent_run=agent_run,
            finding=finding,
        )

        assert finding.status is models.FindingStatus.SUSPECTED
    finally:
        server.shutdown()


def test_investigation_agent_cannot_set_confirmed_or_rejected() -> None:
    """Static assertion, not a runtime test: InvestigationAgentOutput has
    no field that could set CONFIRMED/REJECTED, and run_investigation_agent
    never calls assert_valid_transition toward either — the schema itself
    makes the forbidden action unrepresentable, per
    docs/agents/investigation-agent.md's security constraint."""
    from offensivex.agents.investigation import InvestigationAgentOutput

    assert set(InvestigationAgentOutput.model_fields) == {"still_present", "notes"}

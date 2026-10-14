"""Integration test for the Phase 6 Recon Agent: a scripted agent
resolves "localhost" and probes a real local HTTP server through the
real Tool Registry, normalizing both into Asset/Observation rows against
a real Postgres container — then reads them back through the real
GET /api/v1/assessments/{id}/assets endpoint.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.agents.recon import run_recon_agent
from offensivex.agents.runtime import AgentStep
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.main import create_app
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.registry import ScopeViolationError, ToolRegistry

pytestmark = pytest.mark.integration


class _QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib-mandated name
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"recon target page")

    def log_message(self, *args: Any) -> None:  # silence stdlib's own logging
        pass


@pytest.fixture
def local_http_server():
    server = HTTPServer(("127.0.0.1", 0), _QuietHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()


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


def test_recon_agent_discovers_host_and_endpoint_through_real_tools(
    session: Session, local_http_server: int
) -> None:
    port = local_http_server
    name = f"phase6-{uuid.uuid4().hex[:8]}.test"
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

    agent_run = models.AgentRun(
        assessment_id=assessment.id,
        agent_type=models.AgentType.RECON,
        status=models.AgentRunStatus.QUEUED,
    )
    session.add(agent_run)
    session.flush()

    registry = ToolRegistry()
    registry.register(DnsResolutionAdapter())
    registry.register(HttpProbeAdapter())

    llm = _ScriptedLLMProvider(
        [
            AgentStep(
                action="call_tool",
                capability="dns_resolution",
                request={"hostname": "localhost"},
            ),
            AgentStep(
                action="call_tool",
                capability="http_probe",
                request={"url": f"http://localhost:{port}/"},
            ),
            AgentStep(
                action="finish",
                output={"assets_discovered": 2, "summary": "mapped localhost and its web port"},
            ),
        ]
    )

    result = run_recon_agent(
        session,
        llm_provider=llm,
        tool_registry=registry,
        assessment=assessment,
        agent_run=agent_run,
    )

    assert result.output.assets_discovered == 2
    assert agent_run.status is models.AgentRunStatus.SUCCEEDED

    assets = session.query(models.Asset).filter_by(assessment_id=assessment.id).all()
    assert len(assets) == 2
    host_asset = next(a for a in assets if a.asset_type is models.AssetType.HOST)
    endpoint_asset = next(a for a in assets if a.asset_type is models.AssetType.ENDPOINT)
    assert host_asset.canonical_key == "localhost"
    assert endpoint_asset.canonical_key == f"http://localhost:{port}/"
    assert endpoint_asset.attributes["status_code"] == 200

    observations = (
        session.query(models.Observation)
        .join(models.Asset)
        .filter(models.Asset.assessment_id == assessment.id)
        .all()
    )
    assert {o.type for o in observations} == {
        models.ObservationType.HOST_DISCOVERED,
        models.ObservationType.ENDPOINT_DISCOVERED,
    }
    assert all(o.tool_execution_id is not None for o in observations)

    # Read them back through the real HTTP API.
    session.commit()
    api_settings = Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url=session.get_bind().engine.url.render_as_string(hide_password=False),
    )
    client = TestClient(create_app(api_settings))
    response = client.get(f"/api/v1/assessments/{assessment.id}/assets")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert {item["asset_type"] for item in body} == {"host", "endpoint"}


def test_recon_agent_cannot_probe_a_host_outside_scope(session: Session) -> None:
    """scope-escape test: the agent asking for a destination outside the
    authorized scope must be refused by the Scope Guard, exactly as for a
    human-triggered call — the agent's intent never overrides it."""
    name = f"phase6-{uuid.uuid4().hex[:8]}.test"
    target = targets_service.create_target(session, name=name, type_="web_application")
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=[ScopeRuleInput(rule_type="domain", pattern="only-this-host.test")],
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
    agent_run = models.AgentRun(
        assessment_id=assessment.id,
        agent_type=models.AgentType.RECON,
        status=models.AgentRunStatus.QUEUED,
    )
    session.add(agent_run)
    session.flush()

    registry = ToolRegistry()
    registry.register(DnsResolutionAdapter())
    registry.register(HttpProbeAdapter())

    llm = _ScriptedLLMProvider(
        [
            AgentStep(
                action="call_tool",
                capability="dns_resolution",
                request={"hostname": "localhost"},  # not in scope for this assessment
            ),
        ]
    )

    with pytest.raises(ScopeViolationError):
        run_recon_agent(
            session,
            llm_provider=llm,
            tool_registry=registry,
            assessment=assessment,
            agent_run=agent_run,
        )

    assert agent_run.status is models.AgentRunStatus.FAILED
    assert session.query(models.Asset).filter_by(assessment_id=assessment.id).count() == 0

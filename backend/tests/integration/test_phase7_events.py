"""Integration test for the Phase 7 event log: runs a real Recon Agent
pass (same pattern as Phase 6) and verifies list_assessment_events
assembles every row it touched into one chronological, correctly-typed
feed, against a real Postgres container.
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

from offensivex.agents.recon import run_recon_agent
from offensivex.agents.runtime import AgentStep
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.services import targets as targets_service
from offensivex.services.events import list_assessment_events
from offensivex.services.scope import ScopeRuleInput
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.registry import ToolRegistry

pytestmark = pytest.mark.integration


class _QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: Any) -> None:
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


def test_event_feed_assembles_every_row_in_chronological_order(
    session: Session, local_http_server: int
) -> None:
    port = local_http_server
    name = f"phase7-{uuid.uuid4().hex[:8]}.test"
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
        started_at=now,
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
                action="call_tool", capability="dns_resolution", request={"hostname": "localhost"}
            ),
            AgentStep(
                action="call_tool",
                capability="http_probe",
                request={"url": f"http://localhost:{port}/"},
            ),
            AgentStep(action="finish", output={"assets_discovered": 2, "summary": "done"}),
        ]
    )
    run_recon_agent(
        session,
        llm_provider=llm,
        tool_registry=registry,
        assessment=assessment,
        agent_run=agent_run,
    )
    session.commit()

    events = list_assessment_events(session, assessment_id=assessment.id)
    event_types = [e.type for e in events]

    assert "assessment.created" in event_types
    assert "assessment.started" in event_types
    assert event_types.count("agent.scheduled") == 1
    assert event_types.count("agent.started") == 1
    assert event_types.count("agent.completed") == 1
    assert event_types.count("tool.started") == 2
    assert event_types.count("tool.completed") == 2
    assert event_types.count("asset.discovered") == 2
    assert event_types.count("observation.created") == 2

    # Chronological: every event's occurred_at is non-decreasing.
    timestamps = [e.occurred_at for e in events]
    assert timestamps == sorted(timestamps)


def test_event_feed_for_nonexistent_assessment_raises_not_found(session: Session) -> None:
    from offensivex.core.errors import NotFoundError

    with pytest.raises(NotFoundError):
        list_assessment_events(session, assessment_id=uuid.uuid4())

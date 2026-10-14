"""Integration test for the Phase 5 agent framework: a full agent loop —
call the real dns_resolution capability (Phase 3) through the real Tool
Registry, then finish with a typed output — against a real Postgres
container. Proves the framework end to end with a scripted LLM provider
(no API key available yet; see docs/roadmap/current-status.md).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.agents.definition import RECON_PROOF_DEFINITION, ReconProofOutput
from offensivex.agents.runtime import AgentSession, AgentStep
from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.registry import ToolRegistry

pytestmark = pytest.mark.integration


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


def test_recon_proof_agent_resolves_dns_through_real_registry_and_finishes(
    session: Session,
) -> None:
    name = f"phase5-{uuid.uuid4().hex[:8]}.test"
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

    llm = _ScriptedLLMProvider(
        [
            AgentStep(
                action="call_tool",
                capability="dns_resolution",
                request={"hostname": "localhost"},
            ),
            AgentStep(
                action="finish",
                output={"discovered_addresses": ["127.0.0.1"], "summary": "resolved localhost"},
            ),
        ]
    )

    agent_session = AgentSession(
        session,
        definition=RECON_PROOF_DEFINITION,
        llm_provider=llm,
        tool_registry=registry,
        assessment=assessment,
        agent_run=agent_run,
    )
    result = agent_session.run()

    assert isinstance(result.output, ReconProofOutput)
    assert result.turns_used == 2
    assert agent_run.status is models.AgentRunStatus.SUCCEEDED
    assert agent_run.attempts == 1
    assert agent_run.output_ref["output"]["summary"] == "resolved localhost"

    # The tool call the agent made is audited exactly like a human-
    # triggered one, now linked to this AgentRun.
    tool_execution = session.query(models.ToolExecution).filter_by(agent_run_id=agent_run.id).one()
    assert tool_execution.capability == "dns_resolution"
    assert tool_execution.status is models.ToolExecutionStatus.COMPLETED

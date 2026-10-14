"""Unit tests for offensivex.agents.runtime's bounded-agency checks that
need no database: toolset membership and the typed output contract are
both enforced *before* anything would ever touch the Tool Registry or a
real session, so they're provable with plain Python doubles.

The full happy-path loop (an agent actually calling a tool through the
real Tool Registry and writing an AgentRun row) is an integration test —
see tests/integration/test_phase5_agent_runtime.py.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from offensivex.agents.definition import AgentDefinition
from offensivex.agents.runtime import (
    AgentOutputContractError,
    AgentSession,
    AgentStep,
    AgentTurnLimitExceededError,
    ToolsetMembershipError,
)
from offensivex.db import models


class _ProofOutput(BaseModel):
    summary: str


class _ScriptedLLMProvider:
    """Implements offensivex.llm.base.LLMProvider against a fixed script
    of steps, one per call — no network, no API key."""

    name = "scripted"

    def __init__(self, steps: list[AgentStep]) -> None:
        self._steps = list(steps)

    async def generate_structured(self, *, prompt: str, schema: type, **params: Any) -> Any:
        return self._steps.pop(0)


def _definition(allowed: frozenset[str] = frozenset({"dns_resolution"})) -> AgentDefinition:
    return AgentDefinition(
        agent_type=models.AgentType.RECON,
        allowed_capabilities=allowed,
        system_prompt="test",
        output_schema=_ProofOutput,
        max_turns=3,
    )


def _bare_agent_run() -> models.AgentRun:
    """A transient (never session.add()-ed) AgentRun — fine for these
    tests, since the mocked session's .flush() is a no-op double, not a
    real database call."""
    return models.AgentRun(
        assessment_id=None,
        agent_type=models.AgentType.RECON,
        status=models.AgentRunStatus.QUEUED,
        attempts=0,
    )


def test_requesting_capability_outside_toolset_is_rejected_before_registry_is_touched() -> None:
    llm = _ScriptedLLMProvider(
        [AgentStep(action="call_tool", capability="shell_execution", request={})]
    )
    registry = MagicMock()
    session_mock = MagicMock()

    agent_session = AgentSession(
        session_mock,
        definition=_definition(allowed=frozenset({"dns_resolution"})),
        llm_provider=llm,
        tool_registry=registry,
        assessment=MagicMock(),
        agent_run=_bare_agent_run(),
    )

    with pytest.raises(ToolsetMembershipError):
        agent_session.run()

    registry.execute.assert_not_called()


def test_finish_with_output_violating_schema_raises_contract_error() -> None:
    llm = _ScriptedLLMProvider([AgentStep(action="finish", output={"wrong_field": "nope"})])
    agent_session = AgentSession(
        MagicMock(),
        definition=_definition(),
        llm_provider=llm,
        tool_registry=MagicMock(),
        assessment=MagicMock(),
        agent_run=_bare_agent_run(),
    )

    with pytest.raises(AgentOutputContractError):
        agent_session.run()


def test_finish_with_valid_output_succeeds_without_any_tool_call() -> None:
    llm = _ScriptedLLMProvider([AgentStep(action="finish", output={"summary": "nothing to do"})])
    registry = MagicMock()
    agent_run = _bare_agent_run()

    agent_session = AgentSession(
        MagicMock(),
        definition=_definition(),
        llm_provider=llm,
        tool_registry=registry,
        assessment=MagicMock(),
        agent_run=agent_run,
    )

    result = agent_session.run()
    assert result.output.summary == "nothing to do"
    assert result.turns_used == 1
    registry.execute.assert_not_called()
    assert agent_run.status is models.AgentRunStatus.SUCCEEDED


def test_exceeding_max_turns_without_finishing_raises() -> None:
    llm = _ScriptedLLMProvider(
        [
            AgentStep(action="call_tool", capability="dns_resolution", request={}),
            AgentStep(action="call_tool", capability="dns_resolution", request={}),
            AgentStep(action="call_tool", capability="dns_resolution", request={}),
        ]
    )
    registry = MagicMock()
    registry.execute.return_value = MagicMock(data={})
    agent_run = _bare_agent_run()

    agent_session = AgentSession(
        MagicMock(),
        definition=_definition(),  # max_turns=3
        llm_provider=llm,
        tool_registry=registry,
        assessment=MagicMock(),
        agent_run=agent_run,
    )

    with pytest.raises(AgentTurnLimitExceededError):
        agent_session.run()
    assert agent_run.status is models.AgentRunStatus.FAILED

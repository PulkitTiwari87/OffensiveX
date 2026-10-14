"""The agent session runtime — Phase 5.

One `AgentSession.run()` call is one `AgentRun`: it drives a bounded
LLM-decision loop (`AgentStep`: call a tool, or finish with a typed
output), enforcing two things the LLM itself must never be trusted to
enforce on its own (docs/architecture/security-boundary.md's "bounded
agency" rule):

1. **Toolset membership** — a capability outside `definition
   .allowed_capabilities` is refused before the Tool Registry (Phase 3)
   is even consulted. This is the one check docs/architecture/
   execution-model.md flagged as deferred from Phase 3 to "once there is
   an agent definition concept" — this module is that concept.
2. **Typed output contract** — `finish`'s `output` must validate against
   `definition.output_schema`; an agent cannot "finish" with whatever
   shape it wants.

Every tool call still goes through `ToolRegistry.execute()` exactly as a
human-triggered call would (Scope Guard, intrusiveness ceiling, validation
gate, `ToolExecution` audit row) — this module adds a check *before* that,
it does not replace it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from offensivex.agents.definition import AgentDefinition
from offensivex.core.errors import OffensiveXError
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.llm.base import LLMProvider
from offensivex.tools.registry import ParsedResult, ToolRegistry


class AgentFrameworkError(OffensiveXError):
    status_code = 422


class ToolsetMembershipError(AgentFrameworkError):
    title = "Capability outside agent's toolset"


class AgentOutputContractError(AgentFrameworkError):
    title = "Agent output failed its typed contract"


class AgentTurnLimitExceededError(AgentFrameworkError):
    title = "Agent exceeded its turn limit"


class AgentStep(BaseModel):
    """What the LLM must return each turn — the one structured schema
    every provider's `generate_structured()` call is asked to fill."""

    action: Literal["call_tool", "finish"]
    capability: str | None = None
    request: dict[str, Any] = {}
    output: dict[str, Any] | None = None


@dataclass(frozen=True)
class AgentRunResult:
    output: BaseModel
    turns_used: int


def _build_prompt(definition: AgentDefinition, history: list[dict[str, Any]]) -> str:
    """Deliberately simple: the system prompt plus a JSON transcript of
    tool calls made so far. A real provider integration (once an LLM key
    is available — see docs/roadmap/current-status.md) may need a richer
    prompt-construction strategy; nothing here commits to the final shape,
    only to there being *a* prompt a provider receives each turn."""
    return (
        f"{definition.system_prompt}\n\n"
        f"Allowed capabilities: {sorted(definition.allowed_capabilities)}\n\n"
        f"Transcript so far:\n{json.dumps(history, default=str)}"
    )


class AgentSession:
    def __init__(
        self,
        session: Session,
        *,
        definition: AgentDefinition,
        llm_provider: LLMProvider,
        tool_registry: ToolRegistry,
        assessment: models.Assessment,
        agent_run: models.AgentRun,
        on_tool_result: Callable[[str, dict[str, Any], ParsedResult], None] | None = None,
    ) -> None:
        self._session = session
        self._definition = definition
        self._llm = llm_provider
        self._registry = tool_registry
        self._assessment = assessment
        self._agent_run = agent_run
        # Lets a real agent (e.g. Recon, Phase 6) persist its own typed
        # rows (Observation/Asset) immediately after each tool call,
        # rather than batching everything until `finish` — per
        # docs/agents/recon-agent.md: "produces observations as it goes...
        # so a crash/cancellation mid-run still leaves partial, usable
        # results." The runtime itself stays agent-agnostic; it has no
        # idea what an Observation is.
        self._on_tool_result = on_tool_result

    def run(self) -> AgentRunResult:
        assert_valid_transition(self._agent_run.status, models.AgentRunStatus.RUNNING)
        self._agent_run.status = models.AgentRunStatus.RUNNING
        self._agent_run.attempts += 1
        self._agent_run.started_at = datetime.now(UTC)
        self._session.flush()

        history: list[dict[str, Any]] = []
        try:
            result = self._run_loop(history)
        except Exception:
            assert_valid_transition(self._agent_run.status, models.AgentRunStatus.FAILED)
            self._agent_run.status = models.AgentRunStatus.FAILED
            self._agent_run.finished_at = datetime.now(UTC)
            self._session.flush()
            raise

        assert_valid_transition(self._agent_run.status, models.AgentRunStatus.SUCCEEDED)
        self._agent_run.status = models.AgentRunStatus.SUCCEEDED
        self._agent_run.output_ref = {"output": result.output.model_dump(mode="json")}
        self._agent_run.finished_at = datetime.now(UTC)
        self._session.flush()
        return result

    def _run_loop(self, history: list[dict[str, Any]]) -> AgentRunResult:
        for turn in range(1, self._definition.max_turns + 1):
            prompt = _build_prompt(self._definition, history)
            step = self._generate_step(prompt)

            if step.action == "finish":
                output = self._validate_output(step.output or {})
                return AgentRunResult(output=output, turns_used=turn)

            if step.capability not in self._definition.allowed_capabilities:
                raise ToolsetMembershipError(
                    f"Agent {self._definition.agent_type.value!r} requested capability "
                    f"{step.capability!r}, which is outside its toolset "
                    f"{sorted(self._definition.allowed_capabilities)}."
                )

            result = self._registry.execute(
                self._session,
                capability=step.capability,
                request=step.request,
                assessment=self._assessment,
                agent_run_id=self._agent_run.id,
            )
            if self._on_tool_result is not None:
                self._on_tool_result(step.capability, step.request, result)
            history.append(
                {"capability": step.capability, "request": step.request, "result": result.data}
            )

        raise AgentTurnLimitExceededError(
            f"Agent {self._definition.agent_type.value!r} did not finish within "
            f"{self._definition.max_turns} turns."
        )

    def _generate_step(self, prompt: str) -> AgentStep:
        return asyncio.run(self._llm.generate_structured(prompt=prompt, schema=AgentStep))

    def _validate_output(self, raw_output: dict[str, Any]) -> BaseModel:
        try:
            return self._definition.output_schema.model_validate(raw_output)
        except ValidationError as exc:
            raise AgentOutputContractError(
                f"Agent output did not match {self._definition.output_schema.__name__}: {exc}"
            ) from exc

"""The real Validation Agent — Phase 10.

docs/agents/validation-agent.md point 1: "Verify the assessment's
validation flag is set; if not, this agent is never invoked (enforced by
the orchestrator, not by the agent's own judgment)." No orchestrator
scheduling loop exists yet (no worker process — see
docs/roadmap/current-status.md), so `run_validation_agent` itself is the
closest thing to "the orchestrator" today and enforces the same gate
explicitly, fast, before doing anything else. The Tool Registry's
validation gate (Phase 3) enforces the identical rule independently, at
the capability level — defense in depth, not a single point of failure
for this specific safety property.

This is the *only* path, besides an explicit analyst override
(`PATCH /findings/{id}/status`, docs/interfaces/api.md), that may ever
set `Finding.status` to `CONFIRMED` or `REJECTED` — see
docs/data/findings.md's corrected lifecycle and CLAUDE.md section 7.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.agents.definition import AgentDefinition
from offensivex.agents.runtime import AgentRunResult, AgentSession
from offensivex.core.errors import OffensiveXError
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.llm.base import LLMProvider
from offensivex.tools.registry import ParsedResult, ToolRegistry


class ValidationNotEnabledError(OffensiveXError):
    status_code = 422
    title = "Validation not enabled"


class ValidationAgentOutput(BaseModel):
    outcome: Literal["confirmed", "rejected", "unresolved"]
    notes: str


VALIDATION_AGENT_DEFINITION = AgentDefinition(
    agent_type=models.AgentType.VALIDATION,
    allowed_capabilities=frozenset({"security_header_validation_check"}),
    system_prompt=(
        "You are the Validation Agent for an authorized security "
        "assessment (docs/agents/validation-agent.md). You have been "
        "given one INVESTIGATING finding. Run the one registered "
        "non-destructive check for its class and interpret the result: "
        "confirmed (the condition positively holds), rejected (it "
        "positively does not), or unresolved (the check errored or was "
        "inconclusive — never guess). You may run only the one "
        "registered check; you do not improvise."
    ),
    output_schema=ValidationAgentOutput,
    max_turns=5,
)


def run_validation_agent(
    session: Session,
    *,
    llm_provider: LLMProvider,
    tool_registry: ToolRegistry,
    assessment: models.Assessment,
    agent_run: models.AgentRun,
    finding: models.Finding,
) -> AgentRunResult:
    if not assessment.validation_enabled:
        raise ValidationNotEnabledError(
            "The Validation Agent may not run: validation is not enabled for this assessment "
            "(docs/security/validation.md — opt-in per assessment)."
        )
    if finding.assessment_id != assessment.id:
        raise ValueError("finding does not belong to this assessment.")
    if finding.status is not models.FindingStatus.INVESTIGATING:
        raise ValueError(
            f"Validation requires an INVESTIGATING finding, got {finding.status.value!r} "
            "(docs/data/findings.md's state machine: CONFIRMED/REJECTED are reachable only "
            "from INVESTIGATING)."
        )

    def on_tool_result(capability: str, request: dict[str, Any], result: ParsedResult) -> None:
        missing = result.data.get("missing_headers", [])
        condition_holds = finding.affected_component in missing
        session.add(
            models.Evidence(
                finding_id=finding.id,
                kind=models.EvidenceKind.VALIDATION_RESULT,
                tool_execution_id=result.tool_execution_id,
                excerpt=(
                    f"Validation check on {request.get('url')!r}: "
                    f"{finding.affected_component!r} "
                    f"{'confirmed missing' if condition_holds else 'found present'}."
                ),
            )
        )
        session.flush()

    agent_session = AgentSession(
        session,
        definition=VALIDATION_AGENT_DEFINITION,
        llm_provider=llm_provider,
        tool_registry=tool_registry,
        assessment=assessment,
        agent_run=agent_run,
        on_tool_result=on_tool_result,
    )
    result = agent_session.run()

    output: ValidationAgentOutput = result.output  # type: ignore[assignment]
    if output.outcome == "confirmed":
        assert_valid_transition(finding.status, models.FindingStatus.CONFIRMED)
        finding.status = models.FindingStatus.CONFIRMED
        session.flush()
    elif output.outcome == "rejected":
        assert_valid_transition(finding.status, models.FindingStatus.REJECTED)
        finding.status = models.FindingStatus.REJECTED
        session.flush()
    # "unresolved": "the finding stays at its prior status rather than
    # being forced to a conclusion either way" (docs/security/validation.md)
    # — no transition at all.

    return result

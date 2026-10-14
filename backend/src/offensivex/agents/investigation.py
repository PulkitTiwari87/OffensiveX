"""The real Investigation Agent — Phase 9.

docs/agents/investigation-agent.md: "Findings moved DISCOVERED -> SUSPECTED
-> INVESTIGATING" — both transitions belong to this agent (the mechanical
"correlated, awaiting investigation" step is trivial for the MVP's
one-observation-per-finding vulnerability class and happens immediately,
not as a separate phase). Investigation re-runs the same read-only
capability the Vulnerability Agent used, attaches the result as
`Evidence` (not another `Observation` — this is a re-check of an existing
finding, not a new discovery), and never promotes a finding past
`INVESTIGATING`: only the Validation Agent's outcome or an explicit
analyst override may set `CONFIRMED`/`REJECTED` (docs/data/findings.md,
the corrected lifecycle; CLAUDE.md section 7).

One `AgentRun` handles exactly one `Finding`, per
docs/agents/orchestrator.md point 4 ("one AgentRun is normally one
finding for Investigation/Validation").

The model drives the re-check and writes the notes, but the *conclusion* is
cross-checked against what the tool actually observed: it must have run the
check on this finding's own endpoint, and its `still_present` must agree
with the observation, or the run fails (visibly) instead of recording a
model-invented conclusion.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.agents.definition import AgentDefinition
from offensivex.agents.runtime import AgentOutputContractError, AgentRunResult, AgentSession
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.llm.base import LLMProvider
from offensivex.tools.registry import ParsedResult, ToolRegistry


class InvestigationAgentOutput(BaseModel):
    still_present: bool
    notes: str


INVESTIGATION_AGENT_DEFINITION = AgentDefinition(
    agent_type=models.AgentType.INVESTIGATION,
    allowed_capabilities=frozenset({"security_header_scan"}),
    system_prompt=(
        "You are the Investigation Agent for an authorized security "
        "assessment (docs/agents/investigation-agent.md). You have been "
        "given one candidate finding. Re-check it with a read-only "
        "capability and decide whether the condition is still present. "
        "You may never mark a finding CONFIRMED or REJECTED — that is "
        "the Validation Agent's job, not yours. Cite the evidence your "
        "conclusion is based on. Finish with still_present and notes."
    ),
    output_schema=InvestigationAgentOutput,
    max_turns=5,
    capability_requests={
        "security_header_scan": '{"url": "<the finding\'s endpoint URL, exactly as given>"}',
    },
)


def run_investigation_agent(
    session: Session,
    *,
    llm_provider: LLMProvider,
    tool_registry: ToolRegistry,
    assessment: models.Assessment,
    agent_run: models.AgentRun,
    finding: models.Finding,
) -> AgentRunResult:
    if finding.assessment_id != assessment.id:
        raise ValueError("finding does not belong to this assessment.")

    # The mechanical correlation step (DISCOVERED -> SUSPECTED) and the
    # Investigation Agent "picking it up" (SUSPECTED -> INVESTIGATING)
    # both happen here, per docs/agents/investigation-agent.md.
    if finding.status is models.FindingStatus.DISCOVERED:
        assert_valid_transition(finding.status, models.FindingStatus.SUSPECTED)
        finding.status = models.FindingStatus.SUSPECTED
    assert_valid_transition(finding.status, models.FindingStatus.INVESTIGATING)
    finding.status = models.FindingStatus.INVESTIGATING
    session.flush()

    asset = session.get(models.Asset, finding.asset_id)
    endpoint_url = asset.canonical_key if asset else None
    prior_evidence = list(
        session.scalars(
            select(models.Evidence.excerpt)
            .where(models.Evidence.finding_id == finding.id)
            .limit(10)
        )
    )
    observed: list[bool] = []  # what the tool actually saw, per check run

    def request_guard(capability: str, request: dict[str, Any]) -> str | None:
        if request.get("url") != endpoint_url:
            return f"re-check only this finding's own endpoint, {endpoint_url!r}"
        return None

    def validate_output(output: BaseModel) -> None:
        if not observed:
            raise AgentOutputContractError(
                "Investigation finished without running the re-check, so there is no "
                "evidence to base a conclusion on."
            )
        claimed: bool = output.still_present  # type: ignore[attr-defined]
        if claimed != observed[-1]:
            raise AgentOutputContractError(
                f"Investigation reported still_present={claimed} but the re-check observed "
                f"{observed[-1]}; refusing to record a conclusion the evidence contradicts."
            )

    def on_tool_result(capability: str, request: dict[str, Any], result: ParsedResult) -> None:
        missing = result.data.get("missing_headers", [])
        still_present = finding.affected_component in missing
        observed.append(still_present)
        session.add(
            models.Evidence(
                finding_id=finding.id,
                kind=models.EvidenceKind.REQUEST_RESPONSE,
                tool_execution_id=result.tool_execution_id,
                excerpt=(
                    f"Re-checked {request.get('url')!r}: "
                    f"{finding.affected_component!r} "
                    f"{'still missing' if still_present else 'now present'}."
                ),
            )
        )
        session.flush()

    agent_session = AgentSession(
        session,
        definition=INVESTIGATION_AGENT_DEFINITION,
        llm_provider=llm_provider,
        tool_registry=tool_registry,
        assessment=assessment,
        agent_run=agent_run,
        on_tool_result=on_tool_result,
        task_context={
            "finding_id": str(finding.id),
            "title": finding.title,
            "check": finding.affected_component,
            "source": finding.source,
            "status": finding.status.value,
        },
        untrusted_context={"endpoint_url": endpoint_url, "prior_evidence": prior_evidence},
        validate_output=validate_output,
        request_guard=request_guard,
    )
    result = agent_session.run()

    # "A finding the agent cannot meaningfully narrow down stays
    # SUSPECTED rather than being forced to a conclusion" — here, "no
    # longer reproducible" is exactly that case: inconclusive, not a
    # rejection (only Validation/an analyst may reject).
    output: InvestigationAgentOutput = result.output  # type: ignore[assignment]
    if not output.still_present:
        assert_valid_transition(finding.status, models.FindingStatus.SUSPECTED)
        finding.status = models.FindingStatus.SUSPECTED
        session.flush()

    return result

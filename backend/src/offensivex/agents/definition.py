"""Agent definitions — the bounded toolset + typed output contract every
agent session is constructed from.

`RECON_PROOF_DEFINITION` is Phase 5's proof instance (implementation-
blueprint.md section 11's P5 row: "applies framework to simplest agent
(Recon)") — a minimal stand-in, not the full Recon Agent. The real Recon
Agent (full toolset, full prompt, full decision logic from
docs/agents/recon-agent.md) is Phase 6.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel

from offensivex.db import models


@dataclass(frozen=True)
class AgentDefinition:
    agent_type: models.AgentType
    # The concrete instance of docs/architecture/security-boundary.md's
    # "toolset membership" table for this agent — a capability outside
    # this set is refused before the Tool Registry is even consulted.
    allowed_capabilities: frozenset[str]
    system_prompt: str
    output_schema: type[BaseModel]
    max_turns: int = 10
    # capability -> the `request` shape the model must send, shown in its
    # prompt (a real LLM cannot guess `{"hostname": ...}` vs `{"url": ...}`).
    capability_requests: dict[str, str] = field(default_factory=dict)


class ReconProofOutput(BaseModel):
    """Phase 5's proof output contract — deliberately minimal. The real
    Recon Agent (Phase 6) writes Observation/Asset rows directly rather
    than returning them in one final structured blob; this exists only to
    prove the runtime enforces *some* typed output contract end to end.
    """

    discovered_addresses: list[str]
    summary: str


RECON_PROOF_DEFINITION = AgentDefinition(
    agent_type=models.AgentType.RECON,
    allowed_capabilities=frozenset({"dns_resolution"}),
    system_prompt=(
        "You are a reconnaissance agent. You may only resolve DNS names "
        "for hosts already confirmed in scope. When you have resolved "
        "every requested host, finish with a summary."
    ),
    output_schema=ReconProofOutput,
)

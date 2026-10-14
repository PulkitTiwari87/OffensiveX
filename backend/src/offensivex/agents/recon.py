"""The real Recon Agent — Phase 6, refactored in Phase 7 to register its
capability handlers on the generalized `ObservationNormalizer`
(offensivex.observations.normalizer) instead of hardcoding its own
dispatch.

docs/agents/recon-agent.md's toolset, trimmed to the MVP recon surface
(docs/roadmap/implementation-blueprint.md section 9: "DNS + HTTP probing
... not full Nmap port sweep"): `dns_resolution` and `http_probe`
(Phase 3's proof adapter and Phase 6's new one), nothing else. Full-width
recon (port/service discovery, subdomain enumeration) is additive, not
blocking, per that same MVP definition.

`run_recon_agent()` works with any `offensivex.llm.base.LLMProvider`: a
scripted double in tests, a real model in production. The model decides
*which* in-scope hostnames/URLs to resolve and probe and in what order, from
the authorized scope given in its prompt; it cannot widen that scope — the
Scope Guard refuses anything outside it regardless of what the model asks
for — and it never writes rows: the deterministic normalizers below turn tool
results into Asset/Observation rows.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from offensivex.agents.definition import AgentDefinition
from offensivex.agents.runtime import AgentRunResult, AgentSession
from offensivex.db import models
from offensivex.llm.base import LLMProvider
from offensivex.observations.normalizer import (
    ObservationNormalizer,
    get_or_create_asset,
    write_observation,
)
from offensivex.tools.registry import ParsedResult, ToolRegistry


class ReconAgentOutput(BaseModel):
    assets_discovered: int
    summary: str


RECON_AGENT_DEFINITION = AgentDefinition(
    agent_type=models.AgentType.RECON,
    allowed_capabilities=frozenset({"dns_resolution", "http_probe"}),
    system_prompt=(
        "You are the Recon Agent for an authorized security assessment "
        "(docs/agents/recon-agent.md). Map the in-scope attack surface "
        "using only the capabilities you have been given: dns_resolution "
        "and http_probe. If the assessment context gives an entry_point URL, "
        "start there and use its exact scheme, host and port. Sequence your "
        "work based on what you learn — "
        "e.g. resolve a host before probing HTTP on it. You are strictly "
        "read-only and must never request a capability outside your "
        "toolset. When you have mapped what is achievable, finish with a "
        "summary."
    ),
    output_schema=ReconAgentOutput,
    max_turns=20,
    capability_requests={
        "dns_resolution": '{"hostname": "<an in-scope hostname>"}',
        "http_probe": '{"url": "<http(s) URL on an in-scope host; start from entry_point>"}',
    },
)


def _normalize_dns_resolution(
    session: Session, assessment: models.Assessment, request: dict[str, Any], result: ParsedResult
) -> None:
    hostname = request["hostname"]
    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.HOST,
        canonical_key=hostname,
        attributes={"resolved_addresses": result.data["addresses"]},
    )
    write_observation(
        session,
        observation_type=models.ObservationType.HOST_DISCOVERED,
        source="dns_resolution",
        asset=asset,
        tool_execution_id=result.tool_execution_id,
        confidence=1.0,
        data={"addresses": result.data["addresses"]},
    )


def _normalize_http_probe(
    session: Session, assessment: models.Assessment, request: dict[str, Any], result: ParsedResult
) -> None:
    url = request["url"]
    asset = get_or_create_asset(
        session,
        assessment_id=assessment.id,
        asset_type=models.AssetType.ENDPOINT,
        canonical_key=url,
        attributes={
            "status_code": result.data.get("status_code"),
            "pinned_ip": result.data.get("pinned_ip"),
        },
    )
    write_observation(
        session,
        observation_type=models.ObservationType.ENDPOINT_DISCOVERED,
        source="http_probe",
        asset=asset,
        tool_execution_id=result.tool_execution_id,
        confidence=1.0,
        data={
            "url": url,
            "status_code": result.data.get("status_code"),
            "headers": result.data.get("headers"),
        },
    )


def build_recon_normalizer() -> ObservationNormalizer:
    normalizer = ObservationNormalizer()
    normalizer.register("dns_resolution", _normalize_dns_resolution)
    normalizer.register("http_probe", _normalize_http_probe)
    return normalizer


def run_recon_agent(
    session: Session,
    *,
    llm_provider: LLMProvider,
    tool_registry: ToolRegistry,
    assessment: models.Assessment,
    agent_run: models.AgentRun,
) -> AgentRunResult:
    normalizer = build_recon_normalizer()

    def on_tool_result(capability: str, request: dict[str, Any], result: ParsedResult) -> None:
        normalizer.normalize(session, assessment, capability, request, result)

    rules = assessment.authorization.scope_rules
    agent_session = AgentSession(
        session,
        definition=RECON_AGENT_DEFINITION,
        llm_provider=llm_provider,
        tool_registry=tool_registry,
        assessment=assessment,
        agent_run=agent_run,
        on_tool_result=on_tool_result,
        task_context={
            "target": assessment.target.name,
            # The operator-configured, validated starting URL (None for targets
            # that predate the field). Exact scheme/host/port to begin with —
            # never infer a port from the target name. It grants nothing: the
            # Scope Guard still checks every call against the scope below.
            "entry_point": assessment.target.entry_point,
            "in_scope": [
                {"type": r.rule_type, "pattern": r.pattern} for r in rules if not r.is_exclusion
            ],
            "excluded": [
                {"type": r.rule_type, "pattern": r.pattern} for r in rules if r.is_exclusion
            ],
            "scan_mode": assessment.scan_mode.value,
        },
    )
    return agent_session.run()

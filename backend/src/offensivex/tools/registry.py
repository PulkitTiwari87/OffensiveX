"""The Tool Registry — Phase 3.

docs/architecture/tool-architecture.md's contract and
docs/architecture/execution-model.md's sequence, exactly:

    Agent -> Tool Registry -> ExecutionPlan -> Scope Guard -> Sandbox -> ...

**No Sandbox exists yet (Phase 4).** `ToolRegistry.execute()` therefore
calls an adapter's `run()` directly, in-process — there is no
containerization, no timeout enforcement, no process-tree kill yet. This
is the honest, documented state of this phase, not a shortcut hidden
from docs/roadmap/current-status.md. Every guarantee execution-model.md
promises *about running the tool itself* (bounded resource use, clean
cancellation) is explicitly Phase 4's job; what Phase 3 proves is the
registry/adapter contract and the Scope Guard integration ahead of it.

**Toolset membership is deliberately not checked here** (execution-model.md
section "What's new": "An agent may only request capabilities listed in
its own agent definition") — there is no agent definition concept to check
against yet; that lands with the agent framework (Phase 5).

**The audit trail is the `ToolExecution` row itself** — plan, scope
decision, and result are recorded as fields on one row (this matches
docs/roadmap/implementation-blueprint.md section 11's P3 row: "ToolExecution
writes", not a separate hash-chained log table). A separate `AuditLogEntry`
entity appears in the traceability matrix (section 1) as its own
capability with no assigned phase number in roadmap.md — out of scope here,
same treatment as Authentication (see docs/roadmap/current-status.md).
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from sqlalchemy.orm import Session

from offensivex.core.errors import OffensiveXError
from offensivex.db import models
from offensivex.tools.network_guard import NetworkContext, NetworkPolicyError
from offensivex.tools.scope_guard import ScopeRuleLike, check_destinations


class Intrusiveness(enum.StrEnum):
    """docs/tools/tool-registry.md's per-entry metadata — exactly the
    three values named there (no "high"; a capability that would need
    one isn't planned)."""

    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"


class IntegrationStatus(enum.StrEnum):
    """Guardrail.md section 7's tool/provider integration vocabulary."""

    PLANNED = "planned"
    MOCKED = "mocked"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    DEPRECATED = "deprecated"


# docs/architecture/execution-model.md's "Intrusiveness ceiling" check
# needs a scan-mode -> max-intrusiveness mapping that no document states
# numerically. Smallest reasonable reading of
# docs/agents/orchestrator.md ("quick ... non-intrusive capabilities") and
# docs/security/validation.md's widening quick -> standard -> deep:
# quick allows passive only, standard adds low, deep adds medium. Subject
# to confirmation alongside real scanner intrusiveness ratings (Phase 8+).
_INTRUSIVENESS_CEILING: dict[models.ScanMode, frozenset[Intrusiveness]] = {
    models.ScanMode.QUICK: frozenset({Intrusiveness.PASSIVE}),
    models.ScanMode.STANDARD: frozenset({Intrusiveness.PASSIVE, Intrusiveness.LOW}),
    models.ScanMode.DEEP: frozenset(
        {Intrusiveness.PASSIVE, Intrusiveness.LOW, Intrusiveness.MEDIUM}
    ),
}


class ToolRegistryError(OffensiveXError):
    status_code = 422


class CapabilityNotFoundError(ToolRegistryError):
    title = "Capability not registered"


class IntrusivenessExceededError(ToolRegistryError):
    title = "Capability too intrusive for scan mode"


class ValidationModeRequiredError(ToolRegistryError):
    title = "Capability requires validation mode"


class ScopeViolationError(ToolRegistryError):
    title = "Scope violation"


class ToolRunError(ToolRegistryError):
    """The tool was allowed and started but failed (host unreachable, port
    closed, timeout). Unlike the refusals above this is an *observation*: an
    agent is told about it and may continue; the `ToolExecution` row is marked
    KILLED and keeps the audit trail."""

    status_code = 502
    title = "Tool execution failed"


@dataclass(frozen=True)
class AdapterMeta:
    name: str
    capability: str
    intrusiveness: Intrusiveness
    requires_validation_mode: bool
    status: IntegrationStatus


@dataclass(frozen=True)
class ExecutionPlan:
    """Declares every destination an adapter will touch, built *before*
    anything runs, so the Scope Guard can check all of them up front.

    `ports`, when given, is parallel to `destinations` and is the TCP port the
    adapter will connect to for that host; an adapter that opens a connection
    MUST declare it, because the Scope Guard then checks host *and* port. `None`
    (the default) means the capability never connects to the destination (DNS
    resolution), so only the host is checked.

    `network` is filled in by `ToolRegistry.execute()` after the Scope Guard
    passes; adapters never build it. An adapter that connects refuses to run
    without it."""

    capability: str
    destinations: list[str]
    request: dict[str, Any] = field(default_factory=dict)
    ports: list[int | None] | None = None
    network: NetworkContext | None = None

    def __post_init__(self) -> None:
        if self.ports is not None and len(self.ports) != len(self.destinations):
            raise ValueError("ExecutionPlan.ports must be parallel to destinations.")


@dataclass(frozen=True)
class ParsedResult:
    """A typed result from `adapter.parse()`. Deliberately minimal here —
    adapters subclass or wrap this with capability-specific fields; the
    one proof adapter (DNS resolution) does so in
    offensivex.tools.adapters.dns_resolution.

    `tool_execution_id` is filled in by `ToolRegistry.execute()` after
    the fact (an adapter's own `parse()` has no ToolExecution row to
    reference yet) — it's what lets a caller write an `Evidence` or
    `Observation` row whose `tool_execution_id` FK actually points at the
    call that produced it, e.g. the Recon Agent (Phase 6)."""

    capability: str
    data: dict[str, Any]
    tool_execution_id: Any | None = None


@runtime_checkable
class ToolAdapter(Protocol):
    meta: AdapterMeta

    def plan(self, request: dict[str, Any]) -> ExecutionPlan: ...

    def run(self, plan: ExecutionPlan) -> bytes:
        """Produce the raw artifact. Phase 3: runs in-process, no
        sandbox. Phase 4 moves this inside a container."""
        ...

    def parse(self, raw_artifact: bytes) -> ParsedResult: ...


class ToolRegistry:
    def __init__(self, *, allow_private_targets: bool = False) -> None:
        """`allow_private_targets` mirrors `OFFENSIVEX_ALLOW_PRIVATE_TARGETS`
        (Guardrail.md section 2.7). Default-deny: a registry built without it
        refuses to connect to loopback/private/link-local destinations."""
        self._adapters: dict[str, ToolAdapter] = {}
        self._allow_private_targets = allow_private_targets

    def register(self, adapter: ToolAdapter) -> None:
        self._adapters[adapter.meta.capability] = adapter

    def get(self, capability: str) -> ToolAdapter:
        adapter = self._adapters.get(capability)
        if adapter is None:
            raise CapabilityNotFoundError(f"No adapter registered for capability {capability!r}.")
        return adapter

    def execute(
        self,
        session: Session,
        *,
        capability: str,
        request: dict[str, Any],
        assessment: models.Assessment,
        agent_run_id: object | None = None,
    ) -> ParsedResult:
        """The full path: intrusiveness ceiling -> validation gate ->
        Scope Guard -> run -> parse, with a `ToolExecution` row recording
        every step, exactly as docs/architecture/execution-model.md's
        sequence diagram describes (minus the Sandbox box — Phase 4).
        """
        adapter = self.get(capability)
        meta = adapter.meta

        allowed_intrusiveness = _INTRUSIVENESS_CEILING[assessment.scan_mode]
        if meta.intrusiveness not in allowed_intrusiveness:
            raise IntrusivenessExceededError(
                f"Capability {capability!r} has intrusiveness {meta.intrusiveness.value!r}, "
                f"which exceeds what scan mode {assessment.scan_mode.value!r} allows."
            )
        if meta.requires_validation_mode and not assessment.validation_enabled:
            raise ValidationModeRequiredError(
                f"Capability {capability!r} requires validation mode, which is not "
                "enabled for this assessment."
            )

        plan = adapter.plan(request)
        scope_rules: list[ScopeRuleLike] = list(assessment.authorization.scope_rules)
        checks = check_destinations(plan.destinations, scope_rules, plan.ports)
        denied = [c for c in checks if not c.allowed]

        tool_execution = models.ToolExecution(
            agent_run_id=agent_run_id,
            tool_name=meta.name,
            capability=capability,
            scope_decision=(
                models.ScopeDecision.DENIED if denied else models.ScopeDecision.ALLOWED
            ),
            status=(
                models.ToolExecutionStatus.DENIED if denied else models.ToolExecutionStatus.PLANNED
            ),
            argv={
                "destinations": plan.destinations,
                "ports": plan.ports,
                "request": plan.request,
            },
        )
        session.add(tool_execution)
        session.flush()

        if denied:
            raise ScopeViolationError(denied[0].reason)

        tool_execution.status = models.ToolExecutionStatus.RUNNING
        tool_execution.started_at = datetime.now(UTC)
        session.flush()

        plan = replace(
            plan,
            network=NetworkContext(
                rules=tuple(scope_rules), allow_private_targets=self._allow_private_targets
            ),
        )
        try:
            raw_artifact = adapter.run(plan)
        except NetworkPolicyError as exc:
            # Connection-time enforcement (resolved address / pinned peer): a
            # scope refusal, recorded as DENIED rather than as a tool failure.
            tool_execution.scope_decision = models.ScopeDecision.DENIED
            tool_execution.status = models.ToolExecutionStatus.DENIED
            tool_execution.finished_at = datetime.now(UTC)
            session.flush()
            raise ScopeViolationError(str(exc)) from exc
        except Exception as exc:
            tool_execution.status = models.ToolExecutionStatus.KILLED
            tool_execution.finished_at = datetime.now(UTC)
            session.flush()
            raise ToolRunError(f"{capability} failed: {type(exc).__name__}: {exc}") from exc

        tool_execution.artifact_hash = hashlib.sha256(raw_artifact).hexdigest()
        tool_execution.status = models.ToolExecutionStatus.COMPLETED
        tool_execution.exit_status = 0
        tool_execution.finished_at = datetime.now(UTC)
        session.flush()

        parsed = adapter.parse(raw_artifact)
        return replace(parsed, tool_execution_id=tool_execution.id)

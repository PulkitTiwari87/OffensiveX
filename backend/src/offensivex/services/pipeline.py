"""Assessment pipeline — minimal stage sequencing (docs/agents/orchestrator.md).

Runs the agents for one RUNNING assessment, in order:

    Recon -> Vulnerability -> Investigation (one run per DISCOVERED finding)
          -> Validation (one run per INVESTIGATING finding, only if the
             assessment opted in to validation)

then settles the assessment's status. This is deliberately the smallest thing
that lets the agents run end to end against a real LLM: sequential, in-process,
no queue, no retries, no prioritisation (those remain orchestrator work).

Failure semantics — nothing is hidden:

* Each stage commits when it finishes, so a failure later never discards
  earlier findings, and a failed agent's own `FAILED` AgentRun row (plus any
  denied/killed `ToolExecution` rows) is persisted as the audit trail.
* A failed Recon or Vulnerability stage ends the pipeline (`FAILED`).
* A failed per-finding Investigation/Validation is recorded and the pipeline
  moves on to the next finding (`COMPLETED_WITH_ERRORS`).
* Every stage's outcome is returned; errors are reported as the error class
  plus our own message, never swallowed.

Which tools exist, and what each agent may call, is decided by the registry
and the agent definitions — the LLM only chooses among them.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.agents.investigation import run_investigation_agent
from offensivex.agents.recon import run_recon_agent
from offensivex.agents.validation import run_validation_agent
from offensivex.agents.vulnerability import run_vulnerability_agent
from offensivex.core.errors import OffensiveXError
from offensivex.core.logging import get_logger
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.llm.base import LLMProvider
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.adapters.security_header_scan import SecurityHeaderScanAdapter
from offensivex.tools.adapters.security_header_validation import SecurityHeaderValidationCheck
from offensivex.tools.registry import ToolRegistry

log = get_logger(__name__)


class PipelineNotRunnableError(OffensiveXError):
    status_code = 422
    title = "Assessment cannot be run"


@dataclass(frozen=True)
class StageResult:
    agent: str
    agent_run_id: str
    succeeded: bool
    subject: str | None = None  # the finding id, for per-finding stages
    error: str | None = None


@dataclass
class PipelineResult:
    final_status: models.AssessmentStatus
    stages: list[StageResult] = field(default_factory=list)

    @property
    def failures(self) -> list[StageResult]:
        return [s for s in self.stages if not s.succeeded]


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(DnsResolutionAdapter())
    registry.register(HttpProbeAdapter())
    registry.register(SecurityHeaderScanAdapter())
    registry.register(SecurityHeaderValidationCheck())
    return registry


def _describe(exc: Exception) -> str:
    # Our own errors carry a message written for humans; for anything else
    # the class name is the safe, non-leaky summary (details are in the logs).
    return (
        f"{type(exc).__name__}: {exc.detail}"
        if isinstance(exc, OffensiveXError)
        else (type(exc).__name__)
    )


def run_assessment(
    session: Session,
    *,
    assessment: models.Assessment,
    llm_provider: LLMProvider,
    tool_registry: ToolRegistry | None = None,
) -> PipelineResult:
    if assessment.status is not models.AssessmentStatus.RUNNING:
        raise PipelineNotRunnableError(
            f"Assessment is {assessment.status.value!r}; only a running assessment can be run."
        )
    registry = tool_registry or build_default_registry()
    result = PipelineResult(final_status=models.AssessmentStatus.RUNNING)

    def new_run(agent_type: models.AgentType) -> models.AgentRun:
        run = models.AgentRun(
            assessment_id=assessment.id,
            agent_type=agent_type,
            status=models.AgentRunStatus.QUEUED,
        )
        session.add(run)
        session.flush()
        return run

    def stage(
        agent: models.AgentType,
        run: models.AgentRun,
        action: Callable[[], object],
        subject: str | None = None,
    ) -> bool:
        try:
            action()
            outcome = StageResult(agent.value, str(run.id), True, subject)
        except Exception as exc:
            # The traceback goes to the server log only; the returned/printed
            # error stays a short, non-leaky summary (see _describe).
            log.warning(
                "pipeline.stage_failed", agent=agent.value, error=type(exc).__name__, exc_info=True
            )
            outcome = StageResult(agent.value, str(run.id), False, subject, _describe(exc))
        result.stages.append(outcome)
        session.commit()  # persist this stage's rows, including a FAILED run
        return outcome.succeeded

    queued_recon = next(
        (
            r
            for r in assessment.agent_runs
            if r.agent_type is models.AgentType.RECON and r.status is models.AgentRunStatus.QUEUED
        ),
        None,
    )
    recon_run = queued_recon or new_run(models.AgentType.RECON)
    ok = stage(
        models.AgentType.RECON,
        recon_run,
        lambda: run_recon_agent(
            session,
            llm_provider=llm_provider,
            tool_registry=registry,
            assessment=assessment,
            agent_run=recon_run,
        ),
    )
    if ok:
        vuln_run = new_run(models.AgentType.VULNERABILITY)
        ok = stage(
            models.AgentType.VULNERABILITY,
            vuln_run,
            lambda: run_vulnerability_agent(
                session,
                llm_provider=llm_provider,
                tool_registry=registry,
                assessment=assessment,
                agent_run=vuln_run,
            ),
        )

    if ok:
        discovered = list(
            session.scalars(
                select(models.Finding)
                .where(
                    models.Finding.assessment_id == assessment.id,
                    models.Finding.status == models.FindingStatus.DISCOVERED,
                )
                .order_by(models.Finding.first_seen)
            )
        )
        investigation_failed: set[object] = set()
        for finding in discovered:
            inv_run = new_run(models.AgentType.INVESTIGATION)
            if not stage(
                models.AgentType.INVESTIGATION,
                inv_run,
                partial(
                    run_investigation_agent,
                    session,
                    llm_provider=llm_provider,
                    tool_registry=registry,
                    assessment=assessment,
                    agent_run=inv_run,
                    finding=finding,
                ),
                subject=str(finding.id),
            ):
                investigation_failed.add(finding.id)

        if assessment.validation_enabled:
            investigating = list(
                session.scalars(
                    select(models.Finding)
                    .where(
                        models.Finding.assessment_id == assessment.id,
                        models.Finding.status == models.FindingStatus.INVESTIGATING,
                    )
                    .order_by(models.Finding.first_seen)
                )
            )
            for finding in investigating:
                if finding.id in investigation_failed:
                    continue  # no evidence from a failed investigation to validate against
                val_run = new_run(models.AgentType.VALIDATION)
                stage(
                    models.AgentType.VALIDATION,
                    val_run,
                    partial(
                        run_validation_agent,
                        session,
                        llm_provider=llm_provider,
                        tool_registry=registry,
                        assessment=assessment,
                        agent_run=val_run,
                        finding=finding,
                    ),
                    subject=str(finding.id),
                )

    if not ok:
        final = models.AssessmentStatus.FAILED
    elif result.failures:
        final = models.AssessmentStatus.COMPLETED_WITH_ERRORS
    else:
        final = models.AssessmentStatus.COMPLETED
    assert_valid_transition(assessment.status, final)
    assessment.status = final
    assessment.finished_at = datetime.now(UTC)
    session.commit()
    result.final_status = final
    return result

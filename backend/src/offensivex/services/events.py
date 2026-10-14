"""The event log — Phase 7.

docs/roadmap/implementation-blueprint.md section 6 ("Event Model") names
`assessment.*`/`agent.*`/`tool.*`/`asset.*`/`observation.*` events and
says, in its MVP implementation note: "every event above is first
implemented as a **persisted row** ... consistent with ... 'no WebSockets
in MVP'." No separate `Event` table is introduced — the persisted rows
are the `Assessment`/`AgentRun`/`ToolExecution`/`Asset`/`Observation` rows
that already exist (Phase 1). This module assembles them, for one
assessment, into the chronological feed the event table describes.

API surface is "event query (internal)" per implementation-blueprint.md
section 11's P7 row — no public REST route is added here; the real
Agent Activity dashboard view (Phase 15) is what eventually calls this.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from offensivex.db import models
from offensivex.services.assessments import get_assessment


@dataclass(frozen=True)
class AssessmentEvent:
    type: str
    occurred_at: datetime
    payload: dict[str, Any]


def list_assessment_events(session: Session, *, assessment_id: UUID) -> list[AssessmentEvent]:
    assessment = get_assessment(session, assessment_id)
    events: list[AssessmentEvent] = [
        AssessmentEvent(
            "assessment.created",
            assessment.created_at,
            {"assessment_id": str(assessment.id), "target_id": str(assessment.target_id)},
        )
    ]
    if assessment.started_at is not None:
        events.append(
            AssessmentEvent(
                "assessment.started", assessment.started_at, {"assessment_id": str(assessment.id)}
            )
        )
    if assessment.finished_at is not None:
        events.append(
            AssessmentEvent(
                "assessment.completed",
                assessment.finished_at,
                {"assessment_id": str(assessment.id), "final_status": assessment.status.value},
            )
        )

    agent_runs = session.query(models.AgentRun).filter_by(assessment_id=assessment_id).all()
    for run in agent_runs:
        events.append(
            AssessmentEvent(
                "agent.scheduled",
                run.created_at,
                {"agent_run_id": str(run.id), "agent_type": run.agent_type.value},
            )
        )
        if run.started_at is not None:
            events.append(
                AssessmentEvent("agent.started", run.started_at, {"agent_run_id": str(run.id)})
            )
        if run.finished_at is not None:
            event_type = (
                "agent.completed"
                if run.status is models.AgentRunStatus.SUCCEEDED
                else "agent.failed"
            )
            events.append(
                AssessmentEvent(
                    event_type,
                    run.finished_at,
                    {"agent_run_id": str(run.id), "status": run.status.value},
                )
            )

    tool_executions = (
        session.query(models.ToolExecution)
        .join(models.AgentRun, models.ToolExecution.agent_run_id == models.AgentRun.id)
        .filter(models.AgentRun.assessment_id == assessment_id)
        .all()
    )
    for execution in tool_executions:
        events.append(
            AssessmentEvent(
                "tool.started",
                execution.created_at,
                {
                    "tool_execution_id": str(execution.id),
                    "capability": execution.capability,
                    "scope_decision": execution.scope_decision.value,
                },
            )
        )
        if execution.finished_at is not None:
            events.append(
                AssessmentEvent(
                    "tool.completed",
                    execution.finished_at,
                    {
                        "tool_execution_id": str(execution.id),
                        "exit_status": execution.exit_status,
                        "artifact_hash": execution.artifact_hash,
                    },
                )
            )

    assets = session.query(models.Asset).filter_by(assessment_id=assessment_id).all()
    for asset in assets:
        events.append(
            AssessmentEvent(
                "asset.discovered",
                asset.created_at,
                {
                    "asset_id": str(asset.id),
                    "asset_type": asset.asset_type.value,
                    "canonical_key": asset.canonical_key,
                },
            )
        )

    observations = (
        session.query(models.Observation)
        .join(models.Asset)
        .filter(models.Asset.assessment_id == assessment_id)
        .all()
    )
    for observation in observations:
        events.append(
            AssessmentEvent(
                "observation.created",
                observation.created_at,
                {
                    "observation_id": str(observation.id),
                    "type": observation.type.value,
                    "asset_id": str(observation.asset_id),
                },
            )
        )

    events.sort(key=lambda event: event.occurred_at)
    return events

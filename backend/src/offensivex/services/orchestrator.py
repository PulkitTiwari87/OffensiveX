"""Orchestrator skeleton — Phase 2.

docs/agents/orchestrator.md step 1: "Assessment creation validates target
scope/authorization and scan mode, then enqueues the Recon Agent. Nothing
else runs yet." This module is exactly that one decision — nothing more.

The "no-op test agent" the roadmap asks for is this: an `AgentRun` row
scheduled with `agent_type=RECON`, `status=QUEUED`. It proves the
orchestrator's scheduling decision end-to-end (a real row, in the real
schema, with the real agent type the real Recon Agent will use) without
executing anything — there is no agent runtime to pick it up yet (that is
Phase 5), and no Recon Agent to actually run (Phase 6). It will simply sit
QUEUED, which is the honest, correct state for "nothing else runs yet."

Everything else in docs/agents/orchestrator.md's decision logic (stage
sequencing by scan mode, prioritization, retries, attack-graph/reporting
triggers) requires agents that do not exist yet and is out of scope here —
see roadmap.md P5 onward.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from offensivex.db import models


def schedule_initial_recon(session: Session, assessment: models.Assessment) -> models.AgentRun:
    agent_run = models.AgentRun(
        assessment_id=assessment.id,
        agent_type=models.AgentType.RECON,
        status=models.AgentRunStatus.QUEUED,
    )
    session.add(agent_run)
    session.flush()
    return agent_run

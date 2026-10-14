"""Assessment lifecycle service — Phase 2.

This is the "scope/authorization gate (carried over from the original
design)" the roadmap names: an Assessment cannot be created unless its
target has a currently-approved, unexpired Authorization. Everything after
that gate (transitioning PENDING -> RUNNING and scheduling the orchestrator's
first decision) is the Phase 2 orchestrator skeleton.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from offensivex.core.errors import NotFoundError, OffensiveXError
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.services import orchestrator, targets


class ScopeNotAuthorizedError(OffensiveXError):
    status_code = 422
    title = "Target not authorized"


def create_assessment(
    session: Session,
    *,
    target_id: object,
    scan_mode: models.ScanMode = models.ScanMode.STANDARD,
    validation_enabled: bool = False,
) -> models.Assessment:
    """docs/roadmap/implementation-blueprint.md section 5's USER ->
    ASSESSMENT flow, exactly: "Target has no approved/unexpired
    authorization -> 422, nothing created."
    """
    target = targets.get_target(session, target_id)
    authorization = targets.get_current_approved_authorization(session, target.id)
    if authorization is None:
        raise ScopeNotAuthorizedError(
            f"Target {target.name!r} has no currently approved, unexpired authorization. "
            "Submit and approve an authorization before creating an assessment."
        )

    if target.entry_point:
        # Authoritative re-check against the approved, stored rules (the same
        # check ran at submission, but this is the one that gates a scan): an
        # entry point outside scope means nothing is created.
        targets.assert_entry_point_in_scope(target.entry_point, authorization.scope_rules)

    assessment = models.Assessment(
        target_id=target.id,
        authorization_id=authorization.id,
        scan_mode=scan_mode,
        validation_enabled=validation_enabled,
        status=models.AssessmentStatus.PENDING,
    )
    session.add(assessment)
    session.flush()

    # docs/agents/orchestrator.md step 1: validate (done above), then
    # enqueue the Recon Agent. Nothing else runs yet.
    assert_valid_transition(assessment.status, models.AssessmentStatus.RUNNING)
    assessment.status = models.AssessmentStatus.RUNNING
    assessment.started_at = datetime.now(UTC)
    orchestrator.schedule_initial_recon(session, assessment)

    session.flush()
    return assessment


def get_assessment(session: Session, assessment_id: object) -> models.Assessment:
    assessment = session.get(models.Assessment, assessment_id)
    if assessment is None:
        raise NotFoundError(f"Assessment {assessment_id!r} does not exist.")
    return assessment


def list_assessments(
    session: Session,
    *,
    status: models.AssessmentStatus | None = None,
    target_id: object | None = None,
    limit: int = 50,
) -> list[tuple[models.Assessment, int]]:
    """Newest first, each with its finding count."""
    finding_count = (
        select(func.count(models.Finding.id))
        .where(models.Finding.assessment_id == models.Assessment.id)
        .correlate(models.Assessment)
        .scalar_subquery()
    )
    query = select(models.Assessment, finding_count).order_by(models.Assessment.created_at.desc())
    if status is not None:
        query = query.where(models.Assessment.status == status)
    if target_id is not None:
        query = query.where(models.Assessment.target_id == target_id)
    rows: Any = session.execute(query.limit(limit)).all()
    return [(a, int(n)) for a, n in rows]


class AssessmentNotRunnableError(OffensiveXError):
    status_code = 409
    title = "Assessment cannot be started"


def assert_runnable(assessment: models.Assessment) -> None:
    """A run may start once: the assessment must be RUNNING (created, not
    cancelled/finished) and have no agent run beyond its initial QUEUED one."""
    if assessment.status is not models.AssessmentStatus.RUNNING:
        raise AssessmentNotRunnableError(
            f"Assessment is {assessment.status.value!r}; only a newly created (running) "
            "assessment can be started."
        )
    if any(r.status is not models.AgentRunStatus.QUEUED for r in assessment.agent_runs):
        raise AssessmentNotRunnableError("This assessment has already been started.")


def cancel_assessment(session: Session, *, assessment_id: object) -> models.Assessment:
    assessment = get_assessment(session, assessment_id)
    assert_valid_transition(assessment.status, models.AssessmentStatus.CANCELLED)
    assessment.status = models.AssessmentStatus.CANCELLED
    assessment.finished_at = datetime.now(UTC)
    session.flush()
    return assessment

"""Assessment lifecycle service — Phase 2.

This is the "scope/authorization gate (carried over from the original
design)" the roadmap names: an Assessment cannot be created unless its
target has a currently-approved, unexpired Authorization. Everything after
that gate (transitioning PENDING -> RUNNING and scheduling the orchestrator's
first decision) is the Phase 2 orchestrator skeleton.
"""

from __future__ import annotations

from datetime import UTC, datetime

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


def cancel_assessment(session: Session, *, assessment_id: object) -> models.Assessment:
    assessment = get_assessment(session, assessment_id)
    assert_valid_transition(assessment.status, models.AssessmentStatus.CANCELLED)
    assessment.status = models.AssessmentStatus.CANCELLED
    assessment.finished_at = datetime.now(UTC)
    session.flush()
    return assessment

"""Finding read service — Phase 8, extended in Phase 9 with
`get_finding` (`GET /findings/{id}`, implementation-blueprint.md §7) and
in Phase 10 with `override_finding_status`
(`PATCH /findings/{id}/status`, the explicit analyst override path —
docs/data/findings.md: "the Validation Agent's checked outcome, or an
explicit, audited analyst override" are the only two ways a finding may
reach `CONFIRMED`/`REJECTED`).

Who may call the override, and the audit row for it, are enforced at the
API boundary (`api.findings`: `findings:override` + `audit.record`); this
function enforces only the finding state machine.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.core.errors import NotFoundError
from offensivex.db import models
from offensivex.db.transitions import assert_valid_transition
from offensivex.services.assessments import get_assessment


def list_findings(
    session: Session, *, assessment_id: UUID, status: models.FindingStatus | None = None
) -> list[models.Finding]:
    """`status` filters the Phase 11 "status filters finalized" API
    surface (implementation-blueprint.md §11's P11 row) — omitted, every
    status is returned."""
    get_assessment(session, assessment_id)  # 404s if the assessment doesn't exist
    query = select(models.Finding).where(models.Finding.assessment_id == assessment_id)
    if status is not None:
        query = query.where(models.Finding.status == status)
    return list(session.scalars(query.order_by(models.Finding.first_seen)))


def get_finding(session: Session, finding_id: UUID) -> models.Finding:
    finding = session.get(models.Finding, finding_id)
    if finding is None:
        raise NotFoundError(f"Finding {finding_id!r} does not exist.")
    return finding


def override_finding_status(
    session: Session, *, finding_id: UUID, new_status: models.FindingStatus
) -> models.Finding:
    """The explicit analyst override. Only enforces the state machine
    (`offensivex.db.transitions`) — see module docstring for the known
    auth/audit gap."""
    finding = get_finding(session, finding_id)
    assert_valid_transition(finding.status, new_status)
    finding.status = new_status
    session.flush()
    return finding


def mark_finding_reported(session: Session, finding_id: UUID) -> models.Finding:
    """The last edge in docs/data/findings.md's lifecycle:
    `{CONFIRMED,REJECTED,INVESTIGATING,SUSPECTED} -> REPORTED` — a
    finding appearing in a generated report (the Reporting Agent, Phase
    14, is the real caller; this completes the Phase 11 "full lifecycle"
    requirement ahead of that agent existing, same incremental pattern as
    every other phase so far).
    """
    finding = get_finding(session, finding_id)
    assert_valid_transition(finding.status, models.FindingStatus.REPORTED)
    finding.status = models.FindingStatus.REPORTED
    session.flush()
    return finding

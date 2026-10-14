"""Explicit valid state transitions for the entities in offensivex.db.models.

CLAUDE.md section 8: "Job, task, and worker states must have explicit valid
transitions. Never allow arbitrary state mutation. Invalid transitions
should be rejected." This module is that explicit table, plus the one
function services use to enforce it.

Only entities with a real lifecycle get a table here (Authorization,
Assessment, Finding, AgentRun, ToolExecution) — Target/Asset/Observation/
Evidence/AttackNode/AttackEdge/AttackPath/Report are either CRUD, immutable,
or derived, per docs/roadmap/implementation-blueprint.md section 3.

Wiring this into actual write paths belongs to the services that own each
transition: Assessment lifecycle (P2), the agent runtime (P5), Investigation
(P9), Validation (P10). This module is deliberately usable standalone (no DB
session needed) so those services can call `assert_valid_transition` before
committing a status change, and so it is unit-testable without a database.
"""

from __future__ import annotations

import enum

from offensivex.db.models import (
    AgentRunStatus,
    AssessmentStatus,
    AuthorizationStatus,
    FindingStatus,
    ToolExecutionStatus,
)

AUTHORIZATION_TRANSITIONS: dict[AuthorizationStatus, set[AuthorizationStatus]] = {
    AuthorizationStatus.PENDING: {AuthorizationStatus.APPROVED, AuthorizationStatus.REJECTED},
    AuthorizationStatus.APPROVED: {AuthorizationStatus.REVOKED},
    AuthorizationStatus.REJECTED: set(),
    AuthorizationStatus.REVOKED: set(),
}

ASSESSMENT_TRANSITIONS: dict[AssessmentStatus, set[AssessmentStatus]] = {
    AssessmentStatus.PENDING: {AssessmentStatus.RUNNING, AssessmentStatus.CANCELLED},
    AssessmentStatus.RUNNING: {
        AssessmentStatus.COMPLETED,
        AssessmentStatus.COMPLETED_WITH_ERRORS,
        AssessmentStatus.FAILED,
        AssessmentStatus.CANCELLED,
    },
    AssessmentStatus.COMPLETED: set(),
    AssessmentStatus.COMPLETED_WITH_ERRORS: set(),
    AssessmentStatus.FAILED: set(),
    AssessmentStatus.CANCELLED: set(),
}

# Exactly docs/data/findings.md's lifecycle diagram — do not add a shortcut
# edge (e.g. DISCOVERED -> CONFIRMED) without updating that document first.
FINDING_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.DISCOVERED: {FindingStatus.SUSPECTED},
    FindingStatus.SUSPECTED: {FindingStatus.INVESTIGATING, FindingStatus.REPORTED},
    FindingStatus.INVESTIGATING: {
        FindingStatus.SUSPECTED,
        FindingStatus.CONFIRMED,
        FindingStatus.REJECTED,
        FindingStatus.REPORTED,
    },
    FindingStatus.CONFIRMED: {FindingStatus.REPORTED},
    FindingStatus.REJECTED: {FindingStatus.REPORTED},
    FindingStatus.REPORTED: set(),
}

AGENT_RUN_TRANSITIONS: dict[AgentRunStatus, set[AgentRunStatus]] = {
    AgentRunStatus.QUEUED: {AgentRunStatus.RUNNING, AgentRunStatus.CANCELLED},
    AgentRunStatus.RUNNING: {
        AgentRunStatus.SUCCEEDED,
        AgentRunStatus.FAILED,
        AgentRunStatus.CANCELLED,
    },
    AgentRunStatus.SUCCEEDED: set(),
    AgentRunStatus.FAILED: set(),
    AgentRunStatus.CANCELLED: set(),
}

# Matches docs/roadmap/implementation-blueprint.md section 3:
# "planned -> allowed/denied -> {completed, timed_out, killed}". ALLOWED
# itself is not a status value here (it's `ToolExecution.scope_decision`);
# PLANNED -> RUNNING is the "allowed" path, PLANNED -> DENIED the other.
TOOL_EXECUTION_TRANSITIONS: dict[ToolExecutionStatus, set[ToolExecutionStatus]] = {
    ToolExecutionStatus.PLANNED: {ToolExecutionStatus.RUNNING, ToolExecutionStatus.DENIED},
    ToolExecutionStatus.RUNNING: {
        ToolExecutionStatus.COMPLETED,
        ToolExecutionStatus.TIMED_OUT,
        ToolExecutionStatus.KILLED,
    },
    ToolExecutionStatus.COMPLETED: set(),
    ToolExecutionStatus.TIMED_OUT: set(),
    ToolExecutionStatus.KILLED: set(),
    ToolExecutionStatus.DENIED: set(),
}

_ALL_TRANSITION_TABLES: dict[type, dict] = {
    AuthorizationStatus: AUTHORIZATION_TRANSITIONS,
    AssessmentStatus: ASSESSMENT_TRANSITIONS,
    FindingStatus: FINDING_TRANSITIONS,
    AgentRunStatus: AGENT_RUN_TRANSITIONS,
    ToolExecutionStatus: TOOL_EXECUTION_TRANSITIONS,
}


class InvalidTransitionError(ValueError):
    """Raised when a caller attempts to move a status enum to a value its
    transition table does not allow from the current value."""


def assert_valid_transition(current: enum.StrEnum, new: enum.StrEnum) -> None:
    """Raise InvalidTransitionError unless `current -> new` is allowed.

    `current` and `new` must be members of the same status enum (one of
    the keys of `_ALL_TRANSITION_TABLES`). A no-op "transition" (new ==
    current) is never valid here — callers that mean to leave a status
    unchanged simply should not call this.
    """
    enum_type = type(current)
    if enum_type is not type(new):
        raise InvalidTransitionError(
            f"Cannot compare {current!r} and {new!r}: different status types."
        )
    table = _ALL_TRANSITION_TABLES.get(enum_type)
    if table is None:
        raise InvalidTransitionError(f"{enum_type!r} has no registered transition table.")
    allowed = table.get(current, set())
    if new not in allowed:
        raise InvalidTransitionError(
            f"{enum_type.__name__}: {current.value!r} -> {new.value!r} is not a valid "
            f"transition. Allowed from {current.value!r}: "
            f"{sorted(s.value for s in allowed) or 'none (terminal state)'}."
        )

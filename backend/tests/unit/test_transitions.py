"""Unit tests for offensivex.db.transitions: the explicit state-machine
tables required by CLAUDE.md section 8 ("invalid transitions should be
rejected"). No database needed — these tables are pure Python.
"""

from __future__ import annotations

import pytest

from offensivex.db.models import (
    AgentRunStatus,
    AssessmentStatus,
    AuthorizationStatus,
    FindingStatus,
    ToolExecutionStatus,
)
from offensivex.db.transitions import (
    AGENT_RUN_TRANSITIONS,
    ASSESSMENT_TRANSITIONS,
    AUTHORIZATION_TRANSITIONS,
    FINDING_TRANSITIONS,
    TOOL_EXECUTION_TRANSITIONS,
    InvalidTransitionError,
    assert_valid_transition,
)


@pytest.mark.parametrize(
    "table",
    [
        AUTHORIZATION_TRANSITIONS,
        ASSESSMENT_TRANSITIONS,
        FINDING_TRANSITIONS,
        AGENT_RUN_TRANSITIONS,
        TOOL_EXECUTION_TRANSITIONS,
    ],
)
def test_every_enum_member_has_a_table_entry(table: dict) -> None:
    """Every status value must appear as a key, even if its only valid
    "transition" is none (a terminal state) — a typo in an enum name must
    not silently resolve to an empty-set default everywhere."""
    enum_type = next(iter(table)).__class__
    assert set(table.keys()) == set(enum_type)


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (AuthorizationStatus.PENDING, AuthorizationStatus.APPROVED),
        (AuthorizationStatus.PENDING, AuthorizationStatus.REJECTED),
        (AuthorizationStatus.APPROVED, AuthorizationStatus.REVOKED),
    ],
)
def test_authorization_valid_transitions(
    current: AuthorizationStatus, new: AuthorizationStatus
) -> None:
    assert_valid_transition(current, new)  # must not raise


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (AuthorizationStatus.REJECTED, AuthorizationStatus.APPROVED),  # terminal
        (AuthorizationStatus.REVOKED, AuthorizationStatus.APPROVED),  # terminal
        (AuthorizationStatus.PENDING, AuthorizationStatus.REVOKED),  # skips approved
    ],
)
def test_authorization_invalid_transitions(
    current: AuthorizationStatus, new: AuthorizationStatus
) -> None:
    with pytest.raises(InvalidTransitionError):
        assert_valid_transition(current, new)


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (AssessmentStatus.PENDING, AssessmentStatus.RUNNING),
        (AssessmentStatus.PENDING, AssessmentStatus.CANCELLED),
        (AssessmentStatus.RUNNING, AssessmentStatus.COMPLETED),
        (AssessmentStatus.RUNNING, AssessmentStatus.COMPLETED_WITH_ERRORS),
        (AssessmentStatus.RUNNING, AssessmentStatus.FAILED),
        (AssessmentStatus.RUNNING, AssessmentStatus.CANCELLED),
    ],
)
def test_assessment_valid_transitions(current: AssessmentStatus, new: AssessmentStatus) -> None:
    assert_valid_transition(current, new)


def test_assessment_cannot_skip_running() -> None:
    with pytest.raises(InvalidTransitionError):
        assert_valid_transition(AssessmentStatus.PENDING, AssessmentStatus.COMPLETED)


@pytest.mark.parametrize("terminal", list(AssessmentStatus)[2:])  # completed/failed/cancelled/...
def test_assessment_terminal_states_accept_nothing(terminal: AssessmentStatus) -> None:
    for candidate in AssessmentStatus:
        if candidate is terminal:
            continue
        with pytest.raises(InvalidTransitionError):
            assert_valid_transition(terminal, candidate)


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (FindingStatus.DISCOVERED, FindingStatus.SUSPECTED),
        (FindingStatus.SUSPECTED, FindingStatus.INVESTIGATING),
        (FindingStatus.SUSPECTED, FindingStatus.REPORTED),
        (FindingStatus.INVESTIGATING, FindingStatus.SUSPECTED),
        (FindingStatus.INVESTIGATING, FindingStatus.CONFIRMED),
        (FindingStatus.INVESTIGATING, FindingStatus.REJECTED),
        (FindingStatus.INVESTIGATING, FindingStatus.REPORTED),
        (FindingStatus.CONFIRMED, FindingStatus.REPORTED),
        (FindingStatus.REJECTED, FindingStatus.REPORTED),
    ],
)
def test_finding_valid_transitions(current: FindingStatus, new: FindingStatus) -> None:
    """Exactly the edges in docs/data/findings.md's mermaid diagram."""
    assert_valid_transition(current, new)


def test_finding_cannot_skip_investigation_straight_to_confirmed() -> None:
    """The specific rule CLAUDE.md and docs/data/findings.md both insist
    on: only the Validation Agent's checked outcome (via INVESTIGATING) or
    an explicit analyst override may confirm/reject a finding — scanner
    output alone (DISCOVERED) must never reach CONFIRMED directly."""
    with pytest.raises(InvalidTransitionError):
        assert_valid_transition(FindingStatus.DISCOVERED, FindingStatus.CONFIRMED)


def test_finding_reported_is_terminal() -> None:
    for candidate in FindingStatus:
        if candidate is FindingStatus.REPORTED:
            continue
        with pytest.raises(InvalidTransitionError):
            assert_valid_transition(FindingStatus.REPORTED, candidate)


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (AgentRunStatus.QUEUED, AgentRunStatus.RUNNING),
        (AgentRunStatus.QUEUED, AgentRunStatus.CANCELLED),
        (AgentRunStatus.RUNNING, AgentRunStatus.SUCCEEDED),
        (AgentRunStatus.RUNNING, AgentRunStatus.FAILED),
        (AgentRunStatus.RUNNING, AgentRunStatus.CANCELLED),
    ],
)
def test_agent_run_valid_transitions(current: AgentRunStatus, new: AgentRunStatus) -> None:
    assert_valid_transition(current, new)


def test_agent_run_cannot_go_from_queued_to_succeeded() -> None:
    with pytest.raises(InvalidTransitionError):
        assert_valid_transition(AgentRunStatus.QUEUED, AgentRunStatus.SUCCEEDED)


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (ToolExecutionStatus.PLANNED, ToolExecutionStatus.RUNNING),
        (ToolExecutionStatus.PLANNED, ToolExecutionStatus.DENIED),
        (ToolExecutionStatus.RUNNING, ToolExecutionStatus.COMPLETED),
        (ToolExecutionStatus.RUNNING, ToolExecutionStatus.TIMED_OUT),
        (ToolExecutionStatus.RUNNING, ToolExecutionStatus.KILLED),
    ],
)
def test_tool_execution_valid_transitions(
    current: ToolExecutionStatus, new: ToolExecutionStatus
) -> None:
    assert_valid_transition(current, new)


def test_tool_execution_denied_is_terminal() -> None:
    with pytest.raises(InvalidTransitionError):
        assert_valid_transition(ToolExecutionStatus.DENIED, ToolExecutionStatus.RUNNING)


def test_mismatched_enum_types_rejected() -> None:
    with pytest.raises(InvalidTransitionError):
        assert_valid_transition(AssessmentStatus.PENDING, FindingStatus.DISCOVERED)


def test_same_status_is_never_a_valid_transition() -> None:
    """A no-op isn't a transition this module should validate — callers
    that mean "leave it unchanged" must not call assert_valid_transition
    at all, not rely on it accepting current == new."""
    with pytest.raises(InvalidTransitionError):
        assert_valid_transition(AssessmentStatus.PENDING, AssessmentStatus.PENDING)

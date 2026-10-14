"""Integration tests for the Phase 3 Tool Registry: real Postgres (for the
ToolExecution audit trail) + a real DNS resolution of "localhost" (no
external network dependency — resolving "localhost" never leaves the
machine). Require a real PostgreSQL instance, same skip-gracefully
convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.services import targets as targets_service
from offensivex.services.scope import ScopeRuleInput
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.registry import (
    AdapterMeta,
    ExecutionPlan,
    IntegrationStatus,
    Intrusiveness,
    IntrusivenessExceededError,
    ParsedResult,
    ScopeViolationError,
    ToolRegistry,
    ValidationModeRequiredError,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test")


@pytest.fixture
def db_engine(settings: Settings):
    url = settings.test_database_url or settings.database_url
    engine = create_engine(
        url, pool_pre_ping=True, future=True, connect_args={"connect_timeout": 2}
    )
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable at {url!r} ({exc.__class__.__name__}).")
    yield engine
    engine.dispose()


@pytest.fixture
def session(db_engine):
    with Session(db_engine) as s:
        yield s
        s.rollback()


def _assessment_with_scope(
    session: Session, *, scope_pattern: str, scan_mode=models.ScanMode.STANDARD
) -> models.Assessment:
    name = f"phase3-{uuid.uuid4().hex[:8]}.test"
    target = targets_service.create_target(session, name=name, type_="web_application")
    now = datetime.now(UTC)
    authorization = targets_service.submit_authorization(
        session,
        target_id=target.id,
        scope_rules=[ScopeRuleInput(rule_type="domain", pattern=scope_pattern)],
        attestation="attestation",
        valid_from=now,
        valid_until=now + timedelta(days=1),
        allow_private_targets=True,  # "localhost" resolves to a loopback address
    )
    targets_service.approve_authorization(
        session, target_id=target.id, version=authorization.version
    )
    assessment = models.Assessment(
        target_id=target.id,
        authorization_id=authorization.id,
        scan_mode=scan_mode,
        status=models.AssessmentStatus.RUNNING,
    )
    session.add(assessment)
    session.flush()
    return assessment


@dataclass(frozen=True)
class _FakeAdapter:
    meta: AdapterMeta

    def plan(self, request: dict[str, Any]) -> ExecutionPlan:
        return ExecutionPlan(capability=self.meta.capability, destinations=["localhost"])

    def run(self, plan: ExecutionPlan) -> bytes:
        return b"ok"

    def parse(self, raw_artifact: bytes) -> ParsedResult:
        return ParsedResult(capability=self.meta.capability, data={})


def test_real_dns_resolution_within_scope_succeeds(session: Session) -> None:
    assessment = _assessment_with_scope(session, scope_pattern="localhost")
    registry = ToolRegistry()
    registry.register(DnsResolutionAdapter())

    result = registry.execute(
        session,
        capability="dns_resolution",
        request={"hostname": "localhost"},
        assessment=assessment,
    )
    assert "addresses" in result.data
    assert len(result.data["addresses"]) >= 1

    execution = (
        session.query(models.ToolExecution)
        .filter_by(tool_name="dns_resolution")
        .order_by(models.ToolExecution.created_at.desc())
        .first()
    )
    assert execution is not None
    assert execution.scope_decision is models.ScopeDecision.ALLOWED
    assert execution.status is models.ToolExecutionStatus.COMPLETED
    assert execution.artifact_hash is not None


def test_out_of_scope_destination_denied_and_audited(session: Session) -> None:
    assessment = _assessment_with_scope(session, scope_pattern="only-this-host.test")
    registry = ToolRegistry()
    registry.register(DnsResolutionAdapter())

    with pytest.raises(ScopeViolationError):
        registry.execute(
            session,
            capability="dns_resolution",
            request={"hostname": "localhost"},  # not in scope
            assessment=assessment,
        )

    execution = (
        session.query(models.ToolExecution)
        .filter_by(tool_name="dns_resolution")
        .order_by(models.ToolExecution.created_at.desc())
        .first()
    )
    assert execution is not None
    assert execution.scope_decision is models.ScopeDecision.DENIED
    assert execution.status is models.ToolExecutionStatus.DENIED
    # A denied plan never ran anything.
    assert execution.artifact_hash is None


def test_intrusiveness_exceeding_scan_mode_rejected_before_scope_check(
    session: Session,
) -> None:
    assessment = _assessment_with_scope(
        session, scope_pattern="localhost", scan_mode=models.ScanMode.QUICK
    )
    registry = ToolRegistry()
    registry.register(
        _FakeAdapter(
            meta=AdapterMeta(
                name="fake_medium",
                capability="fake_medium",
                intrusiveness=Intrusiveness.MEDIUM,
                requires_validation_mode=False,
                status=IntegrationStatus.MOCKED,
            )
        )
    )

    with pytest.raises(IntrusivenessExceededError):
        registry.execute(session, capability="fake_medium", request={}, assessment=assessment)

    # Rejected before an ExecutionPlan even exists -> no ToolExecution row.
    count = session.query(models.ToolExecution).filter_by(tool_name="fake_medium").count()
    assert count == 0


def test_validation_required_capability_rejected_when_disabled(session: Session) -> None:
    assessment = _assessment_with_scope(session, scope_pattern="localhost")
    assert assessment.validation_enabled is False
    registry = ToolRegistry()
    registry.register(
        _FakeAdapter(
            meta=AdapterMeta(
                name="fake_validation",
                capability="fake_validation",
                intrusiveness=Intrusiveness.PASSIVE,
                requires_validation_mode=True,
                status=IntegrationStatus.MOCKED,
            )
        )
    )

    with pytest.raises(ValidationModeRequiredError):
        registry.execute(session, capability="fake_validation", request={}, assessment=assessment)

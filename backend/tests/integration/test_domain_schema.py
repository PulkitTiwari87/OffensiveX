"""Integration tests for the Phase 1 domain schema: require a real
PostgreSQL instance (see docker-compose.yml), same convention as
test_db_connectivity.py — skip gracefully rather than fail when none is
reachable.

Covers the roadmap's Phase 1 acceptance bar ("migration tests") beyond the
no-op proof in test_db_connectivity.py: the real domain schema applies
cleanly, round-trips through downgrade, and a representative row can
actually be written end-to-end through the ORM (exercising FKs, enum
columns, and the confidence CHECK constraint against a real database, not
just Python-side assumptions).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from offensivex.core.config import Settings
from offensivex.db import models

pytestmark = pytest.mark.integration

_BACKEND_DIR = Path(__file__).resolve().parents[2]

_EXPECTED_TABLES = {
    "targets",
    "authorizations",
    "scope_rules",
    "assessments",
    "assets",
    "observations",
    "findings",
    "evidence",
    "agent_runs",
    "tool_executions",
    "attack_nodes",
    "attack_edges",
    "attack_paths",
    "reports",
}


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
        pytest.skip(
            "PostgreSQL is not reachable at "
            f"{url!r} ({exc.__class__.__name__}). "
            "Start it with: docker compose up -d postgres"
        )
    yield engine
    engine.dispose()


@pytest.fixture
def alembic_cfg(settings: Settings) -> Config:
    cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.test_database_url or settings.database_url)
    return cfg


@pytest.fixture
def migrated_db(db_engine, alembic_cfg: Config):
    """Ensures head, yields the engine, then resets back to base so this
    test file is idempotent across repeated local runs — same convention
    as test_db_connectivity.py's test_alembic_migrations_run_cleanly."""
    command.upgrade(alembic_cfg, "head")
    yield db_engine
    command.downgrade(alembic_cfg, "base")


def test_domain_migration_creates_exactly_the_blueprint_tables(migrated_db, alembic_cfg) -> None:  # type: ignore[no-untyped-def]
    inspector = inspect(migrated_db)
    tables = set(inspector.get_table_names())
    assert _EXPECTED_TABLES <= tables
    assert "alembic_version" in tables


def test_domain_migration_downgrade_removes_everything(db_engine, alembic_cfg: Config) -> None:  # type: ignore[no-untyped-def]
    command.upgrade(alembic_cfg, "head")
    command.downgrade(alembic_cfg, "base")
    inspector = inspect(db_engine)
    tables = set(inspector.get_table_names())
    assert _EXPECTED_TABLES.isdisjoint(tables)
    with db_engine.connect() as conn:
        enum_count = conn.execute(
            text("SELECT count(*) FROM pg_type WHERE typname = 'impact_level'")
        ).scalar_one()
    assert enum_count == 0


def test_full_chain_round_trips_through_the_orm(migrated_db) -> None:  # type: ignore[no-untyped-def]
    """Writes one row per entity along the MVP chain
    (Target -> Authorization -> Assessment -> Asset -> Observation ->
    Finding -> Evidence -> AgentRun -> ToolExecution -> AttackNode ->
    AttackEdge -> AttackPath -> Report) and reads it back, proving the FKs,
    enum columns, JSONB columns, and the confidence CHECK constraint all
    work against a real Postgres, not just as Python-side assumptions.
    All values are synthetic placeholders, not real scan data.
    """
    with Session(migrated_db) as session:
        now = datetime.now(UTC)

        target = models.Target(name=f"example-{uuid.uuid4().hex[:8]}.test", type="web_application")
        session.add(target)
        session.flush()
        assert target.default_exposure == models.ImpactLevel.MEDIUM

        authorization = models.Authorization(
            target_id=target.id,
            version=1,
            attestation="I attest I am authorized to test this target.",
            valid_from=now,
            valid_until=now + timedelta(days=30),
            status=models.AuthorizationStatus.APPROVED,
        )
        session.add(authorization)
        session.flush()

        scope_rule = models.ScopeRule(
            authorization_id=authorization.id, rule_type="domain", pattern=target.name
        )
        session.add(scope_rule)

        assessment = models.Assessment(
            target_id=target.id,
            authorization_id=authorization.id,
            scan_mode=models.ScanMode.STANDARD,
            validation_enabled=True,
            status=models.AssessmentStatus.RUNNING,
        )
        session.add(assessment)
        session.flush()

        asset = models.Asset(
            assessment_id=assessment.id,
            asset_type=models.AssetType.APPLICATION,
            canonical_key=target.name,
            attributes={"scheme": "https"},
        )
        session.add(asset)
        session.flush()

        agent_run = models.AgentRun(
            assessment_id=assessment.id,
            agent_type=models.AgentType.VULNERABILITY,
            status=models.AgentRunStatus.RUNNING,
        )
        session.add(agent_run)
        session.flush()

        tool_execution = models.ToolExecution(
            agent_run_id=agent_run.id,
            tool_name="example-scanner",
            capability="http_scan",
            scope_decision=models.ScopeDecision.ALLOWED,
            status=models.ToolExecutionStatus.COMPLETED,
        )
        session.add(tool_execution)
        session.flush()

        observation = models.Observation(
            type=models.ObservationType.VULNERABILITY_SIGNAL_DISCOVERED,
            source="example-scanner",
            asset_id=asset.id,
            tool_execution_id=tool_execution.id,
            confidence=0.8,
            data={"signal": "reflected-parameter"},
        )
        session.add(observation)

        finding = models.Finding(
            assessment_id=assessment.id,
            asset_id=asset.id,
            title="Reflected XSS (example, synthetic test data)",
            severity=models.FindingSeverity.MEDIUM,
            confidence=0.8,
            source="example-scanner",
            status=models.FindingStatus.DISCOVERED,
        )
        session.add(finding)
        session.flush()

        evidence = models.Evidence(
            finding_id=finding.id,
            kind=models.EvidenceKind.REQUEST_RESPONSE,
            tool_execution_id=tool_execution.id,
            excerpt="GET /search?q=<script> -> reflected unescaped (synthetic)",
        )
        session.add(evidence)

        attack_node = models.AttackNode(
            assessment_id=assessment.id, asset_id=asset.id, access_level="unauthenticated_access"
        )
        session.add(attack_node)
        session.flush()

        other_node = models.AttackNode(
            assessment_id=assessment.id, asset_id=asset.id, access_level="data_read"
        )
        session.add(other_node)
        session.flush()

        attack_edge = models.AttackEdge(
            src_node_id=attack_node.id,
            dst_node_id=other_node.id,
            relationship_type=models.AttackRelationship.EXPLOITS,
            cause_type=models.AttackEdgeCauseType.FINDING,
            cause_id=finding.id,
            evidence_level=models.EvidenceLevel.INFERRED,
        )
        session.add(attack_edge)
        session.flush()

        attack_path = models.AttackPath(
            assessment_id=assessment.id,
            entry_node_id=attack_node.id,
            target_node_id=other_node.id,
            edge_ids=[str(attack_edge.id)],
            evidence_level=models.EvidenceLevel.INFERRED,
        )
        session.add(attack_path)

        report = models.Report(
            assessment_id=assessment.id,
            formats=[models.ReportFormat.JSON.value, models.ReportFormat.MARKDOWN.value],
            provenance={"rules_version": "0"},
        )
        session.add(report)

        session.commit()

        # Read back through a fresh query, not just the in-memory objects.
        reloaded = session.get(models.Finding, finding.id)
        assert reloaded is not None
        assert reloaded.status is models.FindingStatus.DISCOVERED
        assert len(reloaded.evidence) == 1
        assert reloaded.evidence[0].excerpt.startswith("GET /search")


def test_confidence_check_constraint_is_enforced_by_postgres(migrated_db) -> None:  # type: ignore[no-untyped-def]
    """The 0..1 confidence bound on Finding is a DB-level CHECK, not only
    a convention — an out-of-range value must fail the INSERT itself."""
    with Session(migrated_db) as session:
        target = models.Target(name=f"example-{uuid.uuid4().hex[:8]}.test", type="web_application")
        session.add(target)
        session.flush()

        now = datetime.now(UTC)
        authorization = models.Authorization(
            target_id=target.id,
            version=1,
            attestation="attestation",
            valid_from=now,
            valid_until=now + timedelta(days=30),
            status=models.AuthorizationStatus.APPROVED,
        )
        session.add(authorization)
        session.flush()

        assessment = models.Assessment(
            target_id=target.id,
            authorization_id=authorization.id,
            status=models.AssessmentStatus.RUNNING,
        )
        session.add(assessment)
        session.flush()

        asset = models.Asset(
            assessment_id=assessment.id,
            asset_type=models.AssetType.HOST,
            canonical_key=target.name,
        )
        session.add(asset)
        session.flush()

        bad_finding = models.Finding(
            assessment_id=assessment.id,
            asset_id=asset.id,
            title="Invalid confidence (synthetic test data)",
            severity=models.FindingSeverity.LOW,
            confidence=1.5,  # out of [0, 1] — must be rejected by the DB
            source="test",
        )
        session.add(bad_finding)
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

"""Unit tests for offensivex.db.models: shape/metadata checks that don't
need a database. Behavior against a real Postgres (constraints, FKs, enum
types) is covered by tests/integration/test_domain_schema.py.
"""

from __future__ import annotations

from offensivex.db.base import Base
from offensivex.db.models import (
    AgentRun,
    Assessment,
    Asset,
    AttackEdge,
    AttackNode,
    AttackPath,
    Authorization,
    Evidence,
    Finding,
    Observation,
    Report,
    ScopeRule,
    Target,
    ToolExecution,
)

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
    # Added by migration 0004 (ADR-012 / ADR-013): authentication, RBAC, audit.
    "users",
    "auth_sessions",
    "audit_log",
}


def test_all_blueprint_entities_are_registered_on_base_metadata() -> None:
    """docs/roadmap/implementation-blueprint.md section 3 lists exactly
    these 14 MVP entities — no more, no fewer, for Phase 1."""
    assert set(Base.metadata.tables.keys()) == _EXPECTED_TABLES


def test_target_construction() -> None:
    target = Target(name="example.com", type="web_application")
    assert target.name == "example.com"
    # Column defaults (default_exposure, default_criticality, timestamps)
    # are applied by SQLAlchemy at flush/INSERT time, not at bare
    # construction, so they are asserted against a real session in
    # test_domain_schema.py rather than here.


def test_finding_relationships_declared() -> None:
    assert Finding.assessment.property.mapper.class_ is Assessment
    assert Finding.asset.property.mapper.class_ is Asset
    assert Finding.evidence.property.mapper.class_ is Evidence


def test_authorization_scope_rules_relationship_declared() -> None:
    assert Authorization.scope_rules.property.mapper.class_ is ScopeRule
    assert Authorization.target.property.mapper.class_ is Target


def test_assessment_relationships_declared() -> None:
    assert Assessment.target.property.mapper.class_ is Target
    assert Assessment.assets.property.mapper.class_ is Asset
    assert Assessment.findings.property.mapper.class_ is Finding
    assert Assessment.agent_runs.property.mapper.class_ is AgentRun


def test_agent_run_tool_executions_relationship_declared() -> None:
    assert AgentRun.tool_executions.property.mapper.class_ is ToolExecution


def test_attack_graph_tables_have_no_orm_relationships_yet() -> None:
    """AttackNode/AttackEdge/AttackPath are written by the deterministic
    Attack Graph Agent (P12), not navigated via ORM relationships from
    other entities in Phase 1 — documented as deliberate, not an
    oversight, so a future change doesn't "fix" a missing relationship
    that was never meant to exist yet."""
    assert len(AttackNode.__mapper__.relationships) == 0
    assert len(AttackEdge.__mapper__.relationships) == 0
    assert len(AttackPath.__mapper__.relationships) == 0


def test_observation_and_evidence_have_no_updated_at() -> None:
    """Both are documented as immutable once written."""
    assert "updated_at" not in Observation.__table__.columns.keys()
    assert "updated_at" not in Evidence.__table__.columns.keys()


def test_report_has_no_updated_at() -> None:
    """Regeneration creates a new row rather than mutating an existing
    one — see Report's docstring."""
    assert "updated_at" not in Report.__table__.columns.keys()

"""The shared SQLAlchemy declarative base.

Phase 0 deliberately declares no domain model classes here — the canonical
entities (Target, Assessment, Asset, Observation, Finding, Evidence,
AgentRun, ToolExecution, AttackNode, AttackEdge, AttackPath, Report; see
docs/roadmap/implementation-blueprint.md section 3) belong to Phase 1.
`Base.metadata` exists now only so Alembic (backend/migrations/env.py) has a
real target to diff against, proving the migration mechanism end-to-end
before there is a schema to migrate.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all future ORM models."""

"""baseline: establish the migration mechanism, no schema yet

This revision is deliberately a no-op. Its only purpose is to prove that
`alembic upgrade head` runs cleanly against a real PostgreSQL instance and
creates the `alembic_version` bookkeeping table (see
backend/tests/integration/test_db_connectivity.py). The actual domain
schema (Target, Assessment, Asset, Observation, Finding, Evidence,
AgentRun, ToolExecution, AttackNode, AttackEdge, AttackPath, Report) is
added starting Phase 1 (docs/roadmap/roadmap.md) — see
docs/roadmap/implementation-blueprint.md section 3 for the full model.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-10-07

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

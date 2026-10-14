"""scope rule ports: scope_rules.ports

Adds a nullable `ports` list ("80,443,8000-8100") to `scope_rules` so a scope rule
can say which TCP ports it authorizes (ADR-024). Purely additive: no row is
rewritten, renamed or dropped, and no data is deleted by the upgrade.

Compatibility policy for rows that already exist (all of them get NULL):

* an existing **include** rule keeps authorizing its host, but now only on the web
  default ports 80 and 443 — a hostname grant no longer implies every port. This
  is intentionally *narrower* than before (fail-closed); nothing is widened. A
  target that is assessed on another port needs a new authorization version
  with an explicit `ports` list (authorizations are versioned, old rows stay
  as the audit record).
* an existing **exclude** rule keeps excluding its host on *every* port.

The CHECK is a coarse database-level backstop on the shape of the list; the real
validation (range bounds, catch-all rejection) is offensivex.core.ports.

Revision ID: 0006_scope_rule_ports
Revises: 0005_target_entry_point
Create Date: 2026-10-14

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_scope_rule_ports"
down_revision: str | None = "0005_target_entry_point"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scope_rules", sa.Column("ports", sa.String(200), nullable=True))
    op.create_check_constraint(
        "ck_scope_rules_ports_shape",
        "scope_rules",
        r"ports IS NULL OR ports ~ '^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$'",
    )


def downgrade() -> None:
    # Reverting necessarily discards the port restrictions stored by this
    # revision; rules revert to host-only (and so to their pre-0006 meaning).
    op.drop_constraint("ck_scope_rules_ports_shape", "scope_rules", type_="check")
    op.drop_column("scope_rules", "ports")

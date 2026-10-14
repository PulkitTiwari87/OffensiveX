"""target entry point: targets.entry_point

Adds a nullable, http(s)-only `entry_point` URL to `targets` so Recon knows the
real starting point (scheme, host, port) instead of guessing it from the
target name. Purely additive: existing rows keep working with NULL, nothing is
rewritten, renamed or dropped by the upgrade.

The CHECK is a coarse database-level backstop (http/https only); the real
validation (host syntax, port, no userinfo/query/fragment, scope coverage)
lives in offensivex.core.urls and offensivex.services.targets.

Revision ID: 0005_target_entry_point
Revises: 0004_auth_and_audit
Create Date: 2026-10-14

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_target_entry_point"
down_revision: str | None = "0004_auth_and_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("entry_point", sa.String(2048), nullable=True))
    op.create_check_constraint(
        "ck_targets_entry_point_http",
        "targets",
        "entry_point IS NULL OR entry_point LIKE 'http://%' OR entry_point LIKE 'https://%'",
    )


def downgrade() -> None:
    # Reverting necessarily discards the entry points stored by this revision.
    op.drop_constraint("ck_targets_entry_point_http", "targets", type_="check")
    op.drop_column("targets", "entry_point")

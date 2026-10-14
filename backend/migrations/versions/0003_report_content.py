"""report content columns: Phase 14

Adds `content_json`/`content_markdown` to `reports` — the actual
rendered output a generated report produces (JSON + Markdown, per
docs/roadmap/implementation-blueprint.md section 9's MVP formats).
Previously the table only recorded metadata (formats requested,
provenance) with nowhere to put the content itself.

Revision ID: 0003_report_content
Revises: 0002_domain_model
Create Date: 2026-10-14

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003_report_content"
down_revision: str | None = "0002_domain_model"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("content_json", JSONB, nullable=True))
    op.add_column("reports", sa.Column("content_markdown", sa.Text, nullable=True))


def downgrade() -> None:
    op.drop_column("reports", "content_markdown")
    op.drop_column("reports", "content_json")

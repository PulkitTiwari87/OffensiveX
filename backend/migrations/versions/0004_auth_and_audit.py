"""authentication, RBAC and audit log: users, auth_sessions, audit_log

Adds the tables behind ADR-012 (local accounts + server-side sessions) and
ADR-013 (roles; self-approval rule), plus an append-only audit log. Purely
additive: two nullable FK columns on `authorizations`, three new tables,
two new enum types. Nothing existing is renamed or dropped.

The audit log is made append-only at the database level: a trigger rejects
UPDATE, DELETE and TRUNCATE, so an application bug or a compromised API
user cannot rewrite history. (A database superuser/owner can still drop
the trigger — the control is against the application, not the DBA.)

Revision ID: 0004_auth_and_audit
Revises: 0003_report_content
Create Date: 2026-10-14

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ENUM, JSONB

revision: str = "0004_auth_and_audit"
down_revision: str | None = "0003_report_content"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_user_role = ENUM("admin", "analyst", "viewer", name="user_role", create_type=False)
_audit_outcome = ENUM("success", "denied", "failure", name="audit_outcome", create_type=False)


def upgrade() -> None:
    _user_role.create(op.get_bind(), checkfirst=True)
    _audit_outcome.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(100), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", _user_role, nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("actor_user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("actor_username", sa.String(100), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("outcome", _audit_outcome, nullable=False),
        sa.Column("target_type", sa.String(50), nullable=True),
        sa.Column("target_id", sa.String(100), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_audit_log_occurred_at", "audit_log", ["occurred_at"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_actor_user_id", "audit_log", ["actor_user_id"])

    op.execute(
        """
        CREATE FUNCTION audit_log_reject_change() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only (% rejected)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_truncate
        BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change()
        """
    )

    op.add_column(
        "authorizations",
        sa.Column("submitted_by_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id")),
    )
    op.add_column(
        "authorizations",
        sa.Column("decided_by_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id")),
    )


def downgrade() -> None:
    op.drop_column("authorizations", "decided_by_id")
    op.drop_column("authorizations", "submitted_by_id")

    # Dropping the table drops its triggers; the function is separate.
    op.drop_table("audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_reject_change()")
    op.drop_table("auth_sessions")
    op.drop_table("users")

    _audit_outcome.drop(op.get_bind(), checkfirst=True)
    _user_role.drop(op.get_bind(), checkfirst=True)

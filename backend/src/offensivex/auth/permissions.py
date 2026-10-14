"""The one place that says which role may do what (ADR-013 layer 1).

Deny by default: a role holds only the permissions listed for it here, and
`has_permission` is False for anything else. Routes never test roles
directly — they declare a `Permission` through
`offensivex.api.deps.require_permission`, so the whole policy is reviewable
in this file.

This is user authorization only. Whether the *system* may touch a *target*
(ADR-013 layer 2) is the separate target-authorization gate plus the Scope
Guard, and is deliberately independent of anything here.
"""

from __future__ import annotations

import enum

from offensivex.db.models import UserRole


class Permission(enum.StrEnum):
    DATA_READ = "data:read"  # assessments, assets, findings, attack paths, reports
    TARGETS_WRITE = "targets:write"  # create target, submit authorization
    AUTHORIZATIONS_DECIDE = "authorizations:decide"  # approve / reject scope
    ASSESSMENTS_WRITE = "assessments:write"  # create / cancel
    FINDINGS_OVERRIDE = "findings:override"  # analyst status override
    REPORTS_GENERATE = "reports:generate"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"


_ANALYST = frozenset(
    {
        Permission.DATA_READ,
        Permission.TARGETS_WRITE,
        Permission.ASSESSMENTS_WRITE,
        Permission.FINDINGS_OVERRIDE,
        Permission.REPORTS_GENERATE,
    }
)

ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.VIEWER: frozenset({Permission.DATA_READ}),
    UserRole.ANALYST: _ANALYST,
    # Admin = everything an analyst can do, plus scope decisions, user
    # management and the audit log.
    UserRole.ADMIN: _ANALYST
    | frozenset({Permission.AUTHORIZATIONS_DECIDE, Permission.USERS_MANAGE, Permission.AUDIT_READ}),
}


def has_permission(role: UserRole, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())

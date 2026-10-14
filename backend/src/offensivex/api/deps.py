"""Shared FastAPI dependencies — Phase 2, extended with auth/RBAC.

A route depends on `get_db_session`, gets a transactional `Session` for
the lifetime of the request (commit on success, rollback on error — see
offensivex.db.session.session_scope), and never constructs its own.

Authorization is declared per route with `require_permission(...)`; there is
no other way a route learns who the caller is. A route that declares neither
`require_permission` nor `get_principal` is public — the only public routes
are `/healthz`, `/readyz` and `POST /api/v1/auth/login`, and a test
(`test_rbac_matrix`) fails if any other route is reachable anonymously.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Generator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from offensivex.auth import sessions
from offensivex.auth.permissions import Permission, has_permission
from offensivex.auth.principal import Principal
from offensivex.core.config import Settings
from offensivex.core.errors import AuthenticationError, PermissionDeniedError
from offensivex.db import models
from offensivex.db.session import session_scope
from offensivex.services import audit

CSRF_HEADER = "X-CSRF-Token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_db_session(request: Request) -> Generator[Session]:
    session_factory = request.app.state.session_factory
    with session_scope(session_factory) as session:
        yield session


def get_request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_principal(
    request: Request, session: Annotated[Session, Depends(get_db_session)]
) -> Principal:
    """Authenticate the request from its session cookie and, for
    state-changing methods, check the CSRF token (ADR-012)."""
    settings = get_app_settings(request)
    token = request.cookies.get(settings.session_cookie_name)
    row = sessions.resolve_session(session, token) if token else None
    if row is None:
        raise AuthenticationError("Authentication required.")

    principal = Principal(
        user_id=row.user.id,
        username=row.user.username,
        role=row.user.role,
        session_id=row.id,
    )
    if request.method not in _SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not secrets.compare_digest(supplied.encode(), row.csrf_token.encode()):
            audit.record_independent(
                request.app.state.session_factory,
                action="authz.csrf_rejected",
                outcome=models.AuditOutcome.DENIED,
                actor=principal,
                request_id=get_request_id(request),
                details={"method": request.method, "path": request.url.path},
            )
            raise PermissionDeniedError("CSRF token missing or invalid.")
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_permission(permission: Permission) -> Callable[..., Principal]:
    """Dependency factory: 401 if unauthenticated, 403 (and an audit row) if
    the caller's role does not hold `permission`."""

    def _dependency(request: Request, principal: CurrentPrincipal) -> Principal:
        if not has_permission(principal.role, permission):
            audit.record_independent(
                request.app.state.session_factory,
                action="authz.denied",
                outcome=models.AuditOutcome.DENIED,
                actor=principal,
                request_id=get_request_id(request),
                details={
                    "permission": permission.value,
                    "method": request.method,
                    "path": request.url.path,
                },
            )
            raise PermissionDeniedError("You do not have permission to perform this action.")
        return principal

    return _dependency

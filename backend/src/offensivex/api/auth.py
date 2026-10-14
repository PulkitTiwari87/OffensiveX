"""Authentication API — login, logout, current session (ADR-012).

`POST /auth/login` is the only public route besides the health checks.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from offensivex.api.deps import (
    CurrentPrincipal,
    get_app_settings,
    get_db_session,
    get_request_id,
)
from offensivex.auth import sessions
from offensivex.auth.principal import Principal
from offensivex.core.config import Settings
from offensivex.core.errors import AuthenticationError, TooManyRequestsError
from offensivex.db import models
from offensivex.services import audit
from offensivex.services import users as users_service

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    # Bounded so an unauthenticated caller can't make us hash megabytes.
    password: str = Field(min_length=1, max_length=256)


class UserSummary(BaseModel):
    id: str
    username: str
    role: models.UserRole


class SessionResponse(BaseModel):
    user: UserSummary
    # Send back as `X-CSRF-Token` on every POST/PATCH/PUT/DELETE.
    csrf_token: str
    expires_at: datetime


def _session_response(user: models.User, row: models.AuthSession) -> SessionResponse:
    return SessionResponse(
        user=UserSummary(id=str(user.id), username=user.username, role=user.role),
        csrf_token=row.csrf_token,
        expires_at=row.expires_at,
    )


@router.post("/login", response_model=SessionResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SessionResponse:
    request_id = get_request_id(request)
    session_factory = request.app.state.session_factory
    username = users_service.normalize_username(body.username)

    since = datetime.now(UTC) - timedelta(minutes=settings.login_failure_window_minutes)
    failures = audit.count_recent_failures(
        session, action="auth.login", actor_username=username, since=since
    )
    if failures >= settings.login_max_failures:
        audit.record_independent(
            session_factory,
            action="auth.login.throttled",
            outcome=models.AuditOutcome.DENIED,
            actor_username=username,
            request_id=request_id,
        )
        raise TooManyRequestsError("Too many failed login attempts. Try again later.")

    user = users_service.authenticate(session, username=username, password=body.password)
    if user is None:
        audit.record_independent(
            session_factory,
            action="auth.login",
            outcome=models.AuditOutcome.FAILURE,
            actor_username=username,
            request_id=request_id,
        )
        raise AuthenticationError("Invalid username or password.")

    raw_token, row = sessions.create_session(
        session, user=user, ttl_minutes=settings.session_ttl_minutes
    )
    audit.record(
        session,
        action="auth.login",
        actor=Principal(user_id=user.id, username=user.username, role=user.role, session_id=row.id),
        request_id=request_id,
    )
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        path="/",
    )
    return _session_response(user, row)


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> None:
    row = session.get(models.AuthSession, principal.session_id)
    if row is not None:
        sessions.revoke_session(session, row)
    audit.record(session, action="auth.logout", actor=principal, request_id=get_request_id(request))
    response.delete_cookie(settings.session_cookie_name, path="/")


@router.get("/me", response_model=SessionResponse)
def me(
    principal: CurrentPrincipal,
    session: Annotated[Session, Depends(get_db_session)],
) -> SessionResponse:
    row = session.get(models.AuthSession, principal.session_id)
    user = session.get(models.User, principal.user_id)
    if row is None or user is None:  # pragma: no cover - principal came from this row
        raise AuthenticationError("Authentication required.")
    return _session_response(user, row)

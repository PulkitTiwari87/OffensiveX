"""User management API — admin only (`users:manage`).

The response model never includes `password_hash`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from offensivex.api.deps import get_db_session, get_request_id, require_permission
from offensivex.auth.permissions import Permission
from offensivex.auth.principal import Principal
from offensivex.db import models
from offensivex.services import audit
from offensivex.services import users as users_service

router = APIRouter(prefix="/users", tags=["users"])

_ManageUsers = Annotated[Principal, Depends(require_permission(Permission.USERS_MANAGE))]


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)
    role: models.UserRole


class UserUpdateRequest(BaseModel):
    role: models.UserRole | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: UUID
    username: str
    role: models.UserRole
    is_active: bool
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateRequest,
    request: Request,
    actor: _ManageUsers,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.User:
    user = users_service.create_user(
        session, username=body.username, password=body.password, role=body.role
    )
    audit.record(
        session,
        action="user.create",
        actor=actor,
        target_type="user",
        target_id=user.id,
        request_id=get_request_id(request),
        details={"username": user.username, "role": user.role.value},
    )
    return user


@router.get("", response_model=list[UserResponse])
def list_users(
    _actor: _ManageUsers, session: Annotated[Session, Depends(get_db_session)]
) -> list[models.User]:
    return users_service.list_users(session)


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: UUID,
    body: UserUpdateRequest,
    request: Request,
    actor: _ManageUsers,
    session: Annotated[Session, Depends(get_db_session)],
) -> models.User:
    before = users_service.get_user(session, user_id)
    previous = {"role": before.role.value, "is_active": before.is_active}
    user = users_service.update_user(
        session, user_id=user_id, acting=actor, role=body.role, is_active=body.is_active
    )
    audit.record(
        session,
        action="user.update",
        actor=actor,
        target_type="user",
        target_id=user.id,
        request_id=get_request_id(request),
        details={
            "from": previous,
            "to": {"role": user.role.value, "is_active": user.is_active},
        },
    )
    return user

"""User accounts and credential checking (ADR-012).

There is deliberately no self-registration and no default account: users are
created by an admin (API) or, for the very first admin, by the CLI
(`python -m offensivex.admin create-user`).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from offensivex.auth import sessions
from offensivex.auth.passwords import hash_password, needs_rehash, verify_password
from offensivex.auth.principal import Principal
from offensivex.core.errors import NotFoundError, OffensiveXError, PermissionDeniedError
from offensivex.db import models


class UserAlreadyExistsError(OffensiveXError):
    status_code = 409
    title = "User already exists"


def normalize_username(username: str) -> str:
    return username.strip().lower()


def create_user(
    session: Session, *, username: str, password: str, role: models.UserRole
) -> models.User:
    name = normalize_username(username)
    if not name:
        raise OffensiveXError("Username must not be empty.", status_code=422)
    user = models.User(username=name, password_hash=hash_password(password), role=role)
    session.add(user)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise UserAlreadyExistsError(f"A user named {name!r} already exists.") from exc
    return user


def get_user(session: Session, user_id: UUID) -> models.User:
    user = session.get(models.User, user_id)
    if user is None:
        raise NotFoundError(f"User {user_id!r} does not exist.")
    return user


def list_users(session: Session) -> list[models.User]:
    return list(session.scalars(select(models.User).order_by(models.User.username)))


def authenticate(session: Session, *, username: str, password: str) -> models.User | None:
    """The user if the credentials are valid and the account is active,
    else None — never says which part was wrong. Spends the same time on an
    unknown username as on a wrong password."""
    user = session.scalar(
        select(models.User).where(models.User.username == normalize_username(username))
    )
    password_ok = verify_password(password, user.password_hash if user else None)
    if user is None or not password_ok or not user.is_active:
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = datetime.now(UTC)
    session.flush()
    return user


def set_password(session: Session, *, user_id: UUID, new_password: str) -> models.User:
    """Replace a user's password and end all their sessions."""
    user = get_user(session, user_id)
    user.password_hash = hash_password(new_password)
    sessions.revoke_all_for_user(session, user.id)
    session.flush()
    return user


def update_user(
    session: Session,
    *,
    user_id: UUID,
    acting: Principal,
    role: models.UserRole | None = None,
    is_active: bool | None = None,
) -> models.User:
    """Change a user's role or active state.

    An admin cannot change their *own* role or active state: that closes the
    self-escalation path and means the system can never be left without an
    admin by one account's own action. Demoting/deactivating revokes the
    target's sessions so the change takes effect immediately.
    """
    user = get_user(session, user_id)
    if user.id == acting.user_id and (role is not None or is_active is not None):
        raise PermissionDeniedError("You cannot change your own role or active state.")
    if role is not None:
        user.role = role
    if is_active is not None:
        user.is_active = is_active
    if role is not None or is_active is False:
        sessions.revoke_all_for_user(session, user.id)
    session.flush()
    return user

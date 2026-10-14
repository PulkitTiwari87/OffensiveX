"""The authenticated caller, as handed to services and the audit log."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from offensivex.db.models import UserRole


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    username: str
    role: UserRole
    session_id: uuid.UUID | None = None

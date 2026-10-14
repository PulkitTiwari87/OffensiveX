"""Shared FastAPI dependencies — Phase 2.

A route depends on `get_db_session`, gets a transactional `Session` for
the lifetime of the request (commit on success, rollback on error — see
offensivex.db.session.session_scope), and never constructs its own.
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Request
from sqlalchemy.orm import Session

from offensivex.db.session import session_scope


def get_db_session(request: Request) -> Generator[Session]:
    session_factory = request.app.state.session_factory
    with session_scope(session_factory) as session:
        yield session

"""Database engine/session lifecycle and connectivity check.

Synchronous SQLAlchemy 2 session, per ADR-002 in docs/Decision.md (FastAPI
runs sync handlers in a threadpool; long-running work happens in workers,
not here). One engine per process, created lazily so importing this module
never opens a connection by itself (tests can construct their own).
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from offensivex.core.config import Settings
from offensivex.core.logging import get_logger

log = get_logger(__name__)


def create_db_engine(settings: Settings) -> Engine:
    # An explicit connect timeout matters: without one, a connection attempt
    # to an unreachable host can block far longer than any caller (e.g. the
    # /readyz probe) should ever wait, instead of failing fast so the
    # process can honestly report "not ready".
    #
    # Measured, not assumed: a hostname like "localhost" resolves to both
    # ::1 and 127.0.0.1 on this host, and psycopg tries each address in
    # turn, so the real worst case is connect_timeout x (addresses tried),
    # not connect_timeout alone (verified: connect_timeout=3 against an
    # unresponsive "localhost" target took ~6s, not ~3s). Kept short for
    # exactly that reason, so /readyz stays within a few seconds even in
    # the worst case rather than appearing to "fail fast" on paper only.
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        future=True,
        connect_args={"connect_timeout": 2},
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """A transactional session: commits on success, rolls back on error."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_connectivity(engine: Engine) -> bool:
    """Used by GET /readyz and the DB integration test.

    Returns False rather than raising on any failure — the caller (the
    readiness endpoint) decides what to do with "not ready"; a connectivity
    check failing is an expected, not exceptional, condition.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # noqa: BLE001 - deliberately broad: any DB failure means "not ready"
        log.warning("db.connectivity_check_failed", error=str(exc))
        return False

"""Integration tests: require a real PostgreSQL instance.

Run `docker compose up -d postgres` (or let CI's postgres service container
provide one) before running these. They skip gracefully — rather than
fail — when no database is reachable, so `pytest` run without Docker still
completes and reports honestly what it could and could not verify.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from offensivex.core.config import Settings
from offensivex.db.session import check_connectivity

pytestmark = pytest.mark.integration

_BACKEND_DIR = Path(__file__).resolve().parents[2]


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test")


@pytest.fixture
def db_engine(settings: Settings):
    url = settings.test_database_url or settings.database_url
    # A short, explicit connect timeout matters here: without it, attempting
    # to reach a host with nothing listening can hang far longer than a
    # developer would ever wait (observed in practice when Docker Desktop is
    # installed but its daemon isn't running) instead of skipping quickly.
    # "localhost" resolves to both ::1 and 127.0.0.1 here, and psycopg tries
    # each in turn, so the real worst case is ~2x this value, not 1x
    # (measured directly — see db/session.py for the same note).
    engine = create_engine(
        url, pool_pre_ping=True, future=True, connect_args={"connect_timeout": 2}
    )
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            "PostgreSQL is not reachable at "
            f"{url!r} ({exc.__class__.__name__}). "
            "Start it with: docker compose up -d postgres"
        )
    yield engine
    engine.dispose()


def test_connectivity_check_succeeds_against_real_postgres(db_engine) -> None:  # type: ignore[no-untyped-def]
    assert check_connectivity(db_engine) is True


def test_alembic_migrations_run_cleanly(db_engine, settings: Settings) -> None:  # type: ignore[no-untyped-def]
    """Proves the migration mechanism itself works end-to-end (Phase 0
    acceptance criterion), independent of there being a real schema yet."""
    alembic_cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    alembic_cfg.set_main_option(
        "sqlalchemy.url", settings.test_database_url or settings.database_url
    )

    command.upgrade(alembic_cfg, "head")

    inspector = inspect(db_engine)
    assert "alembic_version" in inspector.get_table_names()

    # Clean up so repeated local test runs stay idempotent.
    command.downgrade(alembic_cfg, "base")

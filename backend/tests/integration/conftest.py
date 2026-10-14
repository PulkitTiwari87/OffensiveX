"""Shared setup for tests/integration/*.

Bug this fixes: test_domain_schema.py's own tests exercise `alembic
upgrade`/`downgrade` directly (that is their point — proving the migration
mechanism), and some of them tear the schema back down to `base` as part
of that. Running the full suite in one pytest session, other integration
test files (test_phase2_services.py, test_phase2_api.py, ...) would then
find the schema missing if they happened to run afterward — a real
ordering bug, caught by actually running the whole suite together rather
than one file at a time.

Fix: before every test under tests/integration/, idempotently ensure the
schema is at `head` (a no-op if it already is). This never hides a
database being unreachable — the connectivity probe here mirrors the one
every test file's own fixture already does, and if it fails, this fixture
simply does nothing, leaving each test's own `pytest.skip(...)` to report
it clearly, the same way it always has.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from offensivex.core.config import Settings

_BACKEND_DIR = Path(__file__).resolve().parents[2]


def _db_reachable(url: str) -> bool:
    engine = create_engine(url, connect_args={"connect_timeout": 2})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        return False
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _ensure_schema_at_head() -> None:
    settings = Settings(environment="test")
    url = settings.test_database_url or settings.database_url
    if not _db_reachable(url):
        return  # let the test's own fixture skip with a clear message

    alembic_cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    alembic_cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(alembic_cfg, "head")

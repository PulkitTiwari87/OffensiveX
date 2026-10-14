"""Alembic environment.

The database URL comes from OffensiveX's own Settings, not from
alembic.ini, so there is exactly one source of truth for the connection
string (and it is never committed — see .env.example at the repo root).
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from offensivex.core.config import get_settings
from offensivex.db import models  # noqa: F401 - populates Base.metadata (Phase 1)
from offensivex.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)

# Phase 1 populated Base's metadata with the real model classes in
# offensivex.db.models (imported above for its side effect on
# Base.metadata); `alembic revision --autogenerate` now diffs against the
# full domain schema, not just the no-op baseline from Phase 0.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Same bounded connect timeout as offensivex.db.session.create_db_engine
    # and the DB integration test fixture — without it, `alembic upgrade`
    # against an unreachable database hangs with no bound at all (verified:
    # it exceeded a 30s foreground run during Phase 0 verification before
    # this was added). See db/session.py for why the real worst case is
    # ~2x this value on a dual-stack "localhost".
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args={"connect_timeout": 2},
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from offensivex.core.config import Settings
from offensivex.main import create_app


def _load_test_database_url() -> None:
    """Integration tests drop and recreate the schema, so they must never share a
    database with the one the dashboard/CLI use. Take OFFENSIVEX_TEST_DATABASE_URL
    from backend/.env when it is not already in the environment (this is the only
    key read from that file; the rest of `.env` is ignored by tests)."""
    key = "OFFENSIVEX_TEST_DATABASE_URL"
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if key not in os.environ and env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == key and value.strip():
                os.environ[key] = value.strip()
                break
    if key in os.environ:
        # Alembic (migrations/env.py) and any `Settings()` read DATABASE_URL, so the
        # whole test process is pointed at the test database, not just the tests that
        # look at the TEST_ variable.
        os.environ["OFFENSIVEX_DATABASE_URL"] = os.environ[key]


_load_test_database_url()


@pytest.fixture(autouse=True)
def _no_real_llm_in_tests(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """The suite never calls a real model, whatever the developer's shell or
    `.env` says. Environment variables outrank the dotenv file, so forcing
    the switch off here neutralises both; only `@pytest.mark.real_llm` tests
    (explicitly opt-in) see the real configuration."""
    if request.node.get_closest_marker("real_llm"):
        return
    monkeypatch.setenv("OFFENSIVEX_LLM_ENABLED", "false")
    # Also ignore the developer's `.env` entirely: its LLM values (base URL,
    # model, ...) would otherwise fill in fields a test left unset and change
    # what the test proves. Tests pass what they need explicitly.
    monkeypatch.setitem(Settings.model_config, "env_file", None)


@pytest.fixture
def test_settings() -> Settings:
    """A Settings instance that never touches a real network/database.

    Constructed from explicit kwargs (which take priority over any
    environment variables or a stray .env file) so tests are deterministic
    regardless of what's set on the developer's machine.
    """
    return Settings(
        environment="test",
        secret_key="test-secret-key-not-used-for-anything-real",
        database_url="postgresql+psycopg://offensivex:offensivex@localhost:5433/offensivex",
        log_level="INFO",
    )


@pytest.fixture
def app(test_settings: Settings) -> FastAPI:
    return create_app(test_settings)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)

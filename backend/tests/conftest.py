from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from offensivex.core.config import Settings
from offensivex.main import create_app


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

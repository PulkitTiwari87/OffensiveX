from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from offensivex.core.config import Settings
from offensivex.main import create_app


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

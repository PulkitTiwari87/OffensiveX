"""Helpers for tests that call the HTTP API now that every route (except
health and login) requires a session. Real login, real cookies, real CSRF —
no bypass hook exists in the application for tests to use."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from offensivex.core.config import Settings
from offensivex.db import models
from offensivex.db.session import create_db_engine
from offensivex.main import create_app
from offensivex.services import users as users_service

# Test-only credential for throwaway users in a throwaway test database.
TEST_PASSWORD = "correct-horse-battery-staple"  # noqa: S105


def create_user(
    settings: Settings, *, role: models.UserRole, username: str | None = None
) -> models.User:
    engine = create_db_engine(settings)
    try:
        with Session(engine) as session:
            user = users_service.create_user(
                session,
                username=username or f"{role.value}-{uuid.uuid4().hex[:10]}",
                password=TEST_PASSWORD,
                role=role,
            )
            session.commit()
            session.refresh(user)
            return user
    finally:
        engine.dispose()


def login(client: TestClient, username: str, password: str = TEST_PASSWORD) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    csrf = response.json()["csrf_token"]
    client.headers["X-CSRF-Token"] = csrf
    return {"csrf_token": csrf}


def authenticated_client(
    settings: Settings, role: models.UserRole = models.UserRole.ADMIN
) -> TestClient:
    """A client already logged in as a fresh user with `role`."""
    user = create_user(settings, role=role)
    client = TestClient(create_app(settings))
    login(client, user.username)
    return client

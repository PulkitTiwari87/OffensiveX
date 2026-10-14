from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from offensivex.api import health as health_module


def test_healthz_returns_ok(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_returns_200_when_db_reachable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(health_module, "check_connectivity", lambda engine: True)
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readyz_returns_503_when_db_unreachable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(health_module, "check_connectivity", lambda engine: False)
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["title"] == "Not ready"
    assert "request_id" in body


def test_readyz_failure_response_has_no_internal_leakage(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(health_module, "check_connectivity", lambda engine: False)
    response = client.get("/readyz")
    body = response.json()
    # Only the generic detail message, never a raw exception/connection string.
    assert "psycopg" not in str(body).lower()
    assert "traceback" not in str(body).lower()

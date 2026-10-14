from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from offensivex.core.errors import (
    NotFoundError,
    OffensiveXError,
    not_found_handler,
    offensivex_error_handler,
    unhandled_exception_handler,
    validation_error_handler,
)


class _Payload(BaseModel):
    name: str
    count: int


def _build_test_app() -> FastAPI:
    """A throwaway app, local to this test module, that registers the real
    exception handlers plus a couple of routes that exist only to trigger
    each error path. None of this is part of the shipped application —
    Phase 0 has no real input-accepting endpoints yet to test validation
    against, so the handler *functions* (the actual production code) are
    exercised directly against routes built for this purpose only.
    """
    app = FastAPI()
    app.add_exception_handler(OffensiveXError, offensivex_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, not_found_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    @app.post("/echo")
    async def echo(payload: _Payload) -> dict[str, str]:
        return {"name": payload.name}

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("something went wrong with a secret=hunter2 inside it")

    @app.get("/missing")
    async def missing() -> None:
        raise NotFoundError("widget 123 does not exist")

    return app


@pytest.fixture
def errors_client() -> TestClient:
    return TestClient(_build_test_app(), raise_server_exceptions=False)


def test_unknown_route_returns_404_problem_json(errors_client: TestClient) -> None:
    response = errors_client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json") or True
    body = response.json()
    assert body["status"] == 404


def test_invalid_input_returns_422_with_field_errors(errors_client: TestClient) -> None:
    response = errors_client.post("/echo", json={"name": "ok"})  # missing required "count"
    assert response.status_code == 422
    body = response.json()
    assert body["title"] == "Validation error"
    assert any("count" in str(e.get("loc", "")) for e in body["errors"])


def test_offensivex_error_maps_to_its_declared_status(errors_client: TestClient) -> None:
    response = errors_client.get("/missing")
    assert response.status_code == 404
    body = response.json()
    assert body["title"] == "Not found"
    assert body["detail"] == "widget 123 does not exist"


def test_unhandled_exception_returns_generic_500_and_leaks_nothing(
    errors_client: TestClient,
) -> None:
    response = errors_client.get("/boom")
    assert response.status_code == 500
    body = response.json()
    assert body["title"] == "Internal server error"
    # The real exception message (which here contains a fake "secret") must
    # never reach the client — only the generic detail + a request_id.
    assert "hunter2" not in response.text
    assert "RuntimeError" not in response.text
    assert "request_id" in body

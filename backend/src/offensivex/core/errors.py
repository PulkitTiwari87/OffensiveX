"""Centralized, consistent error handling.

Every error response is an RFC 9457 `application/problem+json` body — the
convention already fixed in docs/interfaces/api.md ("Errors: RFC 9457
application/problem+json ... no stack traces"). Error handlers here are the
single place that decides what a client is allowed to see, so individual
routes never need to remember not to leak internals.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from offensivex.core.logging import get_logger

log = get_logger(__name__)

_PROBLEM_CONTENT_TYPE = "application/problem+json"


class OffensiveXError(Exception):
    """Base class for application errors that should produce a clean,
    predictable client response (as opposed to an unexpected bug)."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    title: str = "Application error"

    def __init__(self, detail: str, *, title: str | None = None, status_code: int | None = None):
        super().__init__(detail)
        self.detail = detail
        if title is not None:
            self.title = title
        if status_code is not None:
            self.status_code = status_code


class NotFoundError(OffensiveXError):
    status_code = status.HTTP_404_NOT_FOUND
    title = "Not found"


class ServiceUnavailableError(OffensiveXError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    title = "Service unavailable"


def _problem_response(
    *,
    request: Request,
    status_code: int,
    title: str,
    detail: str,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": title,
        "status": status_code,
        "detail": detail,
        "request_id": request_id,
    }
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status_code, content=body, media_type=_PROBLEM_CONTENT_TYPE)


async def offensivex_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # FastAPI's add_exception_handler is typed against the base `Exception`
    # (it has to be, since the same method also registers WebSocket
    # handlers) — this assertion is what we register the handler *for*, so
    # it always holds at runtime; it only exists to narrow the type for mypy.
    assert isinstance(exc, OffensiveXError)
    log.info("request.error", title=exc.title, detail=exc.detail, status_code=exc.status_code)
    return _problem_response(
        request=request, status_code=exc.status_code, title=exc.title, detail=exc.detail
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    log.info("request.validation_error", errors=exc.errors())
    return _problem_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        title="Validation error",
        detail="The request did not pass validation.",
        extra={"errors": exc.errors()},
    )


async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    return _problem_response(
        request=request,
        status_code=status.HTTP_404_NOT_FOUND,
        title="Not found",
        detail="The requested resource does not exist.",
    )


async def invalid_transition_handler(request: Request, exc: Exception) -> JSONResponse:
    """`offensivex.db.transitions.InvalidTransitionError` is a plain
    `ValueError`, not an `OffensiveXError` (it's deliberately usable
    standalone, with no DB/HTTP dependency — see that module's
    docstring). Any API route whose service calls `assert_valid_transition`
    (Assessment/Authorization/Finding status changes) needs this mapped
    to a clean 422, not the generic 500 `unhandled_exception_handler`
    would otherwise give it — found while adding Phase 10's
    `PATCH /findings/{id}/status`.
    """
    log.info("request.error", title="Invalid state transition", detail=str(exc))
    return _problem_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        title="Invalid state transition",
        detail=str(exc),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler for anything not already caught.

    The real exception and traceback are logged server-side (structured,
    so they're searchable) — but the client only ever sees a generic
    message and a request_id to correlate with those logs. Never expose
    `str(exc)` or a traceback in the response body, in any environment:
    debugging happens via logs, not via the HTTP response.
    """
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    log.error("request.unhandled_exception", request_id=request_id, exc_info=exc)
    return _problem_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Internal server error",
        detail="An unexpected error occurred. Reference the request_id when reporting this.",
    )

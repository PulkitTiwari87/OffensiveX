"""Application factory.

Phase 0: app startup/shutdown, request logging + correlation IDs,
centralized error handling, CORS, health/readiness endpoints. Phase 2 adds
the first `/api/v1` routes: Targets/Authorizations (offensivex.api.targets)
and Assessments (offensivex.api.assessments).

Security boundary: every `/api/v1` route requires an authenticated session
and a declared permission (ADR-012 / ADR-013; see
docs/security/access-control.md for the route-by-route classification).
The only public routes are `/healthz`, `/readyz` and `POST /api/v1/auth/login`.
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from offensivex.api import (
    assessments,
    assets,
    attack_graph,
    audit,
    auth,
    findings,
    health,
    reports,
    targets,
    users,
)
from offensivex.core.config import Settings, get_settings
from offensivex.core.errors import (
    OffensiveXError,
    invalid_transition_handler,
    not_found_handler,
    offensivex_error_handler,
    unhandled_exception_handler,
    validation_error_handler,
)
from offensivex.core.logging import configure_logging, get_logger
from offensivex.db.session import create_db_engine, create_session_factory
from offensivex.db.transitions import InvalidTransitionError
from offensivex.llm.base import try_get_llm_provider

log = get_logger(__name__)

_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    log.info(
        "application.starting",
        environment=settings.environment,
        llm_enabled=settings.llm_enabled,
    )
    yield
    log.info("application.stopping")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    # The interactive docs/schema are unauthenticated routes; keep them off in
    # production so the only public endpoints are health checks and login.
    docs_enabled = settings.environment != "production"
    app = FastAPI(
        title="OffensiveX API",
        lifespan=_lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.settings = settings
    # None when OFFENSIVEX_LLM_ENABLED is false. A misconfigured provider
    # raises here, at startup, rather than on the first request.
    app.state.llm_provider = try_get_llm_provider(settings)
    app.state.db_engine = create_db_engine(settings)
    app.state.session_factory = create_session_factory(app.state.db_engine)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        # The id lands in logs and the audit log (varchar(64)), so a client-
        # supplied value is accepted only if it is short and boring.
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _REQUEST_ID_RE.fullmatch(supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()
        with structlog.contextvars.bound_contextvars(request_id=request_id):
            log.info("request.started", method=request.method, path=request.url.path)
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            log.info(
                "request.completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
            )
        response.headers["X-Request-ID"] = request_id
        return response

    app.add_exception_handler(OffensiveXError, offensivex_error_handler)
    app.add_exception_handler(InvalidTransitionError, invalid_transition_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, not_found_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    app.include_router(health.router)

    # Base path /api/v1 (docs/interfaces/api.md). Phase 2 adds the first
    # routes: Targets/Authorizations and Assessments.
    v1_router = APIRouter(prefix="/api/v1")
    v1_router.include_router(auth.router)
    v1_router.include_router(users.router)
    v1_router.include_router(audit.router)
    v1_router.include_router(targets.router)
    v1_router.include_router(assessments.router)
    v1_router.include_router(assets.router)
    v1_router.include_router(findings.router)
    v1_router.include_router(findings.detail_router)
    v1_router.include_router(attack_graph.router)
    v1_router.include_router(reports.router)
    v1_router.include_router(reports.detail_router)
    app.include_router(v1_router)

    return app


app = create_app()

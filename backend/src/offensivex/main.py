"""Application factory.

Phase 0: app startup/shutdown, request logging + correlation IDs,
centralized error handling, CORS, health/readiness endpoints. Phase 2 adds
the first `/api/v1` routes: Targets/Authorizations (offensivex.api.targets)
and Assessments (offensivex.api.assessments).

Security boundary note, corrected from an earlier draft of this docstring:
ADR-012/ADR-013 (docs/Decision.md) describe session-based auth and RBAC as
landing "Phase 2," but that predates the later architecture-to-
implementation consistency review (docs/roadmap/implementation-blueprint.md),
whose Phase 2 row (section 11) scopes this phase to Target/Authorization/
Assessment services and the orchestrator skeleton only — no Auth Service,
no `User`/`Session` entities. Per that newer, reconciled breakdown (which
CLAUDE.md section 22's ambiguity-resolution order ranks above an older ADR
when the two disagree), no route below requires authentication yet. This
is a tracked gap, not an oversight — see docs/roadmap/current-status.md's
Phase 2 section. `approve_authorization` in particular is specified
(ADR-013) to require the `admin` role and is not yet restricted to one.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from offensivex.api import assessments, assets, attack_graph, findings, health, reports, targets
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

log = get_logger(__name__)


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

    app = FastAPI(title="OffensiveX API", lifespan=_lifespan)
    app.state.settings = settings
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
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
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

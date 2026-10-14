"""Liveness and readiness endpoints.

Unversioned, per docs/interfaces/api.md ("GET /healthz, /readyz | ... |
none"). Everything else the API will eventually expose is versioned under
/api/v1 (see offensivex.main for the empty, ready-to-use v1 router) — but
no /api/v1 route exists yet; that starts with the Assessment API in Phase 2.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from offensivex.core.errors import ServiceUnavailableError
from offensivex.db.session import check_connectivity

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: the process is up and able to handle requests at all.

    Deliberately checks nothing external — a dependency outage should make
    /readyz fail, not /healthz (which would cause an orchestrator to kill
    and restart a perfectly healthy process).
    """
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request, response: Response) -> dict[str, str]:
    """Readiness: the process can actually serve requests that touch the
    database. Returns 503 (via a problem+json body) rather than raising an
    unhandled error when the database is unreachable."""
    engine = request.app.state.db_engine
    if not check_connectivity(engine):
        raise ServiceUnavailableError("Database is not reachable.", title="Not ready")
    response.status_code = status.HTTP_200_OK
    return {"status": "ok"}

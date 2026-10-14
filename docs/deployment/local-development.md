# Local Development

Status: PARTIAL — Phase 0 (project foundation) is implemented and **fully verified, including Docker**: app startup, config, logging, error handling, health/readiness endpoints, the DB connectivity + migration mechanism, the test suite, and the containerized API + Postgres stack. There is no domain schema, no API beyond health checks, and no frontend yet — see [../roadmap/current-status.md](../roadmap/current-status.md).
Related: [docker.md](docker.md) · [configuration.md](configuration.md)

## Prerequisites (confirmed present on the primary development machine)

| Tool | Version observed | Role |
|---|---|---|
| Python | 3.12.6 | Backend / agent runtime |
| Node.js | 22.12.0 | Dashboard frontend (not needed until Phase 15) |
| Docker Desktop | installed and **working** (a stale-socket crash in earlier sessions was resolved; see [../Memory.md](../Memory.md)) | Postgres, Compose, later the Sandbox |
| Git | present (repository initialized in Phase 0, no commits made yet) | Version control |

`nmap` and `psql` are **not** installed on the host — recon/scanner tooling and database access are expected to run inside containers (see [docker.md](docker.md)), not natively on a Windows host.

## Day-to-day workflow (verified working in Phase 0, without Docker)

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate        # .venv\Scripts\Activate.ps1 on native PowerShell
pip install -e ".[dev]"
```

```bash
ruff format --check .         # format — verified clean
ruff check .                  # lint — verified clean
mypy src                      # type check — verified clean
pytest                        # verified: 27 passed, 0 skipped against a real
                               # Postgres; without Postgres running, the 2 DB
                               # integration tests skip gracefully instead,
                               # with the real connection error printed
```

```bash
uvicorn offensivex.main:app --reload
# then: curl http://localhost:8000/healthz
```

`GET /healthz` returns `200 {"status": "ok"}` immediately (verified live, ~0.1s). `GET /readyz` additionally checks the database and returns `503` (problem+json) if it can't connect — verified live against an unreachable database: **4.1s**, not a hang, with the real error logged server-side and only a generic message in the response body.

## With Postgres (requires a running Docker daemon)

```bash
cp .env.example .env           # first time only — docker compose reads this
docker compose up -d postgres
cd backend
alembic upgrade head           # creates the alembic_version table — no domain
                                # schema exists yet (Phase 1 adds it)
pytest -m integration          # exercises DB connectivity + the migration
                                # mechanism against the real database
```

**VERIFIED.** Full stack exercised for real: `docker compose config` resolves correctly, `docker compose up -d postgres` starts and reports `healthy`, `docker compose up -d --build` builds the API image (~47s cold) and starts it, `docker compose exec api whoami` → `offensivex` (uid=1000, confirmed non-root), `curl http://localhost:8000/healthz` and `/readyz` both return `200` (the latter in ~25ms, talking to the containerized database), `alembic upgrade head` succeeds against the live database, and `pytest -m integration` → `2 passed`. Containers were torn down afterward with `docker compose down`.

An earlier Docker Desktop crash on this host (a stale AF_UNIX socket reparse point left by an abnormal prior crash — the exact file the crash dialog named) was resolved by stopping all Docker processes, running `wsl --shutdown`, and restarting Docker Desktop — see [../Memory.md](../Memory.md) for the full diagnosis if this recurs.

## Frontend

Not started — correctly so; the dashboard is Phase 15, far later than Phase 0 (see [../roadmap/roadmap.md](../roadmap/roadmap.md)). Node.js is confirmed available for when that phase begins.

## Running a lab target

A deliberately vulnerable, loopback-only lab target (e.g. OWASP Juice Shop) is planned for exercising the full assessment lifecycle end-to-end without touching any real system — see [docker.md](docker.md) for its isolation requirements. Not part of Phase 0.

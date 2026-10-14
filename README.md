# OffensiveX

> An autonomous, AI-assisted penetration-testing platform for **authorized** security assessments.

**Status: the backend is implemented through Phase 14 (reporting), plus authentication/RBAC/audit logging and LLM-provider integration. The dashboard, CLI and cloud security are still designs. No real LLM has been run against the agents yet — see below.** See [docs/roadmap/current-status.md](docs/roadmap/current-status.md) for the single authoritative "what actually exists" table.

## What OffensiveX is

OffensiveX orchestrates specialized AI agents — reconnaissance, vulnerability discovery, investigation, validation, attack-graph construction, risk analysis, and reporting — over a controlled **Tool Registry**, running every tool call inside a sandboxed, scope-checked execution path. Raw tool output becomes structured observations, observations are correlated into evidence-backed findings, confirmed findings and asset relationships build an **attack graph**, and a deterministic **risk engine** scores findings by what they let an attacker reach next — not just by isolated severity. That combination, **attack-path intelligence and risk propagation**, is OffensiveX's core differentiator.

```
Target → Recon → Vulnerability Discovery → Investigation → Validation (opt-in)
       → Evidence → Confirmed Findings → Attack Graph → Risk Analysis → Report
```

The agent/tool-registry/sandbox shape is **inspired by the public architecture of projects such as Strix** (orchestrator → specialized agents → tool abstraction → sandboxed execution). OffensiveX is an original implementation — its data model, attack-graph engine, and risk-propagation logic are its own design — and is not a fork or clone of Strix.

## Architecture summary

| Layer | Role |
|---|---|
| Orchestrator | Owns the assessment lifecycle and schedules agents; no tool access itself. |
| Agents | Recon, Vulnerability, Investigation, Validation, Attack Graph, Risk, Reporting — each with a narrow toolset and one kind of output. |
| Tool Registry | The single abstraction every agent calls tools through. |
| Sandbox + Scope Guard | Every tool call is scope-checked (default-deny) and runs in an isolated, resource-limited container. |

Full detail: [docs/architecture/overview.md](docs/architecture/overview.md).

## Planned technology stack

Python (backend, agent runtime), PostgreSQL (all persistent state), React + TypeScript (dashboard), Docker Compose (deployment and sandboxing). None of this is implemented yet — see [docs/deployment/](docs/deployment/local-development.md) for the intended local-dev workflow and [docs/roadmap/roadmap.md](docs/roadmap/roadmap.md) for the build order.

## Development status

| Area | Status |
|---|---|
| Documentation | IMPLEMENTED (this tree) |
| Backend, Phases 0–14 | IMPLEMENTED and verified against real PostgreSQL — domain model, Tool Registry, agents, findings lifecycle, attack graph, risk engine, reports |
| Authentication, RBAC, audit log | IMPLEMENTED and verified — [docs/security/access-control.md](docs/security/access-control.md) |
| LLM integration (Anthropic, OpenAI-compatible) | IMPLEMENTED, **not yet verified against a real model** — [docs/architecture/llm-integration.md](docs/architecture/llm-integration.md) |
| CLI (`offensivex`, P16) | IMPLEMENTED and verified against a real backend — [docs/interfaces/cli.md](docs/interfaces/cli.md) |
| Dashboard (React + TypeScript + Vite, P15) | IMPLEMENTED and verified in a browser against a real backend — [docs/interfaces/dashboard.md](docs/interfaces/dashboard.md) |
| Cloud Security | NOT STARTED |

See [docs/roadmap/current-status.md](docs/roadmap/current-status.md) for the full table and known gaps.

## Quick start (Phase 0)

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate   # .venv\Scripts\Activate.ps1 on native PowerShell
pip install -e ".[dev]"

ruff format --check .   # format
ruff check .            # lint
mypy src                # type check
pytest                  # unit tests always run; DB integration tests skip
                        # gracefully without a reachable Postgres

uvicorn offensivex.main:app --reload
# curl http://localhost:8000/healthz
```

With a running Docker daemon: `cp .env.example .env`, then `docker compose up -d postgres`, then `alembic upgrade head` and `pytest -m integration` from `backend/` to exercise the database layer for real. **Verified**: the full stack (API container + Postgres) has been built, run, and tested end-to-end — `27/27` tests pass against a real database, and the API container runs as a confirmed non-root user. See [docs/deployment/local-development.md](docs/deployment/local-development.md) for the full picture.

### First run: create an admin, optionally enable the LLM

There is **no default account**. With the database migrated (`alembic upgrade head`):

```bash
python -m offensivex.admin create-user --username <you> --role admin   # prompts for a password
uvicorn offensivex.main:app
```

Log in with `POST /api/v1/auth/login` (cookie session + `X-CSRF-Token`; see
[docs/interfaces/api.md](docs/interfaces/api.md)). The LLM is **off** unless you set
`OFFENSIVEX_LLM_ENABLED=true` plus `OFFENSIVEX_LLM_PROVIDER`, `_MODEL` and `_API_KEY` in your
own environment (never commit them; see [.env.example](.env.example)). Then:

```bash
pytest -m real_llm tests/integration/test_real_llm.py     # opt-in; costs money
python -m offensivex.admin run-assessment --assessment-id <uuid> --report
```

### MVP walkthrough (local lab, CLI and dashboard)

Everything below runs on your machine against a lab target **you own**. Never point it at a third party.

```bash
# 1. Database and backend
docker compose up -d postgres                       # repo root
cd backend && pip install -e ".[dev]" && alembic upgrade head
# 2. Dashboard build (served by the backend at /dashboard)
cd ../frontend && npm ci && npm run build && cd ../backend
# 3. Optional LLM (agents cannot run without it) - put these in backend/.env, never commit them:
#    OFFENSIVEX_LLM_ENABLED=true  OFFENSIVEX_LLM_PROVIDER=openai
#    OFFENSIVEX_LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
#    OFFENSIVEX_LLM_MODEL=gemini-3.1-flash-lite   OFFENSIVEX_LLM_API_KEY=...
# 4. Start (private targets must be allowed explicitly to scan localhost)
OFFENSIVEX_ALLOW_PRIVATE_TARGETS=true uvicorn offensivex.main:app --host 127.0.0.1 --port 8000

# 5. First administrator, then an analyst (passwords are prompted, never arguments)
offensivex admin create-user --username admin1 --role admin
offensivex admin create-user --username analyst1 --role analyst

# 6. Analyst: target + scope (host AND port); admin approves; analyst runs it
offensivex login --username analyst1
offensivex target create --name lab --type web_application --entry-point http://localhost:8099/
offensivex authorization submit lab --include domain:localhost@8099 --attestation "My own lab" --valid-days 1
offensivex login --username admin1 && offensivex authorization approve lab 1   # a different person than the submitter
offensivex login --username analyst1
offensivex assessment create lab && offensivex assessment run <id> --wait
offensivex finding list --assessment <id> && offensivex finding show <finding-id>
offensivex report generate <id> --format both -o report.md
```

Open <http://127.0.0.1:8000/dashboard/> and sign in with the same accounts: the dashboard and CLI read the same database. Port scope matters: an include rule without `@PORTS` covers only 80/443. Set `OFFENSIVEX_TEST_DATABASE_URL` to a separate database before running `pytest`, otherwise tests write into the same database the dashboard shows.

## Documentation

Start at [docs/README.md](docs/README.md). Read [docs/Guardrail.md](docs/Guardrail.md) first — it is the binding safety-rules document (authorized use, scope enforcement, sandboxing, AI/agent constraints) that every other document assumes.

## Security and authorization notice

OffensiveX is designed **only** for infrastructure you own, infrastructure you are explicitly authorized in writing to test, or controlled lab/educational environments where testing is permitted. It enforces default-deny scope and requires an approved authorization record before any assessment can run against a target. It performs no destructive, denial-of-service, brute-force, or exploitation actions by default; a narrow, non-destructive validation capability exists only as an explicit per-assessment opt-in. See [docs/Guardrail.md](docs/Guardrail.md) for the complete rules.

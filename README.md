# OffensiveX

> An autonomous, AI-assisted penetration-testing platform for **authorized** security assessments.

**Status: Phase 0 (project foundation) is implemented and verified; every other capability described below is still a design, not a feature.** See [docs/roadmap/current-status.md](docs/roadmap/current-status.md) for the single authoritative "what actually exists" table.

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
| Project foundation (Phase 0) | IMPLEMENTED — app startup, config, logging, error handling, `/healthz`/`/readyz`, DB connectivity + migration mechanism, tests, CI. See below. |
| Assessment/Agent/Tool API, Database schema, Agents, Tool Registry, Sandbox, CLI, Dashboard, Cloud Security | NOT STARTED |

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

## Documentation

Start at [docs/README.md](docs/README.md). Read [docs/Guardrail.md](docs/Guardrail.md) first — it is the binding safety-rules document (authorized use, scope enforcement, sandboxing, AI/agent constraints) that every other document assumes.

## Security and authorization notice

OffensiveX is designed **only** for infrastructure you own, infrastructure you are explicitly authorized in writing to test, or controlled lab/educational environments where testing is permitted. It enforces default-deny scope and requires an approved authorization record before any assessment can run against a target. It performs no destructive, denial-of-service, brute-force, or exploitation actions by default; a narrow, non-destructive validation capability exists only as an explicit per-assessment opt-in. See [docs/Guardrail.md](docs/Guardrail.md) for the complete rules.

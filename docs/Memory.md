# OffensiveX — Durable Memory

This file holds facts that should survive across Claude Code sessions and are **not** already recorded in code, git history, or another doc. It is not a changelog — update entries in place; do not append session-by-session narration here.

## Project identity

**OffensiveX** — an autonomous, AI-assisted penetration-testing platform for authorized security assessments. Orchestrator + seven specialized agents (recon, vulnerability discovery, investigation, validation, attack-graph, risk, reporting) over a sandboxed Tool Registry. Core differentiator: **attack-path intelligence and risk propagation** — a finding is scored by what it lets an attacker reach, not just by isolated severity. Architecturally inspired by Strix (orchestrator → agents → tool abstraction → sandbox); an original implementation, not a fork.

## Pipeline (current)

```
Target → Assessment created → Orchestrator → Recon → Attack Surface → Vulnerability Discovery
       → Investigation → Validation (opt-in) → Evidence → Confirmed Findings
       → Attack Graph → Risk Analysis → Report → Completed Assessment
```

## History: the agent-architecture pivot

The project's **first** documentation pass (same day, earlier in this session) specified a non-agentic, fixed-pipeline modular monolith with a strictly advisory, tool-less LLM. The project owner then redirected it to the agent-based design above (see ADR-021 in `Decision.md`). `PRD.md`, `Architecture.md`, `Design.md`, `Plan.md`, and `Phases.md` at the docs root are **superseded stubs** pointing into the new tree (`docs/architecture/`, `docs/agents/`, `docs/security/`, `docs/data/`, `docs/tools/`, `docs/interfaces/`, `docs/reporting/`, `docs/deployment/`, `docs/roadmap/`). `Guardrail.md` and `Decision.md` were kept and updated in place rather than replaced. The one deliberate rule reversal from the first pass: the LLM/agent layer went from "no tools and no agency" to "bounded agency" (Guardrail §5) — everything else in Guardrail.md carried forward unchanged.

## Directory conventions

`docs/` root: `README.md` (navigation), `Guardrail.md` (binding safety rules — read first), `Decision.md` (ADR log), `Memory.md` (this file), plus the five superseded stubs above. Everything else lives under one of: `architecture/`, `agents/`, `security/`, `data/`, `tools/`, `interfaces/`, `reporting/`, `deployment/`, `roadmap/`. Outside `docs/`: `notebooks/` holds three EXPERIMENTAL ML research notebooks (severity, exploit likelihood, contextual risk) with their own `README.md`; they are not part of the application, and their outputs go to the git-ignored `artifacts/ml-research/`.

## Status vocabulary

`IMPLEMENTED` / `PARTIAL` (= `IN PROGRESS`) / `PLANNED` / `FUTURE` / `NOT STARTED` (zero code, as distinct from `PLANNED` meaning "designed"). `docs/roadmap/current-status.md` is the single authoritative status table — if any other document implies otherwise, that file wins. ADRs use their own vocabulary: `PROPOSED` / `ACCEPTED` / `SUPERSEDED` / `DEPRECATED`. Full definitions in `Guardrail.md §7`.

## Environment (confirmed across three sessions)

Windows 11. Python 3.12.6 (`C:\Users\tpulk\AppData\Local\Programs\Python\Python312\python.exe`), Node 22.12.0 (`D:\Node.js`), Git present; `git init` was run in Phase 0 (no commits made — left for the user). `nmap` and `psql` still **not** installed on the host — recon/scanner tooling and DB access run in containers, not natively on Windows.

**Docker Desktop works on this host as of session 3** (it did not in sessions 1–2). Root cause of the earlier failure: a stale AF_UNIX socket reparse point (`sailor-ingest.sock`, confirmed via `Get-Item` showing `Attributes: ReparsePoint`) left behind under `%LOCALAPPDATA%\Docker\run\` by an earlier abnormal crash — the exact file named in the crash dialog the user screenshotted. **Fix that worked:** stop all `docker`/`com.docker` processes, run `wsl --shutdown` (fully releases the WSL2 utility VM, which is what was still holding the kernel socket object open even with no visible process), then restart Docker Desktop — came up cleanly in ~20s. The stale `.sock`/`.sock.stale` files themselves were never successfully deleted directly (Windows kept refusing with "The file cannot be accessed by the system" even after the process/WSL reset) — but Docker Desktop tolerated them fine on the next clean start regardless, so deleting them turned out to be unnecessary. **If this recurs:** try the process-kill + `wsl --shutdown` + restart sequence before suggesting a full reboot or "Reset to factory defaults" — it resolved a case that looked identical to one needing a reboot.

## Known limitations and assumptions (carry forward, re-check before quoting as fact)

- Phase 0 (project foundation) is **fully verified as of session 3, including Docker**: ruff (lint + format) / mypy / pytest all pass (**27 passed, 0 skipped** — both DB integration tests now run against real PostgreSQL); the app was exercised live both locally and as a built, running, non-root Docker container talking to a real containerized Postgres over the Compose network. Everything from Phase 1 onward is still design only (see `roadmap/current-status.md` → GAP IDENTIFIED).
- Candidate tool choices (Nmap, Nuclei, Semgrep, Trivy, Playwright) are not confirmed integrations and may change once actually implemented.
- The risk-scoring formula's shape is fixed (deterministic, path-aware, versioned, breakdown-explainable); exact weights are not yet finalized.
- No lab/sandbox AWS or other cloud account has been offered by the owner for verification; cloud security (P17) has no confirmed provider yet.
- **LLM:** Anthropic and OpenAI-compatible providers exist behind `llm/base.py` (Track B, ADR-023) and are configured only through `OFFENSIVEX_LLM_*`; the owner supplies the key locally. The OpenAI-compatible provider has been run for real against Gemini (3 `real_llm` tests + one full lab pipeline, 2026-10-14); the Anthropic provider has **never** run against a real endpoint. Real-model evidence is a handful of runs on one small model — don't over-claim. Gemini notes: `gemini-2.5-flash` is 404 for new keys; capacity 503/429s are common; `GET <base_url>/models` lists usable models; a Gemini model with `provider=openai` needs `OFFENSIVEX_LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/`. No model is trained and there is no dataset/notebook (the AI layer is an LLM over deterministic engines).
- **Access control:** local accounts + sessions + RBAC + append-only audit log are implemented (Track A, ADR-012/013/022); there is no default account (create the first admin with `python -m offensivex.admin create-user`). Lessons worth keeping: validation errors must never echo submitted values; any client-supplied header that is stored must be length/charset-bounded; piping text into a Python CLI from Windows PowerShell 5.1 prepends a BOM; PowerShell also mangles inner quotes passed to `curl.exe` (use body files).
- Test isolation: an autouse fixture forces `OFFENSIVEX_LLM_ENABLED=false` for every test; real-model tests are opt-in (`-m real_llm`).

## Phase 0 implementation (project foundation)

Implemented under `backend/` (Python 3.12, FastAPI, SQLAlchemy 2 sync, Alembic, structlog, pydantic-settings — per ADR-002/003/014/017): app factory (`main.py`), config (`core/config.py` — env-based, `OFFENSIVEX_` prefix, fail-fast on weak production secrets, `SecretStr` throughout), structured JSON logging with a redaction processor (`core/logging.py`), centralized problem+json error handling with no internal leakage (`core/errors.py`), `/healthz` + `/readyz` (`api/health.py`), DB engine/session + connectivity check (`db/session.py`, `db/base.py` — no domain models yet, deliberately), Alembic migration mechanism with one no-op baseline revision, an `LLMProvider` Protocol placeholder with no implementation (`llm/base.py`), `docker-compose.yml` + `backend/Dockerfile` (non-root), and `.github/workflows/ci.yml` (runs a real Postgres service container). Test suite: **27/27 tests pass** (config/logging/health/errors unit tests + both DB integration tests, now run against real PostgreSQL). `ruff format --check .`, `ruff check .`, and `mypy src` all clean. Docker build/run/non-root all verified for real.

**Real bugs found and fixed across three verification sessions**, worth remembering for later phases:
1. `create_engine(...)` without an explicit `connect_args={"connect_timeout": N}` can hang far longer than expected when the configured host doesn't cleanly refuse the connection. `db/session.py` and the integration test fixture were fixed first; a later session then found the **same fix was missing from `migrations/env.py`** (the Alembic CLI builds its own engine via `engine_from_config(...)`, a separate code path) — `alembic current` hung past 30s before that was added too. **Lesson: a connect-timeout fix applied to one engine-construction call site does not cover every call site; grep for every `create_engine`/`engine_from_config` call when applying this pattern.**
2. The real worst-case latency is **not** `connect_timeout` — it's `connect_timeout × (number of addresses the hostname resolves to)`. `localhost` resolves to both `::1` and `127.0.0.1` on this host, and psycopg tries each in turn; measured directly: `connect_timeout=3` against an unresponsive target took 6.01s, not 3s. All three call sites now use `connect_timeout=2` (not 5/3) for a tighter, documented bound.
3. `ruff format --check .` had never been run (only `ruff check .` had) — found 5 files not canonically formatted.
4. Running against a *real* database (only possible once Docker worked) surfaced one more: Alembic's `path_separator` deprecation warning — fixed with one line in `alembic.ini` (`path_separator = os`). **Lesson: some bugs only surface once the "unverified" path actually runs — don't assume the gate-keeping fixes (like the connect timeout) were the only things wrong until the real path has executed at least once.**

Live-verified, local and containerized: `/healthz` → 200 in ~0.1s; `/readyz` against a real, containerized Postgres → 200 in 25ms; `/readyz` against an unreachable DB → 503 problem+json in ~4s (not a hang); a 404 → clean problem+json; `alembic upgrade head` against real Postgres → succeeds, `alembic current` → `0001_baseline (head)`; `docker compose exec api whoami` → `offensivex` (uid=1000, confirmed non-root).

## Implementation blueprint (architecture-to-implementation review)

A full consistency review converted the documentation into an implementation-ready blueprint: `roadmap/implementation-blueprint.md` (traceability matrix, assessment flow trace, domain model with 13 entities, agent/tool-registry/event/API/frontend contracts, MVP definition, first vertical slice, P0–P19 phase breakdown) and `roadmap/architecture-risks.md` (12 risks + mitigations). `architecture/implementation-summary.md` is the single developer-facing entry point — read it first, before any phase's code. `roadmap.md` was renumbered in this same pass (P0–P17 → P0–P19, splitting foundation/domain-model and giving the sandbox its own phase) so there is one current phase numbering, not two; every other doc referencing a specific P-number was updated to match.

**Decisions made during the review (not yet separate ADRs — fold into an ADR if/when code commits to them):**
- Fixed a real contradiction: `data/findings.md`'s lifecycle allowed `CONFIRMED` via investigation alone when validation is off ("strongly evidenced"); corrected so **only** the Validation Agent's outcome or an explicit audited analyst override may set `CONFIRMED`/`REJECTED`.
- `RiskAssessment` as a standalone entity overlaps with `Finding`'s inline `risk_score`/`risk_breakdown` fields — default to **inline on `Finding`** for MVP; a history table is deferred until something needs to query score history.
- "Source Analysis" (raised as a possible separate agent) stays a **capability inside the Vulnerability Agent's toolset** (Semgrep/static analysis) — not promoted to an eighth agent; no distinct responsibility justifies the split yet.
- First vertical slice recommendation: a non-intrusive web header/reflection-class finding (not an exploit-grade class), specifically because it validates non-destructively and exercises every lifecycle stage once.

## Network safety (ADR-024, before P15)

Scope is now checked on **host and port**, and connecting adapters validate **every resolved address** and connect to an approved IP literal. Decisions worth remembering: a host-only include rule means ports 80/443 only (never "all ports"); a host-only exclude rule means every port; cloud-metadata addresses are never contacted even with `OFFENSIVEX_ALLOW_PRIVATE_TARGETS` (stricter than the original Guardrail 2.7 text); a mixed public/private DNS answer rejects the whole resolution; a public-looking name that resolves privately needs an explicit `cidr` include rule even in a lab; redirects are reported, never followed; existing authorizations were narrowed (not widened) by migration `0006` and must be re-issued as a new version to cover other ports. Details and limits: `security/network-safety.md`.

## Dashboard and CLI (ADR-025, P15/P16)

- `frontend/` (React + TS + Vite) is built with `npm run build` and served by the backend at `/dashboard`; `offensivex` (`backend/src/offensivex/cli.py`) is a thin HTTP client. Both use the same API, cookie session and CSRF token; `POST /assessments/{id}/run` starts the pipeline in the API process.
- **Run backend tests only against a separate database.** The migration tests drop the schema; set `OFFENSIVEX_TEST_DATABASE_URL` (in `backend/.env`; `tests/conftest.py` applies it to the whole test process). Using the dev DB twice erased the dashboard's accounts and data.
- Gemini: `gemini-2.5-flash` returns 404 for chat on the owner's key although `/models` lists it; `gemini-3.1-flash-lite` works (verified 2026-10-14).
- Dev-DB lab accounts `mvp-admin/analyst/viewer` were created for verification; their passwords live only in a session scratch file. Change or remove them.

## Unresolved questions for the project owner

- Which LLM provider/model to run first for real verification (both an Anthropic and an OpenAI-compatible provider are implemented; neither is verified).
- Confirm whether a lab/sandbox cloud account will be made available for cloud-security verification (Guardrail "VERIFIED" status needs it).
- Confirm whether MCP/external-integration (P19) should stay last, or move up once a specific external consumer is identified.
- Confirm the MVP vertical-slice finding class (header/reflection-class recommended in `roadmap/implementation-blueprint.md §10`) before Phase P8 is implemented.

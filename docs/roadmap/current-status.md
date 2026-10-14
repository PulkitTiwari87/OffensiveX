# Current Status

Status: this document is the single source of truth for "what exists today." If any other document in this repository implies something here contradicts, **this page wins**.

Last updated: 2026-10-14 (Phase 14 — Reporting — JSON + Markdown reports with escaping and grounded-citation checks, verified against real Postgres; AI prose still unexercisable without an LLM provider; see "Phase 14" section below. Phases 0–13 remain verified, see their sections).

## Repository state

Phases 0–7 are implemented under `backend/` and verified end-to-end against a real Postgres instance (plus a real Docker daemon for Phase 4, a real local HTTP server for Phase 6+): FastAPI app factory, centralized config, structured logging, centralized error handling, `/healthz`/`/readyz`, the full 14-table domain schema with its state-machine transition tables, a Target/Authorization/Assessment service layer with a working scope/authorization gate and an orchestrator skeleton, real `/api/v1` routes (Targets, Authorizations, Assessments, Assets), a Tool Registry with a real Scope Guard and two real stdlib-only adapters (DNS resolution, IP-pinned HTTP probing), a containerized Sandbox primitive (not yet wired into an adapter), an agent framework (`AgentSession`) with toolset-membership and typed-output enforcement, a real Recon Agent writing real Asset/Observation rows, a generalized observation normalizer, and an event-log read service — a unit + integration test suite (**174/174 tests passing**, 0 skipped), `docker-compose.yml` + `backend/Dockerfile` (built and run for real, confirmed non-root), and a CI workflow with a real Postgres service container (config validated; not yet triggered in CI itself). **No concrete LLM provider exists yet** — every agent run so far has been driven by a scripted test double, not a real model (queued, see "Access / credentials needed" below). There is still no Vulnerability/Investigation/Validation/Attack-Graph/Risk/Reporting agent, no authentication/RBAC, and no frontend — those are Phase 8 onward. `git` was initialized in Phase 0; no commit has been made yet.

## Component status

| Component | Status | Notes |
|---|---|---|
| Documentation (this tree) | IMPLEMENTED | The architecture, agent, security, data, tools, interfaces, reporting, deployment, and roadmap docs described here exist and reflect the current intended design. |
| Project foundation (Phase 0) | **VERIFIED** | App startup/shutdown, config, logging, error handling, health/readiness, DB connectivity + migration mechanism, test/lint/type-check tooling, CI config, Docker build/run. Acceptance criteria independently checked against a real Postgres and a real built container — see Phase 0 section below. |
| Database / domain model (Phase 1) | **VERIFIED** | All 14 MVP entities from [implementation-blueprint.md §3](implementation-blueprint.md) (`Target`, `Authorization`, `ScopeRule`, `Assessment`, `Asset`, `Observation`, `Finding`, `Evidence`, `AgentRun`, `ToolExecution`, `AttackNode`, `AttackEdge`, `AttackPath`, `Report`), migrated and round-tripped through the ORM against a real Postgres container; explicit state-machine transition tables for Authorization/Assessment/Finding/AgentRun/ToolExecution. |
| Assessment lifecycle (Phase 2) | **VERIFIED** | Target/Authorization services with the ADR-013 target-authorization gate, scope-rule validation (Guardrail.md §2's "scan creation" layer), Assessment creation/cancellation, and an Orchestrator skeleton that schedules the first (`QUEUED`, unexecuted) `AgentRun`. Verified end-to-end over real HTTP against a real Postgres container — see Phase 2 section below. **No authentication/RBAC layer exists yet** (known, documented gap — see Phase 2 section). |
| Frontend / Dashboard | NOT STARTED | No code. See [../interfaces/dashboard.md](../interfaces/dashboard.md) for the plan. |
| Backend / API | PARTIAL | `/healthz`, `/readyz`, Targets, Authorizations, Assessments (Phase 2), `GET /assessments/{id}/assets` (Phase 6), `GET /assessments/{id}/findings` (Phase 8), `GET /findings/{id}` with evidence (Phase 9), `PATCH /findings/{id}/status` analyst override (Phase 10). No Attack-Path/Risk/Reports routes yet (Phase 12+). See [../interfaces/api.md](../interfaces/api.md). |
| Database | **VERIFIED** | Connection, session lifecycle, migration mechanism, the full Phase 1 domain schema, and real service/agent layers (Phases 2, 6) reading/writing `Target`/`Authorization`/`ScopeRule`/`Assessment`/`AgentRun`/`ToolExecution`/`Asset`/`Observation` all exist and are verified against a real Postgres instance (`backend/src/offensivex/db/`, `backend/src/offensivex/services/`, `backend/src/offensivex/agents/`). See [../data/data-model.md](../data/data-model.md). |
| Orchestrator | PARTIAL | Skeleton only: validates scope/authorization, transitions `Assessment` to `running`, and schedules one `QUEUED` `AgentRun` (Phase 2). No stage sequencing, retries, or prioritization yet — those need real agents (Phase 5+). See [../agents/orchestrator.md](../agents/orchestrator.md). |
| Agent framework (runtime for all 7 agents) | PARTIAL (Phase 5) | `AgentSession`: bounded LLM-decision loop, toolset-membership enforcement, typed output contract, writes real `AgentRun`/`ToolExecution` rows. Proven against a scripted provider end-to-end through the real Tool Registry — **no concrete LLM vendor is wired** (no provider chosen, no API key — queued, see below). See Phase 5 section and [../architecture/agent-architecture.md](../architecture/agent-architecture.md). |
| Recon (Phase 6) | PARTIAL | Real `dns_resolution` + new `http_probe` (IP-pinned, stdlib-only) adapters; real Asset/Observation normalization; real `GET /assessments/{id}/assets`. All proven end-to-end against real Postgres + a real local HTTP server. **Agentic decision-making itself is scripted**, not LLM-driven (no provider — same queued gap as Phase 5). See Phase 6 section and [../agents/recon-agent.md](../agents/recon-agent.md), [../security/reconnaissance.md](../security/reconnaissance.md). |
| Vulnerability Discovery (Phase 8) | PARTIAL | Real `security_header_scan` adapter (reuses `HttpProbeAdapter`, the vertical-slice finding class per implementation-blueprint.md §10: missing security headers); real `Finding` writes with dedup/fingerprinting (`(assessment_id, asset_id, source, affected_component)`); real `GET /assessments/{id}/findings`. **Agentic decision-making is scripted** — same queued LLM gap as Phases 5/6. See Phase 8 section and [../agents/vulnerability-agent.md](../agents/vulnerability-agent.md). |
| Investigation (Phase 9) | PARTIAL | Real `run_investigation_agent`: re-checks a `Finding` via the same read-only capability it was discovered with, transitions `DISCOVERED→SUSPECTED→INVESTIGATING` (and back to `SUSPECTED` if no longer reproducible), writes real `Evidence` linked to the re-check's `ToolExecution`. **Cannot** set `CONFIRMED`/`REJECTED` — unrepresentable by its own output schema, not just a convention. Real `GET /findings/{id}` with evidence. **Agentic decision-making is scripted** — same queued LLM gap. See Phase 9 section and [../agents/investigation-agent.md](../agents/investigation-agent.md). |
| Validation (Phase 10) | PARTIAL | Real `security_header_validation_check` (`requires_validation_mode=True`), real Validation Agent moving `INVESTIGATING→CONFIRMED/REJECTED` (the only agentic path to either), the opt-in gate enforced at **two** independent layers (agent-level + Tool Registry), and the explicit analyst-override `PATCH /findings/{id}/status`. **Agentic decision-making is scripted** — same queued LLM gap. See Phase 10 section and [../agents/validation-agent.md](../agents/validation-agent.md). |
| Findings engine (Phase 11) | **VERIFIED** | The complete `DISCOVERED→SUSPECTED→INVESTIGATING→{CONFIRMED,REJECTED}→REPORTED` lifecycle exercised end to end through real service calls; `REPORTED` confirmed terminal; dedup/fingerprinting holds even after a finding is reported (rediscovery bumps `last_seen`, never duplicates); `GET /assessments/{id}/findings?status=` filter. See Phase 11 section and [../data/findings.md](../data/findings.md). |
| Evidence | NOT STARTED | See [../data/evidence-model.md](../data/evidence-model.md). |
| Attack Graph (Phase 12) | **VERIFIED** | Deterministic engine (`build_attack_graph`/`find_attack_paths`) — genuinely no LLM dependency, matching CLAUDE.md's "plain deterministic code" requirement. One curated rule (missing X-Frame-Options → clickjacking-assisted action). Bounded BFS path search; evidence level honestly derived from the causing finding's real status (never fabricated). Real `GET /assessments/{id}/attack-paths`. See Phase 12 section and [../data/attack-graph.md](../data/attack-graph.md). |
| Risk Engine (Phase 13) | **VERIFIED** | `risk_model_v1`: deterministic, no LLM, formula finalized and documented in [../security/risk-analysis.md](../security/risk-analysis.md) (severity × confidence × asset criticality/exposure × attack-graph evidence bonus, clamped 0–10). Golden-value + monotonicity tests; real integration with Phase 12's attack graph (score rises once a finding is actually on a verified edge). `risk_score`/`risk_breakdown` returned inline by `GET /findings/{id}`. See Phase 13 section. |
| Reporting (Phase 14) | PARTIAL | Deterministic report assembly, JSON + Markdown output with untrusted-content escaping, grounded-citation check for an AI executive summary, immutable `Report` snapshots, `POST /assessments/{id}/reports` + `GET /reports/{id}`. **No LLM-authored prose has ever been generated for real** (no provider) — the summary path is proven only against a scripted double, and the HTTP path never produces one. SARIF/PDF not built. See Phase 14 section. |
| Tool Registry (Phase 3) | **VERIFIED** | Adapter contract (`ToolAdapter` Protocol), registry, Scope Guard integration, intrusiveness-ceiling + validation-gate checks, `ToolExecution`-row audit trail. Two real adapters now: DNS resolution and IP-pinned HTTP probing (Phase 6), both stdlib-only, no new dependency. See Phase 3 section below. |
| Docker Sandbox (Phase 4) | **VERIFIED** (standalone) | `ContainerSandbox`: one container per run, non-root, read-only filesystem + writable `/tmp`, `--network none` by default, memory/CPU/PID limits, argv-list-only invocation, a wall-clock timeout that kills the *container* (verified: no orphaned containers after a kill). `FixtureReplaySandbox` for Docker-free tests. **Still not wired into any tool adapter** — both adapters that exist (Phase 3, Phase 6) are stdlib calls, not subprocesses. See Phase 4 section below. |
| Observation / event system (Phase 7) | **VERIFIED** | Generalized `ObservationNormalizer` (capability -> handler registry), extracted from Phase 6's Recon-specific version; an event-log read service (`list_assessment_events`) assembling `assessment.*`/`agent.*`/`tool.*`/`asset.*`/`observation.*` events from existing rows, no new table. Internal only — no public REST route yet (Phase 15's dashboard). See Phase 7 section below and [../data/observations.md](../data/observations.md). |
| CLI | NOT STARTED | See [../interfaces/cli.md](../interfaces/cli.md). |
| Cloud Security | NOT STARTED | Planned direction only; no provider interface exists. See [roadmap.md](roadmap.md) P17. |
| CI/CD | NOT STARTED | See [roadmap.md](roadmap.md) P18. |
| MCP / external integrations | NOT STARTED | Deliberately deferred — see [roadmap.md](roadmap.md) P19. |

## Phase 0 — project foundation (VERIFIED, across three sessions)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| Config (env-based, fail-fast on weak production secrets, SecretStr redaction) | `src/offensivex/core/config.py` | `tests/unit/test_config.py` (9 tests, pass) |
| Structured JSON logging + secret redaction processor | `src/offensivex/core/logging.py` | `tests/unit/test_logging.py` (8 tests, pass); observed directly in both local and **containerized** server logs |
| Centralized problem+json error handling (404/422/500, no internal leakage) | `src/offensivex/core/errors.py` | `tests/unit/test_errors.py` (4 tests, pass); `/healthz`, `/readyz`, and a 404 exercised live via `curl`, both locally and through the running container |
| App factory: CORS, request-ID + logging middleware, exception handlers, `/healthz`, `/readyz`, reserved empty `/api/v1` router | `src/offensivex/main.py`, `src/offensivex/api/health.py` | `tests/unit/test_health.py` (4 tests, pass) + live `curl` against both a local and a containerized run |
| DB engine/session lifecycle + connectivity check, with a bounded connect timeout | `src/offensivex/db/session.py`, `db/base.py` | `tests/integration/test_db_connectivity.py` — **passes against a real PostgreSQL 16 container**; `/readyz` through the containerized API, talking to the containerized database: **200 OK in 25ms** |
| Migration mechanism (one no-op baseline revision), bounded by a connect timeout | `alembic.ini`, `migrations/` | `alembic upgrade head` run for real against a live Postgres container: succeeds, creates `alembic_version`, `alembic current` reports `0001_baseline (head)` |
| `LLMProvider` interface placeholder (no implementation) | `src/offensivex/llm/base.py` | Not directly tested — nothing to test yet; importable, raises `NotImplementedError` if called |
| Docker: API Dockerfile (non-root), Compose (postgres + api) | `backend/Dockerfile`, `docker-compose.yml` | **VERIFIED** — see "Docker verification" below |
| Code quality: ruff (lint + format), mypy, pytest config | `backend/pyproject.toml` | `ruff check .` clean; `ruff format --check .` clean; `mypy src` clean (13 source files) |
| CI skeleton with a real Postgres service container | `.github/workflows/ci.yml` | Config now known-correct (exercises the exact commands just verified manually); the workflow itself has not been triggered by a push/PR |

**Final test results:** `pytest -vv` → **`27 passed, 0 skipped`** in 0.57s, run against a real, containerized PostgreSQL 16 — the two DB integration tests that had skipped in every prior session now genuinely pass.

**Bugs found and fixed across this verification effort** (three real bugs total, all confirmed by direct observation, not assumption):
1. `ruff format --check .` had never been run (only `ruff check .` had) — found 5 files not canonically formatted. Fixed with `ruff format .`.
2. **The Alembic CLI path (`migrations/env.py`) did not use the connect-timeout fix applied to `db/session.py`** — `alembic current` hung past 30s against an unreachable database until the same `connect_args={"connect_timeout": 2}` was added there too. Also discovered *why* the real-world bound is `~2x connect_timeout`: `localhost` resolves to both `::1` and `127.0.0.1` on this host, and psycopg tries each in turn (measured: `connect_timeout=3` against an unresponsive target took 6.01s).
3. Running against a real database surfaced one more: a path-splitting **DeprecationWarning** from Alembic (`No path_separator found`) — fixed by adding `path_separator = os` to `alembic.ini`. Re-verified: warning gone, full suite clean (`27 passed`, 1 unrelated pre-existing warning about `httpx`/`starlette.testclient`).

## Docker verification

```
VERIFIED
```

Docker Desktop was crashing on this host with a stale Unix-socket reparse point (`sailor-ingest.sock`, confirmed via the user's screenshot and independently via `Get-Item` showing `Attributes: ReparsePoint` on an orphaned AF_UNIX socket object). Root cause found and fixed: stopped all Docker-related processes, ran `wsl --shutdown` to fully release the WSL2 utility VM, then restarted Docker Desktop — the daemon came up cleanly (`docker info` reachable in ~20s). From there, the full stack was exercised for real:

- `docker compose config` — resolves correctly (after creating a local `.env` from `.env.example`, the documented first step).
- `docker compose up -d postgres` — container starts and reports `healthy` within seconds.
- `docker compose up -d --build` — the API image **builds successfully** (Python 3.12-slim base, dependencies install cleanly, ~47s cold build) and the container **starts and runs**.
- `docker compose exec api whoami` → `offensivex` (uid=1000) — **confirmed non-root**, not merely asserted.
- `curl http://localhost:8000/healthz` → `200 {"status":"ok"}`; `curl http://localhost:8000/readyz` → `200 {"status":"ok"}` in **25ms**, the containerized API talking to the containerized database over the Compose network, with structured logs (request ID, duration) visible in `docker compose logs api`.
- `alembic upgrade head` run directly against the live container → succeeds; `alembic current` → `0001_baseline (head)`.
- `pytest -m integration` → **2 passed** (both tests that had skipped in every prior session now genuinely pass against real PostgreSQL).
- Containers torn down afterward (`docker compose down`); the data volume was left intact (not force-removed).

Nothing about the original `docker-compose.yml`/`backend/Dockerfile`/CI configuration needed to change to make this work — the earlier "NOT VERIFIED" status was correctly attributed to a host-level Docker Desktop fault, not a defect in this project, and that assessment is now confirmed.

## Phase 1 — database / domain model (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| 14 MVP entities + their enums (ImpactLevel, AuthorizationStatus, ScanMode, AssessmentStatus, AssetType, AssetScopeState, ObservationType, FindingSeverity, FindingStatus, EvidenceKind, AgentType, AgentRunStatus, ScopeDecision, ToolExecutionStatus, AttackRelationship, AttackEdgeCauseType, EvidenceLevel, ReportFormat) | `src/offensivex/db/models.py` | `tests/unit/test_models.py` (metadata/relationship shape checks); `tests/integration/test_domain_schema.py` (full ORM round-trip against real Postgres) |
| Explicit state-machine transition tables (Authorization, Assessment, Finding, AgentRun, ToolExecution) per CLAUDE.md section 8 | `src/offensivex/db/transitions.py` | `tests/unit/test_transitions.py` (37 tests: every valid edge in each lifecycle diagram accepted, every tested invalid edge — including the specific "scanner output alone must never reach CONFIRMED" rule — rejected) |
| Migration creating the full schema (14 tables, 17 Postgres ENUM types, FKs, 2 confidence CHECK constraints, 3 unique constraints) | `migrations/versions/0002_domain_model.py`, `migrations/env.py` (now imports `db.models` to populate `Base.metadata`) | `alembic upgrade head` / `alembic downgrade base` run for real against a live Postgres container — tables and enum types confirmed present after upgrade (`\dt`, `\dT`) and confirmed gone after downgrade (`tests/integration/test_domain_schema.py`) |
| Full-chain ORM write + read-back (Target → Authorization → Assessment → Asset → Observation → Finding → Evidence → AgentRun → ToolExecution → AttackNode → AttackEdge → AttackPath → Report, one row each) | `tests/integration/test_domain_schema.py::test_full_chain_round_trips_through_the_orm` | Passed against real Postgres — exercises every FK and every enum column, not just Python-side assumptions |
| Finding/Observation confidence `CHECK (confidence BETWEEN 0 AND 1)` enforced at the DB layer, not just convention | same file, `test_confidence_check_constraint_is_enforced_by_postgres` | An out-of-range `confidence=1.5` INSERT raises `IntegrityError` for real |

**Final test results:** `pytest -vv` → **`87 passed, 0 skipped`** (the 27 from Phase 0 plus 60 new Phase 1 tests), run against the same real, containerized PostgreSQL 16 used for Phase 0 verification. `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (15 source files).

**One bug found and fixed during this verification:** SQLAlchemy's native `Enum` sends a Python enum member's *name* (e.g. `"MEDIUM"`) to Postgres by default, not its `.value` (`"medium"`) — which does not match the lowercase labels the migration creates. Every enum column in `models.py` now passes `values_callable=lambda e: [m.value for m in e]` (via the `_pg_enum()` helper) so the ORM and the migration agree on-the-wire; caught by the full-chain integration test actually inserting a row, not by unit tests alone.

**Two vocabulary gaps the documentation left open were resolved with the smallest reasonable choice, not silently:** a shared four-tier `ImpactLevel` (LOW/MEDIUM/HIGH/CRITICAL) for Target/Asset criticality and exposure (placeholder pending the Risk Agent's formula, P13), and `AttackPath.edge_ids` as an ordered JSONB array of edge ids rather than a join table (per ADR-003's "relational + in-memory graph library" storage decision — a path is a recomputed query result, not independently mutable state). Both are called out in `models.py`'s module docstring.

**Deliberately not done in Phase 1** (belongs to later phases, per roadmap.md): state-machine transitions for `AgentRun`/`ToolExecution` are defined but not yet wired into any write path that executes anything (Phase 5); `Finding` transitions are defined but nothing produces a `Finding` yet (Phase 8+).

## Phase 2 — assessment lifecycle (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| Scope rule validation (Guardrail.md §2's "scan creation" layer: catch-all/TLD-wildcard rejection, private/loopback/metadata-address rejection unless `OFFENSIVEX_ALLOW_PRIVATE_TARGETS=true`) | `src/offensivex/services/scope.py`, new `Settings.allow_private_targets` | `tests/unit/test_scope.py` (13 tests) |
| Target / Authorization service (create, submit scope, approve, version increment, the ADR-013 approved-unexpired-authorization gate) | `src/offensivex/services/targets.py` | `tests/integration/test_phase2_services.py` against real Postgres |
| Orchestrator skeleton (docs/agents/orchestrator.md step 1 only: schedules one `QUEUED` `AgentRun(agent_type=RECON)` — the "no-op test agent" the roadmap asks for; nothing executes it, by design, since the agent runtime (P5) and the real Recon Agent (P6) don't exist yet) | `src/offensivex/services/orchestrator.py` | same, plus the API-level test below |
| Assessment lifecycle service (create — enforcing the scope/authorization gate, 422 if absent; get; cancel) | `src/offensivex/services/assessments.py` | same |
| `POST /api/v1/targets`, `POST /api/v1/targets/{id}/authorizations`, `POST /api/v1/targets/{id}/authorizations/{v}/approve`, `POST /api/v1/assessments`, `GET /api/v1/assessments/{id}`, `POST /api/v1/assessments/{id}/cancel` | `src/offensivex/api/targets.py`, `src/offensivex/api/assessments.py`, `src/offensivex/api/deps.py`, `main.py` (now wires a `session_factory` and the v1 router) | `tests/integration/test_phase2_api.py` — the full vertical slice (create target → submit auth → approve → create assessment → get → cancel) driven over real HTTP against real Postgres, plus the 422/404/409 error paths |

**Final test results:** `pytest -vv` → **`123 passed, 0 skipped`** (87 from Phases 0–1 plus 36 new Phase 2 tests), against the same real, containerized PostgreSQL 16. `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (23 source files).

**One real bug found and fixed while running the full suite together** (not caught file-by-file): `tests/integration/test_domain_schema.py`'s own migration-mechanism tests downgrade the schema to `base` as part of what they're proving; running the whole integration suite in one pytest session, later files (the new Phase 2 tests) would then find the schema missing depending on collection order. Fixed with `tests/integration/conftest.py`: an autouse fixture that idempotently re-runs `alembic upgrade head` before every integration test, only when a database is actually reachable (never hiding a genuinely unreachable database — that still skips exactly as before, with the same message).

**One documentation contradiction resolved, not silently:** `docs/Decision.md`'s ADR-012/ADR-013 state authentication/RBAC lands "Phase 2," but that predates `docs/roadmap/implementation-blueprint.md`'s later, reconciled Phase 2 scope (section 11's P2 row: Target/Authorization/Assessment services + orchestrator skeleton only — no Auth Service, no `User`/`Session`). Per CLAUDE.md section 22's ambiguity-resolution order (current phase plan over an older ADR), **no authentication/RBAC layer was built in Phase 2.** Every route added this phase is reachable by anyone who can reach the API — same as Phase 0's health endpoints. `approve_authorization` in particular is specified (ADR-013) to require the `admin` role and does not yet enforce that. `backend/src/offensivex/main.py`'s module docstring documents this correction in place. **This is the first queued access/credential gap this project has surfaced** (see "Access/credentials needed" below) — nothing blocks it from being built properly in a dedicated phase.

**Deliberately not done in Phase 2:** anything that requires a real agent (stage sequencing, retries, prioritization, actually running Recon); CIDR-width limits on scope rules (no number is specified anywhere in the documentation — see `services/scope.py`'s docstring); any authentication, session, or RBAC enforcement (see above).

## Access / credentials needed (queued, not blocking)

Nothing encountered so far in Phases 0–2 required any credential, API key, external account, or other access this agent doesn't have. If something is required for a specific future phase, it will be listed here with instructions, rather than stopping mid-phase to ask:

- **LLM provider API key** (blocking real agentic reasoning, confirmed concretely in Phases 5 and 6): no provider is chosen yet (`docs/Memory.md` "Unresolved questions"); once one is, `OFFENSIVEX_LLM_API_KEY`/`OFFENSIVEX_LLM_PROVIDER`/`OFFENSIVEX_LLM_MODEL` will need a real value to exercise any agent for real (the placeholder `LLMProvider` interface raises `NotImplementedError` until then — this is expected, not a bug). Every agent run so far has used a scripted test double standing in for this.
- **A real external scan target** (Phases 8–10, Vulnerability/Investigation/Validation): Phase 6 got through DNS + HTTP probing against a local throwaway HTTP server (no target needed beyond `localhost`), but a real vulnerability scan needs something to actually find a vulnerability *in* — a disposable local container built for testing (Guardrail.md §1's "controlled lab environments"), not a synthetic fixture. Not needed yet; fixture-replay mode (Phase 4) and local servers have covered everything through Phase 6.
- **Cloud provider read-only credentials** (Phase 17, Cloud Security — explicitly P17, late, not MVP): AWS (or whichever provider is chosen) read-only API credentials, scoped per Guardrail.md's "never store cloud credentials in the database" rule.

None of these block Phase 5 (agent framework) up through its non-LLM plumbing — the LLM key is only needed the moment a real agent call is made, not before.

## Phase 3 — Tool Registry (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| Adapter contract (`ToolAdapter` Protocol: `meta`, `plan()`, `run()`, `parse()`), `AdapterMeta`, `ExecutionPlan`, `ParsedResult` | `src/offensivex/tools/registry.py` | `tests/unit/test_registry.py`, `test_dns_adapter.py` |
| Scope Guard (default-deny, exclude-wins, `domain`/`cidr` rule matching, per docs/Guardrail.md §2.2) | `src/offensivex/tools/scope_guard.py` | `tests/unit/test_scope_guard.py` (10 tests) |
| `ToolRegistry.execute()`: intrusiveness ceiling -> validation gate -> Scope Guard -> run -> parse, with a `ToolExecution` row as the audit trail at every step | `src/offensivex/tools/registry.py` | `tests/integration/test_phase3_tool_registry.py` against real Postgres |
| One proof adapter: DNS resolution (stdlib `socket.getaddrinfo`, not the candidate `dnspython` — the stdlib is sufficient for this capability, see the adapter's docstring) | `src/offensivex/tools/adapters/dns_resolution.py` | Real resolution of `"localhost"` (no external network dependency) against the live registry + Postgres |

**Final test results:** `pytest -vv` → **`144 passed, 0 skipped`** (123 from Phases 0–2 plus 21 new Phase 3 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (28 source files).

**One real bug found by mypy, not by a test:** `socket.getaddrinfo`'s `sockaddr` tuple is typed as mixed `str | int` members (it's `(host, port)` for IPv4 and `(host, port, flowinfo, scopeid)` for IPv6) — `sockaddr[0]` needed an explicit type-narrowing assertion before it could key a `dict[str, None]`.

**Two design choices made where the documentation didn't commit to one, and flagged rather than invented silently:**
1. The scan-mode -> intrusiveness-ceiling mapping (quick=passive only, standard=+low, deep=+medium) — no document states this numerically; it's the smallest reading of `docs/agents/orchestrator.md`'s "quick ... non-intrusive capabilities" consistent with scan modes widening. Documented in `registry.py` as subject to confirmation once real scanner intrusiveness ratings exist (Phase 8+).
2. The audit trail is the `ToolExecution` row itself, not a separate hash-chained `AuditLogEntry` table — matching `implementation-blueprint.md` §11's P3 row exactly. A standalone `AuditLogEntry`/Audit Service capability exists in the traceability matrix (§1) with no assigned roadmap phase number — same unscheduled-capability treatment as Authentication (Phase 2's note).

**Deliberately not done in Phase 3** (belongs to Phase 4+): no containerization, no timeout enforcement, no process-tree kill — `ToolRegistry.execute()` calls `adapter.run()` directly, in-process; **toolset membership** (an agent may only request capabilities in its own definition) isn't checked because no agent-definition concept exists yet (Phase 5).

## Phase 4 — Sandbox / execution layer (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| `ContainerSandbox`: one container per `run()` (`--rm`, unique `--name`), non-root, `--read-only` + `/tmp` tmpfs, `--network none` by default, memory/CPU/PID limits, argv-list-only (no shell at either the `docker` CLI layer or inside the container), a wall-clock timeout that `docker kill`s the container itself | `src/offensivex/sandbox/container.py` | `tests/integration/test_phase4_sandbox.py` against a real Docker daemon |
| The proof image: minimal Alpine, non-root `sandbox` user (uid 1000), no `ENTRYPOINT`/`CMD` | `backend/sandbox/Dockerfile` | Built for real this session (`docker build -t offensivex-sandbox:latest backend/sandbox`) |
| `FixtureReplaySandbox` (no Docker required) | `src/offensivex/sandbox/container.py` | `tests/unit/test_fixture_sandbox.py` |

**Final test results:** `pytest -vv` → **`155 passed, 0 skipped`** (144 from Phases 0–3 plus 11 new Phase 4 tests), the sandbox tests run for real against a live Docker daemon (not skipped) — including manually confirming, outside pytest, that a `sleep 30` was killed at 2.2s with exit code 137, and that `docker ps -a` shows no leaked container afterward. `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (30 source files).

**Known, documented limitation (not claimed as solved):** the output-size cap truncates *after* reading stdout/stderr fully into memory, not via a bounded streaming read — docs/tools/sandbox.md's "cannot exhaust host resources" guarantee (e.g. against a decompression-bomb response) is only partially met. Worth revisiting once a real tool adapter (Phase 6+) can actually produce output large enough for it to matter; flagged in `container.py`'s module docstring.

**Deliberately not done in Phase 4** (per implementation-blueprint.md §11's P4 row: "none new" DB/API/agent): not wired into any tool adapter yet — the only adapter that exists (DNS resolution, Phase 3) is a stdlib call, not a subprocess, so there is nothing for it to containerize. This becomes the execution primitive real tool adapters (Nmap, Nuclei, ...) call starting Phase 6+. Network egress restricted to *approved* destinations specifically (vs. just "off by default") is also not implemented — doing that precisely (vs. a blanket `--network none`) needs a real per-destination network policy mechanism, which is premature before any adapter needs network access at all.

## Phase 5 — agent framework (VERIFIED, with one unresolved dependency)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| `AgentSession`: bounded LLM-decision loop (`AgentStep`: `call_tool` or `finish`), toolset-membership enforcement (refuses an out-of-definition capability *before* the Tool Registry is consulted), typed output contract (`finish`'s output validated against the agent definition's Pydantic schema), real `AgentRun` status transitions via Phase 1's `assert_valid_transition` | `src/offensivex/agents/runtime.py` | `tests/unit/test_agent_runtime.py` (4 tests, scripted provider, no DB) |
| `AgentDefinition` + the Phase 5 proof instance `RECON_PROOF_DEFINITION` (toolset = `{"dns_resolution"}`, the one adapter that exists) | `src/offensivex/agents/definition.py` | same, plus the integration test below |
| Full loop, for real: a scripted agent calls the real `dns_resolution` capability through the real Phase 3 `ToolRegistry`, then finishes with a typed output — against real Postgres | `tests/integration/test_phase5_agent_runtime.py` | Passed against real Postgres; the resulting `ToolExecution` row is linked to the `AgentRun` by `agent_run_id`, proving the audit trail actually connects agent → tool call |

**Final test results:** `pytest -vv` → **`160 passed, 0 skipped`** (155 from Phases 0–4 plus 5 new Phase 5 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (33 source files).

**What is explicitly NOT verified, and why — the queued access item from Phase 2 becomes concrete here:** no concrete `LLMProvider` (Anthropic/OpenAI/Gemini/local — vendor still undecided, `docs/Memory.md`) has been implemented or called. `AgentSession` is proven against a scripted test double that implements the same `LLMProvider.generate_structured()` protocol a real one would — the framework's *mechanics* (toolset enforcement, output contract, AgentRun lifecycle, real tool-call audit linkage) are genuinely verified; a real agent making a real LLM-driven decision is not, and cannot be, without an API key. Per Guardrail.md §7's tool/provider vocabulary, the framework itself is **VERIFIED**; any concrete provider remains **PLANNED**. This is still queued, not blocking: Phase 6 (the real Recon Agent) is the first phase that actually needs a real decision from a real model.

**Deliberately not done in Phase 5** (per implementation-blueprint.md §11's P5 row: "none new" DB/API, agent column only "applies framework to simplest agent (Recon)"): no real Recon Agent (full toolset, full prompt from docs/agents/recon-agent.md) — `RECON_PROOF_DEFINITION` is a deliberately minimal stand-in; that is Phase 6. The Sandbox (Phase 4) still isn't wired into anything — `dns_resolution` is still a stdlib call, not a subprocess.

## Phase 6 — Recon Agent (mechanics VERIFIED; agentic reasoning not yet possible)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| `http_probe` adapter: IP-pinned (resolve once, connect to the pinned address, TLS hostname verification independent of which address was actually dialed — Guardrail.md §2.8), stdlib-only (`socket`/`ssl`, not `httpx`), with a real multi-address fallback bug found and fixed this phase (see below) | `src/offensivex/tools/adapters/http_probe.py` | `tests/unit/test_http_probe_adapter.py` (plan/parse, no network) + a real local HTTP server in the integration test |
| The real Recon Agent definition (`dns_resolution` + `http_probe` toolset, the real prompt drawn from docs/agents/recon-agent.md) and the DNS/HTTP-probe -> Asset/Observation normalizer | `src/offensivex/agents/recon.py` | `tests/integration/test_phase6_recon_agent.py` against real Postgres + a real local HTTP server |
| `GET /api/v1/assessments/{id}/assets` | `src/offensivex/api/assets.py`, `src/offensivex/services/assets.py` | Same integration test, read back through a real `TestClient` call |
| `ParsedResult.tool_execution_id` (Phase 3's dataclass, extended) — lets a normalizer point an `Observation.tool_execution_id` FK at the exact call that produced it | `src/offensivex/tools/registry.py` | Same test: asserts every Observation's `tool_execution_id` is set |

**Final test results:** `pytest -vv` → **`169 passed, 0 skipped`** (160 from Phases 0–5 plus 9 new Phase 6 tests), including a real scope-escape test (the scripted agent requesting a destination outside the assessment's authorized scope is refused by the Scope Guard exactly as a human-triggered call would be, and the `AgentRun` is marked `FAILED` with zero `Asset` rows written). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (37 source files).

**One real bug found and fixed while manually verifying `http_probe` against a real server:** the adapter originally connected only to the *first* resolved address; on this dual-stack host `"localhost"` resolves to `["::1", "127.0.0.1"]` and the test server (bound to `127.0.0.1` only) was unreachable over `::1`, so the very first manual run failed with `ConnectionRefusedError`. Fixed by trying each resolved address in order and falling back, while still pinning whichever one actually connects (not re-resolving mid-request). A real-world client with broken IPv6 connectivity to an otherwise-fine dual-stack host would have hit exactly this.

**What is explicitly NOT verified, carried over from Phase 5 and now concretely blocking a further claim:** the Recon Agent's *decisions* (which host to resolve, when to probe HTTP, when to stop) are still scripted, not produced by a real LLM — no provider is wired (same queued gap). Everything **around** that decision — the real adapters, the real Scope Guard enforcement, the real Asset/Observation writes, the real API read-back — is genuinely proven; the one thing that makes this "the Recon Agent" rather than "a recon pipeline" (an LLM actually choosing what to do next) is not yet exercisable.

**Deliberately not done in Phase 6** (per implementation-blueprint.md §11's MVP recon scope, section 9): no TCP port/service discovery, no subdomain enumeration — "DNS + HTTP probing" only, which is explicitly sufficient to prove the chain. Redirects are reported, not followed (see `http_probe.py`'s docstring on per-hop scope re-checking). The tool->Observation normalization here is Recon-specific, not yet generalized into the agent-agnostic normalizer + event log that Phase 7 ("Observation / event system") formalizes.

## Phase 7 — Observation / event system (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| Generalized `ObservationNormalizer` (capability -> handler registry) + `get_or_create_asset`/`write_observation`, extracted from Phase 6's Recon-specific version | `src/offensivex/observations/normalizer.py` | `tests/unit/test_normalizer.py` (dispatch mechanics); `tests/integration/test_phase6_recon_agent.py` now runs through this refactored path unchanged (same assertions, still passing) |
| `recon.py` refactored to register its two handlers on the normalizer instead of hardcoding dispatch | `src/offensivex/agents/recon.py` | same |
| The event log: `list_assessment_events()` assembles `assessment.*`/`agent.*`/`tool.*`/`asset.*`/`observation.*` events (implementation-blueprint.md §6) from the existing `Assessment`/`AgentRun`/`ToolExecution`/`Asset`/`Observation` rows — no new table, per that section's own MVP note ("every event ... is first implemented as a persisted row") | `src/offensivex/services/events.py` | `tests/integration/test_phase7_events.py` against real Postgres: every expected event type present with the right count, and the whole feed verified chronologically sorted |

**Final test results:** `pytest -vv` → **`174 passed, 0 skipped`** (169 from Phases 0–6 plus 5 new Phase 7 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (40 source files).

**One stale doc bullet corrected while editing this section:** this GAP list previously still carried a "No sandbox exists" line dated from before Phase 4 landed — removed; see the Phase 4 section for what actually exists.

**Deliberately not done in Phase 7** (per implementation-blueprint.md §11's P7 row: API surface is "event query (internal)" only): no public REST endpoint for the event feed — that is Phase 15's Agent Activity dashboard view's job, once there is a dashboard to call it. The event log is a read-side query over existing rows, not a new persistence mechanism — real-time push (SSE/WebSocket) is explicitly deferred (section 6: "no event ... is real-time required for correctness, only for UX polish").

## Phase 8 — Vulnerability Discovery (mechanics VERIFIED; agentic reasoning not yet possible)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| `security_header_scan` adapter — the implementation-blueprint.md §10 vertical-slice finding class (missing security headers), built by composing `HttpProbeAdapter` rather than a second HTTP client | `src/offensivex/tools/adapters/security_header_scan.py` | `tests/unit/test_security_header_adapter.py` (4 tests, no network) + a real local HTTP server in the integration test |
| The real Vulnerability Agent definition + normalizer (tool result -> `Finding(status=DISCOVERED)`, one per missing header) | `src/offensivex/agents/vulnerability.py` | `tests/integration/test_phase8_vulnerability_agent.py` against real Postgres + a real local HTTP server |
| Finding dedup/fingerprinting: `get_or_create_finding()`, keyed on `(assessment_id, asset_id, source, affected_component)` | `src/offensivex/observations/normalizer.py` | Same test: running the identical scan twice produces exactly 3 `Finding` rows both times (not 6), with `last_seen` advancing and `first_seen` unchanged |
| `GET /api/v1/assessments/{id}/findings` | `src/offensivex/api/findings.py`, `src/offensivex/services/findings.py` | Same test, read back through a real `TestClient` call |

**Final test results:** `pytest -vv` → **`180 passed, 0 skipped`** (174 from Phases 0–7 plus 6 new Phase 8 tests), including a real negative case (a server that sets all three checked headers produces zero findings — the scanner doesn't fabricate a finding when there's nothing to report, per Guardrail.md §3). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (44 source files).

**Deliberately not done in Phase 8** (per implementation-blueprint.md §10: "a single non-intrusive web-scanner check," not "all four candidates" in docs/tools/scanners.md): no Nuclei/Semgrep/Trivy integration — one finding class only, by design, to prove the chain before widening scanner breadth. Severity is a fixed `MEDIUM` placeholder (no CVSS applies to a configuration-hardening gap) pending the Risk Agent's real taxonomy (Phase 13). The agent's *decisions* (which endpoint to scan, when to stop) are still scripted, same queued LLM gap as Phases 5–7.

## Phase 9 — Investigation (mechanics VERIFIED; agentic reasoning not yet possible)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| The real Investigation Agent: one `AgentRun` per `Finding` (per docs/agents/orchestrator.md point 4), re-runs `security_header_scan`, writes `Evidence` (not another `Observation` — this is a re-check, not a new discovery) | `src/offensivex/agents/investigation.py` | `tests/integration/test_phase9_investigation_agent.py` against real Postgres + real local HTTP servers |
| `DISCOVERED→SUSPECTED→INVESTIGATING` transitions, and the "inconclusive" path back to `SUSPECTED` when the condition is no longer reproducible | same | Two real scenarios: condition still present (→`INVESTIGATING`) and condition fixed since discovery (→`SUSPECTED`), both exercised against real servers |
| `GET /api/v1/findings/{id}` with its evidence list | `src/offensivex/api/findings.py` (`detail_router`), `src/offensivex/services/findings.py` (`get_finding`) | Same test, read back through a real `TestClient` call |

**Final test results:** `pytest -vv` → **`183 passed, 0 skipped`** (180 from Phases 0–8 plus 3 new Phase 9 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (45 source files).

**Security constraint verified structurally, not just by convention:** docs/agents/investigation-agent.md says the agent can never set `CONFIRMED`/`REJECTED`. `InvestigationAgentOutput` has exactly two fields (`still_present`, `notes`) — there is no field path by which this agent's output could carry a `CONFIRMED`/`REJECTED` status, and `run_investigation_agent` never calls `assert_valid_transition` toward either. A test asserts the schema's field set directly, so a future edit that quietly added such a field would fail it immediately.

**Deliberately not done in Phase 9**: multi-observation correlation (the DISCOVERED -> SUSPECTED step is instantaneous here because Phase 8's vulnerability class is already one-observation-per-finding; a scanner producing multiple raw signals for one real finding would need real correlation logic, not built yet — no finding class requires it so far). The agent's *decisions* are still scripted, same queued LLM gap as every prior agent phase.

## Phase 10 — Validation + Evidence (mechanics VERIFIED; agentic reasoning not yet possible)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| The one registered non-destructive validation check (`security_header_validation_check`, `requires_validation_mode=True`), composing `SecurityHeaderScanAdapter` rather than reimplementing the request | `src/offensivex/tools/adapters/security_header_validation.py` | `tests/integration/test_phase10_validation_agent.py` against real Postgres + real local HTTP servers |
| The real Validation Agent: `INVESTIGATING→CONFIRMED`/`REJECTED`, or unchanged on `unresolved`; writes `Evidence(kind=VALIDATION_RESULT)` | `src/offensivex/agents/validation.py` | Same test: all three outcomes exercised for real |
| The opt-in gate, enforced at **two independent layers**: `run_validation_agent` itself refuses to start, and separately, the Phase 3 Tool Registry's `requires_validation_mode` check refuses the capability directly, bypassing the agent entirely | same | Two separate tests prove each layer independently — the second specifically to show neither is a single point of failure for this safety property |
| `PATCH /api/v1/findings/{id}/status` — the explicit analyst override (the only other path to `CONFIRMED`/`REJECTED`, per docs/data/findings.md) | `src/offensivex/api/findings.py`, `src/offensivex/services/findings.py` (`override_finding_status`) | Same test: a valid override (DISCOVERED-chain finding stuck at `INVESTIGATING`→`rejected`) succeeds; an invalid one (`DISCOVERED`→`confirmed`, skipping the state machine) returns a clean 422 |

**Final test results:** `pytest -vv` → **`190 passed, 0 skipped`** (183 from Phases 0–9 plus 7 new Phase 10 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (47 source files).

**One real bug found and fixed while building the analyst-override endpoint:** `offensivex.db.transitions.InvalidTransitionError` is a plain `ValueError`, not an `OffensiveXError` (deliberately, so the transitions module stays usable with no DB/HTTP dependency — Phase 1's design). No API route had ever actually hit an invalid transition through the HTTP layer until this phase's negative test did, and it would have surfaced as an opaque 500, not a clean 422. Fixed with a new `invalid_transition_handler` registered in `main.py` — this also silently fixes the same latent gap for Phase 2's `approve_authorization`/`cancel_assessment` routes, which had the identical exposure and were never exercised against an already-terminal state through the API in their own tests.

**Deliberately not done in Phase 10**: no `AuditLogEntry`/who-did-this trail for the analyst override (no auth/user model exists — same Phase 2 gap, documented in `services/findings.py`'s docstring rather than silently assumed). The agent's *decisions* are still scripted, same queued LLM gap as every prior agent phase.

## Phase 11 — Findings Engine (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| `mark_finding_reported` — the last previously-unreachable edge in the state machine (`{CONFIRMED,REJECTED,INVESTIGATING,SUSPECTED}→REPORTED`); stands in for the Reporting Agent (Phase 14), which doesn't exist yet | `src/offensivex/services/findings.py` | `tests/integration/test_phase11_findings_engine.py` against real Postgres |
| `status` query filter on `GET /assessments/{id}/findings` — implementation-blueprint.md §11's P11 row, "status filters finalized" | `src/offensivex/api/findings.py`, `services/findings.py` (`list_findings`) | Same test, via a real `TestClient` call |

**Final test results:** `pytest -vv` → **`194 passed, 0 skipped`** (190 from Phases 0–10 plus 4 new Phase 11 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (47 source files).

**One test bug caught and fixed while writing this phase's own tests** (not a code bug): a dedup test tried to mark a freshly-`DISCOVERED` finding `REPORTED` directly — correctly rejected by the state machine built in Phase 1 (`'discovered' -> 'reported' is not a valid transition`). Fixed the test, not the code; the rejection was the system working as designed, not a surprise.

**"Analyst triage" scoped deliberately, not left silently vague:** docs/data/findings.md's "What's new since the pre-agent design" section mentions an analyst-facing triage dimension (accept-risk, mark-fixed) from the original pre-pivot design, but no current document commits this to a concrete field, enum, or endpoint for the MVP — `docs/data/findings.md`'s own canonical field list (the one this repository's schema was built against, Phase 1) does not include one. Per CLAUDE.md section 22 (smallest reasonable decision over inventing one), "analyst triage" for this phase is satisfied by the two mechanisms that already exist and are concretely specified: the Phase 10 `PATCH /findings/{id}/status` override and this phase's status filtering. Adding a dedicated triage-status field/table is deferred until a document actually specifies its shape.

**Deliberately not done in Phase 11**: no new finding-class-specific dedup logic beyond the `(assessment_id, asset_id, source, affected_component)` key from Phase 8 — no finding class built so far needs anything finer-grained. A finer fingerprint (e.g. incorporating a normalized request signature for classes with many near-duplicate variants) is additive, not blocking, and not built speculatively ahead of a class that needs it.

## Phase 12 — Attack Graph (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| The curated rule set (exactly one rule: missing `X-Frame-Options` → `clickjacking_assisted_action`, `EXPLOITS` relationship) and the evidence-level mapping (`CONFIRMED→verified`, well-evidenced `SUSPECTED`/`INVESTIGATING→potential`, everything else→no edge) | `src/offensivex/attack_graph/engine.py` | `tests/unit/test_attack_graph_rules.py` (6 tests, no DB) |
| `build_attack_graph()` — deterministic, idempotent `AttackNode`/`AttackEdge` construction from existing `Finding` rows | same | `tests/integration/test_phase12_attack_graph.py` against real Postgres |
| `find_attack_paths()` — bounded BFS from every entry node, replacing (not appending to) prior `AttackPath` rows each pass, with a path's evidence level correctly computed as its weakest edge | same | Same test |
| `GET /api/v1/assessments/{id}/attack-paths` | `src/offensivex/api/attack_graph.py`, `services/attack_graph.py` | Same test, via a real `TestClient` call |

**Final test results:** `pytest -vv` → **`204 passed, 0 skipped`** (194 from Phases 0–11 plus 10 new Phase 12 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (51 source files).

**No LLM dependency at all in this phase** — unlike every agent phase since Phase 5, this is genuinely, verifiably deterministic code (per CLAUDE.md section 2 and docs/agents/attack-graph-agent.md), so there is nothing queued or scripted here; the "no concrete LLM provider" gap does not apply to this phase's own functionality.

**Deliberately minimal, not an oversight:** only one curated rule exists, for the one finding class (`X-Frame-Options`) with a plausible, honestly-describable escalation — the other two checked headers (`Strict-Transport-Security`, `X-Content-Type-Options`) correctly produce **no** edge, verified by a dedicated negative test, because this project has not built a rule connecting them to reachable access yet (per docs/roadmap/architecture-risks.md risk #9: rules are added when a finding/asset class justifies one, never speculatively). No rule here ever produces `observed` or `inferred` evidence levels — this engine has no real asset-relationship data (e.g. IAM trust edges) to derive those from; claiming otherwise would be fabrication (Guardrail.md §3).

## Phase 13 — Risk Engine (VERIFIED)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| The finalized `risk_model_v1` formula, documented with its exact weights in [../security/risk-analysis.md](../security/risk-analysis.md) (ADR-019 updated to point here rather than at the superseded, now-contentless `Architecture.md` it originally cited) | `docs/security/risk-analysis.md`, `docs/Decision.md` | — (documentation) |
| `compute_risk`/`score_finding`/`score_assessment_findings` | `src/offensivex/risk/engine.py` | `tests/unit/test_risk_engine.py` (10 tests: one golden value, six monotonicity properties, clamping, weakest-edge selection, unknown-flagging) |
| Real integration with Phase 12's attack graph: the identical finding scores strictly higher once `build_attack_graph` actually puts it on a `verified` edge | same | `tests/integration/test_phase13_risk_engine.py` against real Postgres |
| `risk_score`/`risk_breakdown` returned inline by `GET /findings/{id}` | `src/offensivex/api/findings.py` | Same test, via a real `TestClient` call |

**Final test results:** `pytest -vv` → **`217 passed, 0 skipped`** (204 from Phases 0–12 plus 13 new Phase 13 tests). `ruff check .` clean, `ruff format --check .` clean, `mypy src` clean (53 source files).

**No LLM dependency at all in this phase either** — same as Phase 12, this is genuinely deterministic (docs/security/risk-analysis.md section "Deterministic by design"; CLAUDE.md section 2). The "no concrete LLM provider" gap does not apply here.

**One documentation correction made while finalizing the formula:** ADR-019 pointed to "Architecture §11" for the concrete weights, but the pre-pivot `Architecture.md` was gutted to a redirect stub (ADR-021) before any numbers were ever written there — the formula was never actually recoverable from this repository. Fixed by making risk-analysis.md the sole source of truth for the weights and correcting ADR-019's pointer, rather than silently leaving a dead reference.

**Deliberately deferred, not faked (named explicitly in risk-analysis.md's "Factors deferred to a later version"):** exploitability (no exploit-prediction/KEV data source), blast radius/downstream impact beyond one hop (Phase 12's graph has only one rule — no real multi-hop chains exist to measure), and sensitive-data exposure (no asset carries a "holds sensitive data" flag in the schema). Each gets a neutral default, flagged in `risk_breakdown.unknowns_defaulted`, rather than a guessed non-neutral value — guessing would be exactly the overclaiming Guardrail.md §3 forbids.

## Phase 14 — Reporting (mechanics VERIFIED; AI prose not yet possible)

What exists, concretely, under `backend/`:

| Area | Files | Verified by |
|---|---|---|
| `build_report_data` (Scope, Attack Surface, Findings, Confirmed Vulnerabilities, Evidence, Attack Paths, Risk Analysis, Remediation, Technical Appendix — all straight from stored rows), `render_markdown` (escapes every untrusted string; evidence excerpts rendered as indented code blocks so they cannot break out), `build_report` (marks included findings `REPORTED`, persists an immutable `Report`) | `src/offensivex/reporting/builder.py` | `tests/unit/test_report_builder.py` (6 tests), `tests/integration/test_phase14_reporting.py` (4 tests, real Postgres) |
| Grounded executive summary: every cited evidence ID must exist in the report, else `UngroundedCitationError` (422); output always `ai_generated: True` and labeled in Markdown | same | Unit tests, against a scripted provider only |
| `content_json`/`content_markdown` columns on `reports` | `migrations/versions/0003_report_content.py`, `db/models.py` | Applied by the integration suite's autouse `alembic upgrade head` |
| `POST /api/v1/assessments/{id}/reports` (optional `formats`), `GET /api/v1/reports/{id}`; regenerating creates a new report | `src/offensivex/api/reports.py`, `services/reports.py`, `main.py` | Integration test over real HTTP: round trip, new-report-per-generation, markdown-only, 404s |

**Final test results:** `pytest` → **`227 passed, 0 skipped`**. `ruff check .`, `ruff format --check .`, `mypy src` (57 files) clean.

**Deliberately not done / honest limits:** the HTTP path never passes an LLM provider, so no report from the API has an executive summary (`provenance.ai_generated_executive_summary` is `false`); no separate "Reporting Agent" `AgentRun` is created (assembly is a service function — there is no LLM decision loop to wrap yet); Technologies section omitted (no fingerprinting capability); remediation is one fixed sentence per header class, not LLM prose; SARIF/PDF are not built; generating a report mutates finding status to `REPORTED` as a side effect (Phase 11's terminal edge), so a second report over the same assessment still lists those findings but they are already terminal.

## GAP IDENTIFIED

- **Phases 0–14 exist now (project foundation, domain schema, assessment lifecycle, Tool Registry, Sandbox, agent framework, Recon + Vulnerability + Investigation + Validation mechanics, the observation/event system, the findings engine, the attack graph, the risk engine, reporting); everything from Phase 15 onward (dashboard, CLI, cloud security) is still design only, not code.** Treat every diagram, API table, and CLI example in those areas as a specification, not evidence of functionality.
- **No concrete LLM provider exists** — every agent run so far (Recon, Vulnerability, Investigation, Validation) has been driven by a scripted test double, never a real model. This is the sharpest edge of the "queued access" item first flagged in Phase 2, and it blocks a genuine "the agent decided X" claim for every agent built so far, not just the framework in the abstract.
- **No authentication/RBAC exists** — every route is unauthenticated, including the analyst-override `PATCH` added this phase; see the Phase 2 section above for why this was deferred rather than silently skipped.
- **The Sandbox isn't wired into anything yet** — every adapter so far (DNS resolution, HTTP probe, security header scan/validation) is a direct stdlib call, not a subprocess, so there is still nothing for the Phase 4 sandbox primitive to containerize. This becomes relevant the moment a capability that spawns a real tool subprocess (Nmap, Nuclei, ...) is added.
- **No `AuditLogEntry` exists** — the analyst override and every agent action are traceable through `AgentRun`/`ToolExecution`/`Evidence` rows, but there is no dedicated, hash-chained audit log (an unscheduled capability, same treatment as Authentication).
- **The specific scanners/libraries named in [../tools/tool-registry.md](../tools/tool-registry.md) and [../tools/scanners.md](../tools/scanners.md) (Nmap, Nuclei, Semgrep, Trivy, Playwright) are candidate choices, not confirmed integrations.** They may change when each is actually implemented and tested.
- **The risk-scoring formula is not yet finalized** — [../security/risk-analysis.md](../security/risk-analysis.md) commits to the model's shape (deterministic, path-aware, versioned) but not to final weights.
- **The CI workflow itself has not been triggered** — its configuration is now known-correct (it runs exactly the commands just verified manually, against the same kind of Postgres service container), but no push/PR has exercised it in GitHub Actions.
- **No Phase 0 gaps remain otherwise.** Docker, Postgres, migrations, and the full local test suite are all genuinely verified, not assumed.

## Implementation readiness

A full architecture-to-implementation consistency review has been completed: [implementation-blueprint.md](implementation-blueprint.md) (traceability matrix, assessment flow trace, domain model, agent/tool-registry/event/API/frontend contracts, MVP definition, first vertical slice, phase breakdown) and [architecture-risks.md](architecture-risks.md) (12 identified risks with mitigations). One documentation contradiction was found and fixed during the review: [../data/findings.md](../data/findings.md)'s lifecycle diagram previously allowed an investigated-but-unvalidated finding to reach `CONFIRMED` ("strongly evidenced"); it now correctly matches [../agents/investigation-agent.md](../agents/investigation-agent.md) and [../agents/validation-agent.md](../agents/validation-agent.md): only the Validation Agent's checked outcome, or an explicit audited analyst override, may set `CONFIRMED`/`REJECTED`. The repository remains documentation-only; this review did not add or require any code.

## Relationship to the previous (pre-pivot) documentation

`docs/PRD.md`, `docs/Architecture.md`, `docs/Design.md`, `docs/Plan.md`, and `docs/Phases.md` describe an earlier, non-agentic direction and are marked superseded in place, with a pointer to this tree. `docs/Guardrail.md` and `docs/Decision.md` were kept and updated (see ADR-021 in [../Decision.md](../Decision.md)) because the safety rules and decision history both carry forward.

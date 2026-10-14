# OffensiveX — Architecture Decision Records

All ADRs are `PROPOSED` until the project owner approves the documentation set; then they become `ACCEPTED`. ADR status values: `PROPOSED`, `ACCEPTED`, `SUPERSEDED`, `DEPRECATED` (ADR-018).

Selection principle: **boring, maintainable technology unless a more complex choice is justified by a stated requirement.** Version numbers are intentionally omitted; the version of each dependency is pinned in the phase that introduces it.

Index

| ADR | Topic |
|---|---|
| 001 | Frontend framework |
| 002 | Backend framework |
| 003 | Database |
| 004 | Background jobs |
| 005 | Queue / cache |
| 006 | Tool execution architecture |
| 007 | Scanner adapter architecture |
| 008 | Cloud provider strategy |
| 009 | ML architecture |
| 010 | LLM abstraction |
| 011 | Attack graph representation |
| 012 | Authentication |
| 013 | Authorization |
| 014 | Observability |
| 015 | Testing |
| 016 | Deployment |
| 017 | Configuration & secrets |
| 018 | Status vocabulary |
| 019 | Risk scoring model |
| 020 | Scope enforcement |
| 021 | Agent-based execution architecture (pivot) |

---

# ADR-001

## Decision
Frontend: **React + TypeScript (strict) + Vite**, React Router, TanStack Query (server state) and TanStack Table, Tailwind CSS, Cytoscape.js for graphs. Types for the API client are generated from the backend OpenAPI schema.

## Context
The UI is an authenticated, data-dense analyst tool: large tables, filters, detail drawers, a graph view. It does not need SEO or server-side rendering. The developer already has Node 22.

## Alternatives
- Next.js (SSR/RSC): extra server runtime and complexity with no SSR requirement.
- Vue/Svelte: capable, but smaller ecosystem for data-grid and graph components; no advantage here.
- Server-rendered templates (Jinja + HTMX): simpler, but graph interaction and dense filtered tables would be awkward.

## Reasoning
A static SPA served by the API (or any static host) is the smallest deployable unit. TanStack Table/Query solve the exact hard parts (sorting/filtering/caching). Cytoscape.js is a mature graph library with layout algorithms and styling suited to evidence-level edge encoding. Generating types from OpenAPI keeps frontend and backend contracts in sync.

## Trade-offs
SPA means client-side routing and an API-only backend (fine). Tailwind couples styling to markup. Cytoscape's canvas rendering needs explicit accessibility work (a tabular path view is provided as an alternative).

## Consequences
Frontend lives in `frontend/`; built to static assets. No SSR concerns. Accessibility of the graph is a design requirement (see Design.md).

## Status
PROPOSED

---

# ADR-002

## Decision
Backend: **Python 3.12 + FastAPI**, Pydantic v2, SQLAlchemy 2 (**synchronous** sessions) + Alembic, psycopg 3. Layered modules: `api` → `services` → `db`/engines/adapters. Route handlers contain no business logic.

## Context
Domain is Python-friendly (subprocess tool orchestration, parsing, graph analysis, LLM SDKs, boto3). Python 3.12 is installed locally. Workloads are I/O- and subprocess-bound, not CPU-bound web traffic.

## Alternatives
- Django/DRF: batteries-included, but heavier; its ORM/admin add little here, and OpenAPI generation is weaker.
- Flask: lighter, but no built-in request validation/OpenAPI.
- Go/Node backend: weaker fit for the ML/LLM/boto3 ecosystem.
- Async SQLAlchemy: more concurrency but harder debugging and testing.

## Reasoning
FastAPI + Pydantic gives validated schemas and OpenAPI for free (feeds ADR-001's client generation). Sync SQLAlchemy keeps transactions and debugging simple; FastAPI runs sync handlers in a threadpool, which is adequate for MVP load. Long work runs in worker processes, not request handlers.

## Trade-offs
Sync handlers cap per-process concurrency; scale-out is by more processes. If measurements later demand async, services are isolated enough to migrate.

## Consequences
One `pyproject.toml`; `ruff` + `mypy` + `pytest`. Workers are a separate entrypoint of the same package.

## Status
PROPOSED

---

# ADR-003

## Decision
**PostgreSQL only.** Relational tables for everything, including the asset graph (`asset_relationships`) and persisted attack paths. JSONB for tool-specific attributes. No separate graph, document, or search database.

## Context
Requirements: durable transactional metadata; findings with relations to assets/evidence/scans; filtering/search; graph of assets with at most thousands of nodes per target; reproducibility and audit.

## Alternatives
- Neo4j / graph DB: natural for path queries, but adds an operational dependency; path search here is bounded and in-memory.
- MongoDB / document store: flexible, but weak for relational integrity and joins.
- SQLite: simple, but poor concurrent-writer story for workers (`SKIP LOCKED` queue) and weaker JSON/search.
- Elasticsearch: only justified by search scale that does not exist.

## Reasoning
The graph is small and bounded; storing edges as rows and loading a target's subgraph into memory (networkx) for path search is simple and fast enough. Postgres also provides the job queue (ADR-004/005), JSONB, full-text search (`tsvector`), and constraints that enforce data integrity.

## Trade-offs
Deep graph queries in SQL are awkward — so none are done in SQL. If graphs grow to hundreds of thousands of nodes, revisit (new ADR) with measurements.

## Consequences
Single storage technology to back up and secure. Migrations via Alembic. Integration tests need a real Postgres (docker compose).

## Status
PROPOSED

---

# ADR-004

## Decision
Background jobs: **Postgres-backed job table processed by separate worker processes** (`python -m offensivex.worker`). A job is claimed with `SELECT … FOR UPDATE SKIP LOCKED`, carries a lease (`lease_expires_at`) and bounded `attempts`. Scan pipeline steps are idempotent.

## Context
Scans run for minutes, drive subprocesses, must be cancellable, and must survive worker crashes without duplicating results.

## Alternatives
- Celery (+ Redis/RabbitMQ): mature, but adds a broker and a large operational surface.
- RQ/Arq (Redis): lighter, still needs Redis.
- FastAPI `BackgroundTasks`: tied to the web process; no durability or cancellation.
- Temporal etc.: far beyond MVP needs.

## Reasoning
The queue's durability, transactionality (enqueue in the same transaction as the scan row), and visibility come free with Postgres, which is already required. Expected throughput is low (scans, not millions of jobs).

## Trade-offs
Polling instead of push (short poll interval, optional `LISTEN/NOTIFY` later). Less tooling than Celery. We own lease/retry logic — kept small and heavily tested.

## Consequences
Phase 4 builds and tests the queue. Delivery is **at-least-once**; handlers must be idempotent. Retries are bounded; exhausted jobs fail visibly.

## Status
PROPOSED

---

# ADR-005

## Decision
**No separate queue or cache** in MVP. No Redis. Rate limiting and caching use in-process structures or Postgres where needed.

## Context
Redis is commonly added reflexively. Concrete needs: a job queue (ADR-004), API rate limiting, short-lived caches.

## Alternatives
Redis for queue/cache/rate limits; Memcached; Kafka/RabbitMQ.

## Reasoning
Single-process-per-role deployment at MVP scale does not need a distributed cache. API rate limiting is for auth endpoints and can be per-process. Fewer moving parts = fewer failure modes and a smaller attack surface.

## Trade-offs
Per-process rate limits are not globally exact with multiple API replicas. Acceptable for MVP; revisit if multiple replicas are deployed.

## Consequences
Postgres is the only stateful service. Adding Redis later requires a new ADR with a measured justification.

## Status
PROPOSED

---

# ADR-006

## Decision
Tool execution goes through one **Execution Engine** that: receives an `ExecutionPlan` from an adapter, validates every declared destination against the scope (ADR-020), pins resolved IPs, runs the tool as a **subprocess with an argv list (never a shell)**, enforces timeout, output-size cap, scrubbed environment, and process-tree termination, stores raw output as a content-addressed artifact, and returns it for parsing. In production, tools run **inside the worker container**.

## Context
Security tools are external binaries (Nmap, Nuclei). `nmap` is not installed on the developer's Windows machine; Docker is. Subprocess handling differs across OSes (process-tree kill).

## Alternatives
- Call tools directly from adapters (no shared engine): duplicates safety logic, easy to forget a check.
- Run each tool in its own ephemeral container: stronger isolation, but needs Docker-in-Docker/socket access — a bigger attack surface and more complexity.
- Library bindings (python-nmap etc.): thin wrappers over the same binaries, still need the binary.

## Reasoning
A single choke point makes scope enforcement, rate caps, timeouts, and auditing impossible to bypass accidentally. The worker image bundles the pinned tool binaries, giving Linux semantics everywhere; Windows developers use docker compose or fixture-replay mode.

## Trade-offs
All tools share the worker container's privileges (mitigated by non-root user, dropped capabilities, and egress restrictions in Phase 16). Native Windows execution of tools is unsupported.

## Consequences
`OFFENSIVEX_TOOL_FIXTURE_MODE` replays recorded outputs for development/CI. Tool binaries are versioned in the worker image and recorded in provenance.

## Status
PROPOSED

---

# ADR-007

## Decision
**Adapter interface** per tool: `plan(request) → ExecutionPlan`, `parse(raw_artifact) → ParsedResult`, plus static metadata (`name`, `version_probe`, `capabilities`, `intrusiveness`, `status`). The orchestrator depends only on the interface. A **Normalizer** converts `ParsedResult` into canonical assets/relationships/findings/evidence. Adapters are registered in a simple in-code registry (no plugin framework).

## Context
The product must not be coupled to one CLI tool; tools change output formats; each tool's integration status must be honest (`MOCKED` vs `IMPLEMENTED`).

## Alternatives
- Hard-code Nmap/Nuclei calls into services: fastest, but couples the product to them.
- Dynamic plugin discovery (entry points): flexible but speculative (YAGNI).

## Reasoning
Interface + registry gives replaceability with minimal machinery. Parsers are pure functions testable from recorded fixtures. Intrusiveness metadata lets the engine refuse adapters above the scan's profile.

## Trade-offs
Adding a tool requires a code change and release (acceptable).

## Consequences
Each adapter carries an integration status (Guardrail §7) shown in the UI settings page. MVP adapters: `dns`, `http_probe`, `nmap`, `web_baseline`, `nuclei`, plus the AWS cloud provider (ADR-008).

## Status
PROPOSED

---

# ADR-008

## Decision
Cloud security via a **`CloudProvider` interface**; **AWS is the only MVP provider**. Access is **read-only via an assumed role** (role ARN + external ID stored; no access keys stored). Check families in MVP: S3, network exposure (security groups/public instances), IAM subset. Azure/GCP are `PLANNED`, `FUTURE`.

## Context
Cloud security is a primary focus, but three providers would triple the surface and verification cost. AWS has the most mature tooling (boto3, `moto` for tests).

## Alternatives
- All three providers in MVP: breadth over depth, unverifiable without three accounts.
- Wrap an existing cloud scanner (e.g. Prowler/ScoutSuite) as an adapter: faster coverage, but heavier dependency and less control over normalization — may be reconsidered as an optional adapter later.

## Reasoning
Depth on one provider with a clean interface demonstrates the architecture; the interface test suite (contract tests) makes adding Azure/GCP mechanical.

## Trade-offs
MVP users on Azure/GCP get no cloud coverage. Verification against real AWS requires the owner to supply a sandbox account (open question).

## Consequences
Credentials come from the environment/role at runtime, never the DB or UI. A read-only IAM policy document ships with the docs. Until a real-account run, AWS status is `MOCKED`.

## Status
PROPOSED

---

# ADR-009

## Decision
**No ML model ships in the MVP critical path.** The "Analysis Engine" ML slot is a reserved, **optional** interface (`Predictor`) with no implementation until (a) analyst-labeled data exists and (b) an offline evaluation shows a model beats the deterministic risk engine. Candidate first uses: false-positive likelihood from analyst feedback; anomaly detection on scan-to-scan diffs.

## Context
The project's "AI" focus is delivered in the MVP by the LLM analysis layer plus deterministic engines. There is no labeled dataset. Training on public data and calling the result "prioritization" would be unverifiable.

## Alternatives
- Train a CVSS/EPSS-based classifier now: reproduces existing public scores; adds no information.
- Use an LLM as a "model" for scoring: violates Guardrail §5.

## Reasoning
"Do not add ML just for the sake of saying the project uses ML." The honest path collects feedback now (statuses, reasons) so a later model has data.

## Trade-offs
The project's ML story is weaker at MVP. Mitigated by designing feedback capture (FR-VUL-06) and keeping the interface ready.

## Consequences
`ml/` is not created until a phase needs it. This is an **open question** for the owner (is ML a required headline?).

## Status
PROPOSED

---

# ADR-010

## Decision
**`LLMProvider` interface** (`generate_structured(prompt, schema, params) → ProviderResult`) with providers: `FakeProvider` (deterministic, tests/offline) and `GeminiProvider` (`OPTIONAL`). The rest of the app depends only on the interface. A **Context Builder** assembles evidence-ID-bearing structured input; a **Grounding Validator** checks output; an **Analysis Service** orchestrates both. Provider/model names come from configuration — none hard-coded.

## Context
Requirement: vendor independence; hallucination controls; degraded operation; data-egress control.

## Alternatives
- Call a vendor SDK directly in services: simplest, locks in vendor.
- LangChain/agent frameworks: large dependency, hides prompts, and agentic loops conflict with "LLM has no agency".

## Reasoning
A thin interface plus our own validation keeps control of prompts and safety. Structured output (JSON schema) lets us validate mechanically.

## Trade-offs
We write a small amount of provider glue. Provider-specific features (tool calling, long context) are deliberately unused.

## Consequences
LLM features are off by default (`OFFENSIVEX_LLM_ENABLED=false`); per-target consent for external providers; all calls audit-logged. Gemini remains `MOCKED` until run with a real key.

## Status
PROPOSED

---

# ADR-011

## Decision
Attack graph: **nodes = (asset, access level)**; **edges** carry `cause` (finding or relationship), `rule_id`, and `evidence_level ∈ {observed, inferred, potential, verified}`. Edges come from (a) observed relationships and (b) a **curated, versioned rule set** mapping finding classes (CWE/tags) to access gained. The graph is **computed in memory (networkx)** from assets/relationships/findings; only resulting **paths** are persisted. Path search is bounded (max depth, max paths).

## Context
The graph must answer "if an attacker reaches X, what could they reach next?" without implying proof of exploitation.

## Alternatives
- Asset-only graph (no access levels): cannot express privilege progression.
- Graph DB: see ADR-003.
- ML/LLM-generated paths: unverifiable; violates grounding principles.

## Reasoning
(asset, access) nodes are the standard attack-graph formulation and make evidence labeling per edge natural. Rule-based edges are explainable and testable. Persisting only paths avoids duplicating relational state.

## Trade-offs
The rule set must be curated and will be incomplete; "no path found" never means "safe" (stated in UI/reports). Path enumeration is bounded, so some long paths are not shown.

## Consequences
Phase 9 delivers rules file + validator. Path evidence level = weakest edge on the path. `verified` is set only by analyst action in MVP.

## Status
PROPOSED

---

# ADR-012

## Decision
Authentication: **local accounts**, passwords hashed with **argon2id**, **server-side sessions** stored in Postgres, delivered as `HttpOnly; Secure; SameSite=Strict` cookies, with CSRF protection for state-changing requests. First admin created via CLI. SSO/OIDC and API tokens are `FUTURE`.

## Context
Single-organization MVP, browser SPA, no existing identity provider assumed.

## Alternatives
- JWT in localStorage: XSS-exfiltratable; revocation is awkward.
- JWT access + rotating refresh cookie: more code for the same outcome.
- OIDC only: forces an IdP dependency for every developer.

## Reasoning
Server-side sessions are boring, revocable, and avoid token storage in JS. Postgres-backed sessions need no cache (ADR-005).

## Trade-offs
Session lookup per request (indexed; negligible). Cookie auth needs CSRF handling and same-site deployment of UI and API (served from one origin).

## Consequences
Phase 2 implements auth + CSRF; Phase 16 adds rate limiting/lockout. Cookie flags relax only in explicit `development` mode.

**Implemented (Track A, after Phase 14):** exactly as decided — argon2id (`argon2-cffi`), Postgres sessions storing only the SHA-256 of the token, `HttpOnly; SameSite=Strict` cookie (`Secure` outside development/test), a per-session synchronizer CSRF token in `X-CSRF-Token`, first admin via `python -m offensivex.admin create-user`. Two deliberate deviations/additions: (1) a small login throttle (5 failures/username/15 min → 429, counted from the audit log) was pulled forward from Phase 16 because shipping password login with no brute-force limit was not acceptable; Phase 16 still owns IP-level rate limiting. (2) Wildcard CORS origins are rejected at startup because the API is cookie-authenticated. See [security/access-control.md](security/access-control.md).

## Status
ACCEPTED

---

# ADR-013

## Decision
Authorization has two layers. **(1) RBAC:** roles `admin` (everything incl. user management, scope approval), `analyst` (create targets/scans, triage findings, run analysis, generate reports), `viewer` (read-only). **(2) Target authorization:** a scan may run only against a target whose authorization is `approved`, unexpired, and not revoked, with a non-empty valid scope. Scope approval requires `admin`; self-approval is allowed only if `OFFENSIVEX_ALLOW_SELF_APPROVAL=true` (default false; intended for single-user lab setups).

## Context
Two different questions: "may this *user* do this?" and "may this *system* touch this *target*?" Conflating them leads to unsafe shortcuts.

## Alternatives
- Fine-grained per-resource ACLs/ABAC: not justified for a single org.
- Four-eyes approval always: safer, but blocks solo lab use; kept as config.

## Reasoning
Simple role checks in a FastAPI dependency plus a dedicated, heavily tested target-authorization gate satisfies the safety requirement without a policy engine.

## Trade-offs
Roles are coarse. Per-target ownership/ACLs are `FUTURE`.

## Consequences
An authorization-matrix test enumerates every endpoint × role (Phase 16). The target-authorization gate sits in the scan service **and** the execution engine (defense in depth).

**Implemented (Track A):** the matrix test ships now (`tests/integration/test_auth_rbac_audit.py`), not in Phase 16: every route is classified, an inventory test fails on any unclassified route, and each role is exercised against each. The model's output is never an authorization input — it is not given the user's identity or role, and tool calls are validated against the agent's toolset and the Scope Guard independently. Self-approval is tracked via `authorizations.submitted_by_id`/`decided_by_id`.

## Status
ACCEPTED

---

# ADR-014

## Decision
Observability: **structlog JSON logs** with correlation IDs (`request_id`, `scan_id`, `job_id`); `/healthz` (liveness) and `/readyz` (DB reachable, migrations current); per-scan step logs stored in the DB and shown in UI; a **Prometheus-format `/metrics`** endpoint added in Phase 16. OpenTelemetry tracing is `FUTURE`.

## Context
Need to debug distributed-ish scan runs, audit, and (later) operate the service. Logs must never contain secrets or raw evidence bodies.

## Alternatives
Full OTel from day one; ELK/Loki stack; plain `logging`.

## Reasoning
Structured logs with IDs give 90% of the value for MVP at minimal cost. Metrics come once there is something worth measuring.

## Trade-offs
No distributed tracing; no bundled log/metrics backend.

## Consequences
A log-redaction test is part of Phase 16. The audit log (ADR-020/Architecture §8) is separate from operational logs.

## Status
PROPOSED

---

# ADR-015

## Decision
Testing pyramid: **unit** (pure logic: scope, risk, graph, grounding, parsers, state machines) → **integration** (API + real Postgres via docker compose; worker/queue; migrations) → **E2E** (full pipeline in fixture mode in CI; real-tool run against a local lab target). Tools: pytest, hypothesis (scope validator only), moto (AWS), Vitest + Testing Library, Playwright. Negative tests are mandatory for safety-critical code. Coverage gates apply to safety modules (scope ≥ 95% branch).

## Context
A security tool with a wrong scope check is worse than no tool. LLM and tool outputs are nondeterministic or external.

## Alternatives
Mock the database (faster, hides SQL/locking bugs); skip E2E (misses integration); snapshot-only testing.

## Reasoning
Real Postgres is cheap with Docker and is required to test `SKIP LOCKED` queue behavior. Fixture replay + fake LLM makes E2E deterministic.

## Trade-offs
Integration tests need Docker running. hypothesis is a dev-only dependency, justified solely by scope-validator fuzzing.

## Consequences
CI runs lint, type check, unit, integration (Postgres service), and fixture-mode E2E. Lab-target runs are a separate, explicitly-triggered job that promotes `MOCKED` → `VERIFIED`.

## Status
PROPOSED

---

# ADR-016

## Decision
Deployment: **Docker Compose** (`api`, `worker`, `postgres`; frontend built to static assets served by the API or a minimal static server). Separate `lab` compose profile for deliberately vulnerable targets bound to loopback only. No Kubernetes, no service mesh. Containers: non-root, minimal capabilities, read-only root filesystem where feasible; egress restriction guidance for the worker.

## Context
Single-organization MVP; developer machine runs Docker Desktop; portfolio demonstrability matters.

## Alternatives
Kubernetes/Helm; PaaS (Render/Vercel); bare-metal scripts.

## Reasoning
Compose is reproducible, reviewable, and sufficient. PaaS hosting would put an active-scanning tool on shared infrastructure — undesirable, and may violate hosting provider policies.

## Trade-offs
No built-in HA or autoscaling. Hosted multi-user deployment is out of scope until a hardening review.

## Consequences
Hosted deployment is **not** a goal. Documentation includes a "running this safely" section.

## Status
PROPOSED

---

# ADR-017

## Decision
Configuration via **environment variables** parsed by pydantic-settings (`OFFENSIVEX_` prefix), validated at startup (fail fast). `.env` for local development only (git-ignored); `.env.example` committed with placeholders only. No secrets in the database. Cloud credentials come from the AWS credential chain/role at runtime. Secrets are never logged; settings objects redact secret fields in `repr`.

## Context
Guardrail: never hardcode or expose credentials. Different needs per environment (`development`, `test`, `production`).

## Alternatives
YAML config files with secrets; a secrets manager (Vault/SSM) from day one.

## Reasoning
Environment variables are the lowest-common-denominator, 12-factor approach and work with Docker secrets/compose. A secrets manager can be layered later without changing the application.

## Trade-offs
Env vars are visible to the process and `docker inspect`; production guidance recommends Docker/OS secrets mounted as files for the session secret and LLM key (supported via `*_FILE` variants).

## Consequences
Startup refuses to run in `production` with default/empty secret key or insecure cookie settings. Planned variable list lives in Memory.md.

## Status
PROPOSED

---

# ADR-018

## Decision
**One unified status vocabulary** (defined in Guardrail §7). Work items: `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `TESTED`, `VERIFIED`, `BLOCKED`, `DEPRECATED`. Integrations additionally use `MOCKED` in the lifecycle and carry tags `OPTIONAL` and `FUTURE`. `DONE` is never used. ADR status is separate (`PROPOSED`/`ACCEPTED`/`SUPERSEDED`/`DEPRECATED`).

## Context
The initial project brief specified three overlapping status lists: one for development (`PLANNED … VERIFIED/BLOCKED/DEPRECATED`), one for tool integrations (`PLANNED/IMPLEMENTED/MOCKED/OPTIONAL/FUTURE`), and one in the guardrail section (`PLANNED/MOCKED/IMPLEMENTED/VERIFIED/DEPRECATED`). They conflict on meaning (e.g. `IMPLEMENTED` before/after `TESTED`; `OPTIONAL`/`FUTURE` are not lifecycle states).

## Alternatives
Keep three vocabularies (confusing); drop `MOCKED` (hides important honesty about unverified integrations).

## Reasoning
Lifecycle states and orthogonal tags remove ambiguity: `OPTIONAL` and `FUTURE` describe *scope*, not progress. `MOCKED` is retained because it is the honest state for fixture-only integrations.

## Trade-offs
Slightly longer definition; lifecycle for integrations differs a little from work items (adds `MOCKED`).

## Consequences
All docs, UI labels (Settings → Integrations), and code comments use this vocabulary. Reconciliation is reported to the owner in the session summary.

## Status
PROPOSED

---

# ADR-019

## Decision
Risk score v1 is a **project-defined, transparent, weighted heuristic**, explicitly **not scientifically validated**. It is deterministic, versioned (`risk_model_v1`), configurable by weights, and stored with a component breakdown. When an input is unknown, a documented neutral default is used and the breakdown flags it.

**Finalized, Phase 13:** the concrete weights (severity/confidence/asset-criticality/asset-exposure/attack-graph-evidence multipliers) are fixed in [../security/risk-analysis.md](../security/risk-analysis.md)'s "`risk_model_v1` (finalized, Phase 13)" section — the formula referenced here as "Architecture §11" lived in the superseded pre-pivot `Architecture.md`, which was gutted to a redirect stub (ADR-021) before any concrete numbers were ever recorded there; risk-analysis.md is now the sole source of truth for the actual weights, not this ADR.

## Context
Users need one sortable number, but there is no validated formula that combines scanner severity with environment context. CVSS alone ignores exposure and asset value; EPSS/KEV ignore environment.

## Alternatives
Use CVSS only (simple, context-blind); use an ML model (no labels; ADR-009); let the LLM score (non-deterministic; Guardrail §5).

## Reasoning
A transparent weighted sum with a confidence multiplier is easy to explain and test, and its breakdown prevents "black box" prioritization. Honest labeling avoids over-claiming.

## Trade-offs
Weights are judgment calls; two teams may want different weights (hence configuration + versioning). Heuristic scores can mislead if unknowns dominate — the breakdown surfaces this.

## Consequences
Golden-value tests with hand-computed expected scores; monotonicity property tests; re-scoring job when inputs change; reports print the model version and the "heuristic, not validated" note.

## Status
PROPOSED

---

# ADR-020

## Decision
**Scope enforcement is a single, pure, default-deny `ScopeGuard`** used at four layers: (1) scan creation/preflight, (2) execution-plan validation for every tool invocation (with DNS pinning), (3) discovered-asset handling (`out_of_scope` assets are recorded, never scanned), (4) parsed-output filtering. Failures **fail closed**. Every decision (allow or deny, with rule ID) is audit-logged. The audit log is **hash-chained** (tamper-evident).

## Context
OffensiveX is an active-scanning platform. The worst failure mode is touching a system the operator was not authorized to touch, or doing so unaccountably.

## Alternatives
Check scope only at scan creation (misses redirects, DNS changes, discovered assets); rely on tool-native scope flags (inconsistent across tools); network-level egress filtering only (necessary but coarse, added in Phase 16 as an additional layer).

## Reasoning
Defense in depth with a single implementation avoids divergent logic; purity makes it exhaustively testable (including fuzzing). Hash-chaining is cheap and makes after-the-fact tampering detectable.

## Trade-offs
Some legitimate recon (e.g. following a redirect to a partner domain) is refused unless scoped. A hash chain proves tampering only if the chain head is retained elsewhere; external anchoring is `FUTURE`.

## Consequences
Scope module has the strictest test bar (≥95% branch coverage, negative and property tests). Adapters cannot reach the network except via the Execution Engine (HTTP probe included — it uses an engine-provided pinned-IP client).

## Status
PROPOSED

---

# ADR-021

## Decision
OffensiveX adopts an **agent-based execution architecture**: an orchestrator schedules seven specialized agents (recon, vulnerability discovery, investigation, validation, attack-graph, risk, reporting), each with a narrow toolset called through a single **Tool Registry**, itself sandboxed and scope-checked. The project's stated core differentiator becomes **attack-path intelligence and risk propagation** (not "we also have an LLM"). The architecture is **inspired by** the public architecture of projects such as Strix (orchestrator → specialized agents → tool abstraction → sandboxed execution); OffensiveX is an original implementation, does not reuse Strix code/prompts/branding, and is not described as a clone. This supersedes the "fixed deterministic pipeline + purely advisory, tool-less LLM" shape recorded in the original `docs/Architecture.md`/`docs/Design.md` (now superseded documents; see `docs/roadmap/` for the current tree).

## Context
The original design (ADR-002 through ADR-016) built a correct, safe, but rigid pipeline: fixed steps, fixed tool list per step, an LLM that could only explain and recommend over data the pipeline already produced (ADR-010; Guardrail §5 as originally written: "no tools and no agency"). That design cannot adapt its next recon/investigation action to what the last tool call actually returned, which is exactly the judgment-heavy work a human pentester does well and a fixed pipeline does poorly. The project owner has redirected OffensiveX toward an autonomous, agent-driven model, using Strix's publicly known architecture as a reference benchmark, while keeping attack-path/risk-propagation analysis — already present in the original design as one engine among several (ADR-011, ADR-019) — as the product's headline capability rather than a secondary feature.

## Alternatives
- **Keep the fixed pipeline, add more LLM "explain" calls at more steps:** does not address the core gap (no adaptive investigation) and risks the project reading as "an AI feature bolted onto a scanner" rather than an autonomous assessment platform.
- **Give agents unrestricted tool access ("full autonomy"):** rejected — directly violates the project's authorized-use and safety guardrails (Guardrail §1–§4); an agent's speed is exactly why its blast radius must stay bounded.
- **Copy Strix's architecture and terminology directly:** rejected per explicit project direction — OffensiveX must remain an original project with its own data model, risk logic, and attack-graph engine; Strix is a reference point, not a template to clone.

## Reasoning
Specialized agents over one tool abstraction, sandboxed and scope-checked, give the adaptability a fixed pipeline lacks while keeping every one of the original safety guarantees (default-deny scope, no-shell/argv-only execution, audit trail, non-destructive-by-default) intact — because those guarantees live in the Tool Registry/Scope Guard/Sandbox layer, which every agent must pass through regardless of what it "decided." Keeping the Attack Graph and Risk Agents **deterministic, non-agentic engines** (not LLM calls) preserves score reproducibility, which is non-negotiable for a report an operator will act on.

## Trade-offs
More moving parts than a fixed pipeline (seven agent definitions instead of one step list); agent behavior is less predictable turn-to-turn than a fixed step, which raises the bar on toolset-scoping, intrusiveness ceilings, and audit logging (addressed in `architecture/execution-model.md` and `architecture/security-boundary.md`). The project must be disciplined about not quietly over-claiming "autonomous" behavior where a stage is actually deterministic (attack graph, risk) — documents in `docs/agents/` say so explicitly per agent.

## Consequences
- `docs/Guardrail.md §5` rewritten from "no agency" to "bounded agency" (the one deliberate rule reversal from the original design — recorded there, not silently).
- `docs/PRD.md`, `docs/Architecture.md`, `docs/Design.md`, `docs/Plan.md`, `docs/Phases.md` marked superseded in place; their content is replaced by `docs/architecture/`, `docs/agents/`, `docs/security/`, `docs/data/`, `docs/tools/`, `docs/interfaces/`, `docs/reporting/`, `docs/deployment/`, `docs/roadmap/`.
- Validation (any state-changing/active-confirmation action) becomes an explicit, narrowly-scoped, opt-in agent capability (`agents/validation-agent.md`, `security/validation.md`) rather than something the original design excluded from MVP entirely — this is a scope **addition**, made consciously and bounded by the same non-destructive-by-default rule as everything else.
- `docs/roadmap/roadmap.md` replaces `docs/Phases.md`'s phase order with one built around the agent/tool-registry/observation model, with cloud security and CI/CD pushed later and MCP/external integrations deliberately last (P19 as of the implementation-blueprint renumbering; P17 at the time this ADR was written).

## Status
ACCEPTED

---

# ADR-022

## Decision
Security-relevant actions are recorded in a persistent, **append-only `audit_log` table**. A successful sensitive action writes its audit row **in the same transaction** as the change (`audit.record`); a denial or failure writes its row in a **separate, immediately-committed transaction** (`audit.record_independent`) so it survives the request's rollback. Append-only is enforced by the database (a trigger rejects `UPDATE`, `DELETE` and `TRUNCATE`), not just by the absence of an API route. `details` is scrubbed of secret-looking keys and truncated.

## Context
ADR-013 and `data/findings.md` require "audited" analyst overrides and scope approvals; until now the only trail was `AgentRun`/`ToolExecution`/`Evidence` rows, which say nothing about *who* did an administrative action or who was *refused*.

## Alternatives
- A hash-chained log (tamper-evident, like the original design's idea): stronger against a malicious DBA, but a hash chain serialises writers and needs a verifier; deferred. The trigger protects against the application and API users, which is the realistic threat for this stage.
- Audit rows only for successes: loses exactly the events (denials, failed logins) an investigator wants.
- Writing denial rows in the request transaction: they would roll back with the failed request.

## Reasoning
Same-transaction success rows can never describe a change that did not happen, nor miss one that did. Independent denial rows cannot be erased by the failure they record.

## Trade-offs
A database owner/superuser can still drop the trigger — the control is against the application, not against the DBA. Failed-login rows are written for unknown usernames too (needed for the throttle) and are therefore attacker-fillable; a retention policy is future work.

## Consequences
Covered events: `auth.login` (success/failure), `auth.login.throttled`, `auth.logout`, `authz.denied`, `authz.csrf_rejected`, `target.create`, `authorization.submit/approve/reject`, `assessment.create/cancel`, `finding.status_override` (with reason), `report.generate`, `user.create/update/set_password`, `pipeline.run`. Admin-only read API `GET /api/v1/audit-log`. See [security/access-control.md](security/access-control.md).

## Status
ACCEPTED

---

# ADR-023

## Decision
LLM access goes through the `LLMProvider` protocol (`generate_structured(prompt, schema) -> schema instance`); vendor code lives only in `llm/providers/`. A shared base (`llm/structured.py`) gives every provider the same validation, **bounded retries** (1 + `LLM_MAX_RETRIES` attempts, capped backoff, permanent errors not retried), prompt-size and output-token caps, and secret-free logging. Two providers ship: **Anthropic** (official SDK, forced tool use for structured output) and an **OpenAI-compatible** one (httpx; covers OpenAI, Gemini's compatibility endpoint, and local servers). Configuration uses the project's existing `OFFENSIVEX_LLM_*` variables. **The model proposes; deterministic code disposes:** it never writes rows, never sets a status the evidence contradicts, and is never an input to authorization.

## Context
Agents had been proven only against scripted doubles; ADR-010/021 left the vendor open. The risk of a real model is not that it is wrong but that a wrong or manipulated answer silently becomes a finding, a verdict or a report claim.

## Alternatives
- One vendor SDK called from agents directly: couples agents to a vendor and scatters retry/validation logic.
- A framework such as LangChain: a large dependency for one method call.
- Letting the model's `still_present`/`outcome` stand on its own: a model that is wrong or prompt-injected would move findings to CONFIRMED/REJECTED. Rejected — the conclusion must agree with what the tool observed or the run fails.

## Reasoning
The existing runtime already had the right seam (`AgentSession` + a typed `AgentStep`); the work was making the prompt carry real context, fencing untrusted data, cross-checking conclusions against tool results, and making failures loud. No silent fallback exists: an LLM failure fails the agent run (visible in `agent_runs`) or marks the report's `ai_summary` as `failed`.

## Trade-offs
A strict cross-check turns some model mistakes into failed runs instead of quietly "reasonable" results — intended. Prompt-injection defences (fencing, closing-tag neutralisation, size clipping) reduce but cannot eliminate the risk; the hard guarantees are structural (toolset, Scope Guard, deterministic normalizers, state machine, cross-checks), not prompt wording. Neither provider has been exercised against a real endpoint in CI; see `real_llm` tests.

## Consequences
Config validation fails at startup if the LLM is enabled but incomplete. Tests never call a real model (an autouse fixture forces it off); `pytest -m real_llm` is the explicit opt-in. See [architecture/llm-integration.md](architecture/llm-integration.md).

## Status
ACCEPTED

# ADR-024

## Decision
Two enforcement gaps in the Scope Guard are closed. **(1) Port scope:** scope rules gain an optional `ports` list; an include rule without it authorizes the web default ports (80, 443) only, an exclude rule without it excludes every port; the Scope Guard checks host *and* port for every connecting capability. **(2) Connection-time address policy:** a connecting adapter resolves a hostname once, validates every resolved address (`tools/network_guard.py`), connects to an approved IP literal, verifies the peer, and verifies TLS against the original hostname. Cloud-metadata addresses are never contacted; loopback/private/link-local/reserved/multicast/CGNAT addresses need `OFFENSIVEX_ALLOW_PRIVATE_TARGETS` **and** explicit scope coverage of the address. Redirects are reported, not followed. Full rules: [security/network-safety.md](security/network-safety.md).

## Context
The Scope Guard matched hostnames only. A rule `localhost` or `app.example.com` therefore authorized every port, and a public name that resolved (or was rebound) to `127.0.0.1`, `10.x` or `169.254.169.254` was not stopped at runtime: the probe pinned the IP it resolved but never checked it against anything. Guardrail §2.7/§2.8 promised both protections; only the IP-literal and creation-time halves existed. The project owner asked for both to be closed before the dashboard (P15).

## Alternatives
- Keep a host rule meaning "all ports" and add `ports` only as an optional narrowing: rejected — an authorization for a hostname would still silently cover SSH, databases and admin ports, which is the gap being closed.
- Backfill existing rules with `ports = '1-65535'` in the migration to preserve old behaviour: rejected — it would carry the unsafe breadth forward as data and the catch-all is rejected for new rules.
- Backfill existing targets' entry-point ports into their rules: rejected — a migration must not grant access the authorization never named; a new authorization version is the audited way to widen.
- Do a DNS lookup for validation and let an HTTP library connect by name: rejected — that is the check/use gap rebinding exploits; the standard-library `socket`/`ssl` probe already owns the connection, so pinning is exact.
- Follow redirects with per-hop checks: deferred — nothing needs it, and not following is the strictly safer behaviour.
- Reject only the *private* answers of a mixed DNS response and connect to the public ones: rejected — a mixed answer is itself the signature of a rebinding attempt; the whole resolution is refused.

## Reasoning
Port and address are authorization dimensions just as the hostname is, so they belong to the same default-deny, exclude-wins decision and are enforced where every tool passes (the registry, plus the adapter that opens the socket) rather than in an agent. Treating "no `ports`" as the web defaults for includes and as "all ports" for excludes makes every ambiguous legacy rule fail closed in both directions. Metadata addresses are the one class never permitted even with the deployment switch and an explicit rule: no legitimate assessment target is an instance-metadata service, and a rule naming one is far more likely a mistake or an attack. This is stricter than the literal Guardrail §2.7 text (which allowed it with both opt-ins); it strengthens, not weakens, the guardrail.

## Trade-offs
Existing authorizations now cover fewer ports: a target on a non-default port needs a new authorization version before its next assessment (fail-closed, documented, reversible). A lab that maps a public-looking name to a private address needs an explicit `cidr` include rule for it. `dns_resolution` still reports private answers as data. The probe still runs in-process, so there is no network-namespace egress filter underneath; and resolver honesty is out of scope.

## Consequences
Migration `0006_scope_rule_ports` (additive). `ExecutionPlan` gains `ports` and `network`; `ToolRegistry` takes `allow_private_targets`; a policy refusal at connect time is recorded `DENIED` and raised as `ScopeViolationError`. Existing local-lab tests now state their opt-ins explicitly (`ToolRegistry(allow_private_targets=True)` and a `ports` list). See [roadmap/current-status.md](roadmap/current-status.md#network-safety-port-scope-and-dns-pinning-verified-before-p15).

## Status
ACCEPTED


---

# ADR-025

## Decision
The operator interfaces are two clients of the one HTTP API. **CLI:** `offensivex` (`backend/src/offensivex/cli.py`) is a thin `httpx` client; it keeps a session token + CSRF token in an owner-only file and has no privileged path. Only `offensivex admin ...` touches the database directly (bootstrap of the first account). **Dashboard:** React + TypeScript + Vite (ADR-001), built to static files and served by the backend at `/dashboard`, so the browser has a single origin with the API. **Running a pipeline:** `POST /assessments/{id}/run` starts the existing pipeline as a background task of the API process; it returns 202 and clients poll `GET /assessments/{id}`.

## Context
P15/P16 needed a way to start the agent pipeline from a client (until now only `python -m offensivex.admin run-assessment` could), and a decision on how the browser reaches the API under cookie + CSRF authentication.

## Alternatives
- CLI that calls services directly against the database: rejected — it would bypass RBAC, CSRF and audit attribution and duplicate the API's rules.
- Dashboard on its own origin (Vite dev server / separate host) with CORS and credentialed requests: rejected for the default path — more surface (origin allow-list, `SameSite` tuning) for no benefit; `npm run dev` with a proxy remains available for UI work.
- A job queue/worker for assessments: deferred — nothing needs it yet (CLAUDE.md: no future-proofing).
- TanStack Query/Table, Tailwind, Cytoscape from ADR-001: deferred; plain React state, tables and CSS were enough for the MVP. Attack paths are shown as a table, not a drawn graph.

## Reasoning
Both interfaces then inherit authentication, RBAC, CSRF, scope enforcement and audit logging from one place, and a test of the API is a test of both.

## Trade-offs
The pipeline runs inside the API process: a restart mid-run leaves the assessment `running` with no worker (it can be cancelled only before it starts; there is no resume). A double-launch guard is in-process and persisted-state based, so it is not safe across multiple API workers. The pipeline now ends with the deterministic attack-graph and risk step (previously nothing invoked them outside tests).

## Consequences
New routes (see docs/interfaces/api.md), `AgentRun.error` (derived from `output_ref`, no migration), `Settings.dashboard_dir`, the `offensivex` console script. Tests must use a separate database (`OFFENSIVEX_TEST_DATABASE_URL`): the migration tests recreate the schema.

## Status
ACCEPTED

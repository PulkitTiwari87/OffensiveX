# Implementation Blueprint

Status: PLANNED — this document converts the existing documentation set into an implementation-ready blueprint. It does not introduce new architecture; where it appears to add detail (exact field lists, endpoint shapes), that detail is the natural, non-speculative completion of what [architecture/](../architecture/overview.md), [agents/](../agents/orchestrator.md), [data/](../data/data-model.md), and [tools/](../tools/tool-registry.md) already specify. Nothing here is implemented — see [current-status.md](current-status.md).

Related: [architecture-risks.md](architecture-risks.md) · [../architecture/implementation-summary.md](../architecture/implementation-summary.md) · [roadmap.md](roadmap.md)

---

## 1. System Traceability Matrix

Maps every major documented capability to the concrete components that implement it. "Backend" = the service/module owning the logic; "Agent" = the agent (or "—" if the capability is not agentic); "Database" = the entities it reads/writes; "API" = the endpoint group; "Frontend" = the dashboard view; "Tooling" = what it calls through the Tool Registry; "Tests" = the test category that proves it.

| Capability | Backend | Agent | Database | API | Frontend | Tooling | Tests |
|---|---|---|---|---|---|---|---|
| Target & scope management | Target Service, Scope Guard | — | `Target`, `ScopeRule`, `Authorization` | Targets API | Targets view | — | Scope unit tests (≥95% branch), property tests |
| Assessment lifecycle | Orchestrator | — (coordinates all) | `Assessment`, `AgentRun` | Assessment API | Assessment Overview | — | State-machine tests, cancellation tests |
| Reconnaissance | Tool Registry, Recon Agent runtime | Recon Agent | `Asset`, `Observation`, `ToolExecution` | Assets API | Attack Surface view | DNS, port/service discovery, HTTP probe, subdomain enum | Adapter fixture tests, scope-escape tests |
| Vulnerability discovery | Tool Registry, Vulnerability Agent runtime | Vulnerability Agent | `Observation`, `Finding` (`DISCOVERED`) | Findings API | Findings view | Template web scan, dependency/container scan, static analysis | Parser tests, dedupe/fingerprint tests |
| Investigation | Investigation Agent runtime | Investigation Agent | `Finding` (`SUSPECTED→INVESTIGATING`), `Evidence` | Findings API | Finding Details view | Read-only re-checks via Tool Registry | Grounding tests (citation of evidence IDs), lifecycle tests |
| Validation | Validation Agent runtime, per-class check registry | Validation Agent | `Finding` (`→CONFIRMED/REJECTED`), `Evidence` | Findings API (validation sub-resource) | Finding Details view | One pre-reviewed non-destructive check per finding class | Non-destructiveness review, opt-in gating tests |
| Evidence | Evidence Service | — (every agent attaches) | `Evidence`, `ToolExecution` (artifact ref) | Evidence API | Evidence view | — | Content-hash / traceability tests |
| **Attack Path Analysis** | Attack Graph Service | Attack Graph Agent (deterministic engine) | `AttackNode`, `AttackEdge`, `AttackPath` | Attack Path API | Attack Graph view | — | Graph construction tests, bounded-search tests |
| **Risk Analysis** | Risk Engine | Risk Agent (deterministic engine) | `Finding.risk_score/risk_breakdown`, `RiskAssessment` | Risk API (nested under Findings) | Risk view | — | Golden-value tests, monotonicity property tests |
| Reporting | Report Assembler | Reporting Agent | `Report` | Reports API | Reports view | — | Golden-file tests, XSS-escaping tests |
| Dashboard / Agent activity | API read models | — | `AgentRun`, `ToolExecution` | Agents API | Agent Activity view | — | Contract tests against real endpoints |
| Tool execution & sandboxing | Tool Registry, Execution Engine, Sandbox | — (used by all agents) | `ToolExecution` | — (internal) | — | All tool categories | Scope-check tests, no-shell tests, timeout/kill tests |
| Authentication & RBAC | Auth Service | — | `User`, `Session` | Auth API | Login, role-gated UI | — | Authorization-matrix test |
| Audit | Audit Service | — | `AuditLogEntry` (hash-chained) | Audit API (admin) | Settings → Audit view | — | Tamper-detection tests |
| CLI | CLI client | — (thin client over API) | — | Uses Assessment/Reports API | — | — | CLI integration tests against a running API |
| Cloud Security (P15, not MVP) | Cloud Provider interface | Vulnerability Agent (extended) or dedicated check runner | `Asset` (`cloud_resource`), `Finding` | Cloud API (future) | Cloud view (future) | AWS read-only APIs | `moto`-based contract tests |

---

## 2. Complete Assessment Flow Trace

```
USER → ASSESSMENT → ORCHESTRATOR → AGENT TASK → TOOL EXECUTION → OBSERVATION
     → INVESTIGATION → VALIDATION → EVIDENCE → FINDING → ATTACK GRAPH → RISK → REPORT
```

| Transition | Input | Output | Responsible component | DB entity touched | Event / state change | Failure condition |
|---|---|---|---|---|---|---|
| USER → ASSESSMENT | Target ID, scan mode, validation flag | `Assessment` row, `pending` | API (Assessment Service) | `Assessment` | `assessment.created` | Target has no approved/unexpired authorization → 422, nothing created. |
| ASSESSMENT → ORCHESTRATOR | `Assessment.pending` | Orchestrator claims it | Orchestrator | `Assessment` (`pending→running`) | `assessment.started` | Orchestrator unavailable → assessment stays `pending`, visible as stalled past a timeout. |
| ORCHESTRATOR → AGENT TASK | Assessment state, next-stage rule | `AgentRun` row, `queued` | Orchestrator | `AgentRun` | `agent.scheduled` | Prerequisite stage has zero output → stage explicitly skipped, not silently hung. |
| AGENT TASK → TOOL EXECUTION | Agent's capability request | `ExecutionPlan` → scope-checked → sandboxed run | Tool Registry, Scope Guard, Sandbox | `ToolExecution` | `tool.started` / `tool.completed` | Scope denial → no process started, `ScopeViolation` returned to agent, audited. Toolset/intrusiveness/validation-gate denial → same, before scope check even runs. |
| TOOL EXECUTION → OBSERVATION | Raw artifact | Normalized, typed `Observation` | Tool adapter `parse()` + Normalizer | `Observation`, `Asset` (upsert) | `observation.created`, `asset.discovered` | Parse failure → `ToolExecution` marked failed, raw artifact retained, no observation fabricated. |
| OBSERVATION → (correlation) → FINDING | ≥1 related observation | `Finding` row, `DISCOVERED` | Vulnerability Agent / correlation logic | `Finding` | `finding.created` | No correlating rule matches → observation stored, no finding created (not every observation becomes a finding). |
| FINDING → INVESTIGATION | `Finding.DISCOVERED` | `Finding.SUSPECTED → INVESTIGATING`, investigation notes | Investigation Agent | `Finding`, `Evidence` (read-only re-check evidence) | `finding.investigating` | Inconclusive → `Finding` stays `SUSPECTED`/`INVESTIGATING`, reported as unconfirmed — never forced to a verdict. |
| INVESTIGATION → VALIDATION | `Finding.INVESTIGATING`, validation flag = true | Validation Agent run | Orchestrator (schedules), Validation Agent (executes) | `AgentRun`, `ToolExecution` | `agent.started` (Validation Agent) | Validation flag = false → this transition never occurs; finding proceeds directly toward Attack Graph as unconfirmed. |
| VALIDATION → EVIDENCE | Validation check result | `Evidence` row (`validation_result`) | Validation Agent | `Evidence` | `evidence.created` | Check errors/times out → evidence of the *attempt* is still recorded; finding status is *not* changed. |
| EVIDENCE → FINDING (status) | Evidence + check outcome | `Finding.CONFIRMED` or `Finding.REJECTED` | Validation Agent (or explicit analyst override) | `Finding` | `finding.validated` / `finding.rejected` | A finding cannot become `CONFIRMED` with zero evidence — enforced at the data layer, not only by convention. |
| FINDING → ATTACK GRAPH | Confirmed (+ well-evidenced suspected) findings, assets, relationships | `AttackNode`/`AttackEdge` rows | Attack Graph Agent (deterministic engine) | `AttackNode`, `AttackEdge`, `AttackPath` | `attack_path.discovered` | Rule-set invalid at startup → engine refuses to run rather than building a wrong graph; a mid-run failure leaves the previous graph in place, marked stale. |
| ATTACK GRAPH → RISK | Finding + its graph position | `Finding.risk_score/risk_breakdown` | Risk Agent (deterministic engine) | `Finding`, `RiskAssessment` | `risk.updated` | Graph not yet computed → path-position term dropped, other weights renormalized, breakdown flags `path_position: unavailable` (never blocks scoring entirely). |
| RISK → REPORT | All of the above, assembled | `Report` row (immutable) | Reporting Agent | `Report` | `report.generated` | Reporting failure → assessment data is untouched; report generation can be retried without re-running any other agent. |
| → COMPLETED ASSESSMENT | Report generated (or explicitly skipped) | `Assessment.completed` | Orchestrator | `Assessment` | `assessment.completed` | Any stage with zero usable output overall → `Assessment.completed_with_errors`, never silently reported as fully successful. |

This table is the single reference for "what exactly happens between two stages" during implementation; phase-level acceptance criteria in [roadmap.md](roadmap.md) should cite rows from it rather than restate them.

---

## 3. Canonical Domain Model

For each entity: purpose, important fields, relationships, lifecycle, owning service, MVP requirement. This refines — does not replace — [../data/data-model.md](../data/data-model.md).

| Entity | Purpose | Important fields | Relationships | Lifecycle | Owner | MVP? |
|---|---|---|---|---|---|---|
| **Target** | What may be assessed, and under what scope/authorization. | `id`, `name`, `type`, `entry_point` (nullable http(s) URL; migration 0005), `default_exposure`, `default_criticality` | has many `Authorization` (versioned), has many `Assessment` | n/a (CRUD) | Target Service | **Yes** |
| **Authorization** | The approved scope + attestation that makes a target assessable. | `id`, `target_id`, `version`, `scope_rules`, `attestation`, `valid_from/until`, `status` | belongs to `Target`; an `Assessment` snapshots one version | `pending→approved/rejected`, `approved→revoked`, derived `expired` | Target Service | **Yes** |
| **Assessment** | One run of the full lifecycle against one target. | `id`, `target_id`, `authorization_id` (snapshot), `scan_mode`, `validation_enabled`, `status`, timestamps | has many `AgentRun`, `Asset`, `Finding`, `AttackNode/Edge`, `Report` | `pending→running→{completed, completed_with_errors, failed, cancelled}` | Orchestrator | **Yes** |
| **Asset** | A discovered host/port/service/application/endpoint/cloud resource. | `id`, `assessment_id`, `asset_type`, `canonical_key`, `attributes`, `criticality`, `exposure`, `scope_state` | has many `Observation`; participates in `AttackNode` | discovered → (criticality/exposure editable) | Recon/Vulnerability Agents (write), Asset Service (read/edit) | **Yes** |
| **Observation** | A normalized, typed fact from one tool execution. | `id`, `type`, `source`, `asset_id`, `confidence`, `data` (typed payload), `tool_execution_id` | belongs to `ToolExecution`, `Asset`; correlates into `Finding` | immutable once written | Normalizer | **Yes** |
| **Finding** | A candidate or confirmed weakness. | `id`, `assessment_id`, `asset_id`, `title`, `severity`, `confidence`, `cvss_*`/`cve`/`cwe` (nullable), `source`, `source_reference`, `affected_component`, `status`, `risk_score`/`risk_breakdown`/`risk_model_version`, `first_seen`/`last_seen` | has many `Evidence`; causes `AttackEdge`s | `DISCOVERED→SUSPECTED→INVESTIGATING→{CONFIRMED,REJECTED}→REPORTED` (see [../data/findings.md](../data/findings.md), corrected) | Vulnerability/Investigation/Validation Agents | **Yes** |
| **Evidence** | A specific artifact backing a finding. | `id`, `finding_id`, `kind`, `tool_execution_id`, `excerpt` (sanitized, size-capped), `artifact_ref`, `captured_at` | belongs to `Finding`, `ToolExecution` | immutable once written | whichever agent/tool call produced it | **Yes** |
| **AgentRun** | One execution of one agent. | `id`, `assessment_id`, `agent_type`, `status`, `attempts`, `input_ref`, `output_ref`, started/finished | belongs to `Assessment`; produces `ToolExecution`s | `queued→running→{succeeded,failed,cancelled}`, bounded attempts | Orchestrator (schedules), agent runtime (executes) | **Yes** |
| **ToolExecution** | One tool call made through the Tool Registry. | `id`, `agent_run_id` (nullable for non-agent calls), `tool_name`, `capability`, `scope_decision`, `argv` (secrets redacted), `artifact_hash`, `exit_status`, timing | belongs to `AgentRun`; produces `Observation`/`Evidence` | `planned→allowed/denied→{completed,timed_out,killed}` | Tool Registry / Execution Engine | **Yes** |
| **AttackNode** | `(asset, access_level)` graph vertex. | `id`, `assessment_id`, `asset_id`, `access_level` | has many `AttackEdge` (src/dst) | rebuilt per Attack Graph Agent pass; stale-flagged between passes | Attack Graph Agent | **Yes** |
| **AttackEdge** | A graph edge with cause and evidence level. | `id`, `src_node_id`, `dst_node_id`, `cause_type` (`finding`/`relationship`), `cause_id`, `rule_id`, `evidence_level` | belongs to two `AttackNode`s; `cause_id` may reference `Finding` | derived, not independently transitioned | Attack Graph Agent | **Yes** |
| **AttackPath** | A persisted, bounded-search result: entry → target. | `id`, `assessment_id`, `entry_node_id`, `target_node_id`, `path_risk`, `evidence_level` (weakest edge), `rules_version` | has many ordered `AttackEdge` references (steps) | recomputed per pass; a path is a query result, not independently mutable | Attack Graph Agent | **Yes** |
| **RiskAssessment** | The versioned score + breakdown for one finding at one point in time. | `id`, `finding_id`, `score`, `band`, `breakdown` (component values, `assumed` flags), `model_version`, `computed_at` | belongs to `Finding` (1:1 "current", N:1 historically if re-scored) | recomputed when inputs change (criticality/exposure edits, graph updates) | Risk Agent | **Yes** — *(note: could be folded into `Finding` directly as denormalized columns rather than a separate table; see overlap note below)* |
| **Report** | An immutable, generated snapshot. | `id`, `assessment_id`, `formats`, `included_scan_ids`, `provenance` (tool/model/rule versions), `generated_at` | references `Assessment`, the specific `Finding`/`Evidence` it includes | immutable; regeneration creates a new row | Reporting Agent | **Yes** |

**Overlap flagged, not silently resolved:** `Finding.risk_score/risk_breakdown/risk_model_version` (inline fields, per [../data/findings.md](../data/findings.md)) and a standalone `RiskAssessment` entity (introduced by this blueprint to satisfy the user's requested entity list in §4 of the review prompt) describe the same information. **Recommendation:** keep risk fields **inline on `Finding`** for the current value (simplest, matches existing docs, avoids a join on every findings-list query) and add a `RiskAssessment` **history table** only if/when re-scoring history needs to be queryable (not required for MVP). This is a design choice for Phase P11 to confirm, not a silent architecture change — flagged here per the review's instruction.

**Entities evaluated and intentionally not modeled as separate tables for MVP:** a standalone `Identity`/`Credential`/`Role` table (the attack graph treats these as `Asset` subtypes with `attributes.kind`, per [../data/attack-graph.md](../data/attack-graph.md) — introducing separate tables now would be premature generalization ahead of cloud security, P15).

---

## 4. Agent Contracts

Each agent's full narrative documentation already exists in `docs/agents/*.md`; this section is the compact, implementation-facing contract view for all nine components (the Orchestrator plus seven agents, with the ninth row addressing a naming question raised by this review).

```
Orchestrator
├── Responsibility: Own the assessment lifecycle; schedule agent runs; enforce stage dependencies; retries/cancellation.
├── Inputs: Assessment state, scan mode, validation flag.
├── Tools: none.
├── Outputs: Assessment transitions, scheduled AgentRuns.
├── Events Produced: assessment.created/started/completed, agent.scheduled
├── Database Writes: Assessment, AgentRun
├── Dependencies: none (first to run)
├── Permissions: no Tool Registry access, by construction.
└── Failure Handling: stage with zero output blocks progression; partial output → completed_with_errors.

Recon Agent
├── Responsibility: Map the in-scope attack surface.
├── Inputs: scope snapshot, prior observations.
├── Tools: DNS resolution, port/service discovery, HTTP probing, subdomain enumeration (read-only).
├── Outputs: Observations (HOST/PORT/SERVICE/TECHNOLOGY/ENDPOINT_DISCOVERED), Assets.
├── Events Produced: tool.started/completed, asset.discovered, observation.created
├── Database Writes: Observation, Asset
├── Dependencies: Assessment created, scope/authorization valid.
├── Permissions: read-only recon capabilities only; cannot request requires_validation_mode.
└── Failure Handling: partial recon kept; stage completed_with_errors, not endlessly retried.

Vulnerability Agent
├── Responsibility: Run scanners against the discovered surface; produce candidate findings.
├── Inputs: Assets/Observations from Recon, scan mode.
├── Tools: template web scanning, dependency/container scanning, static analysis (non-intrusive config).
├── Outputs: Observations (VULNERABILITY_SIGNAL_DISCOVERED), Findings at DISCOVERED.
├── Events Produced: tool.started/completed, finding.created
├── Database Writes: Observation, Finding
├── Dependencies: Recon output (at least one asset).
├── Permissions: no shell/code execution, no requires_validation_mode capability.
└── Failure Handling: one scanner's failure degrades that scanner's coverage only.

Investigation Agent
├── Responsibility: Resolve ambiguity in candidate findings via read-only re-checks.
├── Inputs: Findings at DISCOVERED + their evidence.
├── Tools: read-only re-probe/re-request/artifact inspection only.
├── Outputs: Finding.status → SUSPECTED/INVESTIGATING, investigation notes/evidence.
├── Events Produced: finding.investigating
├── Database Writes: Finding (status only, never CONFIRMED/REJECTED), Evidence, Observation (from re-checks)
├── Dependencies: Vulnerability Agent output.
├── Permissions: read-only only; CANNOT set CONFIRMED/REJECTED (data-model-enforced, not just convention).
└── Failure Handling: inconclusive → finding stays SUSPECTED, reported as unconfirmed.

Validation Agent
├── Responsibility: Confirm/reject a finding via one pre-reviewed, non-destructive, per-class check.
├── Inputs: a single INVESTIGATING finding + the assessment's validation flag.
├── Tools: exactly one registered non-destructive check for the finding's class; gated by requires_validation_mode.
├── Outputs: Finding.status → CONFIRMED/REJECTED, validation Evidence.
├── Events Produced: finding.validated / finding.rejected
├── Database Writes: Finding (status), Evidence
├── Dependencies: assessment.validation_enabled == true; Investigation output.
├── Permissions: the ONLY agent allowed to request a requires_validation_mode capability, and only the one check registered for the finding's class.
└── Failure Handling: check errors/times out → finding stays at prior status, never forced to a verdict.

Attack Graph Agent (deterministic engine, not an LLM call)
├── Responsibility: Build attack graph nodes/edges from assets, relationships, confirmed/well-evidenced findings.
├── Inputs: Assets, relationships, Findings (status + confidence).
├── Tools: none.
├── Outputs: AttackNode, AttackEdge (with evidence_level), AttackPath (bounded search).
├── Events Produced: attack_path.discovered
├── Database Writes: AttackNode, AttackEdge, AttackPath
├── Dependencies: Confirmed-findings set has stabilized for this pass.
├── Permissions: no target interaction at all.
└── Failure Handling: invalid rule set → refuses to start; mid-run failure → previous graph kept, marked stale.

Risk Agent (deterministic engine, not an LLM call)
├── Responsibility: Compute path-aware risk score + breakdown per finding.
├── Inputs: Finding (severity, confidence, exploitability), its Attack Graph position.
├── Tools: none.
├── Outputs: Finding.risk_score/risk_breakdown/risk_model_version.
├── Events Produced: risk.updated
├── Database Writes: Finding (risk fields) [/ RiskAssessment history, see §3 overlap note]
├── Dependencies: Attack Graph Agent output (or explicit "unavailable" fallback).
├── Permissions: none; pure function of stored data.
└── Failure Handling: graph unavailable → path term dropped, weights renormalized, breakdown flags it — never blocks scoring.

Reporting Agent
├── Responsibility: Assemble the evidence-linked report; write grounded prose sections.
├── Inputs: full assessment state (assets, findings+evidence, graph, risk).
├── Tools: none against the target; reads assessment data only.
├── Outputs: Report (JSON/SARIF/Markdown/PDF).
├── Events Produced: report.generated
├── Database Writes: Report
├── Dependencies: Risk Agent has scored all in-scope findings.
├── Permissions: read-only over assessment state; cannot alter any finding/score/graph data.
└── Failure Handling: failure does not lose assessment data; report generation is retryable independently.

"Source Analysis Agent" — NOT a separate component (see Contradictions Found, §14 of this review)
├── Status: static/source analysis (Semgrep) is currently documented as a CAPABILITY inside the
│   Vulnerability Agent's toolset (tools/scanners.md, tools/tool-registry.md), not a standalone agent.
├── Recommendation: keep it there for MVP — splitting it into its own agent is not justified by a
│   distinct responsibility today (it produces the same DISCOVERED-finding output as other scanners).
└── Open question: revisit only if source-analysis workflows grow enough judgment-heavy, multi-step
    investigation of their own (analogous to why Investigation was split out from Vulnerability) —
    not before.
```

---

## 5. Tool Registry Contract

```
Tool
├── name                  — unique capability identifier (e.g. "port_scan", "http_probe")
├── description           — human-readable purpose
├── input schema          — typed ExecutionPlan fields the adapter's plan() must populate
├── output schema         — typed ParsedResult the adapter's parse() must return
├── permissions           — which agent types may request this capability (toolset membership, see
│                           architecture/execution-model.md)
├── scope requirements    — every destination declared in the plan; checked by Scope Guard before
│                           any process starts
├── timeout               — wall-clock cap; exceeding it kills the whole process tree
├── execution environment — sandbox profile (non-root, resource caps, network policy)
└── audit information     — tool name/version, redacted argv, exit code, artifact hash, timing
```

### Tool classification (honest status — none is above PLANNED today)

| Tool / capability | Category | Status | Tag |
|---|---|---|---|
| DNS resolution (dnspython) | Reconnaissance | PLANNED | — |
| TCP port/service discovery (Nmap) | Reconnaissance | PLANNED | — |
| HTTP request/response (httpx) | Web | PLANNED | — |
| Browser automation (Playwright) | Web | PLANNED | — |
| Proxy/interception (mitmproxy or equivalent) | Web | PLANNED | UNCONFIRMED (candidate only) |
| Template-based web scanning (Nuclei) | Vulnerability | PLANNED | — |
| Static analysis (Semgrep) | Vulnerability | PLANNED | — |
| Dependency/container scanning (Trivy) | Vulnerability | PLANNED | — |
| Sandboxed shell | Execution | PLANNED | — |
| Sandboxed Python | Execution | PLANNED | — |

No row above is `IMPLEMENTED`; "candidate implementation" names are not integration claims (per [../tools/tool-registry.md](../tools/tool-registry.md) and [../roadmap/current-status.md](current-status.md)). `OPTIONAL` is reserved for a tool whose absence degrades a feature gracefully rather than blocking the pipeline — no tool has been implemented yet to classify this way.

---

## 6. Event Model

| Event | Producer | Consumer(s) | Payload (key fields) | Persistence | Real-time requirement |
|---|---|---|---|---|---|
| `assessment.created` | API | Orchestrator, Dashboard | `assessment_id`, `target_id`, `scan_mode` | Yes (audit + `Assessment` row) | Not required (poll acceptable for MVP) |
| `assessment.started` | Orchestrator | Dashboard | `assessment_id` | Yes | Nice-to-have |
| `agent.scheduled` | Orchestrator | Agent runtime, Dashboard (Agent Activity) | `agent_run_id`, `agent_type` | Yes | Nice-to-have |
| `agent.started` | Agent runtime | Dashboard | `agent_run_id` | Yes | Nice-to-have |
| `agent.completed` | Agent runtime | Orchestrator, Dashboard | `agent_run_id`, `status`, `output_summary` | Yes | Nice-to-have |
| `agent.failed` | Agent runtime | Orchestrator, Dashboard | `agent_run_id`, `error` | Yes | Nice-to-have |
| `tool.started` | Tool Registry | Dashboard, Audit | `tool_execution_id`, `capability`, `scope_decision` | Yes (required — audit trail) | Not required |
| `tool.completed` | Tool Registry | Dashboard, Audit, Normalizer | `tool_execution_id`, `exit_status`, `artifact_hash` | Yes (required) | Not required |
| `asset.discovered` | Normalizer | Dashboard (Attack Surface) | `asset_id`, `asset_type`, `canonical_key` | Yes | Nice-to-have |
| `observation.created` | Normalizer | Investigation Agent (reads on demand), Dashboard | `observation_id`, `type`, `asset_id` | Yes | Not required |
| `finding.created` | Vulnerability Agent | Investigation Agent (reads on demand), Dashboard | `finding_id`, `status=DISCOVERED` | Yes | Nice-to-have |
| `finding.investigating` | Investigation Agent | Validation Agent (reads on demand), Dashboard | `finding_id` | Yes | Not required |
| `finding.validated` | Validation Agent | Risk/Attack Graph Agents (reads on demand), Dashboard | `finding_id`, `status=CONFIRMED` | Yes | Nice-to-have |
| `finding.rejected` | Validation Agent | Dashboard | `finding_id`, `status=REJECTED` | Yes | Not required |
| `attack_path.discovered` | Attack Graph Agent | Risk Agent, Dashboard | `assessment_id`, path count/summary | Yes | Not required |
| `risk.updated` | Risk Agent | Reporting Agent (reads on demand), Dashboard | `finding_id`, `risk_score`, `risk_band` | Yes | Not required |
| `report.generated` | Reporting Agent | Dashboard, user (download link) | `report_id`, `formats` | Yes | Nice-to-have (user is usually waiting) |
| `assessment.completed` | Orchestrator | Dashboard, user | `assessment_id`, `final_status` | Yes | Nice-to-have |

**MVP implementation note:** every event above is first implemented as a **persisted row + poll-based dashboard refresh** (consistent with the original design's "no WebSockets in MVP" decision — see the superseded `Design.md`). A real-time transport (SSE/WebSocket) is a pure additive enhancement for a later phase, not a prerequisite for any MVP capability — no event in this table is "real-time required" for correctness, only for UX polish.

---

## 7. API Surface

Builds on [../interfaces/api.md](../interfaces/api.md); adds request/response shape and explicitly separates **CURRENTLY REQUIRED** (first vertical slice, §10) from **FUTURE**. Nothing below is implemented.

### Assessment

| Method | Path | Purpose | Request | Response | Auth | Scope/role | Status |
|---|---|---|---|---|---|---|---|
| POST | `/api/v1/assessments` | Create assessment | `{target_id, scan_mode, validation_enabled}` | `Assessment` (`pending`) | session | `analyst` | **CURRENTLY REQUIRED** |
| GET | `/api/v1/assessments/{id}` | Status + stage progress | — | `Assessment` + `AgentRun[]` summary | session | any role | **CURRENTLY REQUIRED** |
| POST | `/api/v1/assessments/{id}/cancel` | Cancel | — | `Assessment` (`cancelled`) | session | `analyst` | **CURRENTLY REQUIRED** |
| GET | `/api/v1/assessments` | List | query filters | `Assessment[]` | session | any role | FUTURE (nice for dashboard list, not blocking the vertical slice) |

### Assets / Observations

| Method | Path | Purpose | Request | Response | Auth | Scope/role | Status |
|---|---|---|---|---|---|---|---|
| GET | `/api/v1/assessments/{id}/assets` | Discovered assets | query filters | `Asset[]` | session | any role | **CURRENTLY REQUIRED** |
| GET | `/api/v1/assets/{id}/observations` | Observations for one asset | — | `Observation[]` | session | any role | FUTURE (debugging aid; not needed for the vertical slice's happy path) |

### Findings / Evidence

| Method | Path | Purpose | Request | Response | Auth | Scope/role | Status |
|---|---|---|---|---|---|---|---|
| GET | `/api/v1/assessments/{id}/findings` | List findings | filters (status/severity/risk) | `Finding[]` | session | any role | **CURRENTLY REQUIRED** |
| GET | `/api/v1/findings/{id}` | Finding detail + evidence | — | `Finding` + `Evidence[]` | session | any role | **CURRENTLY REQUIRED** |
| PATCH | `/api/v1/findings/{id}/status` | Analyst override (confirm/reject/accept-risk/fixed) | `{status, reason}` | `Finding` | session | `analyst` | **CURRENTLY REQUIRED** (this is the "explicit analyst override" path referenced in §14) |

### Attack Paths

| Method | Path | Purpose | Request | Response | Auth | Scope/role | Status |
|---|---|---|---|---|---|---|---|
| GET | `/api/v1/assessments/{id}/attack-paths` | Computed paths | — | `AttackPath[]` (with steps, evidence levels) | session | any role | **CURRENTLY REQUIRED** |
| POST | `/api/v1/assessments/{id}/attack-paths/recompute` | Force recompute | — | `202` | session | `analyst` | FUTURE |

### Risk

Nested under Findings for MVP (`Finding.risk_score`/`risk_breakdown` are returned inline by `GET /findings/{id}`); a standalone `/risk` resource is FUTURE, contingent on the `RiskAssessment` history-table decision in §3.

### Agents

| Method | Path | Purpose | Request | Response | Auth | Scope/role | Status |
|---|---|---|---|---|---|---|---|
| GET | `/api/v1/assessments/{id}/agent-runs` | Agent activity log | — | `AgentRun[]` (+ linked `ToolExecution[]`) | session | any role | **CURRENTLY REQUIRED** (this is the audit-facing view the architecture review treats as non-optional) |

### Reports

| Method | Path | Purpose | Request | Response | Auth | Scope/role | Status |
|---|---|---|---|---|---|---|---|
| POST | `/api/v1/assessments/{id}/reports` | Generate report | `{formats, include_ai_content}` | `Report` (`202` while generating) | session | `analyst` | **CURRENTLY REQUIRED** |
| GET | `/api/v1/reports/{id}` | Fetch report | — | `Report` (+ download links) | session | any role | **CURRENTLY REQUIRED** |

### Targets / Auth (carried over, already specified)

Unchanged from [../interfaces/api.md](../interfaces/api.md): Targets, Authorizations, `/healthz`, `/readyz` — all **CURRENTLY REQUIRED** (nothing above works without them).

**Explicitly FUTURE, not designed further here:** webhooks, GraphQL, public/unauthenticated API access, MCP endpoints (P17).

---

## 8. Frontend Surface

| Screen | Data required | API required | Real-time events | Key user actions |
|---|---|---|---|---|
| Dashboard | Aggregate counts across assessments | `GET /assessments` (+ per-assessment summaries) | None (poll) | Open an assessment |
| Assessment (overview) | `Assessment`, `AgentRun[]` | `GET /assessments/{id}` | Poll every few seconds while `running` | Cancel; view stage progress |
| Attack Surface | `Asset[]` | `GET /assessments/{id}/assets` | None | Filter by type; drill into an asset |
| Findings | `Finding[]` | `GET /assessments/{id}/findings` | None | Filter/sort; open a finding |
| Finding Details | `Finding` + `Evidence[]` | `GET /findings/{id}` | None | Set status (analyst override, with required reason) |
| Evidence (within Finding Details) | `Evidence[]` | (included in finding detail response) | None | View excerpt; open raw artifact |
| Attack Graph | `AttackPath[]` (+ steps) | `GET /assessments/{id}/attack-paths` | None | Select a node; "what can be reached from here" |
| Risk (within Finding Details) | `Finding.risk_score/risk_breakdown` | (included in finding detail response) | None | View breakdown; understand `assumed` flags |
| Agent Activity | `AgentRun[]`, `ToolExecution[]` | `GET /assessments/{id}/agent-runs` | Poll while assessment is running | Audit what an agent did and why |
| Reports | `Report[]` | `POST`/`GET /reports` | Poll while generating | Generate; download |

**The frontend is never the source of truth** — every screen above is a read (and, for the one write action, `PATCH /findings/{id}/status`, an explicitly audited write) over API data; no screen computes risk, builds the graph, or decides a finding's status client-side.

---

## 9. MVP Definition

The smallest realistic end-to-end OffensiveX MVP demonstrates the full chain, once, correctly:

```
Authorized Target → Assessment → Recon → Observation → Potential Finding
  → Investigation → Validation → Evidence → Confirmed Finding
  → Attack Graph → Risk → Report
```

**In the MVP:**
- One target type (web application), one scan mode path exercised end-to-end (`standard`, validation **enabled** — otherwise the "Confirmed Finding" step in the required chain above is never reached, see the corrected lifecycle in [../data/findings.md](../data/findings.md)).
- Recon: DNS + HTTP probing (not full Nmap port sweep — HTTP-only surface is sufficient to prove the chain; port scanning is additive, not blocking).
- Vulnerability discovery: **one** scanner integration, not all four candidates in [../tools/scanners.md](../tools/scanners.md) (see §11, vertical slice).
- Investigation: real agent reasoning over the one finding class chosen for the vertical slice.
- Validation: **one** registered non-destructive check, for that one finding class.
- Attack graph: a minimal, correct rule set (need not cover every relationship type in [../data/attack-graph.md](../data/attack-graph.md) — a handful of rules proving the mechanism is sufficient).
- Risk: the full deterministic formula, with real (even if not perfectly tuned) weights.
- Report: JSON **and** Markdown (SARIF/PDF are FUTURE for MVP, per §7).
- Dashboard: Assessment overview, Findings, Finding Details, Reports (Attack Graph and Agent Activity views are strongly desirable but not blocking — they can ship as read-only, less polished views).
- CLI: `scan`, `status`, `report` (the three commands the vertical slice actually needs; `view`/`target` management are FUTURE for MVP).

**Not needed for MVP** (per the review prompt, confirmed against the documentation): every scanner (one is enough to prove the pattern), cloud providers, every vulnerability class, MCP, real-time transport, PDF/SARIF rendering, multi-target/multi-tenant concerns, scheduled scans.

---

## 10. First Vertical Slice

**Recommendation: a reflected-input web finding (e.g. a missing-security-header or reflected-parameter class), not an exploit-grade vulnerability class.**

```
Assessment
→ Recon (DNS + HTTP probe on the one authorized web target)
→ HTTP/Web discovery (headers, technology fingerprint)
→ One vulnerability workflow: a single non-intrusive web-scanner check
   (e.g. a missing/misconfigured security header, or a template match for a
   well-known, low-risk-to-check class)
→ Investigation (Investigation Agent re-requests the page, confirms the
   condition is stable, attaches evidence)
→ Controlled validation (the one registered non-destructive check for this
   finding class — e.g. re-request and verify the header is still absent,
   nothing more invasive)
→ Evidence (request/response pairs from every step above)
→ Finding (CONFIRMED)
→ Attack graph (a single edge: internet-exposed web app → the access level
   this finding class grants, per one curated rule)
→ Risk (full formula, real weights, this one finding scored)
→ Report (JSON + Markdown, one finding, one path, fully evidence-linked)
```

**Why this and not something "more impressive":** it is genuinely low-risk to validate non-destructively (a header check or a stable reflection check requires no state-changing request), it exercises **every** stage in the lifecycle exactly once, and it keeps the first implementation effort focused on proving the *architecture* (orchestrator → agent → tool registry → sandbox → observation → finding → graph → risk → report) rather than on scanner breadth or exploit sophistication. A SQLi/RCE-class slice would be more "impressive" to describe but would pull Phase P8 (Validation) into exploit-development territory before the architecture itself is proven — exactly the risk [architecture-risks.md](architecture-risks.md) flags under "excessive ambition in the first slice."

---

## 11. Implementation Phases

Converts [roadmap.md](roadmap.md)'s P0–P17 into the structure requested by this review. Each phase's detailed task/test/acceptance breakdown is still written **immediately before that phase starts** (per [CLAUDE.md](../../CLAUDE.md)'s "document first" discipline) — what follows here is the dependency-correct skeleton, confirmed against the documentation rather than invented fresh.

| Phase | Objective | Components | Dependencies | DB changes | API changes | Agent changes | Frontend changes | Tests |
|---|---|---|---|---|---|---|---|---|
| **P0** | Project foundation | `pyproject.toml`, config, logging, health checks, CI skeleton | none | none | `/healthz`, `/readyz` | none | none | Config/health unit tests |
| **P1** | Database / domain model | SQLAlchemy models, Alembic baseline, state machines | P0 | `Target`, `Authorization`, `ScopeRule`, `Assessment`, `Asset`, `Observation`, `Finding`, `Evidence`, `AgentRun`, `ToolExecution` (schema only) | none yet | none | none | Migration tests, state-machine table tests |
| **P2** | Assessment lifecycle | Target/Authorization/Scope services, Orchestrator skeleton with a no-op test agent | P1 | writes to `Target`, `Authorization`, `Assessment`, `AgentRun` | Targets, Authorizations, `POST/GET /assessments` | Orchestrator only | none | Scope property tests (≥95% branch), assessment-creation tests |
| **P3** | Tool Registry | Adapter contract, registry, Scope Guard integration, audit log | P2 | `ToolExecution` writes | internal only | none | none | Scope-check + audit tests, one proof adapter (DNS) |
| **P4** | Sandbox / execution layer | Containerized execution, timeouts, process-tree kill, fixture-replay mode | P3 | none new | none | none | none | No-shell tests, timeout/kill tests, fixture-mode tests |
| **P5** | Agent framework | LLM-session runtime: bounded toolset, typed output contract | P4 | none new | none | applies framework to simplest agent (Recon) | none | Toolset-membership enforcement tests |
| **P6** | Recon | Recon Agent for real, DNS + HTTP probe adapters | P5 | `Asset`, `Observation` writes | `GET /assessments/{id}/assets` | Recon Agent | Attack Surface view (basic) | Adapter fixture tests, scope-escape tests |
| **P7** | Observation / event system | Full `Observation` normalization path, event table/log | P6 | `Observation` finalized | event query (internal) | none | Agent Activity view (basic, tool-execution log) | Normalization unit tests |
| **P8** | Vulnerability discovery | Vulnerability Agent + **one** scanner adapter (the vertical-slice class) | P6 | `Finding` writes (`DISCOVERED`) | `GET /assessments/{id}/findings` | Vulnerability Agent | Findings view (basic) | Parser + dedupe/fingerprint tests |
| **P9** | Investigation | Investigation Agent, read-only re-check capability | P8 | `Finding` status writes, `Evidence` | `GET /findings/{id}` | Investigation Agent | Finding Details view (basic) | Grounding/citation tests |
| **P10** | Validation + Evidence | Validation Agent, one registered check, full evidence model | P9 | `Finding` → `CONFIRMED/REJECTED`, `Evidence` finalized | `PATCH /findings/{id}/status` (analyst override) | Validation Agent | Finding Details: status + evidence | Non-destructiveness review, opt-in gating tests |
| **P11** | Findings engine | Full lifecycle, dedup, analyst triage | P10 | — (completes Finding) | status filters finalized | — | Findings filters/search | Lifecycle corner-case tests (per the correction in §14) |
| **P12** | Attack graph | Deterministic engine, bounded path search, minimal rule set | P11 | `AttackNode`, `AttackEdge`, `AttackPath` | `GET /assessments/{id}/attack-paths` | Attack Graph Agent (engine) | Attack Graph view (basic) | Graph construction + bounded-search tests |
| **P13** | Risk engine | Deterministic, path-aware formula, real weights | P12 | `Finding.risk_score/breakdown` | (inline in finding response) | Risk Agent (engine) | Risk breakdown display | Golden-value + monotonicity tests |
| **P14** | Reporting | Reporting Agent, JSON + Markdown output, grounded AI prose | P13 | `Report` | `POST/GET /reports` | Reporting Agent | Reports view | Golden-file + escaping tests |
| **P15** | Dashboard | Remaining views, aggregate endpoints | P14 | none new | aggregate endpoints | none | Dashboard, Agent Activity (full) | Contract tests against real endpoints |
| **P16** | CLI | `scan`, `status`, `report` (and later `view`, `target`) | P14 (API-complete enough) | none | none (consumes existing API) | none | none | CLI integration tests |
| **P17** | Cloud security | `CloudProvider` interface, AWS read-only checks | P11 (findings pipeline) | `Asset(cloud_resource)` | Cloud API | extends Vulnerability Agent or a dedicated check runner (see §4) | Cloud view | `moto` contract tests |
| **P18** | CI/CD | Automated test/lint/security-scan pipeline, reproducible build | any point after P2 (can start early, run alongside) | none | none | none | none | Pipeline itself is the test |
| **P19** | MCP / integrations | External tool/agent protocol support | Everything above (deliberately last) | TBD | TBD | TBD | TBD | TBD |

**Ordering note:** this follows the review prompt's requested order with one adjustment the documentation justifies: **P18 (CI/CD)** does not need to wait for P17 (Cloud Security) — it can and should start as soon as there is anything to test (P2+) and run continuously alongside later phases, rather than being a discrete phase inserted near the end. The table lists it at its conventional position for readability; actual CI setup work begins much earlier.

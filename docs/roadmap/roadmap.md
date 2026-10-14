# Roadmap

Status: PLANNED. This replaces the phase order in the superseded `docs/Phases.md`. See [current-status.md](current-status.md) for what exists today (nothing, yet).

**Renumbered (2026-10-07)** during the architecture-to-implementation consistency review to split "foundation" into project-setup vs. domain-model work, and to give the sandbox/execution layer its own phase separate from the Tool Registry contract — a cleaner dependency breakdown than the original P0–P17 list. Phase objectives below are unchanged in substance; see [implementation-blueprint.md §11](implementation-blueprint.md#11-implementation-phases) for the full per-phase components/dependencies/DB/API/agent/frontend/test breakdown — this table is the short index, that one is authoritative for phase content.

## Build order

| Phase | Objective |
|---|---|
| **P0** | Project foundation: repo/package scaffolding, config, logging, health checks, CI skeleton. |
| **P1** | Database / domain model: SQLAlchemy models, Alembic baseline, state machines for the core entities. |
| **P2** | Assessment lifecycle: Target/Authorization/Scope services, Orchestrator skeleton with a no-op test agent, scope/authorization gate (carried over from the original design). |
| **P3** | Tool Registry: adapter contract, registry, Scope Guard integration — proven with one adapter (e.g. DNS resolution). |
| **P4** | Sandbox / execution layer: containerized execution, timeouts, process-tree kill, fixture-replay mode, audit log. |
| **P5** | Agent framework: the runtime that gives an LLM session a bounded toolset and a typed output contract, applied first to the simplest agent. |
| **P6** | Recon: the Recon Agent for real, over the Tool Registry capabilities it needs. |
| **P7** | Observation / event system: the `Observation` model, the tool→observation normalization path, and the event log. |
| **P8** | Vulnerability Discovery: the Vulnerability Agent and its first scanner adapter (one, not all four candidates — see [implementation-blueprint.md §10](implementation-blueprint.md#10-first-vertical-slice)). |
| **P9** | Investigation: the Investigation Agent and the finding lifecycle through `INVESTIGATING`. |
| **P10** | Validation + Evidence: the Validation Agent (opt-in), one registered non-destructive check, and the full evidence model. |
| **P11** | Findings Engine: the complete `DISCOVERED → … → REPORTED` lifecycle, dedup/fingerprinting, analyst triage. |
| **P12** | Attack Graph: the deterministic graph-construction engine and bounded path search, minimal rule set. |
| **P13** | Risk Engine: the deterministic, path-aware risk model (formula finalized and documented in [../security/risk-analysis.md](../security/risk-analysis.md) at this point). |
| **P14** | Reporting: the Reporting Agent, deterministic sections, grounded AI prose, JSON + Markdown output (SARIF/PDF are FUTURE). |
| **P15** | Dashboard: the sections in [../interfaces/dashboard.md](../interfaces/dashboard.md), backed only by real endpoints that exist by this point. |
| **P16** | CLI: `scan`, `status`, `report` first; `view`/`target` management follow. |
| **P17** | Cloud Security: provider abstraction + first provider's read-only checks, feeding the same findings/attack-graph pipeline. |
| **P18** | CI/CD: automated testing, security scanning, and a reproducible build/deploy pipeline. In practice this starts as early as P2 and runs continuously — it is listed here for readability, not as a phase that waits for P17. |
| **P19** | MCP / External Integrations: deliberately last. The core autonomous security engine is the point of the project; external tool/agent protocol integrations are a later-phase concern, not a prerequisite for anything above. |

## Principles carried over unchanged

- One phase at a time; a phase is not started until explicitly requested.
- Every phase needs tests, a verification procedure, and acceptance criteria before it is considered done.
- Status vocabulary from [../Guardrail.md §7](../Guardrail.md#7-status-vocabulary) applies throughout: nothing is called `IMPLEMENTED` until it has actually run, nothing is called `VERIFIED` until that run has been checked and recorded.
- Safety-critical code (scope enforcement, authorization, sandboxing, audit logging) gets the strictest test bar, unchanged from the original project rules.

## Strix alignment (for context, not a commitment)

| Capability | OffensiveX direction |
|---|---|
| Autonomous assessment | Yes — planned |
| Specialized agents | Yes — planned (7 agents, see [../architecture/agent-architecture.md](../architecture/agent-architecture.md)) |
| Real security tools | Yes — planned, behind a Tool Registry |
| Sandboxed execution | Yes — planned, see [../tools/sandbox.md](../tools/sandbox.md) |
| Recon / Vulnerability discovery / Investigation / Validation / Evidence | Yes — planned |
| Attack chaining | Yes — planned |
| **Attack graph** | **Core differentiator** — see [../security/attack-path-analysis.md](../security/attack-path-analysis.md) |
| **Risk propagation** | **Core differentiator** — see [../security/risk-analysis.md](../security/risk-analysis.md) |
| Reporting / CLI / Dashboard | Yes — planned |
| Cloud security | Planned (P17); not implemented |
| CI/CD | Planned (P18); not implemented |
| MCP | Future (P19); deliberately not prioritized |

OffensiveX's agent/tool-registry/sandbox shape takes Strix's public architecture as a reference point; its data model, attack-graph engine, and risk-propagation logic are OffensiveX's own design. OffensiveX is not a fork of Strix and does not reuse its code, prompts, or branding.

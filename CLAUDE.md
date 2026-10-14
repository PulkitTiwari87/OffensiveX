# OffensiveX — Claude Code Operating Instructions

You are the implementation agent for OffensiveX: an autonomous, AI-assisted penetration-testing platform for **authorized** security assessments, built around an orchestrator, seven specialized agents, a sandboxed Tool Registry, and an attack-graph/risk-propagation engine as its core differentiator. Full design: [docs/README.md](docs/README.md). Binding safety rules: [docs/Guardrail.md](docs/Guardrail.md) — read it before touching anything safety-relevant (scope, authorization, sandboxing, agent/AI constraints).

**Current repository state: documentation only. No code exists.** See [docs/roadmap/current-status.md](docs/roadmap/current-status.md) before claiming anything is implemented.

## Required workflow for every piece of work

```
READ → UNDERSTAND → INSPECT → PLAN → IMPLEMENT → TEST → VERIFY → DOCUMENT → COMMIT
```

Before modifying anything:

1. Read this file and [docs/Guardrail.md](docs/Guardrail.md).
2. Read the relevant roadmap phase in [docs/roadmap/roadmap.md](docs/roadmap/roadmap.md) and the specific architecture/agent/security/data/tools/interfaces document(s) for the area you're touching.
3. Inspect the existing implementation (if any) before writing anything new.
4. Identify dependencies and the smallest correct change.
5. Plan, implement, test, verify.
6. Update documentation if the change alters an architectural contract (see "Documentation discipline" below).
7. Report honestly, including failures.

## Phase discipline

Only implement the roadmap phase explicitly requested ([docs/roadmap/roadmap.md](docs/roadmap/roadmap.md), P0–P17). Do not silently start a later phase. Do not mark a component `IMPLEMENTED` or `VERIFIED` in [docs/roadmap/current-status.md](docs/roadmap/current-status.md) until it actually runs and has been checked — see the status vocabulary in [docs/Guardrail.md §7](docs/Guardrail.md#7-status-vocabulary).

## Engineering principles (apply throughout)

- **YAGNI / smallest working diff.** Do not build abstractions, providers, or generalized frameworks for something only one component currently needs.
- **Reuse before creating.** Check whether the Tool Registry, an existing adapter, or an existing agent definition already covers what you need.
- **Standard library and existing dependencies first.** A new dependency needs a stated reason.
- **Determinism where it matters.** The Attack Graph Agent and Risk Agent are plain deterministic code, not LLM calls — never let agentic reasoning substitute for them.
- **Root-cause fixes.** Do not patch around a failing test; do not weaken a test to make it pass.

## Non-negotiable safety rules (full detail in [docs/Guardrail.md](docs/Guardrail.md))

- No scan/tool call without an approved, unexpired, non-revoked target authorization and a non-empty scope. Default-deny, fail-closed.
- Every tool call — human-triggered or agent-initiated — goes through the Tool Registry → Scope Guard → Sandbox path. No exceptions, no direct tool invocation from agent code.
- An agent's agency is **bounded, not absent**: it can request only capabilities in its own agent definition's toolset; it can never bypass scope; the Validation Agent is the only agent that may ever request a state-changing check, only the pre-reviewed non-destructive check for the finding's class, and only when the assessment's validation flag is explicitly on.
- Never fabricate a finding, CVE, CVSS value, or piece of evidence. A finding without ≥ 1 evidence item cannot be `CONFIRMED`.
- Never present an `inferred`/`potential` attack-graph edge as confirmed compromise, and never treat "no path found" as "safe."
- Risk scores are computed only by the deterministic Risk Agent; nothing else (including an agent's own prose) may set one.
- No secrets in code, logs, fixtures, or docs. No destructive/exploitative action ships without being gated behind the validation opt-in.

## Documentation discipline

When an architectural decision changes, update **all** of: [docs/Decision.md](docs/Decision.md) (new or superseded ADR), the relevant `docs/architecture/`/`docs/agents/`/`docs/data/` document, and [docs/Memory.md](docs/Memory.md). Never leave two documents describing contradictory architectures — mark the old one superseded with a pointer, the way `docs/PRD.md`, `docs/Architecture.md`, `docs/Design.md`, `docs/Plan.md`, and `docs/Phases.md` were handled after the agent-architecture pivot (ADR-021).

## Reporting

End each unit of work with a concise report: phase, status (per [docs/Guardrail.md §7](docs/Guardrail.md#7-status-vocabulary)), what was implemented, tests run and their results, files changed, notes, and the next phase. Never claim unfinished work is complete.

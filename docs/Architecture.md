# OffensiveX — Architecture (SUPERSEDED)

**This document is superseded.** It described a modular-monolith pipeline (fixed scan steps, single Execution Engine, deterministic engines, a tool-less advisory LLM) rather than the current agent-based design. See ADR-021 in [Decision.md](Decision.md) for why the project pivoted, and [roadmap/current-status.md](roadmap/current-status.md) for what honestly exists today (nothing is implemented yet, under either design).

Much of this document's *engineering substance* carried forward unchanged and now lives in the new tree instead of being duplicated here:

| What this document covered | Now documented in |
|---|---|
| High-level architecture, component catalog | [architecture/overview.md](architecture/overview.md), [architecture/system-architecture.md](architecture/system-architecture.md) |
| Tool execution architecture (Execution Engine) | [architecture/execution-model.md](architecture/execution-model.md), [architecture/tool-architecture.md](architecture/tool-architecture.md) |
| Authorization and scope architecture | [Guardrail.md §2](Guardrail.md#2-scope-mandatory-default-deny) (unchanged), [architecture/security-boundary.md](architecture/security-boundary.md) |
| Canonical finding / asset data model | [data/data-model.md](data/data-model.md), [data/findings.md](data/findings.md) |
| Risk engine | [security/risk-analysis.md](security/risk-analysis.md) |
| Attack path architecture | [data/attack-graph.md](data/attack-graph.md), [security/attack-path-analysis.md](security/attack-path-analysis.md) |
| AI/ML architecture, LLM safety and grounding | [architecture/security-boundary.md](architecture/security-boundary.md) (the "no agency" → "bounded agency" change is recorded there and in [Guardrail.md §5](Guardrail.md#5-ai--llm--agents)) |
| Cloud security architecture | [roadmap/roadmap.md](roadmap/roadmap.md) (P17) — not yet re-specified in detail; flagged as a gap in [roadmap/current-status.md](roadmap/current-status.md) |
| Database architecture | [data/data-model.md](data/data-model.md) |

Kept only as a pointer so old links still resolve.

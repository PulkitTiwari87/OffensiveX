# OffensiveX Documentation

Status: documentation phase. **No code exists yet** — every document below describes a `PLANNED` design unless it says otherwise. See [roadmap/current-status.md](roadmap/current-status.md) for the single source of truth on what is implemented.

> OffensiveX is an autonomous, AI-assisted penetration-testing platform for **authorized** security assessments. It orchestrates specialized agents over a controlled tool registry, turns raw tool output into evidence-backed findings, builds an attack graph across the assessed environment, computes path-aware risk, and produces evidence-linked reports. Its core differentiator is **attack-path intelligence and risk propagation**: a weakness is scored not just by how dangerous it is in isolation, but by what it lets an attacker reach next.

OffensiveX's agent-and-tool-registry approach is **inspired by the public architecture of projects like Strix** (orchestrator → specialized agents → tool abstraction → sandboxed execution). OffensiveX is an original implementation with its own data model, risk logic, and attack-graph engine — it is not a fork or clone, and does not reuse Strix code or branding.

## How this documentation is organized

| Directory | Contents |
|---|---|
| [architecture/](architecture/overview.md) | System design: layers, agents, tools, execution model, security boundary. |
| [agents/](agents/orchestrator.md) | One document per agent: purpose, inputs, tools, outputs, decision logic, constraints. |
| [security/](security/reconnaissance.md) | How each assessment capability actually works (recon → validation → attack paths → risk). |
| [data/](data/data-model.md) | The data model: assessments, observations, findings, evidence, attack graph. |
| [tools/](tools/tool-registry.md) | The tool abstraction and the categories of tools behind it. |
| [interfaces/](interfaces/api.md) | API, CLI, and dashboard as seen by a user. |
| [reporting/](reporting/reporting.md) | Report structure and output formats. |
| [deployment/](deployment/docker.md) | Running OffensiveX locally and in containers. |
| [roadmap/](roadmap/current-status.md) | Honest status table, the build order, the [implementation blueprint](roadmap/implementation-blueprint.md), and [architecture risks](roadmap/architecture-risks.md). |
| [Guardrail.md](Guardrail.md) | Binding safety rules (scope, authorization, sandboxing, AI constraints). Read this one first. |
| [Decision.md](Decision.md) | Architecture Decision Records (ADR log, including the agent-architecture pivot, ADR-021). |
| [Memory.md](Memory.md) | Durable cross-session project memory for Claude Code. |

## Documents superseded by this pivot

`PRD.md`, `Architecture.md`, `Design.md`, `Plan.md`, and `Phases.md` at the `docs/` root described an earlier, non-agentic "modular monolith" direction (deterministic pipeline, LLM strictly advisory with no tool access). That direction has been superseded by the agent-based architecture described here. Those five files now contain a short redirect notice plus a summary of what changed, so links and history are not lost. **Guardrail.md** and **Decision.md** were kept and updated in place, since scope/authorization/audit rules and the ADR log both carry forward.

## Status vocabulary

Used consistently across every document in this tree:

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | Exists in the repository and runs. |
| `PARTIAL` | Some of it exists; the rest is designed but not built. |
| `PLANNED` | Designed here; no code yet. |
| `FUTURE` | Deliberately deferred; not part of the near-term build order. |

Today, every component in this repository is `PLANNED`. Nothing in these documents should be read as "implemented" unless [roadmap/current-status.md](roadmap/current-status.md) says so.

## Before writing any code

Read [architecture/implementation-summary.md](architecture/implementation-summary.md) — the single developer-facing entry point that ties this whole tree together — and [roadmap/implementation-blueprint.md](roadmap/implementation-blueprint.md), which traces every capability to concrete backend/agent/database/API/frontend/tooling/test components and defines the MVP and first vertical slice. [roadmap/architecture-risks.md](roadmap/architecture-risks.md) lists the risks to watch for while implementing.

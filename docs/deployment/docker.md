# Docker

Status: PLANNED — no Dockerfile or Compose file exists yet.
Related: [../tools/sandbox.md](../tools/sandbox.md) · [local-development.md](local-development.md)

## Why Docker is central to this architecture

Docker is not only a deployment convenience here — it **is** the sandbox described in [../tools/sandbox.md](../tools/sandbox.md). Every tool execution an agent triggers is planned to run in its own ephemeral container, isolated from the API/orchestrator/agent-worker processes and from other assessments' containers.

## Planned topology

| Service | Role |
|---|---|
| `api` | REST API + serves the dashboard SPA |
| `orchestrator` | Schedules agent runs, owns assessment state |
| `agent-worker` | Executes agent runs (LLM session + bounded toolset) |
| `sandbox` (per tool execution, ephemeral) | Non-root, resource-limited, network-restricted container that actually runs a tool |
| `postgres` | All persistent state |
| `lab` (separate Compose profile) | Deliberately vulnerable target(s), bound to loopback only |

## Hardening requirements carried over unchanged

Non-root containers, dropped capabilities, read-only root filesystem where feasible, resource limits, and an egress policy restricting the `sandbox` role's outbound traffic to destinations the Scope Guard has already approved — all unchanged from the original deployment design (see [../Guardrail.md](../Guardrail.md), [../Decision.md](../Decision.md) ADR-016). No Kubernetes, no service mesh — Docker Compose is sufficient for the planned scale and keeps the deployment reviewable.

## Status

No `Dockerfile`, `docker-compose.yml`, or `labs/` directory exists in the repository yet. This page is the target design, to be implemented starting in the roadmap's foundation phase ([../roadmap/roadmap.md](../roadmap/roadmap.md), P0–P4 — compose/postgres from P0, the sandbox/execution-layer container work specifically at P4).

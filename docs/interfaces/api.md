# API

Status: PLANNED — no endpoint below exists yet.
Related: [../data/data-model.md](../data/data-model.md) · [cli.md](cli.md) · [dashboard.md](dashboard.md)

No API is implemented. This page specifies the **planned** surface so the CLI/dashboard documents have something concrete to reference; every row is `PLANNED` until [../roadmap/current-status.md](../roadmap/current-status.md) says otherwise. Base path, conventions (JSON, UUIDs, cursor pagination, `problem+json` errors) follow the original API conventions unchanged.

| Method | Path | Purpose | Auth | Lifecycle impact |
|---|---|---|---|---|
| POST | `/api/v1/targets` | Register a target | session | — |
| POST | `/api/v1/targets/{id}/authorizations` | Submit scope + attestation for approval | session | Required before any assessment on this target. |
| POST | `/api/v1/targets/{id}/authorizations/{v}/approve` | Approve an authorization version | session, `admin` | Makes the target assessable. |
| POST | `/api/v1/assessments` | Create an assessment (target, scan mode, validation flag) | session | Creates `Assessment` in `pending`; orchestrator schedules Recon. |
| GET | `/api/v1/assessments/{id}` | Assessment status and stage progress | session | — |
| POST | `/api/v1/assessments/{id}/cancel` | Cancel a running assessment | session | Stops scheduling further agent runs; terminates in-flight tool calls. |
| GET | `/api/v1/assessments/{id}/assets` | Discovered assets | session | — |
| GET | `/api/v1/assessments/{id}/findings` | Findings (filterable by status/severity/risk) | session | — |
| PATCH | `/api/v1/findings/{id}/status` | Analyst triage after `CONFIRMED` (accept risk / mark fixed) | session, `analyst` | Does not affect the `DISCOVERED…CONFIRMED/REJECTED` agent lifecycle, which is agent/validation-owned. |
| GET | `/api/v1/assessments/{id}/attack-paths` | Computed attack paths | session | — |
| POST | `/api/v1/assessments/{id}/reports` | Generate a report | session, `analyst` | Creates an immutable `Report`. |
| GET | `/api/v1/reports/{id}` | Fetch a generated report | session | — |
| GET | `/healthz`, `/readyz` | Liveness / readiness | none | — |

Every endpoint will also appear in the authorization-matrix test described in the roadmap's hardening phase before it ships, following the same discipline the original design required (`Guardrail.md`, API hardening phase).

## Not planned for the near term

Public/unauthenticated API access, webhooks, and GraphQL are not planned; see [../roadmap/roadmap.md](../roadmap/roadmap.md) P19 for external/MCP integration, which is explicitly a later-phase concern.

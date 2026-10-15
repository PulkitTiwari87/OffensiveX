# API

Status: IMPLEMENTED for every endpoint below (verified against real PostgreSQL — see
[../roadmap/current-status.md](../roadmap/current-status.md)). Interactive schema at
`/docs` and `/openapi.json` in development/test only; **disabled in production**.
Related: [../data/data-model.md](../data/data-model.md) · [cli.md](cli.md) · [dashboard.md](dashboard.md) · [../security/access-control.md](../security/access-control.md)

Conventions: JSON, UUID ids, base path `/api/v1`, errors are RFC 9457 `application/problem+json`
with a `request_id` that matches the `X-Request-ID` response header and the server logs.
Validation errors report only `loc`/`msg`/`type` (never the submitted value).

## Authentication

Cookie sessions (ADR-012). `POST /auth/login` sets an `HttpOnly; SameSite=Strict` cookie and
returns a `csrf_token`; send it back as `X-CSRF-Token` on every `POST`/`PATCH`/`PUT`/`DELETE`.
`GET /auth/me` returns the current user and the same token (use it after a page reload).
No cookie / expired / revoked → **401**. Wrong role, missing CSRF token, self-approval,
self-escalation → **403**. Too many failed logins → **429**.

## Endpoints

"Permission" is the capability required (role mapping in
[access-control.md](../security/access-control.md): viewer < analyst < admin).

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/healthz`, `/readyz` | public | liveness / readiness |
| POST | `/api/v1/auth/login` | public (throttled) | body `{username, password}` |
| POST | `/api/v1/auth/logout` | any authenticated | revokes the session server-side; 204 |
| GET | `/api/v1/auth/me` | any authenticated | |
| POST | `/api/v1/targets` | `targets:write` | register a target. Optional `entry_point`: an http(s) URL where assessment starts (see below). **422** `Invalid entry point` if malformed/ambiguous or (unless `OFFENSIVEX_ALLOW_PRIVATE_TARGETS=true`) loopback/private |
| GET | `/api/v1/targets/{id}` | `data:read` | includes the normalized `entry_point` (null for legacy targets) |
| POST | `/api/v1/targets/{id}/authorizations` | `targets:write` | submit scope + attestation (records the submitter). Each `scope_rules[]` item is `{rule_type, pattern, is_exclusion?, ports?}`; `ports` is e.g. `"80,443,8000-8100"` (omitted: an include rule covers 80/443 only, an exclude rule covers every port — [security/network-safety.md](../security/network-safety.md)). **422** `Invalid scope rule` for a malformed/catch-all `ports`, and `Entry point outside authorized scope` if the target's entry-point host *or port* is not covered |
| POST | `/api/v1/targets/{id}/authorizations/{v}/approve` | `authorizations:decide` | admin only; **403** if you submitted it, unless `OFFENSIVEX_ALLOW_SELF_APPROVAL=true` |
| POST | `/api/v1/targets/{id}/authorizations/{v}/reject` | `authorizations:decide` | a rejected version can never be approved |
| POST | `/api/v1/assessments` | `assessments:write` | requires an approved, unexpired authorization; schedules Recon |
| GET | `/api/v1/targets` | `data:read` | all targets |
| GET | `/api/v1/targets/{id}/authorizations` | `data:read` | every version with `status`, `attestation`, `scope_rules[{rule_type, pattern, is_exclusion, ports}]` |
| GET | `/api/v1/assessments` | `data:read` | `?status=&target_id=&limit(≤200)=`; newest first, each with `target_name`, `finding_count` |
| POST | `/api/v1/assessments/{id}/run` | `assessments:write` | **202**. Starts the agent pipeline in the background of the server process. **503** if no LLM is configured (nothing changes); **409** if the assessment is not newly created/running, has already started, or is already running in this process. Audited as `pipeline.run`. Scope and authorization were enforced at creation and are enforced again by the Scope Guard on every tool call |
| GET | `/api/v1/assessments/{id}` | `data:read` | includes `agent_runs[]` with `status`, `error` (why a stage failed), timestamps |
| GET | `/api/v1/assessments/{id}/reports` | `data:read` | reports of one assessment, newest first |
| GET | `/api/v1/findings` | `data:read` | `?assessment_id=&status=&severity=&limit(≤500)=`; newest first |
| GET | `/api/v1/overview` | `data:read` | counts by assessment status / finding severity / finding status, recent assessments |
| GET | `/api/v1/system/status` | `data:read` | environment, LLM `{enabled, provider, model}`, `allow_private_targets`, `allow_self_approval`, `session_ttl_minutes`. Never the API key, base URL or secret key |
| POST | `/api/v1/assessments/{id}/cancel` | `assessments:write` | |
| GET | `/api/v1/assessments/{id}/assets` | `data:read` | |
| GET | `/api/v1/assessments/{id}/findings` | `data:read` | `?status=` filter |
| GET | `/api/v1/findings/{id}` | `data:read` | with evidence, `risk_score`, `risk_breakdown` |
| GET | `/api/v1/findings/{id}/ml-advisory` | `data:read` | optional ML estimates (ADR-026), separate from the finding; `ml_advisory: []` = none available (feature off, no/invalid model, non-CVE finding), never "safe" |
| PATCH | `/api/v1/findings/{id}/status` | `findings:override` | body `{status: "confirmed"\|"rejected", reason?}`; the state machine still applies; audited with the reason |
| GET | `/api/v1/assessments/{id}/attack-paths` | `data:read` | |
| POST | `/api/v1/assessments/{id}/reports` | `reports:generate` | body `{formats?: ["json","markdown"]}`; immutable; 201. If the LLM is enabled the report may carry an AI summary — see `provenance.ai_summary.status` (`generated` \| `failed` \| `skipped`) |
| GET | `/api/v1/reports/{id}` | `data:read` | |
| POST | `/api/v1/users` | `users:manage` | body `{username, password, role}`; password 12–256 chars |
| GET | `/api/v1/users` | `users:manage` | never includes password hashes |
| PATCH | `/api/v1/users/{id}` | `users:manage` | `{role?, is_active?}`; **cannot target yourself**; ends the user's sessions |
| GET | `/api/v1/audit-log` | `audit:read` | `?action=&actor_user_id=&limit(≤500)=&offset=`; read-only |

An inventory test fails the build if a route exists that is not in the access-control matrix.

### Target entry points

`entry_point` is validated by one strict parser (`offensivex/core/urls.py`) and stored normalized
(lowercase scheme/host, default port dropped, path defaulted to `/`, trailing host dot removed).
Accepted: `http`/`https`, a DNS name or canonical IP literal (IPv6 in brackets), an optional port
1–65535, an optional path. **Rejected (422):** other schemes, credentials (`user@host`), backslashes,
whitespace/control characters, non-ASCII hosts (use punycode), fragments, query strings (they can
carry secrets), port 0 / non-numeric / out-of-range ports, malformed DNS names, non-canonical
numeric hosts (`2130706433`, `127.1`, `0x7f.1`), and input over 2048 characters.

The entry point must also be covered by the authorization's scope: submitting an authorization whose
rules do not allow its host returns **422** `Entry point outside authorized scope`, and creating an
assessment re-checks it against the approved rules. It is a starting point, never extra permission.
It cannot be changed after creation (create a new target); existing targets keep `entry_point: null`.

## Not exposed over HTTP (by design)

- **Starting the agent pipeline** (it spends LLM money and launches scans): `python -m offensivex.admin run-assessment`.
- **Creating the first admin / resetting a password:** `python -m offensivex.admin create-user|set-password`.

## Not planned for the near term

Public/unauthenticated data access, webhooks, and GraphQL; see
[../roadmap/roadmap.md](../roadmap/roadmap.md) P19 for external/MCP integration, which is
explicitly a later-phase concern. API tokens / SSO are `FUTURE` (ADR-012).

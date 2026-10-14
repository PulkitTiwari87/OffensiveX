# Access control: authentication, RBAC, audit log

Status: IMPLEMENTED and tested against real PostgreSQL (see
[../roadmap/current-status.md](../roadmap/current-status.md)). Decisions:
ADR-012, ADR-013, ADR-022 in [../Decision.md](../Decision.md).

Two different questions are answered by two independent mechanisms and neither
trusts the other:

1. **May this *user* do this?** — RBAC, this document.
2. **May this *system* touch this *target*?** — the target-authorization gate and
   the Scope Guard ([Guardrail.md](../Guardrail.md) §2). Nothing in this document
   weakens or bypasses it, and an LLM's output is an input to neither.

## Authentication

| Aspect | Implementation |
|---|---|
| Accounts | Local accounts in `users`. **No default account, no self-registration.** The first admin is created with `python -m offensivex.admin create-user --username <n> --role admin` (password via prompt or `--password-stdin`, never an argument). |
| Passwords | argon2id (`argon2-cffi` defaults, parameters stored in each hash; rehashed on login if parameters are raised). 12–256 characters. Unknown usernames cost a real hash verification (no timing oracle). |
| Sessions | Server-side, in `auth_sessions`. The browser holds an opaque random token; the database holds **only its SHA-256**. Absolute lifetime `OFFENSIVEX_SESSION_TTL_MINUTES` (default 480). Revoked on logout, password change, role change, and deactivation; a deactivated user's sessions fail immediately because every request re-checks `users.is_active`. |
| Cookie | `ofx_session`; `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` in every environment except `development`/`test`. |
| CSRF | Synchronizer token returned by `POST /auth/login` and `GET /auth/me`, required in `X-CSRF-Token` on every state-changing request (constant-time compare). A bad/missing token → 403 and an audit row. |
| Brute force | After `OFFENSIVEX_LOGIN_MAX_FAILURES` (5) failed logins for a username within `OFFENSIVEX_LOGIN_FAILURE_WINDOW_MINUTES` (15) → 429, even for the right password. Counted from the audit log, so it survives restarts and works across workers. |
| Failure messages | Wrong password, unknown user, and deactivated account are indistinguishable (`401 Invalid username or password.`). |
| Secrets | Passwords, tokens and keys are never logged (the logger redacts by key *and* validation errors no longer echo submitted values), never returned (`password_hash` is in no response model), and never stored in audit `details` (scrubbed). |

## Roles and permissions

Defined in one file, `backend/src/offensivex/auth/permissions.py`. Deny by default:
a role has only what is listed, and an unknown role has nothing. Routes declare a
`Permission` via `require_permission(...)`; no route compares role names.

| Permission | viewer | analyst | admin |
|---|:-:|:-:|:-:|
| `data:read` — assessments, assets, findings, attack paths, reports | ✔ | ✔ | ✔ |
| `targets:write` — create target, submit authorization | | ✔ | ✔ |
| `assessments:write` — create / cancel | | ✔ | ✔ |
| `findings:override` — analyst status override | | ✔ | ✔ |
| `reports:generate` | | ✔ | ✔ |
| `authorizations:decide` — approve / reject scope | | | ✔ |
| `users:manage` | | | ✔ |
| `audit:read` | | | ✔ |

Roles are strictly nested (viewer ⊂ analyst ⊂ admin); a test asserts it.

Rules that are not just a permission check:

- **Separation of duties.** An admin may not approve an authorization they
  submitted themselves unless `OFFENSIVEX_ALLOW_SELF_APPROVAL=true` (default
  false; intended for single-user labs). The refusal is audited.
- **No self-escalation.** Nobody can change their *own* role or active state —
  not even an admin — so a user cannot raise their own privileges and the system
  cannot be left without an admin by one account's own action. A role change or
  deactivation ends the target's sessions.
- **Approval workflow intact.** A rejected or revoked authorization cannot be
  approved; the state machine still applies.

## Route classification

Every route is public, authenticated, or restricted to one permission. This table is
enforced by `test_every_route_is_classified` (fails on any route not listed here
or in the test's matrix) and `test_rbac_matrix_is_enforced_for_every_role`.

| Method & path | Access |
|---|---|
| `GET /healthz`, `GET /readyz` | **public** (no data; probes) |
| `POST /api/v1/auth/login` | **public** (it *is* the credential check; throttled) |
| `GET /openapi.json`, `/docs`, `/redoc` | public in development/test; **disabled in production** |
| `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` | authenticated (any role) |
| `POST /api/v1/targets` | `targets:write` |
| `GET /api/v1/targets/{id}` | `data:read` |
| `POST /api/v1/targets/{id}/authorizations` | `targets:write` |
| `POST /api/v1/targets/{id}/authorizations/{v}/approve` | `authorizations:decide` + self-approval rule |
| `POST /api/v1/targets/{id}/authorizations/{v}/reject` | `authorizations:decide` |
| `POST /api/v1/assessments`, `POST …/{id}/cancel` | `assessments:write` |
| `GET /api/v1/assessments/{id}` and `…/assets`, `…/findings`, `…/attack-paths` | `data:read` |
| `GET /api/v1/findings/{id}` | `data:read` |
| `PATCH /api/v1/findings/{id}/status` | `findings:override` |
| `POST /api/v1/assessments/{id}/reports` | `reports:generate` |
| `GET /api/v1/reports/{id}` | `data:read` |
| `POST /api/v1/users`, `GET /api/v1/users`, `PATCH /api/v1/users/{id}` | `users:manage` |
| `GET /api/v1/audit-log` | `audit:read` |

Status codes: no/invalid/expired/revoked session → **401**; authenticated but
not permitted (or CSRF failure, self-approval, self-escalation) → **403**;
throttled login → **429**.

Not covered by the API at all (by design): the agent pipeline. It is started by
`python -m offensivex.admin run-assessment`, i.e. by someone with shell access to
the deployment — there is deliberately no HTTP route that spends LLM money or
launches scans yet.

## Audit log

Table `audit_log` (migration `0004_auth_and_audit`):

| Column | Notes |
|---|---|
| `id` uuid PK, `occurred_at` timestamptz (server default `now()`) | indexed on `occurred_at` |
| `actor_user_id` → `users.id` (nullable), `actor_username` varchar(100) | null user for failed logins / CLI (`cli:<os user>`); indexed on `actor_user_id` |
| `action` varchar(100), `outcome` enum `success` \| `denied` \| `failure` | `action` indexed |
| `target_type`, `target_id` | what was acted on |
| `request_id` varchar(64) | the `X-Request-ID` of the request (client values accepted only if `[A-Za-z0-9._-]{1,64}`, else replaced), matching the id in logs and error bodies |
| `details` jsonb | scrubbed: secret-looking keys dropped, strings truncated, NUL removed |

**Append-only in the database:** triggers reject `UPDATE`, `DELETE`, `TRUNCATE`
(tested). There is no write or delete API. `actor_user_id` has no `ON DELETE`
action and users are never deleted, so history cannot be edited indirectly.

**Transaction behaviour:** a *successful* sensitive action writes its row in the
same transaction (atomic with the change). A *denial or failure* writes in its own
committed transaction so it survives the request's rollback. A failure to write a
denial row is logged loudly and never changes the response.

Covered events: `auth.login` (success/failure), `auth.login.throttled`,
`auth.logout`, `authz.denied`, `authz.csrf_rejected`, `target.create`,
`authorization.submit`, `authorization.approve` (incl. denied self-approval),
`authorization.reject`, `assessment.create`, `assessment.cancel`,
`finding.status_override` (from/to/reason), `report.generate`, `user.create`,
`user.update` (from/to role & active), `user.set_password`, `pipeline.run`.

## Known limitations (honest list)

- A database owner/superuser can drop the audit trigger; the log is not hash-chained
  (ADR-022). It resists the application and API users, not the DBA.
- The login throttle is per-username, so an attacker can temporarily lock a known
  username out (15 min); IP-level rate limiting is Phase 16. Failed-login rows for
  unknown usernames are attacker-fillable; there is no retention policy yet.
- No self-service password change (an admin uses `admin set-password`, which ends
  the user's sessions); no MFA / SSO / API tokens (ADR-012: `FUTURE`).
- The CLI is trusted by virtue of shell + database access; it is audited with the
  OS user name but not authenticated.
- Sessions are absolute-lifetime only (no idle timeout).
- Cookie `Secure` and HTTPS termination depend on the deployment; the UI and API
  must be served from one site for `SameSite=Strict` to work (ADR-012).

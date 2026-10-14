# Dashboard

Status: **IMPLEMENTED** (P15) — `frontend/` (React + TypeScript strict + Vite, per ADR-001; React Router; plain CSS).
Related: [api.md](api.md) · [cli.md](cli.md) · [../security/access-control.md](../security/access-control.md)

## Run it

```bash
cd frontend && npm ci && npm run build      # outputs frontend/dist
cd ../backend && uvicorn offensivex.main:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000/dashboard/
```

The backend serves `frontend/dist` at `/dashboard` (override with `OFFENSIVEX_DASHBOARD_DIR`; no build → no mount, the API runs as before). One origin means the HttpOnly `SameSite=Strict` session cookie works with no CORS. `npm run dev` (port 5173, proxies `/api` to 8000) is for UI development.

## Pages

| Page | Shows | Source |
|---|---|---|
| Overview | assessment/finding counts, recent assessments, LLM/config notice | `GET /overview`, `/system/status` |
| Targets / target detail | targets with entry points; authorizations with every scope rule (host, port, include/exclude; approve/reject for admins); submit scope; create assessment | `/targets`, `/targets/{id}/authorizations` |
| Assessments / detail | status, agent runs with failure reasons, start/cancel, live refresh while running, findings, assets, attack paths, reports | `/assessments*` |
| Findings / detail | filter by status/severity/assessment, sortable; evidence (as inert text), risk score and breakdown, analyst override | `/findings*` |
| Report | Markdown / JSON as text, download | `/reports/{id}` |
| Audit | audit log (admin only; others get the server's 403 message) | `/audit-log` |

Every view is persisted state: empty states say so (e.g. "No attack paths were derived. This does not mean the target is safe"), nothing is sample data.

## Security

- Login goes through `POST /auth/login`; the cookie is HttpOnly so scripts cannot read it. The CSRF token is held in memory only and re-fetched from `/auth/me` after a reload; it is sent as `X-CSRF-Token` on every mutation.
- Nothing is written to `localStorage`/`sessionStorage` (tested). Passwords are cleared from the form after submit.
- Hiding controls by role (`capabilities()` in `src/auth.tsx`) is display only. The server enforces every permission; a rejected action surfaces the server's message.
- Evidence and report text come from scanned targets and are rendered with React text nodes / `<pre>`, never as HTML.

## Verified

- `npm run typecheck`, `npm test` (21 tests: API client incl. CSRF/storage/error mapping, login, role-based controls, authorization view, assessment failure/launch, findings sort/empty/inert evidence), `npm run build` — also replayed from a clean `npm ci` copy, matching the CI `frontend` job.
- `backend/tests/integration/test_dashboard_api.py` — the API contracts above, static mount with and without a build.
- Driven in a browser against a real backend and PostgreSQL: sign-in, overview, target detail with port-level scope, creating an assessment and pressing **Start run** (real Gemini pipeline, live progress, 3 findings), assessment detail with a recorded provider failure, results consistent with the CLI.

## Not built / limits

No charts or graph canvas (attack paths are a table of hops and evidence level, not a drawn graph); no user-management page; no SSE (polling every 3 s); no browser E2E suite (component tests with a stubbed `fetch`, plus the manual browser run above); accessibility checked by role/label queries in tests only, not with an audit tool.

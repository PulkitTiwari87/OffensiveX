# Dashboard

Status: **IMPLEMENTED** (P15) — `frontend/` (React + TypeScript strict + Vite, per ADR-001; React Router; plain CSS). UI redesigned onto a token-based design system (sidebar shell, shared components in `src/ui.tsx`, tokens in `src/styles.css`); no new dependencies.
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
| Audit | audit log with client-side search over the loaded entries and the server `action` filter (admin only; others get the server's 403 message) | `/audit-log` |
| System | environment, LLM provider/model (never keys or URLs), private-target and self-approval switches with warnings, session lifetime | `GET /system/status` |

Shell and interaction rules: left sidebar (drawer below 900 px), breadcrumbs, skip link; dark workspace with a light theme that follows the OS setting; severity and status are always icon + text, never colour alone; wide tables become labelled rows below 720 px; `prefers-reduced-motion`, `prefers-reduced-transparency` and `prefers-contrast` are honoured. Consequential actions (approve/reject scope, start/cancel assessment, finding override) ask for confirmation in a focus-trapped dialog and show a toast on success; server refusals stay visible inline. Search boxes filter the data already loaded; status/severity filters are sent to the server.

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

Redesign verification (honest scope): after the redesign, `npm run typecheck`, `npm test` (29 tests, incl. confirm dialogs, search, tabs, system page, shell navigation) and `npm run build` pass, and the production build was inspected in the browser pane at desktop and phone widths against a **local mock API with synthetic data** (layout, drawer, stacked tables, dialog, no horizontal overflow). It has **not** yet been re-driven against the real backend after the redesign. No ESLint is configured in this project. The Targets list has no per-target scope/authorization status because `GET /targets` does not return one (would need a backend field), and there is no global Reports list because reports are only listed per assessment. The Stitch MCP produced one screen (Overview) and a design system; later screens timed out, so the remaining layouts follow that shell.

No charts or graph canvas (attack paths are a table of hops and evidence level, not a drawn graph); no user-management page; no SSE (polling every 3 s); no browser E2E suite (component tests with a stubbed `fetch`, plus the manual browser run above); accessibility checked by role/label queries in tests only, not with an audit tool.

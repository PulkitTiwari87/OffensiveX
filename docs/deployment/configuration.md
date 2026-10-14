# Configuration

Status: PLANNED — no settings module exists yet.
Related: [docker.md](docker.md) · [../Guardrail.md](../Guardrail.md)

## Approach

Environment variables, validated at startup, fail-fast on missing/weak production secrets — unchanged from the original design (`Decision.md` ADR-017 in the superseded documentation set). `.env` for local development only (git-ignored); `.env.example` committed with placeholders only. No secret value is ever logged.

## Planned variable groups (names illustrative, fixed when implemented)

| Group | Examples |
|---|---|
| Core | `OFFENSIVEX_ENV`, `OFFENSIVEX_SECRET_KEY`, `OFFENSIVEX_DATABASE_URL` |
| Agent / LLM | Provider selection, model name, API key (never hard-coded; never committed) |
| Scan safety | `OFFENSIVEX_ALLOW_PRIVATE_TARGETS` (default false; **implemented** — governs both what may be written into scope rules / entry points *and* what tools may connect to at runtime, where a private/loopback destination additionally needs an explicit scope rule for the address; cloud-metadata addresses are never allowed — [../security/network-safety.md](../security/network-safety.md)), `OFFENSIVEX_MAX_CIDR_SIZE` |
| Dashboard / CLI (**implemented**) | `OFFENSIVEX_DASHBOARD_DIR` (built dashboard served at `/dashboard`; default `<repo>/frontend/dist` if present), CLI: `OFFENSIVEX_API_URL` (default `http://127.0.0.1:8000`), `OFFENSIVEX_CLI_HOME` (session directory, default `~/.offensivex`) |
| Tests | `OFFENSIVEX_TEST_DATABASE_URL` — **use a separate database** (e.g. `offensivex_test`). The integration tests drop and recreate the schema; `tests/conftest.py` reads this key from `backend/.env` and points the whole test process at it. Without it, tests run against `OFFENSIVEX_DATABASE_URL` and erase its data |
| LLM (Gemini) | `OFFENSIVEX_LLM_PROVIDER=openai`, `OFFENSIVEX_LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/`, `OFFENSIVEX_LLM_MODEL=gemini-3.1-flash-lite` (verified 2026-10-14; `gemini-2.5-flash` answers HTTP 404 to new keys even though `/models` lists it), `OFFENSIVEX_LLM_API_KEY` |
| Validation | A global kill switch independent of any per-assessment flag, so an operator/deployment can disable validation mode entirely regardless of what any assessment requests |
| Sandbox | Container image references, resource limit defaults, egress allow-list |

## No credentials in the database or UI

Cloud credentials (where cloud security checks apply, see [../roadmap/roadmap.md](../roadmap/roadmap.md) P17) are never accepted through the API or stored in the database — only role/assume-role references, with actual credentials obtained at runtime from the environment's credential chain. This is unchanged from the original cloud-security design.

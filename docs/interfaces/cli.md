# CLI

Status: **IMPLEMENTED** (P16) — `backend/src/offensivex/cli.py`, registered as the `offensivex` console script (`pip install -e .`; also `python -m offensivex.cli`).
Related: [api.md](api.md) · [dashboard.md](dashboard.md) · [../security/access-control.md](../security/access-control.md)

## What it is

A thin client over the HTTP API. Every command except `admin` calls the same authenticated, RBAC-checked, scope-enforcing routes as the dashboard, so it has no privileged path: a viewer cannot launch an assessment from the CLI, scope approval needs an admin who is not the submitter, and `assessment run` asks the server to run the normal orchestrator → agents → Tool Registry path.

`offensivex admin create-user|set-password` is the exception: it talks to the database directly (the first administrator must exist before anyone can log in). It reuses `offensivex.admin` and writes an audit row.

## Commands

| Command | Purpose |
|---|---|
| `status` | API health/readiness; when logged in, environment, LLM provider/model (never the key), private-target and self-approval switches |
| `login [--username] [--password-stdin]` / `logout` / `whoami` | session handling |
| `admin create-user --username U --role viewer\|analyst\|admin [--password-stdin]`, `admin set-password` | local account setup |
| `target create --name N --type T [--entry-point URL] [--exposure] [--criticality]`, `target list`, `target show T` | targets (by name or id) |
| `authorization submit T --include TYPE:PATTERN[@PORTS] [--exclude ...] --attestation TEXT [--valid-days N]`, `authorization list T`, `authorization approve\|reject T VERSION` | scope. `domain:localhost@8000-8100`; an include without `@PORTS` covers 80/443 only, an exclude without it covers all ports |
| `assessment create T [--mode quick\|standard\|deep] [--validate]`, `assessment run ID [--wait]`, `assessment show ID`, `assessment list`, `assessment cancel ID` | assessments; `show` lists agent runs and failure reasons |
| `finding list [--assessment ID --status S --severity S]`, `finding show ID`, `finding override ID confirmed\|rejected [--reason]` | findings with evidence, severity, risk |
| `report generate ID [--format json\|markdown\|both] [-o FILE]`, `report list ID`, `report get ID [--format] [-o FILE]` | reports |
| `audit list [--action]` | audit log (admin) |

Global options: `--api-url` (env `OFFENSIVEX_API_URL`, default `http://127.0.0.1:8000`), `--json` for machine-readable output. `OFFENSIVEX_CLI_HOME` moves the session directory.

## Exit codes

`0` ok · `1` request rejected / operation failed · `2` usage error · `3` not logged in or bad credentials · `4` permission denied (including self-approval) · `5` not found · `6` server unreachable or server error (including "no LLM configured") · `7` `assessment run --wait` finished in a state other than `completed`.

## Secrets

Passwords come from a hidden prompt or `--password-stdin`, never an argument. After login only the session token and CSRF token are stored, in `~/.offensivex/session.json`: created `0600` on POSIX, and on Windows reduced to the current user with `icacls` (verified). The file is tied to one API URL, deleted on `logout` and when the server answers 401. Server error text is shown; request bodies are not logged.

## Verified

- `backend/tests/integration/test_cli_workflow.py` — whole operator workflow incl. RBAC refusals, self-approval, failure reasons, report files (real PostgreSQL, real local lab server, scripted model).
- `backend/tests/unit/test_cli_process.py` — the registered executable in a subprocess (help, exit codes), session file contents, logout, error→exit-code mapping.
- A real run with the installed `offensivex` executable against a real server, a local lab target and Gemini (`gemini-3.1-flash-lite`): login, target/scope/approval, `assessment run --wait` (one stage failed on a provider error and the CLI reported it and exited 7), findings with evidence and risk, Markdown report.

## Not built

`scan`/`view` shortcuts and SARIF/PDF reports from the original plan; user management commands (use the API or `admin`); shell completion.

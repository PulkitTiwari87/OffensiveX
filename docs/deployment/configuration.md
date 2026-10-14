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
| Scan safety | `OFFENSIVEX_ALLOW_PRIVATE_TARGETS` (default false), `OFFENSIVEX_MAX_CIDR_SIZE` |
| Validation | A global kill switch independent of any per-assessment flag, so an operator/deployment can disable validation mode entirely regardless of what any assessment requests |
| Sandbox | Container image references, resource limit defaults, egress allow-list |

## No credentials in the database or UI

Cloud credentials (where cloud security checks apply, see [../roadmap/roadmap.md](../roadmap/roadmap.md) P17) are never accepted through the API or stored in the database — only role/assume-role references, with actual credentials obtained at runtime from the environment's credential chain. This is unchanged from the original cloud-security design.

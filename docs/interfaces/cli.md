# CLI

Status: PLANNED — no command below exists yet.
Related: [api.md](api.md) · [../roadmap/roadmap.md](../roadmap/roadmap.md) (P16)

## Target conceptual interface

```bash
offensivex scan --target <target>
offensivex scan --target <target> --mode deep
offensivex status <assessment-id>
offensivex report <assessment-id>
offensivex view
```

| Command | Purpose | Status |
|---|---|---|
| `offensivex scan --target <target> [--mode quick\|standard\|deep] [--validate]` | Create and run an assessment against a registered, authorized target | PLANNED |
| `offensivex status <assessment-id>` | Print current stage, agent-run progress, and any errors | PLANNED |
| `offensivex report <assessment-id> [--format json\|sarif\|markdown\|pdf]` | Generate/fetch a report | PLANNED |
| `offensivex view` | Open the dashboard for the most recent (or a specified) assessment | PLANNED |
| `offensivex target add / list / authorize` | Target and scope/authorization management (mirrors the dashboard's Targets view) | PLANNED |

`--validate` is the CLI's explicit opt-in for the Validation Agent (see [../security/validation.md](../security/validation.md)); it is never implied by `--mode deep`.

## What the CLI does not do

It is a thin client over the API ([api.md](api.md)) — it has no privileged path that bypasses scope/authorization checks, and it cannot run tools directly against a target; every `scan` invocation still goes through the orchestrator → agents → Tool Registry → sandbox path described in [../architecture/execution-model.md](../architecture/execution-model.md).

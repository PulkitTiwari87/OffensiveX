# Terminal / Execution

Status: PLANNED
Related: [tool-registry.md](tool-registry.md) · [sandbox.md](sandbox.md) · [../architecture/security-boundary.md](../architecture/security-boundary.md)

## What this capability is for

A small number of validation checks and investigation steps need to run a short, specific command (e.g. to assemble a crafted request a plain HTTP client can't express, or to inspect a previously collected artifact programmatically) rather than talk to the target over the network directly. "Terminal" here means a **sandboxed shell/interpreter the agent framework controls**, not access to any host shell.

## Planned capability

| Capability | Status |
|---|---|
| Sandboxed shell (fixed, reviewed set of invocable commands) | PLANNED |
| Sandboxed Python interpreter | PLANNED |

## This is the most tightly constrained tool category

- Runs only inside the sandbox described in [sandbox.md](sandbox.md) — never on the host running OffensiveX, never with access to OffensiveX's own credentials, database, or other assessments' data.
- An agent cannot submit an arbitrary shell string; invocations are built from the same `plan()`/argv-list discipline as every other adapter (no shell, no string interpolation of untrusted input — [../architecture/execution-model.md](../architecture/execution-model.md)).
- A command that would reach outside the assessment's scope (e.g. attempt an outbound connection to a non-scoped host) is refused by the sandbox's network policy independently of what the agent intended.
- Full output is captured as `Evidence` and the exact command, exit code, and timing are audit-logged exactly like any other tool execution.

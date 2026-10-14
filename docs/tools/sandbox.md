# Sandbox

Status: PLANNED
Related: [../architecture/execution-model.md](../architecture/execution-model.md) · [../architecture/security-boundary.md](../architecture/security-boundary.md)

## Why tool execution needs isolation

Security tools run untrusted or semi-trusted code paths against a live target and, occasionally, parse hostile input back (a malicious response designed to exploit the scanner itself). An agent choosing *when* to run a tool adds a second reason for isolation: even a correctly-scoped, correctly-authorized tool call should never be able to affect anything other than the target it was aimed at and the one artifact it produces — not the OffensiveX host, not another assessment running concurrently, not the agent's own reasoning process.

## What the sandbox provides

| Control | Purpose |
|---|---|
| **Docker containerization** | Every tool execution runs in its own container, not in the API/orchestrator/agent-worker process. |
| **Process isolation** | One container per tool execution; no shared process space between concurrent tool calls, including across agents within the same assessment. |
| **Resource limits** | CPU/memory/output-size caps so a misbehaving tool or a hostile response (e.g. a decompression bomb) cannot exhaust host resources. |
| **Timeouts** | Every invocation has a wall-clock timeout; exceeding it terminates the whole process tree, not just the parent process. |
| **Filesystem boundaries** | Non-root user, minimal writable paths, no access to the OffensiveX codebase, database, or other assessments' artifacts. |
| **Network restrictions** | Egress limited to destinations the current `ExecutionPlan` already declared and the Scope Guard already approved — the sandbox is a second, independent enforcement point behind the Scope Guard, not a substitute for it. |
| **Command execution discipline** | Argv-list invocation only, no shell, scrubbed environment (no secrets passed to tool processes). |
| **Auditability** | Every container run is linked to its `ToolExecution` row: tool, version, arguments (secrets redacted), exit code, raw artifact hash, start/end time. |

## Relationship to the Scope Guard

The sandbox does not replace scope enforcement — it backs it up. The Scope Guard is what decides *whether* a destination may be touched at all (described once, centrally, in [../Guardrail.md §2](../Guardrail.md#2-scope-mandatory-default-deny)); the sandbox is what limits the *blast radius* if a tool misbehaves even after being told to touch only approved destinations. Both are required; neither is sufficient alone.

## Ephemeral by default

A sandbox container exists for exactly one tool execution and is destroyed afterward — no state persists between tool calls inside the sandbox itself. Anything that needs to persist (an observation, a piece of evidence, a raw artifact) is written out to the database/artifact store before the container is torn down.

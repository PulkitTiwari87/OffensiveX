# Evidence

Status: PLANNED
Related: [../data/evidence-model.md](../data/evidence-model.md) · [../agents/investigation-agent.md](../agents/investigation-agent.md)

## The principle

> AI reasoning should be backed by observable evidence whenever possible.

This has been a project rule since before the agent-architecture pivot (Guardrail §3/§5) and becomes more important, not less, once agents make tool-use decisions: every claim an agent makes — "this finding is real," "this path is reachable," "this is the right remediation" — must be traceable to something that was actually observed, not asserted from the model's general knowledge.

## What counts as evidence

| Evidence kind | Example | Produced by |
|---|---|---|
| Request/response | The exact HTTP request sent and the response received | Any tool call through the Tool Registry |
| Headers | Captured response headers | HTTP probing, web scanning |
| Screenshots | A rendered page state | Browser automation (see [../tools/browser.md](../tools/browser.md)) |
| Source locations | File/line a static check flagged | Static analysis |
| Scanner output | Raw tool output (template ID, matched pattern) | Vulnerability scanners |
| Command output | Output of a sandboxed command (validation checks only) | Terminal/sandbox (see [../tools/terminal.md](../tools/terminal.md)) |
| Browser observations | DOM state, console errors observed during automation | Browser automation |
| Validation results | The specific check run and its pass/fail evidence | Validation Agent |

Every evidence item is content-addressed (stored with a hash) and linked to the specific tool call / agent run that produced it, so a report claim can always be traced back to exactly the bytes that justified it. Full field-level detail is in [../data/evidence-model.md](../data/evidence-model.md).

## Evidence is attached as it happens, not reconstructed afterward

Each stage attaches its own evidence to the observation/finding it is working on at the moment the tool call completes — there is no separate "evidence collection pass" after the fact. This is what makes a finding's evidence trail a faithful record of what actually happened during the assessment, rather than a best-effort reconstruction.

## A finding with no evidence cannot be confirmed

Carried over unchanged from the original finding model (Guardrail §3, "never fabricate findings"): a finding cannot reach `CONFIRMED` status without at least one evidence item. This is enforced at the data layer (see [../data/findings.md](../data/findings.md)), not only by convention.

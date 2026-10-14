# Validation Agent

Status: PLANNED
Related: [../security/validation.md](../security/validation.md) · [../data/findings.md](../data/findings.md) · [../architecture/security-boundary.md](../architecture/security-boundary.md)

## Purpose

Confirm or reject a candidate finding using a **controlled, non-destructive** check — the step that turns "a scanner flagged this" into "this was actually observed to be true," without doing anything that could alter or damage the target. Full detail on what "controlled, non-destructive" means per finding class is in [../security/validation.md](../security/validation.md).

## Inputs

A single `SUSPECTED`/`INVESTIGATING` finding, its evidence, and — critically — the assessment's **validation flag**. If that flag is not enabled, the Validation Agent is never scheduled at all; this is an opt-in capability, not a default.

## Tools

A narrow, per-finding-class, non-destructive confirmation check (e.g. a single inert request that proves a condition exists without exfiltrating data or changing state). The exact check is determined by the finding's class/rule, not chosen freely by the agent — the agent decides *whether and when* to run the applicable check, not *what the check does*.

## Outputs

`Finding.status → CONFIRMED` or `→ REJECTED`, with the validation check's own evidence attached. A check that errors (times out, gets blocked, behaves unexpectedly) leaves the finding unresolved rather than being interpreted as either outcome.

## Decision logic

1. Verify the assessment's validation flag is set; if not, this agent is never invoked (enforced by the orchestrator, not by the agent's own judgment).
2. Select the finding class's registered non-destructive check (one check per class, defined and reviewed ahead of time — the agent does not improvise a novel exploitation technique).
3. Run it through the Tool Registry like any other tool call (scope-checked, sandboxed, audited).
4. Interpret the check's result against its documented pass/fail criteria and write the outcome plus evidence.

## Data produced

Updated `Finding.status`, validation evidence (request/response or command output proving/disproving the condition).

## Interaction with other agents

Reads Investigation Agent output; its outcome is what the Risk Agent treats as `evidence_level = verified` on any attack-graph edge the finding supports (see [../data/attack-graph.md](../data/attack-graph.md)).

## Security constraints

This is the one agent whose actions are explicitly gated by `requires_validation_mode` (see [../architecture/execution-model.md](../architecture/execution-model.md)) and the only agent permitted to request a capability in that category at all. Every validation check is: non-destructive by design (no data modification, no data exfiltration, no denial-of-service), scoped to proving/disproving one specific finding, logged with full before/after evidence, and never run against a target without the assessment's own operator having explicitly turned validation on. This is the direct continuation of the original Guardrail rule that the platform ships "no destructive, denial-of-service, brute-force, credential-guessing, or exploitation actions by default" (Guardrail §3) — validation does not relax that, it defines the one narrow, reviewed exception an operator can opt into.

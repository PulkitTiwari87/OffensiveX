# Reporting Agent

Status: PLANNED
Related: [../reporting/reporting.md](../reporting/reporting.md) · [../data/evidence-model.md](../data/evidence-model.md)

## Purpose

Assemble the final, evidence-linked report: pull together the deterministic sections (scope, attack surface, findings, risk, attack paths) and write the prose sections (executive summary, remediation framing) grounded in that data.

## Inputs

The completed (or in-progress, for a draft report) assessment: assets, confirmed/unconfirmed findings with evidence, the attack graph, and risk scores.

## Tools

None against the target. May read previously collected evidence and assessment data only.

## Outputs

A report object per [../reporting/reporting.md](../reporting/reporting.md), in JSON/SARIF (machine-readable) and Markdown/PDF (human-readable).

## Decision logic

Deterministic sections (scope, attack surface, findings table, risk breakdown, attack-path list) are assembled directly from stored data — no LLM involvement, so they cannot drift from what was actually found. Prose sections (executive summary, per-finding remediation framing) are LLM-generated but constrained exactly like the original LLM-analysis design required: every claim must cite evidence IDs, "insufficient evidence" is preferred to a guess, and AI-authored text is always labeled as such in the output (Guardrail §5, carried forward unchanged — see [../architecture/security-boundary.md](../architecture/security-boundary.md)).

## Data produced

A `Report` row referencing the assessment and the specific findings/evidence it includes; reports are immutable snapshots — regenerating creates a new report rather than editing one in place (unchanged from the original design).

## Interaction with other agents

Reads the output of every other agent; produces no data any other agent consumes (terminal stage).

## Security constraints

Cannot alter any finding, score, or graph data while reporting — it is read-only over assessment state. All evidence rendered into a report is treated as untrusted and escaped (an attacker-controlled response body must never become executable content inside a report), unchanged from the original reporting design.

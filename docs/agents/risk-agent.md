# Risk Agent

Status: PLANNED
Related: [../security/risk-analysis.md](../security/risk-analysis.md) · [../data/attack-graph.md](../data/attack-graph.md)

## Purpose

Compute, for every finding, a risk score that reflects not just how dangerous the finding is in isolation, but what it lets an attacker reach — OffensiveX's stated core differentiator. See [../security/risk-analysis.md](../security/risk-analysis.md) for the full severity-vs-path-risk argument and the scoring approach.

## Inputs

Every finding (severity, confidence, exploitability signals) and its position in the attack graph produced by the Attack Graph Agent (which targets it can reach, and the weakest evidence level on the way there).

## Tools

None — like the Attack Graph Agent, this is a deterministic engine, not an open-ended LLM call, for the same reproducibility reason.

## Outputs

A risk score, risk band, and a component breakdown per finding, versioned by the risk-model version that produced it.

## Decision logic

A transparent, documented formula — not an LLM judgment and not a black box. The exact formula, its terms, and the honest "this is a heuristic, not a validated model" caveat are specified once, in [../security/risk-analysis.md](../security/risk-analysis.md), rather than duplicated here.

## Data produced

`risk_score`, `risk_band`, `risk_breakdown`, `risk_model_version` on each `Finding`.

## Interaction with other agents

Consumes Attack Graph Agent output; its scores are what the Reporting Agent uses to order and prioritize findings in the report.

## Security constraints

Deterministic and reproducible by construction — no model call, no variance between runs on identical input. This is what makes a risk number defensible in a report: it can always be recomputed and explained from its breakdown.

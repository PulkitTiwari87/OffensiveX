# Attack-Path Analysis

Status: PLANNED
Related: [../data/attack-graph.md](../data/attack-graph.md) · [../agents/attack-graph-agent.md](../agents/attack-graph-agent.md) · [risk-analysis.md](risk-analysis.md)

## Why this is a first-class capability, not a side feature

A list of findings sorted by severity answers "what is dangerous here?" It does not answer the question an actual attacker — and an actual defender prioritizing remediation — cares about most:

> If an attacker compromises this component, what can they reach next?

That is an attack-graph question, not a per-finding question. OffensiveX treats the attack graph as a first-class model precisely because **this is the platform's stated core differentiator** (attack-path intelligence + risk propagation), not a bonus visualization layered on top of a findings list.

## Illustrative chain

```
Internet
  ↓
Web Application
  ↓            (finding: IDOR)
User Account
  ↓            (relationship: token issued to account)
Token
  ↓            (relationship: token trusted by cloud role)
Cloud Role
  ↓            (relationship: role has access to)
Storage
  ↓            (relationship: contains)
Sensitive Data
```

Each arrow in a real attack path is one graph edge, carrying the finding or relationship that caused it and an **evidence level** — the full entity/relationship model is specified in [../data/attack-graph.md](../data/attack-graph.md).

## Honesty about what the graph proves

A graph edge is one of exactly four evidence levels: `observed` (the underlying fact was directly seen — e.g. an open port, a real trust relationship), `inferred` (derived by a curated rule from an observed, high-confidence finding), `potential` (depends on a lower-confidence or unverified finding), or `verified` (a human or the Validation Agent actually confirmed this specific step). A path's overall evidence level is its weakest edge. **No path is ever presented as proof of exploitation, and the absence of a path is never presented as proof of safety** — both rules are unchanged from the original attack-graph design (Guardrail §3).

## How this feeds risk

The graph does not stand alone — a finding's position in it (how close it sits to an internet-facing entry point, how close to a high-value asset) is one of the direct inputs to the risk score, which is the subject of [risk-analysis.md](risk-analysis.md).

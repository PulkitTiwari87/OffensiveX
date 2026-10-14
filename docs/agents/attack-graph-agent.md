# Attack Graph Agent

Status: PLANNED
Related: [../data/attack-graph.md](../data/attack-graph.md) · [../security/attack-path-analysis.md](../security/attack-path-analysis.md)

## Purpose

Turn assets, their relationships, and confirmed (and well-evidenced suspected) findings into the attack graph: a model that answers *"if an attacker compromises this component, what can they reach next?"* This is called out as deliberately **not** an open-ended LLM reasoning task — see [why below](#decision-logic).

## Inputs

The assessment's current assets, asset relationships, and findings (with status and confidence).

## Tools

None. This agent (really, this stage — see note below) makes no tool calls against the target; it operates purely on data already collected.

## Outputs

`AttackNode` and `AttackEdge` rows (see [../data/attack-graph.md](../data/attack-graph.md)), each edge carrying an evidence level (`observed` / `inferred` / `potential` / `verified`) and a reference to the finding or relationship that caused it.

## Decision logic

Graph construction is a **deterministic, rule-based** process, not a free-form LLM judgment call: a curated, versioned rule set maps finding classes to the access they grant, and relationships (e.g. "this service connects to this database") come from recon/cloud observations directly. This is labeled an "agent" in this document set for consistency with the pipeline's naming, but it is implemented as an ordinary deterministic engine so that *the same inputs always produce the same graph* — reproducibility matters more here than adaptive judgment, for the same reason the risk score must be reproducible (see [../security/risk-analysis.md](../security/risk-analysis.md)).

## Data produced

The attack graph for the assessment: nodes of the form `(asset, access_level)`, edges labeled with cause, rule ID, and evidence level.

## Interaction with other agents

Reads confirmed/suspected findings and assets produced by every upstream agent; its output (specifically, each finding's position in the graph) is consumed by the Risk Agent to compute path-aware risk.

## Security constraints

No target interaction at all. The only "constraint" that matters here is intellectual honesty: an `inferred` or `potential` edge must never be presented, in the graph or downstream in a report, as proof of actual compromise — the same distinction the original design insisted on (Guardrail §3: "treat an inferred attack path as confirmed compromise" is explicitly listed as something the platform must never do).

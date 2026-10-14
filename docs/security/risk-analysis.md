# Risk Analysis

Status: PLANNED
Related: [attack-path-analysis.md](attack-path-analysis.md) · [../agents/risk-agent.md](../agents/risk-agent.md) · [../data/attack-graph.md](../data/attack-graph.md)

## Why not just CVSS

CVSS (and similar isolated severity scores) describe how dangerous a vulnerability is **in a vacuum**: assuming nothing about what else is around it. That is useful but incomplete — a medium-severity issue on an internet-facing host that sits two hops from a production database is a bigger problem than a high-severity issue on an isolated host with nothing reachable beyond it. Relying on CVSS alone would mean OffensiveX's prioritization is no better than any single scanner's severity column, which defeats the purpose of building an attack graph at all.

## Vulnerability severity vs. attack-path risk

| | Vulnerability severity | Attack-path risk |
|---|---|---|
| **Question answered** | How dangerous is this weakness, considered by itself? | How dangerous does this weakness become inside *this* environment? |
| **Inputs** | CVSS/scanner severity, confidence | Severity **and** exploitability, asset criticality, exposure, graph position (reachability, blast radius, downstream impact, sensitive-data exposure), attack-chain importance |
| **Changes if the environment changes?** | No — it's a property of the vulnerability class | Yes — the same finding scores differently on an isolated dev host vs. an internet-facing host in front of a production database |
| **Where it's computed** | Scanner / catalog | OffensiveX's risk engine, from the attack graph |

**This distinction — severity vs. path-aware risk — is one of OffensiveX's strongest conceptual points**, and the reason the risk engine is described as a distinct capability from "the scanner reported a severity," not a thin wrapper around CVSS.

## Factors the risk engine combines

Severity, exploitability (is this finding class known to be reliably exploitable, and is there any indication it's being exploited in the wild), confidence (how sure is the source and the investigation), asset criticality, privilege gain (what access level the finding grants, per the attack graph), blast radius / reachability (what else can be reached from here), downstream impact, sensitive-data exposure, and attack-chain importance (is this finding a required link in an otherwise-high-value path).

## Deterministic by design

Risk scoring is **not** an LLM call. It is a transparent, versioned, reproducible formula over the factors above — the same design decision the project made before the agent pivot (the original ADR-019 in [../Decision.md](../Decision.md)) and one the pivot does not change: an agent can *investigate* a finding, but only the deterministic Risk Agent *scores* it. This is what lets every score in a report be explained and recomputed from its breakdown, and is why the Risk Agent in [../agents/risk-agent.md](../agents/risk-agent.md) has no LLM/tool access at all.

## `risk_model_v1` (finalized, Phase 13)

Per ADR-019: "a project-defined, transparent, weighted heuristic... explicitly not scientifically validated." The formula below is that heuristic, fixed now that the Risk Agent is actually built (`backend/src/offensivex/risk/engine.py`). It is deliberately simple and only uses inputs the data model can currently supply — see "Factors deferred to a later version" below for what is honestly not yet included, rather than faked.

```
base              = SEVERITY_WEIGHT[finding.severity] * 10        # 0..10
confidence_factor = finding.confidence                            # 0..1
criticality_factor = IMPACT_WEIGHT[asset.criticality or target.default_criticality]   # 0.25..1.0
exposure_factor    = IMPACT_WEIGHT[asset.exposure or target.default_exposure]         # 0.25..1.0
graph_factor        = 1.0 + 0.5 * EVIDENCE_WEIGHT[weakest attack-graph edge caused by this finding]
                       (1.0 — no bonus — if the finding is not yet on the attack graph at all)

risk_score = clamp(base * confidence_factor * ((criticality_factor + exposure_factor) / 2) * graph_factor, 0, 10)
```

| Table | Values |
|---|---|
| `SEVERITY_WEIGHT` | `info`=0.1, `low`=0.3, `medium`=0.5, `high`=0.75, `critical`=1.0 |
| `IMPACT_WEIGHT` (criticality and exposure share one scale — Phase 1's placeholder `ImpactLevel`) | `low`=0.25, `medium`=0.5, `high`=0.75, `critical`=1.0 |
| `EVIDENCE_WEIGHT` | `verified`=1.0, `observed`=0.9, `inferred`=0.6, `potential`=0.3 |

**Monotonic by construction** (every factor is a multiplier ≥ 0, never a subtraction): raising severity, confidence, asset criticality, asset exposure, or attack-graph evidence strength never *lowers* the score. This is what "golden-value tests, monotonicity property tests" (ADR-019's consequences) actually check.

**Unknown inputs get a documented neutral default, flagged in the breakdown, never silently guessed at a non-neutral value:** missing `asset.criticality`/`asset.exposure` fall back to the target's declared default (itself `medium` unless set); a finding with no attack-graph edge at all gets `graph_factor = 1.0` (no bonus, no penalty) rather than being assumed either reachable or not.

**Risk band** (for display, not stored as its own column — it's derived from `risk_score`): `critical` ≥ 7.5, `high` ≥ 5.0, `medium` ≥ 2.5, else `low`.

**Every score's breakdown is stored verbatim** in `Finding.risk_breakdown` (JSONB) alongside `Finding.risk_model_version = "risk_model_v1"`, so any score in a report can be recomputed and explained from exactly the inputs that produced it — the whole point of a transparent heuristic over a black box.

### Factors deferred to a later version, not yet included

Per the "Factors the risk engine combines" list above, this repository's data model cannot yet honestly supply: **exploitability** (no exploit-prediction/KEV data source exists), **blast radius / downstream impact beyond one hop** (the attack graph's bounded search, Phase 12, only has one curated rule so far — no multi-hop real chains exist to measure blast radius over), and **sensitive-data exposure** (no asset ever carries a "holds sensitive data" flag in the current schema). Each is added to the formula only when the data to compute it honestly exists — guessing a value for an unmeasured factor would be exactly the kind of overclaiming Guardrail.md §3 forbids, worse than simply not including the factor yet.

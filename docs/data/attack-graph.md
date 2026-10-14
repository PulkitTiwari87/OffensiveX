# Attack Graph

Status: PLANNED
Related: [../security/attack-path-analysis.md](../security/attack-path-analysis.md) · [../agents/attack-graph-agent.md](../agents/attack-graph-agent.md)

## Entities

| Entity | Represents |
|---|---|
| Assets | Hosts, services, applications, cloud resources (same asset model as [data-model.md](data-model.md)). |
| Vulnerabilities (findings) | What causes an edge to exist between two access levels. |
| Identities | User/service accounts discovered or declared. |
| Credentials | Discovered or inferred authentication material (represented abstractly — never stored as actual secret values; see [../Guardrail.md §3](../Guardrail.md#3-safety--never)). |
| Roles | Cloud/IAM roles or application-level privilege roles. |
| Services | Running services an asset exposes. |
| Resources | Data stores, buckets, databases, queues — things that hold value. |
| Data | Sensitive data a resource contains, used to mark high-value targets for path search. |

A graph **node** is `(asset, access_level)` — e.g. `(web-app, unauthenticated_access)`, `(database, data_read)` — so the graph can represent privilege progression on a single asset, not just connectivity between assets.

## Relationships (edge types)

| Relationship | Meaning |
|---|---|
| `EXPOSES` | An asset exposes a service/endpoint. |
| `RUNS` | A host runs a service. |
| `AUTHENTICATES_TO` | An identity authenticates to a service. |
| `HAS_ACCESS` | An identity/role has access to a resource. |
| `CAN_REACH` | Network/logical reachability between assets. |
| `EXPLOITS` | A finding's effect, turning reachability into a higher access level. |
| `ESCALATES_TO` | A finding/relationship that raises privilege level on the same asset. |
| `TRUSTS` | A trust relationship (e.g. a role trusts a token issuer). |
| `LEADS_TO` | Generic "this state makes that state reachable," used for relationship-only edges without a specific finding cause. |

Each edge also carries: `cause` (the specific `Finding` or relationship observation that justifies it), `rule_id` (for rule-derived edges), and an **evidence level**.

## Evidence levels

| Level | Meaning |
|---|---|
| `observed` | The underlying fact was directly seen (e.g. an open port, a real `TRUSTS` relationship read from IAM config). |
| `inferred` | Derived by a curated, versioned rule from a high-confidence finding (e.g. "a confirmed RCE-class finding implies code execution is achievable here"). |
| `potential` | Depends on a lower-confidence or not-yet-validated finding. |
| `verified` | A human, or the Validation Agent, specifically confirmed this exact step. |

A path's evidence level is the weakest edge on it. **This is the same evidence-level model from the original (pre-agent) attack-graph design (ADR-011), unchanged by the pivot** — the pivot changes *who builds the graph* (an engine the orchestrator schedules as part of the agent pipeline, rather than a standalone step) and *how central it is to the product story* (now the stated core differentiator), not the honesty model underneath it.

## What the graph answers

> "If an attacker compromises this component, what can they reach next?"

Answered by a bounded reachability search from a chosen node (see [../security/attack-path-analysis.md](../security/attack-path-analysis.md) for the full worked example and the honesty rules around what a path does and does not prove).

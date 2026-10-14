# Dashboard

Status: PLANNED — no UI exists yet.
Related: [api.md](api.md) · [../data/data-model.md](../data/data-model.md)

## Sections

| Section | Represents | Backed by |
|---|---|---|
| Assessment overview | Status, scan mode, validation flag, stage progress, timing | `Assessment`, `AgentRun` |
| Attack surface | Discovered assets (hosts/ports/services/technologies/endpoints) | `Asset`, recon `Observation`s |
| Findings | Findings table with status, severity, confidence, risk | `Finding` |
| Evidence | Evidence linked to the selected finding (request/response, screenshots, command output) | `Evidence` |
| Attack paths | The attack graph, with evidence-level-encoded edges and a path list | `AttackNode` / `AttackEdge` |
| Risk | Per-finding risk score and breakdown; per-assessment risk summary | `Finding.risk_score` / `risk_breakdown` |
| Agent activity | Live/historical agent-run log: which agent ran, on what input, what it did, what it produced | `AgentRun`, `ToolExecution` |
| Reports | Generated reports, their formats, download links | `Report` |

## Every section is a view over persisted state

Each widget/section reads directly from the entities in [../data/data-model.md](../data/data-model.md) through the API — there is no section that shows simulated, mocked, or hard-coded sample data once implemented. Until a section's backing data actually exists (see [../roadmap/current-status.md](../roadmap/current-status.md)), the section is either absent from the shipped UI or shown as an explicit "not yet available" state — never populated with placeholder numbers, which is the same discipline the original design's empty/degraded-state rules required.

## Agent activity is a first-class section, not an afterthought

Because agents — not just fixed pipeline steps — are now doing the work, the dashboard must let an operator see *what each agent actually did* (which tool calls it made, what it concluded, what evidence it attached) well enough to audit any individual claim in a report back to a specific agent run. This is the dashboard-level expression of the project's evidence-first principle.

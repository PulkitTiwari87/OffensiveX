# OffensiveX — UI/UX Design (SUPERSEDED)

**This document is superseded.** It specified a UI over the original fixed-pipeline backend (scans/steps, not assessments/agent-runs). See ADR-021 in [Decision.md](Decision.md).

| What this document covered | Now documented in |
|---|---|
| Navigation, dashboard widgets | [interfaces/dashboard.md](interfaces/dashboard.md) |
| Scan views, findings views | [interfaces/dashboard.md](interfaces/dashboard.md), [data/findings.md](data/findings.md) |
| Attack path graph view | [interfaces/dashboard.md](interfaces/dashboard.md), [security/attack-path-analysis.md](security/attack-path-analysis.md) |
| AI analysis panels | [architecture/security-boundary.md](architecture/security-boundary.md), [agents/reporting-agent.md](agents/reporting-agent.md) |
| Reports view | [reporting/reporting.md](reporting/reporting.md) |

The new [interfaces/dashboard.md](interfaces/dashboard.md) is intentionally lighter-weight than this original document (which specified exact color tokens, component inventories, and pixel-level layout) — detailed visual design is deferred until the dashboard's backing API actually exists (see [roadmap/roadmap.md](roadmap/roadmap.md), P15), so this document is not re-expanded to full detail yet. Kept only as a pointer so old links still resolve.

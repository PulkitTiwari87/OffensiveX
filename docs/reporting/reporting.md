# Reporting

Status: PARTIAL — JSON + Markdown implemented (Phase 14), see [../roadmap/current-status.md](../roadmap/current-status.md); SARIF/PDF and the Technologies section are not built.
Related: [../agents/reporting-agent.md](../agents/reporting-agent.md) · [../data/evidence-model.md](../data/evidence-model.md)

## Report sections

1. Executive Summary (AI-authored prose, grounded in the sections below; always labeled as AI-generated)
2. Scope
3. Attack Surface
4. Technologies
5. Findings
6. Confirmed Vulnerabilities
7. Evidence
8. Attack Paths
9. Risk Analysis
10. Remediation
11. Technical Appendix (raw tool/agent provenance: tool versions, agent-run IDs, model/prompt versions)

## Formats

| Format | Kind | Status |
|---|---|---|
| JSON | Machine-readable | PLANNED |
| SARIF | Machine-readable (for CI/code-scanning integration) | PLANNED |
| Markdown | Human-readable | PLANNED |
| PDF | Human-readable | PLANNED |

None is implemented yet. SARIF in particular is **planned**, not implemented — it's listed here because it's a natural fit for a findings-with-locations model, not because it exists.

## Honesty rules this stage enforces

- Deterministic sections (scope, attack surface, findings table, risk breakdown, attack-path list) are assembled directly from stored data, never paraphrased by an LLM — so they cannot drift from what was actually found.
- Every finding and evidence reference in a report links back to the real record behind it (see [../data/evidence-model.md](../data/evidence-model.md)); nothing in a report exists only as report prose.
- AI-authored prose (executive summary, remediation framing) is always labeled as AI-generated and must cite the evidence IDs it's grounded in — unchanged from the original LLM-analysis design (Guardrail §5).
- Reports are immutable snapshots; regenerating produces a new report rather than editing one in place.
- All evidence rendered into any format is treated as untrusted and escaped — an attacker-controlled response body must never become executable content in an HTML/PDF report.

## Provenance block

Every report carries: assessment ID, agent-run IDs that contributed, tool versions used, risk-model version, attack-graph rule-set version, and (for AI-authored sections) provider/model/prompt version and generation time — carried over unchanged from the original reporting design.

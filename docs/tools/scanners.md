# Scanners

Status: PLANNED
Related: [tool-registry.md](tool-registry.md) · [../security/vulnerability-discovery.md](../security/vulnerability-discovery.md)

All tools on this page are candidate choices for a `PLANNED` capability — none is integrated yet.

| Tool | Capability | Notes |
|---|---|---|
| Nmap | TCP port/service discovery | Rate-limited, no NSE scripts, no UDP by default — same restrictions the original (pre-agent) design placed on it. |
| Nuclei | Template-based web vulnerability scanning | Curated, non-intrusive template set only; no DoS/fuzzing/brute-force/OAST templates — carried over from the original adapter design. |
| Semgrep | Static analysis | Only runs against source the operator has made available in scope; pattern-based, no code execution. |
| Trivy | Dependency / container image scanning | Matches against known-vulnerability databases; never a live exploitation attempt. |

## Why these four

They cover the planned MVP vulnerability-discovery surface (network/service, web application, source, and software-composition) without introducing an intrusive or exploitation-capable tool by default. Any tool added later goes through the same adapter contract ([../architecture/tool-architecture.md](../architecture/tool-architecture.md)) and the same honesty requirement: it is `PLANNED` in documentation until it has actually been run, `MOCKED`/`IMPLEMENTED` once it has (see [../Guardrail.md §7](../Guardrail.md#7-status-vocabulary)).

## What scanners do not do here

A scanner's output is never auto-promoted to a confirmed finding (see [../security/vulnerability-discovery.md](../security/vulnerability-discovery.md)); scanners here produce observations and `DISCOVERED` findings only.

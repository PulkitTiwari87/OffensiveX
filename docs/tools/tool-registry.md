# Tool Registry

Status: PLANNED
Related: [../architecture/tool-architecture.md](../architecture/tool-architecture.md) · [sandbox.md](sandbox.md)

## Concept

Agents do not call tools directly. They request a **capability** (e.g. "discover open TCP ports on this host"), and the Tool Registry — a single abstraction every agent and every pipeline step goes through — resolves that to a concrete adapter, builds the concrete invocation, checks it against scope, and runs it in the sandbox. This keeps agents decoupled from specific tool implementations (swapping or adding a scanner never touches agent logic) and keeps the scope/audit checks in exactly one place, regardless of who's asking. Full detail on the contract every adapter implements is in [../architecture/tool-architecture.md](../architecture/tool-architecture.md).

## Registry entries (planned)

| Capability | Candidate implementation | Category | Status |
|---|---|---|---|
| DNS resolution | dnspython | Reconnaissance | PLANNED |
| TCP port/service discovery | Nmap | Reconnaissance | PLANNED |
| HTTP request/response | httpx (engine-provided client) | Web | PLANNED |
| Browser automation | Playwright | Web | PLANNED |
| Proxy/interception | mitmproxy or equivalent | Web | PLANNED |
| Template-based web scanning | Nuclei | Vulnerability | PLANNED |
| Static analysis | Semgrep | Vulnerability | PLANNED |
| Dependency/container scanning | Trivy | Vulnerability | PLANNED |
| Sandboxed shell | containerized shell, no host access | Execution | PLANNED |
| Sandboxed Python | containerized interpreter, no host access | Execution | PLANNED |

**Nothing in this table is implemented.** "Candidate implementation" names the tool the design currently expects to use; it is not a claim that integration exists. See [../roadmap/current-status.md](../roadmap/current-status.md) for the only authoritative status table.

## Per-entry metadata

Every registry entry carries: `capability` name, `intrusiveness` (passive / low / medium), `requires_validation_mode` (bool — see [../security/validation.md](../security/validation.md)), and `status` (per [../Guardrail.md §7](../Guardrail.md#7-status-vocabulary)). The Tool Registry refuses a request whose intrusiveness exceeds the assessment's scan mode or whose `requires_validation_mode` is true while the assessment has validation disabled — before the Scope Guard is even consulted (see [../architecture/execution-model.md](../architecture/execution-model.md)).

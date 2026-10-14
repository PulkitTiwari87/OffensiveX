# Recon Agent

Status: PLANNED
Related: [../security/reconnaissance.md](../security/reconnaissance.md) · [../tools/tool-registry.md](../tools/tool-registry.md) · [../data/observations.md](../data/observations.md)

## Purpose

Map the in-scope attack surface: hosts, open ports, running services, web technologies, and endpoints. The Recon Agent's judgment is in **sequencing and triage** — deciding which recon capability to run next based on what the last one returned (e.g. only probe HTTP on ports that port discovery actually found open) — not in interpreting vulnerability data, which is the Vulnerability Agent's job.

## Inputs

- The assessment's scope snapshot (what is in/out of scope — enforced independently by the Scope Guard regardless of what the agent "decides").
- The target's **entry point** (`targets.entry_point`, optional): a validated, normalized http(s) URL giving the exact scheme, host and port to start from. It is a starting point, never permission — it must itself be covered by the authorization's scope, and every tool call is still checked against that scope. Recon never infers a port or URL from the target name; with no entry point it only knows hostnames and tries the default http/https URLs.
- Prior observations from this assessment (so re-runs/re-scans don't blindly repeat work already done).

## Tools

Read-only reconnaissance capabilities only, per [../architecture/security-boundary.md](../architecture/security-boundary.md): DNS resolution, TCP port/service discovery, HTTP probing, subdomain enumeration. No browser automation, no shell/code execution, no vulnerability scanners.

## Outputs

`Observation` rows of type `HOST_DISCOVERED`, `PORT_DISCOVERED`, `SERVICE_DISCOVERED`, `TECHNOLOGY_DISCOVERED`, `ENDPOINT_DISCOVERED` (see [../data/observations.md](../data/observations.md)) and the `Asset` rows derived from them.

## Decision logic

1. Start from the target's declared scope (domains/IPs/CIDRs/URL prefixes).
2. Resolve names; for each resolved, in-scope destination, decide which discovery capability is worth running next (e.g. skip port discovery on a destination already fully characterized by a prior assessment pass, in `deep` mode go wider on subdomain enumeration, in `quick` mode stop after the first HTTP probe pass).
3. Every decision is still bounded: the agent cannot request a capability outside its toolset, and every destination it names still goes through the Scope Guard before any tool runs (see [../architecture/execution-model.md](../architecture/execution-model.md)) — discovering a name does not make it in scope.
4. Produces observations as it goes rather than batching everything to the end, so a crash/cancellation mid-run still leaves partial, usable results.

## Data produced

Observations and assets. The Recon Agent never writes a `Finding` directly — findings only ever come from the Vulnerability/Investigation/Validation path.

## Interaction with other agents

Hands the discovered attack surface to the Vulnerability Agent (which reads assets/observations, not raw recon-agent output) and, indirectly, supplies the asset inventory the Attack Graph Agent later builds nodes from.

## Security constraints

Strictly read-only/observational. Cannot request a capability tagged `requires_validation_mode`. Every destination is scope-checked before the corresponding tool runs; out-of-scope names discovered along the way (e.g. a sibling subdomain found via a certificate) are recorded as `out_of_scope` observations and never acted on, carried over unchanged from the original scope-enforcement design (Guardrail §2).

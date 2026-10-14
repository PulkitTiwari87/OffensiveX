# Reconnaissance

Status: PLANNED
Related: [../agents/recon-agent.md](../agents/recon-agent.md) · [../tools/scanners.md](../tools/scanners.md)

## What reconnaissance produces

Reconnaissance maps the in-scope **attack surface**: which hosts exist, which ports/services are open, what web technologies are running, and what endpoints are reachable. It produces `Observation`s (see [../data/observations.md](../data/observations.md)), not findings — recon never asserts a vulnerability, only a fact about what exists.

## Capabilities (by category)

| Category | What it establishes | Status |
|---|---|---|
| DNS resolution | Names → addresses; record types (A/AAAA/CNAME/NS/MX/TXT) | PLANNED |
| TCP port/service discovery | Which ports are open on a host and what service/version is listening | PLANNED |
| HTTP probing | Status, headers, title, redirects, TLS certificate info | PLANNED |
| Subdomain enumeration | Additional in-scope names via passive sources (certificate transparency, passive DNS) | PLANNED |

No capability above is `IMPLEMENTED`. See [../tools/scanners.md](../tools/scanners.md) for the specific tools planned behind each capability.

## How the Recon Agent decides what to run

Unlike a fixed "always run tool X then tool Y" pipeline, the Recon Agent sequences discovery based on what it has already found in *this* assessment — e.g. it only probes HTTP on ports that port discovery actually reported open, and it widens subdomain enumeration in `deep` mode but not in `quick` mode. The full decision logic lives in [../agents/recon-agent.md](../agents/recon-agent.md); this document describes *what the capabilities are*, that one describes *how the agent chooses among them*.

## Scope is enforced independently of agent judgment

Every destination the Recon Agent's plan would touch is checked against the assessment's scope by the Scope Guard before any tool runs — the agent choosing to explore a destination does not make it authorized. A name discovered during recon (e.g. a sibling subdomain found via a TLS certificate's SAN list) that falls outside scope is recorded as an `out_of_scope` observation and is never itself scanned. This is the same default-deny, four-layer enforcement described in [../Guardrail.md §2](../Guardrail.md#2-scope-mandatory-default-deny), unchanged by the move to an agent architecture.

## Output

Recon observations become `Asset` rows (hosts, ports, services, applications — see [../data/data-model.md](../data/data-model.md)) and feed directly into [vulnerability-discovery.md](vulnerability-discovery.md).

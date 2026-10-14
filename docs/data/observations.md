# Observations

Status: PLANNED
Related: [findings.md](findings.md) · [../tools/tool-registry.md](../tools/tool-registry.md) · [../agents/recon-agent.md](../agents/recon-agent.md)

## The core architectural concept

Raw tool output is noisy, tool-specific, and not directly useful to an agent's reasoning or to the data model. Every tool call's parsed result is first normalized into one or more **observations** — small, typed, timestamped, confidence-scored facts — before anything else happens with it:

```
Tool  →  Observation  →  Correlation  →  Investigation  →  Finding
```

An observation is a fact ("port 443 is open on host X," "this response header is missing," "this template matched"). A finding is a claim ("this is a vulnerability"), built by correlating one or more observations and then investigated. Keeping these as separate concepts is what lets OffensiveX say precisely *why* it believes something, and is what the Investigation Agent in [../agents/investigation-agent.md](../agents/investigation-agent.md) actually operates over.

## Shape

```json
{
  "type": "PORT_DISCOVERED",
  "source": "nmap",
  "asset_id": "...",
  "confidence": 0.91,
  "data": {}
}
```

| Field | Meaning |
|---|---|
| `type` | One of a fixed vocabulary (see below) — never a free-form string. |
| `source` | The tool or agent that produced it. |
| `asset_id` | The asset this observation is about. |
| `confidence` | How sure the *source* is (not the eventual finding's confidence — a scanner's own confidence in its own output). |
| `data` | Type-specific structured payload (never free text pasted in — a `PORT_DISCOVERED` observation has a port number and protocol, not a sentence). |

## Observation types (planned vocabulary)

| Type | Produced by |
|---|---|
| `HOST_DISCOVERED`, `PORT_DISCOVERED`, `SERVICE_DISCOVERED`, `TECHNOLOGY_DISCOVERED`, `ENDPOINT_DISCOVERED` | Recon Agent |
| `VULNERABILITY_SIGNAL_DISCOVERED` | Vulnerability Agent |
| `OUT_OF_SCOPE` | Any agent, when a discovered destination falls outside the assessment's scope (recorded, never acted on — see [../Guardrail.md §2](../Guardrail.md#2-scope-mandatory-default-deny)) |

This list grows as capabilities are implemented; it is not meant to be exhaustive on day one, and new types are added deliberately rather than ad hoc per tool.

## Correlation

Correlation is the step that groups related observations (e.g. a `SERVICE_DISCOVERED` for an HTTP service plus a `VULNERABILITY_SIGNAL_DISCOVERED` against one of its endpoints) into a single candidate finding, rather than one finding per raw observation. This is what keeps a finding list from fragmenting into dozens of near-duplicate entries for what is really one weakness observed from several angles.

# Investigation Agent

Status: PLANNED
Related: [../data/findings.md](../data/findings.md) · [../data/observations.md](../data/observations.md) · [../agents/validation-agent.md](validation-agent.md)

## Purpose

Resolve ambiguity that scanners alone leave behind. A scanner often produces a partial signal (a reflected character that *might* indicate injection, a response header that *might* indicate a misconfigured framework); this is exactly the judgment-heavy, exploratory work an agent is suited for, and the reason the project adopted an agent architecture at all (see [../architecture/overview.md](../architecture/overview.md)).

## Inputs

Candidate findings at `DISCOVERED`, their supporting observations/evidence, and — when useful — the ability to request further **read-only** checks (re-request a page, inspect a prior artifact more closely, correlate against another observation).

## Tools

Read-only re-checks only: re-probe, re-request, inspect previously collected artifacts. No capability marked `requires_validation_mode`, no write/execution capability.

## Outputs

Findings moved `DISCOVERED → SUSPECTED → INVESTIGATING`, with reasoning and any additional evidence attached. A finding the agent cannot meaningfully narrow down stays `SUSPECTED` rather than being forced to a conclusion — see [../data/findings.md](../data/findings.md) for the full lifecycle.

## Decision logic

1. Read the candidate finding and its evidence.
2. Decide whether the existing evidence is already strong enough to warrant validation, needs one or more additional **read-only** checks, or is too weak to pursue further (in which case the finding is left `SUSPECTED`, visibly, rather than silently dropped).
3. Every claim the agent writes into a finding's notes must cite the specific evidence it is based on — the same evidence-grounding discipline the original LLM-analysis design required (Guardrail §5), now applied to an agent's intermediate reasoning, not only to the final report text.
4. Recommends (but does not itself trigger) whether a finding is a good candidate for the Validation Agent; the orchestrator decides whether to actually schedule validation, based on whether validation mode is enabled for the assessment.

## Data produced

Updated `Finding.status`, investigation notes/evidence, and — only when truly warranted — additional observations from the read-only re-checks it requested.

## Interaction with other agents

Consumes Vulnerability Agent output; its output is read by the Validation Agent (if validation is enabled) and, for findings that are never validated, directly by the Risk and Reporting Agents (reported as unconfirmed).

## Security constraints

Cannot request anything beyond a read-only re-check. Cannot mark a finding `CONFIRMED` or `REJECTED` — those statuses are written only by the Validation Agent's outcome (or by an explicit analyst action), never by the Investigation Agent's own reasoning, exactly mirroring the original rule that an LLM "cannot alter severity, risk, status, or scope" (Guardrail §5), narrowed here to "status" since investigation is itself now agentic.

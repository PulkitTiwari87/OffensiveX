# Orchestrator

Status: PLANNED
Related: [../architecture/agent-architecture.md](../architecture/agent-architecture.md) · [../data/data-model.md](../data/data-model.md)

## Purpose

The orchestrator is not an agent — it has no LLM call of its own. It owns the **assessment lifecycle**: creating assessments, deciding which agent runs next, tracking state, enforcing that stages run in the right dependency order, retrying failed work within bounds, and deciding when an assessment is done. Its job is to make sure the seven agents act as **one coordinated assessment**, not seven disconnected AI features that happen to write to the same database.

## Inputs

- A target, its authorization record, and its scope snapshot (validated before an assessment can even be created — unchanged from the original Scope Guard design, see [../Guardrail.md](../Guardrail.md)).
- A requested scan mode (`quick` / `standard` / `deep`, see [../security/validation.md](../security/validation.md)) and whether validation is enabled for this assessment.
- The current assessment state: which stages have produced output, which agent runs are in flight, what failed.

## Tools

None. The orchestrator calls no tools and touches no target. It schedules **agent runs** and reads/writes **assessment state** in the database.

## Outputs

- `Assessment` state transitions (`pending → running → … → completed / completed_with_errors / failed / cancelled`).
- Scheduled `AgentRun` rows (which agent, with what inputs, when).
- The decision of when each later stage (investigation, validation, attack graph, risk, reporting) is *allowed* to start.

## Decision logic

1. **Assessment creation** validates target scope/authorization and scan mode, then enqueues the Recon Agent. Nothing else runs yet.
2. **Scan modes** change which agents/capabilities are in play, not the stage order itself:
   - `quick` — Recon + Vulnerability Agent only, non-intrusive capabilities, no Investigation/Validation, attack graph and risk still run (on whatever was found).
   - `standard` — Recon → Vulnerability → Investigation → (Validation, if enabled) → Attack Graph → Risk → Reporting, the full lifecycle in [agent-architecture.md](../architecture/agent-architecture.md#3-the-assessment-lifecycle).
   - `deep` — same stage order as `standard`, with higher investigation/validation budgets (more agent turns, more candidate findings pursued) and a wider recon/vulnerability tool set.
3. **Agent scheduling** — the orchestrator starts the next agent only once its stage's prerequisite data exists (e.g. the Investigation Agent is not scheduled until the Vulnerability Agent has produced at least one candidate finding, or Recon has produced zero findings and the stage is explicitly skipped rather than hung).
4. **Task delegation** — one `AgentRun` is normally one finding (for Investigation/Validation) or one discovered-asset batch (for Recon/Vulnerability), so failures are isolated and retryable at that granularity, not per-assessment.
5. **Prioritization** — when there are more candidate findings than the assessment's investigation/validation budget allows (bounded by scan mode), the orchestrator orders them by a simple, deterministic pre-score (raw severity × exposure) so the most consequential candidates are investigated first — this ordering is not itself the project's risk score, only a scheduling heuristic.
6. **Retries and failure handling** — each `AgentRun` has bounded attempts (same lease/attempt model as the original job queue, ADR-004). A stage with zero usable output blocks progression (nothing to investigate); a stage with partial output proceeds and the gap is recorded (`completed_with_errors`).
7. **Validation triggers** — the Validation Agent is only scheduled for a `CONFIRMED`-candidate if the assessment's validation flag is enabled; otherwise the finding stays `SUSPECTED`/`INVESTIGATING` and is reported as unconfirmed.
8. **Attack-graph triggers** — scheduled once per assessment after the confirmed-findings set stabilizes for the current pass (not after every single finding, to avoid rebuilding the graph needlessly), and again on demand if an operator edits asset criticality/exposure.
9. **Reporting triggers** — scheduled once risk scores exist for all findings that will appear in the report; can be re-triggered on demand without re-running any other agent.

## Data produced

`Assessment`, `AgentRun` (see [../data/data-model.md](../data/data-model.md)). No findings/observations/graph/risk data directly — those belong to the agents that produce them.

## Interaction with other agents

The orchestrator is the only component that schedules agent runs; agents never schedule each other. It is also the only component allowed to mark an `Assessment` as `completed`.

## Security constraints

The orchestrator cannot itself invoke the Tool Registry — it has no tool access at all, by construction, which is what keeps "coordinate the assessment" and "touch the target" as two separate, separately-audited privileges.

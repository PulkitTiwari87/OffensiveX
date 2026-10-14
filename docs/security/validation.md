# Validation

Status: PLANNED
Related: [../agents/validation-agent.md](../agents/validation-agent.md) · [../architecture/security-boundary.md](../architecture/security-boundary.md) · [../data/findings.md](../data/findings.md)

## Why scanner output should not automatically become a confirmed vulnerability

A `DISCOVERED` finding is a hypothesis, not a fact. Automatically reporting every scanner hit as a confirmed vulnerability would flood a report with false positives and would violate the project's evidence-first principle (Guardrail §3/§6). Validation is the controlled step that turns a well-investigated hypothesis into either `CONFIRMED` (the condition was actually observed to hold) or `REJECTED` (it does not). It is **opt-in per assessment** — an operator must explicitly enable it, because even a "non-destructive" check still sends crafted, atypical traffic at a live target, which is a decision only the authorizing operator should make.

## Validation is non-destructive by design, not by promise

Every validation check is drawn from a small, pre-defined, reviewed set — one check per finding class — rather than improvised by the agent at run time. A check is written to **prove or disprove a specific condition** (e.g. "this parameter reflects unescaped input," "this header is actually missing") using the least intrusive request that can establish that fact, and is reviewed ahead of time for exactly this property before it is added to the registry. This is the same "no destructive, denial-of-service, brute-force, credential-guessing, or exploitation actions by default" guarantee the project has always made (Guardrail §3) — validation does not weaken it; it is the one reviewed, explicitly-opt-in capability that operates close to that line, and it never crosses into data modification, data exfiltration, or service disruption.

## Scan modes and validation

| Mode | Recon / Vuln scanning | Investigation | Validation |
|---|---|---|---|
| **Quick** | Fast, narrow recon + common-vulnerability scan | Not run | Not run |
| **Standard** | Full recon + scanning | Runs on all candidates | Runs only if explicitly enabled for the assessment |
| **Deep** | Wider recon + scanning | Runs with a larger budget (more candidates pursued, more re-checks per candidate) | Runs only if explicitly enabled; wider validation budget |

None of these modes is implemented yet; this table describes the planned behavior that [../agents/orchestrator.md](../agents/orchestrator.md) will enforce. No mode, including `deep`, implies validation is on by default — validation is always a separate, explicit assessment setting.

## Validation outcomes

| Outcome | Meaning |
|---|---|
| `CONFIRMED` | The check positively established the condition; evidence attached. |
| `REJECTED` | The check positively established the condition does *not* hold. |
| *(unresolved)* | The check errored, timed out, or was blocked — the finding stays at its prior status rather than being forced to a conclusion either way. |

See the full status machine in [../data/findings.md](../data/findings.md).

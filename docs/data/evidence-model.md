# Evidence Model

Status: PLANNED
Related: [../security/evidence.md](../security/evidence.md) · [findings.md](findings.md)

## Fields

| Field | Meaning |
|---|---|
| `id` | Stable identifier, citable from agent reasoning and reports (e.g. `EV-3fa9c2d1`). |
| `finding_id` | The finding this evidence supports. |
| `kind` | `request_response` \| `header` \| `screenshot` \| `source_location` \| `scanner_output` \| `command_output` \| `browser_observation` \| `validation_result`. |
| `tool_execution_id` | The specific tool call that produced it — links back to the audit trail. |
| `excerpt` | A size-capped, sanitized excerpt (never the full raw payload if it's large; never executed or rendered as anything but text). |
| `artifact_ref` | Pointer to the full raw artifact (content-addressed by hash), for cases the excerpt doesn't fully capture. |
| `captured_at` | Timestamp. |

## Why this shape

Keeping evidence as its own entity (rather than a free-text field on a finding) is what lets an agent — or a report — **cite** a specific piece of evidence by ID, rather than describing it in prose that can drift from what was actually observed. It is also what lets the grounding/validation discipline inherited from the original LLM-analysis design (Guardrail §5) apply to agent reasoning generally, not only to a final report-writing pass: any claim an agent makes should be traceable to an `EV-…` ID that actually exists for this finding.

## Evidence is untrusted content

Everything inside an evidence excerpt came from the target (a response body, a header value, a scanner's echo of an injected string) and must be treated as untrusted: rendered as text only, never interpreted as instructions by an agent and never rendered as executable content in a report (same rule as the original design's XSS/prompt-injection handling, Guardrail §3/§4).

# Security Boundary

Status: PLANNED
Related: [../Guardrail.md](../Guardrail.md) (binding rules — read in full) · [execution-model.md](execution-model.md) · [../tools/sandbox.md](../tools/sandbox.md)

This document explains **where agent agency ends and hard controls begin**. The binding rules themselves — scope enforcement, authorization, safety "never/always" lists, AI constraints, status vocabulary — live in [../Guardrail.md](../Guardrail.md) and are not duplicated here. This page is the map from those rules onto the new agent model, and records the one place the rules changed.

## OffensiveX is for authorized testing only

Unchanged from the original design (Guardrail §1): owned infrastructure, explicitly authorized infrastructure, controlled lab environments, or educational environments where testing is permitted. Nothing about adding agents changes this — if anything, it raises the bar, because an agent can act faster than a human operator reviews each step, so the controls below exist specifically to keep that speed from becoming a liability.

## What changed: "no agency" → "bounded agency"

The original Guardrail (§5, AI/LLM) stated: *"The LLM has no tools and no agency: it cannot trigger scans, change scope, change findings, or call network resources."* That rule assumed the LLM was purely an explain-and-recommend layer sitting beside a deterministic pipeline. It is now **superseded** by the agent architecture, where agents *do* call tools — that is the whole point of the pivot. [../Guardrail.md §5](../Guardrail.md#5-ai--llm--agents) has been updated to the rule actually in force:

> An agent's agency is **bounded**, not absent. An agent may only act through the Tool Registry; every action is scope-checked, sandboxed, and audited exactly like a human-triggered one. An agent can never: bypass the Scope Guard, touch a destination outside the assessment's scope, run a destructive or exploitative action without the assessment's validation mode being explicitly enabled, alter a finding's status or risk score directly (those are written only by the deterministic normalizer, Validation Agent outcome, and Risk Agent respectively — never by an agent "deciding" a finding is confirmed in prose), or disable/evade auditing.

What did **not** change: the LLM/agent is still never ground truth for severity or risk (those come from deterministic engines — [../security/risk-analysis.md](../security/risk-analysis.md)); it still must ground its claims in evidence; it still prefers "insufficient evidence" over a guess; fabricated CVEs/findings/evidence are still never acceptable (Guardrail §3, §5).

## Agent permissions, concretely

| Agent | May call | May never call |
|---|---|---|
| Recon | DNS, port/service discovery, HTTP probing, subdomain enumeration (read-only) | Anything in the Validation or Execution tool categories |
| Vulnerability | Vulnerability scanners (passive/template-based, non-intrusive config) | Shell/Python execution against the target; exploit-grade payload tools |
| Investigation | Read-only re-checks (re-probe, re-request, inspect prior artifacts) | New destructive or write-capable calls |
| Validation | A narrow, per-finding-class, **non-destructive** confirmation check — only when the assessment's validation mode is enabled | Anything beyond the specific check it was invoked for; nothing that modifies target state |
| Attack Graph, Risk | No tool calls at all — pure functions over already-collected data | — |
| Reporting | No tool calls against the target; may read assessment data | — |

This table is the concrete instance of the "toolset membership" check described in [execution-model.md](execution-model.md).

## Sandboxing is part of the security boundary, not an implementation detail

Every tool call — whatever agent requested it — runs inside the sandbox described in [../tools/sandbox.md](../tools/sandbox.md): a non-root, resource-limited, network-restricted container with a timeout and no persistent state between tool calls. The sandbox is the last line of defense if a tool misbehaves or an agent's request is subtly wrong; it does not replace the Scope Guard, it backs it up.

## Audit trail

Every agent run, every tool call it makes (plan, scope decision, result), every finding-status transition, and every validation action is written to the same hash-chained audit log described in [../Guardrail.md §8/§4](../Guardrail.md). An assessment's full audit trail should let an operator reconstruct exactly what each agent saw, decided, and did — this is treated as a correctness requirement for the agent architecture, not an optional nicety.

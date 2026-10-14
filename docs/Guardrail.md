# OffensiveX — Guardrails

Status: PLANNED (documentation phase; no code exists yet)

These rules are binding for every contributor, human or AI. They protect the people who run OffensiveX, the systems it assesses, and the credibility of its output. Where a guardrail conflicts with a feature request, the guardrail wins until the guardrail is changed through the process in [§9](#9-changing-a-guardrail).

---

## 1. Authorized use

OffensiveX is for assessing:

- infrastructure the operator **owns**,
- infrastructure the operator is **explicitly authorized in writing** to assess,
- **controlled lab environments** (e.g. local containers built for testing),
- **educational environments** where testing is permitted by the environment's owner.

The platform must not be designed, documented, or marketed around unauthorized targeting, stealth, evasion of defenders, or mass internet scanning.

**Honest limitation.** Software cannot prove legal authorization. OffensiveX records a signed-in user's *attestation* and enforces the *technical scope* that attestation defines. It makes accidental out-of-scope activity hard and makes every action attributable. It does not make unauthorized use legal.

## 2. Scope (mandatory, default-deny)

1. Every scan has an explicit scope. **No scope → no scan.** There is no "scan everything" mode.
2. Scope is **default-deny**: a destination is allowed only if an `include` rule matches and no `exclude` rule matches. Exclude wins.
3. Scope is checked at **four layers** (defense in depth): scan creation, per-tool-invocation planning, discovered-asset handling, and parsed-output filtering (see `Architecture.md` §7).
4. **Discovery is not permission.** An asset found during recon that is outside scope is *recorded* as `out_of_scope` and is **never** scanned.
5. Scope-widening requires a new authorization approval, which is audit-logged. A running scan never widens its own scope.
6. Catch-all and overly broad rules (`0.0.0.0/0`, `::/0`, TLD-only wildcards, CIDRs wider than the configured limit) are rejected at validation time.
7. Loopback, link-local, private-range, and cloud-metadata destinations (e.g. `169.254.169.254`) are denied unless they are explicitly listed in scope **and** the deployment permits private targets (`OFFENSIVEX_ALLOW_PRIVATE_TARGETS`).
8. Destinations are resolved **once**, validated, and the tool is given the validated IP (pinned) to prevent DNS-rebinding / time-of-check-to-time-of-use escapes.

## 3. Safety — never

- hardcode credentials, tokens, or keys anywhere (code, tests, fixtures, docs, logs);
- expose secrets in API responses, logs, reports, LLM prompts, or error messages;
- **fabricate** findings, vulnerabilities, CVEs, CVSS scores, scan results, assets, or evidence — including in test fixtures presented as real tool output (fixtures must be labeled as synthetic or recorded, see §6);
- claim exploitation without evidence of exploitation;
- present an **inferred** or **potential** attack path as confirmed compromise;
- silently scan outside configured scope, or silently skip a scope check "for convenience";
- introduce destructive, denial-of-service, brute-force, credential-guessing, or exploitation actions by default — MVP has none;
- bypass, weaken, or add "temporary" backdoors to authorization controls;
- let a tool run with a shell (`shell=True`) or with user-controlled strings interpolated into a command line;
- send scan data to a third party (LLM API, CT log, threat-intel service) unless that egress is enabled, documented, and audit-logged (see §5);
- store cloud credentials in the database or UI.

## 4. Safety — always

- Safe defaults: `passive` scan profile, dry-run available for every scan, conservative rate caps, no UDP, no NSE scripts, no intrusive scanner templates.
- Every security-relevant action produces an **audit log** entry (who, what, when, scope decision, outcome).
- Every scan can be **cancelled**, and cancellation terminates the tool's whole process tree.
- Evidence and raw tool output are retained so any finding can be traced to the exact command and output that produced it.
- Treat all scanner output and all remote content (banners, headers, HTML, certificates) as **untrusted input** — it can contain XSS payloads and prompt-injection text.

## 5. AI / LLM / agents

> **Updated by the agent-architecture pivot (ADR-021).** The original version of this rule read: *"The LLM has no tools and no agency: it cannot trigger scans, change scope, change findings, or call network resources."* That assumed an LLM used only as an explain-and-recommend layer beside a deterministic pipeline. OffensiveX now uses LLM-driven **agents** (recon, vulnerability discovery, investigation, validation, reporting — see `architecture/agent-architecture.md`) that do call tools. The rule below is the one actually in force; it bounds agency instead of forbidding it, and is deliberately stricter in the one place that matters most (validation/destructive actions), not looser everywhere.

- An agent's agency is **bounded, not absent**. An agent may act only through the Tool Registry (`architecture/tool-architecture.md`); every action is scope-checked (§2 of this document, unchanged), sandboxed (`tools/sandbox.md`), and audited exactly as a human-triggered action would be.
- An agent can **never**: bypass the Scope Guard, touch a destination outside the assessment's scope, run a destructive/exploitative/validation-class action without the assessment's validation mode being explicitly enabled (`security/validation.md`), write a finding's `status`/`risk_score` directly from its own prose (those fields are written only by the deterministic normalizer, the Validation Agent's checked outcome, and the Risk Agent respectively), or disable/evade auditing.
- The LLM/agent layer is **never ground truth** for severity or risk. Findings are investigated and validated by agents; they are **scored** only by the deterministic Risk Agent (`security/risk-analysis.md`) and only after the deterministic Attack Graph Agent has run.
- Every claim an agent writes must cite evidence IDs (`data/evidence-model.md`) from data actually collected in this assessment; output that mentions a CVE, IP, hostname, or port not present in the supplied context is flagged or rejected (grounding validator, carried over unchanged).
- "Insufficient evidence" / "left unresolved" is a valid, preferred outcome over a forced guess, at every stage (recon, investigation, validation), not only in final report text.
- AI-generated text is **always labeled** as AI-generated in the dashboard and in reports, and stored with provider, model, prompt version, and input hash.
- External LLM/provider use is **off by default** and gated by a per-deployment switch and a per-assessment consent flag; evidence is redacted before leaving the deployment.
- The **only** agent permitted to request a capability that could alter target state is the Validation Agent, and only for the specific, pre-reviewed, non-destructive check registered for the finding's class, and only when the assessment's validation flag is on (see `agents/validation-agent.md`). No other agent may request such a capability under any configuration.

## 6. Development

Never:

- rewrite working modules unnecessarily;
- introduce a dependency without a stated reason in the phase notes (standard library and existing dependencies first);
- duplicate a service or abstraction that exists;
- swallow errors (`except: pass`) or log-and-continue on a safety-relevant failure — scope, auth, and audit failures **fail closed**;
- disable, skip, or weaken a test to make a build pass;
- mark incomplete functionality as complete;
- silently change the architecture (see §8);
- implement a phase other than the one explicitly requested;
- commit real secrets, real third-party scan data, or real target data.

Always:

- inspect before editing; reuse before creating;
- write tests with the code (scope/auth/grounding/state-machine code requires negative tests);
- run tests, lint, type checks, and builds, and report results honestly, including failures;
- keep each change scoped to the current phase.

**Fixtures.** Test fixtures are either (a) *recorded* output from a real tool run against a lab target the developer owns, with the command and tool version noted alongside, or (b) *synthetic*, with `synthetic` in the filename or header. Fixtures must never be presented as evidence of a real vulnerability in a real system.

## 7. Status vocabulary

One vocabulary is used across all documents and code comments. (See ADR-018 for why it is unified.)

**Work-item status** (phases, components, features):

| Status | Meaning |
|---|---|
| `PLANNED` | Designed in docs, no code. |
| `IN PROGRESS` | Being implemented now. |
| `IMPLEMENTED` | Code exists and compiles/runs; tests may be incomplete. |
| `TESTED` | Automated tests for the acceptance criteria pass. |
| `VERIFIED` | Acceptance criteria independently checked (including against a real/lab system where the criteria say so) and the check recorded. |
| `BLOCKED` | Cannot proceed; reason recorded. |
| `DEPRECATED` | Superseded; replacement named. |

**Tool/provider integration status** — an integration moves through:

`PLANNED` → `MOCKED` (works against fixtures/fakes only) → `IMPLEMENTED` (works against the real tool/API in at least one manual run) → `VERIFIED` (covered by a repeatable lab/CI check that exercises the real tool) → `DEPRECATED`.

Two **tags** may accompany any integration status:

- `OPTIONAL` — the platform runs correctly without it (feature degrades gracefully).
- `FUTURE` — outside the MVP; no commitment on timing.

Rules:

- An integration may not be called *implemented* in docs, UI, or README until it has run against the real tool. Before that it is `MOCKED`.
- The word `DONE` is never used. Use `TESTED` or `VERIFIED`.
- Docs must never say "supports X" for anything below `IMPLEMENTED`.

**ADR status** uses its own vocabulary: `PROPOSED`, `ACCEPTED`, `SUPERSEDED`, `DEPRECATED`.

**Note (ADR-021):** `docs/roadmap/current-status.md` additionally uses `PARTIAL` (synonym for `IN PROGRESS`) and `NOT STARTED` (a component with a design document but literally zero code, as distinct from `PLANNED` used loosely elsewhere to mean "designed"). Where the two tables could be read as disagreeing, `current-status.md` is authoritative for "what exists today."

## 8. Documentation and architecture changes

When a significant architecture decision changes, **all three** are updated in the same change:

1. `docs/Decision.md` — a new ADR (or the old one marked `SUPERSEDED`),
2. `docs/Architecture.md`,
3. `docs/Memory.md`.

Also update `docs/PRD.md`, `docs/Design.md`, or `docs/Phases.md` if their content is affected. A change that makes docs and code disagree is not finished.

## 9. Changing a guardrail

A guardrail may only be changed by an explicit instruction from the project owner, recorded as an ADR that states which guardrail changed and why. Guardrails in §2 (scope) and §3 (safety — never) are **safety-critical**: weakening them also requires a new negative test demonstrating the replacement control works.

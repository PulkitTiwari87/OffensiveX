# LLM integration

Status: IMPLEMENTED and tested with fakes/mocks (unit + integration, real PostgreSQL).
**Verified against a real model for the OpenAI-compatible provider** (Google Gemini): the
three `real_llm` tests pass and one full pipeline + report run succeeded against a local
lab server — results and caveats in [../roadmap/current-status.md](../roadmap/current-status.md)
(Track B). **The Anthropic provider has not been run against a real endpoint.** See
[Verifying with a real provider](#verifying-with-a-real-provider). Decision: ADR-023 in
[../Decision.md](../Decision.md).

The AI architecture is unchanged: an LLM **analysis/decision layer** on top of
**deterministic engines**. No model is trained, no dataset or notebook exists.

## What the model does and does not do

| The model may | The model may not (enforced in code, not by prompt) |
|---|---|
| Choose which allowed tool to call next and with what request | Call a capability outside its agent's toolset (refused before the registry) |
| Decide when it has finished | Reach anything outside the authorized scope (Scope Guard, per call) |
| Write the `notes`/`summary` text of its result | Create an Asset, Observation, Finding or Evidence row — only deterministic normalizers do, from tool results |
| Interpret a check's result | Set a conclusion the tool contradicts: Investigation's `still_present` and Validation's `confirmed`/`rejected` must agree with what the check observed, or the run **fails** |
| Draft the report's executive summary | Cite evidence that is not in the report (ungrounded → rejected) or alter any score, status or graph |
| — | Grant or approve anything for a user: it is never given a user identity/role, and RBAC and the approval workflow are independent of it |
| — | Run commands/code: it can only emit an `AgentStep` naming a registered capability |

Tool results, page headers and bodies, discovered URLs and evidence excerpts are
**untrusted**: they are fenced in `<untrusted_data>` blocks (a closing tag inside the
payload is neutralised, results are size-clipped) and the prompt tells the model to
treat them as data. This lowers the chance of prompt injection; the guarantees above
are what limit the damage if it succeeds anyway.

## Which phases are genuinely LLM-driven

| Phase | Agent | LLM decides | Deterministic / enforced |
|---|---|---|---|
| P6 | Recon | which in-scope hosts/URLs to resolve and probe, in what order, when to stop (scope is in its prompt) | Scope Guard; Asset/Observation rows written only by normalizers |
| P8 | Vulnerability | which discovered endpoints to scan | the scanner (`security_header_scan`) and the normalizer create every Finding; the model **cannot** originate a finding. Only one scanner and one finding class exist, so "LLM-assisted discovery" today means choosing what to scan, not finding new classes |
| P9 | Investigation | how to re-check one finding; the `notes` | check must target the finding's own endpoint; `still_present` must match the observation; evidence rows come from the tool result; cannot set CONFIRMED/REJECTED (not in its output schema) |
| P10 | Validation | interpretation of the single registered check | opt-in gate at agent **and** registry; verdict must match the check; `unresolved` always allowed and changes nothing |
| P14 | Reporting | the executive summary only | every other section is built from stored rows; summary must cite real evidence ids; remediation text stays fixed per header class (no LLM remediation prose yet) |
| P12 attack graph, P13 risk | **none** — deterministic by design; an LLM narrative can never raise a score |

"LLM-driven" here means the mechanics are in place and tested with a scripted model
standing in; it does **not** mean a real model has been observed doing it.

## Pipeline

`services/pipeline.py` sequences the agents for a RUNNING assessment (Recon →
Vulnerability → Investigation per finding → Validation per investigated finding if the
assessment opted in), committing after each stage. A failed Recon/Vulnerability stage
ends the run (`failed`); a failed per-finding stage is recorded and the rest continue
(`completed_with_errors`), and a finding whose investigation failed is not validated.
It is started with:

```bash
python -m offensivex.admin run-assessment --assessment-id <uuid> [--report]
```

There is no HTTP route for this yet. This is the *minimum* stage sequencing, not the
full orchestrator (no queue, retries, prioritisation, or concurrency).

## Configuration

All variables use the project's existing `OFFENSIVEX_` prefix (`core/config.py`); the
unprefixed `LLM_*` names are **not** read. Real values go in your shell or an
untracked `backend/.env`; nothing is committed.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `OFFENSIVEX_LLM_ENABLED` | — | `false` | Master switch. When false nothing calls a model; reports record `ai_summary.status = "skipped"` |
| `OFFENSIVEX_LLM_PROVIDER` | if enabled | — | `anthropic`, `openai`, or `local`. (`gemini` has no native provider — use `openai` with Google's OpenAI-compatible `BASE_URL`) |
| `OFFENSIVEX_LLM_MODEL` | if enabled | — | Model id, passed through unchanged (no model name is hardcoded anywhere) |
| `OFFENSIVEX_LLM_API_KEY` | if enabled, except `local` | — | Secret (`SecretStr`; never logged or echoed) |
| `OFFENSIVEX_LLM_BASE_URL` | `local` only | provider default | Gateway/proxy, or the server for `local` (e.g. `http://localhost:11434/v1`) |
| `OFFENSIVEX_LLM_TIMEOUT_SECONDS` | — | `60` | Per-request timeout (≤ 600) |
| `OFFENSIVEX_LLM_MAX_RETRIES` | — | `2` | Retries after the first attempt, for transient errors and malformed output only (0–5). Total attempts = 1 + this, always |
| `OFFENSIVEX_LLM_MAX_OUTPUT_TOKENS` | — | `2048` | Output cap per call |
| `OFFENSIVEX_LLM_MAX_PROMPT_CHARS` | — | `60000` | A larger prompt is refused before it is sent |

Enabled-but-incomplete configuration **fails at startup** with the missing variable
names. Examples:

```bash
# Anthropic
OFFENSIVEX_LLM_ENABLED=true  OFFENSIVEX_LLM_PROVIDER=anthropic
OFFENSIVEX_LLM_MODEL=<model id>  OFFENSIVEX_LLM_API_KEY=<key>

# OpenAI
OFFENSIVEX_LLM_ENABLED=true  OFFENSIVEX_LLM_PROVIDER=openai
OFFENSIVEX_LLM_MODEL=<model id>  OFFENSIVEX_LLM_API_KEY=<key>

# Gemini via its OpenAI-compatible endpoint
OFFENSIVEX_LLM_ENABLED=true  OFFENSIVEX_LLM_PROVIDER=openai
OFFENSIVEX_LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
OFFENSIVEX_LLM_MODEL=<model id>  OFFENSIVEX_LLM_API_KEY=<key>

# Local OpenAI-compatible server (Ollama, vLLM, LM Studio…): no key needed
OFFENSIVEX_LLM_ENABLED=true  OFFENSIVEX_LLM_PROVIDER=local
OFFENSIVEX_LLM_BASE_URL=http://localhost:11434/v1  OFFENSIVEX_LLM_MODEL=<model>
```

## Providers

- **Anthropic** (`llm/providers/anthropic.py`, official `anthropic` SDK): structured
  output by forcing a single tool whose `input_schema` is the caller's JSON Schema;
  the SDK's own retries are off so the shared layer's bounds are the only ones.
- **OpenAI-compatible** (`llm/providers/openai_compat.py`, `httpx`): chat completions
  with `response_format: json_schema`. Sends `max_completion_tokens` only when the URL is
  `api.openai.com`, and `max_tokens` for every other server. Used for `openai` and `local`.
  A Gemini model with `PROVIDER=openai` and no `BASE_URL` is refused at startup, because the
  key would otherwise be sent to api.openai.com.
- **Gemini note (unverified):** Gemini 2.5 models spend part of the output budget on internal
  "thinking". If you see `LLMOutputError ... truncated`, raise `OFFENSIVEX_LLM_MAX_OUTPUT_TOKENS`
  (e.g. `8192`). Google's compatibility endpoint is documented to accept `response_format`
  `json_schema`, but that has only been checked against the docs, not a live call.

Both inherit `llm/structured.py`: schema validation of every reply; retry only on
timeout/connection error/408/409/429/5xx and on malformed or schema-invalid output;
no retry on 4xx auth/request errors; capped exponential backoff (0.5 s, 1 s, … ≤ 8 s);
truncated (`max_tokens`/`length`) replies are treated as malformed. Logs carry provider,
model, attempt, latency, token counts and the error *class* — never prompts,
completions, or credentials. Error messages never include the provider's response body.

The sync vendor client runs in a worker thread so the agent runtime's `asyncio.run()`
per turn never shares an event loop across calls.

## Failure semantics (nothing is faked)

| Situation | Result |
|---|---|
| Missing/invalid config | `LLMConfigurationError` (startup, or CLI exit 1) |
| Provider down / rate-limited after retries / bad key | `LLMProviderError`; the agent run is `FAILED`, pipeline records the stage failure |
| Reply not valid for the schema after retries | `LLMOutputError`; same |
| Prompt over the size cap | `LLMPromptTooLargeError`, nothing sent |
| Model requests a malformed tool call | fed back to the model (counts a turn; bounded by the agent's `max_turns`) |
| Model requests an out-of-task call (e.g. another endpoint) | refused and fed back; nothing executed |
| An allowed tool call fails (host unreachable, port closed, timeout) | `ToolRunError`: reported to the model as the call's result so it can adapt (bounded by `max_turns`); the `ToolExecution` row is marked `KILLED` |
| Model requests a capability outside its toolset / out of scope | the run fails (`ToolsetMembershipError` / `ScopeViolationError`) |
| Model's conclusion contradicts the tool | `AgentOutputContractError`; run `FAILED`; finding unchanged |
| Executive summary fails or is ungrounded | the report is still produced with **no** summary; `provenance.ai_summary = {status: "failed", error, …}` and a visible notice in the Markdown |

Report provenance for the AI section records provider, model, `prompt_version`
(`exec-summary-v1`) and status.

## Testing

- The default suite never calls a model: an autouse fixture forces
  `OFFENSIVEX_LLM_ENABLED=false` for every test, whatever your shell or `.env` says, and
  `addopts = -m 'not real_llm'` excludes the real tests.
- `tests/unit/test_llm_providers.py` — config validation, factory, retry bounds,
  permanent vs transient, malformed output, both providers' wire format via a fake SDK
  client and `httpx.MockTransport`, prompt fencing/clipping.
- `tests/integration/test_llm_agent_safety.py` — agents, pipeline and reports against
  real PostgreSQL and a real local HTTP server with a scripted model.
- `tests/integration/test_real_llm.py` — opt-in real-provider checks.

### Verifying with a real provider

```bash
# set the OFFENSIVEX_LLM_* variables for your provider (see above), then:
pytest -m real_llm tests/integration/test_real_llm.py -v
```

It checks schema-valid output, that a real model follows the `AgentStep` contract with
the trusted/untrusted prompt layout, and that a real summary passes the grounding check.
Then try the whole thing against a local lab target:
`python -m offensivex.admin run-assessment --assessment-id <uuid> --report`.

## Known limitations

- **The Anthropic provider has never run against a real endpoint**; its forced-tool-use
  request is verified only against a fake SDK client. The OpenAI-compatible provider has
  been verified against Gemini's endpoint (the `json_schema` response format worked);
  other servers are untested, and some local servers ignore `response_format` — a model
  that then answers in prose is rejected as malformed after the bounded retries.
- Model availability and capacity are outside the project's control: with Gemini,
  `gemini-2.5-flash` was unavailable to a new key (404), and several models returned
  503/429 or stalled for 45 s during testing. Retries are bounded (default 2); for
  flaky capacity set `OFFENSIVEX_LLM_MAX_RETRIES` higher (up to 5) or pick another model.
  Use `GET <base_url>/models` to see which models your key can use.
- Recon cannot discover ports (MVP scope). It learns the port from the target's
  configured `entry_point` (a validated URL, never inferred from the target name); a
  legacy target with no entry point only gets hostnames and the default http/https URLs.
- Prompt-injection defence is layered but not absolute (see ADR-023).
- Retries re-send the same prompt (no repair prompt); the backoff ignores `Retry-After`.
- There is no per-assessment token/cost budget — only the per-call caps and agent
  `max_turns`; one run can still make many calls.
- Prompts are not stored; to debug a bad decision you have `AgentRun.output_ref`,
  `ToolExecution` and the structured `llm.call*` log lines, not the raw prompt.

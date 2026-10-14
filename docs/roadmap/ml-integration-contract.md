# ML Integration Contract (future)

Status: **PLANNED** — a contract for a possible future integration. **Nothing in this document is implemented.** No model from `notebooks/` is loaded by, or shipped with, the application.
Related: [../Decision.md](../Decision.md) ADR-009 (no ML in the MVP critical path) and ADR-019 (`risk_model_v1`) · [../security/risk-analysis.md](../security/risk-analysis.md) · [../Guardrail.md](../Guardrail.md) §3 (never fabricate; risk scores only from the deterministic Risk Agent) · research notebooks: [../../notebooks/README.md](../../notebooks/README.md)

## 1. Principles

1. **Three different quantities are never merged into one number.** *Severity* (how bad if exploited, CVSS), *exploit likelihood* (will it be / is it exploited, KEV/EPSS-like), and *environmental risk* (what it means for this asset in this environment, `risk_model_v1`) are stored, named and displayed separately.
2. **Deterministic components stay authoritative.** If a CVSS vector exists, the deterministic calculator defines the score (the notebook-01 reconstruction benchmark shows ML only approximates it). If a CVE is in KEV, it *is* known-exploited, whatever a model says. `risk_score` is written only by the deterministic Risk Agent ([Guardrail](../Guardrail.md): nothing else, including agent prose, may set one).
3. **ML output is advisory metadata.** It never changes `Finding.severity`, `Finding.cvss_score`, `Finding.status`, `Finding.risk_score`, evidence, or an attack-graph edge. It is stored in its own clearly-named, versioned field and is always labelled as an estimate.
4. **Absence of a model is a normal state.** The product must behave identically (minus the advisory field) when no model is installed.
5. **A good experiment is not a reason to integrate.** See the acceptance gate in §9.

## 2. Candidate model slots (ADR-009's reserved `Predictor` interface)

| Slot | Notebook | May be integrated? | Authoritative alternative | Output name (never reuse an existing field) |
|---|---|---|---|---|
| Severity estimator | 01 | Only as a *pre-scoring estimate* for a CVE that has no vector yet | deterministic CVSS calculation; the NVD/CNA score once present | `ml_advisory.severity_estimate` |
| Exploit-likelihood ranker | 02 | Only as an *ordering hint* for CVEs **not** in KEV | KEV membership; (future, ADR required) EPSS lookup | `ml_advisory.kev_listing_probability` |
| Contextual priority model | 03 | **No** — the notebook trains none (no legitimate labels exist) | `risk_model_v1` | — |

A change to `risk_model_v1` itself (e.g. adding a KEV/EPSS exploitability factor, or continuous severity) is **not** an ML integration; it is a new deterministic version (`risk_model_v2`) requiring its own ADR, golden-value and monotonicity tests, and a bumped `RISK_MODEL_VERSION` — see notebook 03 for sensitivity evidence.

## 3. Expected input features and validation

Each slot has an exported `feature_schema.json` (written by the notebook) that is the single source of truth. The application must validate **before** inference and reject (not silently coerce) violations.

| Slot | Required raw inputs | Optional raw inputs | Derived inside the integration layer (reference code in the schema) |
|---|---|---|---|
| Severity | `description_en` (non-empty) | `source_identifier`, `primary_cwe_id` | `desc_length`, `desc_words`, `kw_*` flags |
| Exploit-likelihood | `description_en` (non-empty) | `cvss_v3_vector`, `cvss_v3_base_score`, `source_identifier`, `primary_cwe_id` | CVSS v3 metric categories, `has_cvss3`, text flags; **exploitation-statement scrubbing of the description** (leakage guard; the regex is stored in the schema) |

Validation rules (all mandatory):
* **Schema match:** `schema_name` and `schema_version` equal the model's; unknown extra columns are rejected.
* **Forbidden inputs are rejected:** any `cvss_*` score for the severity slot; any `epss_*`, `kev_*`, `reference_count`, `cpe_match_count`, `vuln_status`, `last_modified*` or date field — these are the leakage-controlled fields the models were trained *without*.
* **Ranges/format:** `cvss_v3_base_score` ∈ [0, 10] (computed from the vector with the official calculator if absent); vector must parse as CVSS 3.0/3.1 with all eight base metrics, otherwise it is treated as missing; CWE id pattern; text must be non-empty after scrubbing.
* **Version hygiene:** CVSS v2 / v3.x / v4.0 values are never mixed into one feature.

## 4. Missing-feature behaviour

| Situation | Behaviour |
|---|---|
| Required input missing / empty | **Reject** the request; no estimate is produced; deterministic flow continues |
| Optional categorical missing (`source_identifier`, `primary_cwe_id`) | Treated as the "unknown / infrequent" category (as trained); advisory marked `degraded_inputs: [...]` |
| CVSS vector missing (exploit slot) | `has_cvss3 = 0`, metric categories `MISSING` (as trained); marked degraded |
| Text becomes empty after scrubbing | Reject (a placeholder would itself leak the label) |
| Any field outside the training distribution (unseen CNA/CWE) | Handled by the encoder's infrequent-category path; no extrapolation claims |

## 5. Versioning

Every stored advisory carries: `model_id`, `model_version` (semver, bumped on any retrain), `schema_version`, `artifact_sha256`, `training_dataset_fingerprint` (from `dataset_metadata.json`), `trained_at`, the `python` and `scikit-learn` versions the artifact was built with, `fast_dev` (must be `false`), and the experiment-report reference. Re-scoring after a model change is an explicit job (mirroring the Risk Agent's re-scoring job), never a silent overwrite; old advisories keep their original version tag.
Load-time compatibility: refuse an artifact whose scikit-learn **major.minor** differs from the runtime's, whose checksum does not match the pinned value in configuration, or whose `fast_dev` is `true`.

## 6. Output format

```json
{
  "ml_advisory": {
    "slot": "exploit_likelihood",
    "is_estimate": true,
    "model_id": "cve-exploit-likelihood", "model_version": "0.1.0", "schema_version": "1.0.0",
    "artifact_sha256": "…", "training_dataset_fingerprint": "…",
    "kev_listing_probability": 0.031,
    "probability_meaning": "Calibrated estimate that this CVE is added to CISA KEV within 90 days of NVD publication, among CVEs resembling the training distribution. NOT a probability of compromise.",
    "flag": false, "threshold": 0.0354, "threshold_policy": "recall_target",
    "degraded_inputs": [],
    "limitations_ref": "model_card.md"
  }
}
```
Rules: the probability is shown with its meaning and horizon, never as "risk %" or "chance of breach"; the flag is a review-queue hint, never a verdict; a low value is never rendered as "safe". (The values above are illustrative placeholders, not results.)

## 7. Loading and inference requirements

* **Offline and sandboxed:** no network access at load or inference; run in-process only for artifacts the operator has pinned by checksum; otherwise in a restricted worker.
* **Pickle/joblib is code execution.** Artifacts are only ever loaded from the operator-configured path after SHA-256 verification; never from user uploads, assessment data, tool output, or URLs. (A future move to a non-pickle format is preferable.)
* Pure function of validated inputs, deterministic given a fixed artifact; no learning at runtime; no logging of raw descriptions beyond what findings already store.
* Latency/memory budget and CPU-only operation must be measured before enabling (not yet measured).

## 8. Fallback behaviour

Model missing, checksum mismatch, version-incompatible, schema-invalid input, or an inference exception ⇒ **omit `ml_advisory`**, emit a structured warning (no stack traces to users), and continue the deterministic pipeline unchanged. The assessment must never fail, block, or change a finding's status because an advisory is unavailable. The UI shows "estimate unavailable", not a default number.

## 9. Acceptance gate before any integration (all required)

1. Notebooks re-run **at full scale** by the owner on Kaggle with `FAST_DEV = False`; artifacts reproduced from the recorded dataset fingerprint and seeds; results recorded with the experiment-summary template.
2. **Out-of-time re-validation** on CVEs published after the training snapshot, and a drift check on the input distribution.
3. For the exploit slot: the operating threshold and precision/recall are reviewed by a stakeholder who accepts the cost of false positives; calibration re-checked on the new period.
4. For ADR-009's own criterion: an offline evaluation, on labelled data of the *deployed* task, shows the model beats the deterministic engine — notebook 03 shows this cannot currently be done (no contextual labels), so no contextual ML slot exists.
5. Security review of the artifact-loading path (§7); dependency pinning; model card and prohibited-use text surfaced in the UI/report.
6. New ADR (and updates to `current-status.md`, `risk-analysis.md` where relevant) merged **before** code; golden-value and fallback tests added.

## 10. Out of scope here

Training pipelines in production, online learning, feature stores, model registries, and any use of ML to set `risk_score`, change finding status, or choose agent actions.

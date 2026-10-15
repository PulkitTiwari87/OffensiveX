# OffensiveX ML research notebooks

Status: **EXPERIMENTAL research.** Three notebooks that study where machine learning could (and could not) help vulnerability prioritisation. **Nothing here is integrated into the application**, and the existing deterministic engines (`risk_model_v1`, the CVSS calculator) remain authoritative — see [ADR-009 and ADR-019](../docs/Decision.md) and the [future integration contract](../docs/roadmap/ml-integration-contract.md).

| # | Notebook | Question | Headline design choices |
|---|---|---|---|
| 01 | [`01_cve_severity_prediction.ipynb`](01_cve_severity_prediction.ipynb) | Can ML predict CVSS severity from CVE metadata? | **Experiment A** = reconstruction benchmark (re-learning the CVSS formula from base metrics — *not* a capability claim; an exact calculator is implemented and validated against every score). **Experiment B** = metadata-only prediction (description, CNA, CWE), chronological test, leakage audit, ablations. CVSS v2 / v3.0 / v3.1 / v4.0 are never mixed. |
| 02 | [`02_exploit_likelihood_prediction.ipynb`](02_exploit_likelihood_prediction.ipynb) | Can public metadata rank CVEs likely to enter CISA KEV within 90 days? | Label = KEV-within-horizon (explicitly *not* "exploited", *not* EPSS). Right-censoring, label-horizon **embargo**, class-imbalance metrics (PR-AUC), calibration fitted on validation only, thresholds/top-k, text-leakage guard, EPSS only as a labelled hindsight reference. |
| 03 | [`03_contextual_risk_prioritization.ipynb`](03_contextual_risk_prioritization.ipynb) | How do severity, exploit signals and asset context combine — and can ML beat the deterministic engine? | A **suitability gate**: public data has no contextual labels, so **no ML model is trained**. It builds an independent, parity-checked `risk_model_v1` baseline, clearly-**SIMULATED** scenarios, sensitivity analysis, and a guarded supervised branch that only runs on legitimately labelled data you supply. |

**Run order:** 01 → 02 → 03 (independent, but 02/03 reuse the same cached data and build on the concepts in 01). Each notebook is self-contained and runs top-to-bottom.

## The three concepts (do not conflate them)

* **Severity** — how bad a vulnerability is *if exploited*, per CVSS; context-free and deterministic from its metrics.
* **Exploit likelihood** — how likely it is to be (or already be) exploited. Different data: KEV (CISA's catalogue of known exploited CVEs), EPSS (FIRST's *model estimate*), PoC existence. KEV-negative ≠ "not exploited".
* **Contextual (environmental) risk** — what a finding means for *this* asset: criticality, exposure, evidence confidence, attack-path position. No public CVE dataset contains this, which is why notebook 03 refuses to train on public data.

## Verified datasets (checked 2026-10-14)

| Source | Identifier / URL | Used in | Access | License |
|---|---|---|---|---|
| **Kaggle: NVD CVE CVSS KEV EPSS Vulnerabilities 2020-2026** | `afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026` — file `nvd_cve_records.parquet` (41.8 MB; 201,542 CVEs × 106 columns; built 2026-05-02; documented by its own `data_dictionary.csv`) | 01, 02, 03 | **Kaggle Input panel** (no download, works with internet off). Elsewhere: Kaggle CLI/API | CC0 (per Kaggle listing) |
| NVD CVE JSON 2.0 yearly feeds | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<year>.json.gz` (10–25 MB each; keyed by **CVE-ID year**) | 01, 02, 03 (alternative) | public HTTPS; used only when `ALLOW_NETWORK=True` and nothing local is found | public NVD data |
| CISA KEV | `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv` | 02, 03 (official-feed route) | public HTTPS | see CISA's license link on the KEV page |
| FIRST EPSS | `https://epss.cyentia.com/epss_scores-current.csv.gz` | 02, 03 (reference only) | public HTTPS | free with attribution to FIRST |
| NVD CVE API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | **not used** | — | bulk feeds are cheaper; the API is paginated (≤2000/page) and rate-limited (5 requests / 30 s without a key) |

What was verified: the Kaggle dataset exists and its schema (data dictionary read; the CVSS v2 *component* columns are empty, so the notebooks parse metrics from vector strings); the official feed parser reproduces the Kaggle table on 99 %+ of CVSS fields for the same CVEs; the KEV and EPSS files are reachable and have the documented columns. **Not verified:** the full Kaggle CSV variant was not downloaded; behaviour on later dataset versions is untested (the schema check will fail clearly if columns change).

## Dependencies

Required: `numpy pandas scikit-learn(>=1.3) matplotlib seaborn joblib`; `pyarrow` only for `.parquet`. Optional: none (SHAP is deliberately not used). Kaggle and Colab already have all of them. Locally:

```bash
pip install numpy pandas "scikit-learn>=1.3" matplotlib seaborn joblib pyarrow jupyter
```

Nothing is installed or downloaded implicitly. No GPU is needed.

## Running on Kaggle (recommended)

1. New Notebook → **File → Import notebook** → upload one of the `.ipynb` files.
2. **Input → Add Input** → search `afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026` → add. Internet can stay **off**.
3. **Run All.** Auto-discovery finds `/kaggle/input/.../nvd_cve_records.parquet`; data is read in place (not copied).
4. Outputs land in `/kaggle/working/artifacts/ml-research/<experiment>/` — download them from the *Output* tab (they are not committed to Git).

**Cells/variables you may need to change** (all in the notebook's *Configuration* cell): `DATASET_PATH` (only if discovery fails), `ALLOW_NETWORK`, `NVD_YEARS` (feed route only), `OUTPUT_ROOT` (optional). Notebook 03 additionally has `CONTEXT_LABELS_PATH` (leave `None` unless you own legitimately labelled findings). Keep `FAST_DEV = False` for any run you intend to report.

## Running on Google Colab

Either set `ALLOW_NETWORK = True` (downloads the official NVD feeds, KEV and EPSS into a cache directory, with retries/back-off; cached afterwards), **or** use the Kaggle dataset:
1. Add `KAGGLE_USERNAME` and `KAGGLE_KEY` in Colab **Secrets** (key icon). **Never paste tokens into cells or commit them.**
2. In a cell: `from google.colab import userdata; import os; os.environ["KAGGLE_USERNAME"]=userdata.get("KAGGLE_USERNAME"); os.environ["KAGGLE_KEY"]=userdata.get("KAGGLE_KEY")`, then `!kaggle datasets download -d afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026 -f nvd_cve_records.parquet --unzip -p /content/data`.
3. Set `DATASET_PATH = "/content/data"` and Run All. Outputs: `/content/artifacts/ml-research/...`.

## Running locally

```bash
cd <repo>/notebooks
jupyter lab                      # open a notebook, set DATASET_PATH (or ALLOW_NETWORK=True), Run All
```
Outputs go to `<repo>/artifacts/ml-research/<experiment>/` (**git-ignored**). Offline mode: place `nvd_cve_records.parquet` (or `nvdcve-2.0-<year>.json.gz` files plus the KEV csv and EPSS csv.gz) under a folder and point `DATASET_PATH` at it; with `ALLOW_NETWORK=False` nothing is ever downloaded and a missing file produces an actionable error.

## Expected outputs

Each experiment writes to `artifacts/ml-research/<severity | exploit_likelihood | risk_prioritization>/`:

| File | Content |
|---|---|
| `models/*.joblib` | fitted preprocessing + model (01: regressor + classifier; 02: pipeline + calibrator + threshold bundle; 03: **none** unless you supplied valid labels) |
| `feature_schema.json`, `target_definition.json`, `hyperparameters.json` | what the model expects, how the label is defined, chosen parameters |
| `metrics.json`, `model_comparison*.csv`, `tuning_log.csv`, `subgroup_metrics.csv`, `*ablation*.csv` | all reported numbers |
| `dataset_metadata.json` (file SHA-256 fingerprints), `experiment_config.json`, `dependency_versions.json`, `exclusion_ledger.csv` | reproducibility record; **every dropped row is listed with a reason** |
| `experiment_report.md`, `model_card.md` | human-readable results (generated from the run's numbers) and intended/prohibited use |
| `plots/*.png` | every figure shown in the notebook (01: 20, 02: 15, 03: 4, or 6 with a valid labels file) |
| `blocked_report.json` (02 only, instead of models) | written when the target cannot be established (too few positives) |

Use [`EXPERIMENT_SUMMARY_TEMPLATE.md`](EXPERIMENT_SUMMARY_TEMPLATE.md) to record each full run so runs stay comparable. **Never commit** `artifacts/`, models, datasets or tokens (`artifacts/` is already in `.gitignore`).

## Runtime and resources

**Measured by the author** (Windows laptop, CPU only, Kaggle parquet): notebook 03 end-to-end through a Jupyter kernel on the **full** data: **≈ 1 minute**. Notebooks 01 and 02 were executed **only in `FAST_DEV` mode** (01: 40 k-row subsample ≈ 8 min as a script; 02: all positives + 40 k negatives ≈ 3 min) — **full-data runs of 01 and 02 have not been executed by the author.** Expect them to take noticeably longer than the FAST_DEV figures (01 trains ~190 k rows with TF-IDF/SVD, random forests, repeated splits and bootstrap CIs — likely tens of minutes; 02 is smaller). Memory: a few GB for 01/02; set `FAST_DEV=True` to debug quickly (results from such runs are flagged and must not be reported).

**Kaggle full-data runs (2026-10-14, CPU, `FAST_DEV=False`):** 01 ran in 2,219 s (44 files exported), 02 in 1,554 s (38 files), 03 in under a minute (21 files, no model). Outputs were downloaded to `artifacts/ml-research/<NN_name>/`; the integrated models are described in [`../docs/roadmap/ml-integration-contract.md`](../docs/roadmap/ml-integration-contract.md) §11.

## Common errors

| Symptom | Cause / fix |
|---|---|
| `DataNotFoundError: No supported dataset found…` | Dataset not attached / `DATASET_PATH` wrong. Kaggle: add the input. Else set the path or `ALLOW_NETWORK=True`. |
| `ValueError: Schema mismatch: … missing …` | A different/updated dataset layout. The message lists missing columns; adapt the dataset or the config. |
| `ImportError: scikit-learn >= 1.3 required` / unreadable `.parquet` | Upgrade scikit-learn / `pip install pyarrow`. |
| `RuntimeError: EXPERIMENT BLOCKED … positives` (02) | Too few KEV positives for the chosen horizon/years. Use more `NVD_YEARS`, a shorter `LABEL_HORIZON_DAYS`, or different `TIME_SPLIT_QUANTILES`. Intentional — no labels are fabricated. |
| Notebook 03 prints "SUPERVISED BRANCH SKIPPED" | Expected with public data. See its §14 for what labelled data would be needed. |
| `HTTP 403/404` on download | Official URL moved or blocked; download manually and use `DATASET_PATH`. 429/503 are retried with back-off. |
| Reload fails with a version error | Artifacts need the same scikit-learn major.minor (`dependency_versions.json`). |
| Kaggle: output not found | It is under `/kaggle/working/artifacts/ml-research/` — use the Output tab. |

## Limitations (read before citing any number)

* **Snapshot semantics:** NVD records reflect their *current* state (CWE, CVSS, descriptions may post-date publication). Leakage controls reduce but cannot eliminate this.
* **Heterogeneous scorers:** NVD vs hundreds of CNAs score differently; this bounds how learnable severity is.
* **KEV is an incomplete, US-federal-curated proxy** for exploitation; positives are rare (~0.3–0.5 % in the full data) and a large share are listed at/before NVD publication (unpredictable from metadata). Negative ≠ unexploited.
* **EPSS** is a model output and hindsight-contaminated for historical CVEs — never a label or a fair baseline.
* **Notebook 02's text-leakage guard** removes sentences such as "…exploited in the wild" from descriptions; without it the model trivially reads the label. The scrub is regex-based and may be imperfect.
* **Notebook 03:** scenario/sensitivity results are *simulated* and say nothing about real-world risk or predictive performance; no validated environmental-risk labels exist in public data.
* Confidence intervals are bootstrap/Wilson intervals over a single time-ordered test window; **no claim of statistical significance** is made.

## Research artifacts are not production-ready

Completing training means only that the code ran. Before any model is considered for the product it must pass the acceptance gate in the [integration contract](../docs/roadmap/ml-integration-contract.md) (full-scale reproduction, out-of-time validation, security review of artifact loading, a new ADR). Until then the deterministic engines decide; ML output, if ever shown, is a labelled estimate in a separate field.

# Experiment summary — <notebook> — <YYYY-MM-DD>

Copy this file per **full** run (never for `FAST_DEV` runs). Fill every field from the run's `experiment_report.md` / `metrics.json`; write "n/a" rather than leaving blanks.

| Field | Value |
|---|---|
| Notebook / experiment | 01 severity · 02 exploit likelihood · 03 risk prioritisation |
| Run by / environment | Kaggle · Colab · local — Python / scikit-learn versions |
| `FAST_DEV` | must be `false` |
| Dataset source + fingerprint | (`dataset_metadata.json` → `dataset_fingerprint_sha256`) |
| Snapshot / label horizon (02) | |
| Rows: analysed / train / val / test (positives for 02) | |
| Rows excluded and why | (top reasons from `exclusion_ledger.csv`) |
| Seed(s) | |
| Split protocol | chronological (+ embargo) · random |
| Selected model(s) + hyper-parameters | |
| Baselines (dummy / deterministic / comparator) and their scores | |

## Headline held-out results (test split only)

| Metric | Selected model | Baseline | 95 % CI / note |
|---|---|---|---|
| 01: MAE · R² · macro-F1 | | | |
| 02: PR-AUC · ROC-AUC · Brier · recall & precision at threshold · recall@5 % | | | |
| 03: gate result · ML trained? · (if trained) NDCG@k difference vs strongest baseline | | | |

## Checks

- [ ] Leakage audit table reviewed; ablation with leaked inputs recorded (01 §15, 02 §14)
- [ ] Reload smoke test passed; `artifacts/` not committed
- [ ] Subgroup / error analysis read; weakest subgroup: …
- [ ] Every number labelled observed vs simulated (03)
- [ ] Differences from the previous run explained (data version, config, code)

## Interpretation (≤ 5 lines)

What the result does and does **not** show; which prohibited interpretations from the model card apply.

## Decision

Integration status: **not integrated** (default) · candidate for the acceptance gate in `docs/roadmap/ml-integration-contract.md` (state which criteria are still open).

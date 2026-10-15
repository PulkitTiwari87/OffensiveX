"""ML advisory service (ADR-026; docs/roadmap/ml-integration-contract.md).

Produces *advisory estimates* for a CVE finding from two research models trained
in notebooks 01 (severity) and 02 (exploit likelihood). Hard rules, from the
contract and docs/Guardrail.md:

* Advisory only. Nothing here reads or writes `Finding.severity`, `cvss_score`,
  `status`, `risk_score`, evidence or attack-graph state. The result is a
  separate, versioned, always-labelled-as-estimate structure.
* Absence is a normal state. Disabled, no `ml` extra, missing/mismatched/
  unpinned artifact, incompatible scikit-learn, `fast_dev` artifact, invalid
  input or an inference error => no advisory (a structured warning is logged);
  the caller continues unchanged.
* joblib is pickle (code execution): an artifact is unpickled only if its
  SHA-256 equals the operator-pinned value in configuration.
* The severity estimate is offered only when the finding has no CVSS vector (the
  deterministic calculation stays authoritative). KEV membership is not known to
  this project, so the exploit advisory states that it was not checked.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensivex.core.config import Settings, get_settings
from offensivex.core.logging import get_logger

log = get_logger(__name__)

# src/offensivex/ml_advisory/service.py -> backend/
_BACKEND_DIR = Path(__file__).resolve().parents[3]

MODEL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_SEVERITY_MEANING = (
    "Model estimate of the CVSS v3.1 base score/band from the CVE description (and CWE) only. "
    "NOT an official or authoritative CVSS score and not exploit likelihood or business risk."
)
_EXPLOIT_MEANING = (
    "Calibrated estimate that this CVE is added to CISA KEV within 90 days of NVD publication, "
    "among CVEs resembling the training distribution. NOT a probability of compromise."
)


@dataclass(frozen=True)
class SlotSpec:
    slot: str
    dirname: str
    model_id: str
    schema_name: str
    artifacts: tuple[str, ...]  # paths relative to the slot directory


SEVERITY = SlotSpec(
    "severity",
    "severity",
    "cve-severity-estimator",
    "offensivex-ml-research/cve-severity-input",
    ("models/severity_regressor.joblib", "models/severity_classifier.joblib"),
)
EXPLOIT = SlotSpec(
    "exploit_likelihood",
    "exploit_likelihood",
    "cve-exploit-likelihood",
    "offensivex-ml-research/cve-exploit-likelihood-input",
    ("models/exploit_likelihood_bundle.joblib",),
)


class _Unavailable(Exception):
    """A slot cannot be used; the message is the (safe-to-log) reason."""


@dataclass
class _Loaded:
    spec: SlotSpec
    models: dict[str, Any]
    shas: dict[str, str]
    schema: dict
    meta: dict
    extra: dict


_cache: dict[tuple, _Loaded | None] = {}


def reset_cache() -> None:
    _cache.clear()


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _major_minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def _load(spec: SlotSpec, settings: Settings) -> _Loaded:
    try:
        import joblib
        import sklearn

        from offensivex.ml_advisory import features  # noqa: F401  (needs numpy/pandas)
    except ImportError as exc:
        raise _Unavailable("optional 'ml' dependencies are not installed") from exc

    base = Path(settings.ml_models_dir) if settings.ml_models_dir else _BACKEND_DIR / "models"
    root = base / spec.dirname

    shas: dict[str, str] = {}
    for rel in spec.artifacts:
        path = root / rel
        if not path.is_file():
            raise _Unavailable(f"artifact missing: {rel}")
        pin = settings.ml_artifact_pins.get(path.name)
        if not pin:
            raise _Unavailable(f"no pinned checksum configured for {path.name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if not hmac.compare_digest(digest, pin.lower()):
            raise _Unavailable(f"checksum mismatch for {path.name}")
        shas[path.name] = digest

    try:
        schema = _read_json(root / "feature_schema.json")
        deps = _read_json(root / "dependency_versions.json")
        metrics = _read_json(root / "metrics.json")
        dataset = _read_json(root / "dataset_metadata.json")
    except (OSError, ValueError) as exc:
        raise _Unavailable("model metadata missing or unreadable") from exc

    if (
        schema.get("schema_name") != spec.schema_name
        or schema.get("schema_version") != SCHEMA_VERSION
    ):
        raise _Unavailable("feature schema name/version mismatch")
    if metrics.get("fast_dev") is not False or dataset.get("fast_dev") is not False:
        raise _Unavailable("artifact was trained in fast_dev mode")
    if _major_minor(str(deps.get("sklearn", ""))) != _major_minor(sklearn.__version__):
        raise _Unavailable(
            f"scikit-learn mismatch: artifact {deps.get('sklearn')} "
            f"vs runtime {sklearn.__version__}"
        )

    models = {Path(rel).name: joblib.load(root / rel) for rel in spec.artifacts}
    meta = {
        "training_dataset_fingerprint": dataset.get("dataset_fingerprint_sha256"),
        # Time the training run loaded its dataset: the notebooks record no later timestamp.
        "trained_at": dataset.get("loaded_at_utc"),
        "python_version": deps.get("python"),
        "sklearn_version": deps.get("sklearn"),
    }

    extra: dict[str, Any] = {}
    if spec.slot == "severity":
        target = _read_json(root / "target_definition.json")
        extra["label_map"] = target["label_mapping_index_to_class"]
        extra["severity_map"] = target["offensivex_severity_mapping"]
    else:
        bundle = models["exploit_likelihood_bundle.joblib"]
        if bundle.get("fast_dev") is not False:
            raise _Unavailable("bundle was trained in fast_dev mode")
        if bundle.get("calibration_method") != "isotonic":
            raise _Unavailable("unsupported calibration method")  # YAGNI: only isotonic is exported
        if _major_minor(str(bundle.get("sklearn_version", ""))) != _major_minor(
            sklearn.__version__
        ):
            raise _Unavailable("bundle scikit-learn version mismatch")
    return _Loaded(spec, models, shas, schema, meta, extra)


def _get(spec: SlotSpec, settings: Settings) -> _Loaded | None:
    key = (spec.slot, settings.ml_models_dir, tuple(sorted(settings.ml_artifact_pins.items())))
    if key not in _cache:
        try:
            _cache[key] = _load(spec, settings)
        except _Unavailable as exc:
            log.warning("ml_advisory.slot_unavailable", slot=spec.slot, reason=str(exc))
            _cache[key] = None
        except Exception as exc:  # contract s8: any load failure => omit, never fail the request
            log.warning(
                "ml_advisory.slot_load_error", slot=spec.slot, error_type=type(exc).__name__
            )
            _cache[key] = None
    return _cache[key]


def _envelope(loaded: _Loaded, degraded: list[str]) -> dict:
    shas: Any = next(iter(loaded.shas.values())) if len(loaded.shas) == 1 else loaded.shas
    return {
        "slot": loaded.spec.slot,
        "is_estimate": True,
        "model_id": loaded.spec.model_id,
        "model_version": MODEL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "artifact_sha256": shas,
        **loaded.meta,
        "fast_dev": False,
        "degraded_inputs": degraded,
        "limitations_ref": "model_card.md",
    }


def _severity(loaded: _Loaded, description: str, cwe: str | None) -> dict:
    import numpy as np
    import pandas as pd

    from offensivex.ml_advisory.features import prepare_severity_inputs

    raw = pd.DataFrame([{"description_en": description, "primary_cwe_id": cwe}])
    x = prepare_severity_inputs(raw, loaded.schema["model_columns"])
    score = float(np.clip(loaded.models["severity_regressor.joblib"].predict(x)[0], 0.0, 10.0))
    idx = int(loaded.models["severity_classifier.joblib"].predict(x)[0])
    band = loaded.extra["label_map"][str(idx)]
    degraded = ["source_identifier"] + (
        [] if x["primary_cwe_id"].notna().iloc[0] else ["primary_cwe_id"]
    )
    return {
        **_envelope(loaded, degraded),
        "severity_estimate": {
            "cvss_v3_base_score": round(score, 1),
            "band": band,
            "offensivex_severity_equivalent": loaded.extra["severity_map"][band],
        },
        "estimate_meaning": _SEVERITY_MEANING,
    }


def _exploit(loaded: _Loaded, description: str, cvss_vector: str | None, cwe: str | None) -> dict:
    import pandas as pd

    from offensivex.ml_advisory.features import prepare_exploit_inputs

    bundle = loaded.models["exploit_likelihood_bundle.joblib"]
    raw = pd.DataFrame(
        [{"description_en": description, "cvss_v3_vector": cvss_vector, "primary_cwe_id": cwe}]
    )
    x = prepare_exploit_inputs(raw, bundle["model_columns"])
    score = bundle["pipeline"].predict_proba(x)[:, 1]
    prob = float(bundle["calibrator"].predict(score)[0])
    degraded = ["source_identifier"]
    if not x["has_cvss3"].iloc[0]:
        degraded.append("cvss_v3_vector")
    if x["primary_cwe_id"].isna().iloc[0]:
        degraded.append("primary_cwe_id")
    return {
        **_envelope(loaded, degraded),
        "kev_listing_probability": prob,
        "probability_meaning": _EXPLOIT_MEANING,
        "flag": prob >= float(bundle["threshold"]),
        "threshold": float(bundle["threshold"]),
        "threshold_policy": bundle["threshold_policy"],
        # No KEV data in this project; KEV membership would be authoritative.
        "known_exploited_check": "not_performed",
    }


def get_advisories(
    *,
    cve: str | None,
    description: str | None,
    cvss_vector: str | None = None,
    cwe: str | None = None,
    settings: Settings | None = None,
) -> list[dict]:
    """Advisory estimates for one CVE finding; `[]` whenever none is available."""
    settings = settings or get_settings()
    if not settings.ml_advisory_enabled:
        return []
    if not cve or not _CVE_RE.match(cve) or not description or not description.strip():
        return []  # the models are CVE-description models: nothing to say otherwise

    out: list[dict] = []
    jobs = []
    if not cvss_vector:  # a vector exists => the deterministic calculation is authoritative
        jobs.append((SEVERITY, lambda ld: _severity(ld, description, cwe)))
    jobs.append((EXPLOIT, lambda ld: _exploit(ld, description, cvss_vector, cwe)))
    for spec, build in jobs:
        loaded = _get(spec, settings)
        if loaded is None:
            continue
        try:
            out.append(build(loaded))
        except Exception as exc:  # contract s8: inference/validation failure => omit
            log.warning(
                "ml_advisory.inference_failed", slot=spec.slot, error_type=type(exc).__name__
            )
    return out

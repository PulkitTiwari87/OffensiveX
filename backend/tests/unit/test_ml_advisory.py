"""ML advisory layer (ADR-026): contract fallbacks, input validation, real-model smoke.

Fallback tests use fake artifact bytes and assert the pickle is NEVER loaded when a
gate fails (docs/roadmap/ml-integration-contract.md sections 5, 7, 8). Real-model
tests run only when the optional `ml` extra and the staged artifacts are present.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from offensivex.core.config import Settings
from offensivex.ml_advisory import service

pd = pytest.importorskip("pandas")
pytest.importorskip("sklearn")
from offensivex.ml_advisory import features  # noqa: E402

MODELS = Path(__file__).resolve().parents[2] / "models"
DESC = (
    "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints. "
    "An attacker who can control log messages can execute arbitrary code."
)
CVE = "CVE-2021-44228"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _settings(**kw) -> Settings:
    return Settings(_env_file=None, ml_advisory_enabled=True, **kw)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(autouse=True)
def _fresh_cache():
    service.reset_cache()
    yield
    service.reset_cache()


@pytest.fixture
def forbid_unpickle(monkeypatch):
    import joblib

    def _boom(*_a, **_k):  # pragma: no cover - only runs on a regression
        raise AssertionError("joblib.load must not run when a gate fails")

    monkeypatch.setattr(joblib, "load", _boom)


def _fake_slot(tmp_path: Path, spec: service.SlotSpec, *, fast_dev=False, sklearn_version=None):
    """A slot directory with fake artifact bytes and valid-looking metadata."""
    import sklearn

    root = tmp_path / spec.dirname
    pins = {}
    for rel in spec.artifacts:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"not a pickle")
        pins[p.name] = _sha(p)
    (root / "feature_schema.json").write_text(
        json.dumps({"schema_name": spec.schema_name, "schema_version": service.SCHEMA_VERSION})
    )
    (root / "dependency_versions.json").write_text(
        json.dumps({"sklearn": sklearn_version or sklearn.__version__})
    )
    (root / "metrics.json").write_text(json.dumps({"fast_dev": fast_dev}))
    (root / "dataset_metadata.json").write_text(json.dumps({"fast_dev": False}))
    return pins


# --- fallbacks: every failure omits the advisory (contract section 8) -----------


def test_disabled_by_default_returns_nothing():
    s = Settings(_env_file=None)
    assert s.ml_advisory_enabled is False
    assert service.get_advisories(cve=CVE, description=DESC, settings=s) == []


@pytest.mark.parametrize(
    ("cve", "description"),
    [(None, DESC), ("not-a-cve", DESC), (CVE, None), (CVE, "   ")],
)
def test_non_cve_or_empty_description_returns_nothing(cve, description):
    assert service.get_advisories(cve=cve, description=description, settings=_settings()) == []


def test_unpinned_artifact_is_never_loaded(tmp_path, forbid_unpickle):
    _fake_slot(tmp_path, service.SEVERITY)
    s = _settings(ml_models_dir=str(tmp_path), ml_artifact_pins={})
    assert service.get_advisories(cve=CVE, description=DESC, settings=s) == []


def test_checksum_mismatch_is_never_loaded(tmp_path, forbid_unpickle):
    pins = _fake_slot(tmp_path, service.SEVERITY)
    pins["severity_regressor.joblib"] = "0" * 64
    s = _settings(ml_models_dir=str(tmp_path), ml_artifact_pins=pins)
    assert service.get_advisories(cve=CVE, description=DESC, settings=s) == []


def test_fast_dev_artifact_is_refused_before_unpickling(tmp_path, forbid_unpickle):
    pins = _fake_slot(tmp_path, service.SEVERITY, fast_dev=True)
    s = _settings(ml_models_dir=str(tmp_path), ml_artifact_pins=pins)
    assert service.get_advisories(cve=CVE, description=DESC, settings=s) == []


def test_sklearn_major_minor_mismatch_is_refused_before_unpickling(tmp_path, forbid_unpickle):
    pins = _fake_slot(tmp_path, service.SEVERITY, sklearn_version="1.5.2")
    s = _settings(ml_models_dir=str(tmp_path), ml_artifact_pins=pins)
    assert service.get_advisories(cve=CVE, description=DESC, settings=s) == []


# --- input validation (contract section 3: reject, never coerce) -----------------


@pytest.mark.parametrize("bad", ["epss_score", "kev_flag", "last_modified", "published_date"])
def test_exploit_inputs_reject_forbidden_columns(bad):
    raw = pd.DataFrame([{"description_en": DESC, bad: 1}])
    with pytest.raises(ValueError, match="forbidden"):
        features.prepare_exploit_inputs(raw, ["description_en"])


@pytest.mark.parametrize("bad", ["cvss_v3_base_score", "severity", "cvss_v3_vector", "epss_score"])
def test_severity_inputs_reject_forbidden_columns(bad):
    raw = pd.DataFrame([{"description_en": DESC, bad: "x"}])
    with pytest.raises(ValueError, match="forbidden"):
        features.prepare_severity_inputs(raw, ["description_en"])


def test_unknown_extra_column_is_rejected():
    raw = pd.DataFrame([{"description_en": DESC, "asset_name": "web01"}])
    with pytest.raises(ValueError, match="unknown input column"):
        features.prepare_severity_inputs(raw, ["description_en"])


def test_empty_description_and_out_of_range_score_rejected():
    with pytest.raises(ValueError, match="non-empty"):
        features.prepare_exploit_inputs(pd.DataFrame([{"description_en": " "}]), ["description_en"])
    raw = pd.DataFrame([{"description_en": DESC, "cvss_v3_base_score": 99.0}])
    with pytest.raises(ValueError, match="0-10"):
        features.prepare_exploit_inputs(raw, ["description_en"])


def test_description_that_is_only_an_exploitation_statement_is_rejected():
    raw = pd.DataFrame(
        [{"description_en": "This vulnerability is being actively exploited in the wild."}]
    )
    with pytest.raises(ValueError, match="exploitation statement"):
        features.prepare_exploit_inputs(raw, ["description_en"])


def test_exploitation_statements_are_scrubbed_from_text():
    s = pd.Series(["Heap overflow in foo. Reported as exploited in the wild. Fixed in 2.1."])
    out = features.scrub_exploitation_statements(s).iloc[0]
    assert "in the wild" not in out and "Heap overflow" in out and "Fixed in 2.1" in out


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ],
)
def test_cvss3_calculator_golden_values(vector, score):
    assert features.cvss3_base_score(vector) == score


# --- real models (skipped unless staged) -----------------------------------------

_real = pytest.mark.skipif(
    not (MODELS / "severity" / "models").is_dir()
    or not (MODELS / "exploit_likelihood" / "models").is_dir(),
    reason="staged ML artifacts not present (backend/models/ is git-ignored)",
)


def _real_pins() -> dict[str, str]:
    files = [*(MODELS / "severity" / "models").glob("*.joblib")]
    files += [*(MODELS / "exploit_likelihood" / "models").glob("*.joblib")]
    return {p.name: _sha(p) for p in files}


@_real
def test_real_models_produce_contract_shaped_advisories():
    s = _settings(ml_artifact_pins=_real_pins())
    out = {a["slot"]: a for a in service.get_advisories(cve=CVE, description=DESC, settings=s)}
    assert set(out) == {"severity", "exploit_likelihood"}
    for a in out.values():
        assert a["is_estimate"] is True and a["fast_dev"] is False
        assert a["model_version"] == service.MODEL_VERSION
        assert len(a["training_dataset_fingerprint"]) == 64
        assert a["limitations_ref"] == "model_card.md"
    sev = out["severity"]["severity_estimate"]
    assert 0.0 <= sev["cvss_v3_base_score"] <= 10.0 and sev["band"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }
    ex = out["exploit_likelihood"]
    assert 0.0 <= ex["kev_listing_probability"] <= 1.0
    assert ex["known_exploited_check"] == "not_performed"
    assert (
        isinstance(ex["flag"], bool)
        and "NOT a probability of compromise" in ex["probability_meaning"]
    )


@_real
def test_real_severity_estimate_is_omitted_when_a_cvss_vector_exists():
    s = _settings(ml_artifact_pins=_real_pins())
    slots = [
        a["slot"]
        for a in service.get_advisories(cve=CVE, description=DESC, cvss_vector=VECTOR, settings=s)
    ]
    assert slots == ["exploit_likelihood"]


@_real
def test_real_models_are_deterministic():
    s = _settings(ml_artifact_pins=_real_pins())
    a = service.get_advisories(cve=CVE, description=DESC, settings=s)
    b = service.get_advisories(cve=CVE, description=DESC, settings=s)
    assert a == b

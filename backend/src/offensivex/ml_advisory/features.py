"""Input validation and feature derivation for the ML advisory models.

A faithful port of the reference `prepare_inputs` functions in
notebooks/01_cve_severity_prediction.ipynb and
notebooks/02_exploit_likelihood_prediction.ipynb — the models were trained on
exactly these derived columns, so the logic must not drift from the notebooks.
Contract: docs/roadmap/ml-integration-contract.md section 3 (reject, never
coerce). Requires the optional `ml` extra (numpy, pandas); `service` imports
this module lazily so the application runs without them.
"""

from __future__ import annotations

import math
import re

import numpy as np
import pandas as pd

CVSS3_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

FLAG_PATTERNS = {
    "kw_rce": r"remote code execution|execute arbitrary (?:code|commands?)|arbitrary code|code execution|command injection|os command",
    "kw_sqli": r"sql injection|\bsqli\b",
    "kw_xss": r"cross[- ]site scripting|\bxss\b",
    "kw_memory": r"buffer overflow|out[- ]of[- ]bounds|heap[- ]based|stack[- ]based|use[- ]after[- ]free|memory corruption",
    "kw_auth_bypass": r"authentication bypass|bypass authentication|improper authentication|missing authentication",
    "kw_privesc": r"privilege escalation|escalat\w+ privileges|gain privileges|elevat\w+ privileges",
    "kw_dos": r"denial of service|\bdos\b|infinite loop|resource exhaustion",
    "kw_traversal": r"path traversal|directory traversal",
    "kw_csrf": r"cross[- ]site request forgery|\bcsrf\b",
    "kw_infoleak": r"information disclosure|sensitive information|information leak",
    "kw_remote": r"\bremote(?:ly)?\b|over the network",
    "kw_local": r"\blocal(?:ly)?\b",
    "kw_unauth": r"unauthenticated|without authentication|not require authentication|no authentication",
    "kw_auth": r"\bauthenticated\b|valid credentials|logged[- ]in|low[- ]privileged",
    "kw_user_interaction": r"user interaction|convince|trick|if a user|victim|\bclick",
    "kw_exploit_public": r"exploit (?:is|has been|code)[^.]{0,30}(?:public|disclosed|available|released)|publicly (?:exploit|disclosed)|proof[- ]of[- ]concept",
}

# Sentences stating exploitation evidence are removed before featurising (a label
# leak otherwise — notebook 02 section on the text-leakage guard).
EXPLOIT_STMT_PATTERN = (
    r"(?i)[^.!?]*\b(?:in the wild|actively exploit\w*|active exploitation|being exploited|"
    r"(?:has|have|had) been exploited|known to be exploited|"
    r"aware of (?:any )?reports?|zero[- ]day|0[- ]day|"
    r"exploitation (?:of this|has been|was|is) (?:observed|detected|reported|occurring))\b[^.!?]*[.!?]?"
)

# Leakage-controlled fields the models were trained WITHOUT (contract section 3).
FORBIDDEN_RE_SEVERITY = re.compile(
    r"cvss|score|severity|epss|kev|^y$|^label$|best_|exploitab|impact|vuln_status|last_modified|offensivex_severity",
    re.I,
)
FORBIDDEN_RE_EXPLOIT = re.compile(
    r"epss|kev|^y$|^y_|lag_days|vuln_status|last_modified|published|cvss_v2|cvss_v40|description_raw|had_exploit",
    re.I,
)

ALLOWED_SEVERITY = {"description_en", "source_identifier", "primary_cwe_id"}
ALLOWED_EXPLOIT = ALLOWED_SEVERITY | {"cvss_v3_vector", "cvss_v3_base_score"}

_CWE_RE = re.compile(r"^(CWE-\d+|NVD-CWE-(noinfo|Other))$")

_W31 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def parse_cvss_vector(vec):
    """'CVSS:3.1/AV:N/...' -> (version, {metric: value}); None if unparsable."""
    if not isinstance(vec, str) or not vec:
        return None
    version, metrics = None, {}
    for part in vec.split("/"):
        if ":" not in part:
            return None
        k, v = part.split(":", 1)
        if k == "CVSS":
            version = v
        else:
            metrics[k] = v
    return (version or "2.0"), metrics


def _roundup_31(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector):
    """Official CVSS v3.0/v3.1 base score from a vector string (None if invalid)."""
    p = parse_cvss_vector(vector)
    if p is None or p[0] not in ("3.0", "3.1"):
        return None
    ver, m = p
    try:
        changed = m["S"] == "C"
        iss = 1 - (1 - _W31["CIA"][m["C"]]) * (1 - _W31["CIA"][m["I"]]) * (1 - _W31["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        pr = (_W31["PR_C"] if changed else _W31["PR_U"])[m["PR"]]
        expl = 8.22 * _W31["AV"][m["AV"]] * _W31["AC"][m["AC"]] * pr * _W31["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min((impact + expl) * (1.08 if changed else 1.0), 10)
    return _roundup_31(raw) if ver == "3.1" else math.ceil(raw * 10 - 1e-9) / 10.0


def scrub_exploitation_statements(s: pd.Series) -> pd.Series:
    return (
        s.fillna("")
        .str.replace(EXPLOIT_STMT_PATTERN, " ", regex=True)
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )


def add_text_features(df: pd.DataFrame) -> pd.DataFrame:
    """desc_length, desc_words and kw_* flags — pure row-wise functions of the text."""
    d = df.copy()
    text = d["description_en"].fillna("")
    low = text.str.lower()
    d["desc_length"] = text.str.len().astype("int32")
    d["desc_words"] = text.str.split().str.len().astype("int32")
    for name, pat in FLAG_PATTERNS.items():
        d[name] = low.str.contains(pat, regex=True).astype("int8")
    return d


def _check_columns(raw: pd.DataFrame, allowed: set[str], forbidden: re.Pattern) -> None:
    if "description_en" not in raw.columns:
        raise ValueError("missing required input column: description_en")
    bad = [c for c in raw.columns if forbidden.search(c)]
    if bad:
        raise ValueError(f"forbidden (leakage-prone) input column(s): {bad}")
    extra = [c for c in raw.columns if c not in allowed]
    if extra:
        raise ValueError(f"unknown input column(s): {extra}")  # contract s3: reject extras
    if (
        raw["description_en"].isna().any()
        or raw["description_en"].astype(str).str.strip().eq("").any()
    ):
        raise ValueError("description_en must be non-empty for every row")


def _clean_cwe(s: pd.Series) -> pd.Series:
    return s.where(s.map(lambda v: isinstance(v, str) and bool(_CWE_RE.match(v))), None)


def prepare_severity_inputs(raw: pd.DataFrame, model_columns: list[str]) -> pd.DataFrame:
    _check_columns(raw, ALLOWED_SEVERITY, FORBIDDEN_RE_SEVERITY)
    x = raw.copy()
    for c in ALLOWED_SEVERITY:
        if c not in x.columns:
            x[c] = None
    x["primary_cwe_id"] = _clean_cwe(x["primary_cwe_id"])
    return add_text_features(x.assign(description_en=x["description_en"].astype(str)))[
        model_columns
    ]


def prepare_exploit_inputs(raw: pd.DataFrame, model_columns: list[str]) -> pd.DataFrame:
    _check_columns(raw, ALLOWED_EXPLOIT, FORBIDDEN_RE_EXPLOIT)
    x = raw.copy()
    for c in ("cvss_v3_vector", "cvss_v3_base_score", "source_identifier", "primary_cwe_id"):
        if c not in x.columns:
            x[c] = None
    x["primary_cwe_id"] = _clean_cwe(x["primary_cwe_id"])
    parsed = x["cvss_v3_vector"].map(parse_cvss_vector)
    ok = parsed.map(
        lambda p: p is not None and p[0] in ("3.0", "3.1") and all(m in p[1] for m in CVSS3_METRICS)
    )
    score = pd.to_numeric(x["cvss_v3_base_score"], errors="coerce")
    if (score.dropna().lt(0) | score.dropna().gt(10)).any():
        raise ValueError("cvss_v3_base_score must be within 0-10")
    calc = pd.Series(
        [
            cvss3_base_score(v) if o else np.nan
            for v, o in zip(x["cvss_v3_vector"], ok, strict=True)
        ],
        index=x.index,
        dtype=float,
    )
    x["cvss3_score"] = score.where(score.notna(), calc)
    x["has_cvss3"] = x["cvss3_score"].notna().astype(int)
    for m in CVSS3_METRICS:
        x[f"c3_{m}"] = [p[1][m] if o else "MISSING" for p, o in zip(parsed, ok, strict=True)]
    x["description_en"] = scrub_exploitation_statements(x["description_en"].astype(str))
    if (x["description_en"].str.len() == 0).any():
        raise ValueError(
            "description_en consists only of an exploitation statement; "
            "nothing left to score after the leakage guard"
        )
    return add_text_features(x)[model_columns]

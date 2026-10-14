"""`risk_model_v1` — Phase 13.

Implements exactly the formula finalized in
docs/security/risk-analysis.md's "`risk_model_v1` (finalized, Phase 13)"
section. Keep this module and that section in sync; if one changes, the
other must too, and `RISK_MODEL_VERSION` must bump.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from offensivex.db import models

RISK_MODEL_VERSION = "risk_model_v1"

_SEVERITY_WEIGHT: dict[models.FindingSeverity, float] = {
    models.FindingSeverity.INFO: 0.1,
    models.FindingSeverity.LOW: 0.3,
    models.FindingSeverity.MEDIUM: 0.5,
    models.FindingSeverity.HIGH: 0.75,
    models.FindingSeverity.CRITICAL: 1.0,
}

_IMPACT_WEIGHT: dict[models.ImpactLevel, float] = {
    models.ImpactLevel.LOW: 0.25,
    models.ImpactLevel.MEDIUM: 0.5,
    models.ImpactLevel.HIGH: 0.75,
    models.ImpactLevel.CRITICAL: 1.0,
}

_EVIDENCE_WEIGHT: dict[models.EvidenceLevel, float] = {
    models.EvidenceLevel.VERIFIED: 1.0,
    models.EvidenceLevel.OBSERVED: 0.9,
    models.EvidenceLevel.INFERRED: 0.6,
    models.EvidenceLevel.POTENTIAL: 0.3,
}

# Weakest-first, for picking the weakest edge caused by a finding (same
# ranking offensivex.attack_graph.engine uses for a path's weakest edge).
_EVIDENCE_RANK: dict[models.EvidenceLevel, int] = {
    models.EvidenceLevel.POTENTIAL: 0,
    models.EvidenceLevel.INFERRED: 1,
    models.EvidenceLevel.OBSERVED: 2,
    models.EvidenceLevel.VERIFIED: 3,
}


def _band(score: float) -> str:
    if score >= 7.5:
        return "critical"
    if score >= 5.0:
        return "high"
    if score >= 2.5:
        return "medium"
    return "low"


@dataclass(frozen=True)
class RiskResult:
    score: float
    breakdown: dict[str, Any]


def compute_risk(session: Session, finding: models.Finding) -> RiskResult:
    unknowns_defaulted: list[str] = []

    asset = finding.asset
    target = finding.assessment.target

    criticality = asset.criticality
    if criticality is None:
        criticality = target.default_criticality
        unknowns_defaulted.append("asset.criticality (defaulted to target.default_criticality)")

    exposure = asset.exposure
    if exposure is None:
        exposure = target.default_exposure
        unknowns_defaulted.append("asset.exposure (defaulted to target.default_exposure)")

    base = _SEVERITY_WEIGHT[finding.severity] * 10
    confidence_factor = finding.confidence
    criticality_factor = _IMPACT_WEIGHT[criticality]
    exposure_factor = _IMPACT_WEIGHT[exposure]

    edges = session.scalars(
        select(models.AttackEdge).where(models.AttackEdge.cause_id == finding.id)
    ).all()
    on_attack_graph = len(edges) > 0
    if on_attack_graph:
        weakest_edge = min(edges, key=lambda e: _EVIDENCE_RANK[e.evidence_level])
        evidence_multiplier = _EVIDENCE_WEIGHT[weakest_edge.evidence_level]
        weakest_evidence_level: str | None = weakest_edge.evidence_level.value
        graph_factor = 1.0 + 0.5 * evidence_multiplier
    else:
        weakest_evidence_level = None
        graph_factor = 1.0
        unknowns_defaulted.append("not yet on the attack graph (neutral: graph_factor = 1.0)")

    raw_score = (
        base * confidence_factor * ((criticality_factor + exposure_factor) / 2) * graph_factor
    )
    score = round(max(0.0, min(10.0, raw_score)), 2)

    breakdown = {
        "model_version": RISK_MODEL_VERSION,
        "base_severity_score": base,
        "confidence_factor": confidence_factor,
        "asset_criticality": criticality.value,
        "criticality_factor": criticality_factor,
        "asset_exposure": exposure.value,
        "exposure_factor": exposure_factor,
        "on_attack_graph": on_attack_graph,
        "weakest_evidence_level": weakest_evidence_level,
        "graph_factor": graph_factor,
        "risk_band": _band(score),
        "unknowns_defaulted": unknowns_defaulted,
        "heuristic_not_validated": True,
    }
    return RiskResult(score=score, breakdown=breakdown)


def score_finding(session: Session, finding: models.Finding) -> models.Finding:
    result = compute_risk(session, finding)
    finding.risk_score = result.score
    finding.risk_breakdown = result.breakdown
    finding.risk_model_version = RISK_MODEL_VERSION
    session.flush()
    return finding


def score_assessment_findings(
    session: Session, assessment: models.Assessment
) -> list[models.Finding]:
    findings = session.scalars(
        select(models.Finding).where(models.Finding.assessment_id == assessment.id)
    ).all()
    return [score_finding(session, finding) for finding in findings]

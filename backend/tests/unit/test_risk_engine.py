"""Unit tests for risk_model_v1's arithmetic and monotonicity — the
"golden-value tests, monotonicity property tests" ADR-019 names. No real
database: a MagicMock session stands in for the one query the engine
makes (attack-graph edges caused by this finding), and plain,
unpersisted ORM instances carry the rest (SQLAlchemy relationships work
as ordinary Python attributes even without a session).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from offensivex.db import models
from offensivex.risk.engine import compute_risk


def _finding(
    *,
    severity: models.FindingSeverity = models.FindingSeverity.MEDIUM,
    confidence: float = 1.0,
    asset_criticality: models.ImpactLevel | None = None,
    asset_exposure: models.ImpactLevel | None = None,
    target_default: models.ImpactLevel = models.ImpactLevel.MEDIUM,
) -> models.Finding:
    target = models.Target(
        name="x",
        type="web_application",
        default_criticality=target_default,
        default_exposure=target_default,
    )
    assessment = models.Assessment()
    assessment.target = target
    asset = models.Asset(
        asset_type=models.AssetType.ENDPOINT,
        canonical_key="x",
        criticality=asset_criticality,
        exposure=asset_exposure,
    )
    finding = models.Finding(
        title="x",
        severity=severity,
        confidence=confidence,
        source="security_header_scan",
        affected_component="X-Frame-Options",
        status=models.FindingStatus.DISCOVERED,
    )
    finding.asset = asset
    finding.assessment = assessment
    return finding


def _session_with_edges(edges: list) -> MagicMock:
    session = MagicMock()
    session.scalars.return_value.all.return_value = edges
    return session


def _mock_edge(evidence_level: models.EvidenceLevel) -> MagicMock:
    edge = MagicMock()
    edge.evidence_level = evidence_level
    return edge


def test_golden_value_no_graph_edge_default_unknowns() -> None:
    finding = _finding(severity=models.FindingSeverity.MEDIUM, confidence=1.0)
    result = compute_risk(_session_with_edges([]), finding)
    # base=5, confidence=1.0, criticality=exposure=0.5 (defaulted), graph=1.0
    # -> 5 * 1.0 * 0.5 * 1.0 = 2.5
    assert result.score == 2.5
    assert result.breakdown["model_version"] == "risk_model_v1"
    assert result.breakdown["on_attack_graph"] is False
    assert result.breakdown["risk_band"] == "medium"
    assert len(result.breakdown["unknowns_defaulted"]) == 3  # criticality, exposure, graph


def test_higher_severity_never_decreases_score() -> None:
    session = _session_with_edges([])
    low = compute_risk(session, _finding(severity=models.FindingSeverity.LOW)).score
    medium = compute_risk(session, _finding(severity=models.FindingSeverity.MEDIUM)).score
    high = compute_risk(session, _finding(severity=models.FindingSeverity.HIGH)).score
    critical = compute_risk(session, _finding(severity=models.FindingSeverity.CRITICAL)).score
    assert low <= medium <= high <= critical


def test_higher_confidence_never_decreases_score() -> None:
    session = _session_with_edges([])
    low_conf = compute_risk(session, _finding(confidence=0.3)).score
    high_conf = compute_risk(session, _finding(confidence=1.0)).score
    assert low_conf <= high_conf


def test_higher_asset_criticality_never_decreases_score() -> None:
    session = _session_with_edges([])
    low = compute_risk(session, _finding(asset_criticality=models.ImpactLevel.LOW)).score
    critical = compute_risk(session, _finding(asset_criticality=models.ImpactLevel.CRITICAL)).score
    assert low <= critical


def test_higher_asset_exposure_never_decreases_score() -> None:
    session = _session_with_edges([])
    low = compute_risk(session, _finding(asset_exposure=models.ImpactLevel.LOW)).score
    critical = compute_risk(session, _finding(asset_exposure=models.ImpactLevel.CRITICAL)).score
    assert low <= critical


def test_being_on_attack_graph_never_decreases_score() -> None:
    finding = _finding()
    off_graph = compute_risk(_session_with_edges([]), finding).score
    on_graph = compute_risk(
        _session_with_edges([_mock_edge(models.EvidenceLevel.VERIFIED)]), finding
    ).score
    assert on_graph >= off_graph


def test_stronger_evidence_never_decreases_score() -> None:
    finding = _finding()
    potential = compute_risk(
        _session_with_edges([_mock_edge(models.EvidenceLevel.POTENTIAL)]), finding
    ).score
    verified = compute_risk(
        _session_with_edges([_mock_edge(models.EvidenceLevel.VERIFIED)]), finding
    ).score
    assert potential <= verified


def test_weakest_edge_is_used_when_multiple_exist() -> None:
    finding = _finding()
    result = compute_risk(
        _session_with_edges(
            [
                _mock_edge(models.EvidenceLevel.VERIFIED),
                _mock_edge(models.EvidenceLevel.POTENTIAL),
            ]
        ),
        finding,
    )
    assert result.breakdown["weakest_evidence_level"] == "potential"


def test_score_is_clamped_to_ten() -> None:
    finding = _finding(
        severity=models.FindingSeverity.CRITICAL,
        confidence=1.0,
        asset_criticality=models.ImpactLevel.CRITICAL,
        asset_exposure=models.ImpactLevel.CRITICAL,
    )
    result = compute_risk(_session_with_edges([_mock_edge(models.EvidenceLevel.VERIFIED)]), finding)
    assert result.score <= 10.0


def test_known_asset_level_is_not_flagged_as_an_unknown() -> None:
    finding = _finding(
        asset_criticality=models.ImpactLevel.HIGH, asset_exposure=models.ImpactLevel.HIGH
    )
    result = compute_risk(_session_with_edges([_mock_edge(models.EvidenceLevel.VERIFIED)]), finding)
    assert result.breakdown["unknowns_defaulted"] == []

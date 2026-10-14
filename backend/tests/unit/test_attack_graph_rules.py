"""Unit tests for the Phase 12 engine's pure evidence-level mapping —
no database needed; bare, unpersisted Finding instances suffice."""

from __future__ import annotations

from offensivex.attack_graph.engine import _evidence_level_for_finding
from offensivex.db import models


def _finding(status: models.FindingStatus, confidence: float = 1.0) -> models.Finding:
    return models.Finding(
        title="x",
        severity=models.FindingSeverity.MEDIUM,
        confidence=confidence,
        source="security_header_scan",
        affected_component="X-Frame-Options",
        status=status,
    )


def test_confirmed_maps_to_verified() -> None:
    assert _evidence_level_for_finding(_finding(models.FindingStatus.CONFIRMED)) is (
        models.EvidenceLevel.VERIFIED
    )


def test_rejected_produces_no_edge() -> None:
    assert _evidence_level_for_finding(_finding(models.FindingStatus.REJECTED)) is None


def test_discovered_produces_no_edge() -> None:
    """A bare scanner hit is not enough to claim even a 'potential'
    attack-graph edge — it hasn't been investigated at all yet."""
    assert _evidence_level_for_finding(_finding(models.FindingStatus.DISCOVERED)) is None


def test_well_evidenced_suspected_maps_to_potential() -> None:
    finding = _finding(models.FindingStatus.SUSPECTED, confidence=0.9)
    assert _evidence_level_for_finding(finding) is models.EvidenceLevel.POTENTIAL


def test_low_confidence_suspected_produces_no_edge() -> None:
    finding = _finding(models.FindingStatus.SUSPECTED, confidence=0.5)
    assert _evidence_level_for_finding(finding) is None


def test_investigating_at_the_floor_maps_to_potential() -> None:
    finding = _finding(models.FindingStatus.INVESTIGATING, confidence=0.8)
    assert _evidence_level_for_finding(finding) is models.EvidenceLevel.POTENTIAL

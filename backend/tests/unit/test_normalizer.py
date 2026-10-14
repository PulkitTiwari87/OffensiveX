"""Unit tests for ObservationNormalizer's dispatch mechanics — no
database. `get_or_create_asset`/`write_observation` need a real session
and are exercised for real by
tests/integration/test_phase6_recon_agent.py (now running through this
refactored normalizer).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from offensivex.observations.normalizer import NoNormalizerRegisteredError, ObservationNormalizer


def test_register_and_dispatch() -> None:
    normalizer = ObservationNormalizer()
    calls = []
    normalizer.register(
        "dns_resolution",
        lambda session, assessment, request, result: calls.append((request, result)),
    )

    normalizer.normalize(MagicMock(), MagicMock(), "dns_resolution", {"hostname": "x"}, "RESULT")
    assert calls == [({"hostname": "x"}, "RESULT")]


def test_dispatch_to_unregistered_capability_raises() -> None:
    normalizer = ObservationNormalizer()
    with pytest.raises(NoNormalizerRegisteredError):
        normalizer.normalize(MagicMock(), MagicMock(), "nonexistent", {}, "RESULT")


def test_two_capabilities_dispatch_independently() -> None:
    normalizer = ObservationNormalizer()
    seen = []
    normalizer.register("a", lambda s, a, req, res: seen.append("a"))
    normalizer.register("b", lambda s, a, req, res: seen.append("b"))

    normalizer.normalize(MagicMock(), MagicMock(), "b", {}, None)
    normalizer.normalize(MagicMock(), MagicMock(), "a", {}, None)
    assert seen == ["b", "a"]

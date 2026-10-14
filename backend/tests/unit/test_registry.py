"""Unit tests for offensivex.tools.registry's registration/lookup, which
need no database. `ToolRegistry.execute()` needs a real Assessment +
Authorization and is covered by
tests/integration/test_phase3_tool_registry.py.
"""

from __future__ import annotations

import pytest

from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.registry import CapabilityNotFoundError, ToolRegistry


def test_register_and_get() -> None:
    registry = ToolRegistry()
    adapter = DnsResolutionAdapter()
    registry.register(adapter)
    assert registry.get("dns_resolution") is adapter


def test_get_unregistered_capability_raises() -> None:
    registry = ToolRegistry()
    with pytest.raises(CapabilityNotFoundError):
        registry.get("nonexistent_capability")

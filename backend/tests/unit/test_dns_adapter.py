"""Unit tests for the DNS resolution adapter. No real network call here —
the resolver is injected; tests/integration/test_phase3_tool_registry.py
exercises the real one.
"""

from __future__ import annotations

from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.registry import ExecutionPlan, Intrusiveness


def _fake_resolver(hostname: str) -> list[str]:
    return {"example.test": ["203.0.113.5", "203.0.113.6"]}.get(hostname, [])


def test_meta_is_passive_and_no_validation_required() -> None:
    adapter = DnsResolutionAdapter(resolver=_fake_resolver)
    assert adapter.meta.intrusiveness is Intrusiveness.PASSIVE
    assert adapter.meta.requires_validation_mode is False


def test_plan_declares_the_hostname_as_the_destination() -> None:
    adapter = DnsResolutionAdapter(resolver=_fake_resolver)
    plan = adapter.plan({"hostname": "example.test"})
    assert plan.destinations == ["example.test"]
    assert plan.capability == "dns_resolution"


def test_run_then_parse_round_trips_addresses() -> None:
    adapter = DnsResolutionAdapter(resolver=_fake_resolver)
    plan = ExecutionPlan(capability="dns_resolution", destinations=["example.test"])
    raw = adapter.run(plan)
    result = adapter.parse(raw)
    assert result.data["addresses"] == ["203.0.113.5", "203.0.113.6"]


def test_unknown_hostname_resolves_to_empty() -> None:
    adapter = DnsResolutionAdapter(resolver=_fake_resolver)
    plan = ExecutionPlan(capability="dns_resolution", destinations=["nowhere.test"])
    result = adapter.parse(adapter.run(plan))
    assert result.data["addresses"] == []

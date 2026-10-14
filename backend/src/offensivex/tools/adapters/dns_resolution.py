"""The one proof adapter for Phase 3: DNS resolution.

docs/tools/tool-registry.md lists "dnspython" as the candidate
implementation for this capability. This adapter uses the standard
library's `socket.getaddrinfo` instead: the capability is deliberately
minimal (resolve a hostname to its IP addresses), and the standard library
is sufficient for exactly that — CLAUDE.md's "Standard Library First" /
"Minimal Dependencies" rules both say not to add a dependency a phase
doesn't need yet. Revisit dnspython if/when a capability actually needs
something `socket` cannot do (record types beyond A/AAAA, DNS-over-HTTPS,
etc.) — not before.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from typing import Any

from offensivex.core.urls import parse_host
from offensivex.tools.registry import (
    AdapterMeta,
    ExecutionPlan,
    IntegrationStatus,
    Intrusiveness,
    ParsedResult,
)

Resolver = Callable[[str], list[str]]


def _default_resolver(hostname: str) -> list[str]:
    infos = socket.getaddrinfo(hostname, None)
    # dedupe while preserving order; getaddrinfo repeats entries per
    # socket type (SOCK_STREAM/SOCK_DGRAM/...) for the same address.
    seen: dict[str, None] = {}
    for _family, _type, _proto, _canonname, sockaddr in infos:
        address = sockaddr[0]
        assert isinstance(address, str)  # always true for AF_INET/AF_INET6
        seen.setdefault(address, None)
    return list(seen)


class DnsResolutionAdapter:
    """`request = {"hostname": "example.com"}`."""

    def __init__(self, resolver: Resolver = _default_resolver) -> None:
        self._resolver = resolver
        # IMPLEMENTED (per Guardrail.md section 7's tool/provider
        # vocabulary): it has run against the real resolver, not only a
        # mock — see tests/integration/test_phase3_tool_registry.py. It
        # becomes VERIFIED once that integration test is part of a
        # repeatable CI check (docs/roadmap/current-status.md tracks
        # which is currently true).
        self.meta = AdapterMeta(
            name="dns_resolution",
            capability="dns_resolution",
            intrusiveness=Intrusiveness.PASSIVE,
            requires_validation_mode=False,
            status=IntegrationStatus.IMPLEMENTED,
        )

    def plan(self, request: dict[str, Any]) -> ExecutionPlan:
        # Same strict validation as URLs (offensivex.core.urls): a malformed or
        # ambiguous name ("2130706433", "a b", "host\\x00") is refused before the
        # Scope Guard or the resolver ever sees it. InvalidUrlError is a ValueError.
        hostname = parse_host(request["hostname"])
        return ExecutionPlan(
            capability=self.meta.capability,
            destinations=[hostname],
            request={**request, "hostname": hostname},
        )

    def run(self, plan: ExecutionPlan) -> bytes:
        hostname = plan.destinations[0]
        addresses = self._resolver(hostname)
        return "\n".join(addresses).encode("utf-8")

    def parse(self, raw_artifact: bytes) -> ParsedResult:
        text = raw_artifact.decode("utf-8")
        addresses = [line for line in text.splitlines() if line]
        return ParsedResult(capability=self.meta.capability, data={"addresses": addresses})

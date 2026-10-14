"""Scope Guard — Phase 3.

The per-tool-invocation-planning layer of docs/Guardrail.md section 2's
four-layer model (the "scan creation" layer is
offensivex.services.scope). Every destination an ExecutionPlan declares is
checked here before anything runs: "a destination is allowed only if an
include rule matches and no exclude rule matches. Exclude wins."
(Guardrail.md section 2.2)

Rule matching, by `rule_type` (the same free-string field
offensivex.services.scope.ScopeRuleInput uses — no closed vocabulary is
specified in the docs, so none is invented here either):

- `"domain"`: `pattern` matches a destination hostname exactly, or (if
  `pattern` starts with `"*."`) matches any strict subdomain of the rest
  (not the apex itself — the same convention as a TLS wildcard
  certificate).
- `"cidr"`: `pattern` is an IP network; matches a destination that parses
  as an IP/CIDR within it. A non-IP destination never matches a `cidr`
  rule (and vice versa) — resolving a hostname to check it against a
  `cidr` rule is a caller responsibility (e.g. a future HTTP-probe
  adapter checking the *resolved, pinned* IP, per Guardrail.md section
  2.8), not this function's.
- Any other `rule_type`: never matches anything (fail-closed on an
  unrecognized rule type, consistent with "default-deny").

Ports (offensivex.core.ports, ADR-024): when a destination carries a port, a
rule matches only if it also covers that port. An include rule with no `ports`
covers the web default ports (80, 443) only; an exclude rule with no `ports`
covers every port. A destination with no port (`port=None`) is a host-only
check, used by capabilities that never open a connection to the destination
(DNS resolution): include rules then match on the host alone, and an exclude
rule matches only if it is host-wide (no `ports`).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from offensivex.core.ports import DEFAULT_INCLUDE_PORTS, port_in_spec


class ScopeRuleLike(Protocol):
    """Read-only view of a rule: satisfied by the ORM `ScopeRule` and by the
    frozen `ScopeRuleInput` alike (the guard never mutates a rule)."""

    @property
    def rule_type(self) -> str: ...
    @property
    def pattern(self) -> str: ...
    @property
    def is_exclusion(self) -> bool: ...
    @property
    def ports(self) -> str | None: ...


@dataclass(frozen=True)
class ScopeCheckResult:
    destination: str
    allowed: bool
    reason: str
    matched_rule_pattern: str | None = None
    port: int | None = None


def _domain_rule_matches(pattern: str, destination: str) -> bool:
    destination = destination.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return destination.endswith(suffix) and destination != pattern[2:]
    return destination == pattern


def _cidr_rule_matches(pattern: str, destination: str) -> bool:
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        address = ipaddress.ip_address(destination)
    except ValueError:
        return False
    return address in network


def _host_matches(rule: ScopeRuleLike, destination: str) -> bool:
    if rule.rule_type == "domain":
        return _domain_rule_matches(rule.pattern, destination)
    if rule.rule_type == "cidr":
        return _cidr_rule_matches(rule.pattern, destination)
    return False  # unrecognized rule_type: fail-closed, matches nothing


def _port_matches(rule: ScopeRuleLike, port: int | None) -> bool:
    if rule.ports is None:
        if rule.is_exclusion:
            return True  # host-wide exclusion: every port
        return port is None or port_in_spec(port, DEFAULT_INCLUDE_PORTS)
    if port is None:
        # Host-only check: an include is decided on the host alone; a
        # port-limited exclusion does not exclude the whole host.
        return not rule.is_exclusion
    return port_in_spec(port, rule.ports)


def _rule_matches(rule: ScopeRuleLike, destination: str, port: int | None) -> bool:
    return _host_matches(rule, destination) and _port_matches(rule, port)


def _label(destination: str, port: int | None) -> str:
    return repr(destination) if port is None else f"{destination!r} port {port}"


def find_exclusion(
    destination: str, scope_rules: Sequence[ScopeRuleLike], port: int | None = None
) -> ScopeRuleLike | None:
    """The first exclude rule that matches the destination (and port), if any."""
    for rule in scope_rules:
        if rule.is_exclusion and _rule_matches(rule, destination, port):
            return rule
    return None


def check_destination(
    destination: str, scope_rules: list[ScopeRuleLike], port: int | None = None
) -> ScopeCheckResult:
    """Default-deny, exclude-wins (Guardrail.md section 2.2), port-aware."""
    include_matches = [
        r for r in scope_rules if not r.is_exclusion and _rule_matches(r, destination, port)
    ]
    excluded_by = find_exclusion(destination, scope_rules, port)
    label = _label(destination, port)

    if excluded_by is not None:
        return ScopeCheckResult(
            destination=destination,
            allowed=False,
            reason=f"Destination {label} matches exclude rule {excluded_by.pattern!r}.",
            matched_rule_pattern=excluded_by.pattern,
            port=port,
        )
    if include_matches:
        return ScopeCheckResult(
            destination=destination,
            allowed=True,
            reason=f"Destination {label} matches include rule {include_matches[0].pattern!r}.",
            matched_rule_pattern=include_matches[0].pattern,
            port=port,
        )
    host_only = [r for r in scope_rules if not r.is_exclusion and _host_matches(r, destination)]
    hint = (
        " The host is in scope but this port is not: a rule without `ports` covers only "
        f"{DEFAULT_INCLUDE_PORTS}; list the port explicitly to authorize it."
        if host_only and port is not None
        else ""
    )
    return ScopeCheckResult(
        destination=destination,
        allowed=False,
        reason=f"Destination {label} matches no include rule (default-deny).{hint}",
        port=port,
    )


def check_destinations(
    destinations: list[str],
    scope_rules: list[ScopeRuleLike],
    ports: list[int | None] | None = None,
) -> list[ScopeCheckResult]:
    """Checks every destination an ExecutionPlan declares — "all of them
    up front," per docs/architecture/tool-architecture.md. `ports`, when given,
    is parallel to `destinations`."""
    if ports is not None and len(ports) != len(destinations):
        raise ValueError("`ports` must be parallel to `destinations`.")
    port_list: list[int | None] = ports if ports is not None else [None] * len(destinations)
    return [
        check_destination(d, scope_rules, p) for d, p in zip(destinations, port_list, strict=True)
    ]

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
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Protocol


class ScopeRuleLike(Protocol):
    """Read-only view of a rule: satisfied by the ORM `ScopeRule` and by the
    frozen `ScopeRuleInput` alike (the guard never mutates a rule)."""

    @property
    def rule_type(self) -> str: ...
    @property
    def pattern(self) -> str: ...
    @property
    def is_exclusion(self) -> bool: ...


@dataclass(frozen=True)
class ScopeCheckResult:
    destination: str
    allowed: bool
    reason: str
    matched_rule_pattern: str | None = None


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


def _rule_matches(rule: ScopeRuleLike, destination: str) -> bool:
    if rule.rule_type == "domain":
        return _domain_rule_matches(rule.pattern, destination)
    if rule.rule_type == "cidr":
        return _cidr_rule_matches(rule.pattern, destination)
    return False  # unrecognized rule_type: fail-closed, matches nothing


def check_destination(destination: str, scope_rules: list[ScopeRuleLike]) -> ScopeCheckResult:
    """Default-deny, exclude-wins (Guardrail.md section 2.2)."""
    include_matches = [
        r for r in scope_rules if not r.is_exclusion and _rule_matches(r, destination)
    ]
    exclude_matches = [r for r in scope_rules if r.is_exclusion and _rule_matches(r, destination)]

    if exclude_matches:
        return ScopeCheckResult(
            destination=destination,
            allowed=False,
            reason=(
                f"Destination {destination!r} matches exclude rule {exclude_matches[0].pattern!r}."
            ),
            matched_rule_pattern=exclude_matches[0].pattern,
        )
    if include_matches:
        return ScopeCheckResult(
            destination=destination,
            allowed=True,
            reason=(
                f"Destination {destination!r} matches include rule {include_matches[0].pattern!r}."
            ),
            matched_rule_pattern=include_matches[0].pattern,
        )
    return ScopeCheckResult(
        destination=destination,
        allowed=False,
        reason=f"Destination {destination!r} matches no include rule (default-deny).",
    )


def check_destinations(
    destinations: list[str], scope_rules: list[ScopeRuleLike]
) -> list[ScopeCheckResult]:
    """Checks every destination an ExecutionPlan declares — "all of them
    up front," per docs/architecture/tool-architecture.md."""
    return [check_destination(d, scope_rules) for d in destinations]

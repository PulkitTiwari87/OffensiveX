"""Scope rule validation — the "scan creation" layer of docs/Guardrail.md
section 2's four-layer defense-in-depth model.

The other three layers (per-tool-invocation planning, discovered-asset
handling, parsed-output filtering) belong to the Tool Registry's Scope
Guard (Phase 3) and are not implemented here. This module only validates a
scope rule at the point an Authorization is submitted — rejecting the
catch-all patterns Guardrail.md names explicitly, and private/loopback/
metadata destinations unless the deployment opts in.

Deliberately NOT implemented here (left to Phase 3, where the config value
would actually be exercised against a live tool call, not guessed at):
"CIDRs wider than the configured limit" (Guardrail.md section 2.6) — no
such limit is specified anywhere in the documentation, and inventing a
number now would be exactly the kind of unjustified decision CLAUDE.md
section 22 says to avoid.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from offensivex.core.errors import OffensiveXError
from offensivex.core.ports import InvalidPortSpecError, parse_port_spec

# Exact catch-all patterns Guardrail.md section 2.6 names: "0.0.0.0/0,
# ::/0, TLD-only wildcards". A bare "*" is the degenerate TLD-only case for
# non-CIDR rule types.
_CATCH_ALL_CIDRS = {"0.0.0.0/0", "::/0"}
_CATCH_ALL_PATTERNS = {"*"}


class ScopeValidationError(OffensiveXError):
    status_code = 422
    title = "Invalid scope rule"


@dataclass(frozen=True)
class ScopeRuleInput:
    """What `validate_scope_rules` checks — a plain, pre-persistence shape
    rather than the ORM's `ScopeRule`, so this module needs no DB session.
    """

    rule_type: str
    pattern: str
    is_exclusion: bool = False
    # None = host-only rule: an include covers ports 80/443 only, an exclude
    # covers every port (offensivex.core.ports, ADR-024).
    ports: str | None = None


def _is_tld_only_wildcard(pattern: str) -> bool:
    """`*.com`, `*.io`, ... — a wildcard whose remainder has no further
    dot is effectively "anything on the public internet in this TLD".
    A domain like `*.example.com` is fine; `*.com` is not.
    """
    if not pattern.startswith("*."):
        return False
    remainder = pattern[2:]
    return "." not in remainder


def _is_private_or_reserved(pattern: str) -> bool:
    """True if `pattern` parses as an IP/CIDR and falls in a private,
    loopback, link-local, or reserved range (which includes the cloud
    metadata address 169.254.169.254 — it's link-local). Non-IP patterns
    (domains) return False here; a domain resolving to a private address
    is a runtime (Scope Guard / DNS-pinning) concern, not a creation-time
    one, since the IP isn't known yet at authorization-submission time.
    """
    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False
    return (
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_reserved
        or network.is_multicast
    )


def is_private_or_loopback_host(host: str) -> bool:
    """For a validated host from `offensivex.core.urls`: an IP literal in a
    private/loopback/link-local/reserved range, or a name that is loopback by
    definition (`localhost`, `*.localhost`). Other DNS names return False —
    where they resolve is a runtime concern (see `_is_private_or_reserved`)."""
    return _is_private_or_reserved(host) or host == "localhost" or host.endswith(".localhost")


def validate_scope_rules(rules: list[ScopeRuleInput], *, allow_private_targets: bool) -> None:
    """Raise ScopeValidationError on the first rule that fails Guardrail.md
    section 2's creation-time checks. Does not mutate `rules`.

    An empty `rules` list is also rejected here: "every scan has an
    explicit scope. No scope -> no scan" (Guardrail.md section 2.1) applies
    to the authorization that will back a scan, not only to the scan
    itself.
    """
    if not rules:
        raise ScopeValidationError("An authorization must have at least one scope rule.")

    for rule in rules:
        if rule.ports is not None:
            try:
                parse_port_spec(rule.ports)
            except InvalidPortSpecError as exc:
                raise ScopeValidationError(
                    f"Scope rule {rule.pattern!r} has invalid ports {rule.ports!r}: {exc}"
                ) from None
        if rule.pattern in _CATCH_ALL_CIDRS or rule.pattern in _CATCH_ALL_PATTERNS:
            raise ScopeValidationError(
                f"Scope rule {rule.pattern!r} is a catch-all and is never allowed "
                "(Guardrail.md section 2.6)."
            )
        if _is_tld_only_wildcard(rule.pattern):
            raise ScopeValidationError(
                f"Scope rule {rule.pattern!r} is a TLD-only wildcard and is never "
                "allowed (Guardrail.md section 2.6)."
            )
        if (
            not rule.is_exclusion
            and not allow_private_targets
            and _is_private_or_reserved(rule.pattern)
        ):
            raise ScopeValidationError(
                f"Scope rule {rule.pattern!r} targets a private/loopback/link-local/"
                "reserved address. Set OFFENSIVEX_ALLOW_PRIVATE_TARGETS=true to permit "
                "this for lab/development use (Guardrail.md section 2.7)."
            )

    if all(rule.is_exclusion for rule in rules):
        raise ScopeValidationError(
            "An authorization needs at least one include rule — scope is "
            "default-deny (Guardrail.md section 2.2)."
        )

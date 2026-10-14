"""Connection-time network policy — the half of Guardrail.md section 2.7/2.8
that the hostname-level Scope Guard cannot do.

The Scope Guard decides whether a *hostname and port* may be contacted. A
hostname is only a label, though: `app.example.com` can resolve to
127.0.0.1, 10.0.0.5 or 169.254.169.254, and an attacker-controlled DNS server
can answer differently on the second lookup (DNS rebinding). So an adapter that
opens a connection must (1) resolve the name once, (2) run every address it got
through `check_resolved_addresses`, and (3) connect to one of the *approved IP
literals*, never to the name again. `verify_peer` then confirms the socket really
landed on the address that was approved.

Policy, per resolved address (all addresses must pass — one bad answer in a mixed
public/private set rejects the whole resolution, it is not quietly filtered):

1. Never allowed, regardless of any setting or rule: cloud-metadata endpoints
   (`METADATA_ADDRESSES`), and an address that does not parse.
2. Denied if an *exclude* rule matches the address and port (exclude wins).
3. A globally routable address is allowed (the hostname's own scope rule
   authorized the name).
4. Anything else — loopback, private, link-local, unspecified, multicast,
   reserved, carrier-grade NAT, documentation ranges, and IPv6 forms that embed
   such an IPv4 (`::ffff:a.b.c.d`, NAT64, 6to4) — is allowed only if the
   deployment permits private targets (`OFFENSIVEX_ALLOW_PRIVATE_TARGETS`) AND
   the scope *explicitly* covers that address: an include `cidr` rule matching it
   (with the port), or the destination was that exact IP literal, or the
   destination is a loopback-by-definition name (`localhost`, `*.localhost`) and
   the address is loopback.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Sequence
from dataclasses import dataclass

from offensivex.tools.scope_guard import ScopeRuleLike, check_destination, find_exclusion

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Addresses of cloud instance-metadata services. Several are link-local (so
# already non-global), but some (Azure's 168.63.129.16) are public addresses, so
# they are listed explicitly and are denied even when private targets are allowed.
METADATA_ADDRESSES: frozenset[IPAddress] = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack, DigitalOcean ...
        "169.254.170.2",  # AWS ECS task metadata
        "168.63.129.16",  # Azure WireServer
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud
        "fd00:ec2::254",  # AWS IMDS over IPv6
    )
)

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


class NetworkPolicyError(Exception):
    """A resolved address (or the connection that was made) is not allowed.

    The Tool Registry turns this into a `ScopeViolationError` and records the
    execution as DENIED — it is a scope refusal, not a tool malfunction."""


@dataclass(frozen=True)
class NetworkContext:
    """What a connecting adapter needs to enforce the policy: the authorization's
    rules and the deployment's private-target switch. Built by the Tool
    Registry after the hostname/port Scope Guard check passed; an adapter that
    is not given one refuses to connect."""

    rules: tuple[ScopeRuleLike, ...]
    allow_private_targets: bool = False


def parse_address(raw: str) -> IPAddress:
    """An IP literal from a resolver (a scope id like `fe80::1%eth0` is dropped).
    Anything that does not parse is refused rather than guessed at."""
    try:
        return ipaddress.ip_address(raw.partition("%")[0])
    except ValueError:
        raise NetworkPolicyError(f"Resolver returned an unparseable address {raw!r}.") from None


def _embedded_ipv4(address: IPAddress) -> ipaddress.IPv4Address | None:
    if isinstance(address, ipaddress.IPv4Address):
        return None
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address in _NAT64:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if address in _SIX_TO_FOUR:
        return ipaddress.IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
    return None


def is_metadata_address(address: IPAddress) -> bool:
    embedded = _embedded_ipv4(address)
    return address in METADATA_ADDRESSES or (
        embedded is not None and embedded in METADATA_ADDRESSES
    )


def _is_unicast_global(address: IPAddress) -> bool:
    # `is_global` alone is not enough: some multicast ranges report global.
    return address.is_global and not address.is_multicast


def is_public_address(address: IPAddress) -> bool:
    """A globally routable unicast address, and not an IPv6 wrapper around a
    non-routable IPv4."""
    embedded = _embedded_ipv4(address)
    return _is_unicast_global(address) and (embedded is None or _is_unicast_global(embedded))


def _is_loopback(address: IPAddress) -> bool:
    embedded = _embedded_ipv4(address)
    return address.is_loopback or (embedded is not None and embedded.is_loopback)


def _is_loopback_name(host: str) -> bool:
    return host == "localhost" or host.endswith(".localhost")


def _explicitly_in_scope(
    host: str, address: IPAddress, port: int, rules: Sequence[ScopeRuleLike]
) -> bool:
    if host == str(address):
        return True  # the Scope Guard already matched this exact IP literal
    if _is_loopback_name(host) and _is_loopback(address):
        return True
    cidr_rules = [r for r in rules if r.rule_type == "cidr"]
    return check_destination(str(address), cidr_rules, port).allowed


def check_resolved_addresses(
    host: str, port: int, addresses: Sequence[str], context: NetworkContext
) -> list[str]:
    """Return the approved addresses (resolver order, normalized) or raise
    `NetworkPolicyError`. Call this on the resolver's answer immediately before
    connecting, and connect only to what it returns."""
    if not addresses:
        raise NetworkPolicyError(f"DNS resolution for {host!r} returned no addresses.")
    approved: list[str] = []
    for raw in addresses:
        address = parse_address(raw)
        if is_metadata_address(address):
            raise NetworkPolicyError(
                f"{host!r} resolves to {address}, a cloud-metadata address; "
                "these are never contacted."
            )
        excluded_by = find_exclusion(str(address), context.rules, port)
        if excluded_by is not None:
            raise NetworkPolicyError(
                f"{host!r} resolves to {address}, which exclude rule "
                f"{excluded_by.pattern!r} forbids on port {port}."
            )
        if not is_public_address(address):
            if not context.allow_private_targets:
                raise NetworkPolicyError(
                    f"{host!r} resolves to {address}, a loopback/private/link-local/reserved "
                    "address. Set OFFENSIVEX_ALLOW_PRIVATE_TARGETS=true for lab use "
                    "(Guardrail.md section 2.7)."
                )
            if not _explicitly_in_scope(host, address, port, context.rules):
                raise NetworkPolicyError(
                    f"{host!r} resolves to {address}, a non-public address the scope does not "
                    "explicitly cover; add an include `cidr` rule for it with the port "
                    "(Guardrail.md section 2.7)."
                )
        approved.append(str(address))
    return approved


def verify_peer(sock: socket.socket, expected: str) -> None:
    """Confirm the connected socket's remote address is the approved one — a
    second, independent check that nothing resolved the name behind our back."""
    try:
        peer = parse_address(str(sock.getpeername()[0]))
    except OSError as exc:
        raise NetworkPolicyError(f"Cannot determine the connected peer: {exc}") from exc
    if peer != parse_address(expected):
        raise NetworkPolicyError(
            f"Connected to {peer}, not the approved address {expected}; connection dropped."
        )

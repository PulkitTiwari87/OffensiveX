"""Unit tests for offensivex.tools.network_guard — which resolved addresses may be
connected to. Pure logic: no sockets, no DNS, no database."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from offensivex.tools.network_guard import (
    NetworkContext,
    NetworkPolicyError,
    check_resolved_addresses,
    verify_peer,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


@dataclass(frozen=True)
class Rule:
    rule_type: str
    pattern: str
    is_exclusion: bool = False
    ports: str | None = None


def ctx(*rules: Rule, allow_private: bool = False) -> NetworkContext:
    return NetworkContext(rules=rules, allow_private_targets=allow_private)


NON_PUBLIC = [
    "127.0.0.1",
    "127.1.2.3",
    "::1",
    "10.0.0.5",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.1.1",  # link-local
    "fe80::1",
    "fc00::1",  # unique-local
    "0.0.0.0",  # noqa: S104 (unspecified; an address under test, not a bind)
    "::",
    "224.0.0.1",  # multicast
    "ff02::1",
    "100.64.0.1",  # carrier-grade NAT
    "240.0.0.1",  # reserved
    "192.0.2.1",  # documentation
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
    "::ffff:10.0.0.1",
    "64:ff9b::7f00:1",  # NAT64-wrapped 127.0.0.1
    "2002:7f00:1::",  # 6to4-wrapped 127.0.0.1
    "fe80::1%eth0",  # with a scope id
]

METADATA = [
    "169.254.169.254",
    "169.254.170.2",
    "168.63.129.16",  # a *public* address, still metadata
    "100.100.100.200",
    "192.0.0.192",
    "fd00:ec2::254",
    "::ffff:169.254.169.254",
    "64:ff9b::a9fe:a9fe",  # NAT64-wrapped 169.254.169.254
]


@pytest.mark.parametrize("address", [PUBLIC_V4, PUBLIC_V6])
def test_public_addresses_are_approved(address: str) -> None:
    assert check_resolved_addresses("app.example.test", 443, [address], ctx()) == [address]


@pytest.mark.parametrize("address", NON_PUBLIC)
def test_non_public_addresses_are_denied_by_default(address: str) -> None:
    with pytest.raises(NetworkPolicyError, match="ALLOW_PRIVATE_TARGETS"):
        check_resolved_addresses("app.example.test", 443, [address], ctx())


@pytest.mark.parametrize("address", NON_PUBLIC)
def test_non_public_addresses_stay_denied_even_with_the_switch_if_scope_does_not_cover_them(
    address: str,
) -> None:
    # The deployment allows private targets, but the authorization only names the
    # hostname: a public name that resolves privately is not "explicitly listed".
    rules = ctx(Rule("domain", "app.example.test"), allow_private=True)
    with pytest.raises(NetworkPolicyError, match="does not explicitly cover"):
        check_resolved_addresses("app.example.test", 443, [address], rules)


@pytest.mark.parametrize("address", METADATA)
def test_metadata_addresses_are_never_allowed(address: str) -> None:
    # Not with the switch on, and not even when an include rule names the address.
    permissive = ctx(
        Rule("domain", "app.example.test"),
        Rule("cidr", "169.254.0.0/16"),
        Rule("cidr", "168.63.129.16/32"),
        Rule("cidr", "100.100.100.200/32"),
        Rule("cidr", "192.0.0.192/32"),
        Rule("cidr", "fd00:ec2::/32"),
        allow_private=True,
    )
    with pytest.raises(NetworkPolicyError, match="cloud-metadata"):
        check_resolved_addresses("app.example.test", 80, [address], permissive)


def test_mixed_public_and_private_answers_reject_the_whole_resolution() -> None:
    mixed = ([PUBLIC_V4, "10.0.0.5"], ["10.0.0.5", PUBLIC_V4], [PUBLIC_V4, "169.254.169.254"])
    for answers in mixed:
        with pytest.raises(NetworkPolicyError):
            check_resolved_addresses("app.example.test", 443, answers, ctx())


def test_empty_and_garbage_answers_fail_closed() -> None:
    with pytest.raises(NetworkPolicyError, match="no addresses"):
        check_resolved_addresses("app.example.test", 443, [], ctx())
    with pytest.raises(NetworkPolicyError, match="unparseable"):
        check_resolved_addresses("app.example.test", 443, ["not-an-ip"], ctx())
    with pytest.raises(NetworkPolicyError, match="unparseable"):
        check_resolved_addresses("app.example.test", 443, ["2130706433"], ctx())


def test_exclude_cidr_rule_beats_a_public_hostname_resolving_into_it() -> None:
    rules = ctx(
        Rule("domain", "app.example.test"),
        Rule("cidr", "93.184.216.0/24", is_exclusion=True),
    )
    with pytest.raises(NetworkPolicyError, match="exclude rule"):
        check_resolved_addresses("app.example.test", 443, [PUBLIC_V4], rules)


def test_port_limited_exclude_cidr_only_applies_to_that_port() -> None:
    rules = ctx(Rule("cidr", "93.184.216.0/24", is_exclusion=True, ports="8080"))
    assert check_resolved_addresses("a.example.test", 443, [PUBLIC_V4], rules) == [PUBLIC_V4]
    with pytest.raises(NetworkPolicyError, match="exclude rule"):
        check_resolved_addresses("a.example.test", 8080, [PUBLIC_V4], rules)


def test_private_address_is_approved_only_with_switch_and_an_include_cidr_covering_port() -> None:
    rules = (
        Rule("domain", "lab.example.test", ports="8080"),
        Rule("cidr", "10.0.0.0/24", ports="8080"),
    )
    allowed = ctx(*rules, allow_private=True)
    assert check_resolved_addresses("lab.example.test", 8080, ["10.0.0.5"], allowed) == ["10.0.0.5"]
    # ... not without the deployment switch,
    with pytest.raises(NetworkPolicyError, match="ALLOW_PRIVATE_TARGETS"):
        check_resolved_addresses("lab.example.test", 8080, ["10.0.0.5"], ctx(*rules))
    # ... not outside the cidr,
    with pytest.raises(NetworkPolicyError, match="does not explicitly cover"):
        check_resolved_addresses("lab.example.test", 8080, ["10.0.1.5"], allowed)
    # ... and not on a port the cidr rule does not list.
    with pytest.raises(NetworkPolicyError, match="does not explicitly cover"):
        check_resolved_addresses("lab.example.test", 22, ["10.0.0.5"], allowed)


def test_exact_ip_literal_destination_is_covered_by_its_own_scope_match() -> None:
    # The Scope Guard already required an include rule matching this literal.
    rules = ctx(Rule("cidr", "127.0.0.1/32", ports="8000"), allow_private=True)
    assert check_resolved_addresses("127.0.0.1", 8000, ["127.0.0.1"], rules) == ["127.0.0.1"]


def test_loopback_names_may_resolve_to_loopback_only() -> None:
    rules = ctx(Rule("domain", "localhost", ports="8000"), allow_private=True)
    assert check_resolved_addresses("localhost", 8000, ["127.0.0.1", "::1"], rules) == [
        "127.0.0.1",
        "::1",
    ]
    wildcard = ctx(Rule("domain", "*.localhost", ports="8000"), allow_private=True)
    assert check_resolved_addresses("app.localhost", 8000, ["127.0.0.1"], wildcard) == ["127.0.0.1"]
    # A "localhost" name that a resolver points at a LAN host is not loopback.
    with pytest.raises(NetworkPolicyError, match="does not explicitly cover"):
        check_resolved_addresses("app.localhost", 8000, ["10.0.0.5"], wildcard)


def test_ordinary_lab_name_resolving_to_loopback_needs_an_explicit_cidr() -> None:
    domain_only = ctx(Rule("domain", "lab.example.test", ports="8000"), allow_private=True)
    with pytest.raises(NetworkPolicyError, match="does not explicitly cover"):
        check_resolved_addresses("lab.example.test", 8000, ["127.0.0.1"], domain_only)
    with_cidr = ctx(
        Rule("domain", "lab.example.test", ports="8000"),
        Rule("cidr", "127.0.0.0/8", ports="8000"),
        allow_private=True,
    )
    assert check_resolved_addresses("lab.example.test", 8000, ["127.0.0.1"], with_cidr) == [
        "127.0.0.1"
    ]


def test_addresses_are_returned_normalized_in_resolver_order() -> None:
    answers = ["2606:2800:0220:0001:0248:1893:25c8:1946", PUBLIC_V4]
    assert check_resolved_addresses("a.example.test", 443, answers, ctx()) == [PUBLIC_V6, PUBLIC_V4]


class _Sock:
    def __init__(self, peer: object) -> None:
        self._peer = peer

    def getpeername(self) -> object:
        if isinstance(self._peer, OSError):
            raise self._peer
        return self._peer


def test_verify_peer_accepts_the_approved_address_and_rejects_any_other() -> None:
    verify_peer(_Sock((PUBLIC_V4, 443)), PUBLIC_V4)  # type: ignore[arg-type]
    verify_peer(_Sock((PUBLIC_V6, 443, 0, 0)), PUBLIC_V6)  # type: ignore[arg-type]
    with pytest.raises(NetworkPolicyError, match="not the approved address"):
        verify_peer(_Sock(("127.0.0.1", 443)), PUBLIC_V4)  # type: ignore[arg-type]
    with pytest.raises(NetworkPolicyError, match="Cannot determine"):
        verify_peer(_Sock(OSError("not connected")), PUBLIC_V4)  # type: ignore[arg-type]

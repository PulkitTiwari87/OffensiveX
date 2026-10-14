"""Unit tests for offensivex.tools.scope_guard — pure logic, no database."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from offensivex.tools.scope_guard import check_destination, check_destinations


@dataclass(frozen=True)
class Rule:
    rule_type: str
    pattern: str
    is_exclusion: bool = False
    ports: str | None = None


def test_exact_domain_match_allowed() -> None:
    result = check_destination("example.com", [Rule("domain", "example.com")])
    assert result.allowed is True


def test_no_matching_rule_denied_default_deny() -> None:
    result = check_destination("other.com", [Rule("domain", "example.com")])
    assert result.allowed is False
    assert "default-deny" in result.reason


def test_subdomain_wildcard_matches_subdomain_not_apex() -> None:
    rules = [Rule("domain", "*.example.com")]
    assert check_destination("api.example.com", rules).allowed is True
    assert check_destination("example.com", rules).allowed is False


def test_exclude_wins_over_include() -> None:
    rules = [
        Rule("domain", "*.example.com"),
        Rule("domain", "internal.example.com", is_exclusion=True),
    ]
    assert check_destination("api.example.com", rules).allowed is True
    assert check_destination("internal.example.com", rules).allowed is False


def test_cidr_match() -> None:
    rules = [Rule("cidr", "203.0.113.0/24")]
    assert check_destination("203.0.113.42", rules).allowed is True
    assert check_destination("198.51.100.1", rules).allowed is False


def test_cidr_rule_never_matches_a_hostname() -> None:
    result = check_destination("example.com", [Rule("cidr", "0.0.0.0/8")])
    assert result.allowed is False


def test_domain_rule_never_matches_an_ip() -> None:
    result = check_destination("203.0.113.42", [Rule("domain", "example.com")])
    assert result.allowed is False


def test_unrecognized_rule_type_matches_nothing() -> None:
    result = check_destination("example.com", [Rule("mystery", "example.com")])
    assert result.allowed is False


def test_check_destinations_checks_each_one() -> None:
    rules = [Rule("domain", "example.com")]
    results = check_destinations(["example.com", "other.com"], rules)
    assert [r.allowed for r in results] == [True, False]


@pytest.mark.parametrize("destination", ["EXAMPLE.COM", "Example.Com"])
def test_domain_match_is_case_insensitive(destination: str) -> None:
    assert check_destination(destination, [Rule("domain", "example.com")]).allowed is True


# --- ports (ADR-024) ------------------------------------------------------------------------


def test_host_only_include_rule_covers_only_the_web_default_ports() -> None:
    rules = [Rule("domain", "example.com")]
    assert check_destination("example.com", rules, 80).allowed is True
    assert check_destination("example.com", rules, 443).allowed is True
    denied = check_destination("example.com", rules, 8443)
    assert denied.allowed is False
    assert "port 8443" in denied.reason and "list the port explicitly" in denied.reason


def test_explicit_ports_replace_the_defaults() -> None:
    rules = [Rule("domain", "example.com", ports="8443,9000-9010")]
    assert check_destination("example.com", rules, 8443).allowed is True
    assert check_destination("example.com", rules, 9005).allowed is True
    assert check_destination("example.com", rules, 443).allowed is False  # not implied
    assert check_destination("example.com", rules, 9011).allowed is False


def test_cidr_rules_are_port_aware_too() -> None:
    rules = [Rule("cidr", "203.0.113.0/24", ports="8080")]
    assert check_destination("203.0.113.9", rules, 8080).allowed is True
    assert check_destination("203.0.113.9", rules, 80).allowed is False


def test_host_wide_exclusion_excludes_every_port() -> None:
    rules = [
        Rule("domain", "*.example.com", ports="1-65534"),
        Rule("domain", "admin.example.com", is_exclusion=True),
    ]
    assert check_destination("app.example.com", rules, 8080).allowed is True
    for port in (80, 443, 22, 8080):
        assert check_destination("admin.example.com", rules, port).allowed is False


def test_port_limited_exclusion_only_excludes_those_ports() -> None:
    rules = [
        Rule("domain", "example.com", ports="80,443,8080"),
        Rule("domain", "example.com", ports="8080", is_exclusion=True),
    ]
    assert check_destination("example.com", rules, 443).allowed is True
    assert check_destination("example.com", rules, 8080).allowed is False


def test_host_only_check_without_a_port_ignores_ports_but_honors_host_wide_exclusions() -> None:
    include = [Rule("domain", "example.com", ports="8443")]
    assert check_destination("example.com", include).allowed is True  # e.g. DNS resolution
    port_limited_exclude = [*include, Rule("domain", "example.com", ports="22", is_exclusion=True)]
    assert check_destination("example.com", port_limited_exclude).allowed is True
    host_wide_exclude = [*include, Rule("domain", "example.com", is_exclusion=True)]
    assert check_destination("example.com", host_wide_exclude).allowed is False


def test_unparseable_stored_ports_match_nothing() -> None:
    assert (
        check_destination("example.com", [Rule("domain", "example.com", ports="oops")], 80).allowed
        is False
    )


def test_check_destinations_requires_parallel_ports() -> None:
    rules = [Rule("domain", "example.com")]
    results = check_destinations(["example.com", "example.com"], rules, [443, 8443])
    assert [r.allowed for r in results] == [True, False]
    with pytest.raises(ValueError, match="parallel"):
        check_destinations(["example.com"], rules, [80, 443])

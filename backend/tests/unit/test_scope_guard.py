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

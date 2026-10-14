"""Unit tests for offensivex.services.scope — pure logic, no database."""

from __future__ import annotations

import pytest

from offensivex.services.scope import ScopeRuleInput, ScopeValidationError, validate_scope_rules


def test_empty_scope_is_rejected() -> None:
    with pytest.raises(ScopeValidationError):
        validate_scope_rules([], allow_private_targets=False)


@pytest.mark.parametrize("pattern", ["0.0.0.0/0", "::/0", "*"])
def test_catch_all_patterns_rejected(pattern: str) -> None:
    with pytest.raises(ScopeValidationError):
        validate_scope_rules(
            [ScopeRuleInput(rule_type="cidr", pattern=pattern)], allow_private_targets=False
        )


@pytest.mark.parametrize("pattern", ["*.com", "*.io", "*.uk"])
def test_tld_only_wildcard_rejected(pattern: str) -> None:
    with pytest.raises(ScopeValidationError):
        validate_scope_rules(
            [ScopeRuleInput(rule_type="domain", pattern=pattern)], allow_private_targets=False
        )


def test_subdomain_wildcard_is_allowed() -> None:
    validate_scope_rules(
        [ScopeRuleInput(rule_type="domain", pattern="*.example.com")],
        allow_private_targets=False,
    )


@pytest.mark.parametrize(
    "pattern", ["10.0.0.0/8", "192.168.1.1", "127.0.0.1", "169.254.169.254", "::1"]
)
def test_private_and_metadata_addresses_rejected_by_default(pattern: str) -> None:
    with pytest.raises(ScopeValidationError):
        validate_scope_rules(
            [ScopeRuleInput(rule_type="cidr", pattern=pattern)], allow_private_targets=False
        )


@pytest.mark.parametrize("pattern", ["10.0.0.0/8", "127.0.0.1"])
def test_private_addresses_allowed_when_flag_set(pattern: str) -> None:
    validate_scope_rules(
        [ScopeRuleInput(rule_type="cidr", pattern=pattern)], allow_private_targets=True
    )


def test_exclusion_rule_for_private_range_is_never_rejected() -> None:
    """An exclude rule narrowing an already-approved public range can
    legitimately carve out a private-looking pattern; only include rules
    are checked against the private-range gate."""
    validate_scope_rules(
        [
            ScopeRuleInput(rule_type="domain", pattern="example.com"),
            ScopeRuleInput(rule_type="cidr", pattern="10.0.0.0/8", is_exclusion=True),
        ],
        allow_private_targets=False,
    )


def test_public_domain_and_cidr_are_allowed() -> None:
    validate_scope_rules(
        [
            ScopeRuleInput(rule_type="domain", pattern="example.com"),
            ScopeRuleInput(rule_type="cidr", pattern="8.8.8.0/24"),
        ],
        allow_private_targets=False,
    )


def test_all_exclusion_rules_rejected_for_lacking_an_include() -> None:
    with pytest.raises(ScopeValidationError):
        validate_scope_rules(
            [ScopeRuleInput(rule_type="domain", pattern="example.com", is_exclusion=True)],
            allow_private_targets=False,
        )

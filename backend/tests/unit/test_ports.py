"""Unit tests for offensivex.core.ports — the port-list syntax used by scope rules."""

from __future__ import annotations

import pytest

from offensivex.core.ports import (
    InvalidPortSpecError,
    normalize_port_spec,
    parse_port_spec,
    port_in_spec,
)


def test_parses_singles_and_ranges_and_normalizes() -> None:
    assert parse_port_spec("443, 80,8000-8100") == ((80, 80), (443, 443), (8000, 8100))
    assert normalize_port_spec(" 8443,80, 443,8000-8100,8050-8200") == "80,443,8000-8200,8443"
    assert normalize_port_spec("80,81,82") == "80-82"  # adjacent ports merge


@pytest.mark.parametrize(
    "spec",
    [
        "",
        " ",
        "0",
        "65536",
        "80-",
        "-80",
        "a",
        "80;443",
        "90-80",
        "80,,443",
        "1-65535",
        "1-100,100-65535",
    ],
)
def test_rejects_invalid_or_catch_all_specs(spec: str) -> None:
    with pytest.raises(InvalidPortSpecError):
        parse_port_spec(spec)


def test_rejects_overlong_spec() -> None:
    with pytest.raises(InvalidPortSpecError, match="longer"):
        parse_port_spec(",".join(str(p) for p in range(1000, 1100)) + "," * 100)


def test_port_in_spec() -> None:
    assert port_in_spec(8443, "443,8443") is True
    assert port_in_spec(8444, "443,8443") is False
    assert port_in_spec(9005, "9000-9010") is True
    assert port_in_spec(80, "garbage") is False  # unparseable matches nothing

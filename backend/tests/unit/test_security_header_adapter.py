"""Unit tests for SecurityHeaderScanAdapter.parse() — pure logic, no
network. run() against a real server is covered by
tests/integration/test_phase8_vulnerability_agent.py.
"""

from __future__ import annotations

from offensivex.tools.adapters.security_header_scan import SecurityHeaderScanAdapter
from offensivex.tools.registry import Intrusiveness


def test_meta_is_low_intrusiveness() -> None:
    adapter = SecurityHeaderScanAdapter()
    assert adapter.meta.intrusiveness is Intrusiveness.LOW
    assert adapter.meta.requires_validation_mode is False


def test_all_headers_missing() -> None:
    adapter = SecurityHeaderScanAdapter()
    raw = b"203.0.113.9\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    result = adapter.parse(raw)
    assert set(result.data["missing_headers"]) == {
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
    }


def test_present_headers_are_not_flagged_missing() -> None:
    adapter = SecurityHeaderScanAdapter()
    raw = (
        b"203.0.113.9\n"
        b"HTTP/1.1 200 OK\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"X-Frame-Options: DENY\r\n"
        b"\r\nok"
    )
    result = adapter.parse(raw)
    assert result.data["missing_headers"] == []


def test_header_matching_is_case_insensitive() -> None:
    adapter = SecurityHeaderScanAdapter()
    raw = b"203.0.113.9\nHTTP/1.1 200 OK\r\nstrict-transport-security: max-age=1\r\n\r\nok"
    result = adapter.parse(raw)
    assert "Strict-Transport-Security" not in result.data["missing_headers"]

"""Unit tests for HttpProbeAdapter's plan()/parse() — pure logic, no real
socket or network call. run() against a real server is covered by
tests/integration/test_phase6_recon_agent.py.
"""

from __future__ import annotations

import pytest

from offensivex.tools.adapters.http_probe import HttpProbeAdapter
from offensivex.tools.registry import Intrusiveness


def test_meta_is_low_intrusiveness_no_validation_required() -> None:
    adapter = HttpProbeAdapter()
    assert adapter.meta.intrusiveness is Intrusiveness.LOW
    assert adapter.meta.requires_validation_mode is False


def test_plan_declares_hostname_as_destination() -> None:
    adapter = HttpProbeAdapter()
    plan = adapter.plan({"url": "https://example.test:8443/path?x=1"})
    assert plan.destinations == ["example.test"]


@pytest.mark.parametrize("url", ["ftp://example.test/", "file:///etc/passwd", "example.test"])
def test_plan_rejects_non_http_schemes(url: str) -> None:
    adapter = HttpProbeAdapter()
    with pytest.raises(ValueError, match="scheme"):
        adapter.plan({"url": url})


def test_parse_extracts_status_headers_and_body() -> None:
    adapter = HttpProbeAdapter()
    raw = (
        b"203.0.113.9\n"
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Server: example-server\r\n"
        b"\r\n"
        b"<html>hello</html>"
    )
    result = adapter.parse(raw)
    assert result.data["pinned_ip"] == "203.0.113.9"
    assert result.data["status_code"] == 200
    assert result.data["headers"]["content-type"] == "text/html"
    assert result.data["headers"]["server"] == "example-server"
    assert result.data["body_excerpt"] == "<html>hello</html>"


def test_parse_handles_missing_status_line_gracefully() -> None:
    adapter = HttpProbeAdapter()
    raw = b"203.0.113.9\n\r\n"
    result = adapter.parse(raw)
    assert result.data["status_code"] is None

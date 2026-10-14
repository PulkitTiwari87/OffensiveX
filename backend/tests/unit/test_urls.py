"""The strict URL/hostname parser every entry point and probe request goes
through. The point of most cases: ambiguous input is *rejected*, not
interpreted, so the host that is scope-checked is the host that is contacted."""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from offensivex.core.urls import InvalidUrlError, parse_host, parse_http_url
from offensivex.tools.adapters.dns_resolution import DnsResolutionAdapter
from offensivex.tools.adapters.http_probe import HttpProbeAdapter


@pytest.mark.parametrize(
    ("raw", "normalized", "host", "port"),
    [
        ("http://example.test", "http://example.test/", "example.test", 80),
        ("https://example.test", "https://example.test/", "example.test", 443),
        ("HTTPS://Example.TEST/Path/", "https://example.test/Path/", "example.test", 443),
        ("http://example.test:8080/app", "http://example.test:8080/app", "example.test", 8080),
        ("http://example.test:80/", "http://example.test/", "example.test", 80),  # default dropped
        ("https://example.test:443/x", "https://example.test/x", "example.test", 443),
        ("https://example.test:8443", "https://example.test:8443/", "example.test", 8443),
        ("http://example.test./", "http://example.test/", "example.test", 80),  # trailing dot
        ("  http://example.test:9000/  ", "http://example.test:9000/", "example.test", 9000),
        ("http://127.0.0.1:3000", "http://127.0.0.1:3000/", "127.0.0.1", 3000),
        ("https://[::1]:8443/", "https://[::1]:8443/", "::1", 8443),
        ("http://[2001:db8::1]/", "http://[2001:db8::1]/", "2001:db8::1", 80),
        (
            "http://xn--bcher-kva.example/",
            "http://xn--bcher-kva.example/",
            "xn--bcher-kva.example",
            80,
        ),
        (
            "http://a-b.c-d.example.test/",
            "http://a-b.c-d.example.test/",
            "a-b.c-d.example.test",
            80,
        ),
    ],
)
def test_ordinary_urls_are_accepted_and_normalized(
    raw: str, normalized: str, host: str, port: int
) -> None:
    parsed = parse_http_url(raw, allow_query=False)
    assert (parsed.url, parsed.host, parsed.port) == (normalized, host, port)
    # Normalization is a fixed point: re-parsing the stored form changes nothing.
    assert parse_http_url(parsed.url, allow_query=False).url == parsed.url


@pytest.mark.parametrize(
    ("raw", "fragment_of_message"),
    [
        # schemes
        ("ftp://example.test/", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("gopher://example.test/", "scheme"),
        ("example.test", "scheme"),
        ("//example.test/", "scheme"),
        # empty / structure
        ("", "empty"),
        ("   ", "empty"),
        ("http://", "no hostname"),
        ("http:///path", "no hostname"),
        ("http:example.test", "no hostname"),
        # credentials / parser-differential tricks
        ("http://user:pw@example.test/", "credentials"),
        ("http://allowed.test@evil.test/", "credentials"),
        ("http://evil.test\\@allowed.test/", "backslash"),
        ("http://allowed.test\\.evil.test/", "backslash"),
        # whitespace / control characters (header injection, truncation)
        ("http://example.test/ x", "whitespace"),
        ("http://exa mple.test/", "whitespace"),
        ("http://example.test/\r\nHost: evil.test", "whitespace"),
        ("http://example.test/\x00", "whitespace"),
        ("http://example.test/\ttab", "whitespace"),
        # ports
        ("http://example.test:0/", "Port 0"),
        ("http://example.test:65536/", "malformed"),
        ("http://example.test:99999/", "malformed"),
        ("http://example.test:abc/", "malformed"),
        ("http://example.test:-1/", "malformed"),
        ("http://example.test:/", "empty port"),
        # fragments
        ("http://example.test/#frag", "fragment"),
        ("http://example.test#", "fragment"),
        # non-canonical IP spellings a resolver would turn into a different host
        ("http://2130706433/", "non-canonical"),
        ("http://127.1/", "non-canonical"),
        ("http://0x7f.0.0.1/", "non-canonical"),
        ("http://0177.0.0.1/", "non-canonical"),
        ("http://1.2.3/", "non-canonical"),
        # hostnames
        ("http://-bad.test/", "not a valid DNS name"),
        ("http://bad-.test/", "not a valid DNS name"),
        ("http://bad_name.test/", "not a valid DNS name"),
        ("http://a..b.test/", "not a valid DNS name"),
        ("http://" + "a" * 64 + ".test/", "not a valid DNS name"),
        ("http://%65xample.test/", "forbidden"),
        ("http://[fe80::1%25eth0]/", "forbidden"),
        ("http://[::1/", "malformed"),
        # non-ASCII
        ("http://exämple.test/", "ASCII"),
        ("http://example.test/päth", "ASCII"),
        # size
        ("http://example.test/" + "a" * 2100, "longer than"),
    ],
)
def test_ambiguous_or_malformed_urls_are_rejected(raw: str, fragment_of_message: str) -> None:
    with pytest.raises(InvalidUrlError, match=fragment_of_message):
        parse_http_url(raw, allow_query=True)


def test_non_strings_are_rejected() -> None:
    for bad in (None, 123, ["http://example.test/"], b"http://example.test/"):
        with pytest.raises(InvalidUrlError):
            parse_http_url(bad, allow_query=True)  # type: ignore[arg-type]


def test_entry_points_may_not_carry_a_query_string_but_probe_urls_may() -> None:
    url = "https://example.test/search?token=abc&x=1"
    with pytest.raises(InvalidUrlError, match="query"):
        parse_http_url(url, allow_query=False)
    with pytest.raises(InvalidUrlError, match="query"):
        parse_http_url("https://example.test/?", allow_query=False)
    parsed = parse_http_url(url, allow_query=True)
    assert parsed.url == url and parsed.query == "token=abc&x=1"


@pytest.mark.parametrize(
    "raw",
    [
        "http://allowed.test/",
        "http://allowed.test:8080/a/b?x=1",
        "https://[::1]:8443/",
        "http://10.0.0.5/",
        "http://allowed.test./",
    ],
)
def test_parsed_host_is_the_host_the_stdlib_would_connect_to(raw: str) -> None:
    """For everything we accept there is no disagreement to exploit: our host
    equals what plain urlsplit sees (modulo the normalizations we apply)."""
    parsed = parse_http_url(raw, allow_query=True)
    assert parsed.host == (urlsplit(raw).hostname or "").removesuffix(".")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("LOCALHOST", "localhost"),
        ("Example.Test.", "example.test"),
        ("::1", "::1"),
        ("10.1.2.3", "10.1.2.3"),
    ],
)
def test_parse_host_normalizes(raw: str, expected: str) -> None:
    assert parse_host(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", "a b", "2130706433", "127.1", "host/path", "host@evil", "a\x00b", "ex%41mple.test"]
)
def test_parse_host_rejects_ambiguous_names(raw: str) -> None:
    with pytest.raises(InvalidUrlError):
        parse_host(raw)


# --- the tools use the same parser, so what is checked is what is contacted ---------


def test_probe_plan_scope_checks_and_connects_to_the_same_normalized_host() -> None:
    plan = HttpProbeAdapter().plan({"url": "HTTP://App.Example.TEST.:8080/x?y=1"})
    assert plan.destinations == ["app.example.test"]
    assert plan.request["url"] == "http://app.example.test:8080/x?y=1"


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.test\\@allowed.test/",  # check one host, connect to another
        "http://allowed.test@evil.test/",
        "http://2130706433/",  # resolves to 127.0.0.1; scope never saw an IP
        "http://allowed.test/\r\nX-Injected: 1",
        "http://allowed.test:99999/",
    ],
)
def test_probe_refuses_ambiguous_urls_before_scope_or_network(url: str) -> None:
    with pytest.raises(ValueError):  # InvalidUrlError subclasses ValueError
        HttpProbeAdapter().plan({"url": url})


def test_probe_host_header_includes_a_non_default_port() -> None:
    assert parse_http_url("http://example.test:8080/", allow_query=True).host_header == (
        "example.test:8080"
    )
    assert parse_http_url("https://example.test/", allow_query=True).host_header == "example.test"
    assert parse_http_url("http://[::1]:81/", allow_query=True).host_header == "[::1]:81"


@pytest.mark.parametrize("hostname", ["2130706433", "a b", "host\x00", "evil.test/x", ""])
def test_dns_tool_rejects_ambiguous_hostnames(hostname: str) -> None:
    with pytest.raises(ValueError):
        DnsResolutionAdapter().plan({"hostname": hostname})


def test_dns_tool_normalizes_the_hostname_it_scope_checks() -> None:
    plan = DnsResolutionAdapter().plan({"hostname": "LocalHost."})
    assert plan.destinations == ["localhost"] and plan.request["hostname"] == "localhost"

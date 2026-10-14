"""Strict http(s) URL / hostname parsing — one parser for validation *and*
connection.

Scope checks are only meaningful if the host that was *checked* is the host
that is *connected to*. Python's `urlsplit` is lenient (it accepts
`http://evil.com\\@allowed.com/`, hostnames like `2130706433` that
`getaddrinfo` turns into 127.0.0.1, embedded whitespace, ...), and a browser
or another library may read the same string differently. So everything that
takes a URL from a user or a model — target entry points and the HTTP probe's
requests — goes through `parse_http_url`, which rejects the ambiguous forms
outright instead of interpreting them, and returns a *normalized* URL that is
what gets stored and connected to.

Rejected: non-http(s) schemes, userinfo (`user:pass@`), backslashes,
whitespace/control characters, non-ASCII hosts (use punycode), fragments, a
bad/zero/out-of-range or empty port, percent-signs or zone ids in the host,
over-long input, malformed DNS names, and any numeric-looking host that is not
a canonical dotted-quad / IPv6 literal (`127.1`, `0x7f.1`, `2130706433`).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
_DEFAULT_PORTS = {"http": 80, "https": 443}
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


class InvalidUrlError(ValueError):
    """The input is not an acceptable, unambiguous http(s) URL / hostname."""


@dataclass(frozen=True)
class HttpUrl:
    scheme: str
    host: str  # lowercase, no trailing dot, IPv6 without brackets
    port: int  # effective port (explicit or the scheme default)
    path: str  # always starts with "/"
    query: str

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def host_header(self) -> str:
        """Value for a `Host:` header: bracketed IPv6, port only if non-default."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == _DEFAULT_PORTS[self.scheme] else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        suffix = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{self.host_header}{self.path}{suffix}"


def parse_host(raw: str) -> str:
    """Validate and normalize a bare hostname or IP literal (no port)."""
    if not isinstance(raw, str):
        raise InvalidUrlError("Hostname must be a string.")
    host = raw.strip().lower()
    if not host:
        raise InvalidUrlError("Hostname is empty.")
    if len(host) > 253:
        raise InvalidUrlError("Hostname is too long.")
    if not host.isascii():
        raise InvalidUrlError("Hostname must be ASCII (use punycode for internationalized names).")
    if any(ch in host for ch in "%\\@/?#[]") or any(ord(ch) <= 32 or ord(ch) == 127 for ch in host):
        raise InvalidUrlError(f"Hostname {raw!r} contains forbidden characters.")
    try:
        # Canonical IP literals only; ipaddress rejects "127.1", leading zeros, etc.
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.removesuffix(".")  # "example.com." is the same host
    labels = host.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        raise InvalidUrlError(f"Hostname {raw!r} is not a valid DNS name.")
    # inet_aton-style forms ("127.1", "2130706433", "0x7f.1") end in a number
    # or hex label; a resolver would read them as an IP the scope check never saw.
    last = labels[-1]
    if last.isdigit() or last.startswith("0x"):
        raise InvalidUrlError(
            f"Hostname {raw!r} looks like a non-canonical IP address; write it as a "
            "dotted quad or use a DNS name."
        )
    return host


def parse_http_url(raw: str, *, allow_query: bool) -> HttpUrl:
    """Parse and normalize an http(s) URL, or raise `InvalidUrlError`.

    `allow_query=False` is for stored entry points (a query string can carry
    secrets that would then leak into audit logs and reports); the probe
    allows it.
    """
    if not isinstance(raw, str):
        raise InvalidUrlError("URL must be a string.")
    text = raw.strip()
    if not text:
        raise InvalidUrlError("URL is empty.")
    if len(text) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if not text.isascii():
        raise InvalidUrlError("URL must be ASCII (percent-encode the path, punycode the host).")
    if "\\" in text or any(ord(ch) <= 32 or ord(ch) == 127 for ch in text):
        raise InvalidUrlError("URL contains backslashes, whitespace or control characters.")

    try:
        parts = urlsplit(text)
        port = parts.port  # raises ValueError for non-numeric / out-of-range ports
    except ValueError as exc:
        raise InvalidUrlError(f"URL is malformed: {exc}") from None

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise InvalidUrlError(f"Unsupported URL scheme {parts.scheme!r} (must be http/https).")
    if not parts.netloc or not parts.hostname:
        raise InvalidUrlError("URL has no hostname.")
    if "@" in parts.netloc:
        raise InvalidUrlError("URLs with credentials (user@host) are not accepted.")
    if parts.netloc.endswith(":"):
        raise InvalidUrlError("URL has an empty port.")
    if port == 0:
        raise InvalidUrlError("Port 0 is not valid.")
    if parts.fragment or "#" in text:
        raise InvalidUrlError("URLs with a fragment (#...) are not accepted.")
    if not allow_query and (parts.query or "?" in text):
        raise InvalidUrlError(
            "Entry points must not contain a query string (it could carry secrets)."
        )

    host = parse_host(parts.hostname)
    return HttpUrl(
        scheme=scheme,
        host=host,
        port=port or _DEFAULT_PORTS[scheme],
        path=parts.path or "/",
        query=parts.query,
    )

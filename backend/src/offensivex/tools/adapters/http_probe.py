"""HTTP probe — the second Phase 6 adapter (docs/roadmap/implementation-
blueprint.md section 9's MVP recon surface: "DNS + HTTP probing").

docs/tools/tool-registry.md names "httpx (engine-provided client)" as the
candidate implementation. This adapter uses the standard library instead
(`socket` + `ssl`), for the same "Standard Library First" reason as the
DNS resolution adapter — and because doing so is what makes Guardrail.md
section 2.8's IP-pinning guarantee straightforward to implement correctly:

> "Destinations are resolved once, validated, and the tool is given the
> validated IP (pinned) to prevent DNS-rebinding / time-of-check-to-time-
> of-use escapes."

This adapter resolves the hostname itself right before connecting and
connects to that resolved IP directly (`socket.create_connection((ip,
port), ...)`), never letting a second, later DNS lookup decide where the
connection actually goes. For HTTPS, the TLS handshake still verifies the
certificate against the *original hostname* (`server_hostname=hostname`)
while the raw socket is connected to the pinned IP — a real client
re-resolving mid-request could not get this combination "for free" the
way this adapter does by construction.

**Known limitation, not hidden:** redirects are reported, not followed.
Guardrail.md section 2.3 requires per-hop scope re-checking for any
capability that follows redirects; correctly re-running the Scope Guard on
each hop is a real feature, not a one-line addition, and is deferred
until a capability actually needs to follow a redirect (not before).
"""

from __future__ import annotations

import socket
from ssl import create_default_context
from typing import Any

from offensivex.core.urls import parse_http_url
from offensivex.tools.adapters.dns_resolution import Resolver
from offensivex.tools.adapters.dns_resolution import _default_resolver as _resolve_hostname
from offensivex.tools.registry import (
    AdapterMeta,
    ExecutionPlan,
    IntegrationStatus,
    Intrusiveness,
    ParsedResult,
)

_DEFAULT_CONNECT_TIMEOUT = 10
_DEFAULT_READ_CAP_BYTES = 65536
_BODY_EXCERPT_BYTES = 2048


class HttpProbeAdapter:
    """`request = {"url": "https://example.com/path"}`. Only `http`/
    `https` schemes are accepted; `plan()` raises `ValueError` otherwise
    (caught and surfaced as a normal application error by the Tool
    Registry's caller, same as any other bad-request condition)."""

    def __init__(
        self,
        resolver: Resolver = _resolve_hostname,
        *,
        connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
        read_cap_bytes: int = _DEFAULT_READ_CAP_BYTES,
    ) -> None:
        self._resolver = resolver
        self._connect_timeout = connect_timeout
        self._read_cap_bytes = read_cap_bytes
        self.meta = AdapterMeta(
            name="http_probe",
            capability="http_probe",
            # One step more intrusive than passive DNS resolution — it
            # sends one real request to the target — but still read-only
            # and non-exploitative, consistent with
            # docs/agents/recon-agent.md's "strictly read-only" recon
            # toolset.
            intrusiveness=Intrusiveness.LOW,
            requires_validation_mode=False,
            status=IntegrationStatus.IMPLEMENTED,
        )

    def plan(self, request: dict[str, Any]) -> ExecutionPlan:
        # The one strict parser (offensivex.core.urls): the host that goes into
        # `destinations` for the Scope Guard is, by construction, the host
        # `run()` connects to — both come from the same normalized URL, and
        # ambiguous forms (userinfo, backslashes, 2130706433, ...) are refused
        # here rather than interpreted. InvalidUrlError is a ValueError.
        parsed = parse_http_url(request["url"], allow_query=True)
        return ExecutionPlan(
            capability=self.meta.capability,
            destinations=[parsed.host],
            request={**request, "url": parsed.url},
        )

    def run(self, plan: ExecutionPlan) -> bytes:
        parsed = parse_http_url(plan.request["url"], allow_query=True)
        hostname = parsed.host
        port = parsed.port
        scheme = parsed.scheme
        path = parsed.path if not parsed.query else f"{parsed.path}?{parsed.query}"

        addresses = self._resolver(hostname)
        if not addresses:
            raise RuntimeError(f"DNS resolution for {hostname!r} returned no addresses.")

        # Try each resolved address in order (e.g. a dual-stack host whose
        # IPv6 address resolves but isn't actually reachable) rather than
        # only ever trying the first and failing outright — but still
        # pinned: once one connects, every byte of this request goes to
        # that exact address, never a fresh lookup.
        raw_sock = None
        pinned_ip = None
        last_error: OSError | None = None
        for candidate in addresses:
            try:
                raw_sock = socket.create_connection(
                    (candidate, port), timeout=self._connect_timeout
                )
                pinned_ip = candidate
                break
            except OSError as exc:
                last_error = exc
        if raw_sock is None or pinned_ip is None:
            raise RuntimeError(
                f"Could not connect to any resolved address for {hostname!r}: {addresses}"
            ) from last_error

        try:
            sock: socket.socket
            if scheme == "https":
                context = create_default_context()
                sock = context.wrap_socket(raw_sock, server_hostname=hostname)
            else:
                sock = raw_sock

            request_bytes = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {parsed.host_header}\r\n"
                "Connection: close\r\n"
                "User-Agent: OffensiveX-ReconAgent/0.1\r\n"
                "\r\n"
            ).encode("ascii")
            sock.sendall(request_bytes)

            chunks: list[bytes] = []
            total = 0
            while total < self._read_cap_bytes:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw_response = b"".join(chunks)
        finally:
            raw_sock.close()

        # Prepend the pinned IP (not otherwise recoverable from the raw
        # HTTP response) so parse() can report exactly what was connected
        # to, without re-resolving.
        return pinned_ip.encode("ascii") + b"\n" + raw_response

    def parse(self, raw_artifact: bytes) -> ParsedResult:
        pinned_ip_line, _, rest = raw_artifact.partition(b"\n")
        pinned_ip = pinned_ip_line.decode("ascii")
        head, _, body = rest.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")

        status_code: int | None = None
        if lines and lines[0].startswith("HTTP/"):
            status_parts = lines[0].split(" ", 2)
            if len(status_parts) >= 2 and status_parts[1].isdigit():
                status_code = int(status_parts[1])

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        return ParsedResult(
            capability=self.meta.capability,
            data={
                "pinned_ip": pinned_ip,
                "status_code": status_code,
                "headers": headers,
                "body_excerpt": body[:_BODY_EXCERPT_BYTES].decode("utf-8", errors="replace"),
            },
        )

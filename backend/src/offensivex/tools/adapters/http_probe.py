"""HTTP probe — the second Phase 6 adapter (docs/roadmap/implementation-
blueprint.md section 9's MVP recon surface: "DNS + HTTP probing").

docs/tools/tool-registry.md names "httpx (engine-provided client)" as the
candidate implementation. This adapter uses the standard library instead
(`socket` + `ssl`), for the same "Standard Library First" reason as the
DNS resolution adapter — and because owning the connection is what makes
Guardrail.md section 2.8's IP-pinning guarantee enforceable rather than hoped for
(an HTTP client that is handed a hostname resolves it itself, again, at connect time):

> "Destinations are resolved once, validated, and the tool is given the
> validated IP (pinned) to prevent DNS-rebinding / time-of-check-to-time-
> of-use escapes."

`run()` therefore does exactly this, in order (docs/security/network-safety.md):

1. resolves the hostname **once** (an IP-literal host is not resolved at all);
2. validates **every** returned address with `network_guard.check_resolved_addresses`
   (metadata / private / loopback / link-local / exclude-rule checks; one bad answer
   rejects the whole set);
3. connects to an approved **IP literal** — never the name — so no second lookup
   exists to be rebound, and checks `getpeername()` against that address;
4. for HTTPS, wraps that socket with `server_hostname=<original hostname>` and a
   verifying context, so the certificate is validated for the name the operator
   authorized while the bytes go to the validated IP; the `Host:` header carries the
   original name and port.

The hostname *and port* were already checked by the Scope Guard (`plan()` declares
both); a `run()` that is not handed a `NetworkContext` refuses to connect.

**Redirects are reported, never followed** (3xx responses are returned as data; the
`Location` header is just a header). So a redirect cannot move the probe to a host or
port that was not authorized: the only way to contact the target of a redirect is
for the agent to request it as a new `http_probe`, which goes back through the
Scope Guard and this adapter's address checks like any other request. Following
redirects with per-hop re-validation is a deliberate non-goal until a capability
needs it (Guardrail.md section 2.3).
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable
from typing import Any

from offensivex.core.urls import parse_http_url
from offensivex.tools.adapters.dns_resolution import Resolver
from offensivex.tools.adapters.dns_resolution import _default_resolver as _resolve_hostname
from offensivex.tools.network_guard import (
    NetworkPolicyError,
    check_resolved_addresses,
    verify_peer,
)
from offensivex.tools.registry import (
    AdapterMeta,
    ExecutionPlan,
    IntegrationStatus,
    Intrusiveness,
    ParsedResult,
)

Connector = Callable[[tuple[str, int], float], socket.socket]

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
        connector: Connector = socket.create_connection,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        # `resolver`, `connector` and `ssl_context` are injectable so tests can use a
        # deterministic DNS answer, observe exactly what is connected to, and trust a
        # test CA. Production uses the defaults: the system resolver, a plain TCP
        # connect (always given an IP literal), and a verifying default TLS context.
        self._resolver = resolver
        self._connector = connector
        self._ssl_context = ssl_context
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
        # The one strict parser (offensivex.core.urls): the host and port that go into
        # the plan for the Scope Guard are, by construction, the host and port `run()`
        # connects to — both come from the same normalized URL, and ambiguous forms
        # (userinfo, backslashes, 2130706433, ...) are refused here rather than
        # interpreted. InvalidUrlError is a ValueError.
        parsed = parse_http_url(request["url"], allow_query=True)
        return ExecutionPlan(
            capability=self.meta.capability,
            destinations=[parsed.host],
            request={**request, "url": parsed.url},
            ports=[parsed.port],
        )

    def run(self, plan: ExecutionPlan) -> bytes:
        if plan.network is None:
            raise NetworkPolicyError(
                "No network policy context was supplied; refusing to connect (fail-closed)."
            )
        parsed = parse_http_url(plan.request["url"], allow_query=True)
        hostname = parsed.host
        port = parsed.port
        path = parsed.path if not parsed.query else f"{parsed.path}?{parsed.query}"

        # Resolve ONCE, validate every answer, then connect only to approved IP
        # literals. Nothing below ever resolves `hostname` again.
        resolved = [hostname] if parsed.is_ip else self._resolver(hostname)
        approved = check_resolved_addresses(hostname, port, resolved, plan.network)

        # Try each approved address in order (e.g. a dual-stack host whose IPv6
        # address is not actually reachable) — still pinned: once one connects,
        # every byte of this request goes to that exact address.
        raw_sock: socket.socket | None = None
        pinned_ip: str | None = None
        last_error: OSError | None = None
        for candidate in approved:
            try:
                candidate_sock = self._connector((candidate, port), self._connect_timeout)
            except OSError as exc:
                last_error = exc
                continue
            try:
                verify_peer(candidate_sock, candidate)
            except NetworkPolicyError:
                candidate_sock.close()
                raise
            raw_sock, pinned_ip = candidate_sock, candidate
            break
        if raw_sock is None or pinned_ip is None:
            raise RuntimeError(
                f"Could not connect to any approved address for {hostname!r}: {approved}"
            ) from last_error

        sock: socket.socket = raw_sock
        try:
            if parsed.scheme == "https":
                context = self._ssl_context or ssl.create_default_context()
                sock = context.wrap_socket(raw_sock, server_hostname=hostname)

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
            sock.close()
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
